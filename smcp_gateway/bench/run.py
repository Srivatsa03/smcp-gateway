"""Run the attack bench and the latency measurement, then report."""

from __future__ import annotations

import json
import platform
import shutil
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from .. import __version__
from ..client import MCPClient, SMCPClient, check_response, check_server_hello
from ..gateway import Gateway
from ..protocol import CALL, HELLO, SERVER_HELLO, make_hello, seal_call
from . import upstream
from .scenarios import INTEGRITY, NOT_TESTED, PAPER_ORDER, SCENARIOS, Row, _not_tested
from .world import World

ORDER = {"blocked": 0, "partial": 1, "missed": 2, "not tested": 3, "inconclusive": 4, "error": 5}


def _ms(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"median_ms": round(statistics.median(s) * 1000, 3),
            "p95_ms": round(s[int(0.95 * (len(s) - 1))] * 1000, 3),
            "n": len(s)}


def run_scenarios(world: World) -> tuple[list[Row], list[dict]]:
    rows: list[Row] = []
    for fn in SCENARIOS:
        try:
            rows.append(fn(world))
        except Exception as e:  # report, keep going
            rows.append(Row(0, fn.__name__, "-", "-", "error", f"{type(e).__name__}: {e}"))
        print(f"  {rows[-1].smcp:<10} {rows[-1].risk}", file=sys.stderr, flush=True)
    rows += [_not_tested(*t) for t in NOT_TESTED]
    rows.sort(key=lambda r: PAPER_ORDER.index(r.risk) if r.risk in PAPER_ORDER else len(PAPER_ORDER))
    integrity = []
    for fn in INTEGRITY:
        try:
            integrity.append(fn(world))
        except Exception as e:
            integrity.append({"check": fn.__name__, "result": "error", "evidence": f"{type(e).__name__}: {e}"})
    return rows, integrity


def stdio_latency(world: World, calls: int) -> dict:
    """End-to-end per-call latency over real stdio processes, echo tool."""
    cfg = world.write("latency")
    tok = world.delegate(world.alice, world.report, ["sales_reporting"])
    out = {}
    with MCPClient(World.upstream_cmd()) as plain:
        for _ in range(20):
            plain.call("echo", {"text": "warm"})
        samples = []
        for i in range(calls):
            t = time.perf_counter()
            plain.call("echo", {"text": f"hello {i}"})
            samples.append(time.perf_counter() - t)
        out["plain_mcp"] = _ms(samples)
    c = SMCPClient(world.gateway_cmd(cfg), agent_id=world.report.id, agent_key=world.report.key,
                   registry=world.registry(cfg), delegation=[tok])
    c.start()
    c.list_tools()
    for _ in range(20):
        c.call("echo", {"text": "warm"})
    samples = []
    for i in range(calls):
        t = time.perf_counter()
        r = c.call("echo", {"text": f"hello {i}"})
        ok = c.verify_response(r).ok and not r["result"].get("isError")
        samples.append(time.perf_counter() - t)
        assert ok, r
    c.close()
    out["smcp_gateway"] = _ms(samples)
    out["overhead_median_ms"] = round(out["smcp_gateway"]["median_ms"] - out["plain_mcp"]["median_ms"], 3)
    return out


def inprocess_costs(world: World, n: int = 200) -> dict:
    """Gateway and client CPU cost with no IPC: handshake and one call."""
    cfg = world.write("inproc")
    reg = world.registry(cfg)
    gw = Gateway.from_config(cfg, log=lambda m: None)
    tok = world.delegate(world.alice, world.report, ["sales_reporting"])
    init_result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                   "serverInfo": {"name": "acme-tools", "version": "1.4.2"}}

    hs = []
    session = None
    for i in range(n):
        t = time.perf_counter()
        hello, eph = make_hello(world.report.id, world.report.key, [tok])
        gw.from_client({"jsonrpc": "2.0", "id": i, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "bench", "version": "0"}, "_meta": {HELLO: hello}}})
        out = gw.from_server({"jsonrpc": "2.0", "id": i, "result": json.loads(json.dumps(init_result))})[0]
        session = check_server_hello(reg, hello, eph, out["result"]["_meta"][SERVER_HELLO])
        hs.append(time.perf_counter() - t)

    session_id, key, _ = session
    gw.from_client({"jsonrpc": "2.0", "id": "L", "method": "tools/list", "params": {}})
    gw.from_server({"jsonrpc": "2.0", "id": "L", "result": {"tools": upstream.tools_for("clean")}})
    calls = []
    for seq in range(1, n + 1):
        args = {"text": f"hello {seq}"}
        t = time.perf_counter()
        env = seal_call(key, session_id, seq, "echo", args)
        up, down = gw.from_client({"jsonrpc": "2.0", "id": f"c{seq}", "method": "tools/call",
                                   "params": {"name": "echo", "arguments": args, "_meta": {CALL: env}}})
        assert up and not down
        resp = gw.from_server({"jsonrpc": "2.0", "id": f"c{seq}",
                               "result": {"content": [{"type": "text", "text": args["text"]}], "isError": False}})[0]
        assert check_response(reg, resp, env).ok
        calls.append(time.perf_counter() - t)
    return {"handshake": _ms(hs), "call": _ms(calls),
            "note": "client + gateway work in one process, no IPC; includes the audit write"}


def to_markdown(report: dict) -> str:
    lines = ["| Step | Risk (paper Table 2) | Plain MCP | Through SMCP | Evidence |",
             "|---:|---|---|---|---|"]
    for r in report["rows"]:
        lines.append(f"| {r['step']} | {r['risk']} | {r['baseline']} | **{r['smcp']}** | {r['evidence']} |")
    c = report["summary"]
    lines += ["", f"**{c.get('blocked', 0)} blocked, {c.get('partial', 0)} partial, "
                  f"{c.get('missed', 0)} missed, {c.get('not tested', 0)} not tested** "
                  f"out of {sum(c.values())} risks.", "",
              "| Integrity check | Result | Evidence |", "|---|---|---|"]
    for i in report["integrity"]:
        lines.append(f"| {i['check']} | **{i['result']}** | {i['evidence']} |")
    lat = report["latency"]
    lines += ["",
              "| Latency (echo tool) | median | p95 |", "|---|---:|---:|",
              f"| Plain MCP over stdio | {lat['stdio']['plain_mcp']['median_ms']} ms | {lat['stdio']['plain_mcp']['p95_ms']} ms |",
              f"| Through the SMCP gateway, response verified | {lat['stdio']['smcp_gateway']['median_ms']} ms | {lat['stdio']['smcp_gateway']['p95_ms']} ms |",
              f"| Handshake, in-process | {lat['inprocess']['handshake']['median_ms']} ms | {lat['inprocess']['handshake']['p95_ms']} ms |",
              f"| One call, in-process (seal, decide, audit, sign, verify) | {lat['inprocess']['call']['median_ms']} ms | {lat['inprocess']['call']['p95_ms']} ms |"]
    return "\n".join(lines) + "\n"


def to_text(report: dict) -> str:
    out = []
    for r in report["rows"]:
        out.append(f"[{r['smcp'].upper():<10}] step {r['step']:>2}  {r['risk']}")
        out.append(f"               {r['evidence']}")
    c = report["summary"]
    out.append("")
    out.append(f"{c.get('blocked', 0)} blocked, {c.get('partial', 0)} partial, {c.get('missed', 0)} missed, "
               f"{c.get('not tested', 0)} not tested, out of {sum(c.values())} risks")
    for i in report["integrity"]:
        out.append(f"integrity: {i['check']}: {i['result']} ({i['evidence']})")
    lat = report["latency"]
    out.append(f"latency: plain {lat['stdio']['plain_mcp']['median_ms']} ms, SMCP "
               f"{lat['stdio']['smcp_gateway']['median_ms']} ms per call (median, stdio); handshake "
               f"{lat['inprocess']['handshake']['median_ms']} ms in-process")
    return "\n".join(out)


def main(*, json_out: str | None = None, markdown_out: str | None = None, calls: int = 300,
         keep: str | None = None) -> int:
    root = Path(keep) if keep else Path(tempfile.mkdtemp(prefix="smcp-bench-"))
    try:
        world = World(root)
        print("running attack scenarios...", file=sys.stderr, flush=True)
        rows, integrity = run_scenarios(world)
        print("measuring latency...", file=sys.stderr, flush=True)
        latency = {"stdio": stdio_latency(world, calls), "inprocess": inprocess_costs(world)}
        report = {
            "tool": f"smcp-gateway {__version__}",
            "paper": "arXiv:2602.01129",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "date": time.strftime("%Y-%m-%d"),
            "rows": [r.to_dict() for r in rows],
            "summary": dict(sorted(Counter(r.smcp for r in rows).items(), key=lambda kv: ORDER.get(kv[0], 9))),
            "integrity": integrity,
            "latency": latency,
        }
        print(to_text(report))
        if json_out:
            Path(json_out).write_text(json.dumps(report, indent=2) + "\n")
        if markdown_out:
            Path(markdown_out).write_text(to_markdown(report))
        errors = ([r for r in rows if r.smcp in ("error", "inconclusive")]
                  + [i for i in integrity if i["result"] == "error"])
        return 1 if errors else 0
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
