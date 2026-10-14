"""Run the attack bench and the latency measurement, then report."""

from __future__ import annotations

import json
import platform
import shutil
import statistics
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

from .. import __version__
from ..client import MCPClient, SMCPClient, check_response, check_server_hello
from ..gateway import Deployment, Gateway
from ..protocol import CALL, HELLO, SERVER_HELLO, make_hello, seal_call
from . import upstream
from .scenarios import (CHECKS, NOT_TESTED, PAPER_ORDER, PROFILES, SCENARIOS, Result, Row, _not_tested,
                        benign_workload)
from .world import World

ORDER = {"blocked": 0, "partial": 1, "missed": 2, "not tested": 3, "inconclusive": 4, "error": 5}


def _ms(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"median_ms": round(statistics.median(s) * 1000, 3),
            "p95_ms": round(s[int(0.95 * (len(s) - 1))] * 1000, 3),
            "n": len(s)}


def _run(fn, world: World, profile: str) -> Result:
    try:
        return fn(world, profile)
    except Exception as e:  # report, keep going
        return Result("error", f"{type(e).__name__}: {e}")


def run_scenarios(world: World) -> tuple[list[Row], list[dict], dict]:
    """Every scenario under both profiles, the extra checks, and the benign workload."""
    rows: list[Row] = []
    for fn in SCENARIOS:
        step, risk, attack = fn.meta
        paper, ext = _run(fn, world, "paper"), _run(fn, world, "extended")
        rows.append(Row(step, risk, attack, paper.baseline or ext.baseline,
                        paper.outcome, paper.evidence, paper.control,
                        ext.outcome, ext.evidence, ext.control, ext.variants))
        print(f"  {paper.outcome:<10} {ext.outcome:<10} {risk}", file=sys.stderr, flush=True)
    rows += [_not_tested(*t) for t in NOT_TESTED]
    rows.sort(key=lambda r: PAPER_ORDER.index(r.risk) if r.risk in PAPER_ORDER else len(PAPER_ORDER))
    checks = []
    for fn in CHECKS:
        entry = {}
        for profile in PROFILES:
            try:
                r = fn(world, profile)
            except Exception as e:
                r = {"check": fn.__name__, "result": "error", "evidence": f"{type(e).__name__}: {e}"}
            entry.setdefault("check", r["check"])
            entry[profile] = r["result"]
            entry[f"{profile}_evidence"] = r["evidence"]
        checks.append(entry)
    benign = {}
    for profile in PROFILES:
        try:
            benign[profile] = benign_workload(world, profile)
        except Exception as e:
            benign[profile] = {"error": f"{type(e).__name__}: {e}"}
    return rows, checks, benign


def _time_calls(c: MCPClient, calls: int, verify: bool) -> dict:
    for _ in range(20):
        c.call("echo", {"text": "warm"})
    samples = []
    for i in range(calls):
        t = time.perf_counter()
        r = c.call("echo", {"text": f"hello {i}"})
        ok = (not verify or c.verify_response(r).ok) and not r["result"].get("isError")
        samples.append(time.perf_counter() - t)
        assert ok, r
    return _ms(samples)


def stdio_latency(world: World, calls: int) -> dict:
    """End-to-end per-call latency over real processes, echo tool."""
    from ..httpserve import HttpGateway
    tok = world.delegate(world.alice, world.report, ["sales_reporting"])
    out = {}
    with MCPClient(World.upstream_cmd()) as plain:
        out["plain_mcp"] = _time_calls(plain, calls, False)
    for key, profile in (("smcp_gateway", "paper"), ("smcp_gateway_extended", "extended")):
        cfg = world.write(f"latency-{profile}", profile=profile)
        c = SMCPClient(world.gateway_cmd(cfg), agent_id=world.report.id, agent_key=world.report.key,
                       registry=world.registry(cfg), delegation=[tok])
        c.start()
        c.list_tools()
        out[key] = _time_calls(c, calls, True)
        c.close()
    cfg = world.write("latency-http")
    srv = HttpGateway(("127.0.0.1", 0), Deployment.load(cfg), world.server_cmd(cfg))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = SMCPClient(url=srv.url, agent_id=world.report.id, agent_key=world.report.key,
                       registry=world.registry(cfg), delegation=[tok])
        c.start()
        c.list_tools()
        out["smcp_gateway_http"] = _time_calls(c, calls, True)
        c.close()
    finally:
        srv.shutdown()
        srv.server_close()
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


def _summary_line(c: dict) -> str:
    return (f"{c.get('blocked', 0)} blocked, {c.get('partial', 0)} partial, {c.get('missed', 0)} missed, "
            f"{c.get('not tested', 0)} not tested")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _sentence(text: str) -> str:
    text = _cell(text).strip()
    return text if not text or text.endswith((".", ")")) else text + "."


def to_markdown(report: dict) -> str:
    lines = ["# Bench results", "",
             f"Generated by `smcp-gateway bench` ({report['tool']}) on {report['date']}, Python {report['python']}, "
             f"{report['platform']}. The agent is scripted and the server is simulated; see "
             "[LIMITATIONS.md](LIMITATIONS.md).", "",
             "| Step | Risk (paper Table 2) | Plain MCP | Paper design | With extensions |",
             "|---:|---|---|---|---|"]
    for r in report["rows"]:
        lines.append(f"| {r['step']} | {r['risk']} | {_cell(r['baseline'])} | **{r['paper']}** | "
                     f"**{r['extended']}** |")
    s = report["summary"]
    lines += ["", f"Paper design: **{_summary_line(s['paper'])}**. "
                  f"With extensions: **{_summary_line(s['extended'])}**. Out of {sum(s['paper'].values())} risks.",
              "", "## Evidence, risk by risk", ""]
    for r in report["rows"]:
        lines += [f"### {r['step']}. {r['risk']}", "", f"Attack: {_cell(r['attack'])}", "",
                  f"- Plain MCP: {_cell(r['baseline'])}",
                  f"- Paper design: **{r['paper']}**. {_sentence(r['paper_evidence'])}"
                  + (f" Control: {_sentence(r['paper_control'])}" if r['paper_control'] else ""),
                  f"- With extensions: **{r['extended']}**. {_sentence(r['extended_evidence'])}"
                  + (f" Control: {_sentence(r['extended_control'])}" if r['extended_control'] else "")]
        for v in r.get("variants") or []:
            lines.append(f"  - Variant, {_cell(v['attack'])}: **{v['outcome']}**. {_sentence(v['evidence'])}")
        lines.append("")
    lines += ["## Extra checks", "", "| Check | Paper design | With extensions | Evidence (with extensions) |",
              "|---|---|---|---|"]
    for i in report["checks"]:
        lines.append(f"| {i['check']} | **{i['paper']}** | **{i['extended']}** | {_cell(i['extended_evidence'])} |")
    b = report["benign"]
    lines += ["", "## Benign workload", "",
              "| Profile | Calls | Denied | Needed the user's approval |", "|---|---:|---:|---:|"]
    for profile in ("paper", "extended"):
        x = b[profile]
        lines.append(f"| {profile} | {x.get('calls')} | {x.get('denied')} | {x.get('approvals')} |")
    lat = report["latency"]
    st = lat["stdio"]
    lines += ["", "## Latency", "",
              "| Measurement (echo tool) | median | p95 |", "|---|---:|---:|",
              f"| Plain MCP over stdio | {st['plain_mcp']['median_ms']} ms | {st['plain_mcp']['p95_ms']} ms |",
              f"| Through the gateway, paper design, response verified | {st['smcp_gateway']['median_ms']} ms | "
              f"{st['smcp_gateway']['p95_ms']} ms |",
              f"| Through the gateway, with extensions | {st['smcp_gateway_extended']['median_ms']} ms | "
              f"{st['smcp_gateway_extended']['p95_ms']} ms |",
              f"| Through the gateway over Streamable HTTP (loopback, new TCP connection per POST) | "
              f"{st['smcp_gateway_http']['median_ms']} ms | "
              f"{st['smcp_gateway_http']['p95_ms']} ms |",
              f"| Handshake, in-process | {lat['inprocess']['handshake']['median_ms']} ms | "
              f"{lat['inprocess']['handshake']['p95_ms']} ms |",
              f"| One call, in-process (seal, decide, audit, sign, verify) | {lat['inprocess']['call']['median_ms']} ms | "
              f"{lat['inprocess']['call']['p95_ms']} ms |"]
    return "\n".join(lines) + "\n"


def to_text(report: dict) -> str:
    out = [f"{'PAPER':<11} {'EXTENDED':<11} RISK"]
    for r in report["rows"]:
        out.append(f"{r['paper'].upper():<11} {r['extended'].upper():<11} {r['step']:>2} {r['risk']}")
    s = report["summary"]
    out += ["", f"paper design:    {_summary_line(s['paper'])}",
            f"with extensions: {_summary_line(s['extended'])}"]
    for i in report["checks"]:
        out.append(f"check: {i['check']}: paper {i['paper']}, extended {i['extended']}")
    for profile, x in report["benign"].items():
        out.append(f"benign workload ({profile}): {x.get('calls')} calls, {x.get('denied')} denied, "
                   f"{x.get('approvals')} needed approval")
    st = report["latency"]["stdio"]
    out.append(f"latency (median per call): plain {st['plain_mcp']['median_ms']} ms, paper "
               f"{st['smcp_gateway']['median_ms']} ms, extended {st['smcp_gateway_extended']['median_ms']} ms, "
               f"HTTP {st['smcp_gateway_http']['median_ms']} ms; handshake "
               f"{report['latency']['inprocess']['handshake']['median_ms']} ms in-process")
    return "\n".join(out)


def main(*, json_out: str | None = None, markdown_out: str | None = None, calls: int = 300,
         keep: str | None = None) -> int:
    root = Path(keep) if keep else Path(tempfile.mkdtemp(prefix="smcp-bench-"))
    try:
        world = World(root)
        print("running attack scenarios (paper, extended)...", file=sys.stderr, flush=True)
        rows, checks, benign = run_scenarios(world)
        print("measuring latency...", file=sys.stderr, flush=True)
        latency = {"stdio": stdio_latency(world, calls), "inprocess": inprocess_costs(world)}

        def count(profile: str) -> dict:
            c = Counter(getattr(r, profile) for r in rows)
            return dict(sorted(c.items(), key=lambda kv: ORDER.get(kv[0], 9)))
        report = {
            "tool": f"smcp-gateway {__version__}",
            "paper": "arXiv:2602.01129",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "date": time.strftime("%Y-%m-%d"),
            "rows": [r.to_dict() for r in rows],
            "summary": {"paper": count("paper"), "extended": count("extended")},
            "checks": checks,
            "benign": benign,
            "latency": latency,
        }
        print(to_text(report))
        if json_out:
            Path(json_out).write_text(json.dumps(report, indent=2) + "\n")
        if markdown_out:
            Path(markdown_out).write_text(to_markdown(report))
        bad = ("error", "inconclusive")
        errors = ([r for r in rows if r.paper in bad or r.extended in bad]
                  + [i for i in checks if i["paper"] in bad or i["extended"] in bad]
                  + [p for p, x in benign.items() if "error" in x])
        return 1 if errors else 0
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
