"""Put the gateway, extensions on, in front of the official MCP filesystem server.

The bench uses a simulated server. This script checks the same controls
against real code: @modelcontextprotocol/server-filesystem, unmodified, run by
Node. It pins the server's real tools and package, signs the config, then runs
an SMCP session through the gateway and checks what gets through.

Needs Node.js and the package in npm's cache. Fetch it once with:

    npx -y @modelcontextprotocol/server-filesystem /tmp < /dev/null

Then:

    python examples/real_filesystem.py
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import yaml

from smcp_gateway.approval import approve
from smcp_gateway.audit import verify_log
from smcp_gateway.bench.world import FLOW_POLICY, World
from smcp_gateway.client import MCPClient, SMCPClient
from smcp_gateway.crypto import public_b64
from smcp_gateway.identity import make_id
from smcp_gateway.launch import artifact_digest
from smcp_gateway.registry import definition_hash
from smcp_gateway.scan import blocking, scan_tool

READS = {"read_file", "read_text_file", "read_media_file", "read_multiple_files", "list_directory",
         "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info"}
WRITES = {"write_file", "edit_file", "create_directory", "move_file"}
PATH_ARGS = ["path", "paths", "source", "destination"]
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY99"


def find_package() -> Path | None:
    for d in sorted(Path.home().glob(".npm/_npx/*/node_modules/@modelcontextprotocol/server-filesystem")):
        if (d / "dist" / "index.js").exists():
            return d
    return None


def text(resp: dict) -> str:
    return "".join(b.get("text", "") for b in (resp.get("result") or {}).get("content") or [])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--package-dir", type=Path, help="the server-filesystem package (default: npm's npx cache)")
    args = ap.parse_args()
    pkg = args.package_dir or find_package()
    if pkg is None:
        print("server-filesystem not found; run: npx -y @modelcontextprotocol/server-filesystem /tmp < /dev/null")
        return 2

    work = Path(tempfile.mkdtemp(prefix="smcp-fs-")).resolve()
    data = work / "data"
    data.mkdir()
    (data / "notes.txt").write_text("Q3 notes: demand is flat in NA.\n")
    (data / ".env").write_text(f"AWS_SECRET_ACCESS_KEY={SECRET}\n")
    server = ["node", str(pkg / "dist" / "index.js"), str(data)]

    # 1. Pin what the real server advertises.
    with MCPClient(server) as c:
        info = c.init_result["serverInfo"]
        tools = c.list_tools()
    names = [t["name"] for t in tools]
    flagged = [t["name"] for t in tools if blocking(scan_tool(t, names))]

    # 2. A registry with the bench's identities plus this server, and a signed config.
    world = World(work / "deploy")
    fs_id = make_id("T1", "MCPFS")
    registry = world.registry_data(profile="extended")
    registry["entities"].append({"id": fs_id, "alias": "filesystem"})
    entries = []
    for t in tools:
        sec: dict = {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1",
                     "argumentGuards": {"paths": {"args": PATH_ARGS, "roots": [str(data)]}}}
        if t["name"] in READS:
            sec.update(flow={"produces": ["confidential"]}, dataPolicy={"requiresRedaction": True})
        if t["name"] in WRITES:
            sec["requiresApproval"] = True
        entries.append({"name": t["name"], "toolId": f"TOOL-FS-{t['name'].upper()}",
                        "definitionSha256": definition_hash(t), "security": sec})
    registry["servers"].append({"id": fs_id, "alias": "filesystem", "serverVersion": info["version"],
                                "artifactSha256": artifact_digest(pkg), "tools": entries})
    root = world.root
    (root / "registry-fs.yaml").write_text(yaml.safe_dump(registry, sort_keys=False))
    (root / "policy-fs.yaml").write_text(yaml.safe_dump({"flow": FLOW_POLICY}, sort_keys=False))
    world.sign(root / "registry-fs.yaml", root / "policy-fs.yaml")
    cfg = root / "smcp-fs.yaml"
    cfg.write_text(yaml.safe_dump({
        "gateway": {"id": world.gateway.id, "privateKey": "keys/gateway.pem", "server": fs_id,
                    "serverArtifact": str(pkg)},
        "registry": "registry-fs.yaml", "policy": "policy-fs.yaml",
        "audit": "audit/fs.jsonl", "auditCheckpoint": "witness/fs.json",
        "configSigner": {"id": world.governance.id, "publicKey": public_b64(world.governance.key)},
        "extensions": {"scanDescriptions": True, "scanOutputs": True, "enforceInputSchema": True},
    }, sort_keys=False))

    # 3. An SMCP session through the gateway.
    c = SMCPClient([sys.executable, "-m", "smcp_gateway", "run", "-c", str(cfg), "--", *server],
                   agent_id=world.report.id, agent_key=world.report.key, registry=world.registry(cfg),
                   delegation=[world.delegate(world.alice, world.report, [])])
    c.start()
    listed = c.list_tools()
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))

    check("all tools pinned and listed", len(listed) == len(tools) and not flagged,
          f"{len(listed)} of {len(tools)} listed, scanner flagged {len(flagged)}")
    r = c.call("read_text_file", {"path": str(data / "notes.txt")})
    check("read inside the root", "demand is flat" in text(r) and c.verify_response(r).ok, text(r)[:40])
    r = c.call("read_text_file", {"path": str(data / ".env")})
    check("secret redacted", SECRET not in text(r) and "REDACTED" in text(r), text(r).strip()[:60])
    r = c.call("read_text_file", {"path": str(data / ".." / ".." / "etc" / "passwd")})
    check("traversal denied by the gateway", text(r).startswith("SMCP denied"), text(r)[23:110])
    r = c.call("read_multiple_files", {"paths": [str(data / "notes.txt"), "/etc/hosts"]})
    check("one bad path in a list denied", text(r).startswith("SMCP denied"), text(r)[23:110])
    r = c.call("read_text_file", {})
    check("server's own schema enforced", "arguments.path is required" in text(r), text(r)[23:110])
    target = data / "out.txt"
    r = c.call("write_file", {"path": str(target), "content": "written through SMCP\n"})
    request = c.approval_request(r)
    check("write needs the user's approval", request is not None and not target.exists(),
          text(r)[23:110])
    if request:
        r = c.call("write_file", {"path": str(target), "content": "written through SMCP\n"},
                   approval=approve(request, world.alice.key))
        check("approved write lands", target.exists() and not r["result"].get("isError"), text(r)[:60])
    c.close()

    keys = world.registry(cfg).gateway_keys()
    checkpoint = json.loads((root / "witness" / "fs.json").read_text())
    v = verify_log(root / "audit" / "fs.jsonl", keys, checkpoint)
    check("audit log and checkpoint verify", v.ok, f"{v.entries} entries")

    print(f"server: {info['name']} {info['version']} ({pkg})")
    for name, ok, detail in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: {detail}")
    return 0 if all(ok for _, ok, _ in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
