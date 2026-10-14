"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import __version__
from .audit import AuditIntegrityError, verify_log
from .context import issue_delegation
from .crypto import generate_key, load_key, public_b64, save_key
from .identity import ENTITY_TYPES, make_id, parse_id
from .launch import artifact_digest, sign_file
from .registry import Registry, definition_hash
from .scan import blocking, scan_tool


def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def _deployment(config: str):
    from .gateway import Deployment
    try:
        return Deployment.load(Path(config))
    except (OSError, KeyError, ValueError, AuditIntegrityError) as e:
        print(f"smcp-gateway: cannot start from {config}: {e}", file=sys.stderr)
        return None


def cmd_run(args, server_cmd: list[str]) -> int:
    from .gateway import Gateway, serve_stdio
    if not server_cmd:
        print("smcp-gateway run: give the MCP server command after --", file=sys.stderr)
        return 2
    deployment = _deployment(args.config)
    if deployment is None:
        return 2
    return serve_stdio(Gateway(deployment), server_cmd)


def cmd_serve(args, server_cmd: list[str]) -> int:
    from .httpserve import serve_http
    if not server_cmd:
        print("smcp-gateway serve: give the MCP server command after --", file=sys.stderr)
        return 2
    deployment = _deployment(args.config)
    if deployment is None:
        return 2
    return serve_http(deployment, server_cmd, host=args.host, port=args.port,
                      allowed_origins=tuple(args.allow_origin or ()), allowed_hosts=tuple(args.allow_host or ()),
                      max_sessions=args.max_sessions,
                      verbose=args.verbose)


def cmd_keygen(args, _) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"{out} exists; use --force to overwrite", file=sys.stderr)
        return 2
    key = generate_key()
    save_key(key, out)
    print(public_b64(key))
    return 0


def cmd_id_new(args, _) -> int:
    print(make_id(args.type, args.registrant, authority=args.authority, instance=args.instance))
    return 0


def cmd_id_check(args, _) -> int:
    try:
        ident = parse_id(args.code)
    except ValueError as e:
        print(f"invalid: {e}")
        return 1
    print(json.dumps({**ident.__dict__, "kind": ident.kind, "typeName": ident.type_name}, indent=2))
    return 0


def cmd_delegate(args, _) -> int:
    token = issue_delegation(load_key(Path(args.key)), args.delegator, args.delegate,
                             [s for s in args.scopes.split(",") if s], ttl_seconds=args.ttl)
    print(json.dumps(token, indent=2))
    return 0


def _list_tools(server_cmd: list[str], url: str | None):
    from .client import MCPClient
    with (MCPClient(url=url) if url else MCPClient(server_cmd)) as client:
        version = (client.init_result or {}).get("serverInfo", {}).get("version")
        return version, client.list_tools()


def _print_findings(tools: list[dict]) -> int:
    names = [t["name"] for t in tools]
    flagged = 0
    for t in tools:
        findings = scan_tool(t, names)
        if blocking(findings):
            flagged += 1
        for f in findings:
            print(f"# {t['name']}: [{f.severity}] {f}", file=sys.stderr)
    return flagged


def cmd_pin(args, server_cmd: list[str]) -> int:
    """Print registry entries for every tool a server lists, with definition hashes."""
    if not server_cmd:
        print("smcp-gateway pin: give the MCP server command after --", file=sys.stderr)
        return 2
    version, tools = _list_tools(server_cmd, None)
    entry = {
        "id": args.server_id or "<T1 identity code of this server>",
        "serverVersion": version,
    }
    if args.artifact:
        entry["artifactSha256"] = artifact_digest(Path(args.artifact))
    entry["tools"] = [{"name": t["name"], "toolId": t["name"], "definitionSha256": definition_hash(t),
                       "security": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1"}}
                      for t in tools]
    print(yaml.safe_dump({"servers": [entry]}, sort_keys=False))
    flagged = _print_findings(tools)
    print(f"# pinned {len(tools)} tools; the scanner flags {flagged}. Review every description before you "
          "register them: pinning a poisoned description makes it trusted.", file=sys.stderr)
    return 0


def cmd_scan(args, server_cmd: list[str]) -> int:
    """Scan a server's tool definitions for instruction-like text. Exit 1 if any is flagged."""
    if not server_cmd and not args.file:
        print("smcp-gateway scan: give the MCP server command after --, or --file tools.json", file=sys.stderr)
        return 2
    if args.file:
        data = json.loads(Path(args.file).read_text())
        tools = data["tools"] if isinstance(data, dict) else data
    else:
        _, tools = _list_tools(server_cmd, None)
    flagged = _print_findings(tools)
    print(f"{len(tools)} tools scanned, {flagged} flagged")
    return 1 if flagged else 0


def cmd_sign_config(args, _) -> int:
    key = load_key(Path(args.key))
    for f in args.files:
        out = sign_file(Path(f), key, args.signer, args.serial)
        print(f"signed {f} -> {out}")
    print(f"configSigner: {{id: {args.signer}, publicKey: {public_b64(key)}}}")
    return 0


def cmd_artifact(args, _) -> int:
    print(artifact_digest(Path(args.path)))
    return 0


def cmd_audit_verify(args, _) -> int:
    try:
        registry = Registry.load(Path(args.registry))
        checkpoint = json.loads(Path(args.checkpoint).read_text()) if args.checkpoint else None
        keys = registry.gateway_keys()
        if args.signer:
            keys = {k: v for k, v in keys.items() if k == args.signer}
            if not keys:
                print(f"smcp-gateway audit verify: {args.signer} is not a registered gateway", file=sys.stderr)
                return 2
        result = verify_log(Path(args.path), keys, checkpoint)
    except (OSError, ValueError) as e:
        print(f"smcp-gateway audit verify: {e}", file=sys.stderr)
        return 2
    if result.ok:
        extra = f", and the log holds all {checkpoint['count']} checkpointed entries" if checkpoint else ""
        print(f"ok: {result.entries} entries, hash chain and signatures verify{extra}")
        return 0
    where = f" at line {result.bad_line}" if result.bad_line else ""
    print(f"TAMPERED{where} (after {result.entries} good entries): {result.reason}")
    return 1


def cmd_audit_checkpoint(args, _) -> int:
    """Print a signed checkpoint of a log's current head, to hand to a witness."""
    deployment = _deployment(args.config)
    if deployment is None:
        return 2
    print(json.dumps(deployment.audit.head(), indent=2))
    return 0


def cmd_init(args, _) -> int:
    from .bench.world import World
    world = World(Path(args.dir))
    config = world.write("default", profile=args.profile,
                         legacy={"bindAgent": world.report.id, "assurance": "aal1"} if args.legacy_bind else None)
    print(f"wrote a demo deployment ({args.profile} profile) to {world.root}")
    print(f"  config:   {config}")
    print(f"  registry: {world.registry_path(config)}")
    print(f"  policy:   {world.policy_path(config)}")
    if args.profile == "extended":
        print("  the registry and policy are signed; after an edit, re-sign them with:")
        print(f"    smcp-gateway sign-config --key {world.root / 'keys' / 'governance.pem'} "
              f"--signer {world.governance.id} {world.registry_path(config)} {world.policy_path(config)}")
    print("run it in front of the demo server:")
    print(f"  smcp-gateway run -c {config} -- {' '.join(world.server_cmd(config))}")
    return 0


def cmd_bench(args, _) -> int:
    from .bench.run import main as bench_main
    return bench_main(json_out=args.json, markdown_out=args.markdown, calls=args.calls, keep=args.keep)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="smcp-gateway",
                                 description="Reference gateway for the Secure Model Context Protocol (SMCP).")
    ap.add_argument("--version", action="version", version=f"smcp-gateway {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="enforce SMCP in front of an MCP stdio server: run -c smcp.yaml -- CMD...")
    p.add_argument("-c", "--config", required=True)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("serve", help="serve the gateway over Streamable HTTP: serve -c smcp.yaml -- CMD...")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--allow-origin", action="append", help="an Origin header value to accept (repeatable)")
    p.add_argument("--allow-host", action="append",
                   help="a Host header name to accept (repeatable; default on loopback: loopback names)")
    p.add_argument("--max-sessions", type=int, default=64)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("keygen", help="write an Ed25519 private key (PEM) and print the public key")
    p.add_argument("out")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("id", help="create or check 32-character identity codes")
    idsub = p.add_subparsers(dest="id_command", required=True)
    q = idsub.add_parser("new")
    q.add_argument("--type", required=True, choices=sorted(ENTITY_TYPES))
    q.add_argument("--registrant", required=True)
    q.add_argument("--authority", default="SMCP")
    q.add_argument("--instance", default="1")
    q.set_defaults(func=cmd_id_new)
    q = idsub.add_parser("check")
    q.add_argument("code")
    q.set_defaults(func=cmd_id_check)

    p = sub.add_parser("delegate", help="sign a delegation token from a user (or agent) to an agent")
    p.add_argument("--key", required=True, help="the delegator's private key")
    p.add_argument("--delegator", required=True)
    p.add_argument("--delegate", required=True)
    p.add_argument("--scopes", default="")
    p.add_argument("--ttl", type=float, default=3600)
    p.set_defaults(func=cmd_delegate)

    p = sub.add_parser("pin", help="print registry entries with definition hashes: pin -- CMD...")
    p.add_argument("--server-id")
    p.add_argument("--artifact", help="also pin the SHA-256 of this server file or directory")
    p.set_defaults(func=cmd_pin)

    p = sub.add_parser("scan", help="scan tool definitions for instruction-like text: scan -- CMD...")
    p.add_argument("--file", help="a JSON file with a tools list instead of a live server")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("sign-config", help="sign registry or policy files for configSigner")
    p.add_argument("--key", required=True, help="the governance private key")
    p.add_argument("--signer", required=True, help="the signer's identity code")
    p.add_argument("--serial", type=int, help="the version number to sign (default: one more than the current "
                                              ".sig); the gateway refuses a lower serial than it has loaded")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_sign_config)

    p = sub.add_parser("artifact", help="print the SHA-256 of a server file or directory, for artifactSha256")
    p.add_argument("path")
    p.set_defaults(func=cmd_artifact)

    p = sub.add_parser("audit", help="audit log tools")
    asub = p.add_subparsers(dest="audit_command", required=True)
    q = asub.add_parser("verify")
    q.add_argument("path")
    q.add_argument("--registry", required=True)
    q.add_argument("--checkpoint", help="a signed checkpoint; also detects a truncated log")
    q.add_argument("--signer", help="accept only this gateway's signatures (default: any registered gateway)")
    q.set_defaults(func=cmd_audit_verify)
    q = asub.add_parser("checkpoint", help="print a signed checkpoint of the log's current head")
    q.add_argument("-c", "--config", required=True)
    q.set_defaults(func=cmd_audit_checkpoint)

    p = sub.add_parser("init", help="write a demo deployment (keys, registry, policy, config)")
    p.add_argument("dir")
    p.add_argument("--legacy-bind", action="store_true",
                   help="let SMCP-unaware clients (e.g. Claude Code) through as the demo agent at aal1")
    p.add_argument("--profile", choices=["paper", "extended"], default="paper",
                   help="the paper's design, or with this project's extensions")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("bench", help="run the attack bench (26 risks, both profiles) and the latency check")
    p.add_argument("--json")
    p.add_argument("--markdown")
    p.add_argument("--calls", type=int, default=300, help="calls per latency measurement")
    p.add_argument("--keep", help="keep the generated deployment in this directory")
    p.set_defaults(func=cmd_bench)
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    own, server_cmd = _split_command(argv)
    args = build_parser().parse_args(own)
    return args.func(args, server_cmd)
