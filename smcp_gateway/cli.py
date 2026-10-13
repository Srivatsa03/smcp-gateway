"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import __version__
from .audit import verify_log
from .context import issue_delegation
from .crypto import generate_key, load_key, public_b64, save_key
from .identity import ENTITY_TYPES, make_id, parse_id
from .registry import Registry, definition_hash


def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def cmd_run(args, server_cmd: list[str]) -> int:
    from .gateway import Gateway, serve_stdio
    if not server_cmd:
        print("smcp-gateway run: give the MCP server command after --", file=sys.stderr)
        return 2
    try:
        gateway = Gateway.from_config(Path(args.config))
    except (OSError, KeyError, ValueError) as e:
        print(f"smcp-gateway: cannot start from {args.config}: {e!r}", file=sys.stderr)
        return 2
    return serve_stdio(gateway, server_cmd)


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


def cmd_pin(args, server_cmd: list[str]) -> int:
    """Print registry entries for every tool a server lists, with definition hashes."""
    from .client import MCPClient
    if not server_cmd:
        print("smcp-gateway pin: give the MCP server command after --", file=sys.stderr)
        return 2
    with MCPClient(server_cmd) as client:
        version = (client.init_result or {}).get("serverInfo", {}).get("version")
        tools = client.list_tools()
    entry = {
        "id": args.server_id or "<T1 identity code of this server>",
        "serverVersion": version,
        "tools": [{"name": t["name"], "toolId": t["name"], "definitionSha256": definition_hash(t),
                   "security": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1"}}
                  for t in tools],
    }
    print(yaml.safe_dump({"servers": [entry]}, sort_keys=False))
    print(f"# pinned {len(tools)} tools. Review every description before you register them: "
          "pinning a poisoned description makes it trusted.", file=sys.stderr)
    return 0


def cmd_audit_verify(args, _) -> int:
    registry = Registry.load(Path(args.registry))
    keys = {e.id: e.public_key for e in registry.entities.values() if e.public_key}
    result = verify_log(Path(args.path), keys)
    if result.ok:
        print(f"ok: {result.entries} entries, hash chain and signatures verify")
        return 0
    print(f"TAMPERED at line {result.bad_line} (after {result.entries} good entries): {result.reason}")
    return 1


def cmd_init(args, _) -> int:
    from .bench.world import World
    world = World(Path(args.dir))
    config = world.write("default", legacy={"bindAgent": world.report.id, "assurance": "aal1"}
                         if args.legacy_bind else None)
    print(f"wrote a demo deployment to {world.root}")
    print(f"  config:   {config}")
    print(f"  registry: {config.parent / 'registry-default.yaml'}")
    print(f"  policy:   {config.parent / 'policy.yaml'}")
    print("run it in front of the demo server:")
    print(f"  smcp-gateway run -c {config} -- {' '.join(world.upstream_cmd())}")
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
    p.set_defaults(func=cmd_pin)

    p = sub.add_parser("audit", help="audit log tools")
    asub = p.add_subparsers(dest="audit_command", required=True)
    q = asub.add_parser("verify")
    q.add_argument("path")
    q.add_argument("--registry", required=True)
    q.set_defaults(func=cmd_audit_verify)

    p = sub.add_parser("init", help="write a demo deployment (keys, registry, policy, config)")
    p.add_argument("dir")
    p.add_argument("--legacy-bind", action="store_true",
                   help="let SMCP-unaware clients (e.g. Claude Code) through as the demo agent at aal1")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("bench", help="run the attack bench against the paper's 26 MCP risks")
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
