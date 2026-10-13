"""The SMCP gateway: an enforcing MCP stdio proxy in front of an unmodified server.

The paper places the Policy Enforcement Point at the tool service. A gateway that
runs the real server as a subprocess gets the same position without changing the
server: every message to and from the server passes through here.

Per connection it does five things, mapped to the paper:

* 4.2  mutual authentication on ``initialize`` and a session key
* 4.1  registry vetting of every tool the server lists (unregistered, typosquat,
       name conflict, changed definition)
* 4.3  a security context built from verified facts for every ``tools/call``
* 4.4  a policy decision, then obligations applied to the result
* 4.5  a signed, hash-chained audit entry for every decision

It fails closed: a call without a valid session, envelope or registry entry is
answered with a signed denial and never reaches the server.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO

import yaml

from . import obligations as obl
from .audit import AuditLog
from .context import RISK, DelegationError, link, verify_chain
from .crypto import (b64d, canonical, digest, ephemeral, load_key, mac_ok, nonce,
                     public_b64, session_key, sign, verify)
from .policy import Decision, PolicyEngine
from .protocol import (CALL, HELLO, RESPONSE, SECURITY, SERVER_HELLO, VERSION,
                       new_ref, new_session_id, result_without_response, transcript)
from .registry import Registry, ToolRecord, definition_hash

NO_OBLIGATIONS = {"redactedFields": [], "truncated": False, "secretsRedacted": []}


class AuthError(Exception):
    pass


@dataclass
class Session:
    session_id: str
    key: bytes | None
    agent_id: str
    assurance: str
    chain: list[dict]
    scopes: list[str]
    authn_assertion_id: str
    expires_at: float
    last_seq: int = 0
    legacy: bool = False


def _iso(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _strip_smcp(meta: object) -> dict:
    """Drop any smcp/* keys. Used in both directions: SMCP credentials never reach
    the server, and a server cannot plant its own smcp/* fields."""
    if not isinstance(meta, dict):
        return {}
    return {k: v for k, v in meta.items() if not str(k).startswith("smcp/")}


def _take_smcp(msg: dict) -> dict:
    """Remove and return the smcp/* entries of a client request's params._meta."""
    params = msg.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("_meta"), dict):
        return {}
    meta = params["_meta"]
    taken = {k: v for k, v in meta.items() if str(k).startswith("smcp/")}
    rest = _strip_smcp(meta)
    if rest:
        params["_meta"] = rest
    else:
        params.pop("_meta")
    return taken


def _error(mid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


class Gateway:
    def __init__(
        self,
        *,
        gateway_id: str,
        key,
        server_id: str,
        registry: Registry,
        policy: PolicyEngine,
        audit: AuditLog,
        session_ttl: float = 900,
        clock_skew: float = 120,
        legacy: dict | None = None,
        clock: Callable[[], float] = time.time,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.gateway_id = gateway_id
        self.key = key
        self.server_id = server_id
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.session_ttl = session_ttl
        self.clock_skew = clock_skew
        self.legacy = legacy
        self.clock = clock
        self.log = log or (lambda m: print(f"smcp-gateway: {m}", file=sys.stderr, flush=True))
        self.session: Session | None = None
        self.vetted: dict[str, dict] = {}
        self.refused: str | None = None
        self._pending: dict[object, tuple[str, object]] = {}
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, path: Path, **kwargs) -> "Gateway":
        path = Path(path)
        base = path.parent
        cfg = yaml.safe_load(path.read_text()) or {}
        g = cfg.get("gateway") or {}

        def rel(p: str) -> Path:
            q = Path(p).expanduser()
            return q if q.is_absolute() else base / q

        key = load_key(rel(g["privateKey"]))
        registry = Registry.load(rel(cfg["registry"]))
        policy = PolicyEngine.load(rel(cfg["policy"])) if cfg.get("policy") else PolicyEngine()
        gw = registry.entity(g.get("id"))
        if gw is None or gw.public_key != public_b64(key):
            raise ValueError("gateway.id must be registered with the public key that matches gateway.privateKey")
        server = registry.entity(g.get("server"))
        if server is None or server.kind != "tool":
            raise ValueError("gateway.server must be a registered tool-type entity")
        legacy = g.get("legacyClients", "deny")
        return cls(
            gateway_id=gw.id,
            key=key,
            server_id=server.id,
            registry=registry,
            policy=policy,
            audit=AuditLog(rel(cfg.get("audit", "smcp-audit.jsonl")), key, gw.id),
            session_ttl=float(g.get("sessionTtlSeconds", 900)),
            clock_skew=float(g.get("clockSkewSeconds", 120)),
            legacy=legacy if isinstance(legacy, dict) else None,
            **kwargs,
        )

    # --- entry points ----------------------------------------------------------

    def from_client(self, msg: dict) -> tuple[list[dict], list[dict]]:
        """Handle one client message. Returns (to_server, to_client)."""
        with self._lock:
            smcp = _take_smcp(msg)
            method, mid = msg.get("method"), msg.get("id")
            if method == "initialize":
                return self._on_initialize(msg, smcp.get(HELLO))
            if method == "tools/list":
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                self._pending[mid] = ("tools/list", bool(params.get("cursor")))
                return [msg], []
            if method == "tools/call":
                return self._on_call(msg, smcp.get(CALL))
            return [msg], []

    def from_server(self, msg: dict) -> list[dict]:
        """Handle one server message. Returns the messages for the client."""
        with self._lock:
            mid = msg.get("id")
            if mid is None or "method" in msg:
                return [msg]  # notifications and server-to-client requests pass through
            pending = self._pending.pop(mid, None)
            if pending is None:
                return [msg]
            kind, state = pending
            if kind == "initialize":
                return [self._finish_initialize(msg, state)]
            if kind == "tools/list":
                return [self._filter_tools(msg, state)]
            if kind == "tools/call":
                return [self._finish_call(msg, state)]
            return [msg]

    # --- handshake ---------------------------------------------------------------

    def _on_initialize(self, msg: dict, hello: object) -> tuple[list[dict], list[dict]]:
        mid = msg.get("id")
        state = None
        if hello is not None:
            try:
                state = (hello, *self._accept_hello(hello))
            except (AuthError, DelegationError) as e:
                agent = hello.get("agentId") if isinstance(hello, dict) else None
                self.audit.append("AUTHN_FAILED", agentId=agent, peerId=self.server_id, reason=str(e))
                self.log(f"authentication failed: {e}")
                return [], [_error(mid, -32001, f"SMCP authentication failed: {e}")]
        self._pending[mid] = ("initialize", state)
        return [msg], []

    def _accept_hello(self, hello: object):
        if not isinstance(hello, dict):
            raise AuthError("smcp/hello is not an object")
        body = {k: v for k, v in hello.items() if k != "signature"}
        if body.get("version") != VERSION:
            raise AuthError(f"unsupported SMCP version {body.get('version')!r}")
        agent = self.registry.active(body.get("agentId"))
        if agent is None:
            raise AuthError(f"{self.registry.label(body.get('agentId'))} is not an active registered identity")
        if agent.kind != "agent":
            raise AuthError("only an agent identity can open an SMCP session")
        if not verify(agent.public_key, body, hello.get("signature")):
            raise AuthError(f"the hello signature does not verify against the registered key of {agent.label}")
        now = self.clock()
        ts = body.get("timestamp")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.clock_skew:
            raise AuthError("the hello timestamp is outside the allowed clock skew")
        n = body.get("nonce")
        self._nonces = {k: t for k, t in self._nonces.items() if now - t <= 2 * self.clock_skew}
        if not isinstance(n, str) or n in self._nonces:
            raise AuthError("the hello nonce is missing or was already used")
        self._nonces[n] = now
        try:
            if len(b64d(body.get("ephemeralKey") or "")) != 32:
                raise ValueError
        except ValueError:
            raise AuthError("the hello carries no valid X25519 ephemeral key") from None
        chain, scopes = verify_chain(body.get("delegation") or [], agent, self.registry,
                                     now=now, skew=self.clock_skew)
        return agent, chain, scopes

    def _finish_initialize(self, msg: dict, state) -> dict:
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        if isinstance(result.get("_meta"), dict):
            result["_meta"] = _strip_smcp(result["_meta"]) or None
            if result["_meta"] is None:
                result.pop("_meta")
        now = self.clock()

        pinned = (self.registry.servers.get(self.server_id) or {}).get("serverVersion")
        reported = (result.get("serverInfo") or {}).get("version")
        if pinned and reported != pinned:
            self.refused = f"the upstream server reports version {reported!r} and the registry pins {pinned!r}"
            self.audit.append("SERVER_REJECTED", peerId=self.server_id, reason=self.refused)
            self.log(self.refused)
            return _error(msg.get("id"), -32002, f"SMCP refused the server: {self.refused}")

        if state is None:
            bind = (self.legacy or {}).get("bindAgent")
            agent = self.registry.active(bind) if bind else None
            if agent is not None:
                self.session = Session(
                    session_id=new_session_id(), key=None, agent_id=agent.id,
                    assurance=self.legacy.get("assurance", "aal1"), chain=[link(agent)],
                    scopes=list(self.legacy.get("scopes") or []), authn_assertion_id=new_ref("AA"),
                    expires_at=now + self.session_ttl, legacy=True)
                self.audit.append("SESSION_ESTABLISHED", mode="legacy-bind", sessionId=self.session.session_id,
                                  agentId=agent.id, assurance=self.session.assurance, peerId=self.server_id)
            return msg

        hello, agent, chain, scopes = state
        eph, eph_pub = ephemeral()
        body = {
            "version": VERSION,
            "gatewayId": self.gateway_id,
            "peerId": self.server_id,
            "sessionId": new_session_id(),
            "authnAssertionId": new_ref("AA"),
            "assurance": agent.assurance,
            "delegatorChain": chain,
            "scopes": scopes,
            "expiresAt": now + self.session_ttl,
            "nonce": nonce(),
            "ephemeralKey": eph_pub,
            "helloDigest": digest(hello),
        }
        self.session = Session(
            session_id=body["sessionId"],
            key=session_key(eph, hello["ephemeralKey"], transcript(hello, body)),
            agent_id=agent.id, assurance=agent.assurance, chain=chain, scopes=scopes,
            authn_assertion_id=body["authnAssertionId"], expires_at=body["expiresAt"])
        result.setdefault("_meta", {})[SERVER_HELLO] = {**body, "signature": sign(self.key, body)}
        self.audit.append("SESSION_ESTABLISHED", mode="smcp", sessionId=body["sessionId"],
                          authnAssertionId=body["authnAssertionId"], agentId=agent.id,
                          assurance=agent.assurance, delegatorChain=_chain_summary(chain),
                          scopes=scopes, peerId=self.server_id)
        return msg

    # --- tool listing ---------------------------------------------------------------

    def _filter_tools(self, msg: dict, paged: bool) -> dict:
        if self.refused:
            return _error(msg.get("id"), -32002, f"SMCP refused the server: {self.refused}")
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        self.registry.reload_if_changed()
        kept, vetted = [], {}
        for tool in result.get("tools") or []:
            record, reason = self.registry.vet(self.server_id, tool)
            if record is None:
                self.audit.append("TOOL_REJECTED", sessionId=self.session.session_id if self.session else None,
                                  peerId=self.server_id, toolName=tool.get("name"), reason=reason,
                                  definitionSha256=definition_hash(tool))
                self.log(f"hid tool {tool.get('name')!r}: {reason}")
                continue
            shown = copy.deepcopy(tool)
            shown["_meta"] = {**_strip_smcp(shown.get("_meta")),
                              SECURITY: {"toolId": record.tool_id, "toolVersion": record.version,
                                         **record.security}}
            kept.append(shown)
            vetted[record.name] = tool
        if paged:
            self.vetted.update(vetted)
        else:
            self.vetted = vetted
        result["tools"] = kept
        return msg

    # --- tool calls -----------------------------------------------------------------

    def _on_call(self, msg: dict, envelope: object) -> tuple[list[dict], list[dict]]:
        mid = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        name = params.get("name")
        args = params.get("arguments")
        args = {} if args is None else args

        self.registry.reload_if_changed()
        self.policy.reload_if_changed()
        ctx, problem = self._authenticate_call(envelope, name, args, self.clock())
        record: ToolRecord | None = None
        if problem is None and not isinstance(args, dict):
            problem = "tools/call arguments must be an object"
        if problem is None:
            listed = self.vetted.get(name)
            if listed is not None:
                record, _ = self.registry.vet(self.server_id, listed)  # re-vet against today's registry
            decision = self.policy.evaluate(ctx, record)
        else:
            decision = Decision("DENY", [problem], policy_refs=["SMCP.AUTHN"])
        if not decision.permitted:
            self.log(f"denied {name!r}: {'; '.join(decision.reasons)}")
            return [], [self._deny(mid, name, ctx, record, decision, args if isinstance(args, dict) else {})]
        self._pending[mid] = ("tools/call", (ctx, decision, record, args, name))
        return [msg], []

    def _authenticate_call(self, envelope: object, name: object, args: object, now: float):
        s = self.session
        if self.refused:
            return {"peerId": self.server_id, "toolCallId": new_ref("TC")}, self.refused
        if s is None and any(kind == "initialize" for kind, _ in self._pending.values()):
            return ({"peerId": self.server_id, "toolCallId": new_ref("TC")},
                    "the call arrived before the initialize handshake finished")
        if s is None:
            return ({"peerId": self.server_id, "toolCallId": new_ref("TC")},
                    "no authenticated SMCP session on this connection (the client sent no smcp/hello)")
        ctx = {
            "sessionId": s.session_id,
            "callChainId": None,
            "taskId": None,
            "toolCallId": new_ref("TC"),
            "callerAgentId": s.agent_id,
            "peerId": self.server_id,
            "authnAssertionId": s.authn_assertion_id,
            "assurance": s.assurance,
            "delegatorChain": s.chain,
            "scopes": s.scopes,
            "riskLevel": "low",
            "dataSensitivity": None,
        }
        if now > s.expires_at:
            return ctx, "the SMCP session has expired; open a new session"
        if self.registry.active(s.agent_id) is None:
            return ctx, f"agent {self.registry.label(s.agent_id)} is revoked or suspended in the registry"
        for entry in s.chain:
            if self.registry.active(entry["subjectId"]) is None:
                return ctx, (f"{entry.get('alias') or entry['subjectId']} in the delegation chain is "
                             f"revoked or suspended in the registry")
        if s.legacy:
            return ctx, None
        if not isinstance(envelope, dict):
            return ctx, "the call carries no smcp/call envelope"
        body = {k: v for k, v in envelope.items() if k != "mac"}
        if body.get("sessionId") != s.session_id:
            return ctx, "the envelope is bound to a different session"
        if body.get("tool") != name or body.get("argsDigest") != digest(args):
            return ctx, "the envelope does not match this call's tool name or arguments"
        if not mac_ok(s.key, body, envelope.get("mac")):
            return ctx, "the envelope MAC does not verify with this session's key"
        seq = body.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= s.last_seq:
            return ctx, f"replayed or out-of-order call (seq {seq!r}, last accepted {s.last_seq})"
        ts = body.get("timestamp")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.clock_skew:
            return ctx, "the envelope timestamp is outside the allowed clock skew"
        risk = body.get("riskLevel") or "low"
        if risk not in RISK:
            return ctx, f"unknown riskLevel {risk!r}"
        s.last_seq = seq
        ctx.update(
            riskLevel=risk,
            callChainId=body.get("callChainId"),
            taskId=body.get("taskId"),
            toolCallId=body.get("toolCallId") or ctx["toolCallId"],
            dataSensitivity=body.get("dataSensitivity"),
        )
        return ctx, None

    def _deny(self, mid, name, ctx, record, decision: Decision, args: dict) -> dict:
        result = {
            "content": [{"type": "text", "text": "SMCP denied this call: " + "; ".join(decision.reasons)}],
            "isError": True,
        }
        ref = self._audit_call(ctx, name, record, decision, "DENIED", args, result)
        result["_meta"] = {RESPONSE: self._sign_response(ctx, record, decision, NO_OBLIGATIONS,
                                                         "DENIED", ref, result)}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _finish_call(self, msg: dict, state) -> dict:
        ctx, decision, record, args, name = state
        result = msg.get("result")
        if not isinstance(result, dict):
            self._audit_call(ctx, name, record, decision, "UPSTREAM_ERROR", args, None)
            return msg
        if "_meta" in result:
            cleaned = _strip_smcp(result.get("_meta"))
            if cleaned:
                result["_meta"] = cleaned
            else:
                result.pop("_meta")
        clean, applied = obl.apply(result, decision.obligations)
        action = "TOOL_ERROR" if clean.get("isError") else "SUCCESS"
        ref = self._audit_call(ctx, name, record, decision, action, args, clean, applied)
        signed = self._sign_response(ctx, record, decision, applied, action, ref, clean)
        clean["_meta"] = {**(clean.get("_meta") or {}), RESPONSE: signed}
        msg["result"] = clean
        return msg

    def _audit_call(self, ctx, name, record, decision, action, args, result, applied=None) -> str:
        chain = ctx.get("delegatorChain") or []
        user = next((c for c in chain if c.get("subjectType") == "user"), None)
        req = (record.security.get("auditRequirement") if record else None) or {}
        fields = dict(
            callChainId=ctx.get("callChainId"),
            sessionId=ctx.get("sessionId"),
            taskId=ctx.get("taskId"),
            toolCallId=ctx.get("toolCallId"),
            agentId=ctx.get("callerAgentId"),
            userId=user.get("subjectId") if user else None,
            delegatorChain=_chain_summary(chain) or None,
            toolName=name,
            toolId=record.tool_id if record else None,
            peerId=self.server_id,
            actionCode=action,
            policyDecision=decision.to_dict(),
            obligationsApplied=applied if applied and applied != NO_OBLIGATIONS else None,
            requestedSensitivityLevel=ctx.get("dataSensitivity"),
            appliedSensitivityLevel=record.sensitivity if record else None,
            riskLevel=ctx.get("riskLevel"),
            registryHash=self.registry.fingerprint,
            policyHash=self.policy.fingerprint,
        )
        if req.get("recordParamsSummary", True):
            fields["paramsSummary"] = {"argsDigest": digest(args), "keys": sorted(args)}
        if result is not None and req.get("recordResultSummary", True):
            fields["resultSummary"] = {"resultDigest": digest(result_without_response(result)),
                                       "bytes": len(canonical(result)),
                                       "isError": bool(result.get("isError"))}
        return self.audit.append("TOOL_CALL", **fields)

    def _sign_response(self, ctx, record, decision, applied, action, ref, result) -> dict:
        body = {
            "type": "SMCP.ToolCallResponse",
            "toolCallId": ctx.get("toolCallId"),
            "sessionId": ctx.get("sessionId"),
            "actionCode": action,
            "appliedSecurity": {
                "appliedSensitivityLevel": record.sensitivity if record else None,
                "appliedDataPolicy": record.security.get("dataPolicy") if record else None,
                "obligations": decision.obligations,
                "redactedFields": applied["redactedFields"],
                "secretsRedacted": applied["secretsRedacted"],
                "truncated": applied["truncated"],
                "requiresStepUpForNext": decision.requires_step_up,
            },
            "reasons": decision.reasons,
            "policyRefs": decision.policy_refs,
            "auditRef": ref,
            "resultDigest": digest(result_without_response(result)),
            "signedBy": self.gateway_id,
            "signedAt": _iso(self.clock()),
            "hashAlgo": "SHA-256",
        }
        return {**body, "signature": sign(self.key, body)}


def _chain_summary(chain: list[dict]) -> list[dict]:
    return [{"subjectId": c["subjectId"], "subjectType": c["subjectType"], "role": c.get("role")}
            for c in chain]


# --- stdio transport ---------------------------------------------------------------


def serve_stdio(
    gateway: Gateway,
    server_command: list[str],
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run ``server_command`` as a subprocess and enforce SMCP on everything between."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    proc = subprocess.Popen(server_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, bufsize=1)
    assert proc.stdin and proc.stdout
    out_lock = threading.Lock()

    def to_client(msgs: list[dict]) -> None:
        with out_lock:
            for m in msgs:
                stdout.write(json.dumps(m) + "\n")
            stdout.flush()

    def to_server(msgs: list[dict]) -> None:
        for m in msgs:
            proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()

    def pump() -> None:
        try:
            for line in stdin:
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    to_client([_error(None, -32700, "parse error")])
                    continue
                if not isinstance(msg, dict):
                    to_client([_error(None, -32600, "SMCP gateway does not accept JSON-RPC batches")])
                    continue
                try:
                    up, down = gateway.from_client(msg)
                except Exception as e:  # fail closed: never forward what we could not check
                    gateway.log(f"internal error on client message: {e!r}")
                    up, down = [], ([_error(msg["id"], -32603, f"SMCP gateway error: {e}")]
                                    if "id" in msg else [])
                to_server(up)
                to_client(down)
        except (BrokenPipeError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    threading.Thread(target=pump, daemon=True).start()
    for line in proc.stdout:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            down = gateway.from_server(msg)
        except Exception as e:
            gateway.log(f"internal error on server message: {e!r}")
            down = [_error(msg.get("id"), -32603, f"SMCP gateway error: {e}")] if "id" in msg else []
        to_client(down)
    return proc.wait()
