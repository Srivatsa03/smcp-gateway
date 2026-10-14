"""The SMCP gateway: an enforcing MCP proxy in front of an unmodified server.

The paper places the Policy Enforcement Point at the tool service. A gateway that
runs the real server as a subprocess gets the same position without changing the
server: every message to and from the server passes through here.

Per session it does five things, mapped to the paper:

* 4.2  mutual authentication on ``initialize`` and a session key
* 4.1  registry vetting of every tool the server lists (unregistered, typosquat,
       name conflict, changed definition)
* 4.3  a security context built from verified facts for every ``tools/call``
* 4.4  a policy decision, then obligations applied to the result
* 4.5  a signed, hash-chained audit entry for every decision

and, where configured, this project's extensions: description scanning,
argument guards, session flow labels with a gateway-assessed risk level, user
approval for high-stakes calls, output scanning, server artifact pinning,
signed config, and a policy on server-to-client requests.

It fails closed: a call without a valid session, envelope or registry entry is
answered with a signed denial and never reaches the server.

One ``Gateway`` object serves one MCP session. ``Deployment`` holds what all
sessions share (keys, registry, policy, audit log, handshake nonce cache), so the
HTTP transport can run many sessions against one deployment.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

import yaml

from . import approval as _approval
from . import obligations as obl
from .audit import AuditLog
from .context import RISK, DelegationError, link, rank, token_id, verify_chain
from .crypto import (b64d, canonical, digest, ephemeral, load_key, mac_ok, nonce,
                     public_b64, session_key, sign, verify)
from .flow import FlowState
from .launch import FileVerifier, check_artifact
from .policy import Decision, PolicyEngine
from .protocol import (APPROVAL, CALL, HELLO, RESPONSE, SECURITY, SERVER_HELLO, VERSION,
                       new_ref, new_session_id, result_without_response, transcript)
from .registry import Registry, ToolRecord, definition_hash

NO_OBLIGATIONS = obl.empty_applied()

# client capabilities a server needs before it may send these requests
SERVER_REQUEST_CAPABILITY = {"sampling/createMessage": "sampling", "elicitation/create": "elicitation",
                             "roots/list": "roots"}
# client requests that need an established session, like tools/call
SESSION_GATED = ("resources/", "prompts/", "completion/")


class AuthError(Exception):
    pass


class NonceCache:
    """Handshake nonces seen recently. Shared by every session of a deployment."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, value: str, now: float, window: float) -> bool:
        """Record ``value``. False if it was already seen within the window."""
        with self._lock:
            self._seen = {k: t for k, t in self._seen.items() if now - t <= window}
            if value in self._seen:
                return False
            self._seen[value] = now
            return True


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
    token_ids: list[str] = field(default_factory=list)
    last_seq: int = 0
    legacy: bool = False
    flow: FlowState = field(default_factory=FlowState)
    pending_approvals: dict[str, dict] = field(default_factory=dict)

    @property
    def approver(self) -> dict | None:
        """The user who can approve calls for this session: the root of the chain."""
        root = self.chain[0] if self.chain else None
        return root if root and root.get("subjectType") == "user" else None


@dataclass
class Deployment:
    gateway_id: str
    key: object
    server_id: str
    registry: Registry
    policy: PolicyEngine
    audit: AuditLog
    session_ttl: float = 900
    clock_skew: float = 120
    legacy: dict | None = None
    server_artifact: Path | None = None
    scan_descriptions: bool = False
    scan_outputs: bool = False
    enforce_input_schema: bool = False
    approval_ttl: float = 300
    verifier: FileVerifier | None = None
    nonces: NonceCache = field(default_factory=NonceCache)

    @classmethod
    def load(cls, path: Path) -> "Deployment":
        path = Path(path)
        base = path.parent
        cfg = yaml.safe_load(path.read_text()) or {}
        g = cfg.get("gateway") or {}

        def rel(p: str) -> Path:
            q = Path(p).expanduser()
            return q if q.is_absolute() else base / q

        key = load_key(rel(g["privateKey"]))
        audit = AuditLog(rel(cfg.get("audit", "smcp-audit.jsonl")), key, str(g.get("id")),
                         checkpoint=rel(cfg["auditCheckpoint"]) if cfg.get("auditCheckpoint") else None,
                         checkpoint_every=int(cfg.get("auditCheckpointEvery", 1)),
                         fsync=bool(cfg.get("auditFsync", False)))
        signer = cfg.get("configSigner")
        verifier = FileVerifier(signer["id"], signer["publicKey"]) if signer else None
        if verifier is not None:  # serials loaded before this start: no rollback across restarts
            for e in audit.entries("CONFIG_LOADED"):
                verifier.seed(e["file"], e["serial"])
        registry = Registry.load(rel(cfg["registry"]), verifier)
        policy = PolicyEngine.load(rel(cfg["policy"]), verifier) if cfg.get("policy") else PolicyEngine()
        gw = registry.entity(g.get("id"))
        if gw is None or gw.public_key != public_b64(key):
            raise ValueError("gateway.id must be registered with the public key that matches gateway.privateKey")
        server = registry.entity(g.get("server"))
        if server is None or server.kind != "tool":
            raise ValueError("gateway.server must be a registered tool-type entity")
        legacy = g.get("legacyClients", "deny")
        ext = cfg.get("extensions") or {}
        deployment = cls(
            gateway_id=gw.id,
            key=key,
            server_id=server.id,
            registry=registry,
            policy=policy,
            audit=audit,
            session_ttl=float(g.get("sessionTtlSeconds", 900)),
            clock_skew=float(g.get("clockSkewSeconds", 120)),
            legacy=legacy if isinstance(legacy, dict) else None,
            server_artifact=rel(g["serverArtifact"]) if g.get("serverArtifact") else None,
            scan_descriptions=bool(ext.get("scanDescriptions", False)),
            scan_outputs=bool(ext.get("scanOutputs", False)),
            enforce_input_schema=bool(ext.get("enforceInputSchema", False)),
            approval_ttl=float(ext.get("approvalTtlSeconds", 300)),
            verifier=verifier,
        )
        for watched in (registry, policy):
            deployment.config_loaded(watched)
        return deployment

    def config_loaded(self, watched) -> None:
        """Audit a signed registry or policy version that is now in force."""
        if self.verifier is None or watched.path is None:
            return
        k = FileVerifier.key(watched.path)
        self.audit.append("CONFIG_LOADED", file=k, serial=self.verifier.serials.get(k),
                          fingerprint=watched.fingerprint)

    def check_launch(self) -> str | None:
        """None if the server may be started, else why not. Audited when refused."""
        pinned = (self.registry.servers.get(self.server_id) or {}).get("artifactSha256")
        problem = check_artifact(self.server_artifact, pinned)
        if problem:
            self.audit.append("SERVER_REJECTED", peerId=self.server_id, reason=problem)
        return problem


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


def _clean_result_meta(result: dict) -> None:
    if "_meta" in result:
        cleaned = _strip_smcp(result.get("_meta"))
        if cleaned:
            result["_meta"] = cleaned
        else:
            result.pop("_meta")


def _without_meta(params: dict) -> dict:
    return {k: v for k, v in params.items() if k != "_meta"}


def _error(mid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _result_text(result: dict) -> str:
    parts = []
    for b in result.get("content") or []:
        if isinstance(b, dict) and b.get("type") == "text":
            parts.append(str(b.get("text", "")))
        elif isinstance(b, dict) and b.get("type") == "resource" and isinstance(b.get("resource"), dict):
            parts.append(str(b["resource"].get("text", "")))
    if "structuredContent" in result:
        parts.append(json.dumps(result["structuredContent"]))
    return "\n".join(parts)


class Gateway:
    def __init__(
        self,
        deployment: Deployment,
        *,
        clock: Callable[[], float] = time.time,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.d = deployment
        self.clock = clock
        self.log = log or (lambda m: print(f"smcp-gateway: {m}", file=sys.stderr, flush=True))
        self.session: Session | None = None
        self.vetted: dict[str, dict] = {}
        self.refused: str | None = None
        self._pending: dict[object, tuple[str, object]] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, path: Path, **kwargs) -> "Gateway":
        return cls(Deployment.load(Path(path)), **kwargs)

    # shorthands used throughout
    @property
    def registry(self) -> Registry:
        return self.d.registry

    @property
    def policy(self) -> PolicyEngine:
        return self.d.policy

    @property
    def audit(self) -> AuditLog:
        return self.d.audit

    @property
    def server_id(self) -> str:
        return self.d.server_id

    def _sid(self) -> str | None:
        return self.session.session_id if self.session else None

    def _reload(self) -> None:
        """Pick up registry and policy edits; audit any that were rejected."""
        for watched in (self.registry, self.policy):
            if watched.reload_if_changed():
                self.d.config_loaded(watched)
            problem = watched.pop_rejection()
            if problem:
                self.audit.append("CONFIG_REJECTED", sessionId=self._sid(), reason=problem)
                self.log(f"kept the last good config: {problem}")

    # --- entry points ----------------------------------------------------------

    def from_client(self, msg: dict) -> tuple[list[dict], list[dict]]:
        """Handle one client message. Returns (to_server, to_client)."""
        with self._lock:
            smcp = _take_smcp(msg)
            method, mid = msg.get("method"), msg.get("id")
            if method is None or "id" not in msg:
                return [msg], []  # a notification, or the client's answer to a server request
            # Every forwarded request is tracked by id, so each response is matched to
            # the request it answers. A reused id would let a second response skip
            # enforcement, so it is refused.
            if not isinstance(mid, (str, int)) or isinstance(mid, bool):
                return [], [_error(None, -32600, "SMCP gateway: a request id must be a string or an integer")]
            if mid in self._pending:
                return [], [_error(mid, -32600, f"SMCP gateway: request id {mid!r} is already in use")]
            if method == "initialize":
                return self._on_initialize(msg, smcp.get(HELLO))
            if method == "tools/list":
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                self._pending[mid] = ("tools/list", bool(params.get("cursor")))
                return [msg], []
            if method == "tools/call":
                return self._on_call(msg, smcp)
            if isinstance(method, str) and method.startswith(SESSION_GATED):
                return self._on_gated(msg, smcp)
            self._pending[mid] = ("passthrough", method)
            return [msg], []

    def _on_gated(self, msg: dict, smcp: dict) -> tuple[list[dict], list[dict]]:
        """resources/*, prompts/*, completion/*: they carry content to the model, so
        they need a session and, for SMCP sessions, a sealed envelope like a tool call."""
        method, mid = msg["method"], msg["id"]
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        self._reload()
        _, problem = self._authenticate_call(smcp.get(CALL), method, _without_meta(params), None, self.clock())
        if problem:
            self.audit.append("REQUEST_DENIED", sessionId=self._sid(), method=method, peerId=self.server_id,
                              reason=problem)
            return [], [_error(mid, -32001, f"SMCP denied {method}: {problem}")]
        self._pending[mid] = (method, params)
        return [msg], []

    def handle_server(self, msg: dict) -> tuple[list[dict], list[dict]]:
        """Handle one server message. Returns (to_client, to_server)."""
        with self._lock:
            mid = msg.get("id")
            if "method" in msg:
                if mid is None:
                    return [msg], []  # notification
                return self._on_server_request(msg)
            pending = self._pending.pop(mid, None) if isinstance(mid, (str, int)) else None
            if pending is None:
                if mid is None:
                    return [msg], []  # an error about a message the server could not parse
                self.log(f"dropped a response to request id {mid!r}, which is not pending")
                return [], []
            kind, state = pending
            if kind == "passthrough":
                return [msg], []
            if kind == "initialize":
                return [self._finish_initialize(msg, state)], []
            if kind == "tools/list":
                return [self._filter_tools(msg, state)], []
            if kind == "tools/call":
                return [self._finish_call(msg, state)], []
            return [self._finish_content(msg, kind, state)], []

    def from_server(self, msg: dict) -> list[dict]:
        """Handle one server message. Returns the messages for the client (the
        in-process API; transports use :meth:`handle_server`)."""
        return self.handle_server(msg)[0]

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
        # Hide client capabilities the server may not use, so a well-behaved
        # server never asks for sampling or elicitation it would be refused.
        params = msg.get("params")
        caps = params.get("capabilities") if isinstance(params, dict) else None
        if isinstance(caps, dict):
            allowed = self.registry.server_requests(self.server_id)
            for method, cap in SERVER_REQUEST_CAPABILITY.items():
                if method not in allowed:
                    caps.pop(cap, None)
        self._pending[mid] = ("initialize", state)
        return [msg], []

    def _accept_hello(self, hello: object):
        if not isinstance(hello, dict):
            raise AuthError("smcp/hello is not an object")
        body = {k: v for k, v in hello.items() if k != "signature"}
        if body.get("version") != VERSION:
            raise AuthError(f"unsupported SMCP version {body.get('version')!r}")
        if "audience" in body and body["audience"] != self.d.gateway_id:
            raise AuthError(f"the hello is addressed to {body['audience']}, not to this gateway")
        self._reload()
        agent = self.registry.active(body.get("agentId"))
        if agent is None:
            raise AuthError(f"{self.registry.label(body.get('agentId'))} is not an active registered identity")
        if agent.kind != "agent":
            raise AuthError("only an agent identity can open an SMCP session")
        if not verify(agent.public_key, body, hello.get("signature")):
            raise AuthError(f"the hello signature does not verify against the registered key of {agent.label}")
        now = self.clock()
        ts = body.get("timestamp")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.d.clock_skew:
            raise AuthError("the hello timestamp is outside the allowed clock skew")
        n = body.get("nonce")
        if not isinstance(n, str) or not self.d.nonces.add(n, now, 2 * self.d.clock_skew):
            raise AuthError("the hello nonce is missing or was already used")
        try:
            if len(b64d(body.get("ephemeralKey") or "")) != 32:
                raise ValueError
        except ValueError:
            raise AuthError("the hello carries no valid X25519 ephemeral key") from None
        tokens = body.get("delegation") or []
        chain, scopes = verify_chain(tokens, agent, self.registry, now=now, skew=self.d.clock_skew)
        return agent, chain, scopes, [token_id(t) for t in tokens]

    def _finish_initialize(self, msg: dict, state) -> dict:
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        _clean_result_meta(result)
        now = self.clock()

        pinned = (self.registry.servers.get(self.server_id) or {}).get("serverVersion")
        reported = (result.get("serverInfo") or {}).get("version")
        if pinned and reported != pinned:
            self.refused = f"the upstream server reports version {reported!r} and the registry pins {pinned!r}"
            self.audit.append("SERVER_REJECTED", peerId=self.server_id, reason=self.refused)
            self.log(self.refused)
            return _error(msg.get("id"), -32002, f"SMCP refused the server: {self.refused}")

        if state is None:
            bind = (self.d.legacy or {}).get("bindAgent")
            agent = self.registry.active(bind) if bind else None
            if agent is not None:
                self.session = Session(
                    session_id=new_session_id(), key=None, agent_id=agent.id,
                    assurance=self.d.legacy.get("assurance", "aal1"), chain=[link(agent)],
                    scopes=list(self.d.legacy.get("scopes") or []), authn_assertion_id=new_ref("AA"),
                    expires_at=now + self.d.session_ttl, legacy=True)
                self.audit.append("SESSION_ESTABLISHED", mode="legacy-bind", sessionId=self.session.session_id,
                                  agentId=agent.id, assurance=self.session.assurance, peerId=self.server_id)
            return msg

        hello, agent, chain, scopes, token_ids = state
        eph, eph_pub = ephemeral()
        body = {
            "version": VERSION,
            "gatewayId": self.d.gateway_id,
            "peerId": self.server_id,
            "sessionId": new_session_id(),
            "authnAssertionId": new_ref("AA"),
            "assurance": agent.assurance,
            "delegatorChain": chain,
            "scopes": scopes,
            "expiresAt": now + self.d.session_ttl,
            "nonce": nonce(),
            "ephemeralKey": eph_pub,
            "helloDigest": digest(hello),
        }
        self.session = Session(
            session_id=body["sessionId"],
            key=session_key(eph, hello["ephemeralKey"], transcript(hello, body)),
            agent_id=agent.id, assurance=agent.assurance, chain=chain, scopes=scopes,
            authn_assertion_id=body["authnAssertionId"], expires_at=body["expiresAt"],
            token_ids=token_ids)
        result.setdefault("_meta", {})[SERVER_HELLO] = {**body, "signature": sign(self.d.key, body)}
        self.audit.append("SESSION_ESTABLISHED", mode="smcp", sessionId=body["sessionId"],
                          authnAssertionId=body["authnAssertionId"], agentId=agent.id,
                          assurance=agent.assurance, delegatorChain=_chain_summary(chain),
                          scopes=scopes, peerId=self.server_id)
        return msg

    # --- server-to-client requests ------------------------------------------------------

    def _on_server_request(self, msg: dict) -> tuple[list[dict], list[dict]]:
        method = msg.get("method")
        if method in self.registry.server_requests(self.server_id):
            return [msg], []
        reason = (f"the server sent a {method} request and the registry does not allow it for this server "
                  f"(allowServerRequests)")
        self.audit.append("SERVER_REQUEST_DENIED", sessionId=self._sid(), peerId=self.server_id,
                          method=method, reason=reason)
        self.log(f"blocked server request {method!r}")
        return [], [_error(msg.get("id"), -32001, f"SMCP gateway: {reason}")]

    # --- tool listing ---------------------------------------------------------------

    def _filter_tools(self, msg: dict, paged: bool) -> dict:
        if self.refused:
            return _error(msg.get("id"), -32002, f"SMCP refused the server: {self.refused}")
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        self._reload()
        kept, vetted = [], {}
        for tool in result.get("tools") or []:
            record, reason = self.registry.vet(self.server_id, tool, scan=self.d.scan_descriptions)
            if record is None:
                self.audit.append("TOOL_REJECTED", sessionId=self._sid(),
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

    def _on_call(self, msg: dict, smcp: dict) -> tuple[list[dict], list[dict]]:
        mid = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        name = params.get("name")
        args = params.get("arguments")
        args = {} if args is None else args
        approval = smcp.get(APPROVAL)
        now = self.clock()

        self._reload()
        ctx, problem = self._authenticate_call(smcp.get(CALL), name, args, approval, now)
        record: ToolRecord | None = None
        if problem is None and not isinstance(args, dict):
            problem = "tools/call arguments must be an object"
        request = None
        if problem is None:
            s = self.session
            listed = self.vetted.get(name)
            if listed is not None:  # re-vet against today's registry
                record, _ = self.registry.vet(self.server_id, listed, scan=self.d.scan_descriptions)
            assessed, signals = self.policy.assess_risk(s.flow)
            declared = ctx["riskLevel"]
            ctx.update(declaredRiskLevel=declared, assessedRiskLevel=assessed, riskSignals=signals or None,
                       sessionLabels=s.flow.labels,
                       riskLevel=declared if rank(RISK, declared) >= rank(RISK, assessed) else assessed)
            schema = (listed or {}).get("inputSchema") if self.d.enforce_input_schema else None
            decision = self.policy.evaluate(ctx, record, args=args, input_schema=schema, flow=s.flow)
            if decision.permitted and decision.approval:
                decision, request = self._check_approval(ctx, name, args, decision, approval, now)
        else:
            decision = Decision("DENY", [problem], policy_refs=["SMCP.AUTHN"])
        if not decision.permitted:
            self.log(f"denied {name!r}: {'; '.join(decision.reasons)}")
            return [], [self._deny(mid, name, ctx, record, decision, args if isinstance(args, dict) else {},
                                   request)]
        if self.d.scan_outputs:
            decision.obligations = [*decision.obligations, {"stripInstructions": True}]
            if decision.effect == "PERMIT":
                decision.effect = "PERMIT_WITH_OBLIGATIONS"
        self._pending[mid] = ("tools/call", (ctx, decision, record, args, name))
        return [msg], []

    def _session_problem(self) -> str | None:
        s = self.session
        if self.refused:
            return self.refused
        if s is None and any(kind == "initialize" for kind, _ in self._pending.values()):
            return "the call arrived before the initialize handshake finished"
        if s is None:
            return "no authenticated SMCP session on this connection (the client sent no smcp/hello)"
        if self.clock() > s.expires_at:
            return "the SMCP session has expired; open a new session"
        if self.registry.active(s.agent_id) is None:
            return f"agent {self.registry.label(s.agent_id)} is revoked or suspended in the registry"
        for entry in s.chain:
            if self.registry.active(entry["subjectId"]) is None:
                return (f"{entry.get('alias') or entry['subjectId']} in the delegation chain is "
                        f"revoked or suspended in the registry")
        revoked = [t for t in s.token_ids if t in self.registry.revoked_delegations]
        if revoked:
            return f"delegation {revoked[0]} behind this session is revoked"
        return None

    def _authenticate_call(self, envelope: object, name: object, args: object, approval: object, now: float):
        s = self.session
        if s is None or self.refused:
            return {"peerId": self.server_id, "toolCallId": new_ref("TC")}, self._session_problem()
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
        problem = self._session_problem()
        if problem:
            return ctx, problem
        if s.legacy:
            return ctx, None
        if not isinstance(envelope, dict):
            return ctx, "the call carries no smcp/call envelope"
        body = {k: v for k, v in envelope.items() if k != "mac"}
        if body.get("sessionId") != s.session_id:
            return ctx, "the envelope is bound to a different session"
        if body.get("tool") != name or body.get("argsDigest") != digest(args):
            return ctx, "the envelope does not match this call's tool name or arguments"
        if body.get("approvalDigest") != (digest(approval) if approval is not None else None):
            return ctx, "the envelope does not match the approval sent with this call"
        if not mac_ok(s.key, body, envelope.get("mac")):
            return ctx, "the envelope MAC does not verify with this session's key"
        seq = body.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= s.last_seq:
            return ctx, f"replayed or out-of-order call (seq {seq!r}, last accepted {s.last_seq})"
        ts = body.get("timestamp")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.d.clock_skew:
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

    def _check_approval(self, ctx, name, args, decision: Decision, approval, now):
        """Turn a decision that needs approval into a permit (valid approval) or a
        denial that carries an approval request."""
        s = self.session
        approver = s.approver
        refs = [*decision.policy_refs]
        if approver is None:
            return Decision("DENY", ["this call needs a user's approval and the session has no user at the "
                                     "root of its delegation chain: " + "; ".join(decision.approval)],
                            policy_refs=refs), None
        if approval is not None:
            req, problem = _approval.check(approval, s.pending_approvals, self.registry,
                                           session_id=s.session_id, tool=name, args_digest=digest(args), now=now)
            if problem is None:
                ctx["approvalRef"] = {"requestId": req["requestId"], "approverId": approver["subjectId"]}
                decision.policy_refs = [*refs, "SMCP.EXT.approved"]
                return decision, None
            return Decision("DENY", [f"approval rejected: {problem}"], policy_refs=refs,
                            requires_step_up=True), None
        s.pending_approvals = {k: v for k, v in s.pending_approvals.items() if v["expiresAt"] >= now}
        request = _approval.approval_request(session_id=s.session_id, tool=name, args=args,
                                             approver_id=approver["subjectId"], reasons=decision.approval,
                                             ttl=self.d.approval_ttl, now=now)
        s.pending_approvals[request["requestId"]] = request
        who = approver.get("alias") or approver["subjectId"]
        return Decision("DENY", [f"needs approval from {who}: " + "; ".join(decision.approval)],
                        policy_refs=refs, requires_step_up=True), request

    def _deny(self, mid, name, ctx, record, decision: Decision, args: dict, request: dict | None = None) -> dict:
        result = {
            "content": [{"type": "text", "text": "SMCP denied this call: " + "; ".join(decision.reasons)}],
            "isError": True,
        }
        ref = self._audit_call(ctx, name, record, decision, "DENIED", args, result,
                               approval_request=request["requestId"] if request else None)
        result["_meta"] = {RESPONSE: self._sign_response(ctx, record, decision, NO_OBLIGATIONS,
                                                         "DENIED", ref, result, request)}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _finish_call(self, msg: dict, state) -> dict:
        ctx, decision, record, args, name = state
        result = msg.get("result")
        if not isinstance(result, dict):
            error = msg.get("error") if isinstance(msg.get("error"), dict) else {}
            clean_error, applied = obl.apply_to_error(error, decision.obligations)
            if self.session is not None:
                self._label(name, record, ctx, json.dumps(clean_error), applied)
            self._audit_call(ctx, name, record, decision, "UPSTREAM_ERROR", args, None, applied)
            return {"jsonrpc": "2.0", "id": msg.get("id"), "error": clean_error or
                    {"code": -32603, "message": "the upstream server sent neither a result nor an error"}}
        _clean_result_meta(result)
        clean, applied = obl.apply(result, decision.obligations)
        action = "TOOL_ERROR" if clean.get("isError") else "SUCCESS"
        if self.session is not None:  # an error result can carry the data too
            self._label(name, record, ctx, _result_text(clean), applied)
        ref = self._audit_call(ctx, name, record, decision, action, args, clean, applied)
        signed = self._sign_response(ctx, record, decision, applied, action, ref, clean)
        clean["_meta"] = {**(clean.get("_meta") or {}), RESPONSE: signed}
        msg["result"] = clean
        return msg

    def _label(self, name: str, record: ToolRecord | None, ctx: dict, text: str, applied: dict) -> None:
        flow = self.session.flow
        tcid = ctx.get("toolCallId")
        produces = (record.security.get("flow") or {}).get("produces") or [] if record else []
        for label in produces:
            flow.add(label, name, tcid, text if label == "confidential" else "")
        if applied.get("instructionsRemoved") and "untrusted" not in produces:
            flow.add("untrusted", name, tcid, why="instruction-like content removed from the output")

    # --- resources, prompts ---------------------------------------------------------

    def _finish_content(self, msg: dict, method: str, params: dict) -> dict:
        """Results of session-gated requests: audit them, and strip instructions
        from resource and prompt text when output scanning is on."""
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        _clean_result_meta(result)
        removed: list[str] = []
        if self.d.scan_outputs and method in ("resources/read", "prompts/get"):
            for item in result.get("contents") or []:  # resources/read
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    item["text"], kinds = obl.strip_instructions(item["text"])
                    removed += kinds
            for m in result.get("messages") or []:  # prompts/get
                content = m.get("content") if isinstance(m, dict) else None
                if isinstance(content, dict) and isinstance(content.get("text"), str):
                    content["text"], kinds = obl.strip_instructions(content["text"])
                    removed += kinds
        if removed and self.session is not None:
            self.session.flow.add("untrusted", method, new_ref("RQ"),
                                  why="instruction-like content removed from the output")
        if method in ("resources/read", "prompts/get"):
            self.audit.append("CONTENT_READ", sessionId=self._sid(), peerId=self.server_id, method=method,
                              target=params.get("uri") or params.get("name"),
                              resultDigest=digest(result), instructionsRemoved=sorted(set(removed)) or None)
        return msg

    # --- audit and signing ------------------------------------------------------------

    def _audit_call(self, ctx, name, record, decision, action, args, result, applied=None,
                    approval_request=None) -> str:
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
            declaredRiskLevel=ctx.get("declaredRiskLevel"),
            assessedRiskLevel=ctx.get("assessedRiskLevel"),
            sessionLabels=ctx.get("sessionLabels") or None,
            approval=ctx.get("approvalRef"),
            approvalRequestId=approval_request,
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

    def _sign_response(self, ctx, record, decision, applied, action, ref, result, request=None) -> dict:
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
                "instructionsRemoved": applied["instructionsRemoved"],
                "truncated": applied["truncated"],
                "requiresStepUpForNext": decision.requires_step_up,
            },
            "reasons": decision.reasons,
            "policyRefs": decision.policy_refs,
            "auditRef": ref,
            "resultDigest": digest(result_without_response(result)),
            "signedBy": self.d.gateway_id,
            "signedAt": _iso(self.clock()),
            "hashAlgo": "SHA-256",
        }
        if request is not None:
            body["approvalRequest"] = request
        return {**body, "signature": sign(self.d.key, body)}


def _chain_summary(chain: list[dict]) -> list[dict]:
    return [{"subjectId": c["subjectId"], "subjectType": c["subjectType"], "role": c.get("role")}
            for c in chain]


# --- stdio transport ---------------------------------------------------------------


def _write_lines(stream: TextIO, msgs: list[dict], lock: threading.Lock) -> None:
    with lock:
        for m in msgs:
            stream.write(json.dumps(m) + "\n")
        stream.flush()


def serve_refusal(reason: str, stdin: TextIO, stdout: TextIO) -> int:
    """Answer every request with the reason the server was not started."""
    for line in stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and "id" in msg and "method" in msg:
            stdout.write(json.dumps(_error(msg["id"], -32002, f"SMCP refused the server: {reason}")) + "\n")
            stdout.flush()
    return 3


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
    problem = gateway.d.check_launch()
    if problem:
        gateway.log(f"refusing to start the server: {problem}")
        return serve_refusal(problem, stdin, stdout)
    proc = subprocess.Popen(server_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, bufsize=1)
    assert proc.stdin and proc.stdout
    out_lock, up_lock = threading.Lock(), threading.Lock()

    def to_client(msgs: list[dict]) -> None:
        _write_lines(stdout, msgs, out_lock)

    def to_server(msgs: list[dict]) -> None:
        try:
            _write_lines(proc.stdin, msgs, up_lock)
        except (BrokenPipeError, ValueError):
            pass

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
            down, up = gateway.handle_server(msg)
        except Exception as e:
            gateway.log(f"internal error on server message: {e!r}")
            down, up = ([_error(msg.get("id"), -32603, f"SMCP gateway error: {e}")]
                        if "id" in msg and "method" not in msg else []), []
        to_server(up)
        to_client(down)
    return proc.wait()
