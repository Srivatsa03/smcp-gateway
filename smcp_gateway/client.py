"""Reference clients: a plain MCP client and the SMCP agent side.

``MCPClient`` speaks ordinary MCP over stdio or Streamable HTTP and is the
baseline. ``SMCPClient`` adds the agent half of the protocol: it opens the
session with a signed hello, checks the gateway's signed reply against the
registry, seals every call with the session key, and verifies every signed
response. When a call needs the user's approval, ``approval_request`` pulls the
verified request out of the denial, and ``call(..., approval=...)`` sends it
back signed.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass

from .crypto import b64d, digest, session_key, verify
from .protocol import (APPROVAL, CALL, HELLO, RESPONSE, SERVER_HELLO, make_hello, result_without_response,
                       seal_call, transcript)
from .registry import Registry

PROTOCOL_VERSION = "2025-06-18"


class ProtocolError(Exception):
    pass


def _answer(handlers: dict, msg: dict) -> dict:
    """The client's reply to a server-to-client request."""
    handler = handlers.get(msg.get("method"))
    if handler is None:
        return {"jsonrpc": "2.0", "id": msg["id"],
                "error": {"code": -32601, "message": "method not supported by this client"}}
    return {"jsonrpc": "2.0", "id": msg["id"], "result": handler(msg.get("params") or {})}


class StdioPeer:
    """Newline-delimited JSON-RPC over a subprocess, with a read timeout."""

    def __init__(self, command: list[str], *, env: dict | None = None, timeout: float = 15.0,
                 handlers: dict | None = None) -> None:
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.timeout = timeout
        self.handlers = handlers or {}
        self.requests_seen: list[dict] = []
        self._lines: queue.Queue = queue.Queue()
        self._next_id = 0
        self.notifications: list[dict] = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            if line.strip():
                self._lines.put(line)
        self._lines.put(None)

    def send(self, msg: dict) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        mid = self._next_id
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.wait_for(mid)

    def wait_for(self, mid: object) -> dict:
        while True:
            try:
                line = self._lines.get(timeout=self.timeout)
            except queue.Empty:
                raise ProtocolError(f"no response to request {mid} within {self.timeout}s") from None
            if line is None:
                raise ProtocolError("the peer closed the connection")
            msg = json.loads(line)
            if "method" in msg and "id" in msg:  # server-to-client request
                self.requests_seen.append(msg)
                self.send(_answer(self.handlers, msg))
            elif "method" in msg:
                self.notifications.append(msg)
            elif msg.get("id") == mid:
                return msg

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()


class HttpPeer:
    """MCP Streamable HTTP (2025-06-18): one POST per message, JSON or SSE replies,
    the session in the ``Mcp-Session-Id`` header, DELETE to end it."""

    def __init__(self, url: str, *, timeout: float = 15.0, headers: dict | None = None,
                 handlers: dict | None = None) -> None:
        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.handlers = handlers or {}
        self.requests_seen: list[dict] = []
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._next_id = 0
        self.notifications: list[dict] = []

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self.headers}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    def _post(self, msg: dict):
        """POST one message; return an iterator over the messages that come back.

        An event-stream reply is read one event at a time, so a server request
        in the middle of it can be answered before the response arrives."""
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), method="POST",
                                     headers=self._headers())
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                parsed = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if isinstance(parsed, dict) and "error" in parsed and "id" in parsed:
                return iter([parsed])
            raise ProtocolError(f"HTTP {e.code} from the gateway: {body[:200]!r}") from None
        except urllib.error.URLError as e:
            raise ProtocolError(f"cannot reach {self.url}: {e.reason}") from None
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        return self._messages(resp)

    @staticmethod
    def _messages(resp):
        with resp:
            if resp.status == 202:
                return
            if (resp.headers.get("Content-Type") or "").startswith("text/event-stream"):
                yield from _sse_messages(resp)
                return
            body = resp.read()
            if body.strip():
                yield json.loads(body)

    def send(self, msg: dict) -> None:
        for m in self._post(msg):
            self._side(m)

    def _side(self, m: dict) -> None:
        if "method" in m and "id" in m:
            self.requests_seen.append(m)
            self.send(_answer(self.handlers, m))
        elif "method" in m:
            self.notifications.append(m)

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        mid = self._next_id
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        found = None
        stream = self._post(msg)
        for m in stream:
            if m.get("id") == mid and "method" not in m:
                found = m
                break
            self._side(m)
        if hasattr(stream, "close"):
            stream.close()
        if found is None:
            raise ProtocolError(f"no response to request {mid}")
        if method == "initialize" and "result" in found:
            self.protocol_version = found["result"].get("protocolVersion")
        return found

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def close(self) -> None:
        if not self.session_id:
            return
        req = urllib.request.Request(self.url, method="DELETE", headers=self._headers())
        try:
            urllib.request.urlopen(req, timeout=self.timeout).close()
        except (urllib.error.URLError, OSError):
            pass
        self.session_id = None


def _sse_messages(resp):
    """Yield the JSON-RPC messages in a text/event-stream response."""
    data: list[str] = []
    for raw in resp:
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            if data:
                yield json.loads("\n".join(data))
                data = []
            continue
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    if data:
        yield json.loads("\n".join(data))


class MCPClient:
    def __init__(self, command: list[str] | None = None, *, url: str | None = None, env: dict | None = None,
                 headers: dict | None = None, handlers: dict | None = None,
                 capabilities: dict | None = None) -> None:
        """``handlers`` answers server-to-client requests by method (for example
        ``sampling/createMessage``); ``capabilities`` is what the client advertises."""
        if (command is None) == (url is None):
            raise ValueError("give a server command or a url, not both")
        self.peer = (HttpPeer(url, headers=headers, handlers=handlers) if url
                     else StdioPeer(command, env=env, handlers=handlers))
        self.capabilities = dict(capabilities or {})
        self.init_result: dict | None = None

    def _init_params(self) -> dict:
        return {"protocolVersion": PROTOCOL_VERSION, "capabilities": dict(self.capabilities),
                "clientInfo": {"name": "smcp-gateway-client", "version": "0.2.0"}}

    def start(self) -> dict:
        resp = self.peer.request("initialize", self._init_params())
        if "error" in resp:
            raise ProtocolError(resp["error"].get("message", "initialize failed"))
        self.init_result = resp["result"]
        self.peer.notify("notifications/initialized")
        return self.init_result

    def list_tools(self) -> list[dict]:
        resp = self.peer.request("tools/list", {})
        if "error" in resp:
            raise ProtocolError(resp["error"].get("message", "tools/list failed"))
        return resp["result"].get("tools", [])

    def call(self, name: str, arguments: dict | None = None, **_: object) -> dict:
        return self.peer.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        self.peer.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()


@dataclass
class Verified:
    ok: bool
    reason: str | None = None
    response: dict | None = None


GATEWAY_TYPE = "G2"  # governance.policy: the only entity type that may act as a policy enforcement point


def _gateway_problem(registry: Registry, signer: object, expected: str | None) -> str | None:
    """Why ``signer`` may not speak for the gateway, or None if it may."""
    if expected is not None and signer != expected:
        return f"{signer} is not the expected gateway {expected}"
    entity = registry.active(signer if isinstance(signer, str) else None)
    if entity is None:
        return f"gateway {signer} is not an active registered identity"
    if not entity.id.startswith(GATEWAY_TYPE):
        return f"{entity.label} is a {entity.kind} identity, not a gateway ({GATEWAY_TYPE})"
    return None


def check_server_hello(registry: Registry, hello: dict, eph, server_hello: object, *,
                       gateway_id: str | None = None, server_id: str | None = None) -> tuple[str, bytes, dict]:
    """Agent side of the handshake: verify the gateway and derive the session key.

    Only a registered gateway identity (or exactly ``gateway_id``) may answer,
    for a registered tool server (or exactly ``server_id``)."""
    if not isinstance(server_hello, dict):
        raise ProtocolError("the server did not answer with smcp/serverHello (no SMCP gateway?)")
    body = {k: v for k, v in server_hello.items() if k != "signature"}
    problem = _gateway_problem(registry, body.get("gatewayId"), gateway_id)
    if problem:
        raise ProtocolError(problem)
    gateway = registry.active(body["gatewayId"])
    peer = registry.active(body.get("peerId"))
    if peer is None or peer.kind != "tool" or (server_id is not None and peer.id != server_id):
        raise ProtocolError(f"the serverHello names {body.get('peerId')} as the server, which is not "
                            f"{'the expected server' if server_id else 'an active registered tool server'}")
    if not verify(gateway.public_key, body, server_hello.get("signature")):
        raise ProtocolError("the serverHello signature does not verify against the registry")
    if body.get("helloDigest") != digest(hello):
        raise ProtocolError("the serverHello answers a different hello")
    try:
        if len(b64d(body.get("ephemeralKey") or "")) != 32:
            raise ValueError
    except ValueError:
        raise ProtocolError("the serverHello carries no valid ephemeral key") from None
    key = session_key(eph, body["ephemeralKey"], transcript(hello, body))
    return body["sessionId"], key, body


class SMCPClient(MCPClient):
    def __init__(
        self,
        command: list[str] | None = None,
        *,
        agent_id: str,
        agent_key,
        registry: Registry,
        delegation: list[dict] | tuple = (),
        url: str | None = None,
        env: dict | None = None,
        handlers: dict | None = None,
        capabilities: dict | None = None,
        gateway_id: str | None = None,
        server_id: str | None = None,
    ) -> None:
        """``gateway_id`` and ``server_id`` pin who may answer; ``gateway_id`` is also
        the hello's audience, so a gateway of another deployment refuses it."""
        super().__init__(command, url=url, env=env, handlers=handlers, capabilities=capabilities)
        self.gateway_id = gateway_id
        self.server_id = server_id
        self.agent_id = agent_id
        self.agent_key = agent_key
        self.registry = registry
        self.delegation = list(delegation)
        self.session_id: str | None = None
        self.key: bytes | None = None
        self.seq = 0
        self.server_hello: dict | None = None
        self.last_envelope: dict | None = None

    def start(self) -> dict:
        hello, eph = make_hello(self.agent_id, self.agent_key, self.delegation, audience=self.gateway_id)
        params = {**self._init_params(), "_meta": {HELLO: hello}}
        resp = self.peer.request("initialize", params)
        if "error" in resp:
            raise ProtocolError(resp["error"].get("message", "initialize failed"))
        result = resp["result"]
        sh = (result.get("_meta") or {}).get(SERVER_HELLO)
        self.session_id, self.key, self.server_hello = check_server_hello(
            self.registry, hello, eph, sh, gateway_id=self.gateway_id, server_id=self.server_id)
        self.init_result = result
        self.peer.notify("notifications/initialized")
        return result

    def envelope(self, name: str, arguments: dict | None, **ctx) -> dict:
        if self.key is None or self.session_id is None:
            raise ProtocolError("start() the session first")
        self.seq += 1
        return seal_call(self.key, self.session_id, self.seq, name, arguments, **ctx)

    def call(self, name: str, arguments: dict | None = None, *, approval: dict | None = None, **ctx) -> dict:
        """Call a tool. ``ctx`` takes risk_level, task_id, call_chain_id, data_sensitivity.
        ``approval`` is the user's signed answer to an approval request."""
        env = self.envelope(name, arguments, approval=approval, **ctx)
        self.last_envelope = env
        meta = {CALL: env}
        if approval is not None:
            meta[APPROVAL] = approval
        return self.peer.request("tools/call", {"name": name, "arguments": arguments or {}, "_meta": meta})

    def request(self, method: str, params: dict | None = None) -> dict:
        """A sealed request other than tools/call: resources/*, prompts/*, completion/*."""
        params = dict(params or {})
        env = self.envelope(method, {k: v for k, v in params.items() if k != "_meta"})
        params["_meta"] = {**(params.get("_meta") or {}), CALL: env}
        return self.peer.request(method, params)

    def verify_response(self, resp: dict, envelope: dict | None = None) -> Verified:
        """Check the gateway's signature, the result digest, and the call binding."""
        return check_response(self.registry, resp, envelope or self.last_envelope,
                              gateway_id=(self.server_hello or {}).get("gatewayId"), session_id=self.session_id)

    def approval_request(self, resp: dict) -> dict | None:
        """The approval request in a denial, after checking the gateway signed it."""
        v = self.verify_response(resp)
        return (v.response or {}).get("approvalRequest") if v.ok else None


def check_response(registry: Registry, resp: dict, envelope: dict | None = None, *,
                   gateway_id: str | None = None, session_id: str | None = None) -> Verified:
    """Verify a signed tool result. ``gateway_id`` and ``session_id`` should be the
    ones from this session's serverHello; without them any registered gateway
    identity is accepted."""
    result = resp.get("result")
    if not isinstance(result, dict):
        return Verified(False, "no result to verify")
    signed = (result.get("_meta") or {}).get(RESPONSE)
    if not isinstance(signed, dict):
        return Verified(False, "the result carries no smcp/response")
    body = {k: v for k, v in signed.items() if k != "signature"}
    problem = _gateway_problem(registry, body.get("signedBy"), gateway_id)
    if problem:
        return Verified(False, f"the response is not from this session's gateway: {problem}", body)
    gateway = registry.active(body.get("signedBy"))
    if not verify(gateway.public_key, body, signed.get("signature")):
        return Verified(False, "the response signature does not verify", body)
    if session_id is not None and body.get("sessionId") != session_id:
        return Verified(False, "the signed response belongs to a different session", body)
    if body.get("resultDigest") != digest(result_without_response(result)):
        return Verified(False, "the result was modified after the gateway signed it", body)
    if envelope and body.get("toolCallId") != envelope.get("toolCallId"):
        return Verified(False, "the signed response belongs to a different call", body)
    return Verified(True, None, body)
