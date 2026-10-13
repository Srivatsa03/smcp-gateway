"""Reference clients: a plain MCP client and the SMCP agent side.

``MCPClient`` speaks ordinary MCP over stdio and is the baseline. ``SMCPClient``
adds the agent half of the protocol: it opens the session with a signed hello,
checks the gateway's signed reply against the registry, seals every call with
the session key, and verifies every signed response.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from dataclasses import dataclass

from .crypto import b64d, digest, session_key, verify
from .protocol import (CALL, HELLO, RESPONSE, SERVER_HELLO, make_hello, result_without_response,
                       seal_call, transcript)
from .registry import Registry

PROTOCOL_VERSION = "2025-06-18"


class ProtocolError(Exception):
    pass


class StdioPeer:
    """Newline-delimited JSON-RPC over a subprocess, with a read timeout."""

    def __init__(self, command: list[str], *, env: dict | None = None, timeout: float = 15.0) -> None:
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self.timeout = timeout
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
            if "method" in msg and "id" in msg:  # server-to-client request: not supported here
                self.send({"jsonrpc": "2.0", "id": msg["id"],
                           "error": {"code": -32601, "message": "method not supported by this client"}})
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


class MCPClient:
    def __init__(self, command: list[str], *, env: dict | None = None) -> None:
        self.peer = StdioPeer(command, env=env)
        self.init_result: dict | None = None

    def _init_params(self) -> dict:
        return {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "smcp-gateway-client", "version": "0.1.0"}}

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


def check_server_hello(registry: Registry, hello: dict, eph, server_hello: object) -> tuple[str, bytes, dict]:
    """Agent side of the handshake: verify the gateway and derive the session key."""
    if not isinstance(server_hello, dict):
        raise ProtocolError("the server did not answer with smcp/serverHello (no SMCP gateway?)")
    body = {k: v for k, v in server_hello.items() if k != "signature"}
    gateway = registry.active(body.get("gatewayId"))
    if gateway is None:
        raise ProtocolError(f"gateway {body.get('gatewayId')} is not an active registered identity")
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
        command: list[str],
        *,
        agent_id: str,
        agent_key,
        registry: Registry,
        delegation: list[dict] | tuple = (),
        env: dict | None = None,
    ) -> None:
        super().__init__(command, env=env)
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
        hello, eph = make_hello(self.agent_id, self.agent_key, self.delegation)
        params = {**self._init_params(), "_meta": {HELLO: hello}}
        resp = self.peer.request("initialize", params)
        if "error" in resp:
            raise ProtocolError(resp["error"].get("message", "initialize failed"))
        result = resp["result"]
        sh = (result.get("_meta") or {}).get(SERVER_HELLO)
        self.session_id, self.key, self.server_hello = check_server_hello(self.registry, hello, eph, sh)
        self.init_result = result
        self.peer.notify("notifications/initialized")
        return result

    def envelope(self, name: str, arguments: dict | None, **ctx) -> dict:
        if self.key is None or self.session_id is None:
            raise ProtocolError("start() the session first")
        self.seq += 1
        return seal_call(self.key, self.session_id, self.seq, name, arguments, **ctx)

    def call(self, name: str, arguments: dict | None = None, **ctx) -> dict:
        """Call a tool. ``ctx`` takes risk_level, task_id, call_chain_id, data_sensitivity."""
        env = self.envelope(name, arguments, **ctx)
        self.last_envelope = env
        return self.peer.request("tools/call", {"name": name, "arguments": arguments or {},
                                                "_meta": {CALL: env}})

    def verify_response(self, resp: dict, envelope: dict | None = None) -> Verified:
        """Check the gateway's signature, the result digest, and the call binding."""
        return check_response(self.registry, resp, envelope or self.last_envelope)


def check_response(registry: Registry, resp: dict, envelope: dict | None = None) -> Verified:
    result = resp.get("result")
    if not isinstance(result, dict):
        return Verified(False, "no result to verify")
    signed = (result.get("_meta") or {}).get(RESPONSE)
    if not isinstance(signed, dict):
        return Verified(False, "the result carries no smcp/response")
    body = {k: v for k, v in signed.items() if k != "signature"}
    gateway = registry.active(body.get("signedBy"))
    if gateway is None or not verify(gateway.public_key, body, signed.get("signature")):
        return Verified(False, "the response signature does not verify", body)
    if body.get("resultDigest") != digest(result_without_response(result)):
        return Verified(False, "the result was modified after the gateway signed it", body)
    if envelope and body.get("toolCallId") != envelope.get("toolCallId"):
        return Verified(False, "the signed response belongs to a different call", body)
    return Verified(True, None, body)
