"""Serve the gateway over MCP Streamable HTTP (protocol revision 2025-06-18).

The stdio transport gives each client its own gateway process. Over HTTP one
gateway serves many clients, which is where SMCP's per-session identity matters
most. Each MCP session here gets:

* its own ``Gateway`` object (its own SMCP session, flow labels and approvals)
* its own upstream server process, so sessions never share server state
* the deployment's shared registry, policy, audit log and handshake nonce
  cache, so a hello replayed to another session is refused

Endpoint behaviour, one path (default ``/mcp``):

* ``POST`` one JSON-RPC message. ``initialize`` opens a session and the reply
  carries ``Mcp-Session-Id``; every later POST must send it back. A request
  gets a JSON reply, unless the server sends something first while handling it
  (a sampling or elicitation request the registry allows, a progress
  notification): then the reply becomes an event stream that carries those
  messages and ends with the response. Notifications and responses get
  ``202 Accepted``.
* ``GET`` with ``Accept: text/event-stream`` opens the session's stream for
  server-initiated messages that arrive while no request is open.
* ``DELETE`` ends the session and stops its server process.

An ``Origin`` header must be on the allowlist (DNS rebinding protection), an
unknown session id gets ``404`` so the client starts over, and sessions idle
longer than the session TTL are closed. There is no TLS: bind to loopback, or
put a TLS-terminating proxy in front.
"""

from __future__ import annotations

import json
import queue
import secrets
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .gateway import Deployment, Gateway, _error

SSE_KEEPALIVE = 15.0


def _key(mid: object) -> str:
    return json.dumps(mid, sort_keys=True)


class HttpSession:
    """One MCP session: a gateway, an upstream process, and the routing between them."""

    def __init__(self, sid: str, gateway: Gateway, command: list[str]) -> None:
        self.sid = sid
        self.gateway = gateway
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.waiters: dict[str, queue.Queue] = {}
        self.open_requests: list[queue.Queue] = []  # POSTs that can carry server-initiated messages
        self.stream: queue.Queue = queue.Queue(maxsize=1000)
        self.last_used = time.time()
        self.closed = False
        self._up = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                down, up = self.gateway.handle_server(msg)
            except Exception as e:  # fail closed
                self.gateway.log(f"internal error on server message: {e!r}")
                down = [_error(msg.get("id"), -32603, f"SMCP gateway error: {e}")] if "id" in msg else []
                up = []
            self.send_up(up)
            for m in down:
                self._dispatch(m)
        self.closed = True
        for q in list(self.waiters.values()):
            q.put(None)

    def _dispatch(self, m: dict) -> None:
        if "method" not in m and "id" in m:
            q = self.waiters.pop(_key(m["id"]), None)
            if q is not None:
                q.put(("response", m))
                return
        if self.open_requests:  # most likely related to the request in flight
            self.open_requests[-1].put(("event", m))
            return
        try:
            self.stream.put_nowait(m)  # for the GET stream; dropped if nobody reads it
        except queue.Full:
            pass

    def send_up(self, msgs: list[dict]) -> None:
        if not msgs:
            return
        with self._up:
            try:
                assert self.proc.stdin
                for m in msgs:
                    self.proc.stdin.write(json.dumps(m) + "\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    def exchange(self, msg: dict, timeout: float, on_event=None) -> dict:
        """Send one client request through the gateway and wait for its reply.

        ``on_event`` receives server-initiated messages that arrive meanwhile;
        without it they go to the GET stream.
        """
        self.last_used = time.time()
        key = _key(msg.get("id"))
        q: queue.Queue = queue.Queue()
        self.waiters[key] = q
        if on_event is not None:
            self.open_requests.append(q)
        try:
            try:
                up, down = self.gateway.from_client(msg)
            except Exception as e:
                self.gateway.log(f"internal error on client message: {e!r}")
                return _error(msg.get("id"), -32603, f"SMCP gateway error: {e}")
            if down:
                return down[0]
            self.send_up(up)
            deadline = time.monotonic() + timeout
            while True:
                try:
                    item = q.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    item = None
                if item is None:
                    return _error(msg.get("id"), -32603, "the upstream server exited" if self.closed
                                  else "the upstream server did not answer in time")
                kind, m = item
                if kind == "response":
                    return m
                on_event(m)
                deadline = time.monotonic() + timeout  # the server is still working on it
        finally:
            self.waiters.pop(key, None)
            if on_event is not None and q in self.open_requests:
                self.open_requests.remove(q)

    def deliver(self, msg: dict) -> None:
        """A client notification or response: no reply expected."""
        self.last_used = time.time()
        try:
            up, _ = self.gateway.from_client(msg)
        except Exception as e:
            self.gateway.log(f"internal error on client message: {e!r}")
            return
        self.send_up(up)

    def close(self) -> None:
        self.closed = True
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
        for q in list(self.waiters.values()):
            q.put(None)


class HttpGateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], deployment: Deployment, command: list[str], *,
                 endpoint: str = "/mcp", allowed_origins: tuple[str, ...] = (), max_sessions: int = 64,
                 request_timeout: float = 60.0, verbose: bool = False) -> None:
        super().__init__(address, _Handler)
        self.deployment = deployment
        self.command = command
        self.endpoint = endpoint
        self.allowed_origins = set(allowed_origins)
        self.max_sessions = max_sessions
        self.request_timeout = request_timeout
        self.verbose = verbose
        self.sessions: dict[str, HttpSession] = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._reap, daemon=True).start()

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}{self.endpoint}"

    def log(self, message: str) -> None:
        print(f"smcp-gateway: {message}", file=sys.stderr, flush=True)

    def open_session(self) -> tuple[HttpSession | None, str | None]:
        with self._lock:
            if len(self.sessions) >= self.max_sessions:
                return None, "too many open sessions"
        problem = self.deployment.check_launch()
        if problem:
            return None, f"SMCP refused the server: {problem}"
        sid = secrets.token_urlsafe(24)
        session = HttpSession(sid, Gateway(self.deployment, log=self.log), self.command)
        with self._lock:
            self.sessions[sid] = session
        return session, None

    def drop(self, sid: str) -> bool:
        with self._lock:
            session = self.sessions.pop(sid, None)
        if session is None:
            return False
        session.close()
        return True

    def _reap(self) -> None:
        while True:
            time.sleep(5)
            cutoff = time.time() - self.deployment.session_ttl
            for sid, s in list(self.sessions.items()):
                if s.closed or s.last_used < cutoff:
                    self.drop(sid)

    def server_close(self) -> None:
        for sid in list(self.sessions):
            self.drop(sid)
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: HttpGateway

    def log_message(self, fmt: str, *args) -> None:
        if self.server.verbose:
            super().log_message(fmt, *args)

    # --- helpers ---

    def _send(self, status: int, body: dict | None = None, headers: dict | None = None) -> None:
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _reject(self, status: int, message: str) -> None:
        self._send(status, _error(None, -32600, message))

    def _gate(self) -> bool:
        """Path and Origin checks shared by every method."""
        if self.path.split("?", 1)[0] != self.server.endpoint:
            self._reject(HTTPStatus.NOT_FOUND, f"the MCP endpoint is {self.server.endpoint}")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.allowed_origins:
            self._reject(HTTPStatus.FORBIDDEN, f"origin {origin} is not allowed")
            return False
        return True

    def _session(self) -> HttpSession | None:
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            self._reject(HTTPStatus.BAD_REQUEST, "missing Mcp-Session-Id header")
            return None
        session = self.server.sessions.get(sid)
        if session is None or session.closed:
            self._reject(HTTPStatus.NOT_FOUND, "unknown or expired session; initialize again")
            return None
        return session

    # --- methods ---

    def do_POST(self) -> None:
        if not self._gate():
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            msg = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self._send(HTTPStatus.BAD_REQUEST, _error(None, -32700, "parse error"))
            return
        if not isinstance(msg, dict):
            self._send(HTTPStatus.BAD_REQUEST, _error(None, -32600, "send one JSON-RPC message per POST"))
            return
        if msg.get("method") == "initialize":
            session, problem = self.server.open_session()
            if session is None:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, _error(msg.get("id"), -32002, problem))
                return
            reply = session.exchange(msg, self.server.request_timeout)
            if "error" in reply or session.gateway.refused:
                self.server.drop(session.sid)
                self._send(HTTPStatus.OK, reply)
                return
            self._send(HTTPStatus.OK, reply, {"Mcp-Session-Id": session.sid})
            return
        session = self._session()
        if session is None:
            return
        if "method" in msg and "id" in msg:
            self._request(session, msg)
        else:
            session.deliver(msg)
            self._send(HTTPStatus.ACCEPTED)

    def _request(self, session: HttpSession, msg: dict) -> None:
        """Reply with JSON, or switch to an event stream if the server sends
        anything before its response."""
        if "text/event-stream" not in (self.headers.get("Accept") or ""):
            self._send(HTTPStatus.OK, session.exchange(msg, self.server.request_timeout))
            return
        streaming = False

        def event(m: dict) -> None:
            nonlocal streaming
            if not streaming:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                streaming = True
            self.wfile.write(f"event: message\ndata: {json.dumps(m)}\n\n".encode())
            self.wfile.flush()

        try:
            reply = session.exchange(msg, self.server.request_timeout, on_event=event)
            if streaming:
                event(reply)
            else:
                self._send(HTTPStatus.OK, reply)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        if not self._gate():
            return
        if "text/event-stream" not in (self.headers.get("Accept") or ""):
            self._reject(HTTPStatus.METHOD_NOT_ALLOWED, "GET opens an event stream; send Accept: text/event-stream")
            return
        session = self._session()
        if session is None:
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            while not session.closed:
                try:
                    m = session.stream.get(timeout=SSE_KEEPALIVE)
                    self.wfile.write(f"event: message\ndata: {json.dumps(m)}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_DELETE(self) -> None:
        if not self._gate():
            return
        sid = self.headers.get("Mcp-Session-Id")
        if sid and self.server.drop(sid):
            self._send(HTTPStatus.OK)
        else:
            self._reject(HTTPStatus.NOT_FOUND, "unknown session")


def serve_http(deployment: Deployment, command: list[str], *, host: str = "127.0.0.1", port: int = 8765,
               allowed_origins: tuple[str, ...] = (), max_sessions: int = 64, verbose: bool = False) -> int:
    httpd = HttpGateway((host, port), deployment, command, allowed_origins=allowed_origins,
                        max_sessions=max_sessions, verbose=verbose)
    if host not in ("127.0.0.1", "localhost", "::1"):
        httpd.log(f"listening on {host}: there is no TLS here, put a TLS proxy in front")
    httpd.log(f"serving MCP over HTTP at {httpd.url}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
