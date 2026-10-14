"""The Streamable HTTP transport, against real upstream processes."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from smcp_gateway.client import MCPClient, ProtocolError, SMCPClient
from smcp_gateway.gateway import Deployment
from smcp_gateway.httpserve import HttpGateway


@pytest.fixture
def served(world):
    servers = []

    def start(name, profile="paper", variant="clean", **kw):
        cfg = world.write(name, profile=profile)
        srv = HttpGateway(("127.0.0.1", 0), Deployment.load(cfg), world.server_cmd(cfg, variant), **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv, cfg

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def agent(world, srv, cfg, user=None, scopes=("sales_reporting", "crm_read"), **kw):
    c = SMCPClient(url=srv.url, agent_id=world.report.id, agent_key=world.report.key, registry=world.registry(cfg),
                   delegation=[world.delegate(user or world.alice, world.report, list(scopes))], **kw)
    c.start()
    c.list_tools()
    return c


def raw(url, method="POST", body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_session_over_http(world, served):
    srv, cfg = served("t-http1")
    c = agent(world, srv, cfg)
    r = c.call("lookup_customer", {"customerId": "C1"})
    assert c.verify_response(r).ok and json.loads(r["result"]["content"][0]["text"])["ssn"] == "[REDACTED]"
    assert len(srv.sessions) == 1
    c.close()
    assert len(srv.sessions) == 0  # DELETE ended it and stopped the server process


def test_sessions_are_isolated(world, served):
    srv, cfg = served("t-http2")
    a, b = agent(world, srv, cfg), agent(world, srv, cfg, user=world.mallory)
    assert a.peer.session_id != b.peer.session_id
    assert a.call("query_sales", {"region": "NA"})["result"]["isError"] is False
    assert "not an allowed delegator" in b.call("query_sales", {"region": "NA"})["result"]["content"][0]["text"]
    # a's envelope sent on b's MCP session is bound to a different SMCP session
    env = a.envelope("query_sales", {"region": "NA"})
    r = b.peer.request("tools/call", {"name": "query_sales", "arguments": {"region": "NA"},
                                      "_meta": {"smcp/call": env}})
    assert "different session" in r["result"]["content"][0]["text"]
    a.close()
    b.close()


def test_protocol_errors(world, served):
    srv, cfg = served("t-http3", allowed_origins=("https://console.acme.example",))
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    assert raw(srv.url, body=init, headers={"Origin": "https://evil.test"})[0] == 403
    status, _ = raw(srv.url, body=init, headers={"Origin": "https://console.acme.example"})
    assert status == 200
    assert raw(srv.url, body=call)[0] == 400  # no session header
    assert raw(srv.url, body=call, headers={"Mcp-Session-Id": "nope"})[0] == 404
    assert raw(srv.url, body=[call])[0] == 400  # no batches
    assert raw(srv.url.replace("/mcp", "/other"), body=init)[0] == 404
    assert raw(srv.url, method="GET")[0] == 405
    assert raw(srv.url, method="DELETE", headers={"Mcp-Session-Id": "nope"})[0] == 404


def test_smcp_unaware_client(world, served):
    srv, cfg = served("t-http4")
    with pytest.raises(ProtocolError, match="accepts only SMCP clients"):
        MCPClient(url=srv.url).start()  # refused before any server process starts
    assert not srv.sessions

    cfg = world.write("t-http4b", legacy={"bindAgent": world.report.id, "assurance": "aal1"})
    legacy = HttpGateway(("127.0.0.1", 0), Deployment.load(cfg), world.server_cmd(cfg))
    threading.Thread(target=legacy.serve_forever, daemon=True).start()
    try:
        with MCPClient(url=legacy.url) as plain:
            plain.list_tools()
            assert plain.call("echo", {"text": "hi"})["result"]["content"][0]["text"] == "hi"
            denied = plain.call("query_sales", {"region": "NA"})["result"]["content"][0]["text"]
        assert "assurance aal1" in denied
    finally:
        legacy.shutdown()
        legacy.server_close()


def test_session_cap_is_atomic(world, served):
    srv, cfg = served("t-http7", max_sessions=3)
    from smcp_gateway.protocol import HELLO, make_hello
    tok = world.delegate(world.alice, world.report, [])
    results = []

    def init():
        hello, _ = make_hello(world.report.id, world.report.key, [tok])
        results.append(raw(srv.url, body={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                     "_meta": {HELLO: hello}}})[0])
    threads = [threading.Thread(target=init) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results).count(200) == 3 and len(srv.sessions) == 3


def test_header_checks(world, served):
    srv, cfg = served("t-http8")
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    assert raw(srv.url, body=init, headers={"Host": "evil.test:8765"})[0] == 403  # DNS rebinding
    assert raw(srv.url, body=init, headers={"MCP-Protocol-Version": "1999-01-01"})[0] == 400
    req = urllib.request.Request(srv.url, data=b"", method="POST", headers={"Content-Length": "0"})
    try:
        urllib.request.urlopen(req, timeout=5)
        status = 200
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == 400


def test_server_request_streams_on_the_post(world, served):
    srv, cfg = served("t-http5", variant="sampler")
    seen = []
    c = agent(world, srv, cfg, handlers={"sampling/createMessage": lambda p: seen.append(p) or {
        "role": "assistant", "model": "m", "content": {"type": "text", "text": "ok"}}},
        capabilities={"sampling": {}})
    r = c.call("get_weather", {"city": "Chicago"})
    c.close()
    assert seen and "answered" in r["result"]["content"][0]["text"]


def test_refused_server_closes_session(world, served):
    spoof = world.install("t-http-spoof", spoofed=True)
    cfg = world.write("t-http6", profile="extended", install=spoof)
    srv = HttpGateway(("127.0.0.1", 0), Deployment.load(cfg), world.upstream_cmd(install=spoof))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ProtocolError, match="spoofed or changed install"):
            agent(world, srv, cfg)
        assert not srv.sessions
    finally:
        srv.shutdown()
        srv.server_close()
