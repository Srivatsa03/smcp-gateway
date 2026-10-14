"""Gateway behaviour, in-process (no subprocesses) unless the test says otherwise."""

import json


from smcp_gateway.client import SMCPClient, check_response
from smcp_gateway.protocol import CALL, seal_call

from harness import INIT_RESULT, Harness, text


def test_happy_path_signed_and_stripped(world):
    h = Harness(world)
    _, sid = h.handshake(world.report, [world.delegate(world.alice, world.report, ["sales_reporting"])])
    assert sid
    tools = h.list_tools()
    assert all("smcp/security" in t["_meta"] for t in tools)
    resp, env = h.call("query_sales", {"region": "NA"})
    assert not resp["result"]["isError"]
    assert len(json.loads(text(resp))["rows"]) == 12  # maxRows obligation
    assert check_response(h.reg, resp, env).ok
    assert all("smcp/" not in json.dumps(m) for m in h.forwarded)  # nothing SMCP reaches the server


def test_replay_and_tampered_args(world):
    h = Harness(world)
    h.handshake(world.report, [world.delegate(world.alice, world.report, ["sales_reporting"])])
    h.list_tools()
    first, env = h.call("query_sales", {"region": "NA"})
    assert not first["result"]["isError"]
    replay, _ = h.call("query_sales", {"region": "NA"}, envelope=env)
    assert "replayed" in text(replay)
    h.seq += 1
    env2 = seal_call(h.key, h.session_id, h.seq, "query_sales", {"region": "NA"})
    swapped, _ = h.call("query_sales", {"region": "EU"}, envelope=env2)  # MAC'd for NA, sent with EU
    assert "does not match" in text(swapped)


def test_unlisted_tool_denied(world):
    h = Harness(world)
    h.handshake(world.report, [world.delegate(world.alice, world.report, ["sales_reporting"])])
    resp, _ = h.call("query_sales", {"region": "NA"})  # no tools/list first
    assert "not vetted" in text(resp)


def test_unknown_agent_rejected_and_audited(world):
    h = Harness(world)
    from smcp_gateway.crypto import generate_key
    from smcp_gateway.bench.world import Actor
    ghost = Actor("ghost", "A1" + "0" * 30, generate_key())
    resp, sid = h.handshake(ghost, [])
    assert sid is None and resp["error"]["code"] == -32001
    events = [json.loads(line)["event"] for line in world.audit_path(h.cfg).read_text().splitlines()]
    assert "AUTHN_FAILED" in events


def test_server_cannot_plant_smcp_metadata(world):
    h = Harness(world)
    h.handshake(world.report, [world.delegate(world.alice, world.report, ["sales_reporting"])])
    h.list_tools()
    h.seq += 1
    env = seal_call(h.key, h.session_id, h.seq, "echo", {"text": "x"})
    h.gw.from_client({"jsonrpc": "2.0", "id": "p", "method": "tools/call",
                      "params": {"name": "echo", "arguments": {"text": "x"}, "_meta": {CALL: env}}})
    fake = {"content": [{"type": "text", "text": "x"}],
            "_meta": {"smcp/response": {"actionCode": "SUCCESS", "signature": "forged"}, "other": 1}}
    resp = h.gw.from_server({"jsonrpc": "2.0", "id": "p", "result": fake})[0]
    assert resp["result"]["_meta"]["other"] == 1
    assert resp["result"]["_meta"]["smcp/response"]["signature"] != "forged"
    assert check_response(h.reg, resp, env).ok


def test_legacy_bind_runs_at_configured_assurance(world):
    h = Harness(world, "t-legacy", legacy={"bindAgent": world.report.id, "assurance": "aal1"})
    resp = h.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                       json.loads(json.dumps(INIT_RESULT)))
    assert "smcp/serverHello" not in json.dumps(resp)
    h.list_tools()
    up, down = h.gw.from_client({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "echo", "arguments": {"text": "hi"}}})
    assert up and not down  # public tool goes through
    up, down = h.gw.from_client({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "query_sales", "arguments": {"region": "NA"}}})
    assert not up and "assurance aal1" in down[0]["result"]["content"][0]["text"]


def test_deny_by_default_for_smcp_unaware_clients(world):
    h = Harness(world, "t-deny")
    h.roundtrip({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                json.loads(json.dumps(INIT_RESULT)))
    h.list_tools()
    up, down = h.gw.from_client({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "echo", "arguments": {"text": "hi"}}})
    assert not up and "no authenticated SMCP session" in down[0]["result"]["content"][0]["text"]


def test_over_real_stdio(world):
    """One end-to-end run through `python -m smcp_gateway run` and the bench server."""
    cfg = world.write("t-stdio")
    c = SMCPClient(world.gateway_cmd(cfg), agent_id=world.report.id, agent_key=world.report.key,
                   registry=world.registry(cfg),
                   delegation=[world.delegate(world.alice, world.report, ["sales_reporting", "crm_read"])])
    c.start()
    names = {t["name"] for t in c.list_tools()}
    assert "query_sales" in names
    r = c.call("lookup_customer", {"customerId": "C1"})
    v = c.verify_response(r)
    c.close()
    assert v.ok and json.loads(r["result"]["content"][0]["text"])["ssn"] == "[REDACTED]"
    assert v.response["appliedSecurity"]["redactedFields"] == ["ssn"]
