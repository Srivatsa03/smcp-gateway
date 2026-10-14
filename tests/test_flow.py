import base64

from smcp_gateway.flow import FlowState
from smcp_gateway.policy import PolicyEngine
from smcp_gateway.registry import ToolRecord

CSV = "name,email\nDana Whitfield,dana@example.com\nLeo Park,leo@example.com\n"


def test_labels_and_carried_text():
    f = FlowState()
    assert f.labels == [] and f.carried({"body": CSV}) is None
    f.add("confidential", "read_file", "TC-1", CSV)
    f.add("untrusted", "fetch_url", "TC-2")
    assert f.labels == ["confidential", "untrusted"]
    hit = f.carried({"to": "x", "body": "fyi: " + CSV.replace("\n", "  ")})  # whitespace-insensitive
    assert hit is not None and hit.tool_call_id == "TC-1"
    assert f.carried({"body": base64.b64encode(CSV.encode()).decode()}) is None  # evidence, not the rule
    assert f.carried({"body": "short"}) is None


def test_assessed_risk_and_egress_rules():
    engine = PolicyEngine({"flow": {"untrusted": {"riskFloor": "high", "egress": "deny"},
                                    "confidential": {"egress": "approve"}}})
    f = FlowState()
    assert engine.assess_risk(f) == ("low", [])
    f.add("untrusted", "fetch_url", "TC-9")
    level, signals = engine.assess_risk(f)
    assert level == "high" and "fetch_url" in signals[0]

    post = ToolRecord("S", "http_post", "T", security={"flow": {"egress": True}})
    ctx = {"assurance": "aal1", "delegatorChain": [], "riskLevel": "low"}
    d = engine.evaluate(ctx, post, args={"url": "u"}, flow=f)
    assert not d.permitted and "untrusted content" in d.reasons[0]

    f2 = FlowState()
    f2.add("confidential", "read_file", "TC-1", CSV)
    d = engine.evaluate(ctx, post, args={"body": CSV}, flow=f2)
    assert d.permitted and d.approval and "carry text from the read_file result" in d.approval[0]

    plain = ToolRecord("S", "format_text", "T", security={})
    assert not engine.evaluate(ctx, plain, args={}, flow=f).approval
