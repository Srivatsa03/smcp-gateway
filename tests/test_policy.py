import pytest

from smcp_gateway.bench.world import POLICY
from smcp_gateway.policy import PolicyEngine, PolicyError


def ctx(world, user, *, scopes, assurance="aal2", risk="low"):
    chain = [{"subjectId": user.id, "subjectType": "user", "alias": user.alias,
              "roles": {"alice": ["data_analyst"], "bob": ["admin"], "mallory": ["data_analyst"]}[user.alias],
              "org": "ORG-GLOBEX" if user.alias == "mallory" else "ORG-ACME"},
             {"subjectId": world.report.id, "subjectType": "agent", "alias": "report", "roles": []}]
    return {"delegatorChain": chain, "scopes": scopes, "assurance": assurance, "riskLevel": risk,
            "callerAgentId": world.report.id}


@pytest.fixture()
def setup(world):
    reg = world.registry(world.write("t-policy"))
    return reg, PolicyEngine(POLICY)


def test_permit_with_obligations(world, setup):
    reg, pe = setup
    d = pe.evaluate(ctx(world, world.alice, scopes=["sales_reporting"]), reg.tool(world.acme.id, "query_sales"))
    assert d.effect == "PERMIT_WITH_OBLIGATIONS" and {"maxRows": 12} in d.obligations


def test_each_builtin_check_denies(world, setup):
    reg, pe = setup
    q = reg.tool(world.acme.id, "query_sales")
    assert "assurance" in pe.evaluate(ctx(world, world.alice, scopes=["sales_reporting"], assurance="aal1"), q).reasons[0]
    assert "not an allowed delegator" in pe.evaluate(ctx(world, world.mallory, scopes=["sales_reporting"]), q).reasons[0]
    assert "scopes" in pe.evaluate(ctx(world, world.alice, scopes=[]), q).reasons[0]
    assert pe.evaluate(ctx(world, world.alice, scopes=["sales_reporting"]), None).effect == "DENY"


def test_rule_on_risk_level(world, setup):
    reg, pe = setup
    d = reg.tool(world.acme.id, "delete_user")
    assert pe.evaluate(ctx(world, world.bob, scopes=["user_admin"], risk="medium"), d).permitted
    denied = pe.evaluate(ctx(world, world.bob, scopes=["user_admin"], risk="high"), d)
    assert not denied.permitted and "POLICY-ACME-HIGHLY-SENSITIVE" in denied.reasons[0]


def test_unknown_risk_fails_closed(world, setup):
    reg, pe = setup
    d = reg.tool(world.acme.id, "delete_user")
    assert not pe.evaluate(ctx(world, world.bob, scopes=["user_admin"], risk="whatever"), d).permitted


def test_bad_rules_rejected_at_load():
    with pytest.raises(PolicyError):
        PolicyEngine({"rules": [{"id": "x", "match": {"colour": "red"}}]})
    with pytest.raises(PolicyError):
        PolicyEngine({"rules": [{"id": "x", "require": [{"attr": "riskLevel", "op": "approx"}]}]})
    with pytest.raises(PolicyError):
        PolicyEngine({"rules": [{"id": "x", "obligations": [{"encrypt": True}]}]})
