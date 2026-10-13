import time

import pytest

from smcp_gateway.context import DelegationError, issue_delegation, verify_chain
from smcp_gateway.crypto import generate_key


def test_valid_chain_and_scope_narrowing(world, tmp_path):
    reg = world.registry(world.write("t-deleg"))
    report = reg.entity(world.report.id)
    tok = world.delegate(world.alice, world.report, ["sales_reporting", "crm_read"])
    chain, scopes = verify_chain([tok], report, reg, now=time.time())
    assert [c["alias"] for c in chain] == ["alice", "report"]
    assert scopes == ["crm_read", "sales_reporting"]


def test_no_delegation_means_agent_only(world):
    reg = world.registry(world.write("t-deleg"))
    chain, scopes = verify_chain([], reg.entity(world.helper.id), reg, now=time.time())
    assert [c["subjectType"] for c in chain] == ["agent"] and scopes == []


def test_forged_signature_rejected(world):
    reg = world.registry(world.write("t-deleg"))
    forged = issue_delegation(world.report.key, world.bob.id, world.report.id, ["user_admin"])
    with pytest.raises(DelegationError, match="does not verify"):
        verify_chain([forged], reg.entity(world.report.id), reg, now=time.time())


def test_chain_must_end_at_caller_and_start_at_user(world):
    reg = world.registry(world.write("t-deleg"))
    tok = world.delegate(world.alice, world.helper, ["x"])
    with pytest.raises(DelegationError, match="does not end"):
        verify_chain([tok], reg.entity(world.report.id), reg, now=time.time())
    agent_root = issue_delegation(world.helper.key, world.helper.id, world.report.id, ["x"])
    with pytest.raises(DelegationError, match="start at a user"):
        verify_chain([agent_root], reg.entity(world.report.id), reg, now=time.time())


def test_expired_and_unknown_delegator(world):
    reg = world.registry(world.write("t-deleg"))
    old = issue_delegation(world.alice.key, world.alice.id, world.report.id, ["x"], ttl_seconds=10,
                           now=time.time() - 1000)
    with pytest.raises(DelegationError, match="expired"):
        verify_chain([old], reg.entity(world.report.id), reg, now=time.time())
    stranger = issue_delegation(generate_key(), "U1" + "0" * 30, world.report.id, ["x"])
    with pytest.raises(DelegationError, match="not an active"):
        verify_chain([stranger], reg.entity(world.report.id), reg, now=time.time())
