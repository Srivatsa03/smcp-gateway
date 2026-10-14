"""Security context levels and delegation chains (paper sections 4.3 and 4.4).

The paper's ``delegatorChain`` is a list of who authorised whom, from a user
down to the agent making the call. A chain that the agent merely asserts proves
nothing, so here every link is a token signed by the delegator. The gateway
rebuilds ``delegatorChain`` from verified tokens and never copies it from the
request.
"""

from __future__ import annotations

import time

from .crypto import nonce, sign, verify
from .protocol import new_ref
from .registry import Entity, Registry

RISK = ("low", "medium", "high", "critical")
ASSURANCE = ("aal1", "aal2", "aal3")
SENSITIVITY = ("public", "internal", "sensitive", "highly_sensitive")
ORDERED = {
    "riskLevel": RISK,
    "assurance": ASSURANCE,
    "sensitivityLevel": SENSITIVITY,
    "dataSensitivity": SENSITIVITY,
}


def rank(scale: tuple[str, ...], value: object) -> int:
    if value not in scale:
        raise ValueError(f"{value!r} is not one of {scale}")
    return scale.index(value)  # type: ignore[arg-type]


class DelegationError(Exception):
    pass


def issue_delegation(
    key,
    delegator_id: str,
    delegate_id: str,
    scopes: list[str] | tuple[str, ...],
    *,
    ttl_seconds: float = 3600,
    now: float | None = None,
) -> dict:
    now = time.time() if now is None else now
    body = {
        "type": "SMCP.Delegation",
        "tokenId": new_ref("DT"),
        "delegator": delegator_id,
        "delegate": delegate_id,
        "scopes": sorted(set(scopes)),
        "notBefore": now,
        "notAfter": now + ttl_seconds,
        "nonce": nonce(),
    }
    return {**body, "signature": sign(key, body)}


def token_id(token: dict) -> str:
    """A delegation token's id: ``tokenId``, or its nonce for tokens issued without one."""
    return str(token.get("tokenId") or token.get("nonce"))


def link(entity: Entity) -> dict:
    return {
        "subjectId": entity.id,
        "subjectType": entity.kind,
        "alias": entity.alias,
        "role": entity.roles[0] if entity.roles else None,
        "roles": list(entity.roles),
        "org": entity.org,
    }


def verify_chain(
    tokens: list[dict],
    caller: Entity,
    registry: Registry,
    *,
    now: float,
    skew: float = 120,
) -> tuple[list[dict], list[str]]:
    """Check a delegation chain and return (delegatorChain, effective scopes).

    Rules: the chain starts at a user, each token is signed by its delegator,
    each token's delegate is the next token's delegator, the last delegate is the
    calling agent, every delegator is still active, nothing is expired, and no
    token is on the registry's ``revokedDelegations`` list. Scopes can only
    narrow along the chain (intersection).
    """
    if not isinstance(tokens, list):
        raise DelegationError("delegation must be a list of tokens")
    chain: list[dict] = []
    scopes: set[str] | None = None
    expected: str | None = None
    for i, tok in enumerate(tokens):
        if not isinstance(tok, dict):
            raise DelegationError(f"delegation token {i} is not an object")
        body = {k: v for k, v in tok.items() if k != "signature"}
        if body.get("type") != "SMCP.Delegation":
            raise DelegationError(f"delegation token {i} has the wrong type")
        delegator = registry.active(body.get("delegator"))
        if delegator is None:
            raise DelegationError(
                f"delegator {registry.label(body.get('delegator'))} is not an active registered entity")
        if i == 0 and delegator.kind != "user":
            raise DelegationError("a delegation chain must start at a user")
        if i > 0 and body.get("delegator") != expected:
            raise DelegationError(f"delegation chain is broken at token {i}")
        if not verify(delegator.public_key, body, tok.get("signature")):
            raise DelegationError(f"signature on the delegation from {delegator.label} does not verify")
        try:
            not_before, not_after = float(body["notBefore"]), float(body["notAfter"])
        except (KeyError, TypeError, ValueError):
            raise DelegationError(f"delegation token {i} has no valid lifetime") from None
        if not (not_before - skew <= now <= not_after):
            raise DelegationError(f"the delegation from {delegator.label} is expired or not yet valid")
        if token_id(body) in registry.revoked_delegations:
            raise DelegationError(f"the delegation from {delegator.label} ({token_id(body)}) is revoked")
        tok_scopes = set(body.get("scopes") or [])
        scopes = tok_scopes if scopes is None else scopes & tok_scopes
        chain.append(link(delegator))
        expected = body.get("delegate")
    if tokens and expected != caller.id:
        raise DelegationError("the delegation chain does not end at the calling agent")
    chain.append(link(caller))
    return chain, sorted(scopes or [])
