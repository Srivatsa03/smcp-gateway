"""Per-call user approval (step-up). An extension that completes the paper's
``requiresStepUpForNext`` flag, which the paper sets but never defines.

The paper's policy rules read ``riskLevel``, and the calling agent declares it.
A fooled agent declares "low". This module gives a high-stakes call a check the
agent cannot fake: the user at the root of the delegation chain signs the exact
call (session, tool name, argument digest) with their own key.

Flow:

1. The agent calls a tool that needs approval. The gateway denies it and puts
   an ``SMCP.ApprovalRequest`` in the signed response. The request names the
   tool, shows the arguments and says why approval is needed.
2. The client shows the request to the user. The user's device signs an
   ``SMCP.Approval`` over it.
3. The agent sends the same call again with the approval in
   ``_meta["smcp/approval"]``. The gateway checks the signature against the
   registry, checks that the approval matches this exact call and a request it
   issued, and consumes it. Each approval works once.

What this does not fix: a user who approves whatever they are shown. It moves
the decision to the person who is accountable for it, with the real arguments
in front of them.
"""

from __future__ import annotations

import time

from .crypto import digest, sign, verify
from .protocol import new_ref
from .registry import Registry

ARGS_PREVIEW_BYTES = 4096


def approval_request(*, session_id: str, tool: str, args: dict, approver_id: str,
                     reasons: list[str], ttl: float, now: float) -> dict:
    preview = args if len(repr(args)) <= ARGS_PREVIEW_BYTES else {"_truncated": repr(args)[:ARGS_PREVIEW_BYTES]}
    return {
        "type": "SMCP.ApprovalRequest",
        "requestId": new_ref("AR"),
        "sessionId": session_id,
        "tool": tool,
        "arguments": preview,
        "argsDigest": digest(args),
        "approverId": approver_id,
        "reasons": reasons,
        "expiresAt": now + ttl,
    }


def approve(request: dict, user_key, *, now: float | None = None) -> dict:
    """The user's side: sign an approval for one request. Call this only after a
    person has read the request."""
    body = {
        "type": "SMCP.Approval",
        "requestId": request["requestId"],
        "sessionId": request["sessionId"],
        "tool": request["tool"],
        "argsDigest": request["argsDigest"],
        "approverId": request["approverId"],
        "approvedAt": time.time() if now is None else now,
    }
    return {**body, "signature": sign(user_key, body)}


def check(approval: object, pending: dict[str, dict], registry: Registry, *, session_id: str,
          tool: str, args_digest: str, now: float) -> tuple[dict | None, str | None]:
    """Return (the request it answers, None) or (None, why it is not valid).

    On success the request is removed from ``pending``: an approval is single use.
    """
    if not isinstance(approval, dict):
        return None, "smcp/approval is not an object"
    body = {k: v for k, v in approval.items() if k != "signature"}
    if body.get("type") != "SMCP.Approval":
        return None, "smcp/approval has the wrong type"
    request = pending.get(str(body.get("requestId")))
    if request is None:
        return None, "the approval answers no open request on this session (unknown, used or expired)"
    if now > request["expiresAt"]:
        pending.pop(request["requestId"], None)
        return None, "the approval request expired; call again to get a new one"
    for key, want in (("sessionId", session_id), ("tool", tool), ("argsDigest", args_digest),
                      ("approverId", request["approverId"])):
        if body.get(key) != want or request.get(key, want) != want:
            return None, f"the approval does not match this call ({key} differs)"
    approver = registry.active(body.get("approverId"))
    if approver is None or approver.kind != "user":
        return None, f"approver {registry.label(body.get('approverId'))} is not an active registered user"
    if not verify(approver.public_key, body, approval.get("signature")):
        return None, f"the approval signature does not verify against {approver.label}'s registered key"
    pending.pop(request["requestId"], None)
    return request, None
