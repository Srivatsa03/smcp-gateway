"""SMCP messages carried inside standard MCP traffic (paper sections 4.2 and 4.3.4).

Nothing here adds a JSON-RPC method. Every SMCP field rides in ``_meta``, which
MCP already allows on requests and results, so an SMCP-unaware server or client
still parses each message.

Handshake (mutual authentication, two messages):

    initialize           _meta["smcp/hello"]        agent id, nonce, X25519 key,
                                                    delegation tokens; Ed25519-signed by the agent
    initialize result    _meta["smcp/serverHello"]  session id, verified chain, assurance,
                                                    X25519 key; Ed25519-signed by the gateway

Both sides then derive the same session key. Each ``tools/call`` carries an
envelope MACed with that key and a strictly increasing ``seq``. Each result
carries a response signed by the gateway.

A call that needs the user's approval (an extension, see approval.py) also
carries ``_meta["smcp/approval"]``, and its envelope MACs the approval's digest.
"""

from __future__ import annotations

import copy
import secrets
import time
import uuid

from .crypto import canonical, digest, ephemeral, mac, nonce, sign

HELLO = "smcp/hello"
SERVER_HELLO = "smcp/serverHello"
CALL = "smcp/call"
RESPONSE = "smcp/response"
SECURITY = "smcp/security"
APPROVAL = "smcp/approval"
VERSION = "1"

_ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def new_session_id() -> str:
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(32))


def new_ref(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"


def transcript(hello: dict, server_body: dict) -> bytes:
    return canonical({"hello": hello, "server": server_body})


def make_hello(agent_id: str, agent_key, delegation: list[dict] | tuple = (), *, audience: str | None = None,
               now: float | None = None):
    """Return (hello, ephemeral private key) for the agent side of the handshake.

    ``audience`` names the gateway the hello is for; a different gateway refuses it."""
    eph, eph_pub = ephemeral()
    body = {
        "version": VERSION,
        "agentId": agent_id,
        "nonce": nonce(),
        "ephemeralKey": eph_pub,
        "delegation": list(delegation),
        "timestamp": time.time() if now is None else now,
    }
    if audience is not None:
        body["audience"] = audience
    return {**body, "signature": sign(agent_key, body)}, eph


def seal_call(
    key: bytes,
    session_id: str,
    seq: int,
    tool: str,
    arguments: dict | None,
    *,
    risk_level: str = "low",
    task_id: str | None = None,
    call_chain_id: str | None = None,
    data_sensitivity: str | None = None,
    approval: dict | None = None,
    now: float | None = None,
) -> dict:
    """Build the per-call envelope. The MAC covers the tool name and an argument
    digest, so an envelope cannot be lifted onto a different call."""
    body = {
        "sessionId": session_id,
        "seq": seq,
        "toolCallId": new_ref("TC"),
        "callChainId": call_chain_id or new_ref("CC"),
        "taskId": task_id,
        "tool": tool,
        "argsDigest": digest(arguments or {}),
        "riskLevel": risk_level,
        "dataSensitivity": data_sensitivity,
        "timestamp": time.time() if now is None else now,
    }
    if approval is not None:
        body["approvalDigest"] = digest(approval)
    return {**body, "mac": mac(key, body)}


def result_without_response(result: dict) -> dict:
    """The part of a tools/call result that the gateway's signature covers."""
    r = copy.deepcopy(result)
    meta = r.get("_meta")
    if isinstance(meta, dict):
        meta.pop(RESPONSE, None)
        if not meta:
            r.pop("_meta", None)
    return r
