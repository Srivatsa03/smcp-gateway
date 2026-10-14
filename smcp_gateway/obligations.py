"""Policy Enforcement Point for results: apply obligations to a tools/call result.

Obligations are what a PERMIT_WITH_OBLIGATIONS decision attaches: drop named
fields, cap the number of rows, or mask secrets. They act on JSON text blocks,
on ``structuredContent``, and (for secrets) on any text.

``stripInstructions`` is an extension: it removes instruction-like spans from
text output before the agent sees it (see scan.py).
"""

from __future__ import annotations

import copy
import json
import re

from .scan import strip_instructions

REDACTED = "[REDACTED]"

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)[A-Za-z0-9/+=]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("llm_api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("bearer", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{16,}")),
    ("generic_secret", re.compile(r"(?i)((?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?)[A-Za-z0-9_\-/+=]{12,}")),
]


def redact_secrets(text: str) -> tuple[str, list[str]]:
    found: list[str] = []
    for kind, pattern in SECRET_PATTERNS:
        def repl(m: re.Match, kind: str = kind) -> str:
            found.append(kind)
            prefix = m.group(1) if m.groups() else ""
            return f"{prefix}[REDACTED:{kind}]"
        text = pattern.sub(repl, text)
    return text, found


def _transform(obj: object, fields: set[str], max_rows: int | None, applied: dict) -> object:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in fields:
                out[k] = REDACTED
                if k not in applied["redactedFields"]:
                    applied["redactedFields"].append(k)
            else:
                out[k] = _transform(v, fields, max_rows, applied)
        return out
    if isinstance(obj, list):
        items = obj
        if max_rows is not None and len(items) > max_rows and all(isinstance(x, dict) for x in items):
            items = items[:max_rows]
            applied["truncated"] = True
        return [_transform(x, fields, max_rows, applied) for x in items]
    return obj


def _strip_strings(obj: object, applied: dict) -> object:
    if isinstance(obj, str):
        text, kinds = strip_instructions(obj)
        applied["instructionsRemoved"].extend(kinds)
        return text
    if isinstance(obj, dict):
        return {k: _strip_strings(v, applied) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_strings(v, applied) for v in obj]
    return obj


def empty_applied() -> dict:
    return {"redactedFields": [], "truncated": False, "secretsRedacted": [], "instructionsRemoved": []}


def apply(result: dict, obligations: list[dict]) -> tuple[dict, dict]:
    applied = empty_applied()
    if not obligations:
        return result, applied
    fields: set[str] = set()
    max_rows: int | None = None
    secrets = False
    strip = False
    for ob in obligations:
        if "redactFields" in ob:
            fields.update(ob["redactFields"])
        if "maxRows" in ob:
            n = int(ob["maxRows"])
            max_rows = n if max_rows is None else min(max_rows, n)
        if ob.get("redactSecrets"):
            secrets = True
        if ob.get("stripInstructions"):
            strip = True

    out = copy.deepcopy(result)
    for block in out.get("content") or []:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = block.get("text", "")
        if fields or max_rows is not None:
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                text = json.dumps(_transform(parsed, fields, max_rows, applied))
        if secrets:
            text, found = redact_secrets(text)
            applied["secretsRedacted"].extend(found)
        if strip:
            text, kinds = strip_instructions(text)
            applied["instructionsRemoved"].extend(kinds)
        block["text"] = text
    if "structuredContent" in out and (fields or max_rows is not None or secrets or strip):
        sc = _transform(out["structuredContent"], fields, max_rows, applied)
        if strip:
            sc = _strip_strings(sc, applied)
        if secrets:
            masked, found = redact_secrets(json.dumps(sc))
            applied["secretsRedacted"].extend(found)
            try:
                sc = json.loads(masked)
            except json.JSONDecodeError:
                sc = REDACTED  # a mask that broke the JSON: drop the block, never pass it through
        out["structuredContent"] = sc
    applied["secretsRedacted"] = sorted(set(applied["secretsRedacted"]))
    applied["instructionsRemoved"] = sorted(set(applied["instructionsRemoved"]))
    return out, applied
