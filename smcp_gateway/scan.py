"""Instruction scanner for tool descriptions and tool output. An extension.

The paper's registry pins a tool's description at registration and trusts it
from then on. A description that was malicious on the day it was registered
stays trusted. Tool output is never inspected at all. Both are how text aimed
at the model reaches the model.

This module looks for the markers that injected text usually carries: hidden
Unicode, fake system tags, "ignore your previous instructions", "do not tell the
user", lines addressed to the AI, preference pushing, and (in descriptions)
references to secrets and to other tools.

It is a keyword scanner. Text written to avoid these markers passes. The bench
includes such paraphrases on purpose, and scores the rows they beat as partial.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

HIGH = "high"
INFO = "info"

_HIDDEN = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_TAG_BLOCK = re.compile(r"<\s*(important|system|instructions?|admin|secret)\s*>[\s\S]*?<\s*/\s*\1\s*>",
                        re.IGNORECASE)
_COMMENT = re.compile(r"<!--[\s\S]*?-->")

# (kind, pattern, where it applies: "both", "description" or "output")
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("instruction_tag", re.compile(r"<\s*/?\s*(important|system|instructions?|admin|secret)\s*>|"
                                   r"\[\s*(system|instructions?)\s*\]", re.IGNORECASE), "both"),
    ("override", re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|"
                            r"earlier|all|your|system)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|"
                            r"directions|guidelines)\b", re.IGNORECASE), "both"),
    ("concealment", re.compile(r"\b(do not|don't|never|must not)\b[^.\n]{0,30}\b(tell|mention|inform|reveal|"
                               r"show|notify|disclose)\b[^.\n]{0,30}\b(user|human|anyone)\b|"
                               r"\bwithout (telling|informing|notifying) the user\b|"
                               r"\bmust not be (mentioned|disclosed|shown)\b", re.IGNORECASE), "both"),
    ("agent_address", re.compile(r"\b(ai|llm)\s+(agent|assistant|model)\s*[:,]|"
                                 r"\bnote to (the )?(ai|assistant|agent|model)\b|"
                                 r"^\s*(assistant|system)\s*:", re.IGNORECASE | re.MULTILINE), "both"),
    ("preference", re.compile(r"\b(always|only)\s+(use|call|prefer|choose|pick)\b[^.\n]{0,40}\b(this|me|it)\b|"
                              r"\binstead of (any|all|other)\b", re.IGNORECASE), "description"),
    ("sensitive_target", re.compile(r"~/\.ssh|\bid_(rsa|ed25519|ecdsa|dsa)\b|(^|[\s/'\"`])\.env\b|"
                                    r"/etc/(passwd|shadow)|\bprivate[ _-]?keys?\b|\bapi[ _-]?keys?\b|"
                                    r"\bcredentials?\b|\bpasswords?\b|\bsecrets?\b", re.IGNORECASE),
     "description"),
]
_HIGH_KINDS = {"hidden_unicode", "instruction_tag", "override", "concealment", "agent_address",
               "preference", "sensitive_target"}


@dataclass(frozen=True)
class Finding:
    kind: str
    excerpt: str
    where: str = "description"

    @property
    def severity(self) -> str:
        return HIGH if self.kind in _HIGH_KINDS else INFO

    def __str__(self) -> str:
        return f"{self.kind} in {self.where} ({self.excerpt!r})"


def _excerpt(text: str, start: int, end: int, pad: int = 12) -> str:
    s = text[max(0, start - pad):min(len(text), end + pad)].replace("\n", " ")
    return s if len(s) <= 80 else s[:77] + "..."


def scan_text(text: str, *, context: str = "description", where: str = "description",
              other_tools: tuple[str, ...] | list[str] = ()) -> list[Finding]:
    """Findings in one piece of text. ``context`` is "description" or "output"."""
    if not isinstance(text, str) or not text:
        return []
    found: list[Finding] = []
    m = _HIDDEN.search(text)
    if m:
        found.append(Finding("hidden_unicode", f"U+{ord(m.group()):04X}", where))
    for kind, pattern, scope in _PATTERNS:
        if scope not in ("both", context):
            continue
        m = pattern.search(text)
        if m:
            found.append(Finding(kind, _excerpt(text, m.start(), m.end()), where))
    if context == "description":
        for name in other_tools:
            m = re.search(rf"\b{re.escape(name)}\b", text)
            if m:
                found.append(Finding("cross_tool", name, where))
    return found


def _texts(obj: object, path: str):
    """Every ``description`` and ``title`` string anywhere in a schema or
    annotations object (properties, items, anyOf, oneOf, $defs, ...), plus
    string ``default`` and ``examples`` values, which a model also reads."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            where = f"{path}.{key}"
            if key in ("description", "title", "default") and isinstance(value, str):
                yield where, value
            elif key == "examples" and isinstance(value, list):
                for i, ex in enumerate(value):
                    if isinstance(ex, str):
                        yield f"{where}[{i}]", ex
            else:
                yield from _texts(value, where)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _texts(value, f"{path}[{i}]")


def scan_tool(tool: dict, other_tools: tuple[str, ...] | list[str] = ()) -> list[Finding]:
    """Scan a tool's description and title, and every text inside its input
    schema, output schema and annotations."""
    others = [n for n in other_tools if n != tool.get("name")]
    found = scan_text(tool.get("description") or "", other_tools=others)
    if isinstance(tool.get("title"), str):
        found += scan_text(tool["title"], where="title", other_tools=others)
    for field in ("inputSchema", "outputSchema", "annotations"):
        for path, text in _texts(tool.get(field), field):
            found += scan_text(text, where=path, other_tools=others)
    return found


def blocking(findings: list[Finding], accepted: list[str] | tuple[str, ...] = ()) -> list[Finding]:
    """The findings that hide a tool: high severity and not accepted by the operator."""
    return [f for f in findings if f.severity == HIGH and f.kind not in accepted]


# --- output -------------------------------------------------------------------------

REMOVED = "[SMCP removed instruction-like content]"


def strip_instructions(text: str) -> tuple[str, list[str]]:
    """Remove instruction-like spans from tool output. Returns (text, kinds removed).

    Removed: hidden Unicode characters; fake system-tag blocks; HTML comments
    that carry any marker; and any line that carries an override, concealment
    or agent-addressed marker.
    """
    kinds: list[str] = []
    if _HIDDEN.search(text):
        kinds.append("hidden_unicode")
        text = _HIDDEN.sub("", text)

    def tag_block(m: re.Match) -> str:
        kinds.append("instruction_tag")
        return REMOVED
    text = _TAG_BLOCK.sub(tag_block, text)

    def comment(m: re.Match) -> str:
        inner = scan_text(m.group(), context="output", where="output")
        if inner:
            kinds.extend(f.kind for f in inner)
            return REMOVED
        return m.group()
    text = _COMMENT.sub(comment, text)

    lines = []
    for line in text.split("\n"):
        hits = [f for f in scan_text(line, context="output", where="output") if f.severity == HIGH]
        if hits:
            kinds.extend(f.kind for f in hits)
            lines.append(REMOVED)
        else:
            lines.append(line)
    return "\n".join(lines), sorted(set(kinds))
