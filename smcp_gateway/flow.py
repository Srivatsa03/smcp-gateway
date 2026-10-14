"""Session flow labels. An extension.

The paper decides each call on its own. Tool chaining and indirect prompt
injection both use calls that are allowed one at a time: read a customer file,
then post it out; fetch a page, then do what the page says. Nothing in a single
call is wrong.

The gateway sees the whole session, so it can remember what entered it. Tools
are labelled in the registry:

    flow:
      produces: [untrusted]     # fetch_url: content from outside, may carry instructions
      produces: [confidential]  # read_file, lookup_customer: data that must not leave
      egress: true              # http_post, send_email: data leaves through this tool

Once a label is in the session, the policy file says what follows (see
policy.py): raise the risk floor, require the user's approval for egress, or
deny egress. Labels only accumulate. A long session gets stricter over time,
which is the price of tracking at session granularity.

The gateway also keeps fingerprints of confidential output, so a denial can say
which earlier result an egress call is carrying. That is evidence, not the
rule: base64 or a paraphrase defeats it. The rule is the label.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

LABELS = ("untrusted", "confidential")
WINDOW = 24          # characters per fingerprint
STRIDE = 4           # fingerprint every 4th window of an output
MAX_PRINTS = 50_000  # per session


def _h(s: str) -> bytes:
    return hashlib.blake2b(s.encode("utf-8", "surrogatepass"), digest_size=8).digest()


def _strings(obj: object):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


@dataclass
class Source:
    label: str
    tool: str
    tool_call_id: str
    why: str = ""


@dataclass
class FlowState:
    sources: list[Source] = field(default_factory=list)
    _prints: dict[bytes, int] = field(default_factory=dict)

    @property
    def labels(self) -> list[str]:
        return sorted({s.label for s in self.sources})

    def add(self, label: str, tool: str, tool_call_id: str, text: str = "", why: str = "") -> None:
        self.sources.append(Source(label, tool, tool_call_id, why))
        if label != "confidential" or not text:
            return
        idx = len(self.sources) - 1
        norm = " ".join(text.split())
        for i in range(0, max(1, len(norm) - WINDOW + 1), STRIDE):
            if len(self._prints) >= MAX_PRINTS:
                break
            chunk = norm[i:i + WINDOW]
            if len(chunk) == WINDOW:
                self._prints.setdefault(_h(chunk), idx)

    def first(self, label: str) -> Source | None:
        return next((s for s in self.sources if s.label == label), None)

    def carried(self, args: object) -> Source | None:
        """The confidential result whose text appears in ``args``, if any."""
        if not self._prints:
            return None
        for s in _strings(args):
            norm = " ".join(s.split())
            for i in range(0, len(norm) - WINDOW + 1):
                hit = self._prints.get(_h(norm[i:i + WINDOW]))
                if hit is not None:
                    return self.sources[hit]
        return None

    def summary(self) -> list[dict]:
        return [{"label": s.label, "tool": s.tool, "toolCallId": s.tool_call_id,
                 **({"why": s.why} if s.why else {})} for s in self.sources]
