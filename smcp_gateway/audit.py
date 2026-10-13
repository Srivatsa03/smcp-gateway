"""Tamper-evident audit log (paper section 4.5, Table 8).

Append-only JSONL. Each entry carries the hash of the previous entry and an
Ed25519 signature over its own hash, so editing, reordering or deleting an entry
in the middle breaks verification at that point.

What a hash chain cannot show by itself: that entries were cut off the end.
Detecting truncation needs the latest hash anchored somewhere the writer cannot
rewrite (a transparency log, a second host). See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from .crypto import digest, sign, verify

GENESIS = "0" * 64


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    def __init__(self, path: Path, key, signer_id: str) -> None:
        self.path = Path(path)
        self.key = key
        self.signer_id = signer_id
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev, self._index = GENESIS, 0
        if self.path.exists():
            last = None
            with self.path.open() as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
            if last is not None:
                self._prev, self._index = last["entryHash"], last["index"] + 1

    def append(self, event: str, **fields) -> str:
        with self._lock:
            ts = _now_iso()
            ref = f"AUDIT-{ts[:19].replace(':', '').replace('-', '')}-{self._index:06d}"
            entry = {
                "type": "SMCP.AuditLogEntry",
                "event": event,
                "index": self._index,
                "auditRef": ref,
                "timestamp": ts,
                **{k: v for k, v in fields.items() if v is not None},
                "prevHash": self._prev,
                "signedBy": self.signer_id,
                "hashAlgo": "SHA-256",
            }
            entry_hash = digest(entry)
            entry["entryHash"] = entry_hash
            entry["signature"] = sign(self.key, {"entryHash": entry_hash})
            with self.path.open("a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._prev, self._index = entry_hash, self._index + 1
            return ref


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    bad_line: int | None = None
    reason: str | None = None


def verify_log(path: Path, public_keys: dict[str, str]) -> VerifyResult:
    """Check the chain and every signature. ``public_keys`` maps signer id to key."""
    prev = GENESIS
    count = 0
    with Path(path).open() as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, count, lineno, "line is not valid JSON")
            body = {k: v for k, v in entry.items() if k not in ("entryHash", "signature")}
            if entry.get("index") != count:
                return VerifyResult(False, count, lineno, f"index is {entry.get('index')}, expected {count}")
            if entry.get("prevHash") != prev:
                return VerifyResult(False, count, lineno, "prevHash does not match the previous entry")
            if digest(body) != entry.get("entryHash"):
                return VerifyResult(False, count, lineno, "entry content does not match its entryHash")
            key = public_keys.get(entry.get("signedBy", ""))
            if not verify(key, {"entryHash": entry["entryHash"]}, entry.get("signature")):
                return VerifyResult(False, count, lineno, f"signature by {entry.get('signedBy')} does not verify")
            prev = entry["entryHash"]
            count += 1
    return VerifyResult(True, count)
