"""Tamper-evident audit log (paper section 4.5, Table 8).

Append-only JSONL. Each entry carries the hash of the previous entry and an
Ed25519 signature over its own hash, so editing, reordering or deleting an entry
in the middle breaks verification at that point.

What a hash chain cannot show by itself: that entries were cut off the end.
For that the log keeps a checkpoint: a small signed file with the entry count
and the latest hash, rewritten after every entry. ``verify_log`` with the
checkpoint catches a truncated log, and the gateway refuses to start on a log
that is shorter than its checkpoint, so it never writes over the evidence.

Several gateway processes may share one log (an MCP client starts one stdio
gateway per connection). Each append takes an exclusive file lock and reads the
current tail under it, so the chain stays linear. On systems without ``fcntl``
only one process may write a log.

Rewriting the checkpoint atomically after every entry is most of the
extensions' per-call cost (about 0.6 ms on macOS). ``checkpoint_every=N``
rewrites it every N entries instead; then up to N-1 trailing entries can be cut
without detection.

The checkpoint only helps if it lives where the log's attacker cannot write.
Someone who controls both can cut the log and put back an older checkpoint
that matches. Keep it on another volume or host, or ship ``smcp-gateway audit
checkpoint`` output to a witness. See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: one process per log
    fcntl = None

from .crypto import digest, sign, verify

GENESIS = "0" * 64


class AuditIntegrityError(RuntimeError):
    pass


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    def __init__(self, path: Path, key, signer_id: str, *, checkpoint: Path | None = None,
                 checkpoint_every: int = 1, fsync: bool = False) -> None:
        self.path = Path(path)
        self.key = key
        self.signer_id = signer_id
        self.checkpoint = Path(checkpoint) if checkpoint else None
        self.checkpoint_every = max(1, int(checkpoint_every))
        self.fsync = fsync
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev, self._index = GENESIS, 0
        hashes: list[str] = []
        if self.path.exists():
            with self.path.open() as f:
                for line in f:
                    if line.strip():
                        hashes.append(json.loads(line)["entryHash"])
            if hashes:
                self._prev, self._index = hashes[-1], len(hashes)
        if self.checkpoint is not None and self.checkpoint.exists():
            cp = json.loads(self.checkpoint.read_text())
            n = int(cp.get("count", 0))
            if n > len(hashes) or (n and hashes[n - 1] != cp.get("headHash")):
                raise AuditIntegrityError(
                    f"{self.path} has {len(hashes)} entries but its checkpoint {self.checkpoint} records {n} "
                    f"ending in {str(cp.get('headHash'))[:16]}...; the log was truncated or replaced. "
                    "Investigate before starting the gateway on it.")

    @contextlib.contextmanager
    def _locked(self):
        """The thread lock, plus an exclusive lock on the log file shared with other processes."""
        with self._lock, self.path.open("ab+") as f:
            if fcntl is not None:
                fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield f
            finally:
                if fcntl is not None:
                    fcntl.flock(f, fcntl.LOCK_UN)

    @staticmethod
    def _tail(f) -> tuple[str, int]:
        """(hash of the last entry, number of entries) read from the end of the file."""
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return GENESIS, 0
        chunk = 16384
        while True:
            start = max(0, size - chunk)
            f.seek(start)
            lines = [line for line in f.read(size - start).split(b"\n") if line.strip()]
            if lines and (start == 0 or len(lines) > 1):
                last = json.loads(lines[-1])
                return last["entryHash"], last["index"] + 1
            if start == 0:
                return GENESIS, 0
            chunk *= 4

    def append(self, event: str, **fields) -> str:
        with self._locked() as f:
            self._prev, self._index = self._tail(f)
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
            f.seek(0, os.SEEK_END)
            f.write((json.dumps(entry, sort_keys=True) + "\n").encode())
            f.flush()
            if self.fsync:
                os.fsync(f.fileno())
            self._prev, self._index = entry_hash, self._index + 1
            if self.checkpoint is not None and self._index % self.checkpoint_every == 0:
                self._write_checkpoint()
            return ref

    def entries(self, event: str) -> list[dict]:
        """Every entry of one event type, oldest first."""
        if not self.path.exists():
            return []
        with self._lock, self.path.open() as f:
            return [e for e in (json.loads(line) for line in f if line.strip()) if e.get("event") == event]

    def head(self) -> dict:
        """A signed statement of the log's current length and latest hash."""
        with self._locked() as f:
            self._prev, self._index = self._tail(f)
            return self._head()

    def _head(self) -> dict:
        body = {
            "type": "SMCP.AuditCheckpoint",
            "log": self.path.name,
            "count": self._index,
            "headHash": self._prev,
            "timestamp": _now_iso(),
            "signedBy": self.signer_id,
        }
        return {**body, "signature": sign(self.key, body)}

    def _write_checkpoint(self) -> None:
        assert self.checkpoint is not None
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.checkpoint.with_name(self.checkpoint.name + ".tmp")
        tmp.write_text(json.dumps(self._head(), sort_keys=True) + "\n")
        os.replace(tmp, self.checkpoint)


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    bad_line: int | None = None
    reason: str | None = None


def verify_log(path: Path, public_keys: dict[str, str], checkpoint: dict | None = None) -> VerifyResult:
    """Check the chain and every signature. ``public_keys`` maps signer id to key;
    pass only gateway keys (``Registry.gateway_keys``), or any registered key
    holder could write a log that verifies.

    With a ``checkpoint`` (an ``SMCP.AuditCheckpoint``), also check that the log
    still holds every entry the checkpoint vouches for.
    """
    hashes: list[str] = []
    result = _verify_chain(path, public_keys, hashes)
    if not result.ok or checkpoint is None:
        return result
    body = {k: v for k, v in checkpoint.items() if k != "signature"}
    if not verify(public_keys.get(body.get("signedBy", "")), body, checkpoint.get("signature")):
        return VerifyResult(False, result.entries, None, "the checkpoint signature does not verify")
    n = body.get("count")
    if not isinstance(n, int) or n < 0:
        return VerifyResult(False, result.entries, None, "the checkpoint has no valid count")
    if n > len(hashes):
        return VerifyResult(False, result.entries, None,
                            f"truncated: the checkpoint vouches for {n} entries and the log has {len(hashes)}")
    if n and hashes[n - 1] != body.get("headHash"):
        return VerifyResult(False, result.entries, n, "the log differs from the checkpoint at its head entry")
    return result


def _verify_chain(path: Path, public_keys: dict[str, str], hashes: list[str]) -> VerifyResult:
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
            hashes.append(prev)
            count += 1
    return VerifyResult(True, count)
