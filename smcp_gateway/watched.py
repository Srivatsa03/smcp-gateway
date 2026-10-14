"""YAML config files that are re-read when they change.

The registry and the policy are both files the gateway re-reads on the next
call after an edit, so a revocation takes effect mid-session. A bad edit (a
YAML typo, a rule that does not validate, or, with signed config, a missing or
wrong signature) is rejected: the last good version stays in force and the
gateway audits the rejection once.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable

import yaml

Verifier = Callable[[Path, bytes], None]


class WatchedFile:
    path: Path | None
    verifier: Verifier | None

    def _watch(self, path: Path | None, verifier: Verifier | None) -> None:
        self.path = Path(path) if path else None
        self.verifier = verifier
        self.rejection: str | None = None
        self._reload_lock = threading.Lock()
        self._stamp = self._file_stamp()

    @staticmethod
    def read(path: Path, verifier: Verifier | None = None) -> dict:
        """Read, verify and parse the same bytes, so nothing changes in between."""
        data = Path(path).read_bytes()
        if verifier is not None:
            verifier(Path(path), data)
        return yaml.safe_load(data) or {}

    def _file_stamp(self) -> tuple:
        if self.path is None:
            return ()
        out = []
        for p in (self.path, Path(str(self.path) + ".sig")) if self.verifier else (self.path,):
            try:
                st = os.stat(p)
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def _load(self, data: dict) -> None:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def reload_if_changed(self) -> bool:
        """Re-read the file if it changed. Returns True if a new version is now in force."""
        if self.path is None:
            return False
        with self._reload_lock:
            stamp = self._file_stamp()
            if stamp == self._stamp:
                return False
            self._stamp = stamp  # a rejected version is reported once, not on every call
            try:
                self._load(self.read(self.path, self.verifier))
            except Exception as e:  # keep the last good version
                self.rejection = f"{self.path.name}: {e}"
                return False
            return True

    def pop_rejection(self) -> str | None:
        r, self.rejection = self.rejection, None
        return r
