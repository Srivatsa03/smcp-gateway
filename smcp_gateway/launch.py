"""Server artifact pinning and signed configuration files. Extensions.

Artifact pin. The paper's registry records an "environment digest" for each
component and the v0.1 gateway reduced that to the version string the server
reports about itself, which a spoofed or outdated build can fake. For a stdio
server the gateway starts the process, so it can hash the code before it runs
it. The registry pins ``artifactSha256`` for the server; the gateway config
names the file or directory to hash. A mismatch stops the launch.

Everything under the pinned directory counts, except ``.git``: bytecode caches,
nested dependency folders, and the targets of symlinks (followed, and the link
itself recorded). Python writes ``__pycache__`` into a writable install on first
import, so pin after a first run or make the install read-only. A dependency
outside the pinned directory is not seen, and a file swapped between the check
and the exec (a race) is not caught.

Signed config. The registry and policy files decide everything. An edit to
either goes live on the next call, which is how configuration drift happens.
With ``configSigner`` set, the gateway loads a registry or policy file only if
``<file>.sig`` carries a valid signature from that key over the file's exact
bytes. An unsigned edit is rejected, the last signed version stays in force,
and the rejection is audited.

Each signature carries a ``serial`` that ``sign-config`` increments. The
gateway refuses a serial lower than one it has loaded, so an old signed file
(say, from before a revocation) cannot be put back. Loaded serials are written
to the audit log, and a restarted gateway reads them back, so the rule holds
across restarts; the audit checkpoint protects those entries from truncation.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path

from .crypto import public_b64, sign, verify

def _file_sha(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def artifact_digest(path: Path) -> str:
    """SHA-256 of a file, or of a directory tree: sorted relative paths, each
    file's hash, and each symlink's target."""
    path = Path(path)
    if path.is_file():
        return _file_sha(str(path)).hex()
    if not path.is_dir():
        raise FileNotFoundError(f"{path} does not exist")
    h = hashlib.sha256()
    seen: set[Path] = set()

    def walk(directory: Path, rel: str) -> None:
        real = directory.resolve()
        if real in seen:  # a loop, or a second link to a directory already hashed
            h.update(b"S" + rel.encode() + b"\0")
            return
        seen.add(real)
        for entry in sorted(os.scandir(directory), key=lambda e: e.name):
            if entry.name == ".git":
                continue
            r = f"{rel}/{entry.name}" if rel else entry.name
            if entry.is_symlink():
                h.update(b"L" + r.encode() + b"\0" + os.readlink(entry.path).encode() + b"\0")
            if entry.is_dir():  # follows symlinks
                walk(Path(entry.path), r)
            elif entry.is_file():
                h.update(b"F" + r.encode() + b"\0" + _file_sha(entry.path))

    walk(path, "")
    return h.hexdigest()


def check_artifact(path: Path | None, expected: str | None) -> str | None:
    """None if the artifact matches its pin (or nothing is pinned), else the problem."""
    if not expected:
        return None
    if path is None:
        return "the registry pins artifactSha256 for this server but the gateway config names no serverArtifact"
    try:
        got = artifact_digest(path)
    except OSError as e:
        return f"cannot hash the server artifact {path}: {e}"
    if got != expected:
        return (f"the server artifact {path} hashes to {got[:16]}..., the registry pins {expected[:16]}... "
                f"(spoofed or changed install)")
    return None


# --- signed configuration files ------------------------------------------------------


class ConfigSignatureError(ValueError):
    pass


def sig_path(path: Path) -> Path:
    return Path(str(path) + ".sig")


def sign_file(path: Path, key, signer_id: str, serial: int | None = None) -> Path:
    """Write ``<path>.sig``. ``serial`` defaults to one more than the current one."""
    path = Path(path)
    if serial is None:
        try:
            serial = int(json.loads(sig_path(path).read_text()).get("serial", 0)) + 1
        except (OSError, ValueError, TypeError, AttributeError):
            serial = 1
    body = {
        "type": "SMCP.ConfigSignature",
        "file": path.name,
        "serial": serial,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "signedBy": signer_id,
        "signerKey": public_b64(key),
        "signedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    out = sig_path(path)
    out.write_text(json.dumps({**body, "signature": sign(key, body)}, indent=2) + "\n")
    return out


class FileVerifier:
    """Checks that a config file's bytes carry a valid signature from the trust
    anchor, with a serial no lower than any already loaded for that file."""

    def __init__(self, signer_id: str, public_key: str) -> None:
        self.signer_id = signer_id
        self.public_key = public_key
        self.serials: dict[str, int] = {}  # resolved path -> highest serial loaded
        self._sha: dict[str, str] = {}

    @staticmethod
    def key(path: Path) -> str:
        return str(Path(path).resolve())

    def seed(self, path: str, serial: int) -> None:
        """Remember a serial loaded before (read back from the audit log)."""
        self.serials[path] = max(self.serials.get(path, 0), int(serial))

    def __call__(self, path: Path, data: bytes) -> None:
        sp = sig_path(path)
        try:
            sig = json.loads(sp.read_text())
        except (OSError, json.JSONDecodeError):
            raise ConfigSignatureError(f"{Path(path).name} has no readable signature file {sp.name}") from None
        body = {k: v for k, v in sig.items() if k != "signature"}
        if body.get("signedBy") != self.signer_id or body.get("signerKey") != self.public_key:
            raise ConfigSignatureError(f"{sp.name} is not signed by the configured signer {self.signer_id}")
        if not verify(self.public_key, body, sig.get("signature")):
            raise ConfigSignatureError(f"the signature in {sp.name} does not verify")
        sha = hashlib.sha256(data).hexdigest()
        if body.get("sha256") != sha:
            raise ConfigSignatureError(f"{Path(path).name} changed after it was signed (unsigned edit)")
        serial = body.get("serial")
        if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
            raise ConfigSignatureError(f"{sp.name} has no valid serial")
        k = self.key(path)
        highest = self.serials.get(k, 0)
        if serial < highest or (serial == highest and k in self._sha and self._sha[k] != sha):
            raise ConfigSignatureError(f"rollback: {Path(path).name} is signed with serial {serial}, and serial "
                                       f"{highest} was already loaded")
        self.serials[k], self._sha[k] = serial, sha
