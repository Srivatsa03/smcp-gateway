"""Server artifact pinning and signed configuration files. Extensions.

Artifact pin. The paper's registry records an "environment digest" for each
component and the v0.1 gateway reduced that to the version string the server
reports about itself, which a spoofed or outdated build can fake. For a stdio
server the gateway starts the process, so it can hash the code before it runs
it. The registry pins ``artifactSha256`` for the server; the gateway config
names the file or directory to hash. A mismatch stops the launch.

The pin covers the files named and nothing else: a vulnerable dependency
outside them is not seen, and a file swapped between the check and the exec
(a race) is not caught.

Signed config. The registry and policy files decide everything. An edit to
either goes live on the next call, which is how configuration drift happens.
With ``configSigner`` set, the gateway loads a registry or policy file only if
``<file>.sig`` carries a valid signature from that key over the file's exact
bytes. An unsigned edit is rejected, the last signed version stays in force,
and the rejection is audited.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from pathlib import Path

from .crypto import public_b64, sign, verify

SKIP_DIRS = {"__pycache__", ".git", ".venv", "node_modules"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def artifact_digest(path: Path) -> str:
    """SHA-256 of a file, or of a directory tree (sorted relative paths and file hashes)."""
    path = Path(path)
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        raise FileNotFoundError(f"{path} does not exist")
    h = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SKIP_SUFFIXES):
                continue
            p = Path(root) / name
            rel = p.relative_to(path).as_posix()
            h.update(rel.encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
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


def sign_file(path: Path, key, signer_id: str) -> Path:
    path = Path(path)
    body = {
        "type": "SMCP.ConfigSignature",
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "signedBy": signer_id,
        "signerKey": public_b64(key),
        "signedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    out = sig_path(path)
    out.write_text(json.dumps({**body, "signature": sign(key, body)}, indent=2) + "\n")
    return out


class FileVerifier:
    """Checks that a config file's bytes carry a valid signature from the trust anchor."""

    def __init__(self, signer_id: str, public_key: str) -> None:
        self.signer_id = signer_id
        self.public_key = public_key

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
        if body.get("sha256") != hashlib.sha256(data).hexdigest():
            raise ConfigSignatureError(f"{Path(path).name} changed after it was signed (unsigned edit)")
