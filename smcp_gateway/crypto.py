"""Signing, key agreement and canonical encoding.

Everything that is signed or MACed goes through :func:`canonical` first, so both
sides hash the same bytes regardless of key order or whitespace.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_INFO = b"smcp/v1/session"


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: object) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def nonce(n: int = 16) -> str:
    return b64e(os.urandom(n))


# --- long-term identity keys (Ed25519) ---------------------------------------


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(raw)


def save_key(key: Ed25519PrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    path.chmod(0o600)


def load_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def sign(key: Ed25519PrivateKey, obj: object) -> str:
    return b64e(key.sign(canonical(obj)))


def verify(public_key_b64: str | None, obj: object, signature: object) -> bool:
    if not public_key_b64 or not isinstance(signature, str):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64d(public_key_b64)).verify(b64d(signature), canonical(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- session keys (X25519 + HKDF) and MACs ------------------------------------


def ephemeral() -> tuple[X25519PrivateKey, str]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, b64e(pub)


def session_key(priv: X25519PrivateKey, peer_public_b64: str, transcript: bytes) -> bytes:
    """Derive the 32-byte session key, salted with the handshake transcript.

    Salting with the transcript binds the key to this exact handshake, so a key
    agreed in one session cannot be confused with another that reused an
    ephemeral value.
    """
    shared = priv.exchange(X25519PublicKey.from_public_bytes(b64d(peer_public_b64)))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(transcript).digest(),
        info=SESSION_INFO,
    ).derive(shared)


def mac(key: bytes, obj: object) -> str:
    return b64e(hmac.new(key, canonical(obj), hashlib.sha256).digest())


def mac_ok(key: bytes, obj: object, tag: object) -> bool:
    return isinstance(tag, str) and hmac.compare_digest(mac(key, obj), tag)
