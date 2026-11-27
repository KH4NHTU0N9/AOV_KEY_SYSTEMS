# backend/crypto.py
import base64
import json
from typing import Any, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from config import get_private_key_path, get_public_key_path


def ensure_keypair() -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """Load existing Ed25519 keypair or generate a new 32-byte raw keypair."""
    priv_path = get_private_key_path()
    pub_path = get_public_key_path()

    if priv_path.exists() and pub_path.exists():
        raw_priv = base64.b64decode(priv_path.read_text(encoding="utf-8").strip())
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
        public_b64 = pub_path.read_text(encoding="utf-8").strip()
        return private_key, public_b64

    private_key = ed25519.Ed25519PrivateKey.generate()
    raw_priv = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    priv_b64 = base64.b64encode(raw_priv).decode("ascii")
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    priv_path.write_text(priv_b64, encoding="utf-8")
    pub_path.write_text(pub_b64, encoding="utf-8")
    return private_key, pub_b64


def sign_payload(payload: dict[str, Any]) -> Tuple[str, str]:
    """Serialize payload canonically and return (payload_raw_json, base64_signature)."""
    private_key, _ = ensure_keypair()
    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    signature = private_key.sign(payload_raw.encode("utf-8"))
    return payload_raw, base64.b64encode(signature).decode("ascii")


def verify_signature(payload_raw: str, signature_b64: str, public_b64: str | None = None) -> bool:
    """Verify an Ed25519 signature against raw JSON payload bytes."""
    try:
        if public_b64 is None:
            _, public_b64 = ensure_keypair()
        raw_pub = base64.b64decode(public_b64)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, payload_raw.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False
