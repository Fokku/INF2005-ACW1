"""Digital signatures (spec FR4, learning outcome 3).

Ed25519 by default: 32-byte keys, 64-byte signatures. A small signature matters
because it is embedded inside the cover and eats capacity. RSA-PSS also works if
the team prefers to talk about RSA in the demo — keep the same three functions
and note the signature grows to 256 bytes at RSA-2048, which changes the frame
size in `container.py`.

Key files use standard PEM so any tool can read them:
    private  PKCS#8    keys/private/team_ed25519.pem   (gitignored, demo-only)
    public   SPKI      keys/public/team_ed25519.pub.pem (committed)
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import KeyError_

SIGNATURE_BYTES = 64  # Ed25519. Change this if you switch to RSA.


def generate_keypair() -> tuple[bytes, bytes]:
    """Create a fresh demo key pair. Returns (private_pem, public_pem)."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _load_private_key(private_pem: bytes) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise KeyError_(f"malformed private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyError_("private key is not Ed25519")
    return key


def _load_public_key(public_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:
        raise KeyError_(f"malformed public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyError_("public key is not Ed25519")
    return key


def sign(private_pem: bytes, message: bytes) -> bytes:
    """Sign `message` with the PEM private key. Returns the raw signature."""
    return _load_private_key(private_pem).sign(message)


def verify(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Return True if `signature` is a valid signature of `message`.

    Returns False for a bad signature (-> verdict `Signature Invalid`).
    A malformed KEY raises KeyError_ instead (-> verdict `Cannot Verify`).
    """
    key = _load_public_key(public_pem)
    try:
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def fingerprint(public_pem: bytes) -> str:
    """Short identifier for a public key: SHA-256 of its DER SPKI bytes, hex.

    Shown in the Keys tab so party A and party B can confirm they hold the same
    key.
    """
    key = _load_public_key(public_pem)
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()
