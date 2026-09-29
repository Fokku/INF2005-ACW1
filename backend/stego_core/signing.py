"""Digital signatures (spec FR4, learning outcome 3).

Ed25519 by default: 32-byte keys, 64-byte signatures. A small signature matters
because it is embedded inside the cover and eats capacity.

Key files use standard PEM so any tool can read them:
    private  PKCS#8    keys/private/team_ed25519.pem   (gitignored, demo-only)
    public   SPKI      keys/public/team_ed25519.pub.pem (committed)
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import KeyError_

SIGNATURE_BYTES = 64  # Ed25519. Change this if you switch to RSA.


def generate_keypair() -> tuple[bytes, bytes]:
    """Create a fresh demo key pair. Returns (private_pem, public_pem)."""
    # The private key is the secret half - only the signer (party A) should ever
    # have this. It is used later to produce a signature over the message.
    private_key = Ed25519PrivateKey.generate()

    # Serialize the private key to PEM (a base64 text block) so it can be saved
    # to a .pem file on disk. PKCS8 is just the standard container format for
    # private keys. NoEncryption() means the PEM is not password-protected -
    # fine for this demo/coursework setting, not something you'd do in production.
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # The public key is derived from the private key and is safe to share -
    # it's what party B uses to check the signature. SubjectPublicKeyInfo (SPKI)
    # is the standard format for public keys.
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# `cryptography` raises UnsupportedAlgorithm, which is not a ValueError, for a
# well-formed PEM whose algorithm OID or curve it does not know (for example an
# EC key on brainpoolP160r1). It is still just a key we cannot use, so it becomes
# KeyError_ like any other bad key: 400 from the API, Cannot Verify in a verdict,
# skipped in the keys/public listing, never an unhandled 500.
_UNUSABLE_KEY = (ValueError, TypeError, UnsupportedAlgorithm)


def _load_private_key(private_pem: bytes) -> Ed25519PrivateKey:
    """Parse a PEM byte string back into a usable private key object."""
    try:
        key = serialization.load_pem_private_key(private_pem, password=None)
    except _UNUSABLE_KEY as exc:
        # Not valid PEM / not a key we can parse at all -> treat as a bad key,
        # not a crash. Caller turns this into an HTTP 400 or "Cannot Verify".
        raise KeyError_(f"malformed private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        # PEM parsed fine but it's e.g. an RSA key - we only support Ed25519.
        raise KeyError_("private key is not Ed25519")
    return key


def _load_public_key(public_pem: bytes) -> Ed25519PublicKey:
    """Parse a PEM byte string back into a usable public key object."""
    try:
        key = serialization.load_pem_public_key(public_pem)
    except _UNUSABLE_KEY as exc:
        raise KeyError_(f"malformed public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise KeyError_("public key is not Ed25519")
    return key


def sign(private_pem: bytes, message: bytes) -> bytes:
    """Sign `message` with the PEM private key. Returns the raw signature.

    Called with the serialized Payload bytes (pipeline.py), not the raw cover
    file - the payload already carries media_hash, a hash of the cover's
    pixels/samples, so signing it also binds the signature to the cover
    without hashing gigabytes of image/audio data here. Ed25519 hashes the
    message internally (SHA-512, per the algorithm spec) before signing, so
    the output is always a fixed 64 bytes regardless of message length.
    """
    return _load_private_key(private_pem).sign(message)


def verify(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Return True if `signature` is a valid signature of `message`.

    Returns False for a bad signature (-> verdict `Signature Invalid`).
    A malformed KEY raises KeyError_ instead (-> verdict `Cannot Verify`).
    """
    key = _load_public_key(public_pem)
    try:
        # key.verify() raises InvalidSignature rather than returning a bool,
        # so we convert that exception into a clean True/False here.
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def fingerprint(public_pem: bytes) -> str:
    """Short identifier for a public key: SHA-256 of its DER SPKI bytes, hex.

    Shown in the Keys tab so party A and party B can confirm they hold the same
    key. DER is just the raw binary encoding of the same public key that PEM
    wraps in base64 text - hashing that binary form gives a stable, short
    fingerprint that's easy to eyeball-compare between two people.
    """
    key = _load_public_key(public_pem)
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()
