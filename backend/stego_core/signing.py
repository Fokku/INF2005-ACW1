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

# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric.ed25519 import (
#     Ed25519PrivateKey, Ed25519PublicKey,
# )

SIGNATURE_BYTES = 64  # Ed25519. Change this if you switch to RSA.


def generate_keypair() -> tuple[bytes, bytes]:
    """Create a fresh demo key pair. Returns (private_pem, public_pem).

    TODO(team): implement.

    Sketch:
      priv = Ed25519PrivateKey.generate()
      private_pem = priv.private_bytes(PEM, PKCS8, NoEncryption())
      public_pem  = priv.public_key().public_bytes(PEM, SubjectPublicKeyInfo)
    """
    raise NotImplementedError("TODO(team): generate_keypair — see docstring")


def sign(private_pem: bytes, message: bytes) -> bytes:
    """Sign `message` with the PEM private key. Returns the raw signature.

    TODO(team): implement.
    Sketch: serialization.load_pem_private_key(private_pem, password=None).sign(message)
    """
    raise NotImplementedError("TODO(team): sign — see docstring")


def verify(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Return True if `signature` is a valid signature of `message`.

    Must return False (not raise) for a bad signature — the caller turns that
    into the verdict `Signature Invalid`. Let a malformed KEY raise, because
    that is `Cannot Verify` instead.

    TODO(team): implement.
    Sketch: load_pem_public_key(...).verify(signature, message); except InvalidSignature: return False
    """
    raise NotImplementedError("TODO(team): verify — see docstring")


def fingerprint(public_pem: bytes) -> str:
    """Short identifier for a public key: SHA-256 of its DER SPKI bytes, hex.

    Shown in the Keys tab so party A and party B can confirm they hold the same
    key. TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): fingerprint — see docstring")
