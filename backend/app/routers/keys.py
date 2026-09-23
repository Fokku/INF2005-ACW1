"""Key management (spec FR4).

Generating a key pair in the browser is a demo convenience. In a real
deployment the private key never leaves the signer's machine — say so during
the demo, and mention that these keys exist only for the assignment.
"""

from __future__ import annotations

from fastapi import APIRouter

from stego_core import signing

from .. import storage
from ..schemas import KeyInfo, KeyPairResult

router = APIRouter()


@router.post("/keys/generate", response_model=KeyPairResult)
async def generate(label: str = "team") -> KeyPairResult:
    """Create a fresh Ed25519 key pair and offer both halves as downloads."""
    private_pem, public_pem = signing.generate_keypair()
    fp = signing.fingerprint(public_pem)
    return KeyPairResult(
        key=KeyInfo(
            key_id=fp[:16],
            label=label,
            public_key_pem=public_pem.decode(),
            fingerprint=fp,
        ),
        public_key_file=storage.save(public_pem, f"{label}_ed25519.pub.pem"),
        private_key_file=storage.save(private_pem, f"{label}_ed25519.pem"),
    )


@router.post("/keys/inspect", response_model=KeyInfo)
async def inspect(public_key_pem: str) -> KeyInfo:
    """Show the fingerprint of a public key, so both parties can confirm they
    hold the same one before trusting a verdict."""
    fp = signing.fingerprint(public_key_pem.encode())
    return KeyInfo(key_id=fp[:16], label="imported", public_key_pem=public_key_pem, fingerprint=fp)
