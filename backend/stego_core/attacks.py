"""Tamper simulations that produce the negative test cases (spec Section 5).

The spec needs at least three negative cases, and the Attack Lab tab in the GUI
is one of the team's candidate innovations (spec Section 8, "Attack simulation
module"). Each function takes a stego file and returns a damaged copy, together
with the verdict it should produce.

Build these AFTER protect/verify work — they are how you prove the verdicts.
"""

from __future__ import annotations

from .verdict import Verdict

# What each attack is supposed to prove. Keep this table in sync with the GUI
# and with docs/design/verdict-table.md.
EXPECTED: dict[str, Verdict] = {
    "flip_bits": Verdict.TAMPERED,
    "crop": Verdict.TAMPERED,
    "lsb_scrub": Verdict.PAYLOAD_MISSING,
    "reencode": Verdict.PAYLOAD_MISSING,
    "corrupt_payload": Verdict.TAMPERED,
    "replay": Verdict.TAMPERED,
}


def flip_bits(data: bytes, kind: str, region: tuple[int, int] | None = None) -> bytes:
    """Flip HIGH bits in a region — a visible/audible edit that leaves the frame
    intact. The signature still verifies, but the recomputed media hash differs.
    Proves the hash check works. TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): flip_bits")


def crop(data: bytes, kind: str, fraction: float = 0.9) -> bytes:
    """Crop an image / truncate audio. Changes the shape, which was signed.
    TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): crop")


def lsb_scrub(data: bytes, kind: str, n_lsb: int) -> bytes:
    """Zero the low bits everywhere — destroys the payload without changing how
    the file looks or sounds. Proves LSB steganography is fragile, which is a
    real limitation to discuss. TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): lsb_scrub")


def reencode(data: bytes, kind: str) -> bytes:
    """PNG -> JPEG -> PNG, or resample the audio. This is exactly what an email
    client or a messaging app does to an inline image, so demo it deliberately
    rather than discovering it live. TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): reencode")


def corrupt_payload(data: bytes, kind: str, n_lsb: int, start: int) -> bytes:
    """Flip a few bits INSIDE the embedded frame. CRC fails -> Tampered.
    TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): corrupt_payload")


def replay(stego: bytes, other_cover: bytes, kind: str, n_lsb: int, start: int) -> bytes:
    """Transplant a valid signed frame into a DIFFERENT cover. The signature is
    genuine, but the signed media_hash and shape belong to the other file, so the
    verdict is Tampered. This is why the parameters are bound into the payload.
    TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): replay")
