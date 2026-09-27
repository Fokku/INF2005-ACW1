from __future__ import annotations

import numpy as np

from .errors import FrameError

MIN_REDUNDANCY = 1
MAX_REDUNDANCY = 9  # kept odd so a majority vote is never a tie


def validate_redundancy(redundancy: int) -> None:
    """Raise ValueError unless `redundancy` is an odd int in [1, MAX_REDUNDANCY]."""
    if (
        isinstance(redundancy, bool)
        or not isinstance(redundancy, int)
        or redundancy < MIN_REDUNDANCY
        or redundancy > MAX_REDUNDANCY
        or redundancy % 2 == 0
    ):
        raise ValueError(
            f"redundancy must be an odd integer from {MIN_REDUNDANCY} to {MAX_REDUNDANCY}, got {redundancy!r}"
        )


def repeat_bits(bits: np.ndarray, redundancy: int) -> np.ndarray:
    """`redundancy` block-interleaved copies of `bits`, concatenated.

    redundancy=1 returns `bits` unchanged (this is what every existing
    caller that never passes redundancy effectively does).
    """
    validate_redundancy(redundancy)
    if redundancy == 1:
        return bits
    return np.tile(np.asarray(bits, dtype=np.uint8), redundancy)


def majority_vote(bits: np.ndarray, redundancy: int) -> np.ndarray:
    """Inverse of `repeat_bits`: collapse `redundancy` block-interleaved
    copies back into one copy by a per-bit-position majority vote.

    Raises FrameError if `bits` is not an exact multiple of `redundancy`
    long. That means the caller read the wrong number of bits, not that the
    embedded content is damaged, so it is treated the same way the rest of
    this codebase treats a structurally impossible frame.
    """
    validate_redundancy(redundancy)
    bits = np.asarray(bits, dtype=np.uint8)
    if redundancy == 1:
        return bits
    if len(bits) % redundancy != 0:
        raise FrameError(
            f"redundant bit run length {len(bits)} is not a multiple of redundancy {redundancy}"
        )
    copies = bits.reshape(redundancy, len(bits) // redundancy)
    votes = copies.sum(axis=0, dtype=np.uint16)
    return (votes * 2 > redundancy).astype(np.uint8)
