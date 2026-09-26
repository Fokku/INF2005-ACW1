"""Optional robust-embedding layer (spec Section 8 bonus challenge, not a
required FR). Off by default everywhere. Every existing test and default
code path is unaffected unless a caller explicitly asks for redundancy > 1.

The problem this solves: right now, one damaged bit anywhere inside the
embedded frame either flips the CRC (leading to Tampered) or, in the worst
case, damages the magic bytes themselves (leading to Payload Missing or
Wrong Start Location). LSB replacement is already about the most fragile
embedding domain there is. A lossy re-encode, resampling, or even mild added
noise touches exactly the bits the payload lives in, and there is currently
no way for a frame to survive that and still verify.

The fix: `pipeline.protect` repeats the frame's header and its body (payload
plus signature plus CRC) separately, each as `redundancy` whole copies
placed back to back. That is, [H] x `redundancy` immediately followed by
[body] x `redundancy`. Then `extraction.extract_frame` majority-votes each
block back down to one copy before handing the result to the existing,
unmodified `container.parse_header` / `parse_frame`. If fewer than half the
copies of a given bit are wrong, the vote recovers the original bit and
everything downstream (CRC, signature, hash) runs exactly as it always has.
This is classic repetition-code error correction, the simplest of the three
techniques the spec suggests, and it needs no change to the signed payload
format or the frame layout at all. This module only decides what gets
embedded, never what the frame itself means.

Why the header and body are repeated as two separate blocks, rather than
repeating the whole frame as one block: extraction has to read the header
first to learn the payload/signature lengths, before it can know how many
more bits the body needs. It cannot know the total frame length up front.
If the whole frame were repeated as one block, the header's `redundancy`
copies would sit `frame_bits` apart, a distance that is only known after
parsing a header that has not been read yet, which is circular. Repeating
the header alone first, at a fixed length both sides already know, breaks
that circularity, and the body is then repeated the same way once its
length is known.

Why whole-copy repetition rather than bit-by-bit repetition (b0 b0 b0 b1 b1
b1 and so on): the damage this project's own Attack Lab produces, such as
flip_bits, crop, lsb_scrub or a lossy re-encode, is localized: a contiguous
run of corrupted elements. Bit-by-bit repetition puts every copy of a given
bit right next to each other, so one contiguous burst wipes every copy of
the bits it touches, which is no better than no redundancy at all.
Whole-copy blocks spread each copy across a different third of the embedded
region, so a burst confined to one copy still leaves the other copies, and
the vote, intact.

Limitation worth saying in the demo: `redundancy` is an out-of-band-agreed
parameter, exactly like `n_lsb`, so both sides must use the same value.
Because the header and body are separate blocks, guessing wrong in either
direction (too low or too high) misaligns where the body is read from and
fails, not just guessing too high. Within a single copy count, this defends
against localized or random bit corruption up to floor((redundancy - 1) / 2)
damaged copies out of `redundancy`. It does not defend against damage that
hits every copy at once, such as a full LSB-plane scrub or an n_lsb
mismatch, because there is no surviving majority left to vote with. Genuine
spread-spectrum embedding, spreading the signal across the frequency domain
rather than repeating it in the same LSB domain, would be needed for that,
and is out of scope here.
"""

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
