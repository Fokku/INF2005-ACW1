"""Bit-level LSB replacement. The heart of the whole assignment (spec FR5, FR6).

Everything here works on a FLAT 1-D numpy array of unsigned integers called
`elements`:

  * image -> one element per colour channel of per pixel (h*w*channels), uint8
  * audio -> one element per sample per channel (frames*channels), uint8 or uint16

The codecs in `image_codec.py` / `audio_codec.py` do the converting, so this
module never needs to know whether it is looking at a picture or a sound.

>>> WHY UNSIGNED: 16-bit WAV samples are signed int16. Doing bit operations on
>>> int16 corrupts the high bits through sign extension. Always pass a uint16
>>> *view* of the samples (arr.view(np.uint16)), never the int16 array itself.
"""

from __future__ import annotations

import numpy as np

from .errors import CapacityError


def capacity_bits(n_elements: int, n_lsb: int) -> int:
    """How many payload bits fit in `n_elements` elements using `n_lsb` bits each.

    This one is done for you as a worked example of the maths everything else
    depends on. Note there is no header reservation here: the caller subtracts
    the frame overhead (see `container.frame_size_bits`).
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")
    return n_elements * n_lsb


def bytes_to_bits(data: bytes) -> np.ndarray:
    """Expand bytes into a uint8 array of 0/1, most-significant bit first.

    The MSB-first order is a convention. It only has to match `bits_to_bytes`,
    but write it down in docs/design/payload-format.md so the decoder side of
    the team implements the same thing.
    """
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Inverse of `bytes_to_bits`. `bits` length must be a multiple of 8.

    Enforced, not just documented: np.packbits silently zero-pads a short
    length to the next byte instead of raising, which would otherwise turn
    an off-by-a-few-bits caller mistake into a plausible-looking but WRONG
    byte string — the worst kind of bug in a module a signature is computed
    over, since it fails downstream (hash/signature mismatch) far from its
    actual cause instead of failing here, immediately and clearly.
    """
    if len(bits) % 8 != 0:
        raise ValueError(f"bits length must be a multiple of 8, got {len(bits)}")
    return np.packbits(bits).tobytes()


def embed_bits(elements: np.ndarray, bits: np.ndarray, start: int, n_lsb: int) -> np.ndarray:
    """Replace the low `n_lsb` bits of consecutive elements with `bits`.

    Args:
        elements: flat uint8/uint16 array (NOT modified — return a copy).
        bits:     flat array of 0/1 to hide.
        start:    index of the first element to write into (spec FR7).
        n_lsb:    1..8. At 8, the entire low byte of each element is replaced.

    Returns:
        A new array with the bits embedded.

    Raises:
        CapacityError: if the bits do not fit between `start` and the end.
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")
    if start < 0:
        raise ValueError(f"start must be >= 0, got {start}")

    bits = np.asarray(bits, dtype=np.uint8)
    n_needed = -(-len(bits) // n_lsb)  # ceil division
    if start + n_needed > len(elements):
        raise CapacityError(
            f"payload needs {n_needed} elements at n_lsb={n_lsb} starting at "
            f"{start}, but only {len(elements) - start} are available"
        )

    pad = n_needed * n_lsb - len(bits)
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    groups = bits.reshape(n_needed, n_lsb)

    weights = (1 << np.arange(n_lsb - 1, -1, -1, dtype=np.uint32))
    packed = groups.astype(np.uint32) @ weights  # MSB of each group first

    bit_width = elements.dtype.itemsize * 8
    clear_mask = np.array(~((1 << n_lsb) - 1) & ((1 << bit_width) - 1), dtype=elements.dtype)

    out = elements.copy()
    out[start:start + n_needed] &= clear_mask
    out[start:start + n_needed] |= packed.astype(elements.dtype)
    return out


def extract_bits(elements: np.ndarray, start: int, n_bits: int, n_lsb: int) -> np.ndarray:
    """Read `n_bits` bits back out of the low `n_lsb` bits, starting at `start`.

    Must be the exact inverse of `embed_bits`, including bit order.
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")
    if start < 0:
        raise ValueError(f"start must be >= 0, got {start}")

    n_elements = -(-n_bits // n_lsb)  # ceil division
    if start + n_elements > len(elements):
        raise CapacityError(
            f"need {n_elements} elements at n_lsb={n_lsb} starting at {start}, "
            f"but only {len(elements) - start} are available"
        )

    vals = (elements[start:start + n_elements] & np.array((1 << n_lsb) - 1, dtype=elements.dtype))
    weights = np.arange(n_lsb - 1, -1, -1)  # MSB of each group first, matches embed_bits
    unfolded = ((vals[:, None].astype(np.uint32) >> weights) & 1).astype(np.uint8)
    return unfolded.reshape(-1)[:n_bits]
