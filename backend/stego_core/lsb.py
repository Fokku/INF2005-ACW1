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

from .errors import CapacityError  # noqa: F401  (raised once embed_bits is implemented)


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

    TODO(team): implement.
    Hint: np.unpackbits(np.frombuffer(data, dtype=np.uint8)) does this in one call.

    The MSB-first order is a convention. It only has to match `bits_to_bytes`,
    but write it down in docs/design/payload-format.md so the decoder side of
    the team implements the same thing.
    """
    raise NotImplementedError("TODO(team): bytes_to_bits — see docstring")


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Inverse of `bytes_to_bits`. `bits` length must be a multiple of 8.

    TODO(team): implement. Hint: np.packbits(bits).tobytes()
    """
    raise NotImplementedError("TODO(team): bits_to_bytes — see docstring")


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

    TODO(team): implement.

    Sketch:
      1. n_needed = ceil(len(bits) / n_lsb) elements; raise CapacityError if
         start + n_needed > len(elements).
      2. Pad `bits` with zeros up to n_needed * n_lsb.
      3. Reshape to (n_needed, n_lsb) and fold each row into one integer value
         (MSB of the group first), e.g. via a dot product with
         [2**(n_lsb-1), ..., 2, 1].
      4. out = elements.copy();
         clear:  out[start:start+n_needed] &= ~((1 << n_lsb) - 1)
         set:    out[start:start+n_needed] |= packed_values
      5. Keep the dtype: cast the mask and the packed values to elements.dtype
         so a uint8 array stays uint8.

    Watch out: `~((1 << n_lsb) - 1)` is a negative Python int. Build the mask as
    a numpy scalar of the right dtype, e.g.
        mask = np.array(~((1 << n_lsb) - 1) & 0xFFFF, dtype=elements.dtype)
    """
    raise NotImplementedError("TODO(team): embed_bits — see docstring")


def extract_bits(elements: np.ndarray, start: int, n_bits: int, n_lsb: int) -> np.ndarray:
    """Read `n_bits` bits back out of the low `n_lsb` bits, starting at `start`.

    Must be the exact inverse of `embed_bits`, including bit order.

    TODO(team): implement.

    Sketch:
      1. n_elements = ceil(n_bits / n_lsb).
      2. vals = elements[start:start+n_elements] & ((1 << n_lsb) - 1)
      3. Unfold each value into n_lsb bits, MSB of the group first.
      4. Flatten and return the first n_bits.
    """
    raise NotImplementedError("TODO(team): extract_bits — see docstring")
