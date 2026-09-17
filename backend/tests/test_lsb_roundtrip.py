"""LSB round-trip: whatever you embed must come back out, for every n_lsb 1..8.

This is the first test to make pass. Everything else depends on it.
Remove the `pytest.skip` line as soon as lsb.py is implemented.
"""

from __future__ import annotations

import numpy as np
import pytest

from stego_core import lsb


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("dtype", [np.uint8, np.uint16])
def test_embed_extract_roundtrip(n_lsb: int, dtype) -> None:
    rng = np.random.default_rng(seed=n_lsb)
    elements = rng.integers(0, 256, size=5000, dtype=dtype)
    message = b"INF2005 ACW1 round-trip check"

    bits = lsb.bytes_to_bits(message)
    stego = lsb.embed_bits(elements, bits, start=137, n_lsb=n_lsb)
    out = lsb.extract_bits(stego, start=137, n_bits=len(bits), n_lsb=n_lsb)

    assert lsb.bits_to_bytes(out) == message
    assert stego.dtype == elements.dtype, "embedding must not change the dtype"


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_only_low_bits_change(n_lsb: int) -> None:
    """Embedding must leave the high bits alone — that is what makes the stable
    hash work and what keeps the distortion invisible."""
    rng = np.random.default_rng(seed=99)
    elements = rng.integers(0, 256, size=2000, dtype=np.uint8)
    bits = lsb.bytes_to_bits(b"x" * 50)
    stego = lsb.embed_bits(elements, bits, start=0, n_lsb=n_lsb)

    mask = np.uint8(~((1 << n_lsb) - 1) & 0xFF)
    assert np.array_equal(elements & mask, stego & mask)


def test_capacity_bits() -> None:
    """Already passes — capacity_bits is implemented as a worked example."""
    assert lsb.capacity_bits(1000, 1) == 1000
    assert lsb.capacity_bits(1000, 8) == 8000
    with pytest.raises(ValueError):
        lsb.capacity_bits(1000, 9)
