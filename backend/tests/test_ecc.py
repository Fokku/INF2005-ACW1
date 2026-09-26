"""Unit tests for the bonus robust-embedding layer's repetition code
(spec Section 8): `ecc.py` in isolation, no cover files or pipeline involved.
"""

from __future__ import annotations

import numpy as np
import pytest

from stego_core import ecc
from stego_core.errors import FrameError


def test_validate_redundancy_rejects_even_and_out_of_range() -> None:
    for bad in (0, 2, 4, -1, 11):
        with pytest.raises(ValueError):
            ecc.validate_redundancy(bad)
    for good in (1, 3, 5, 7, 9):
        ecc.validate_redundancy(good)  # must not raise


def test_repeat_bits_redundancy_one_is_identity() -> None:
    bits = np.array([1, 0, 1, 1, 0], dtype=np.uint8)
    assert np.array_equal(ecc.repeat_bits(bits, 1), bits)
    assert np.array_equal(ecc.majority_vote(bits, 1), bits)


def test_repeat_and_majority_vote_roundtrip_without_damage() -> None:
    bits = np.array([1, 0, 1, 1, 0, 0, 1], dtype=np.uint8)
    repeated = ecc.repeat_bits(bits, 5)
    assert len(repeated) == len(bits) * 5
    assert np.array_equal(ecc.majority_vote(repeated, 5), bits)


def test_majority_vote_recovers_from_one_wiped_copy_of_three() -> None:
    """The whole point of block interleaving. A burst that destroys an
    entire copy still leaves the other two to outvote it."""
    bits = np.array([1, 0, 1, 1, 0, 0, 1, 1], dtype=np.uint8)
    repeated = ecc.repeat_bits(bits, 3)
    damaged = repeated.copy()
    n = len(bits)
    damaged[0:n] ^= 1  # flip every bit of copy 1
    assert np.array_equal(ecc.majority_vote(damaged, 3), bits)


def test_majority_vote_fails_once_two_of_three_copies_are_damaged() -> None:
    """Documents the stated limitation. Redundancy=3 tolerates at most one
    damaged copy, not two."""
    bits = np.array([1, 0, 1, 1, 0, 0, 1, 1], dtype=np.uint8)
    repeated = ecc.repeat_bits(bits, 3)
    damaged = repeated.copy()
    n = len(bits)
    damaged[0:n] ^= 1
    damaged[n : 2 * n] ^= 1
    assert not np.array_equal(ecc.majority_vote(damaged, 3), bits)


def test_majority_vote_rejects_length_not_a_multiple_of_redundancy() -> None:
    with pytest.raises(FrameError):
        ecc.majority_vote(np.zeros(10, dtype=np.uint8), 3)
