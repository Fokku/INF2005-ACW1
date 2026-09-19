"""FR7: bounded location recovery must respect element, not byte, alignment."""

import numpy as np
import pytest

from stego_core import container, location, lsb


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("dtype", [np.uint8, np.uint16])
def test_scan_finds_every_element_alignment_and_final_position(n_lsb, dtype):
    magic = lsb.bytes_to_bits(container.MAGIC)
    elements = np.zeros(200, dtype=dtype)
    last = len(elements) - (len(magic) + n_lsb - 1) // n_lsb
    for start in [*range(8), 137, last]:
        stego = lsb.embed_bits(elements, magic, start, n_lsb)
        assert location.scan_for_magic(stego, n_lsb) == start, (n_lsb, start)


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_scan_limit_counts_candidate_starts_and_includes_complete_magic(n_lsb):
    # The final candidate is searched even when its magic crosses the budget
    # boundary; a candidate at the limit itself must not be searched.
    magic = lsb.bytes_to_bits(container.MAGIC)
    elements = np.zeros(200, dtype=np.uint8)
    inside = lsb.embed_bits(elements, magic, 12, n_lsb)
    outside = lsb.embed_bits(elements, magic, 13, n_lsb)
    assert location.scan_for_magic(inside, n_lsb, max_positions=13) == 12
    assert location.scan_for_magic(outside, n_lsb, max_positions=13) is None
    assert location.scan_for_magic(outside, n_lsb, max_positions=14) == 13
    assert location.scan_for_magic(inside, n_lsb, max_positions=0) is None


def test_scan_ignores_magic_between_element_boundaries():
    # At three LSBs, a marker at bit eight is byte-aligned but not the start
    # of any element. The old scanner incorrectly rounded it to element two.
    elements = lsb.embed_bits(
        np.zeros(200, dtype=np.uint8), lsb.bytes_to_bits(b"\x00" + container.MAGIC), 0, 3
    )
    assert location.scan_for_magic(elements, 3) is None
    stego = lsb.embed_bits(elements, lsb.bytes_to_bits(container.MAGIC), 80, 3)
    assert location.scan_for_magic(stego, 3) == 80


def test_scan_returns_earliest_match_across_bit_alignments():
    magic = lsb.bytes_to_bits(container.MAGIC)
    elements = lsb.embed_bits(np.zeros(200, dtype=np.uint8), magic, 3, 3)
    elements = lsb.embed_bits(elements, magic, 24, 3)
    assert location.scan_for_magic(elements, 3) == 3


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_scan_handles_missing_truncated_and_empty_magic(n_lsb):
    assert location.scan_for_magic(np.zeros(200, dtype=np.uint8), n_lsb) is None
    assert location.scan_for_magic(np.zeros(0, dtype=np.uint8), n_lsb) is None
    truncated = lsb.embed_bits(
        np.zeros((24 + n_lsb - 1) // n_lsb, dtype=np.uint8),
        lsb.bytes_to_bits(container.MAGIC[:3]),
        0,
        n_lsb,
    )
    assert location.scan_for_magic(truncated, n_lsb) is None


@pytest.mark.parametrize("limit", [-1, 1.5, True])
def test_scan_rejects_invalid_limits(limit):
    with pytest.raises(ValueError, match="max_positions"):
        location.scan_for_magic(np.zeros(100, dtype=np.uint8), 1, max_positions=limit)


@pytest.mark.parametrize("n_lsb", [0, 9, 1.5, True])
def test_scan_rejects_invalid_lsb_counts(n_lsb):
    with pytest.raises(ValueError, match="n_lsb"):
        location.scan_for_magic(np.zeros(100, dtype=np.uint8), n_lsb)
