"""FR7: start-location bounds, reproducibility, and legacy compatibility."""

import pytest

from stego_core import location
from stego_core.errors import CapacityError


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_explicit_start_accepts_zero_and_last_fitting_element(n_lsb: int) -> None:
    # 17 bits also exercises partial-element rounding at most LSB counts.
    needed = (17 + n_lsb - 1) // n_lsb
    location.validate_start(100, 0, 17, n_lsb)
    location.validate_start(100, 100 - needed, 17, n_lsb)
    with pytest.raises(CapacityError, match="remaining"):
        location.validate_start(100, 101 - needed, 17, n_lsb)


@pytest.mark.parametrize("start", [-1, 1.5, True, "1"])
def test_explicit_start_rejects_invalid_indices(start) -> None:
    with pytest.raises(ValueError, match="start"):
        location.validate_start(100, start, 8, 1)


@pytest.mark.parametrize("start", [100, 101])
def test_explicit_start_rejects_end_and_beyond(start: int) -> None:
    with pytest.raises(CapacityError):
        location.validate_start(100, start, 8, 1)


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_derived_start_accepts_exact_fit(n_lsb: int) -> None:
    assert location.derive_start(b"test-key", "id", "image", n_lsb, 10, 10 * n_lsb) == 0
    with pytest.raises(CapacityError):
        location.derive_start(b"test-key", "id", "image", n_lsb, 10, 10 * n_lsb + 1)


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("image", [1000, 326, 619, 581, 1109, 881, 627, 68]),
        ("audio", [295, 246, 784, 968, 242, 1015, 107, 1133]),
    ],
)
def test_derived_offsets_match_pre_phase_one_values(kind: str, expected: list[int]) -> None:
    # Captured from the original implementation: changing these would move
    # the decoder away from payloads in existing derived-mode files.
    for n_lsb, offset in enumerate(expected, start=1):
        reserved = location.reserved_frame_bits(12000, n_lsb)
        for _ in range(2):
            start = location.derive_start(bytes(range(32)), "fr7-compatibility", kind, n_lsb, 12000, reserved)
            assert start == offset
            location.validate_start(12000, start, reserved, n_lsb)


@pytest.mark.parametrize("n_lsb", [0, 9, 1.5, True])
def test_location_functions_reject_invalid_lsb_counts(n_lsb) -> None:
    with pytest.raises(ValueError, match="n_lsb"):
        location.reserved_frame_bits(100, n_lsb)
    with pytest.raises(ValueError, match="n_lsb"):
        location.derive_start(b"key", "id", "image", n_lsb, 100, 8)
    with pytest.raises(ValueError, match="n_lsb"):
        location.validate_start(100, 0, 8, n_lsb)


@pytest.mark.parametrize("n_elements", [-1, 1.5, True])
def test_location_functions_reject_invalid_cover_sizes(n_elements) -> None:
    with pytest.raises(ValueError, match="n_elements"):
        location.reserved_frame_bits(n_elements, 1)
    with pytest.raises(ValueError, match="n_elements"):
        location.derive_start(b"key", "id", "image", 1, n_elements, 8)


@pytest.mark.parametrize("frame_bits", [0, -1, 1.5, True])
def test_derived_start_rejects_invalid_reservations(frame_bits) -> None:
    with pytest.raises(ValueError, match="frame_bits"):
        location.derive_start(b"key", "id", "image", 1, 100, frame_bits)


def test_empty_cover_cannot_hold_a_frame() -> None:
    assert location.reserved_frame_bits(0, 1) == 0
    with pytest.raises(CapacityError):
        location.validate_start(0, 0, 8, 1)
    with pytest.raises(CapacityError):
        location.derive_start(b"key", "id", "image", 1, 0, 8)


def test_derived_start_requires_a_key() -> None:
    with pytest.raises(ValueError, match="k_loc"):
        location.derive_start(b"", "id", "image", 1, 100, 8)
