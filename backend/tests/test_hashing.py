"""FR9 unit tests for raw and stable SHA-256 hashing.

The stable media hash deliberately ignores the carrier bits used by LSB
embedding while authenticating the remaining content and format fields.
Pipeline-level comparison tests belong to the next FR9 phase.
"""

from __future__ import annotations

import numpy as np
import pytest

from stego_core import hashing

IMAGE_HEADER = {"kind": "image", "height": 2, "width": 4, "channels": 3}
AUDIO_HEADER = {"kind": "audio", "rate": 44100, "channels": 2, "width": 2}


def test_sha256_hex_known_vector() -> None:
    """Use the standard SHA-256 digest for ``abc`` as an independent oracle."""
    assert hashing.sha256_hex(b"abc") == ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


@pytest.mark.parametrize("digest", ["0" * 64, "0123456789abcdef" * 4])
def test_sha256_digest_validation_accepts_canonical_lowercase_hex(digest: str) -> None:
    assert hashing.is_sha256_hex_digest(digest)


@pytest.mark.parametrize(
    "digest",
    [None, 123, "", "a" * 63, "a" * 65, "A" * 64, "g" * 64, ("a" * 63) + " "],
)
def test_sha256_digest_validation_rejects_noncanonical_values(digest: object) -> None:
    assert not hashing.is_sha256_hex_digest(digest)


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("dtype,header", [(np.uint8, IMAGE_HEADER), (np.uint16, AUDIO_HEADER)])
def test_stable_hash_ignores_selected_carrier_bits(n_lsb: int, dtype, header) -> None:
    """Any change confined to the selected LSB plane must preserve the hash."""
    elements = np.arange(24, dtype=dtype)
    low_mask = np.array((1 << n_lsb) - 1, dtype=dtype)
    changed = elements ^ low_mask

    assert hashing.stable_media_hash(elements, n_lsb, header) == hashing.stable_media_hash(
        changed, n_lsb, header
    )


@pytest.mark.parametrize("n_lsb", range(1, 8))
def test_uint8_hash_detects_change_above_carrier_bits(n_lsb: int) -> None:
    """Image content above the selected LSB plane remains authenticated."""
    elements = np.arange(24, dtype=np.uint8)
    changed = elements.copy()
    changed[7] ^= np.uint8(1 << n_lsb)

    assert hashing.stable_media_hash(elements, n_lsb, IMAGE_HEADER) != hashing.stable_media_hash(
        changed, n_lsb, IMAGE_HEADER
    )


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_uint16_hash_detects_change_above_carrier_bits(n_lsb: int) -> None:
    """16-bit audio retains authenticated high bits at every supported depth."""
    elements = np.arange(24, dtype=np.uint16) * 257
    changed = elements.copy()
    changed[7] ^= np.uint16(1 << n_lsb)

    assert hashing.stable_media_hash(elements, n_lsb, AUDIO_HEADER) != hashing.stable_media_hash(
        changed, n_lsb, AUDIO_HEADER
    )


def test_stable_hash_canonicalises_header_key_order() -> None:
    elements = np.arange(24, dtype=np.uint8)
    reordered = {"channels": 3, "width": 4, "kind": "image", "height": 2}

    assert hashing.stable_media_hash(elements, 2, IMAGE_HEADER) == hashing.stable_media_hash(
        elements, 2, reordered
    )


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [("kind", "video"), ("rate", 48000), ("channels", 1), ("width", 1)],
)
def test_stable_hash_authenticates_format_fields(changed_field: str, changed_value: int | str) -> None:
    elements = np.arange(24, dtype=np.uint16) * 257
    changed_header = {**AUDIO_HEADER, changed_field: changed_value}

    assert hashing.stable_media_hash(elements, 2, AUDIO_HEADER) != hashing.stable_media_hash(
        elements, 2, changed_header
    )


@pytest.mark.parametrize("n_lsb", [0, 9])
def test_stable_hash_rejects_unsupported_lsb_depth(n_lsb: int) -> None:
    elements = np.arange(24, dtype=np.uint8)

    with pytest.raises(ValueError, match="n_lsb must be 1..8"):
        hashing.stable_media_hash(elements, n_lsb, IMAGE_HEADER)


@pytest.mark.parametrize("dtype,n_lsb", [(np.uint8, 3), (np.uint16, 8)])
def test_stable_hash_does_not_mutate_elements(dtype, n_lsb: int) -> None:
    elements = np.arange(24, dtype=dtype)
    original = elements.copy()

    hashing.stable_media_hash(elements, n_lsb, IMAGE_HEADER if dtype is np.uint8 else AUDIO_HEADER)

    assert np.array_equal(elements, original)
