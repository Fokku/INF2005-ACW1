"""Pipeline-level tests for the bonus robust-embedding layer (spec Section
8): a full protect -> corrupt -> verify workflow proving redundancy actually
improves survival over the redundancy=1 baseline. See test_ecc.py for the
repetition code tested on its own.
"""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from stego_core import container, image_codec, pipeline, signing
from stego_core.verdict import Verdict


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


def _png_cover() -> bytes:
    rng = np.random.default_rng(7)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (96, 96, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


def _protect(cover_bytes: bytes, keys, redundancy: int, n_lsb: int = 4, start: int = 0):
    return pipeline.protect(
        pipeline.ProtectOptions(
            cover_bytes=cover_bytes,
            cover_kind="image",
            message=b"robust embedding demo message",
            message_mime="text/plain",
            n_lsb=n_lsb,
            media_id="robust-embedding-demo",
            metadata={},
            private_key_pem=keys[0],
            explicit_start=start,
            redundancy=redundancy,
        )
    )


def _verify(stego_bytes: bytes, keys, redundancy: int, n_lsb: int = 4, start: int = 0):
    return pipeline.verify(
        pipeline.VerifyOptions(
            stego_bytes=stego_bytes,
            cover_kind="image",
            public_key_pem=keys[1],
            n_lsb=n_lsb,
            media_id="robust-embedding-demo",
            explicit_start=start,
            redundancy=redundancy,
        )
    )


def _wipe_body_copies(
    stego_bytes: bytes, n_lsb: int, start: int, frame_bytes: int, redundancy: int, copy_indices: list[int]
) -> bytes:
    """Flip every embedded bit belonging to the given body copies (0-indexed).

    `pipeline.protect` embeds the header block ([H]x`redundancy`) and the
    body block ([payload+signature+CRC]x`redundancy`) as two separate
    back-to-back runs, not one repeated whole-frame block. See
    `extraction.extract_frame`'s docstring. This targets exactly the element
    range one particular body copy occupies, simulating a localized attack
    (a crop, an lsb_scrub, noise concentrated in one region) that wipes that
    copy outright while leaving the header block and the other copies intact.
    n_lsb must divide 8 evenly (1, 2, 4 or 8) for these ranges to land on
    whole elements, which is why the tests below fix n_lsb=4.
    """
    cover = image_codec.load_png(stego_bytes)
    elements = cover.elements.copy()
    header_elements = (container.HEADER_SIZE * 8 * redundancy) // n_lsb
    body_len_bytes = frame_bytes - container.HEADER_SIZE
    body_copy_elements = (body_len_bytes * 8) // n_lsb
    body_block_start = start + header_elements
    mask = np.array((1 << n_lsb) - 1, dtype=elements.dtype)
    for index in copy_indices:
        region_start = body_block_start + index * body_copy_elements
        elements[region_start : region_start + body_copy_elements] ^= mask
    return image_codec.save_png(cover, elements)


def test_redundancy_one_baseline_does_not_survive_a_wiped_region(keys) -> None:
    """Control case. With no redundancy, the corrupted region is the entire
    (only) body copy, so verification must not report Authentic."""
    cover_bytes = _png_cover()
    protected = _protect(cover_bytes, keys, redundancy=1)
    assert _verify(protected.stego_bytes, keys, redundancy=1).verdict == Verdict.AUTHENTIC

    damaged = _wipe_body_copies(
        protected.stego_bytes, n_lsb=4, start=0, frame_bytes=protected.frame_bytes,
        redundancy=1, copy_indices=[0],
    )
    result = _verify(damaged, keys, redundancy=1)
    assert result.verdict != Verdict.AUTHENTIC


def test_redundancy_three_survives_one_wiped_copy(keys) -> None:
    """The actual robust-embedding claim. The same kind of localized damage
    that breaks the redundancy=1 baseline above is fully recovered when the
    frame was embedded 3x, because 2 of the 3 body copies are still intact."""
    cover_bytes = _png_cover()
    protected = _protect(cover_bytes, keys, redundancy=3)
    assert _verify(protected.stego_bytes, keys, redundancy=3).verdict == Verdict.AUTHENTIC

    damaged = _wipe_body_copies(
        protected.stego_bytes, n_lsb=4, start=0, frame_bytes=protected.frame_bytes,
        redundancy=3, copy_indices=[1],  # wipe the middle copy only
    )
    result = _verify(damaged, keys, redundancy=3)
    assert result.verdict == Verdict.AUTHENTIC, result.reasons
    assert result.media_hash_embedded == result.media_hash_recomputed


def test_redundancy_three_still_fails_once_two_copies_are_wiped(keys) -> None:
    """Honest limitation check. Redundancy=3 is not magic: wiping two of the
    three body copies removes the majority and verification must not paper
    over it as Authentic."""
    cover_bytes = _png_cover()
    protected = _protect(cover_bytes, keys, redundancy=3)

    damaged = _wipe_body_copies(
        protected.stego_bytes, n_lsb=4, start=0, frame_bytes=protected.frame_bytes,
        redundancy=3, copy_indices=[0, 1],
    )
    result = _verify(damaged, keys, redundancy=3)
    assert result.verdict != Verdict.AUTHENTIC


@pytest.mark.parametrize(("embedded", "guessed"), [(1, 3), (3, 1), (3, 5)])
def test_redundancy_must_match_exactly_between_protect_and_verify(keys, embedded, guessed) -> None:
    """Redundancy is an out-of-band-agreed parameter, like n_lsb. The header
    block and body block are each sized as `redundancy` back-to-back copies,
    so a wrong guess in either direction misaligns where the verifier thinks
    the body starts, and it must not report Authentic. There is no "safe to
    under-guess" case here, unlike a plain repetition count with no block
    structure."""
    cover_bytes = _png_cover()
    protected = _protect(cover_bytes, keys, redundancy=embedded)
    result = _verify(protected.stego_bytes, keys, redundancy=guessed)
    assert result.verdict != Verdict.AUTHENTIC


def test_redundancy_inflates_required_capacity(keys) -> None:
    """A frame that fits at redundancy=1 can legitimately stop fitting once
    asked to repeat itself. This must surface as the same CapacityError
    demo case the spec requires, not a silent truncation."""
    from stego_core.errors import CapacityError

    rng = np.random.default_rng(11)
    buf = io.BytesIO()
    # 64x64x3 = 12288 elements; at n_lsb=1 that is 1536 bytes of raw capacity,
    # comfortably more than the ~465-byte frame needs once (fits), but far
    # short of what 9 back-to-back copies would need (~4185 bytes).
    Image.fromarray(rng.integers(0, 256, (64, 64, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
    small_cover = buf.getvalue()

    _protect(small_cover, keys, redundancy=1, n_lsb=1)  # fits fine on its own
    with pytest.raises(CapacityError):
        _protect(small_cover, keys, redundancy=9, n_lsb=1)
