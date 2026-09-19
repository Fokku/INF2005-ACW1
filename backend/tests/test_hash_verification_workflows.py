"""FR9 integration tests for protect-to-verify media-hash comparison.

These tests exercise the existing image and audio pipelines in explicit and
derived start modes. They do not redefine the FR10 verdict decision table.
"""

from __future__ import annotations

import numpy as np
import pytest

from stego_core import audio_codec, image_codec, pipeline, signing
from stego_core.verdict import Verdict


@pytest.fixture(scope="module")
def hash_keys() -> tuple[bytes, bytes]:
    return signing.generate_keypair()


def _protect_options(kind, mode, png_rgb, wav_16_stereo, private_key):
    return pipeline.ProtectOptions(
        cover_bytes=png_rgb if kind == "image" else wav_16_stereo,
        cover_kind=kind,
        message=b"FR9 protect-to-verify hash comparison",
        message_mime="text/plain",
        n_lsb=2,
        media_id=f"fr9-{kind}-{mode}",
        metadata={"requirement": "FR9"},
        private_key_pem=private_key,
        passphrase="fr9-derived-location" if mode == "derived" else None,
        explicit_start=137 if mode == "explicit" else None,
    )


def _verify_options(options, stego_bytes, public_key):
    return pipeline.VerifyOptions(
        stego_bytes=stego_bytes,
        cover_kind=options.cover_kind,
        public_key_pem=public_key,
        n_lsb=options.n_lsb,
        media_id=options.media_id,
        passphrase=options.passphrase,
        explicit_start=options.explicit_start,
    )


def _codecs(kind):
    if kind == "image":
        return image_codec.load_png, image_codec.save_png
    return audio_codec.load_wav, audio_codec.save_wav


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("mode", ["explicit", "derived"])
def test_unchanged_stego_reports_matching_embedded_and_recomputed_hashes(
    kind, mode, png_rgb, wav_16_stereo, hash_keys
):
    options = _protect_options(kind, mode, png_rgb, wav_16_stereo, hash_keys[0])
    protected = pipeline.protect(options)
    verified = pipeline.verify(_verify_options(options, protected.stego_bytes, hash_keys[1]))

    embedded_hash = protected.payload_json["media_hash"]
    assert verified.verdict is Verdict.AUTHENTIC, verified.reasons
    assert verified.signature_valid is True
    assert verified.media_hash_embedded == embedded_hash
    assert verified.media_hash_recomputed == embedded_hash
    assert verified.start_offset_used == protected.start_offset


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("mode", ["explicit", "derived"])
def test_content_change_above_lsb_plane_causes_hash_mismatch_after_valid_extraction(
    kind, mode, png_rgb, wav_16_stereo, hash_keys
):
    options = _protect_options(kind, mode, png_rgb, wav_16_stereo, hash_keys[0])
    protected = pipeline.protect(options)
    load, save = _codecs(kind)
    cover = load(protected.stego_bytes)

    # Alter the first element after the embedded frame. Flipping the bit just
    # above the selected carrier plane preserves every embedded frame bit, so
    # extraction and signature verification still succeed while FR9 alone
    # detects the changed media content.
    frame_elements = -(-(protected.frame_bytes * 8) // options.n_lsb)
    changed_index = protected.start_offset + frame_elements
    assert changed_index < len(cover.elements)
    changed_elements = cover.elements.copy()
    changed_elements[changed_index] ^= np.array(1 << options.n_lsb, dtype=changed_elements.dtype)
    changed_stego = save(cover, changed_elements)

    verified = pipeline.verify(_verify_options(options, changed_stego, hash_keys[1]))

    assert verified.signature_valid is True
    assert verified.payload_json is not None
    assert verified.media_hash_embedded == protected.payload_json["media_hash"]
    assert verified.media_hash_recomputed is not None
    assert verified.media_hash_recomputed != verified.media_hash_embedded
    assert verified.verdict is Verdict.TAMPERED, verified.reasons
    assert any("media hash" in reason for reason in verified.reasons)
