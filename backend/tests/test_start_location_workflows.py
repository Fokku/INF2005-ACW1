"""FR7 integration: use real PNG/WAV files to validate location settings."""

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from stego_core import audio_codec, image_codec, pipeline, signing
from stego_core.errors import CapacityError, StegoError
from stego_core.verdict import Verdict


@pytest.fixture(scope="module")
def location_keys() -> tuple[bytes, bytes]:
    return signing.generate_keypair()


@pytest.fixture(params=["image", "audio"])
def location_options(request, png_rgb, wav_16_stereo, location_keys):
    kind = request.param
    cover_bytes = png_rgb if kind == "image" else wav_16_stereo
    return pipeline.ProtectOptions(
        cover_bytes=cover_bytes,
        cover_kind=kind,
        message=b"FR7 start-location check",
        message_mime="text/plain",
        n_lsb=2,
        media_id=f"fr7-{kind}",
        metadata={},
        private_key_pem=location_keys[0],
        explicit_start=137,
    )


def _verify_options(options, outcome, public_key):
    return pipeline.VerifyOptions(
        stego_bytes=outcome.stego_bytes,
        cover_kind=options.cover_kind,
        public_key_pem=public_key,
        n_lsb=options.n_lsb,
        media_id=options.media_id,
        passphrase=options.passphrase,
        explicit_start=options.explicit_start,
    )


def _element_count(options):
    loader = image_codec.load_png if options.cover_kind == "image" else audio_codec.load_wav
    return len(loader(options.cover_bytes).elements)


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("mode", ["explicit", "derived"])
def test_sender_and_receiver_use_same_start(location_options, location_keys, n_lsb, mode):
    options = replace(location_options, n_lsb=n_lsb)
    if mode == "derived":
        options = replace(options, explicit_start=None, passphrase="phase-one-passphrase")
    protected = pipeline.protect(options)
    verified = pipeline.verify(_verify_options(options, protected, location_keys[1]))

    assert verified.verdict is Verdict.AUTHENTIC, verified.reasons
    assert verified.start_offset_used == protected.start_offset
    assert 0 <= protected.start_offset < _element_count(options)
    if mode == "explicit":
        assert protected.start_offset == 137


@pytest.mark.parametrize("n_lsb", [1, 3, 8])
def test_last_fitting_offset_round_trip_and_one_past_rejected(
    location_options, location_keys, n_lsb, monkeypatch
):
    # Keep serialized timestamp length fixed while measuring and rebuilding
    # the frame at a different offset; nonce/signature lengths are fixed too.
    fixed = datetime(2026, 9, 19, 0, 0, 0, 123456, tzinfo=UTC)
    monkeypatch.setattr(pipeline, "datetime", SimpleNamespace(now=lambda _tz: fixed))
    options = replace(location_options, n_lsb=n_lsb, explicit_start=0)
    first = pipeline.protect(options)
    needed = (first.frame_bytes * 8 + n_lsb - 1) // n_lsb
    last_start = _element_count(options) - needed
    options = replace(options, explicit_start=last_start)
    protected = pipeline.protect(options)
    verified = pipeline.verify(_verify_options(options, protected, location_keys[1]))
    assert verified.verdict is Verdict.AUTHENTIC, verified.reasons
    assert verified.start_offset_used == last_start

    with pytest.raises(CapacityError, match="remaining"):
        pipeline.protect(replace(options, explicit_start=last_start + 1))


def test_derived_start_checks_actual_frame_not_only_reservation(location_options, monkeypatch):
    fixed = datetime(2026, 9, 19, 0, 0, 0, 123456, tzinfo=UTC)
    monkeypatch.setattr(pipeline, "datetime", SimpleNamespace(now=lambda _tz: fixed))
    options = replace(location_options, n_lsb=8, explicit_start=0, message=b"")
    base = pipeline.protect(options)
    capacity = _element_count(options)  # one byte per element at eight LSBs
    message_size = ((capacity - base.frame_bytes - 4) // 4) * 3
    options = replace(options, message=b"x" * message_size)
    near_full = pipeline.protect(options)
    assert near_full.frame_bytes <= capacity
    with pytest.raises(CapacityError, match="remaining"):
        pipeline.protect(replace(options, explicit_start=None, passphrase="phase-one-passphrase"))


@pytest.mark.parametrize("offset", [-1, 1.5, True, 1_000_000])
def test_impossible_offsets_are_clear_validation_failures(location_options, location_keys, offset):
    options = replace(location_options, explicit_start=offset)
    with pytest.raises(StegoError, match="start"):
        pipeline.protect(options)
    verified = pipeline.verify(
        pipeline.VerifyOptions(
            stego_bytes=options.cover_bytes,
            cover_kind=options.cover_kind,
            public_key_pem=location_keys[1],
            n_lsb=options.n_lsb,
            media_id=options.media_id,
            explicit_start=offset,
        )
    )
    assert verified.verdict is Verdict.CANNOT_VERIFY
    assert "start" in verified.reasons[0]
    assert "unexpected error" not in verified.reasons[0]


@pytest.mark.parametrize("endpoint", ["protect", "verify"])
def test_api_explicit_mode_requires_offset_even_with_passphrase(location_options, location_keys, endpoint):
    options = location_options
    suffix = "png" if options.cover_kind == "image" else "wav"
    cover_field = "cover" if endpoint == "protect" else "stego"
    key_field = "private_key_pem" if endpoint == "protect" else "public_key_pem"
    key = location_keys[0 if endpoint == "protect" else 1]
    response = TestClient(app).post(
        f"/api/{endpoint}",
        files={cover_field: (f"cover.{suffix}", options.cover_bytes), key_field: ("key.pem", key)},
        data={
            "start_mode": "explicit",
            "passphrase": "must-not-be-used-as-fallback",
            "media_id": options.media_id,
            "message_text": "FR7",
        },
    )
    assert response.status_code == 400
    assert "explicit_start" in response.json()["detail"]


@pytest.mark.parametrize("offset", [-1, 1_000_000])
def test_api_protect_rejects_invalid_offset_without_server_error(location_options, location_keys, offset):
    options = location_options
    suffix = "png" if options.cover_kind == "image" else "wav"
    response = TestClient(app).post(
        "/api/protect",
        files={
            "cover": (f"cover.{suffix}", options.cover_bytes),
            "private_key_pem": ("key.pem", location_keys[0]),
        },
        data={
            "start_mode": "explicit",
            "explicit_start": str(offset),
            "media_id": options.media_id,
            "message_text": "FR7",
            "n_lsb": "2",
        },
    )
    assert response.status_code == 400
    assert "start" in response.json()["detail"]
