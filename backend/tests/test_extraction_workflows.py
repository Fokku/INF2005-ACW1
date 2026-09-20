"""FR8: file-based extraction failures and API delivery of recovered messages."""

import base64
import json
import zlib
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app import storage
from app.main import app
from stego_core import audio_codec, container, extraction, image_codec, lsb, pipeline, signing
from stego_core.verdict import Verdict


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


@pytest.fixture(params=["image", "audio"])
def options(request, png_rgb, wav_16_stereo, keys):
    return pipeline.ProtectOptions(
        cover_bytes=png_rgb if request.param == "image" else wav_16_stereo,
        cover_kind=request.param,
        message="FR8: recover this message exactly. 隐藏消息".encode(),
        message_mime="text/plain",
        n_lsb=2,
        media_id=f"fr8-{request.param}",
        metadata={"purpose": "FR8 extraction"},
        private_key_pem=keys[0],
        explicit_start=137,
    )


def _codecs(kind):
    if kind == "image":
        return image_codec.load_png, image_codec.save_png
    return audio_codec.load_wav, audio_codec.save_wav


def _receiver(options, stego, public_key):
    return pipeline.VerifyOptions(
        stego_bytes=stego,
        cover_kind=options.cover_kind,
        public_key_pem=public_key,
        n_lsb=options.n_lsb,
        media_id=options.media_id,
        explicit_start=options.explicit_start,
        passphrase=options.passphrase,
    )


def _canonical(fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _replace_frame(options, protected, raw):
    load, save = _codecs(options.cover_kind)
    cover = load(protected.stego_bytes)
    elements = lsb.embed_bits(cover.elements, lsb.bytes_to_bits(raw), protected.start_offset, options.n_lsb)
    return save(cover, elements)


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("encrypted", [False, True])
def test_pipeline_recovers_exact_signed_payload_and_signature(options, keys, n_lsb, encrypted):
    options = replace(
        options,
        n_lsb=n_lsb,
        encrypt_message=encrypted,
        passphrase="fr8-encryption-test" if encrypted else None,
    )
    protected = pipeline.protect(options)
    load, _ = _codecs(options.cover_kind)
    extracted = extraction.extract_frame(load(protected.stego_bytes).elements, protected.start_offset, n_lsb)
    assert extracted.payload_bytes == _canonical(protected.payload_json)
    assert extracted.signature == protected.signature
    assert extracted.encrypted is encrypted
    verified = pipeline.verify(_receiver(options, protected.stego_bytes, keys[1]))
    assert verified.verdict is Verdict.AUTHENTIC, verified.reasons
    assert verified.signature_valid is True
    assert base64.b64decode(verified.payload_json["message_b64"]) == options.message


@pytest.mark.parametrize(
    ("damage", "reason"),
    [
        ("version", "version"),
        ("flags", "flags"),
        ("lsb", "LSB count"),
        ("payload_length", "past the end"),
        ("empty_payload", "payload and a signature"),
        ("signature_length", "64 bytes"),
        ("crc", "CRC mismatch"),
        ("malformed_json", "malformed payload"),
        ("payload_lsb", "LSB count"),
        ("encryption_flag", "encryption flag"),
        ("metadata", "metadata"),
    ],
)
def test_damaged_frames_use_existing_tampered_rule(options, keys, damage, reason):
    protected = pipeline.protect(options)
    payload_bytes = _canonical(protected.payload_json)
    raw = bytearray(container.build_frame(payload_bytes, protected.signature, options.n_lsb, False))
    if damage == "version":
        raw[4] = 99
    elif damage == "flags":
        raw[5] = 0x80
    elif damage == "lsb":
        raw[6] = 3
    elif damage == "payload_length":
        raw[7:11] = b"\xff" * 4
    elif damage == "empty_payload":
        raw[7:11] = b"\x00" * 4
    elif damage == "signature_length":
        raw[11:13] = (63).to_bytes(2, "big")
    elif damage == "crc":
        raw[-1] ^= 1
    elif damage == "encryption_flag":
        raw[5] = 1
        raw[-4:] = zlib.crc32(raw[:-4]).to_bytes(4, "big")
    else:
        fields = dict(protected.payload_json)
        if damage == "payload_lsb":
            fields["n_lsb"] = 3
        elif damage == "metadata":
            fields["metadata"] = ["not a map"]
        malformed = b"{" if damage == "malformed_json" else _canonical(fields)
        raw = container.build_frame(malformed, signing.sign(keys[0], malformed), options.n_lsb, False)
    stego = _replace_frame(options, protected, bytes(raw))
    verified = pipeline.verify(_receiver(options, stego, keys[1]))
    assert verified.verdict is Verdict.TAMPERED, verified.reasons
    assert any(reason in item for item in verified.reasons)
    assert verified.payload_json is None
    assert verified.signature_valid is None
    assert verified.start_offset_used == protected.start_offset


@pytest.mark.parametrize("part", ["header", "body"])
def test_truncated_png_or_wav_frame_is_not_misreported_as_wrong_start(options, keys, part):
    protected = pipeline.protect(options)
    load, save = _codecs(options.cover_kind)
    cover = load(protected.stego_bytes)
    surviving_bytes = 8 if part == "header" else protected.frame_bytes - 1
    keep = protected.start_offset + surviving_bytes * 8 // options.n_lsb
    keep -= keep % cover.channels
    if options.cover_kind == "image":
        truncated_cover = replace(cover, height=1, width=keep // cover.channels)
    else:
        truncated_cover = replace(cover, frames=keep // cover.channels)
    truncated = save(truncated_cover, cover.elements[:keep])
    verified = pipeline.verify(_receiver(options, truncated, keys[1]))
    assert verified.verdict is Verdict.TAMPERED, verified.reasons
    assert any("past the end" in reason for reason in verified.reasons)
    assert verified.payload_json is None


def test_wrong_signature_still_reaches_existing_signature_check(options, keys):
    protected = pipeline.protect(options)
    signature = bytes([protected.signature[0] ^ 1]) + protected.signature[1:]
    raw = container.build_frame(_canonical(protected.payload_json), signature, options.n_lsb, False)
    stego = _replace_frame(options, protected, raw)
    verified = pipeline.verify(_receiver(options, stego, keys[1]))
    assert verified.verdict is Verdict.SIGNATURE_INVALID
    assert verified.signature_valid is False
    assert verified.payload_json is None


def test_wrong_lsb_setting_never_returns_payload(options, keys):
    protected = pipeline.protect(options)
    verified = pipeline.verify(replace(_receiver(options, protected.stego_bytes, keys[1]), n_lsb=3))
    assert verified.verdict in (Verdict.PAYLOAD_MISSING, Verdict.WRONG_START_LOCATION)
    assert verified.payload_json is None


def _api_verify(options, stego, public_key):
    suffix = "png" if options.cover_kind == "image" else "wav"
    return TestClient(app).post(
        "/api/verify",
        files={"stego": (f"stego.{suffix}", stego), "public_key_pem": ("public.pem", public_key)},
        data={
            "media_id": options.media_id,
            "n_lsb": str(options.n_lsb),
            "start_mode": "explicit",
            "explicit_start": str(options.explicit_start),
        },
    )


def test_api_rejects_malformed_metadata_without_response_validation_crash(options, keys):
    protected = pipeline.protect(options)
    fields = dict(protected.payload_json, metadata=["invalid"])
    raw_payload = _canonical(fields)
    raw = container.build_frame(raw_payload, signing.sign(keys[0], raw_payload), options.n_lsb, False)
    response = _api_verify(options, _replace_frame(options, protected, raw), keys[1])
    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "Tampered"
    assert response.json()["payload"] is None


def test_api_returns_exact_binary_message_download(options, keys, tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)
    options = replace(options, message=bytes(range(256)), message_mime="application/octet-stream")
    protected = pipeline.protect(options)
    response = _api_verify(options, protected.stego_bytes, keys[1])
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["verdict"] == "Authentic"
    downloaded = TestClient(app).get(report["payload"]["message_file"]["download_url"])
    assert downloaded.status_code == 200
    assert downloaded.content == options.message
