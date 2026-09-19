"""FR8: exact frame recovery, bounded reads, and strict decoding of frame data."""

import json
import struct

import numpy as np
import pytest

from stego_core import audio_codec, container, extraction, image_codec, location, lsb, payload, signing
from stego_core.errors import FrameError


@pytest.fixture(scope="module")
def extraction_keys():
    return signing.generate_keypair()


@pytest.fixture(params=["image", "audio"])
def carrier(request, png_rgb, wav_16_stereo):
    if request.param == "image":
        return image_codec.load_png(png_rgb), image_codec.save_png, image_codec.load_png
    return audio_codec.load_wav(wav_16_stereo), audio_codec.save_wav, audio_codec.load_wav


@pytest.mark.parametrize("n_lsb", range(1, 9))
@pytest.mark.parametrize("position", ["explicit", "derived", "last"])
def test_extract_exact_bytes_from_saved_png_and_wav(carrier, extraction_keys, n_lsb, position):
    cover, save, load = carrier
    # Every byte value and UTF-8 exercise exact byte recovery independently of
    # JSON decoding. Extraction must never reserialize the bytes being signed.
    original = bytes(range(256)) + "FR8: 隐藏消息".encode()
    signature = signing.sign(extraction_keys[0], original)
    frame = container.build_frame(original, signature, n_lsb, False)
    if position == "last":
        start = len(cover.elements) - (len(frame) * 8 + n_lsb - 1) // n_lsb
    elif position == "derived":
        start = location.derive_start(
            b"fr8-test-location-key",
            "fr8",
            "image" if cover.elements.dtype == np.uint8 else "audio",
            n_lsb,
            len(cover.elements),
            location.reserved_frame_bits(len(cover.elements), n_lsb),
        )
    else:
        start = 137
    stego = save(cover, lsb.embed_bits(cover.elements, lsb.bytes_to_bits(frame), start, n_lsb))
    reloaded = load(stego)
    before = reloaded.elements.copy()
    decoded = extraction.extract_frame(reloaded.elements, start, n_lsb)
    assert decoded.payload_bytes == original
    assert decoded.signature == signature
    assert decoded.n_lsb == n_lsb
    assert decoded.encrypted is False
    assert np.array_equal(reloaded.elements, before)


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        ((b"BAD!", 1, 0, 2, 10, 64), "bad magic"),
        ((b"ACW1", 2, 0, 2, 10, 64), "version"),
        ((b"ACW1", 1, 2, 2, 10, 64), "flags"),
        ((b"ACW1", 1, 0, 0, 10, 64), "n_lsb"),
        ((b"ACW1", 1, 0, 3, 10, 64), "LSB count"),
        ((b"ACW1", 1, 0, 2, 0, 64), "payload and a signature"),
        ((b"ACW1", 1, 0, 2, 10, 0), "payload and a signature"),
        ((b"ACW1", 1, 0, 2, 10, 63), "64 bytes"),
        ((b"ACW1", 1, 0, 2, 0xFFFFFFFF, 64), "past the end"),
    ],
)
def test_invalid_header_is_rejected_before_any_body_read(header, reason, monkeypatch):
    raw = struct.pack(">4sBBBIH", *header)
    elements = lsb.embed_bits(np.zeros(1000, dtype=np.uint8), lsb.bytes_to_bits(raw), 7, 2)
    original_extract = lsb.extract_bits
    reads = []

    def bounded_read(elements, start, n_bits, n_lsb):
        reads.append(n_bits)
        assert n_bits <= container.HEADER_SIZE * 8, "untrusted header caused a body read"
        return original_extract(elements, start, n_bits, n_lsb)

    monkeypatch.setattr(lsb, "extract_bits", bounded_read)
    with pytest.raises(FrameError, match=reason):
        extraction.extract_frame(elements, 7, 2)
    assert reads == [container.HEADER_SIZE * 8]


def test_partial_header_raises_frame_error():
    elements = lsb.embed_bits(np.zeros(32, dtype=np.uint8), lsb.bytes_to_bits(container.MAGIC), 0, 1)
    with pytest.raises(FrameError, match="header extends past"):
        extraction.extract_frame(elements, 0, 1)


@pytest.mark.parametrize("damage", ["truncated", "crc", "trailing"])
def test_frame_parser_rejects_damaged_or_extra_bytes(damage):
    raw = container.build_frame(b"payload", b"s" * 64, 2, False)
    if damage == "truncated":
        raw = raw[:-1]
    elif damage == "crc":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    else:
        raw += b"extra"
    with pytest.raises(FrameError):
        container.parse_frame(raw)


def test_extract_bits_rejects_negative_length():
    with pytest.raises(ValueError, match="n_bits"):
        lsb.extract_bits(np.zeros(10, dtype=np.uint8), 0, -1, 2)


@pytest.fixture
def valid_payload_fields():
    return {
        "version": payload.PAYLOAD_VERSION,
        "media_id": "fr8",
        "timestamp": "2026-09-19T00:00:00Z",
        "media_hash": "a" * 64,
        "nonce": "b" * 32,
        "cover_kind": "image",
        "n_lsb": 2,
        "shape": [64, 64, 3],
        "message_mime": "text/plain",
        "message_b64": "aGVsbG8=",
        "encrypted": False,
        "metadata": {"purpose": "FR8"},
    }


def test_decode_payload_preserves_original_bytes(valid_payload_fields):
    raw = json.dumps(valid_payload_fields, indent=2).encode()
    frame = extraction.ExtractedFrame(raw, b"s" * 64, 2, False)
    decoded = extraction.decode_payload(frame)
    assert decoded.message == b"hello"
    assert frame.payload_bytes == raw


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 99),
        ("version", True),
        ("n_lsb", "2"),
        ("n_lsb", 9),
        ("n_lsb", 3),
        ("encrypted", "false"),
        ("encrypted", True),
        ("shape", "64,64,3"),
        ("shape", [64, 64]),
        ("shape", [64, 64, -1]),
        ("shape", [64, 64, True]),
        ("metadata", []),
        ("metadata", {"team": 7}),
        ("message_mime", 42),
        ("media_hash", None),
        ("media_hash", "a" * 63),
        ("media_hash", "A" * 64),
        ("media_hash", "g" * 64),
        ("cover_kind", "unknown"),
        ("message_b64", "%%%"),
    ],
)
def test_decode_payload_rejects_malformed_fields(valid_payload_fields, field, value):
    valid_payload_fields[field] = value
    frame = extraction.ExtractedFrame(json.dumps(valid_payload_fields).encode(), b"s" * 64, 2, False)
    with pytest.raises(FrameError):
        extraction.decode_payload(frame)


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"null", b"{}", b"\xff"])
def test_decode_payload_rejects_malformed_documents(raw):
    with pytest.raises(FrameError):
        extraction.decode_payload(extraction.ExtractedFrame(raw, b"s" * 64, 2, False))
