"""Round-trip and rejection tests for the AVI video cover (audio-track embedding).

Unlike `image_codec`/`audio_codec` there is no ready-made stdlib writer for
AVI (there is no `wave`-for-video), so this file builds minimal synthetic AVI
buffers by hand with the same chunk layout a real one would have: a `vids`
stream (untouched, dummy frame bytes) and an `auds` stream carrying PCM,
split across several `movi` chunks the way a real interleaved AVI is.
"""

from __future__ import annotations

import struct

import numpy as np
import pytest

from stego_core import video_codec
from stego_core.errors import UnsupportedCoverError


def _chunk(fourcc: bytes, payload: bytes) -> bytes:
    out = fourcc + struct.pack("<I", len(payload)) + payload
    return out + b"\x00" if len(payload) % 2 else out


def _list(list_type: bytes, inner: bytes) -> bytes:
    return _chunk(b"LIST", list_type + inner)


def _strl(fcc_type: bytes, strf: bytes) -> bytes:
    strh = fcc_type + b"\x00" * 44  # AVISTREAMHEADER; only the fccType is read
    return _list(b"strl", _chunk(b"strh", strh) + _chunk(b"strf", strf))


def _build_avi(
    pcm_bytes: bytes,
    *,
    channels: int = 1,
    sample_width: int = 2,
    sample_rate: int = 8000,
    n_pcm_chunks: int = 3,
    width: int = 64,
    height: int = 48,
) -> bytes:
    bits_per_sample = sample_width * 8
    block_align = channels * sample_width
    wave_format = struct.pack(
        "<HHIIHH",
        1,  # WAVE_FORMAT_PCM
        channels,
        sample_rate,
        sample_rate * block_align,
        block_align,
        bits_per_sample,
    )
    bitmap_info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, 0, 0, 0, 0, 0)

    total_frames = n_pcm_chunks
    avih = struct.pack(
        "<IIIIIIIIIIIIII",
        1_000_000 // 25,  # dwMicroSecPerFrame (25 fps)
        0,
        0,
        0,
        total_frames,  # dwTotalFrames
        0,
        2,  # dwStreams
        0,
        width,
        height,
        0,
        0,
        0,
        0,
    )

    hdrl = _list(
        b"hdrl",
        _chunk(b"avih", avih) + _strl(b"vids", bitmap_info) + _strl(b"auds", wave_format),
    )

    # Split the PCM payload across several `01wb` chunks interleaved with dummy
    # `00dc` video chunks, the way a real interleaved AVI would.
    step = max(1, len(pcm_bytes) // n_pcm_chunks)
    movi_body = b""
    pos = 0
    for i in range(n_pcm_chunks):
        piece = pcm_bytes[pos : pos + step] if i < n_pcm_chunks - 1 else pcm_bytes[pos:]
        movi_body += _chunk(b"00dc", b"\x99" * 8)  # dummy video frame, must be left untouched
        movi_body += _chunk(b"01wb", piece)
        pos += step
    movi = _list(b"movi", movi_body)

    riff_body = b"AVI " + hdrl + movi
    return _chunk(b"RIFF", riff_body)


def test_round_trip_16bit_stereo() -> None:
    rng = np.random.default_rng(seed=1)
    samples = rng.integers(-32768, 32767, size=4000, dtype=np.int16)
    pcm_bytes = samples.tobytes()

    avi_bytes = _build_avi(pcm_bytes, channels=2, sample_width=2, sample_rate=44100)
    cover = video_codec.load_avi(avi_bytes)

    assert cover.channels == 2
    assert cover.sample_width == 2
    assert cover.sample_rate == 44100
    assert cover.width == 64 and cover.height == 48
    assert cover.elements.dtype == np.uint16
    assert np.array_equal(cover.elements.view(np.int16), samples)

    # Unmodified round-trip: load(save(load(x).elements)) must reproduce the file exactly.
    rebuilt = video_codec.save_avi(cover, cover.elements)
    assert rebuilt == avi_bytes

    # A "stego" run: flip the low bit of every sample, then confirm it survives
    # a save -> load cycle and that the video chunks were not touched.
    stego_elements = cover.elements ^ np.uint16(1)
    stego_bytes = video_codec.save_avi(cover, stego_elements)
    assert stego_bytes != avi_bytes
    assert b"\x99" * 8 in stego_bytes  # dummy video frame bytes untouched

    reloaded = video_codec.load_avi(stego_bytes)
    assert np.array_equal(reloaded.elements, stego_elements)


def test_round_trip_8bit_mono() -> None:
    rng = np.random.default_rng(seed=2)
    pcm_bytes = rng.integers(0, 256, size=3000, dtype=np.uint8).tobytes()

    avi_bytes = _build_avi(pcm_bytes, channels=1, sample_width=1, sample_rate=8000, n_pcm_chunks=5)
    cover = video_codec.load_avi(avi_bytes)

    assert cover.sample_width == 1
    assert cover.elements.dtype == np.uint8
    assert cover.elements.tobytes() == pcm_bytes

    rebuilt = video_codec.save_avi(cover, cover.elements)
    assert rebuilt == avi_bytes


def test_rejects_non_avi() -> None:
    with pytest.raises(UnsupportedCoverError):
        video_codec.load_avi(b"not a riff file at all")


def test_rejects_video_with_no_audio_stream() -> None:
    bitmap_info = struct.pack("<IiiHHIIiiII", 40, 64, 48, 1, 24, 0, 0, 0, 0, 0, 0)
    avih = struct.pack("<IIIIIIIIIIIIII", 40000, 0, 0, 0, 1, 0, 1, 0, 64, 48, 0, 0, 0, 0)
    hdrl = _list(b"hdrl", _chunk(b"avih", avih) + _strl(b"vids", bitmap_info))
    movi = _list(b"movi", _chunk(b"00dc", b"\x00" * 8))
    avi_bytes = _chunk(b"RIFF", b"AVI " + hdrl + movi)

    with pytest.raises(UnsupportedCoverError, match="no uncompressed PCM audio track"):
        video_codec.load_avi(avi_bytes)


def test_rejects_compressed_audio_track() -> None:
    # wFormatTag 85 == MP3, not PCM (1) — must be rejected, not silently mis-decoded.
    wave_format = struct.pack("<HHIIHH", 85, 2, 44100, 16000, 1, 0)
    bitmap_info = struct.pack("<IiiHHIIiiII", 40, 64, 48, 1, 24, 0, 0, 0, 0, 0, 0)
    avih = struct.pack("<IIIIIIIIIIIIII", 40000, 0, 0, 0, 1, 0, 2, 0, 64, 48, 0, 0, 0, 0)
    hdrl = _list(
        b"hdrl", _chunk(b"avih", avih) + _strl(b"vids", bitmap_info) + _strl(b"auds", wave_format)
    )
    movi = _list(b"movi", _chunk(b"00dc", b"\x00" * 8) + _chunk(b"01wb", b"\x00" * 32))
    avi_bytes = _chunk(b"RIFF", b"AVI " + hdrl + movi)

    with pytest.raises(UnsupportedCoverError, match="no uncompressed PCM audio track"):
        video_codec.load_avi(avi_bytes)
