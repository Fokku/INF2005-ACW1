"""POST /api/preview/audio-track: an AVI's PCM track as a browser-playable WAV.

Browsers cannot play AVI, so the GUI plays the audio track instead. The WAV
must carry exactly the samples the payload was embedded into.
"""

from __future__ import annotations

import struct
import wave
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.main import app
from stego_core import audio_codec, video_codec

client = TestClient(app)
COVER_AVI = Path(__file__).resolve().parents[2] / "samples" / "video" / "original" / "cover.avi"


def _cover_with_audio_format(*, channels: int | None = None, sample_rate: int | None = None) -> bytes:
    """The demo cover.avi with its audio stream's WAVEFORMATEX edited in place."""
    avi = bytearray(COVER_AVI.read_bytes())
    fmt = avi.index(b"strf", avi.index(b"auds")) + 8  # wFormatTag, nChannels, nSamplesPerSec, ...
    if channels is not None:
        struct.pack_into("<H", avi, fmt + 2, channels)
    if sample_rate is not None:
        struct.pack_into("<I", avi, fmt + 4, sample_rate)
    return bytes(avi)


def test_audio_track_is_the_avi_pcm_as_wav() -> None:
    avi = COVER_AVI.read_bytes()
    r = client.post("/api/preview/audio-track", files={"file": ("cover.avi", avi)})
    assert r.status_code == 200, r.text
    ref = r.json()
    assert ref["mime"] == "audio/wav" and ref["filename"] == "cover.audio-track.wav"
    wav = audio_codec.load_wav(client.get(ref["url"]).content)
    video = video_codec.load_avi(avi)
    assert (wav.sample_rate, wav.channels, wav.sample_width) == (
        video.sample_rate,
        video.channels,
        video.sample_width,
    )
    assert np.array_equal(wav.elements, video.elements)


def test_audio_track_rejects_a_non_avi() -> None:
    r = client.post("/api/preview/audio-track", files={"file": ("x.avi", b"not an avi")})
    assert r.status_code == 415


@pytest.mark.parametrize(
    "header",
    [
        {"channels": 0},
        {"channels": 9},
        {"channels": 65535},
        {"sample_rate": 0},
        {"sample_rate": 0xFFFFFFFF},
    ],
    ids=lambda h: "-".join(f"{k}={v}" for k, v in h.items()),
)
def test_audio_track_rejects_an_impossible_audio_header(header: dict[str, int]) -> None:
    """These used to reach `wave` and fail there as wave.Error or struct.error,
    an unhandled 500. They are unreadable AVIs, so 415 like any other."""
    r = client.post(
        "/api/preview/audio-track", files={"file": ("bad.avi", _cover_with_audio_format(**header))}
    )
    assert r.status_code == 415, r.text
    assert r.json()["error"] == "unsupported_cover"


@pytest.mark.parametrize("error", [wave.Error("bad header"), struct.error("bad field")])
def test_audio_track_maps_a_wav_writer_failure_to_415(error: Exception, monkeypatch) -> None:
    """Backstop for any header load_avi accepts but `wave` still cannot write."""

    def failing_save_wav(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(audio_codec, "save_wav", failing_save_wav)
    r = client.post("/api/preview/audio-track", files={"file": ("cover.avi", COVER_AVI.read_bytes())})
    assert r.status_code == 415, r.text
