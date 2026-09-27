"""POST /api/preview/audio-track: an AVI's PCM track as a browser-playable WAV.

Browsers cannot play AVI, so the GUI plays the audio track instead. The WAV
must carry exactly the samples the payload was embedded into.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from fastapi.testclient import TestClient

from app.main import app
from stego_core import audio_codec, video_codec

client = TestClient(app)
COVER_AVI = Path(__file__).resolve().parents[2] / "samples" / "video" / "original" / "cover.avi"


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
