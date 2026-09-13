"""Round-trip and rejection tests for the WAV/PCM audio cover."""

from __future__ import annotations

import io
import wave

import numpy as np
import pytest

from stego_core import audio_codec
from stego_core.errors import UnsupportedCoverError


def _wav_bytes(
    *, channels: int, sample_width: int, sample_rate: int, n_frames: int, seed: int
) -> tuple[bytes, np.ndarray]:
    rng = np.random.default_rng(seed=seed)
    n_samples = n_frames * channels
    if sample_width == 1:
        samples = rng.integers(0, 256, size=n_samples, dtype=np.uint8)
        raw = samples.tobytes()
    else:
        samples = rng.integers(-32768, 32767, size=n_samples, dtype=np.int16)
        raw = samples.tobytes()

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(raw)
    return buf.getvalue(), samples


def test_round_trip_16bit_stereo() -> None:
    data, samples = _wav_bytes(channels=2, sample_width=2, sample_rate=44100, n_frames=500, seed=1)
    cover = audio_codec.load_wav(data)

    assert cover.channels == 2
    assert cover.sample_width == 2
    assert cover.sample_rate == 44100
    assert cover.frames == 500
    assert cover.elements.dtype == np.uint16
    assert np.array_equal(cover.elements.view(np.int16), samples)

    rebuilt = audio_codec.save_wav(cover, cover.elements)
    assert rebuilt == data

    reloaded = audio_codec.load_wav(rebuilt)
    assert np.array_equal(reloaded.elements, cover.elements)


def test_round_trip_8bit_mono() -> None:
    data, samples = _wav_bytes(channels=1, sample_width=1, sample_rate=8000, n_frames=300, seed=2)
    cover = audio_codec.load_wav(data)

    assert cover.channels == 1
    assert cover.sample_width == 1
    assert cover.elements.dtype == np.uint8
    assert np.array_equal(cover.elements, samples)

    rebuilt = audio_codec.save_wav(cover, cover.elements)
    assert rebuilt == data


def test_modified_elements_survive_save_load() -> None:
    data, _samples = _wav_bytes(channels=1, sample_width=2, sample_rate=44100, n_frames=200, seed=3)
    cover = audio_codec.load_wav(data)

    flipped = cover.elements ^ np.uint16(1)
    stego_bytes = audio_codec.save_wav(cover, flipped)
    assert stego_bytes != data

    reloaded = audio_codec.load_wav(stego_bytes)
    assert np.array_equal(reloaded.elements, flipped)


def test_rejects_non_wav() -> None:
    with pytest.raises(UnsupportedCoverError):
        audio_codec.load_wav(b"not a wav file at all")


def test_rejects_unsupported_sample_width() -> None:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(3)  # 24-bit, unsupported
        w.setframerate(44100)
        w.writeframes(b"\x00" * 30)

    with pytest.raises(UnsupportedCoverError):
        audio_codec.load_wav(buf.getvalue())
