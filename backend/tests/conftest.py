"""Shared fixtures. Synthetic covers, so the tests need no sample files.

Complete — no TODO. Add fixtures here rather than building files inside tests.
"""

from __future__ import annotations

import io
import wave

import numpy as np
import pytest
from PIL import Image


@pytest.fixture
def png_rgb() -> bytes:
    """A small deterministic RGB PNG."""
    rng = np.random.default_rng(seed=1)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def png_rgba() -> bytes:
    rng = np.random.default_rng(seed=2)
    arr = rng.integers(0, 256, size=(32, 32, 4), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, mode="RGBA").save(buf, format="PNG")
    return buf.getvalue()


def _wav(sample_width: int, channels: int, frames: int = 4000) -> bytes:
    rng = np.random.default_rng(seed=3)
    if sample_width == 1:
        data = rng.integers(0, 256, size=frames * channels, dtype=np.uint8).tobytes()
    else:
        data = rng.integers(-30000, 30000, size=frames * channels, dtype=np.int16).tobytes()
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(44100)
        w.writeframes(data)
    return buf.getvalue()


@pytest.fixture
def wav_16_mono() -> bytes:
    return _wav(2, 1)


@pytest.fixture
def wav_16_stereo() -> bytes:
    return _wav(2, 2)


@pytest.fixture
def wav_8_mono() -> bytes:
    return _wav(1, 1)


@pytest.fixture
def short_message() -> bytes:
    """Spec Section 5: one of the Learning Outcomes as the short message."""
    return (
        b"Explain how steganography can be used to embed hidden verification "
        b"data in image and audio cover objects."
    )


@pytest.fixture
def large_message() -> bytes:
    """Spec Section 5: the Project Overview paragraph as the large message."""
    return (
        b"This undergraduate project requires student teams to design, implement "
        b"and demonstrate a GUI-based LSB Replacement steganography program "
        b"(window-based or web-based) that protects and verifies both image and "
        b"audio cover objects using steganography, hashing and digital signatures. "
        b"The project focuses on practical cybersecurity concepts: hiding a "
        b"verification payload inside an image and an audio file, signing relevant "
        b"verification data, extracting the hidden payload, checking the digital "
        b"signature, and demonstrating positive and negative verification cases."
    )
