"""WAV/PCM cover objects: file bytes <-> flat numpy array (spec FR2, FR6).

Scope (from TECH_STACK.md): 8-bit unsigned and 16-bit signed little-endian PCM,
mono or stereo. Anything else (24-bit, 32-bit float, compressed, some
WAVE_FORMAT_EXTENSIBLE files) -> UnsupportedCoverError, which the API turns into
the verdict `Cannot Verify`. Convert demo clips with:

    ffmpeg -i input.mp3 -acodec pcm_s16le -ar 44100 samples/audio/original/clip.wav

>>> THE SIGN TRAP: 16-bit samples are int16. Bit operations on int16 corrupt the
>>> high bits. Return a uint16 VIEW (arr.view(np.uint16)) and convert back with
>>> another view before writing. 8-bit WAV is already unsigned uint8.

>>> DO NOT touch the WAV header. Read the params with `wave`, embed only in the
>>> sample frames, and write the output with the SAME params.
"""

from __future__ import annotations

import io
import wave
from dataclasses import dataclass

import numpy as np

from .errors import UnsupportedCoverError


@dataclass
class AudioCover:
    """A decoded audio cover, ready for `lsb.embed_bits`."""

    elements: np.ndarray  # flat uint8 (8-bit) or uint16 view (16-bit), length = frames * channels
    sample_rate: int
    channels: int
    sample_width: int  # bytes per sample: 1 or 2
    frames: int


def load_wav(data: bytes) -> AudioCover:
    """Decode WAV bytes into a flat unsigned array of samples.

    TODO(team): implement.

    Sketch:
      with wave.open(io.BytesIO(data), "rb") as w:
          nchannels, sampwidth, framerate, nframes = w.getparams()[:4]
          raw = w.readframes(nframes)
      if sampwidth not in (1, 2): raise UnsupportedCoverError(...)
      dtype = np.uint8 if sampwidth == 1 else np.int16
      arr = np.frombuffer(raw, dtype=dtype)
      elements = arr if sampwidth == 1 else arr.view(np.uint16)   # <- the view
      return AudioCover(elements.copy(), framerate, nchannels, sampwidth, nframes)

    `wave` raises wave.Error for compressed/exotic files — catch it and re-raise
    as UnsupportedCoverError with a message the GUI can show.
    """
    try:
        with wave.open(io.BytesIO(data), "rb") as w:
            nchannels, sampwidth, framerate, nframes = w.getparams()[:4]
            raw = w.readframes(nframes)
    except (wave.Error, EOFError) as exc:
        raise UnsupportedCoverError("could not decode audio data as PCM WAV") from exc

    if sampwidth not in (1, 2):
        raise UnsupportedCoverError(f"unsupported WAV sample width: {sampwidth * 8}-bit (need 8 or 16-bit PCM)")

    dtype = np.uint8 if sampwidth == 1 else np.int16
    arr = np.frombuffer(raw, dtype=dtype)
    elements = arr if sampwidth == 1 else arr.view(np.uint16)
    return AudioCover(
        elements=elements.copy(),
        sample_rate=framerate,
        channels=nchannels,
        sample_width=sampwidth,
        frames=nframes,
    )


def save_wav(cover: AudioCover, elements: np.ndarray) -> bytes:
    """Rebuild WAV bytes from (possibly modified) samples, preserving all params.

    TODO(team): implement.

    Sketch:
      raw = elements.astype(np.uint8).tobytes() if sample_width == 1
            else elements.view(np.int16).tobytes()
      with wave.open(buf, "wb") as w:
          w.setnchannels(cover.channels); w.setsampwidth(cover.sample_width)
          w.setframerate(cover.sample_rate); w.writeframes(raw)
    """
    if cover.sample_width == 1:
        raw = elements.astype(np.uint8).tobytes()
    else:
        raw = elements.astype(np.uint16).view(np.int16).tobytes()

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(cover.channels)
        w.setsampwidth(cover.sample_width)
        w.setframerate(cover.sample_rate)
        w.writeframes(raw)
    return buf.getvalue()
