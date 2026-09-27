"""Build the demo video cover: samples/video/original/cover.avi.

The video optional challenge (Ke Ying, `backend/stego_core/video_codec.py`)
embeds into an AVI's uncompressed PCM audio track. `scripts/make_samples.py`
only produces PNG/WAV covers, so this script wraps the team's own
`samples/audio/original/cover.wav` in a small, standards-shaped AVI —
uncompressed 24-bit DIB frames (a moving test-pattern bar, so a player shows
something) interleaved with the PCM audio, plus an `idx1` index — that any
player (VLC, Windows Media Player) opens and the Protect tab accepts.

Usage (repo root, venv active):
    PYTHONPATH=backend python scripts/make_video_cover.py

Deterministic: the same cover.wav always produces the same bytes.
"""

from __future__ import annotations

import struct
import sys
import wave
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from stego_core import video_codec  # noqa: E402

SOURCE_WAV = ROOT / "samples" / "audio" / "original" / "cover.wav"
OUT = ROOT / "samples" / "video" / "original" / "cover.avi"

WIDTH, HEIGHT, FPS = 80, 60, 10
BACKGROUND_BGR = (38, 30, 26)  # the GUI's ink-slate, as B, G, R
BAR_BGR = (40, 150, 230)  # stamp-ink amber


def _chunk(fourcc: bytes, payload: bytes) -> bytes:
    out = fourcc + struct.pack("<I", len(payload)) + payload
    return out + b"\x00" if len(payload) % 2 else out


def _list(list_type: bytes, inner: bytes) -> bytes:
    return _chunk(b"LIST", list_type + inner)


def _stream_header(fcc_type: bytes, scale: int, rate: int, length: int, buffer: int, sample_size: int) -> bytes:
    # AVISTREAMHEADER: fccType, fccHandler, dwFlags, wPriority, wLanguage,
    # dwInitialFrames, dwScale, dwRate, dwStart, dwLength, dwSuggestedBufferSize,
    # dwQuality, dwSampleSize, rcFrame (4 x int16).
    return struct.pack(
        "<4s4sIHHIIIIIIII4h",
        fcc_type, b"\x00" * 4, 0, 0, 0, 0, scale, rate, 0, length, buffer, 0xFFFFFFFF, sample_size,
        0, 0, WIDTH if fcc_type == b"vids" else 0, HEIGHT if fcc_type == b"vids" else 0,
    )


def _frame(index: int, n_frames: int) -> bytes:
    """One bottom-up 24-bit BGR frame: slate with an amber bar sweeping across."""
    img = np.empty((HEIGHT, WIDTH, 3), dtype=np.uint8)
    img[:] = BACKGROUND_BGR
    x = int(index * (WIDTH - 8) / max(1, n_frames - 1))
    img[:, x : x + 8] = BAR_BGR
    return img[::-1].tobytes()  # DIB rows are stored bottom-up; 80*3 is already 4-byte aligned


def build_avi(wav_bytes_path: Path) -> bytes:
    with wave.open(str(wav_bytes_path), "rb") as w:
        channels, sample_width, sample_rate, n_frames = w.getparams()[:4]
        pcm = w.readframes(n_frames)
    if sample_width not in (1, 2):
        raise SystemExit("cover.wav must be 8- or 16-bit PCM")

    block_align = channels * sample_width
    duration = n_frames / sample_rate
    video_frames = max(1, round(duration * FPS))
    frame_bytes = WIDTH * HEIGHT * 3
    audio_per_frame = -(-len(pcm) // video_frames // block_align) * block_align

    movi_parts: list[bytes] = []
    index_entries: list[bytes] = []
    offset = 4  # idx1 offsets are relative to the 'movi' list type fourcc
    pos = 0
    for i in range(video_frames):
        for fourcc, payload, flags in (
            (b"00db", _frame(i, video_frames), 0x10),  # AVIIF_KEYFRAME
            (b"01wb", pcm[pos : pos + audio_per_frame], 0),
        ):
            if not payload:
                continue
            chunk = _chunk(fourcc, payload)
            movi_parts.append(chunk)
            index_entries.append(struct.pack("<4sIII", fourcc, flags, offset, len(payload)))
            offset += len(chunk)
        pos += audio_per_frame
    if pos < len(pcm):
        tail = _chunk(b"01wb", pcm[pos:])
        movi_parts.append(tail)
        index_entries.append(struct.pack("<4sIII", b"01wb", 0, offset, len(pcm) - pos))

    avih = struct.pack(
        "<14I",
        1_000_000 // FPS,  # dwMicroSecPerFrame
        frame_bytes * FPS + sample_rate * block_align,  # dwMaxBytesPerSec
        0,
        0x10 | 0x100,  # AVIF_HASINDEX | AVIF_ISINTERLEAVED
        video_frames,
        0,
        2,  # dwStreams
        max(frame_bytes, audio_per_frame),
        WIDTH,
        HEIGHT,
        0, 0, 0, 0,
    )
    bitmap_info = struct.pack("<IiiHHIIiiII", 40, WIDTH, HEIGHT, 1, 24, 0, frame_bytes, 0, 0, 0, 0)
    wave_format = struct.pack(
        "<HHIIHHH", 1, channels, sample_rate, sample_rate * block_align, block_align, sample_width * 8, 0
    )
    hdrl = _list(
        b"hdrl",
        _chunk(b"avih", avih)
        + _list(
            b"strl",
            _chunk(b"strh", _stream_header(b"vids", 1, FPS, video_frames, frame_bytes, 0))
            + _chunk(b"strf", bitmap_info),
        )
        + _list(
            b"strl",
            _chunk(
                b"strh",
                _stream_header(
                    b"auds", block_align, sample_rate * block_align, len(pcm) // block_align, audio_per_frame, block_align
                ),
            )
            + _chunk(b"strf", wave_format),
        ),
    )
    movi = _list(b"movi", b"".join(movi_parts))
    idx1 = _chunk(b"idx1", b"".join(index_entries))
    return _chunk(b"RIFF", b"AVI " + hdrl + movi + idx1)


def main() -> None:
    avi = build_avi(SOURCE_WAV)
    cover = video_codec.load_avi(avi)  # must round-trip through the team's own decoder
    with wave.open(str(SOURCE_WAV), "rb") as w:
        assert cover.frames == w.getnframes() and cover.sample_rate == w.getframerate()
    assert video_codec.save_avi(cover, cover.elements) == avi
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(avi)
    print(
        f"wrote {OUT.relative_to(ROOT)}: {len(avi):,} bytes, {WIDTH}x{HEIGHT} @ {FPS} fps, "
        f"{cover.duration_seconds:.1f} s, audio {cover.sample_rate} Hz x {cover.channels} ch, "
        f"{len(cover.elements):,} carrier samples"
    )


if __name__ == "__main__":
    main()
