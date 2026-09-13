"""AVI video cover objects: file bytes <-> flat numpy array of PCM samples.

Extends the two required cover types (image, audio — spec FR1, FR2) with a
third: video (spec Section 8, "additional cover object"). Video is carried
through this codebase exactly like audio is: as a flat array of unsigned
sample values that `lsb.embed_bits` / `lsb.extract_bits` don't need to know
anything about.

Design choice — audio-track embedding, not frame embedding
------------------------------------------------------------
The spec calls out two options: selected-frame embedding (hide bits in pixel
data of chosen frames) or audio-track embedding (hide bits in the video's
audio channel). This module implements the second.

Frame embedding was rejected for the same reason JPEG covers are rejected in
`image_codec.py` (see `docs/design/limitations-and-ai-use.md`): every common
video codec (H.264, HEVC, VP9, MPEG-4) is lossy. Decoding a frame to pixels,
flipping an LSB, and re-encoding the video stream re-quantizes the whole
frame and destroys the embedded bit before the file is ever written, for
exactly the same DCT/motion-compensation reasons a JPEG re-save does. There
is no video codec in this project's dependencies (no ffmpeg/PyAV/OpenCV) to
even attempt it, and adding one just to immediately explain why its output
is unrecoverable would not demonstrate anything the JPEG writeup doesn't
already cover.

Audio-track embedding sidesteps that: an AVI container can carry its audio
stream as **uncompressed PCM**, which is byte-for-byte stable under
container repackaging in exactly the way WAV/PCM is. So this module:

  1. Parses the AVI (a RIFF container — the same chunk format `wave` already
     handles for us in `audio_codec.py`, just with more chunk types) using
     only `struct`, no new dependency.
  2. Locates the PCM audio stream's data chunks inside the `movi` LIST and
     reads them out, concatenated, as one PCM byte string — identical in
     shape to what `audio_codec.load_wav` produces.
  3. Leaves every video (`vids`) chunk untouched. `save_avi` patches the
     original file bytes in place at the exact offsets the audio chunks
     occupied, because LSB embedding never changes a chunk's length — only
     its bit values — so the rest of the container (video frames, the
     `idx1` index, chunk sizes) stays byte-identical and valid.

Limitations this implies (see docs/design/limitations-and-ai-use.md for the
full writeup):
  * The video stream itself carries no payload — capacity is bounded by the
    audio track's sample count, same as a WAV file of the same duration.
  * Only PCM (uncompressed) audio tracks are accepted. A video whose audio
    is AAC/MP3/AC3 (the normal case for MP4/MOV/MKV) is rejected with
    `UnsupportedCoverError` — convert first, e.g.:
        ffmpeg -i input.mp4 -c:v copy -c:a pcm_s16le -ar 44100 output.avi
  * A silent video (no audio stream at all) has no carrier and is rejected.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import numpy as np

from .errors import UnsupportedCoverError

_RIFF_HEADER = struct.Struct("<4sI4s")
_CHUNK_HEADER = struct.Struct("<4sI")
_STREAM_FORMAT = struct.Struct("<HHIIHH")  # WAVEFORMATEX, first 16 bytes
_BITMAPINFOHEADER = struct.Struct("<IiiHHIIiiII")  # first 40 bytes of BITMAPINFOHEADER
_AVI_MAIN_HEADER = struct.Struct("<IIIIIIIIIIIIII")  # MainAVIHeader, 14 x uint32
_WAVE_FORMAT_PCM = 1


@dataclass
class VideoCover:
    """A decoded video cover: its audio track's PCM samples, ready for `lsb`.

    `raw` and `chunk_spans` are carried along so `save_avi` can patch the
    embedded samples back into the *original* container bytes rather than
    re-serialising the whole file (which would require re-deriving the
    `idx1` index and any codec-specific chunk layout this module never has
    to understand).
    """

    elements: np.ndarray  # flat uint8 (8-bit) or uint16 view (16-bit) PCM samples
    sample_rate: int
    channels: int
    sample_width: int  # bytes per sample: 1 or 2
    frames: int  # PCM frames (samples per channel)
    width: int  # video frame width, report/GUI only — not used for embedding
    height: int  # video frame height, report/GUI only
    duration_seconds: float
    raw: bytes = field(repr=False)
    chunk_spans: list[tuple[int, int]] = field(repr=False)  # (offset, size) in `raw`, in stream order


def _iter_chunks(buf: bytes, start: int, end: int):
    """Yield (fourcc, data_start, size) for each top-level chunk in buf[start:end].

    A RIFF chunk is a 4-byte tag, a 4-byte little-endian size, then that many
    data bytes, padded with one zero byte if size is odd. `LIST` chunks are
    themselves chunks (fourcc == b"LIST"); the caller recurses into them by
    treating bytes [data_start+4, data_start+size) as another chunk sequence.
    """
    pos = start
    while pos + 8 <= end:
        fourcc, size = _CHUNK_HEADER.unpack_from(buf, pos)
        data_start = pos + 8
        if data_start + size > end:
            break  # truncated/corrupt trailing chunk — stop rather than misread
        yield fourcc, data_start, size
        pos = data_start + size + (size & 1)


def _parse_streams(buf: bytes, hdrl_start: int, hdrl_end: int):
    """Return [(fcc_type, format_bytes)] for each 'strl' stream, in order.

    fcc_type is b"vids" or b"auds" (or whatever else the file declares);
    format_bytes is the raw 'strf' chunk payload for that stream.
    """
    streams: list[tuple[bytes, bytes]] = []
    for fourcc, data_start, size in _iter_chunks(buf, hdrl_start, hdrl_end):
        if fourcc != b"LIST" or buf[data_start : data_start + 4] != b"strl":
            continue
        strl_start, strl_end = data_start + 4, data_start + size
        fcc_type = b""
        strf_bytes = b""
        for sub_fourcc, sub_start, sub_size in _iter_chunks(buf, strl_start, strl_end):
            if sub_fourcc == b"strh" and sub_size >= 4:
                fcc_type = buf[sub_start : sub_start + 4]
            elif sub_fourcc == b"strf":
                strf_bytes = buf[sub_start : sub_start + sub_size]
        streams.append((fcc_type, strf_bytes))
    return streams


def load_avi(data: bytes) -> VideoCover:
    """Decode an AVI file's uncompressed PCM audio track into a sample array.

    Raises `UnsupportedCoverError` if the file is not a RIFF/AVI container,
    has no audio stream, or that stream is not 8/16-bit PCM.
    """
    if len(data) < 12 or data[0:4] != b"RIFF" or data[8:12] != b"AVI ":
        raise UnsupportedCoverError("could not decode video data as AVI (RIFF/'AVI ' container)")

    riff_size = struct.unpack_from("<I", data, 4)[0]
    end = min(len(data), 8 + riff_size)

    hdrl_span: tuple[int, int] | None = None
    movi_span: tuple[int, int] | None = None
    for fourcc, data_start, size in _iter_chunks(data, 12, end):
        if fourcc != b"LIST":
            continue
        list_type = data[data_start : data_start + 4]
        if list_type == b"hdrl":
            hdrl_span = (data_start + 4, data_start + size)
        elif list_type == b"movi":
            movi_span = (data_start + 4, data_start + size)

    if hdrl_span is None or movi_span is None:
        raise UnsupportedCoverError("AVI file is missing its 'hdrl' or 'movi' chunk")

    width = height = 0
    duration_seconds = 0.0
    for fourcc, data_start, size in _iter_chunks(data, *hdrl_span):
        if fourcc == b"avih" and size >= _AVI_MAIN_HEADER.size:
            # MainAVIHeader DWORDs: [0] dwMicroSecPerFrame, [4] dwTotalFrames,
            # [8] dwWidth, [9] dwHeight (the rest aren't needed here).
            fields = _AVI_MAIN_HEADER.unpack_from(data, data_start)
            micro_sec_per_frame, total_frames = fields[0], fields[4]
            width, height = fields[8], fields[9]
            if micro_sec_per_frame:
                duration_seconds = (micro_sec_per_frame * total_frames) / 1_000_000

    streams = _parse_streams(data, *hdrl_span)

    audio_stream_index: int | None = None
    sample_rate = channels = sample_width = 0
    for index, (fcc_type, strf_bytes) in enumerate(streams):
        if fcc_type != b"auds" or len(strf_bytes) < _STREAM_FORMAT.size:
            continue
        fmt_tag, n_channels, samples_per_sec, _avg_bytes, _block_align, bits_per_sample = (
            _STREAM_FORMAT.unpack_from(strf_bytes, 0)
        )
        if fmt_tag != _WAVE_FORMAT_PCM or bits_per_sample not in (8, 16):
            continue
        audio_stream_index = index
        sample_rate, channels, sample_width = samples_per_sec, n_channels, bits_per_sample // 8
        break

    if audio_stream_index is None:
        raise UnsupportedCoverError(
            "video has no uncompressed PCM audio track to embed into — re-encode with e.g. "
            "`ffmpeg -i input.mp4 -c:v copy -c:a pcm_s16le -ar 44100 output.avi`"
        )

    wanted_tag = f"{audio_stream_index:02d}wb".encode("ascii")
    chunk_spans: list[tuple[int, int]] = []
    pcm_parts: list[bytes] = []

    def _walk_movi(start: int, end_: int) -> None:
        for fourcc, data_start, size in _iter_chunks(data, start, end_):
            if fourcc == b"LIST" and data[data_start : data_start + 4] == b"rec ":
                _walk_movi(data_start + 4, data_start + size)
            elif fourcc == wanted_tag:
                chunk_spans.append((data_start, size))
                pcm_parts.append(data[data_start : data_start + size])

    _walk_movi(*movi_span)

    if not pcm_parts:
        raise UnsupportedCoverError("AVI audio stream declared but its data chunks are empty")

    raw_pcm = b"".join(pcm_parts)
    if len(raw_pcm) % sample_width != 0:
        raise UnsupportedCoverError("audio track length is not a whole number of samples")

    dtype = np.uint8 if sample_width == 1 else np.int16
    arr = np.frombuffer(raw_pcm, dtype=dtype)
    elements = arr if sample_width == 1 else arr.view(np.uint16)
    frames = len(elements) // channels if channels else 0

    return VideoCover(
        elements=elements.copy(),
        sample_rate=sample_rate,
        channels=channels,
        sample_width=sample_width,
        frames=frames,
        width=width,
        height=height,
        duration_seconds=duration_seconds,
        raw=data,
        chunk_spans=chunk_spans,
    )


def save_avi(cover: VideoCover, elements: np.ndarray) -> bytes:
    """Rebuild the AVI file with (possibly modified) audio samples patched in.

    The container, video stream, and index are copied through byte-for-byte;
    only the bytes inside the recorded audio-chunk spans change. This only
    works because embedding never changes the number of samples — same trap
    as `audio_codec.save_wav`: view 16-bit samples as uint16 for the bit
    work, then back to int16 before turning them into bytes.
    """
    if cover.sample_width == 1:
        raw_pcm = elements.astype(np.uint8).tobytes()
    else:
        raw_pcm = elements.astype(np.uint16).view(np.int16).tobytes()

    buf = bytearray(cover.raw)
    pos = 0
    for start, size in cover.chunk_spans:
        buf[start : start + size] = raw_pcm[pos : pos + size]
        pos += size

    if pos != len(raw_pcm):
        raise UnsupportedCoverError("re-embedded audio track size does not match the original chunk layout")

    return bytes(buf)
