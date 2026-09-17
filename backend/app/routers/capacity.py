"""Cover capacity check (spec Section 5: "is payload size larger than cover
object size?"). This is a REQUIRED demo case, so it gets its own endpoint and
its own panel in the UI.
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile

from stego_core import audio_codec, container, hashing, image_codec, lsb, signing, video_codec
from stego_core.errors import UnsupportedCoverError

from ..schemas import AudioInfo, CapacityReport, CoverInfo, CoverKind, ImageInfo, VideoInfo

router = APIRouter()

# A rough allowance for the JSON payload fields around the message itself
# (media_id, timestamp, media_hash, nonce, cover_kind, n_lsb, shape,
# message_mime, encrypted, metadata, base64 overhead...). Documented here
# rather than computed exactly, since the metadata size is user-chosen.
PAYLOAD_JSON_OVERHEAD_BYTES = 300


def _sniff_kind(filename: str) -> CoverKind:
    lower = filename.lower()
    if lower.endswith(".png"):
        return CoverKind.image
    if lower.endswith(".wav"):
        return CoverKind.audio
    if lower.endswith(".avi"):
        return CoverKind.video
    raise UnsupportedCoverError(f"unrecognised cover extension: {filename!r} (need .png, .wav, or .avi)")


def _decode_cover(kind: CoverKind, data: bytes):
    if kind == CoverKind.image:
        return image_codec.load_png(data)
    if kind == CoverKind.audio:
        return audio_codec.load_wav(data)
    return video_codec.load_avi(data)


def _cover_info(kind: CoverKind, filename: str, data: bytes, cover) -> CoverInfo:
    info = CoverInfo(kind=kind, filename=filename, size_bytes=len(data), sha256=hashing.sha256_hex(data))
    if kind == CoverKind.image:
        info.image = ImageInfo(
            width=cover.width, height=cover.height, channels=cover.channels, mode=cover.original_mode
        )
    elif kind == CoverKind.audio:
        info.audio = AudioInfo(
            sample_rate=cover.sample_rate,
            channels=cover.channels,
            sample_width_bytes=cover.sample_width,
            frames=cover.frames,
            duration_seconds=(cover.frames / cover.sample_rate) if cover.sample_rate else 0.0,
        )
    else:
        info.video = VideoInfo(
            frame_width=cover.width,
            frame_height=cover.height,
            duration_seconds=cover.duration_seconds,
            sample_rate=cover.sample_rate,
            channels=cover.channels,
            sample_width_bytes=cover.sample_width,
            frames=cover.frames,
        )
    return info


@router.post("/capacity", response_model=CapacityReport)
async def check_capacity(
    cover: UploadFile = File(..., description="PNG, WAV, or AVI cover object"),
    n_lsb: int = Form(1, ge=1, le=8),
    payload_bytes: int | None = Form(None, description="size of the message the user wants to hide"),
) -> CapacityReport:
    """Report how much this cover can hold, and whether the message fits."""
    data = await cover.read()
    kind = _sniff_kind(cover.filename or "")
    decoded = _decode_cover(kind, data)
    cover_info = _cover_info(kind, cover.filename or "cover", data, decoded)

    total_elements = len(decoded.elements)
    capacity_bits = lsb.capacity_bits(total_elements, n_lsb)
    capacity_bytes = capacity_bits // 8

    overhead = container.frame_size_bytes(0, signing.SIGNATURE_BYTES) + PAYLOAD_JSON_OVERHEAD_BYTES
    max_message_bytes = max(0, capacity_bytes - overhead)

    fits = None
    if payload_bytes is not None:
        fits = (payload_bytes + overhead) <= capacity_bytes

    return CapacityReport(
        cover=cover_info,
        n_lsb=n_lsb,
        total_elements=total_elements,
        capacity_bits=capacity_bits,
        capacity_bytes=capacity_bytes,
        frame_overhead_bytes=overhead,
        max_message_bytes=max_message_bytes,
        payload_bytes=payload_bytes,
        fits=fits,
    )
