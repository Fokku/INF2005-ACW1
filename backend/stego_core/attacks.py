"""Controlled media attacks; EXPECTED describes the documented demo conditions."""

from __future__ import annotations

import io
import math
from dataclasses import replace

import numpy as np
from PIL import Image

from . import audio_codec, container, extraction, image_codec, lsb, video_codec
from .errors import FrameError, UnsupportedCoverError
from .verdict import Verdict

EXPECTED = {
    "flip_bits": Verdict.TAMPERED,
    "crop": Verdict.TAMPERED,
    "lsb_scrub": Verdict.PAYLOAD_MISSING,
    "reencode": Verdict.PAYLOAD_MISSING,
    "corrupt_payload": Verdict.TAMPERED,
    "replay": Verdict.TAMPERED,
}

DESCRIPTIONS = {
    "flip_bits": "Flip high sample bits. Expect Tampered when these bits are outside the embedded LSB plane.",
    "crop": "Remove the final 10% of rows/frames. Expect Tampered if the frame survives; verify using the original explicit offset. A lost frame may give Payload Missing.",
    "lsb_scrub": "Zero the selected low bits. Expect Payload Missing after a complete search, or Cannot Verify if a large cover exceeds the search limit. Higher LSB counts can visibly/audibly degrade media.",
    "reencode": "JPEG round-trip for images; downsample and interpolate PCM for audio/video. Expect Payload Missing after a complete unsuccessful search, or Cannot Verify if the search limit is reached. Surviving data can produce other verdicts.",
    "corrupt_payload": "Change one payload bit while preserving the header and stored CRC. Expect Tampered at the original explicit offset.",
    "replay": "Copy a valid frame into a different cover. Expect Tampered; verify using the original media ID, key, LSB count and explicit offset.",
}


def _load(data: bytes, kind: str):
    loaders = {"image": image_codec.load_png, "audio": audio_codec.load_wav, "video": video_codec.load_avi}
    if kind not in loaders:
        raise UnsupportedCoverError(f"unsupported attack cover kind: {kind!r}")
    return loaders[kind](data)


def _save(cover, elements, kind: str) -> bytes:
    return {"image": image_codec.save_png, "audio": audio_codec.save_wav, "video": video_codec.save_avi}[
        kind
    ](cover, elements)


def _frame(elements, n_lsb: int, start: int) -> bytes:
    frame = extraction.extract_frame(elements, start, n_lsb)
    return container.build_frame(frame.payload_bytes, frame.signature, frame.n_lsb, frame.encrypted)


def flip_bits(data: bytes, kind: str, region: tuple[int, int] | None = None) -> bytes:
    """Flip the highest bit in a half-open element region, leaving lower bits intact."""
    cover = _load(data, kind)
    begin, end = region if region is not None else (0, max(1, len(cover.elements) // 10))
    if not 0 <= begin < end <= len(cover.elements):
        raise ValueError("region must select a nonempty range inside the cover")
    elements = cover.elements.copy()
    elements[begin:end] ^= np.array(1 << (elements.dtype.itemsize * 8 - 1), dtype=elements.dtype)
    return _save(cover, elements, kind)


def crop(data: bytes, kind: str, fraction: float = 0.9) -> bytes:
    """Keep leading rows/PCM frames. AVI cropping needs a container remuxer and is unsupported."""
    if not math.isfinite(fraction) or not 0 < fraction < 1:
        raise ValueError("fraction must be between 0 and 1, exclusive")
    if kind == "video":
        raise UnsupportedCoverError("AVI cropping is not supported; use PNG or WAV for this attack")
    cover = _load(data, kind)
    count = cover.height if kind == "image" else cover.frames
    if count < 2:
        raise ValueError("cover needs at least two rows/frames to crop")
    kept = max(1, int(count * fraction))
    if kind == "image":
        changed = replace(cover, height=kept)
        elements = cover.elements[: kept * cover.width * cover.channels]
    else:
        changed = replace(cover, frames=kept)
        elements = cover.elements[: kept * cover.channels]
    return _save(changed, elements, kind)


def lsb_scrub(data: bytes, kind: str, n_lsb: int) -> bytes:
    """Clear the selected LSB plane across the entire cover."""
    if not 1 <= n_lsb <= 8:
        raise ValueError("n_lsb must be between 1 and 8")
    cover = _load(data, kind)
    mask = np.array(np.iinfo(cover.elements.dtype).max ^ ((1 << n_lsb) - 1), dtype=cover.elements.dtype)
    return _save(cover, cover.elements & mask, kind)


def reencode(data: bytes, kind: str) -> bytes:
    """Perform a genuinely lossy transformation; no artificial payload scrubbing."""
    cover = _load(data, kind)
    if kind == "image":
        arr = cover.elements.reshape(cover.height, cover.width, cover.channels)
        img = Image.fromarray(arr).convert("RGB")
        jpeg = io.BytesIO()
        img.save(jpeg, format="JPEG", quality=65)
        png = io.BytesIO()
        with Image.open(io.BytesIO(jpeg.getvalue())) as decoded:
            decoded.save(png, format="PNG")
        return png.getvalue()
    if cover.frames < 3:
        raise ValueError("resampling needs at least three PCM frames")
    # Interpret signed PCM before interpolation, independently for each channel.
    values = cover.elements.view(np.int16) if cover.sample_width == 2 else cover.elements
    values = values.reshape(cover.frames, cover.channels)
    positions = np.arange(0, cover.frames, 2)
    result = np.empty(values.shape, dtype=values.dtype)
    for channel in range(cover.channels):
        result[:, channel] = np.rint(np.interp(np.arange(cover.frames), positions, values[::2, channel]))
    elements = result.reshape(-1)
    if cover.sample_width == 2:
        elements = elements.view(np.uint16)
    return _save(cover, elements, kind)


def corrupt_payload(data: bytes, kind: str, n_lsb: int, start: int) -> bytes:
    """Corrupt the first payload bit, preserving magic/header and the old CRC."""
    cover = _load(data, kind)
    frame = bytearray(_frame(cover.elements, n_lsb, start))
    if container.parse_header(frame)[0] == 0:
        raise FrameError("frame has no payload to corrupt")
    frame[container.HEADER_SIZE] ^= 0x80
    elements = lsb.embed_bits(cover.elements, lsb.bytes_to_bits(bytes(frame)), start, n_lsb)
    return _save(cover, elements, kind)


def replay(stego: bytes, other_cover: bytes, kind: str, n_lsb: int, start: int) -> bytes:
    """Transplant the unchanged signed frame; the target must differ in hashed media or shape."""
    source = _load(stego, kind)
    target = _load(other_cover, kind)
    frame = _frame(source.elements, n_lsb, start)
    mask = np.array(np.iinfo(source.elements.dtype).max ^ ((1 << n_lsb) - 1), dtype=source.elements.dtype)
    same_format = all(
        getattr(source, key, None) == getattr(target, key, None)
        for key in ("height", "width", "channels", "sample_rate", "sample_width", "frames")
    )
    if same_format and np.array_equal(source.elements & mask, target.elements & mask):
        raise ValueError("replay target must differ in signed media content or dimensions")
    elements = lsb.embed_bits(target.elements, lsb.bytes_to_bits(frame), start, n_lsb)
    return _save(target, elements, kind)
