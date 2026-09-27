"""Controlled media attacks; EXPECTED describes the documented demo conditions.

Sealed frames (`sealing.py`): the attacks that never look at the frame
(flip_bits, crop, lsb_scrub, reencode, lsb_noise) work on sealed files
unchanged. corrupt_payload and replay normally parse the plaintext header to
find the payload and the frame length. A sealed header is encrypted, and an
attacker without the passphrase cannot tell a sealed frame from an empty
cover, so neither attack can auto-detect one. Both take `sealed=True` for a
key-less variant instead (CLI: `stego tamper --sealed`); without it they fail
on a sealed file with a FrameError that says why.
"""

from __future__ import annotations

import io
import math
from dataclasses import replace

import numpy as np
from PIL import Image

from . import audio_codec, container, extraction, image_codec, location, lsb, sealing, video_codec
from .errors import CapacityError, FrameError, UnsupportedCoverError
from .verdict import Verdict

EXPECTED = {
    "flip_bits": Verdict.TAMPERED,
    "crop": Verdict.TAMPERED,
    "lsb_scrub": Verdict.PAYLOAD_MISSING,
    "reencode": Verdict.PAYLOAD_MISSING,
    "corrupt_payload": Verdict.TAMPERED,
    "replay": Verdict.TAMPERED,
    "lsb_noise": Verdict.TAMPERED,
}

DESCRIPTIONS = {
    "flip_bits": "Flip high sample bits. Expect Tampered when these bits are outside the embedded LSB plane.",
    "crop": "Remove the final 10% of rows/frames. Expect Tampered if the frame survives; verify using the original explicit offset. A lost frame may give Payload Missing.",
    "lsb_scrub": "Zero the selected low bits. Expect Payload Missing after a complete search, or Cannot Verify if a large cover exceeds the search limit. Higher LSB counts can visibly/audibly degrade media.",
    "reencode": "JPEG round-trip for images; downsample and interpolate PCM for audio/video. Expect Payload Missing after a complete unsuccessful search, or Cannot Verify if the search limit is reached. Surviving data can produce other verdicts.",
    "corrupt_payload": "Change one payload bit while preserving the header and stored CRC. Expect Tampered at the original explicit offset.",
    "replay": "Copy a valid frame into a different cover. Expect Tampered; verify using the original media ID, key, LSB count and explicit offset.",
    "lsb_noise": "Flip 0.1% of the hidden low bits at random, like mild transmission noise; the visible content is unchanged. Expect Tampered for a file protected with 1 copy. A file protected with 3 or 5 copies should still verify Authentic, because the other copies outvote the damaged bits.",
}

# Fraction of hidden low bits flipped by lsb_noise. Measured on the sample
# covers: at 0.1%, 1 copy almost never survives, while 3 and 5 copies almost
# always do, which is the contrast the robust-embedding demo needs.
LSB_NOISE_RATE = 0.001


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


def _magic_absent_at(elements, n_lsb: int, start: int) -> bool:
    """True only if `start` is readable and does not hold the plaintext MAGIC."""
    magic_bits = len(container.MAGIC) * 8
    try:
        location.validate_start(len(elements), start, magic_bits, n_lsb)
    except (CapacityError, ValueError):
        return False
    return lsb.bits_to_bytes(lsb.extract_bits(elements, start, magic_bits, n_lsb)) != container.MAGIC


def _plaintext_frame(elements, n_lsb: int, start: int, attack: str) -> bytes:
    """`_frame`, with an explanation when the file may hold a sealed frame."""
    try:
        return _frame(elements, n_lsb, start)
    except FrameError as exc:
        if not _magic_absent_at(elements, n_lsb, start):
            raise  # out of range, or a damaged plaintext frame: the original error says it all
        raise FrameError(
            f"{exc}. No plaintext frame header at start {start}. If this file was protected with a "
            f"sealed frame, its header is encrypted and opaque to {attack} without the passphrase; "
            f"run the key-less sealed variant instead (CLI: stego tamper --attack {attack} --sealed)."
        ) from exc


def _sealed_region_bits(elements, n_lsb: int, start: int, n_bits: int):
    """Read `n_bits` hidden bits from `start`, as a FrameError if they do not fit."""
    try:
        location.validate_start(len(elements), start, n_bits, n_lsb)
    except CapacityError as exc:
        raise FrameError("the sealed region extends past the end of the cover") from exc
    return lsb.extract_bits(elements, start, n_bits, n_lsb)


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


def lsb_noise(data: bytes, kind: str, n_lsb: int = 1, rate: float = LSB_NOISE_RATE, seed: int = 0) -> bytes:
    """Flip each of the low `n_lsb` bits of every element independently with
    probability `rate`.

    Only the low bits change, so the stable media hash (which masks those
    bits) still matches. Any failure therefore comes from damage to the
    hidden frame itself, which is exactly what robust embedding repairs. The
    fixed seed makes the same file always get the same damage, so a demo can
    be repeated.
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError("n_lsb must be between 1 and 8")
    if not 0 < rate < 1:
        raise ValueError("rate must be between 0 and 1, exclusive")
    cover = _load(data, kind)
    elements = cover.elements.copy()
    rng = np.random.default_rng(seed)
    flips = np.zeros(elements.shape, dtype=elements.dtype)
    for bit in range(n_lsb):
        hit = rng.random(elements.shape) < rate
        flips |= hit.astype(elements.dtype) << bit
    return _save(cover, elements ^ flips, kind)


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


def corrupt_payload(data: bytes, kind: str, n_lsb: int, start: int, *, sealed: bool = False) -> bytes:
    """Corrupt the first payload bit, preserving magic/header and the old CRC.

    sealed=True: flip the same bit without the key. The attacker skips the
    12-byte nonce and the 13 encrypted header bytes and flips the top bit of
    the first ciphertext payload byte. CTR maps a ciphertext bit flip to the
    same plaintext bit, so the header still opens and the (encrypted) CRC
    reports the change -> Tampered. Assumes redundancy 1, like the plaintext
    variant: with more copies the majority vote repairs a single flip.
    """
    cover = _load(data, kind)
    if sealed:
        target_bit = (sealing.NONCE_SIZE + container.HEADER_SIZE) * 8
        # Whole elements only: embed_bits zero-pads a partial final element,
        # which would silently clear sealed bits after the one we flip.
        n_bits = -(-(target_bit + 1) // n_lsb) * n_lsb
        bits = _sealed_region_bits(cover.elements, n_lsb, start, n_bits).copy()
        bits[target_bit] ^= 1
        return _save(cover, lsb.embed_bits(cover.elements, bits, start, n_lsb), kind)
    frame = bytearray(_plaintext_frame(cover.elements, n_lsb, start, "corrupt_payload"))
    if container.parse_header(frame)[0] == 0:
        raise FrameError("frame has no payload to corrupt")
    frame[container.HEADER_SIZE] ^= 0x80
    elements = lsb.embed_bits(cover.elements, lsb.bytes_to_bits(bytes(frame)), start, n_lsb)
    return _save(cover, elements, kind)


def replay(
    stego: bytes, other_cover: bytes, kind: str, n_lsb: int, start: int, *, sealed: bool = False
) -> bytes:
    """Transplant the unchanged signed frame; the target must differ in hashed media or shape.

    sealed=True: a key-less attacker cannot read the sealed frame's length,
    so it copies every hidden bit from `start` to the end of the shorter
    cover. That still carries the whole sealed frame across when it fits, and
    the verifier opens it with the right passphrase, finds a valid signature
    and a media hash that does not match -> Tampered (verify with the
    original explicit offset: a different cover size moves a derived start).
    """
    source = _load(stego, kind)
    target = _load(other_cover, kind)
    if sealed:
        count = min(len(source.elements), len(target.elements)) - start
        if count <= 0:
            raise FrameError(f"start {start} leaves no hidden bits to transplant between these covers")
        bits = _sealed_region_bits(source.elements, n_lsb, start, count * n_lsb)
    else:
        bits = lsb.bytes_to_bits(_plaintext_frame(source.elements, n_lsb, start, "replay"))
    mask = np.array(np.iinfo(source.elements.dtype).max ^ ((1 << n_lsb) - 1), dtype=source.elements.dtype)
    same_format = all(
        getattr(source, key, None) == getattr(target, key, None)
        for key in ("height", "width", "channels", "sample_rate", "sample_width", "frames")
    )
    if same_format and np.array_equal(source.elements & mask, target.elements & mask):
        raise ValueError("replay target must differ in signed media content or dimensions")
    elements = lsb.embed_bits(target.elements, bits, start, n_lsb)
    return _save(target, elements, kind)
