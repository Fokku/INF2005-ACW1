"""Controlled media attacks; EXPECTED describes the documented demo conditions.

Sealed frames (`sealing.py`): the attacks that never look at the frame
(flip_bits, crop, lsb_scrub, reencode, lsb_noise) work on sealed files
unchanged. corrupt_payload and replay normally parse the plaintext header to
find the payload and the frame length. A sealed header is encrypted, and an
attacker without the passphrase cannot tell a sealed frame from an empty
cover, so neither attack can auto-detect one. Both take `sealed=True` for a
key-less variant instead (CLI: `stego tamper --sealed`); without it they fail
on a sealed file with a FrameError that says why.

Robust embedding (`ecc.py`): with redundancy r > 1, `pipeline.protect` embeds
r back-to-back copies of the header block (HEADER_SIZE bytes, or
NONCE_SIZE + HEADER_SIZE for a sealed frame), then, from the next whole
element, r copies of the rest of the frame. The verifier majority-votes each
block back to one copy, so an attack that changes a single copy is simply
outvoted. corrupt_payload and replay therefore take `redundancy` (CLI:
`stego tamper --copies N`) and change or carry every copy; see their
docstrings for the layout each one relies on.
"""

from __future__ import annotations

import io
import math
from dataclasses import replace

import numpy as np
from PIL import Image

from . import audio_codec, container, ecc, extraction, image_codec, location, lsb, sealing, video_codec
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
    "corrupt_payload": "Change one payload bit while preserving the header and stored CRC; with 3 or 5 copies, the same bit in every copy, so the majority vote cannot repair it. A sealed frame with 3 or 5 copies gets its encrypted header version changed in every copy instead, because the copy length is unreadable without the passphrase. Expect Tampered at the original explicit offset and copy count.",
    "replay": "Copy a valid frame, with every embedded copy, into a different cover. Expect Tampered; verify using the original media ID, key, LSB count, copy count and explicit offset.",
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


def _frame(elements, n_lsb: int, start: int, redundancy: int = 1) -> bytes:
    """One (majority-voted) copy of the plaintext frame at `start`, re-serialized."""
    frame = extraction.extract_frame(elements, start, n_lsb, redundancy)
    return container.build_frame(frame.payload_bytes, frame.signature, frame.n_lsb, frame.encrypted)


def _block_elements(block_len: int, n_lsb: int, redundancy: int) -> int:
    """Elements that `redundancy` back-to-back copies of a `block_len`-byte block
    occupy, with the same ceil() that `lsb.embed_bits` used when protect wrote them.
    """
    return -(-(block_len * 8 * redundancy) // n_lsb)


def _flip_hidden_bits(elements, start: int, offsets: list[int], n_lsb: int):
    """Flip the hidden bits at `offsets`, counted from `start` in embed order.

    Hidden bit k lives in element start + k // n_lsb, most-significant of the
    n_lsb low bits first (the order `lsb.embed_bits` writes). Only the named
    bits change; the caller has already checked that they lie inside the cover.
    """
    out = elements.copy()
    for offset in offsets:
        index, position = divmod(offset, n_lsb)
        out[start + index] ^= np.array(1 << (n_lsb - 1 - position), dtype=out.dtype)
    return out


def _magic_absent_at(elements, n_lsb: int, start: int, redundancy: int = 1) -> bool:
    """True only if `start` is readable and its (majority-voted) header does not
    begin with the plaintext MAGIC.

    With redundancy > 1 the MAGIC copies sit HEADER_SIZE bytes apart, so the
    whole header block is read and voted first, exactly as `pipeline.verify` does.
    """
    magic_bits = len(container.MAGIC) * 8
    read_bits = magic_bits if redundancy == 1 else container.HEADER_SIZE * 8 * redundancy
    try:
        location.validate_start(len(elements), start, read_bits, n_lsb)
    except (CapacityError, ValueError):
        return False
    voted = ecc.majority_vote(lsb.extract_bits(elements, start, read_bits, n_lsb), redundancy)
    return lsb.bits_to_bytes(voted[:magic_bits]) != container.MAGIC


def _copies_that_parse(elements, n_lsb: int, start: int, tried: int) -> int | None:
    """Another copy count at which a plaintext frame parses at `start`, if any.

    Only used to explain a failure: a 3-copy file attacked as 1 copy otherwise
    fails with a bare "CRC mismatch" (the first header copy is valid on its own,
    the bytes after it are the second copy, not the payload), and a 1-copy file
    attacked as 3 copies with "bad magic".
    """
    for candidate in range(ecc.MIN_REDUNDANCY, ecc.MAX_REDUNDANCY + 1, 2):
        if candidate == tried:
            continue
        try:
            extraction.extract_frame(elements, start, n_lsb, candidate)
        except (FrameError, CapacityError, ValueError):
            continue
        return candidate
    return None


def _plaintext_frame(elements, n_lsb: int, start: int, attack: str, redundancy: int = 1) -> bytes:
    """`_frame`, with an explanation when the copy count is wrong or the file may
    hold a sealed frame.
    """
    try:
        return _frame(elements, n_lsb, start, redundancy)
    except FrameError as exc:
        copies = _copies_that_parse(elements, n_lsb, start, redundancy)
        if copies is not None:
            raise FrameError(
                f"{exc}. Reading {redundancy} {'copy' if redundancy == 1 else 'copies'} at start {start} "
                f"fails, but a plaintext frame embedded as {copies} {'copy' if copies == 1 else 'copies'} "
                f"parses there; rerun {attack} with redundancy {copies} (CLI: --copies {copies})."
            ) from exc
        if not _magic_absent_at(elements, n_lsb, start, redundancy):
            raise  # out of range, or a damaged plaintext frame: the original error says it all
        copies_flag = f" --copies {redundancy}" if redundancy > 1 else ""
        raise FrameError(
            f"{exc}. No plaintext frame header at start {start}. If this file was protected with a "
            f"sealed frame, its header is encrypted and opaque to {attack} without the passphrase; "
            f"run the key-less sealed variant instead "
            f"(CLI: stego tamper --attack {attack} --sealed --start {start}{copies_flag})."
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


# Byte offset of the VERSION field inside the frame header (container.py's
# layout table: MAGIC, then VERSION).
_VERSION_OFFSET = len(container.MAGIC)


def _sealed_corruption_offsets(redundancy: int) -> tuple[list[int], int]:
    """Key-less corrupt_payload targets on a sealed frame, and the hidden bits
    from `start` that must exist for them to make sense.

    redundancy == 1: the top bit of the first ciphertext payload byte, just
    past the 12-byte nonce and the 13 encrypted header bytes. CTR maps it to
    the same plaintext bit, the header still opens, and the (encrypted) CRC
    reports the change.

    redundancy > 1: the body copies are one encrypted frame length apart, and
    that length is exactly what the attacker cannot read, so the same payload
    bit cannot be found in every body copy. The header block copies, though,
    are a fixed NONCE_SIZE + HEADER_SIZE bytes apart. Flip the top bit of the
    encrypted VERSION byte in every one of them: the vote keeps the flip,
    MAGIC still decrypts (so the verifier knows a sealed frame is there), and
    the opened header is rejected as an unsupported version.
    """
    block_bits = extraction.SEALED_HEADER_BLOCK_SIZE * 8
    if redundancy == 1:
        return [block_bits], block_bits + 1
    version_bit = (sealing.NONCE_SIZE + _VERSION_OFFSET) * 8
    return [copy * block_bits + version_bit for copy in range(redundancy)], block_bits * redundancy


def corrupt_payload(
    data: bytes, kind: str, n_lsb: int, start: int, *, sealed: bool = False, redundancy: int = 1
) -> bytes:
    """Corrupt the first payload bit, preserving magic/header and the old CRC.

    redundancy > 1 (the copy count the file was protected with): flip that
    same bit in EVERY body copy. They sit back to back after the header
    block, one body length apart (see the module docstring), so the vote
    returns the flipped bit and the CRC still reports the change -> Tampered.
    A single flipped copy would be outvoted and the file would stay Authentic.

    sealed=True: do the equivalent without the key; see
    `_sealed_corruption_offsets` for which ciphertext bits that means. Either
    way the verifier opens the header and then rejects the frame -> Tampered.
    The key-less variant cannot confirm a frame is at `start`, so the caller
    must pass the real one (the CLI refuses --sealed without --start).
    """
    ecc.validate_redundancy(redundancy)
    cover = _load(data, kind)
    if sealed:
        offsets, needed_bits = _sealed_corruption_offsets(redundancy)
        try:
            location.validate_start(len(cover.elements), start, needed_bits, n_lsb)
        except CapacityError as exc:
            raise FrameError("the sealed region extends past the end of the cover") from exc
        return _save(cover, _flip_hidden_bits(cover.elements, start, offsets, n_lsb), kind)
    frame = _plaintext_frame(cover.elements, n_lsb, start, "corrupt_payload", redundancy)
    if container.parse_header(frame)[0] == 0:
        raise FrameError("frame has no payload to corrupt")
    if redundancy == 1:
        offsets = [container.HEADER_SIZE * 8]
    else:
        body_offset = _block_elements(container.HEADER_SIZE, n_lsb, redundancy) * n_lsb
        body_bits = (len(frame) - container.HEADER_SIZE) * 8
        offsets = [body_offset + copy * body_bits for copy in range(redundancy)]
    # _plaintext_frame already checked that the whole frame (every copy) fits.
    return _save(cover, _flip_hidden_bits(cover.elements, start, offsets, n_lsb), kind)


def replay(
    stego: bytes,
    other_cover: bytes,
    kind: str,
    n_lsb: int,
    start: int,
    *,
    sealed: bool = False,
    redundancy: int = 1,
) -> bytes:
    """Transplant the unchanged signed frame; the target must differ in hashed media or shape.

    redundancy > 1: carry the whole multi-copy region as embedded (the header
    block copies, then the body block copies), so the verifier reads the same
    copies from the target. Copying one voted copy would leave the target's
    own LSBs where the other copies should be.

    sealed=True: a key-less attacker cannot read the sealed frame's length,
    so it copies every hidden bit from `start` to the end of the shorter
    cover. That still carries the whole sealed frame across when it fits,
    every copy included, and the verifier opens it with the right passphrase,
    finds a valid signature and a media hash that does not match -> Tampered
    (verify with the original explicit offset: a different cover size moves a
    derived start).
    """
    ecc.validate_redundancy(redundancy)
    source = _load(stego, kind)
    target = _load(other_cover, kind)
    if sealed:
        count = min(len(source.elements), len(target.elements)) - start
        if count <= 0:
            raise FrameError(f"start {start} leaves no hidden bits to transplant between these covers")
        header_block_elements = _block_elements(extraction.SEALED_HEADER_BLOCK_SIZE, n_lsb, redundancy)
        if count < header_block_elements:
            raise FrameError(
                f"start {start} leaves {count} elements to transplant between these covers, fewer than "
                f"the {header_block_elements} a sealed header block of {redundancy} "
                f"{'copy' if redundancy == 1 else 'copies'} needs"
            )
        bits = _sealed_region_bits(source.elements, n_lsb, start, count * n_lsb)
    elif redundancy == 1:
        bits = lsb.bytes_to_bits(_plaintext_frame(source.elements, n_lsb, start, "replay"))
    else:
        frame = _plaintext_frame(source.elements, n_lsb, start, "replay", redundancy)
        region_elements = _block_elements(container.HEADER_SIZE, n_lsb, redundancy) + _block_elements(
            len(frame) - container.HEADER_SIZE, n_lsb, redundancy
        )
        bits = lsb.extract_bits(source.elements, start, region_elements * n_lsb, n_lsb)
    mask = np.array(np.iinfo(source.elements.dtype).max ^ ((1 << n_lsb) - 1), dtype=source.elements.dtype)
    same_format = all(
        getattr(source, key, None) == getattr(target, key, None)
        for key in ("height", "width", "channels", "sample_rate", "sample_width", "frames")
    )
    if same_format and np.array_equal(source.elements & mask, target.elements & mask):
        raise ValueError("replay target must differ in signed media content or dimensions")
    elements = lsb.embed_bits(target.elements, bits, start, n_lsb)
    return _save(target, elements, kind)
