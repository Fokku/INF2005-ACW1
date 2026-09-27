"""Cover capacity check (spec Section 5: "is payload size larger than cover
object size?"). This is a REQUIRED demo case, so it gets its own endpoint and
its own panel in the UI.

The answer has to agree with what /api/protect will then do, otherwise the
meter shows green and Protect refuses the message. So nothing here is a rough
allowance any more. Every cost that `pipeline.protect` pays is measured the
way protect pays it:

  * the signed JSON, built with `payload.Payload` / `payload.serialize` from
    the caller's media ID and metadata, around an empty message;
  * the message itself as base64 (`message_b64`), after AES-GCM when
    encryption is on;
  * the frame header, signature and CRC (`container.frame_size_bytes`), plus
    the seal nonce when the frame is sealed;
  * `redundancy` copies, with protect's own per-block rounding to whole
    elements;
  * the start offset: the explicit one, or in derived mode the LATEST offset
    `location.derive_start` can pick, so the answer holds for any passphrase.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from stego_core import (
    audio_codec,
    container,
    ecc,
    hashing,
    image_codec,
    location,
    lsb,
    pipeline,
    sealing,
    signing,
    video_codec,
)
from stego_core import payload as payload_mod
from stego_core.errors import UnsupportedCoverError

from ..schemas import AudioInfo, CapacityReport, CoverInfo, CoverKind, ImageInfo, StartMode, VideoInfo

router = APIRouter()

# Used only when the caller does not say which media ID or metadata the frame
# will carry. Both are user-chosen and signed into the payload, so their size
# is unknown; assume generous ones so the estimate errs towards "does not fit"
# rather than promising room Protect will not find. The answer is then safe
# for a media ID of up to 128 bytes of JSON string (the GUI's default is the
# cover's file name) and metadata of up to 256 bytes of JSON beyond "{}" (five
# times the GUI's default). Larger than that, it is not: nothing bounds what a
# user may type. They are not larger by default because the frame is paid per
# copy, and a bigger guess would leave a small cover with room for nothing at
# redundancy 3. The GUI sends both, which makes the answer exact instead.
FALLBACK_MEDIA_ID_BYTES = 128
FALLBACK_METADATA_BYTES = 256

# The longest form datetime.isoformat() gives for pipeline.protect's UTC
# timestamp: with microseconds, 32 characters. A timestamp that falls on a
# whole second drops the ".ffffff" and is shorter, so this never under-counts.
_TIMESTAMP_EXAMPLE = datetime(2000, 1, 1, microsecond=1, tzinfo=UTC).isoformat()

# What payload.encrypt_message adds to a message: its GCM nonce in front and
# the authentication tag behind (12 + 16 bytes). Measured from the function
# itself rather than restated, so it cannot drift from what protect embeds.
_GCM_OVERHEAD_BYTES = len(payload_mod.encrypt_message(bytes(32), b"", aad=b""))


def _base64_len(raw_bytes: int) -> int:
    """Bytes needed to base64-encode `raw_bytes` of input (with padding).

    payload.serialize() puts the message into the signed JSON as
    `message_b64`, which is base64, not raw -- that inflates it by ~4/3. For
    a short message this rounds to noise; for a large custom message
    (hundreds of KB) it is the dominant term, so it must be accounted for
    explicitly rather than folded into a flat overhead constant.
    """
    return ((raw_bytes + 2) // 3) * 4


def _empty_message_payload_bytes(
    *,
    media_id: str | None,
    metadata: object | None,
    cover_kind: str,
    n_lsb: int,
    shape: list[int],
    message_mime: str,
    encrypted: bool,
) -> int:
    """Size of the signed JSON that pipeline.protect would build, minus the message.

    Built with the same payload.Payload and payload.serialize protect uses, so
    every field costs exactly what it will cost: the media ID and metadata as
    UTF-8 JSON (escapes included), the cover's real shape, and `encrypted` as
    `true` or `false`. The per-embed values are stand-ins of the exact length
    protect produces: a fresh nonce from payload.new_nonce, a SHA-256 hex digest
    for the media hash (always 64 characters), and the longest timestamp form.

    Only the message is left empty. It enters the JSON as base64 inside a
    string that is already there, and base64 never needs a JSON escape, so a
    message adds exactly _base64_len(its size) bytes on top of this.

    A media ID or metadata of None means "not supplied": it is left empty here
    and the FALLBACK_* allowance is added in its place.
    """
    pl = payload_mod.Payload(
        media_id=media_id if media_id is not None else "",
        timestamp=_TIMESTAMP_EXAMPLE,
        media_hash=hashing.sha256_hex(b""),
        nonce=payload_mod.new_nonce(),
        cover_kind=cover_kind,
        n_lsb=n_lsb,
        shape=shape,
        message_mime=message_mime,
        message=b"",
        encrypted=encrypted,
        metadata=metadata if metadata is not None else {},
    )
    size = len(payload_mod.serialize(pl))
    if media_id is None:
        size += FALLBACK_MEDIA_ID_BYTES
    if metadata is None:
        size += FALLBACK_METADATA_BYTES
    return size


def _worst_case_derived_start(n_elements: int, n_lsb: int) -> int:
    """The latest element index location.derive_start can choose on this cover.

    derive_start returns HMAC(K_loc, ...) mod span, somewhere in [0, span),
    where span is what remains once location.reserved_frame_bits has set aside
    about 90% of the cover for the frame. Which offset a passphrase lands on
    cannot be known here: this endpoint takes no passphrase, and the whole
    point of the derivation is that it is keyed. So size the answer for the
    last possible offset, span - 1. A message that fits there fits at every
    earlier offset too, whatever passphrase Protect is given. (A larger one
    may still fit for a passphrase whose start happens to be early, but the
    meter cannot promise that.)
    """
    reserved_elements = -(-location.reserved_frame_bits(n_elements, n_lsb) // n_lsb)
    span = n_elements - reserved_elements
    return max(0, span - 1)


def _max_copy_bytes(room_elements: int, n_lsb: int, redundancy: int, header_block_bytes: int) -> int:
    """Largest embedded copy, in bytes, that fits in `room_elements` elements.

    "Embedded copy" is what pipeline.protect writes once per copy: the frame,
    plus the seal nonce when sealed. This inverts protect's own element count,
    so the two agree to the byte:

      * one copy takes ceil(8 * bytes / n_lsb) elements;
      * with redundancy > 1, protect writes two separately rounded blocks, all
        `redundancy` copies of the header block (header_block_bytes: the 13-byte
        frame header, or nonce + header when sealed) and then all copies of the
        rest. The header block's rounding is paid first and the rest gets the
        elements that are left.

    Returns 0 when not even the header block fits.
    """
    if room_elements <= 0:
        return 0
    if redundancy == 1:
        return room_elements * n_lsb // 8
    header_elements = -(-(header_block_bytes * 8 * redundancy) // n_lsb)
    if room_elements < header_elements:
        return 0
    return header_block_bytes + (room_elements - header_elements) * n_lsb // (8 * redundancy)


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
    payload_bytes: int | None = Form(None, ge=0, description="size of the message the user wants to hide"),
    redundancy: int = Form(1, description="copies of the frame that will be embedded"),
    seal_frame: bool = Form(False, description="the frame will be sealed (adds a 12-byte nonce per copy)"),
    media_id: str | None = Form(
        None, description="the media ID Protect will sign; if omitted, a long one is assumed"
    ),
    metadata_json: str | None = Form(
        None, description="the metadata Protect will sign, as JSON; if omitted, a large object is assumed"
    ),
    message_mime: str = Form("text/plain", description="the message MIME type Protect will sign"),
    encrypt_message: bool = Form(False, description="the message will be AES-GCM encrypted (adds 28 bytes)"),
    start_mode: StartMode = Form(StartMode.derived),
    explicit_start: int | None = Form(None, description="element offset, when start_mode=explicit"),
) -> CapacityReport:
    """Report how much this cover can hold, and whether the message fits.

    Takes the same form fields as /api/protect for everything that changes the
    frame's size or where it starts, so the GUI can send one set of settings to
    both and get the same answer from each.
    """
    try:
        ecc.validate_redundancy(redundancy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if start_mode == StartMode.explicit:
        # Same refusals as /api/protect, so the two never disagree on these.
        if explicit_start is None:
            raise HTTPException(
                status_code=400, detail="explicit start mode requires an explicit_start offset"
            )
        if explicit_start < 0:
            raise HTTPException(status_code=400, detail=f"start must be >= 0, got {explicit_start}")
    metadata = None
    if metadata_json:
        try:
            metadata = json.loads(metadata_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"metadata_json is not valid JSON: {exc}") from exc

    data = await cover.read()
    kind = _sniff_kind(cover.filename or "")
    # The same decode pipeline.protect runs, so `shape` is exactly the list it signs.
    decoded, _header_fields, shape = pipeline._load_cover(kind.value, data)
    cover_info = _cover_info(kind, cover.filename or "cover", data, decoded)

    total_elements = len(decoded.elements)
    capacity_bits = lsb.capacity_bits(total_elements, n_lsb)
    capacity_bytes = capacity_bits // 8

    # 1. Bytes every copy carries whatever the message: the frame around an
    #    empty message, plus the seal nonce when sealed.
    json_bytes = _empty_message_payload_bytes(
        media_id=media_id or None,
        metadata=metadata,
        cover_kind=kind.value,
        n_lsb=n_lsb,
        shape=shape,
        message_mime=message_mime,
        encrypted=encrypt_message,
    )
    fixed_frame_bytes = container.frame_size_bytes(json_bytes, signing.SIGNATURE_BYTES)
    header_block_bytes = container.HEADER_SIZE
    if seal_frame:
        # A sealed frame is nonce || AES-CTR(frame): exactly SEAL_OVERHEAD more
        # bytes, embedded once per copy like the rest of the header block.
        fixed_frame_bytes += sealing.SEAL_OVERHEAD
        header_block_bytes += sealing.NONCE_SIZE

    # 2. Where embedding starts, and so how much of the cover is left after it.
    if start_mode == StartMode.explicit:
        start = explicit_start
    else:
        start = _worst_case_derived_start(total_elements, n_lsb)
    max_copy_bytes = _max_copy_bytes(total_elements - start, n_lsb, redundancy, header_block_bytes)

    # 3. The message goes in as base64, after AES-GCM when encrypted.
    encryption_bytes = _GCM_OVERHEAD_BYTES if encrypt_message else 0

    def message_fits(message_bytes: int) -> bool:
        return fixed_frame_bytes + _base64_len(message_bytes + encryption_bytes) <= max_copy_bytes

    # "Largest message" is a standalone figure independent of what's currently
    # typed. base64 emits whole 4-byte groups, each carrying 3 raw bytes, so
    # the room left in a copy holds 3 * (room // 4) bytes before base64; the
    # GCM nonce and tag take their share of that first. message_fits() agrees
    # at the boundary: this many bytes fit, one more does not.
    max_message_bytes = max(0, 3 * ((max_copy_bytes - fixed_frame_bytes) // 4) - encryption_bytes)

    # frame_overhead_bytes is what the GUI's meter uses: it computes
    # `used = (messageBytes + frame_overhead_bytes) * redundancy` and compares
    # that with capacity_bytes. So it is every byte of a copy's share of the
    # cover that the message cannot use: the fixed frame, THIS message's own
    # base64 and encryption inflation, and the copy's share of the cover lost
    # before the start offset and to element rounding (start_reserve). With
    # that, the meter's comparison is exactly `fits`, including at the limit:
    # (m + overhead) * r <= capacity  <=>  frame bytes <= max_copy_bytes.
    start_reserve = capacity_bytes // redundancy - max_copy_bytes
    typed = payload_bytes or 0
    frame_overhead_bytes = fixed_frame_bytes + (_base64_len(typed + encryption_bytes) - typed) + start_reserve
    fits = message_fits(payload_bytes) if payload_bytes is not None else None

    return CapacityReport(
        cover=cover_info,
        n_lsb=n_lsb,
        total_elements=total_elements,
        capacity_bits=capacity_bits,
        capacity_bytes=capacity_bytes,
        frame_overhead_bytes=frame_overhead_bytes,
        start_reserve_bytes=start_reserve,
        max_message_bytes=max_message_bytes,
        payload_bytes=payload_bytes,
        fits=fits,
        redundancy=redundancy,
    )
