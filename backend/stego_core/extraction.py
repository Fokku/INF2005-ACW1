"""FR8: bounded frame extraction and decoding, independent of signature/hash checks.

The caller supplies the FR7 start and LSB count. Returned bytes are exactly
those embedded; a successful parse is not proof of authenticity. The existing
pipeline still verifies the signature and media hash before returning content.
"""

from dataclasses import dataclass

import numpy as np

from . import container, hashing, location, lsb, signing
from . import payload as payload_mod
from .errors import CapacityError, FrameError


@dataclass(frozen=True)
class ExtractedFrame:
    payload_bytes: bytes
    signature: bytes
    n_lsb: int
    encrypted: bool


def extract_frame(elements: np.ndarray, start: int, n_lsb: int) -> ExtractedFrame:
    """Read a fixed-size header, then a frame bounded by the remaining cover.

    Never allocate from unchecked length fields. A partial header or a frame
    extending past the cover raises FrameError. Invalid caller settings raise
    ValueError through the shared location validator.
    """
    try:
        location.validate_start(len(elements), start, container.HEADER_SIZE * 8, n_lsb)
    except CapacityError as exc:
        raise FrameError("frame header extends past the end of the cover") from exc
    header = lsb.bits_to_bytes(lsb.extract_bits(elements, start, container.HEADER_SIZE * 8, n_lsb))
    payload_len, sig_len, frame_n_lsb, _ = container.parse_header(header)
    if frame_n_lsb != n_lsb:
        raise FrameError("frame LSB count does not match the selected extraction LSB count")
    if sig_len != signing.SIGNATURE_BYTES:
        raise FrameError(f"frame signature must contain {signing.SIGNATURE_BYTES} bytes, got {sig_len}")

    frame_bits = container.frame_size_bits(payload_len, sig_len)
    try:
        location.validate_start(len(elements), start, frame_bits, n_lsb)
    except CapacityError as exc:
        raise FrameError("frame extends past the end of the cover") from exc
    raw = lsb.bits_to_bytes(lsb.extract_bits(elements, start, frame_bits, n_lsb))
    payload_bytes, signature, frame_n_lsb, encrypted = container.parse_frame(raw)
    return ExtractedFrame(payload_bytes, signature, frame_n_lsb, encrypted)


def decode_payload(frame: ExtractedFrame) -> payload_mod.Payload:
    """Decode the existing payload format and reject malformed field types.

    These checks keep corrupt or unsupported values out of the hash function
    and API response models. They do not change serialization or cryptography.
    """
    pl = payload_mod.deserialize(frame.payload_bytes)
    if type(pl.version) is not int or pl.version != payload_mod.PAYLOAD_VERSION:
        raise FrameError("unsupported payload version")
    for name in ("media_id", "timestamp", "media_hash", "nonce", "cover_kind", "message_mime"):
        if not isinstance(getattr(pl, name), str):
            raise FrameError(f"payload {name} must be a string")
    if not hashing.is_sha256_hex_digest(pl.media_hash):
        raise FrameError("payload media_hash must be a 64-character lowercase SHA-256 hex digest")
    if pl.cover_kind not in ("image", "audio", "video"):
        raise FrameError("unsupported payload cover kind")
    if type(pl.n_lsb) is not int or not 1 <= pl.n_lsb <= 8:
        raise FrameError("payload n_lsb must be an integer from 1 to 8")
    if pl.n_lsb != frame.n_lsb:
        raise FrameError("payload LSB count does not match the frame")
    if type(pl.encrypted) is not bool or pl.encrypted != frame.encrypted:
        raise FrameError("payload encryption flag does not match the frame")
    dimensions = 3 if pl.cover_kind == "image" else 2
    if (
        not isinstance(pl.shape, list)
        or len(pl.shape) != dimensions
        or any(type(value) is not int or value <= 0 for value in pl.shape)
    ):
        raise FrameError("payload shape must contain positive integer dimensions for its cover kind")
    if not isinstance(pl.metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in pl.metadata.items()
    ):
        raise FrameError("payload metadata must map strings to strings")
    return pl
