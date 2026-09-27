"""FR8: bounded frame extraction and decoding, independent of signature/hash checks.

The caller supplies the FR7 start and LSB count. Returned bytes are exactly
those embedded; a successful parse is not proof of authenticity. The existing
pipeline still verifies the signature and media hash before returning content.

Sealed frames (`sealing.py`) are read by `sealed_frame_at` and
`extract_sealed_frame`. They follow the same two-step, bounds-checked read as
`extract_frame`, with the 12-byte seal nonce in front of the header and a
decrypt between reading bits and parsing them.
"""

from dataclasses import dataclass

import numpy as np

from . import container, ecc, hashing, location, lsb, sealing, signing
from . import payload as payload_mod
from .errors import CapacityError, FrameError


@dataclass(frozen=True)
class ExtractedFrame:
    payload_bytes: bytes
    signature: bytes
    n_lsb: int
    encrypted: bool


def extract_frame(elements: np.ndarray, start: int, n_lsb: int, redundancy: int = 1) -> ExtractedFrame:
    """Read a fixed-size header, then a frame bounded by the remaining cover.

    Never allocate from unchecked length fields. A partial header or a frame
    extending past the cover raises FrameError. Invalid caller settings raise
    ValueError through the shared location validator.

    `redundancy` is the bonus robust-embedding factor (see `ecc.py`). At the
    default of 1 this function is byte-for-byte identical to before the
    parameter existed. Above 1, `pipeline.protect` embedded the header and
    the rest of the frame as two separate runs of `redundancy` back-to-back
    copies each (header block, then body block) rather than one run of
    whole-frame copies. That split is what lets this function keep reading
    the header first without yet knowing the payload/signature lengths, exactly
    like the redundancy=1 path below, just with each block majority-voted
    back to one copy before it is hashed into `container.parse_header` /
    `parse_frame`.
    """
    if redundancy == 1:
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

    ecc.validate_redundancy(redundancy)
    header_bits_needed = container.HEADER_SIZE * 8 * redundancy
    try:
        location.validate_start(len(elements), start, header_bits_needed, n_lsb)
    except CapacityError as exc:
        raise FrameError("frame header extends past the end of the cover") from exc
    header = lsb.bits_to_bytes(
        ecc.majority_vote(lsb.extract_bits(elements, start, header_bits_needed, n_lsb), redundancy)
    )
    payload_len, sig_len, frame_n_lsb, _ = container.parse_header(header)
    if frame_n_lsb != n_lsb:
        raise FrameError("frame LSB count does not match the selected extraction LSB count")
    if sig_len != signing.SIGNATURE_BYTES:
        raise FrameError(f"frame signature must contain {signing.SIGNATURE_BYTES} bytes, got {sig_len}")

    # The body block starts immediately after the header block's own
    # (possibly zero-padded) element span, using the same ceil() accounting
    # `embed_bits` used when it wrote the two blocks back to back.
    header_elements = -(-header_bits_needed // n_lsb)
    body_start = start + header_elements
    body_bits_needed = (payload_len + sig_len + container.CRC_SIZE) * 8 * redundancy
    try:
        location.validate_start(len(elements), body_start, body_bits_needed, n_lsb)
    except CapacityError as exc:
        raise FrameError("frame extends past the end of the cover") from exc
    body = lsb.bits_to_bytes(
        ecc.majority_vote(lsb.extract_bits(elements, body_start, body_bits_needed, n_lsb), redundancy)
    )
    payload_bytes, signature, frame_n_lsb, encrypted = container.parse_frame(header + body)
    return ExtractedFrame(payload_bytes, signature, frame_n_lsb, encrypted)


SEALED_HEADER_BLOCK_SIZE = sealing.NONCE_SIZE + container.HEADER_SIZE


def _read_sealed_header_block(elements: np.ndarray, start: int, n_lsb: int, redundancy: int) -> bytes:
    """Read (and majority-vote) the nonce + encrypted header block at `start`.

    Protect embeds this block exactly where an unsealed frame keeps its
    plaintext header: first, as one run of `redundancy` back-to-back copies.
    Raises FrameError if the block does not fit in the cover.
    """
    ecc.validate_redundancy(redundancy)
    bits_needed = SEALED_HEADER_BLOCK_SIZE * 8 * redundancy
    try:
        location.validate_start(len(elements), start, bits_needed, n_lsb)
    except CapacityError as exc:
        raise FrameError("sealed frame header extends past the end of the cover") from exc
    bits = lsb.extract_bits(elements, start, bits_needed, n_lsb)
    return lsb.bits_to_bytes(ecc.majority_vote(bits, redundancy))


def sealed_frame_at(elements: np.ndarray, start: int, n_lsb: int, k_seal: bytes, redundancy: int = 1) -> bool:
    """True if a frame sealed under `k_seal` begins at `start`.

    The sealed counterpart of "is the MAGIC here?": decrypt the header block
    and compare its first four bytes with MAGIC. With the wrong key those
    bytes are uniformly random, so a false hit has probability 2^-32 and is
    still stopped by the header, CRC and signature checks that follow. A
    False answer cannot tell "wrong key" from "no payload": that is the
    security property sealing exists to provide.
    """
    try:
        block = _read_sealed_header_block(elements, start, n_lsb, redundancy)
    except FrameError:
        return False
    return sealing.unseal(k_seal, block)[: len(container.MAGIC)] == container.MAGIC


def extract_sealed_frame(
    elements: np.ndarray, start: int, n_lsb: int, k_seal: bytes, redundancy: int = 1
) -> ExtractedFrame:
    """`extract_frame` for a sealed frame: same checks, one decrypt in between.

    Layout mirrors the unsealed one so `redundancy` works unchanged:
      redundancy == 1  nonce || ciphertext, one contiguous run of bits.
      redundancy  > 1  header block = [nonce || first HEADER_SIZE ciphertext
                       bytes] x redundancy, then, from the next whole element,
                       body block = [remaining ciphertext] x redundancy.
    CTR decrypts any prefix on its own, which is what lets the header block
    be opened, parsed and length-checked before the body is read. Lengths
    come from DECRYPTED header fields and are bounds-checked against the
    cover before a single body bit is extracted, exactly like the plaintext
    path. Any failure after the header opened raises FrameError (-> Tampered).
    """
    header_block = _read_sealed_header_block(elements, start, n_lsb, redundancy)
    header = sealing.unseal(k_seal, header_block)
    payload_len, sig_len, frame_n_lsb, _ = container.parse_header(header)
    if frame_n_lsb != n_lsb:
        raise FrameError("frame LSB count does not match the selected extraction LSB count")
    if sig_len != signing.SIGNATURE_BYTES:
        raise FrameError(f"frame signature must contain {signing.SIGNATURE_BYTES} bytes, got {sig_len}")

    frame_len = container.frame_size_bytes(payload_len, sig_len)
    if redundancy == 1:
        sealed_bits = sealing.sealed_size(frame_len) * 8
        try:
            location.validate_start(len(elements), start, sealed_bits, n_lsb)
        except CapacityError as exc:
            raise FrameError("sealed frame extends past the end of the cover") from exc
        sealed = lsb.bits_to_bytes(lsb.extract_bits(elements, start, sealed_bits, n_lsb))
    else:
        header_elements = -(-(SEALED_HEADER_BLOCK_SIZE * 8 * redundancy) // n_lsb)
        body_start = start + header_elements
        body_bits_needed = (frame_len - container.HEADER_SIZE) * 8 * redundancy
        try:
            location.validate_start(len(elements), body_start, body_bits_needed, n_lsb)
        except CapacityError as exc:
            raise FrameError("sealed frame extends past the end of the cover") from exc
        body = lsb.bits_to_bytes(
            ecc.majority_vote(lsb.extract_bits(elements, body_start, body_bits_needed, n_lsb), redundancy)
        )
        sealed = header_block + body

    payload_bytes, signature, frame_n_lsb, encrypted = container.parse_frame(sealing.unseal(k_seal, sealed))
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
