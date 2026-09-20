"""The binary frame that is actually embedded in the cover.

The decoder finds a run of bits and has to answer: is a payload here? how long
is it? was it damaged? This layout answers all three:

    offset  size  field
    0       4     MAGIC        b"ACW1"  — lets the decoder recognise a frame
    4       1     VERSION      frame format version (1)
    5       1     FLAGS        bit0 = message encrypted, rest reserved
    6       1     N_LSB        1..8 — how the rest of the frame was embedded
    7       4     PAYLOAD_LEN  big-endian uint32
    11      2     SIG_LEN      big-endian uint16
    13      N     PAYLOAD      canonical bytes from payload.serialize()
    ...     M     SIGNATURE    over the PAYLOAD bytes
    ...     4     CRC32        over everything before it

>>> Why N_LSB lives in the header AND in the signed payload: the decoder needs
>>> it in the clear to read the rest of the frame, and needs the signed copy to
>>> prove nobody changed it. Cross-check the two at verify time.
>>>
>>> Why CRC32: it separates "bits got corrupted" (-> Tampered) from "the
>>> signature does not match this key" (-> Signature Invalid). It is NOT a
>>> security control — anyone can recompute a CRC. Say that in the limitations.
"""

from __future__ import annotations

import struct
import zlib

from .errors import FrameError

_HEADER_STRUCT = struct.Struct(">4sBBBIH")  # magic, version, flags, n_lsb, payload_len, sig_len
_CRC_STRUCT = struct.Struct(">I")

MAGIC = b"ACW1"
FRAME_VERSION = 1
HEADER_SIZE = 13  # bytes before the payload
CRC_SIZE = 4
FLAG_ENCRYPTED = 0x01


def frame_size_bytes(payload_len: int, sig_len: int) -> int:
    """Total frame size. Use it for capacity checks. Done for you."""
    return HEADER_SIZE + payload_len + sig_len + CRC_SIZE


def frame_size_bits(payload_len: int, sig_len: int) -> int:
    """Same in bits. Done for you."""
    return frame_size_bytes(payload_len, sig_len) * 8


def build_frame(payload_bytes: bytes, signature: bytes, n_lsb: int, encrypted: bool) -> bytes:
    """Assemble the frame above."""
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")
    if len(payload_bytes) > 0xFFFFFFFF or len(signature) > 0xFFFF:
        raise ValueError("payload or signature too large for the frame header's length fields")

    flags = FLAG_ENCRYPTED if encrypted else 0
    head = _HEADER_STRUCT.pack(MAGIC, FRAME_VERSION, flags, n_lsb, len(payload_bytes), len(signature))
    assert len(head) == HEADER_SIZE, "HEADER_SIZE constant and _HEADER_STRUCT have drifted apart"
    body = head + payload_bytes + signature
    return body + _CRC_STRUCT.pack(zlib.crc32(body) & 0xFFFFFFFF)


def parse_frame(data: bytes) -> tuple[bytes, bytes, int, bool]:
    """Read a frame back. Returns (payload_bytes, signature, n_lsb, encrypted).

    Raises FrameError (from .errors) if the magic is wrong, the version is
    unknown, the lengths are impossible, or the CRC fails.

    Two-step read matters here: the caller only knows HEADER_SIZE up front, so
    parse the header first, learn PAYLOAD_LEN and SIG_LEN, and only then ask the
    LSB layer for the remaining bits. See `pipeline.verify`.
    """
    payload_len, sig_len, n_lsb, encrypted = parse_header(data)
    total = HEADER_SIZE + payload_len + sig_len + CRC_SIZE
    if len(data) < total:
        raise FrameError(f"frame truncated: need {total} bytes, have {len(data)}")
    if len(data) > total:
        raise FrameError(f"frame has trailing bytes: expected {total} bytes, have {len(data)}")

    body = data[: HEADER_SIZE + payload_len + sig_len]
    (crc_stored,) = _CRC_STRUCT.unpack_from(data, HEADER_SIZE + payload_len + sig_len)
    crc_actual = zlib.crc32(body) & 0xFFFFFFFF
    if crc_stored != crc_actual:
        raise FrameError(f"CRC mismatch: expected {crc_actual:#010x}, frame says {crc_stored:#010x}")

    payload_bytes = data[HEADER_SIZE : HEADER_SIZE + payload_len]
    signature = data[HEADER_SIZE + payload_len : HEADER_SIZE + payload_len + sig_len]
    return payload_bytes, signature, n_lsb, encrypted


def parse_header(data: bytes) -> tuple[int, int, int, bool]:
    """Parse only the first HEADER_SIZE bytes.

    Returns (payload_len, sig_len, n_lsb, encrypted) so the caller knows how many
    more bits to read. Raises FrameError if MAGIC does not match.
    """
    if len(data) < HEADER_SIZE:
        raise FrameError(f"frame header truncated: need {HEADER_SIZE} bytes, have {len(data)}")

    magic, version, flags, n_lsb, payload_len, sig_len = _HEADER_STRUCT.unpack_from(data, 0)
    if magic != MAGIC:
        raise FrameError(f"bad magic: {magic!r} (expected {MAGIC!r})")
    if version != FRAME_VERSION:
        raise FrameError(f"unsupported frame version: {version}")
    if not 1 <= n_lsb <= 8:
        raise FrameError(f"frame header claims impossible n_lsb: {n_lsb}")
    if flags & ~FLAG_ENCRYPTED:
        raise FrameError(f"frame header contains unsupported flags: {flags:#04x}")
    if payload_len == 0 or sig_len == 0:
        raise FrameError("frame must contain a payload and a signature")

    encrypted = bool(flags & FLAG_ENCRYPTED)
    return payload_len, sig_len, n_lsb, encrypted
