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

import struct  # noqa: F401  (used by build_frame / parse_frame once implemented)

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
    """Assemble the frame above.

    TODO(team): implement.

    Sketch:
      flags = FLAG_ENCRYPTED if encrypted else 0
      head  = MAGIC + struct.pack(">BBBIH", FRAME_VERSION, flags, n_lsb,
                                  len(payload_bytes), len(signature))
      body  = head + payload_bytes + signature
      return body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    Check that len(head) == HEADER_SIZE, or the constant and the format string
    have drifted apart.
    """
    raise NotImplementedError("TODO(team): build_frame — see docstring")


def parse_frame(data: bytes) -> tuple[bytes, bytes, int, bool]:
    """Read a frame back. Returns (payload_bytes, signature, n_lsb, encrypted).

    Raises FrameError (from .errors) if the magic is wrong, the version is
    unknown, the lengths are impossible, or the CRC fails.

    TODO(team): implement.

    Two-step read matters here: the caller only knows HEADER_SIZE up front, so
    parse the header first, learn PAYLOAD_LEN and SIG_LEN, and only then ask the
    LSB layer for the remaining bits. See `pipeline.verify`.
    """
    raise NotImplementedError("TODO(team): parse_frame — see docstring")


def parse_header(data: bytes) -> tuple[int, int, int, bool]:
    """Parse only the first HEADER_SIZE bytes.

    Returns (payload_len, sig_len, n_lsb, encrypted) so the caller knows how many
    more bits to read. Raises FrameError if MAGIC does not match.

    TODO(team): implement.
    Sketch: struct.unpack(">4sBBBIH", data[:HEADER_SIZE])
    """
    raise NotImplementedError("TODO(team): parse_header — see docstring")
