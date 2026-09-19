"""Where the payload starts, and how the verifier finds it again.

This module is worth 5 rubric marks on its own (criterion 1: "start-location
design, start-location security"). Two modes, both selectable in the GUI:

  EXPLICIT  the user picks an offset and tells party B out of band.
            Simple to demo, and the obvious way to show `Wrong Start Location`.

  DERIVED   start = HMAC-SHA256(K_loc, "start" || media_id || cover_kind ||
                                n_lsb || counter) mod (usable_elements)
            where K_loc comes from the shared passphrase (`kdf.py`). Party B
            re-derives the same number from the same passphrase. Nothing about
            the location travels with the file.

>>> THREE THINGS NOT TO DERIVE THE START FROM — each one looks clever and each
>>> one breaks the verdicts:
>>>
>>>  1. The media hash. Any tamper changes the hash, which moves the start, so
>>>     every Tampered file reports `Wrong Start Location` instead. Wrong story.
>>>  2. The nonce inside the payload. You cannot read the payload until you know
>>>     where it starts. Circular.
>>>  3. The cover shape/dimensions. A crop then reports `Wrong Start Location`
>>>     instead of `Tampered`. Bind the shape into the SIGNED PAYLOAD instead
>>>     and cross-check it at verify time.
>>>
>>> HONEST LIMITATION (put this in docs/design/limitations-and-ai-use.md):
>>> the frame starts with a plaintext MAGIC, so anyone can scan the LSB plane
>>> and find it. A secret start location defeats a naive fixed-offset reader,
>>> not a determined analyst. Confidentiality comes from AES-GCM and
>>> authenticity from the signature — not from the location being secret.
"""

from __future__ import annotations

import hashlib
import hmac
from numbers import Integral

from . import container, lsb
from .errors import CapacityError


def _require_integer(value: int, name: str, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, Integral) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}, got {value!r}")


def _required_elements(n_elements: int, frame_bits: int, n_lsb: int) -> int:
    _require_integer(n_elements, "n_elements", 0)
    _require_integer(frame_bits, "frame_bits", 1)
    _require_integer(n_lsb, "n_lsb", 1)
    if n_lsb > 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")
    return -(-frame_bits // n_lsb)


def validate_start(n_elements: int, start: int, frame_bits: int, n_lsb: int) -> None:
    """FR7: require a nonnegative element index with room for the whole frame.

    The final valid offset is n_elements - ceil(frame_bits / n_lsb), inclusive.
    Invalid numbers raise ValueError; insufficient remaining room raises
    CapacityError. The caller must use the actual frame size when protecting.
    """
    _require_integer(start, "start", 0)
    needed = _required_elements(n_elements, frame_bits, n_lsb)
    if start + needed > n_elements:
        raise CapacityError(
            f"start {start} needs {needed} elements at n_lsb={n_lsb}, but only "
            f"{max(0, n_elements - start)} elements are remaining; "
            f"cover has {n_elements} elements"
        )


def derive_start(
    k_loc: bytes,
    media_id: str,
    cover_kind: str,
    n_lsb: int,
    n_elements: int,
    frame_bits: int,
) -> int:
    """Deterministically choose a start element index.

    Keep the original HMAC message (counter zero) and modulus for compatibility
    with existing stego files. If the reservation exactly fills the cover,
    zero is the only valid start. Otherwise the legacy formula excludes the
    last fitting offset; explicit mode can still select that offset.

    >>> WHY `frame_bits` HERE IS NOT THE TRUE FRAME SIZE: the verifier calls
    >>> this function BEFORE it has read anything, so it cannot know the real
    >>> payload length — only the cover size and n_lsb. For the two sides to
    >>> land on the same offset, `frame_bits` must be something BOTH can compute
    >>> without reading the file: `pipeline.protect` and `pipeline.verify` both
    >>> pass `reserved_frame_bits(n_elements, n_lsb)` (below) — a fixed fraction
    >>> of the cover's total raw capacity, regardless of the actual message
    >>> length. This confines the derived start to (roughly) the first 10% of
    >>> the cover, which guarantees at least the other 90% as trailing room for
    >>> the real frame. `pipeline.protect` still separately checks the FULL frame
    >>> fits via `validate_start` before embedding (an unusually large
    >>> custom payload can still legitimately exceed the reserve and raise
    >>> CapacityError), and `pipeline.verify` learns the true payload/signature
    >>> lengths by reading the header it finds at that offset.
    """
    needed = _required_elements(n_elements, frame_bits, n_lsb)
    if not isinstance(k_loc, (bytes, bytearray)) or not k_loc:
        raise ValueError("k_loc must be a nonempty byte key")
    span = n_elements - needed
    if span < 0:
        raise CapacityError(
            f"cover has only {n_elements} elements, not enough room for a "
            f"{needed}-element reservation at n_lsb={n_lsb}"
        )
    if span == 0:
        return 0

    msg = (
        b"start"
        + media_id.encode("utf-8")
        + cover_kind.encode("utf-8")
        + bytes([n_lsb])
        + (0).to_bytes(4, "big")
    )
    digest = hmac.new(k_loc, msg, hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % span


def reserved_frame_bits(n_elements: int, n_lsb: int) -> int:
    """The `frame_bits` both `pipeline.protect` and `pipeline.verify` pass to
    `derive_start`: 90% of the cover's total raw capacity, in bits.

    A fixed fraction of a value both sides already know (cover size, n_lsb) —
    not the true frame size, which only protect knows in advance. Confines the
    derived start to (roughly) the first 10% of the cover, guaranteeing at
    least the other 90% of raw capacity as trailing room for whatever frame
    actually gets embedded. A frame larger than the reservation may still fit,
    but must pass the separate check against space after the derived offset.
    """
    _require_integer(n_elements, "n_elements", 0)
    _require_integer(n_lsb, "n_lsb", 1)
    capacity_bits = lsb.capacity_bits(n_elements, n_lsb)
    return capacity_bits - capacity_bits // 10


def scan_for_magic(elements, n_lsb: int, max_positions: int = 200_000) -> int | None:
    """Bounded search for the frame MAGIC anywhere in the LSB plane.

    This is what makes `Wrong Start Location` and `Payload Missing` different
    verdicts:

        magic not at the expected start, but found elsewhere -> Wrong Start Location
        magic nowhere in the cover                           -> Payload Missing

    Returns the element index where MAGIC was found, or None.

    Extracts the LSB plane once (capped at `max_positions` elements so a 50 MB
    WAV cannot hang the request), packs it to bytes, and searches for MAGIC.
    A frame can start at any ELEMENT, but this byte-aligned search over the
    packed stream only finds frames whose start is a multiple of 8/gcd(8, n_lsb)
    elements — good enough for the demo; documented as a known limitation.
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")

    n_elements = min(len(elements), max_positions)
    n_bits = (n_elements * n_lsb // 8) * 8  # round down to a whole number of bytes
    if n_bits <= 0:
        return None

    bits = lsb.extract_bits(elements, 0, n_bits, n_lsb)
    packed = lsb.bits_to_bytes(bits)
    byte_index = packed.find(container.MAGIC)
    if byte_index == -1:
        return None

    bit_index = byte_index * 8
    return bit_index // n_lsb
