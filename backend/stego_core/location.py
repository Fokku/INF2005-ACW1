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

MAX_COUNTER = 64  # give up after this many derivation attempts


def derive_start(
    k_loc: bytes,
    media_id: str,
    cover_kind: str,
    n_lsb: int,
    n_elements: int,
    frame_bits: int,
) -> int:
    """Deterministically choose a start element index.

    The frame must fit between the start and the end of the cover, so the
    modulus is (usable elements - elements the frame needs), and the counter is
    incremented until a candidate fits.

    TODO(team): implement.

    Sketch:
      needed = ceil(frame_bits / n_lsb)
      span   = n_elements - needed
      if span <= 0: raise CapacityError(...)
      for counter in range(MAX_COUNTER):
          msg = b"start" + media_id.encode() + cover_kind.encode() + bytes([n_lsb]) + counter.to_bytes(4,"big")
          digest = hmac.new(k_loc, msg, hashlib.sha256).digest()
          start = int.from_bytes(digest, "big") % span
          return start        # every candidate fits by construction of `span`

    Keep the counter loop anyway: it is the hook for a future version that skips
    regions (e.g. avoids flat areas of the image), and the design doc can
    explain it.
    """
    raise NotImplementedError("TODO(team): derive_start — see docstring")


def scan_for_magic(elements, n_lsb: int, max_positions: int = 200_000) -> int | None:
    """Bounded search for the frame MAGIC anywhere in the LSB plane.

    This is what makes `Wrong Start Location` and `Payload Missing` different
    verdicts:

        magic not at the expected start, but found elsewhere -> Wrong Start Location
        magic nowhere in the cover                           -> Payload Missing

    Returns the element index where MAGIC was found, or None.

    TODO(team): implement.

    Sketch: extract the whole LSB plane once with lsb.extract_bits(elements, 0,
    n_elements*n_lsb, n_lsb), pack it to bytes, and search for MAGIC. Remember a
    frame can start at any ELEMENT, so a byte-aligned search over the packed
    stream only finds frames whose start is a multiple of 8/gcd(8, n_lsb) —
    good enough for the demo, and a nice thing to explain as a known limitation.
    Cap the work at `max_positions` so a 50 MB WAV cannot hang the request.
    """
    raise NotImplementedError("TODO(team): scan_for_magic — see docstring")
