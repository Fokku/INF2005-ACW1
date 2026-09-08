"""SHA-256 integrity fingerprints (spec FR9, learning outcome 2).

>>> THE PROBLEM THIS MODULE SOLVES
>>> Embedding changes the cover. If you hash the raw file bytes, the hash you
>>> signed before embedding can never match the hash you recompute afterwards,
>>> and every file would look Tampered.
>>>
>>> THE FIX: hash a STABLE REPRESENTATION — the samples with the low n_lsb bits
>>> masked to zero, plus the format fields. Those bits are the only ones
>>> embedding touches, so:
>>>     hash(stable(cover)) == hash(stable(stego))        -> Authentic
>>>     hash changes if anyone edits the real content     -> Tampered
"""

from __future__ import annotations

import hashlib

import numpy as np


def sha256_hex(data: bytes) -> str:
    """Plain SHA-256 of raw bytes, lowercase hex. Used for the file-level
    'same file before send / after download' check in the GUI.

    Done for you.
    """
    return hashlib.sha256(data).hexdigest()


def stable_media_hash(elements: np.ndarray, n_lsb: int, header_fields: dict[str, int | str]) -> str:
    """SHA-256 over the cover content that embedding does NOT change.

    Args:
        elements:      the flat sample/channel array.
        n_lsb:         how many low bits the embedding will use.
        header_fields: format facts that must also be authenticated, e.g.
                       {"kind": "image", "height": 512, "width": 512, "channels": 3}
                       or {"kind": "audio", "rate": 44100, "channels": 2, "width": 2}.

    TODO(team): implement.

    Sketch:
      1. masked = elements & ~((1 << n_lsb) - 1)     # same dtype trick as lsb.py
      2. h = hashlib.sha256()
      3. h.update(canonical bytes of header_fields)  # sorted keys, utf-8, a
         separator you document — this is what makes a crop detectable
      4. h.update(masked.tobytes())
      5. return h.hexdigest()

    Write the exact formula in docs/design/payload-format.md. The verifier
    recomputes it with the SAME n_lsb (which is read from the frame header), so
    both sides must agree bit for bit.
    """
    raise NotImplementedError("TODO(team): stable_media_hash — see docstring")
