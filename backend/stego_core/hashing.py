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
import json

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

    Formula (see docs/design/payload-format.md):
        SHA-256( canonical_json(header_fields) || masked_elements_bytes )
    where masked_elements = elements & ~((1 << n_lsb) - 1), in the array's own
    dtype, and canonical_json uses sorted keys and no whitespace so both sides
    produce byte-identical input.
    """
    if not 1 <= n_lsb <= 8:
        raise ValueError(f"n_lsb must be 1..8, got {n_lsb}")

    bit_width = elements.dtype.itemsize * 8
    clear_mask = np.array(~((1 << n_lsb) - 1) & ((1 << bit_width) - 1), dtype=elements.dtype)
    masked = elements & clear_mask

    h = hashlib.sha256()
    h.update(json.dumps(header_fields, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    h.update(masked.tobytes())
    return h.hexdigest()
