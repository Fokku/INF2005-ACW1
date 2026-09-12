"""PNG cover objects: file bytes <-> flat numpy array (spec FR1, FR5).

Rules for this module (from TECH_STACK.md):
  * PNG only, and always save losslessly. Never JPEG — it re-encodes and wipes
    the LSB plane. (JPEG is allowed by the spec only if you explain that.)
  * Normalise palette / greyscale / LA images to RGB or RGBA 8-bit, and record
    the original mode so the report can show it.
  * 16-bit PNG (mode "I;16") is out of scope -> raise UnsupportedCoverError.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import numpy as np
from PIL import Image

from .errors import UnsupportedCoverError


@dataclass
class ImageCover:
    """A decoded image cover, ready for `lsb.embed_bits`."""

    elements: np.ndarray  # flat uint8, length = height * width * channels
    height: int
    width: int
    channels: int  # 3 or 4
    original_mode: str  # Pillow mode of the file as it arrived


def load_png(data: bytes) -> ImageCover:
    """Decode PNG bytes into a flat uint8 array.

    TODO(team): implement.

    Sketch:
      img = Image.open(io.BytesIO(data))
      if img.format != "PNG": raise UnsupportedCoverError(...)
      original_mode = img.mode
      convert P/L/LA/RGB -> "RGB", keep "RGBA" as "RGBA"; "I;16" -> unsupported
      arr = np.asarray(img, dtype=np.uint8)          # (h, w, c)
      return ImageCover(arr.reshape(-1), h, w, c, original_mode)

    Note on alpha: if you embed into the alpha channel of an RGBA image, a fully
    transparent pixel can hide bits invisibly — that is fine here, but say so in
    the design doc. Simplest defensible choice: normalise everything to RGB.
    """
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:  # Pillow raises various subclasses of OSError
        raise UnsupportedCoverError("could not decode image data as PNG") from exc

    if img.format != "PNG":
        raise UnsupportedCoverError(f"unsupported image format: {img.format!r} (PNG only)")

    original_mode = img.mode

    if original_mode == "RGBA":
        target_mode = "RGBA"
    elif original_mode in ("P", "L", "LA", "RGB", "1"):
        target_mode = "RGB"
    else:
        # e.g. "I", "I;16", "F" — 16-bit / floating point PNGs are out of scope.
        raise UnsupportedCoverError(f"unsupported PNG mode: {original_mode!r}")

    img = img.convert(target_mode)
    arr = np.asarray(img, dtype=np.uint8)  # (h, w, c)
    height, width, channels = arr.shape
    return ImageCover(
        elements=arr.reshape(-1).copy(),
        height=height,
        width=width,
        channels=channels,
        original_mode=original_mode,
    )


def save_png(cover: ImageCover, elements: np.ndarray) -> bytes:
    """Rebuild PNG bytes from (possibly modified) elements.

    TODO(team): implement.

    Sketch:
      arr = elements.reshape(cover.height, cover.width, cover.channels)
      Image.fromarray(arr, mode="RGB"/"RGBA").save(buf, format="PNG", optimize=False)

    Do not pass quality/lossy options. Verify with a round-trip test that
    load_png(save_png(x)) returns identical elements.
    """
    mode = "RGBA" if cover.channels == 4 else "RGB"
    arr = elements.reshape(cover.height, cover.width, cover.channels)
    img = Image.fromarray(arr, mode=mode)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=False)
    return buf.getvalue()


def lsb_plane_png(cover: ImageCover, elements: np.ndarray, n_lsb: int) -> bytes:
    """Render an amplified view of the low `n_lsb` bits, for the GUI comparison.

    Not required by the spec, but it makes the demo far more convincing: the
    cover's LSB plane looks like noise, the stego object's looks structured
    where the payload sits.

    TODO(team): implement (nice-to-have, do it after the round-trip works).

    Sketch: take elements & ((1<<n_lsb)-1), multiply by 255 // ((1<<n_lsb)-1),
    reshape, save as PNG.
    """
    max_val = (1 << n_lsb) - 1
    plane = (elements & max_val).astype(np.uint8) * (255 // max_val)
    arr = plane.reshape(cover.height, cover.width, cover.channels)
    mode = "RGBA" if cover.channels == 4 else "RGB"
    img = Image.fromarray(arr, mode=mode)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=False)
    return buf.getvalue()
