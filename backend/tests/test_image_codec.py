"""Round-trip and rejection tests for the PNG image cover."""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from stego_core import image_codec
from stego_core.errors import UnsupportedCoverError


def _png_bytes(mode: str, size: tuple[int, int] = (12, 9)) -> bytes:
    rng = np.random.default_rng(seed=hash(mode) % (2**32))
    width, height = size
    if mode == "P":
        img = Image.new("P", size)
        img.putpalette(rng.integers(0, 256, size=768, dtype=np.uint8).tobytes())
        pixels = rng.integers(0, 256, size=width * height, dtype=np.uint8)
        img.putdata(pixels.tolist())
    elif mode == "L":
        arr = rng.integers(0, 256, size=(height, width), dtype=np.uint8)
        img = Image.fromarray(arr, mode="L")
    elif mode in ("RGB", "RGBA"):
        channels = 4 if mode == "RGBA" else 3
        arr = rng.integers(0, 256, size=(height, width, channels), dtype=np.uint8)
        img = Image.fromarray(arr, mode=mode)
    else:
        raise ValueError(mode)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.mark.parametrize("mode", ["RGB", "RGBA"])
def test_round_trip_pixel_identical(mode: str) -> None:
    data = _png_bytes(mode)
    cover = image_codec.load_png(data)

    assert cover.original_mode == mode
    assert cover.channels == (4 if mode == "RGBA" else 3)
    assert cover.elements.dtype == np.uint8
    assert cover.elements.size == cover.height * cover.width * cover.channels

    out = image_codec.save_png(cover, cover.elements)
    reloaded = image_codec.load_png(out)
    assert np.array_equal(cover.elements, reloaded.elements)
    assert reloaded.height == cover.height
    assert reloaded.width == cover.width
    assert reloaded.channels == cover.channels


@pytest.mark.parametrize("mode", ["P", "L"])
def test_normalises_odd_modes_to_rgb(mode: str) -> None:
    data = _png_bytes(mode)
    cover = image_codec.load_png(data)

    assert cover.original_mode == mode
    assert cover.channels == 3

    out = image_codec.save_png(cover, cover.elements)
    reloaded = image_codec.load_png(out)
    assert np.array_equal(cover.elements, reloaded.elements)


def test_modified_elements_survive_save_load() -> None:
    data = _png_bytes("RGB")
    cover = image_codec.load_png(data)

    flipped = cover.elements ^ np.uint8(1)
    stego_bytes = image_codec.save_png(cover, flipped)
    assert stego_bytes != data

    reloaded = image_codec.load_png(stego_bytes)
    assert np.array_equal(reloaded.elements, flipped)


def test_rejects_non_png() -> None:
    with pytest.raises(UnsupportedCoverError):
        image_codec.load_png(b"not a png file at all")


def test_rejects_16bit_png() -> None:
    arr = np.zeros((4, 4), dtype=np.uint16)
    img = Image.fromarray(arr, mode="I;16")
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    with pytest.raises(UnsupportedCoverError):
        image_codec.load_png(buf.getvalue())


def test_lsb_plane_png_shape_and_range() -> None:
    data = _png_bytes("RGB")
    cover = image_codec.load_png(data)

    plane_bytes = image_codec.lsb_plane_png(cover, cover.elements, n_lsb=2)
    plane_img = Image.open(io.BytesIO(plane_bytes))
    plane_img.load()
    plane_arr = np.asarray(plane_img)

    assert plane_arr.shape == (cover.height, cover.width, cover.channels)
    max_val = (1 << 2) - 1
    scale = 255 // max_val
    assert set(np.unique(plane_arr)).issubset({v * scale for v in range(max_val + 1)})
