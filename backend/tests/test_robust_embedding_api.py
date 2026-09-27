"""API tests for robust embedding, following the same route the GUI takes:
Protect with a number of copies, damage the file with the Attack Lab's
lsb_noise attack, then Verify with the same number of copies.
"""

from __future__ import annotations

import io

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.main import app
from stego_core import signing

client = TestClient(app)


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


@pytest.fixture(scope="module")
def cover_png() -> bytes:
    rng = np.random.default_rng(3)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (128, 128, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


SETTINGS = {"n_lsb": "2", "media_id": "robust-api", "start_mode": "explicit", "explicit_start": "0"}


def _protect(cover: bytes, private_pem: bytes, redundancy: int) -> dict:
    r = client.post(
        "/api/protect",
        files={
            "cover": ("cover.png", cover, "image/png"),
            "private_key_pem": ("key.pem", private_pem, "application/x-pem-file"),
        },
        data={**SETTINGS, "message_text": "robust embedding through the API", "redundancy": str(redundancy)},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _download(ref: dict) -> bytes:
    r = client.get(ref["download_url"])
    assert r.status_code == 200
    return r.content


def _noise(stego: bytes) -> bytes:
    r = client.post(
        "/api/attack",
        files={"stego": ("stego.png", stego, "image/png")},
        data={"attack": "lsb_noise", "n_lsb": "2", "start_offset": "0"},
    )
    assert r.status_code == 200, r.text
    return _download(r.json()["output"])


def _verify(stego: bytes, public_pem: bytes, redundancy: int) -> dict:
    r = client.post(
        "/api/verify",
        files={
            "stego": ("stego.png", stego, "image/png"),
            "public_key_pem": ("public.pem", public_pem, "application/x-pem-file"),
        },
        data={**SETTINGS, "redundancy": str(redundancy)},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_lsb_noise_is_listed_in_the_attack_lab() -> None:
    kinds = {k["kind"] for k in client.get("/api/attack/kinds").json()}
    assert "lsb_noise" in kinds


def test_protect_reports_the_number_of_copies(cover_png, keys) -> None:
    result = _protect(cover_png, keys[0], redundancy=3)
    assert result["redundancy"] == 3


@pytest.mark.parametrize("redundancy", [3, 5])
def test_multiple_copies_survive_lsb_noise(cover_png, keys, redundancy) -> None:
    stego = _download(_protect(cover_png, keys[0], redundancy)["stego"])
    report = _verify(_noise(stego), keys[1], redundancy)
    assert report["verdict"] == "Authentic", report["reasons"]
    assert report["redundancy"] == redundancy


def test_single_copy_does_not_survive_lsb_noise(cover_png, keys) -> None:
    stego = _download(_protect(cover_png, keys[0], redundancy=1)["stego"])
    assert _verify(stego, keys[1], 1)["verdict"] == "Authentic"
    assert _verify(_noise(stego), keys[1], 1)["verdict"] != "Authentic"


def test_capacity_accounts_for_copies(cover_png) -> None:
    # 128x128x3 at 1 LSB is 6144 bytes of raw space: a 2000-byte message fits
    # once, but not five times over.
    def capacity(redundancy: int) -> dict:
        r = client.post(
            "/api/capacity",
            files={"cover": ("cover.png", cover_png, "image/png")},
            data={"n_lsb": "1", "payload_bytes": "2000", "redundancy": str(redundancy)},
        )
        assert r.status_code == 200, r.text
        return r.json()

    single, five = capacity(1), capacity(5)
    assert single["fits"] is True
    assert five["fits"] is False
    assert five["redundancy"] == 5
    assert five["max_message_bytes"] < single["max_message_bytes"]


@pytest.mark.parametrize("endpoint", ["/api/protect", "/api/verify", "/api/capacity"])
def test_even_copy_count_is_rejected(cover_png, keys, endpoint) -> None:
    files = {"cover": ("cover.png", cover_png, "image/png")}
    if endpoint == "/api/protect":
        files["private_key_pem"] = ("key.pem", keys[0], "application/x-pem-file")
    if endpoint == "/api/verify":
        files = {
            "stego": ("stego.png", cover_png, "image/png"),
            "public_key_pem": ("public.pem", keys[1], "application/x-pem-file"),
        }
    r = client.post(endpoint, files=files, data={**SETTINGS, "message_text": "x", "redundancy": "2"})
    assert r.status_code == 400
    assert "odd" in r.json()["detail"]
