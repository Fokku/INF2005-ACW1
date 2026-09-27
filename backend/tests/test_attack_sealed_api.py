"""The Attack Lab's `sealed` form field: key-less corrupt_payload / replay.

Without the passphrase a sealed frame's header is unreadable, so these two
attacks cannot locate the frame by parsing it; with `sealed=true` they work
blind from the start offset instead (stego_core.attacks), and the verifier
still catches the damage.
"""

from __future__ import annotations

import io

import numpy as np
from fastapi.testclient import TestClient
from PIL import Image

from app.main import app
from stego_core import signing

client = TestClient(app)
PASSPHRASE = "attack-lab-sealed"


def _png(seed: int, size: int = 96) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (size, size, 3), dtype=np.uint8)).save(buf, "PNG")
    return buf.getvalue()


def _protect_sealed(private_pem: bytes) -> tuple[bytes, int]:
    r = client.post(
        "/api/protect",
        files={"cover": ("cover.png", _png(1)), "private_key_pem": ("k.pem", private_pem)},
        data={
            "message_text": "sealed attack target",
            "n_lsb": "2",
            "media_id": "sealed-attack",
            "start_mode": "explicit",
            "explicit_start": "512",
            "passphrase": PASSPHRASE,
            "seal_frame": "true",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sealed"] is True
    return client.get(body["stego"]["url"]).content, body["start_offset"]


def _verify(stego: bytes, public_pem: bytes) -> str:
    r = client.post(
        "/api/verify",
        files={"stego": ("s.png", stego), "public_key_pem": ("p.pem", public_pem)},
        data={
            "n_lsb": "2",
            "media_id": "sealed-attack",
            "start_mode": "explicit",
            "explicit_start": "512",
            "passphrase": PASSPHRASE,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["verdict"]


def test_corrupt_payload_needs_the_sealed_flag_and_then_reports_tampered() -> None:
    private_pem, public_pem = signing.generate_keypair()
    stego, start = _protect_sealed(private_pem)
    assert _verify(stego, public_pem) == "Authentic"

    form = {"attack": "corrupt_payload", "n_lsb": "2", "start_offset": str(start)}
    refused = client.post("/api/attack", files={"stego": ("s.png", stego)}, data=form)
    assert refused.status_code == 400
    assert "sealed" in refused.json()["detail"]

    r = client.post("/api/attack", files={"stego": ("s.png", stego)}, data={**form, "sealed": "true"})
    assert r.status_code == 200, r.text
    damaged = client.get(r.json()["output"]["url"]).content
    assert _verify(damaged, public_pem) == "Tampered"


def test_replay_with_the_sealed_flag_carries_the_frame_to_another_cover() -> None:
    private_pem, public_pem = signing.generate_keypair()
    stego, start = _protect_sealed(private_pem)
    r = client.post(
        "/api/attack",
        files={"stego": ("s.png", stego), "other_cover": ("other.png", _png(2))},
        data={"attack": "replay", "n_lsb": "2", "start_offset": str(start), "sealed": "true"},
    )
    assert r.status_code == 200, r.text
    replayed = client.get(r.json()["output"]["url"]).content
    assert _verify(replayed, public_pem) == "Tampered"
