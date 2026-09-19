"""API smoke tests.

The first two pass today and guard the scaffold. The rest are the end-to-end
tests to enable as the core lands.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_attack_kinds_listed() -> None:
    r = client.get("/api/attack/kinds")
    assert r.status_code == 200
    kinds = {k["kind"] for k in r.json()}
    assert {"flip_bits", "lsb_scrub", "replay"} <= kinds


def test_unimplemented_endpoints_say_so(png_rgb: bytes) -> None:
    """Endpoints whose core is still unimplemented (attacks.py, workstream F)
    return a helpful 501 rather than crashing."""
    r = client.post(
        "/api/attack",
        files={"stego": ("t.png", png_rgb, "image/png")},
        data={"attack": "flip_bits", "n_lsb": "1", "start_offset": "0"},
    )
    assert r.status_code == 501
    assert r.json()["error"] == "not_implemented"


def test_capacity_accounts_for_base64_inflation(png_rgb: bytes) -> None:
    """A message goes into the signed payload as base64 (payload.py's
    message_b64 field), which costs ~4/3 its raw size, not 1x. For a large
    custom message this dominates the frame size, so /api/capacity must not
    report `fits: true` for a message that will actually blow the CapacityError
    on protect (regression: it used to assume the message was embedded 1:1)."""
    # 64x64x3 = 12288 elements; at n_lsb=8, raw capacity is 12288 bytes, but a
    # message anywhere near that size costs ~4/3x once base64'd and will not
    # actually fit once framed.
    r = client.post(
        "/api/capacity",
        files={"cover": ("t.png", png_rgb, "image/png")},
        data={"n_lsb": "8", "payload_bytes": "11000"},
    )
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["fits"] is False, report

    # A message that fits even after base64 inflation should still say so.
    r_small = client.post(
        "/api/capacity",
        files={"cover": ("t.png", png_rgb, "image/png")},
        data={"n_lsb": "8", "payload_bytes": "100"},
    )
    assert r_small.status_code == 200, r_small.text
    assert r_small.json()["fits"] is True


@pytest.mark.parametrize("kind", ["image", "audio"])
def test_protect_then_verify_roundtrip(kind: str, png_rgb: bytes, wav_16_mono: bytes) -> None:
    """The headline test: protect a cover through the API, download the stego
    file, verify it, and expect Authentic.
    """
    from stego_core import signing

    private_pem, public_pem = signing.generate_keypair()

    if kind == "image":
        cover_bytes, filename, content_type = png_rgb, "cover.png", "image/png"
    else:
        cover_bytes, filename, content_type = wav_16_mono, "cover.wav", "audio/wav"

    protect_resp = client.post(
        "/api/protect",
        files={
            "cover": (filename, cover_bytes, content_type),
            "private_key_pem": ("key.pem", private_pem, "application/x-pem-file"),
        },
        data={
            "message_text": "This is the hidden verification payload.",
            "message_mime": "text/plain",
            "n_lsb": "2",
            "media_id": f"roundtrip-{kind}",
            "start_mode": "derived",
            "passphrase": "correct horse battery staple",
        },
    )
    assert protect_resp.status_code == 200, protect_resp.text
    protect_result = protect_resp.json()

    download_resp = client.get(protect_result["stego"]["download_url"])
    assert download_resp.status_code == 200
    stego_bytes = download_resp.content

    verify_resp = client.post(
        "/api/verify",
        files={
            "stego": (f"cover.stego.{filename.split('.')[-1]}", stego_bytes, content_type),
            "public_key_pem": ("key.pub.pem", public_pem, "application/x-pem-file"),
        },
        data={
            "n_lsb": "2",
            "media_id": f"roundtrip-{kind}",
            "start_mode": "derived",
            "passphrase": "correct horse battery staple",
        },
    )
    assert verify_resp.status_code == 200, verify_resp.text
    verify_result = verify_resp.json()
    assert verify_result["verdict"] == "Authentic", verify_result["reasons"]
    assert verify_result["hash_match"] is True
    assert verify_result["signature_valid"] is True
