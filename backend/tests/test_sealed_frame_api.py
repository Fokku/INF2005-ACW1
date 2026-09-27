"""API tests for sealed frames and the signer hand-off fields, along the GUI's route.

Contract under test (see backend/app/schemas.py):
  POST /api/protect   seal_frame: bool = False  -> ProtectResult.sealed,
                      .signer_public_key_pem, .signer_fingerprint
  POST /api/verify    no new inputs             -> VerifyReport.sealed (True / False / None)
  POST /api/capacity  seal_frame: bool = False  -> overhead, max message and fits include 12 bytes
"""

from __future__ import annotations

import io

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app import storage
from app.main import app
from stego_core import pipeline, sealing, signing

client = TestClient(app)

PASSPHRASE = "sealed api passphrase"
SETTINGS = {"n_lsb": "2", "media_id": "sealed-api", "start_mode": "explicit", "explicit_start": "137"}


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


@pytest.fixture(scope="module")
def cover_png() -> bytes:
    rng = np.random.default_rng(21)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (96, 96, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


def _protect(cover: bytes, private_pem: bytes, **data) -> dict:
    r = client.post(
        "/api/protect",
        files={
            "cover": ("cover.png", cover, "image/png"),
            "private_key_pem": ("key.pem", private_pem, "application/x-pem-file"),
        },
        data={**SETTINGS, "message_text": "sealed through the API", **data},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _download(ref: dict) -> bytes:
    r = client.get(ref["download_url"])
    assert r.status_code == 200
    return r.content


def _verify(stego: bytes, public_pem: bytes, **data) -> dict:
    r = client.post(
        "/api/verify",
        files={
            "stego": ("stego.png", stego, "image/png"),
            "public_key_pem": ("public.pem", public_pem, "application/x-pem-file"),
        },
        data={**SETTINGS, **data},
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("start_mode", ["explicit", "derived"])
def test_sealed_protect_and_verify_report_sealed(cover_png, keys, start_mode):
    result = _protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame="true", start_mode=start_mode)
    assert result["sealed"] is True
    report = _verify(_download(result["stego"]), keys[1], passphrase=PASSPHRASE, start_mode=start_mode)
    assert report["verdict"] == "Authentic", report["reasons"]
    assert report["sealed"] is True
    assert report["payload_found"] is True
    assert report["start_offset_used"] == result["start_offset"]
    assert report["payload"]["message_text"] == "sealed through the API"


def test_unsealed_protect_and_verify_report_plaintext(cover_png, keys):
    result = _protect(cover_png, keys[0])
    assert result["sealed"] is False
    report = _verify(_download(result["stego"]), keys[1])
    assert report["verdict"] == "Authentic"
    assert report["sealed"] is False


def test_sealed_frame_bytes_include_the_nonce(cover_png, keys):
    sealed = _protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame="true")
    plain = _protect(cover_png, keys[0], passphrase=PASSPHRASE)
    # Same message and metadata; the payload JSON has the same length both times.
    assert sealed["frame_bytes"] == plain["frame_bytes"] + sealing.NONCE_SIZE


def test_wrong_passphrase_on_a_sealed_file_is_not_found(cover_png, keys):
    stego = _download(_protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame="true")["stego"])
    report = _verify(stego, keys[1], passphrase="not the passphrase")
    assert report["verdict"] in ("Payload Missing", "Cannot Verify")
    assert report["sealed"] is None
    assert report["payload_found"] is False
    assert report["payload"] is None
    assert pipeline.SEALED_NOT_FOUND_HINT in report["reasons"]


def test_wrong_public_key_on_a_sealed_file_is_signature_invalid(cover_png, keys):
    stego = _download(_protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame="true")["stego"])
    report = _verify(stego, signing.generate_keypair()[1], passphrase=PASSPHRASE)
    assert report["verdict"] == "Signature Invalid"
    assert report["sealed"] is True


@pytest.mark.parametrize("passphrase", [None, ""])
def test_seal_without_passphrase_is_a_400(cover_png, keys, passphrase):
    data = {**SETTINGS, "message_text": "x", "seal_frame": "true"}
    if passphrase is not None:
        data["passphrase"] = passphrase
    r = client.post(
        "/api/protect",
        files={
            "cover": ("cover.png", cover_png, "image/png"),
            "private_key_pem": ("key.pem", keys[0], "application/x-pem-file"),
        },
        data=data,
    )
    assert r.status_code == 400
    assert "passphrase" in r.json()["detail"]


def test_sealed_file_through_the_attack_lab(cover_png, keys):
    """flip_bits needs no frame knowledge -> Tampered. corrupt_payload reads a
    plaintext header, which a sealed file does not have -> a clear 400."""
    stego = _download(_protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame="true")["stego"])
    files = {"stego": ("stego.png", stego, "image/png")}
    flipped = client.post("/api/attack", files=files, data={"attack": "flip_bits", "n_lsb": "2"})
    assert flipped.status_code == 200, flipped.text
    report = _verify(_download(flipped.json()["output"]), keys[1], passphrase=PASSPHRASE)
    assert report["verdict"] == "Tampered"
    assert report["sealed"] is True

    corrupt = client.post(
        "/api/attack", files=files, data={"attack": "corrupt_payload", "n_lsb": "2", "start_offset": "137"}
    )
    assert corrupt.status_code == 400
    assert "sealed frame" in corrupt.json()["detail"]


def test_capacity_seal_frame_adds_the_nonce(cover_png):
    def capacity(**data) -> dict:
        r = client.post(
            "/api/capacity",
            files={"cover": ("cover.png", cover_png, "image/png")},
            data={"n_lsb": "1", **data},
        )
        assert r.status_code == 200, r.text
        return r.json()

    plain, sealed = capacity(), capacity(seal_frame="true")
    assert sealed["frame_overhead_bytes"] == plain["frame_overhead_bytes"] + sealing.SEAL_OVERHEAD
    assert sealed["max_message_bytes"] < plain["max_message_bytes"]

    # The largest message that fits unsealed stops fitting once sealed. (Computed
    # from the fits rule, base64 rounded up, rather than max_message_bytes.)
    fitting = (plain["capacity_bytes"] - plain["frame_overhead_bytes"]) // 4 * 3
    assert capacity(payload_bytes=str(fitting))["fits"] is True
    sealed_at_limit = capacity(payload_bytes=str(fitting), seal_frame="true")
    assert sealed_at_limit["fits"] is False
    assert sealed_at_limit["frame_overhead_bytes"] == (
        capacity(payload_bytes=str(fitting))["frame_overhead_bytes"] + sealing.SEAL_OVERHEAD
    )


def test_capacity_seal_frame_is_counted_per_copy(cover_png):
    def report(redundancy: int, seal: bool) -> dict:
        r = client.post(
            "/api/capacity",
            files={"cover": ("cover.png", cover_png, "image/png")},
            data={
                "n_lsb": "1",
                "payload_bytes": "100",
                "redundancy": str(redundancy),
                "seal_frame": "true" if seal else "false",
            },
        )
        assert r.status_code == 200, r.text
        return r.json()

    sealed, plain = report(3, True), report(3, False)
    assert sealed["max_message_bytes"] < plain["max_message_bytes"]
    assert sealed["frame_overhead_bytes"] == plain["frame_overhead_bytes"] + sealing.SEAL_OVERHEAD


# --------------------------------------------------------------------------- #
# Signer hand-off fields on ProtectResult
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seal", ["false", "true"])
def test_protect_returns_the_signer_public_key_and_fingerprint(cover_png, keys, seal):
    result = _protect(cover_png, keys[0], passphrase=PASSPHRASE, seal_frame=seal)
    assert result["signer_public_key_pem"] == keys[1].decode("ascii")
    assert result["signer_fingerprint"] == signing.fingerprint(keys[1])
    # Party B can verify with exactly the PEM that party A was shown.
    report = _verify(
        _download(result["stego"]), result["signer_public_key_pem"].encode("ascii"), passphrase=PASSPHRASE
    )
    assert report["verdict"] == "Authentic"


def test_signer_fingerprint_matches_the_keys_tab(cover_png):
    """Same fingerprint the Keys tab shows for a generated pair."""
    generated = client.post("/api/keys/generate", params={"label": "sealed-api"})
    assert generated.status_code == 200, generated.text
    body = generated.json()
    private_pem = _download(body["private_key_file"])
    result = _protect(cover_png, private_pem)
    assert result["signer_fingerprint"] == body["key"]["fingerprint"]
    assert result["signer_public_key_pem"] == body["key"]["public_key_pem"]
