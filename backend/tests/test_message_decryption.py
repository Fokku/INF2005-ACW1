"""Exercise the public protect/download/verify contract, including locked messages."""

import pytest
from fastapi.testclient import TestClient

from app import storage
from app.main import app
from stego_core import signing


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("mode", ["explicit", "derived"])
@pytest.mark.parametrize("state", ["plain", "correct", "missing", "wrong"])
@pytest.mark.parametrize("mime", ["text/plain", "application/octet-stream"])
def test_message_delivery(kind, mode, state, mime, png_rgb, wav_16_mono, tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)
    client = TestClient(app)
    private, public = signing.generate_keypair()
    cover = png_rgb if kind == "image" else wav_16_mono
    suffix = "png" if kind == "image" else "wav"
    message = "Release approved — 隐藏消息".encode() if mime == "text/plain" else bytes(range(256))
    settings = {
        "media_id": "decryption-regression",
        "n_lsb": "2",
        "start_mode": mode,
        "explicit_start": "64",
        "passphrase": "correct-demo-secret",
    }
    response = client.post(
        "/api/protect",
        files={
            "cover": (f"cover.{suffix}", cover),
            "message": ("message.bin", message),
            "private_key_pem": ("private.pem", private),
        },
        data={**settings, "message_mime": mime, "encrypt_message": str(state != "plain").lower()},
    )
    assert response.status_code == 200, response.text
    stego = client.get(response.json()["stego"]["download_url"])
    assert stego.status_code == 200
    receiver = dict(settings)
    if state == "missing":
        receiver.pop("passphrase")
    elif state == "wrong":
        receiver["passphrase"] = "wrong-secret"
    response = client.post(
        "/api/verify",
        files={"stego": (f"stego.{suffix}", stego.content), "public_key_pem": ("public.pem", public)},
        data=receiver,
    )
    assert response.status_code == 200, response.text
    report = response.json()
    if mode == "derived" and state in ("missing", "wrong"):
        assert report["verdict"] != "Authentic"
        assert report["payload"] is None
        return
    assert report["verdict"] == "Authentic"
    assert report["signature_valid"] is True and report["hash_match"] is True
    payload = report["payload"]
    assert payload["message_encrypted"] is (state != "plain")
    assert payload["message_decrypted"] is (state == "correct")
    if state in ("missing", "wrong"):
        assert payload["decryption_error"]
        assert payload["message_text"] is None
        assert payload["message_file"] is None
    else:
        assert payload["decryption_error"] is None
        if mime == "text/plain":
            assert payload["message_text"] == message.decode()
        downloaded = client.get(payload["message_file"]["download_url"])
        assert downloaded.status_code == 200
        assert downloaded.content == message
