"""Generate FR10/FR11 API evidence; optionally verify actual received attachments.

Run with the repo's .venv Python. Uses temporary API storage and never saves a
private key. Output folders must be new to avoid overwriting curated evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tempfile
import wave
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app import storage
from app.main import app
from fastapi.testclient import TestClient
from stego_core import signing

PASSPHRASE = "FR11-demo-only-release-2026"
CUSTOM = (
    "CONFIDENTIAL DEMO — Kannon media-release approval: asset FR11 is approved "
    "for the coursework demonstration only. Internal reference KANNON-FR11-01. "
    "Synthetic content; no real personal or confidential information."
)


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def get_json(response, status=200):
    require(response.status_code == status, response.text)
    return response.json()


def download(client, ref):
    response = client.get(ref["download_url"])
    require(response.status_code == 200, response.text)
    require(digest(response.content) == ref["sha256"], "API download hash mismatch")
    return response.content


def verify(client, data, filename, public, media_id, offset=64, passphrase=None):
    fields = {
        "media_id": media_id,
        "n_lsb": "2",
        "start_mode": "explicit",
        "explicit_start": str(offset),
    }
    if passphrase:
        fields["passphrase"] = passphrase
    return get_json(
        client.post(
            "/api/verify",
            files={"stego": (filename, data), "public_key_pem": ("public.pem", public)},
            data=fields,
        )
    )


def recovered(client, report):
    payload = report["payload"]
    if payload["message_text"] is not None:
        return payload["message_text"].encode()
    return download(client, payload["message_file"])


def generate(client, output):
    spec = (ROOT / "docs/spec/INF2005-ACW1-spec-v5.md").read_text()
    overview = spec.split("## 2. Project Overview", 1)[1].split("## 3.", 1)[0].strip()
    messages = {
        "short": "Explain how steganography can be used to embed hidden verification data in image and audio cover objects.",
        "large": overview,
        "custom": CUSTOM,
    }
    private, public = signing.generate_keypair()
    _, wrong_public = signing.generate_keypair()
    (output / ".gitignore").write_text("!public.pem\n!wrong-public.pem\n")
    (output / "public.pem").write_bytes(public)
    (output / "wrong-public.pem").write_bytes(wrong_public)
    for name, text in messages.items():
        (output / f"message-{name}.txt").write_text(text)
    image_buffer = io.BytesIO()
    y, x = np.indices((256, 256))
    Image.fromarray(np.stack((x, y, (x + y) % 256), axis=-1).astype(np.uint8)).save(
        image_buffer, format="PNG"
    )
    audio_buffer = io.BytesIO()
    samples = (10000 * np.sin(2 * np.pi * 440 * np.arange(160000) / 32000)).astype(
        "<i2"
    )
    with wave.open(audio_buffer, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(32000)
        wav.writeframes(samples.tobytes())
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "Automated in-process FastAPI requests, not external transfer or GUI screenshots",
        "external_transfer": "PENDING",
        "checks": [],
        "attachments": [],
        "settings": {"n_lsb": 2, "start_mode": "explicit", "explicit_start": 64},
        "demo_passphrase": PASSPHRASE,
    }
    for kind, ext, cover in [
        ("image", "png", image_buffer.getvalue()),
        ("audio", "wav", audio_buffer.getvalue()),
    ]:
        (output / f"original.{ext}").write_bytes(cover)
        for size, text in messages.items():
            media_id = f"kannan-fr11-{kind}-{size}"
            fields = {
                "media_id": media_id,
                "message_text": text,
                "n_lsb": "2",
                "start_mode": "explicit",
                "explicit_start": "64",
                "metadata_json": json.dumps(
                    {"author": "Kannon", "purpose": "FR10/FR11 synthetic demonstration"}
                ),
                "encrypt_message": str(size == "custom").lower(),
            }
            if size == "custom":
                fields["passphrase"] = PASSPHRASE
            files = {
                "cover": (f"original.{ext}", cover),
                "private_key_pem": ("private.pem", private),
            }
            protected = get_json(client.post("/api/protect", files=files, data=fields))
            stego = download(client, protected["stego"])
            name = f"{kind}-{size}.stego.{ext}"
            (output / name).write_bytes(stego)
            result = verify(
                client,
                stego,
                name,
                public,
                media_id,
                passphrase=fields.get("passphrase"),
            )
            require(
                result["verdict"] == "Authentic"
                and result["signature_valid"] is True
                and result["hash_match"] is True,
                result,
            )
            require(
                recovered(client, result) == text.encode(), "Recovered message differs"
            )
            record = {
                "case": f"{kind}-{size}",
                "message_bytes": len(text.encode()),
                "frame_bytes": protected["frame_bytes"],
                "report": result,
                "message_exact": True,
            }
            if size == "custom":
                no_secret = verify(client, stego, name, public, media_id)
                wrong_secret = verify(
                    client,
                    stego,
                    name,
                    public,
                    media_id,
                    passphrase="wrong-demo-passphrase",
                )
                require(no_secret["payload"]["message_encrypted"] is True, no_secret)
                require(
                    recovered(client, no_secret) != text.encode(),
                    "Plaintext exposed without passphrase",
                )
                require(
                    recovered(client, wrong_secret) != text.encode(),
                    "Plaintext exposed with wrong passphrase",
                )
                record["encryption_checks"] = {
                    "correct_secret_recovers_exact_message": True,
                    "absent_and_wrong_secret_do_not_recover_plaintext": True,
                }
                report["attachments"].append(
                    {
                        "filename": name,
                        "sha256": digest(stego),
                        "media_id": media_id,
                        "expected_message_sha256": digest(text.encode()),
                    }
                )
            report["checks"].append(record)
            if size != "short":
                continue
            for label, public_key, offset in [
                ("Signature Invalid", wrong_public, 64),
                ("Wrong Start Location", public, 0),
                ("Cannot Verify", b"not a PEM key", 64),
            ]:
                negative = verify(client, stego, name, public_key, media_id, offset)
                require(negative["verdict"] == label, negative)
                report["checks"].append({"case": f"{kind}-{label}", "report": negative})
            for attack, expected in [
                ("flip_bits", "Tampered"),
                ("lsb_scrub", "Payload Missing"),
            ]:
                attacked = get_json(
                    client.post(
                        "/api/attack",
                        files={"stego": (name, stego)},
                        data={"attack": attack, "n_lsb": "2", "start_offset": "64"},
                    )
                )
                altered = download(client, attacked["output"])
                altered_name = f"{kind}-{attack}.{ext}"
                (output / altered_name).write_bytes(altered)
                negative = verify(client, altered, altered_name, public, media_id)
                require(negative["verdict"] == expected, negative)
                report["checks"].append(
                    {"case": f"{kind}-{attack}", "report": negative}
                )
            capacity = get_json(
                client.post(
                    "/api/capacity",
                    files={"cover": (f"original.{ext}", cover)},
                    data={"n_lsb": "2", "payload_bytes": "100000"},
                )
            )
            require(capacity["fits"] is False, capacity)
            oversized = get_json(
                client.post(
                    "/api/protect",
                    files=files,
                    data={**fields, "message_text": "X" * 100000},
                ),
                400,
            )
            require(oversized.get("error") == "capacity_exceeded", oversized)
            report["checks"].append(
                {
                    "case": f"{kind}-oversized",
                    "capacity": capacity,
                    "protect_error": oversized,
                }
            )
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"PASS: {len(report['checks'])} API cases. External transfer remains PENDING. Evidence: {output}"
    )


def receive(client, manifest_path, received, output):
    manifest = json.loads(manifest_path.read_text())
    attachments = manifest.get("attachments", [])
    require(
        len(attachments) == 2
        and {item.get("filename") for item in attachments}
        == {"image-custom.stego.png", "audio-custom.stego.wav"},
        "Manifest must list both expected PNG and WAV attachments exactly once",
    )
    require(
        manifest.get("settings")
        == {"n_lsb": 2, "start_mode": "explicit", "explicit_start": 64},
        "Manifest settings do not match this evidence runner",
    )
    public = (manifest_path.parent / "public.pem").read_bytes()
    records = []
    for attachment in attachments:
        path = received / attachment["filename"]
        data = path.read_bytes()
        require(digest(data) == attachment["sha256"], f"File hash differs: {path}")
        result = verify(
            client,
            data,
            path.name,
            public,
            attachment["media_id"],
            passphrase=manifest["demo_passphrase"],
        )
        require(
            result["verdict"] == "Authentic"
            and result["signature_valid"] is True
            and result["hash_match"] is True,
            result,
        )
        require(
            digest(recovered(client, result)) == attachment["expected_message_sha256"],
            "Message differs",
        )
        records.append(
            {
                "received_path": str(path.resolve()),
                "file_sha256": digest(data),
                "message_exact": True,
                "report": result,
            }
        )
    (output / "received-verification.json").write_text(
        json.dumps(
            {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "scope": "Checks local received files; email delivery must be evidenced separately",
                "checks": records,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: both received files match sender hashes, signatures, media hashes and messages."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--received-dir", type=Path)
    args = parser.parse_args()
    if bool(args.manifest) != bool(args.received_dir):
        parser.error("--manifest and --received-dir must be provided together")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory() as tmp:
        storage.OUT_DIR = Path(tmp)
        with TestClient(app) as client:
            if args.manifest:
                receive(client, args.manifest, args.received_dir, args.output)
            else:
                generate(client, args.output)


if __name__ == "__main__":
    main()
