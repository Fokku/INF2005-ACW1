"""
What this produces, all under samples/:
  image/original/cover.png   512x512 RGB, deterministic (fixed RNG seed)
  audio/original/cover.wav   16-bit mono PCM, 5 seconds, deterministic
  image/stego/*.stego.png    the cover with a signed payload embedded
  audio/stego/*.stego.wav    same, for audio
  image/tampered/*.png       a stego file with a bit-flip attack applied
  audio/tampered/*.wav       same, for audio
  payloads/*.txt             the exact plaintext of each embedded message

It also (re)creates a demo key pair under keys/ if one is not already there
(keys/private/ is gitignored; keys/public/*.pem is committed), and writes
evidence/logs/sample-manifest.json: every case, the exact settings used, and
the verdict `pipeline.verify` actually returned when re-run just now -- copy
that table straight into README.md's "Expected outputs" section.
"""

from __future__ import annotations

import io
import json
import sys
import wave
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from stego_core import attacks, pipeline, signing  # noqa: E402

SAMPLES = ROOT / "samples"
KEYS_PUBLIC = ROOT / "keys" / "public"
KEYS_PRIVATE = ROOT / "keys" / "private"
LOGS = ROOT / "evidence" / "logs"

TEAM_ID = "P6-8"
N_LSB = 2
EXPLICIT_START = 128
PASSPHRASE = "acw1-demo-passphrase-2026"  # demo-only; documented here and in README

CUSTOM_MESSAGE = (
    "CONFIDENTIAL — ACW1 demo release note: this custom payload is a synthetic, "
    "team-authored message used only to demonstrate AES-256-GCM confidentiality "
    "layered on top of the signed integrity payload. It contains no real "
    "personal or confidential information."
)


def _spec_text() -> str:
    return (ROOT / "docs" / "spec" / "INF2005-ACW1-spec-v5.md").read_text(encoding="utf-8")


def _short_message() -> str:
    """Learning Outcome 1, quoted verbatim from the spec (spec Section 5)."""
    outcomes = _spec_text().split("## 3. Learning Outcomes", 1)[1].split("## 4.", 1)[0]
    first = next(line for line in outcomes.splitlines() if line.strip().startswith("- 1."))
    return first.split(".", 1)[-1].strip()  # split once, on "1." -- keep the sentence's own trailing period


def _large_message() -> str:
    """The Project Overview paragraph, quoted verbatim from the spec (spec Section 5)."""
    return _spec_text().split("## 2. Project Overview", 1)[1].split("## 3.", 1)[0].strip()


def _load_or_create_keys() -> tuple[bytes, bytes]:
    priv_path = KEYS_PRIVATE / "team_ed25519.pem"
    pub_path = KEYS_PUBLIC / "team_ed25519.pub.pem"
    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()
    private_pem, public_pem = signing.generate_keypair()
    KEYS_PRIVATE.mkdir(parents=True, exist_ok=True)
    KEYS_PUBLIC.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    print(f"generated a new demo key pair: {pub_path}")
    return private_pem, public_pem


def _load_or_create_image_cover() -> bytes:
    path = SAMPLES / "image" / "original" / "cover.png"
    if path.exists():
        return path.read_bytes()
    rng = np.random.default_rng(20260908)  # fixed seed: same cover every first run
    arr = rng.integers(0, 256, (512, 512, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, mode="RGB").save(buf, format="PNG")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def _load_or_create_audio_cover() -> bytes:
    path = SAMPLES / "audio" / "original" / "cover.wav"
    if path.exists():
        return path.read_bytes()
    rng = np.random.default_rng(20260908)
    rate = 44100
    frames = rate * 5  # 5 seconds, spec-required minimum
    t = np.arange(frames)
    tone = 8000 * np.sin(2 * np.pi * 440 * t / rate)
    noise = rng.integers(-200, 200, frames)
    samples = np.clip(tone + noise, -32768, 32767).astype(np.int16)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(samples.tobytes())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def _protect(cover_bytes: bytes, cover_kind: str, message: bytes, media_id: str, private_pem: bytes,
             encrypt: bool = False, derived: bool = False) -> pipeline.ProtectOutcome:
    return pipeline.protect(
        pipeline.ProtectOptions(
            cover_bytes=cover_bytes,
            cover_kind=cover_kind,
            message=message,
            message_mime="text/plain",
            n_lsb=N_LSB,
            media_id=media_id,
            metadata={"team": TEAM_ID, "purpose": "ACW1 sample evidence"},
            private_key_pem=private_pem,
            passphrase=PASSPHRASE if (encrypt or derived) else None,
            explicit_start=None if derived else EXPLICIT_START,
            encrypt_message=encrypt,
        )
    )


def _small_untouched_cover(kind: str, ext: str) -> tuple[bytes, Path]:
    """A cover small enough for scan_for_magic to search exhaustively, so
    verifying it (never protected) reports Payload Missing rather than the
    Cannot Verify an incomplete search over a large cover would report."""
    path = SAMPLES / kind / "original" / f"cover-empty.{ext}"
    if path.exists():
        return path.read_bytes(), path
    if kind == "image":
        rng = np.random.default_rng(1)
        buf = io.BytesIO()
        Image.fromarray(rng.integers(0, 256, (32, 32, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
        data = buf.getvalue()
    else:
        rng = np.random.default_rng(1)
        samples = rng.integers(-500, 500, 4000).astype(np.int16)
        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(8000)
            w.writeframes(samples.tobytes())
        data = buf.getvalue()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data, path


def _verify(stego_bytes: bytes, cover_kind: str, media_id: str, public_pem: bytes, **overrides):
    fields = {
        "stego_bytes": stego_bytes,
        "cover_kind": cover_kind,
        "public_key_pem": public_pem,
        "n_lsb": N_LSB,
        "media_id": media_id,
        "explicit_start": EXPLICIT_START,
    }
    fields.update(overrides)
    return pipeline.verify(pipeline.VerifyOptions(**fields))


def main() -> int:
    private_pem, public_pem = _load_or_create_keys()
    _, wrong_public_pem = signing.generate_keypair()

    covers = {"image": (_load_or_create_image_cover(), "png"), "audio": (_load_or_create_audio_cover(), "wav")}
    messages = {"short": (_short_message(), False), "large": (_large_message(), False), "custom": (CUSTOM_MESSAGE, True)}

    payload_dir = SAMPLES / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)
    for size, (text, _) in messages.items():
        (payload_dir / f"{size}.txt").write_text(text, encoding="utf-8")

    manifest: list[dict] = []

    def record(case: str, file_path: Path | None, result: pipeline.VerifyOutcome, **settings) -> None:
        manifest.append(
            {
                "case": case,
                "file": str(file_path.relative_to(ROOT)) if file_path else None,
                "settings": settings,
                "verdict": result.verdict.value,
                "reasons": result.reasons,
            }
        )
        status = "OK" if settings.get("expected", result.verdict.value) == result.verdict.value else "MISMATCH"
        print(f"[{status}] {case}: {result.verdict.value}")

    for kind, (cover_bytes, ext) in covers.items():
        stego_by_size: dict[str, tuple[bytes, str]] = {}

        for size, (text, encrypt) in messages.items():
            media_id = f"{TEAM_ID}-{kind}-{size}"
            outcome = _protect(cover_bytes, kind, text.encode("utf-8"), media_id, private_pem, encrypt)
            stego_path = SAMPLES / kind / "stego" / f"{kind}-{size}.stego.{ext}"
            stego_path.parent.mkdir(parents=True, exist_ok=True)
            stego_path.write_bytes(outcome.stego_bytes)
            stego_by_size[size] = (outcome.stego_bytes, media_id)

            result = _verify(outcome.stego_bytes, kind, media_id, public_pem, passphrase=PASSPHRASE if encrypt else None)
            record(
                f"{kind}-{size}-authentic", stego_path, result, expected="Authentic",
                media_id=media_id, n_lsb=N_LSB, start_mode="explicit", explicit_start=EXPLICIT_START,
                passphrase=PASSPHRASE if encrypt else None, message_bytes=len(text.encode("utf-8")),
            )

        # Negative cases (spec Section 5 / workstream H): one representative
        # message (the short one) driving each required failure mode.
        short_stego, short_media_id = stego_by_size["short"]

        tampered = attacks.flip_bits(short_stego, kind)
        tampered_path = SAMPLES / kind / "tampered" / f"{kind}-flip_bits.{ext}"
        tampered_path.parent.mkdir(parents=True, exist_ok=True)
        tampered_path.write_bytes(tampered)
        result = _verify(tampered, kind, short_media_id, public_pem)
        record(f"{kind}-tampered", tampered_path, result, expected="Tampered",
               media_id=short_media_id, n_lsb=N_LSB, explicit_start=EXPLICIT_START, attack="flip_bits")

        result = _verify(short_stego, kind, short_media_id, wrong_public_pem)
        record(f"{kind}-signature-invalid", None, result, expected="Signature Invalid",
               media_id=short_media_id, n_lsb=N_LSB, explicit_start=EXPLICIT_START, public_key="wrong (mismatched) public key")

        # A cover the size of the hero sample (512x512 / 5s) is too large for
        # scan_for_magic to search exhaustively (location.MAX_SCAN_POSITIONS),
        # so verifying IT unprotected correctly reports Cannot Verify (see
        # test_attacks.py::test_large_cover_attack_reports_incomplete_search),
        # not Payload Missing. To actually demonstrate Payload Missing, use a
        # small untouched cover the scan CAN finish searching.
        empty_bytes, empty_path = _small_untouched_cover(kind, ext)
        result = _verify(empty_bytes, kind, short_media_id, public_pem)
        record(f"{kind}-payload-missing", empty_path, result, expected="Payload Missing",
               media_id=short_media_id, n_lsb=N_LSB, explicit_start=EXPLICIT_START,
               note="a small untouched cover -- never protected, so no payload is found anywhere")

        # Wrong Start Location specifically requires DERIVED mode: only there
        # does the passphrase determine WHERE the frame is read from. (With
        # an explicit offset, a wrong passphrase only breaks message
        # decryption for display -- it never changes the verdict, since the
        # frame is still found at the offset both sides agreed on.)
        derived_outcome = _protect(cover_bytes, kind, b"derived start location demo", f"{TEAM_ID}-{kind}-derived", private_pem, derived=True)
        derived_path = SAMPLES / kind / "stego" / f"{kind}-derived-start.stego.{ext}"
        derived_path.write_bytes(derived_outcome.stego_bytes)
        result = _verify(derived_outcome.stego_bytes, kind, f"{TEAM_ID}-{kind}-derived", public_pem,
                          passphrase="wrong-passphrase-entirely", explicit_start=None)
        record(f"{kind}-wrong-start-location", derived_path, result, expected="Wrong Start Location",
               media_id=f"{TEAM_ID}-{kind}-derived", n_lsb=N_LSB, start_mode="derived",
               correct_passphrase=PASSPHRASE, passphrase_used="wrong-passphrase-entirely",
               note="right key, DERIVED start, WRONG passphrase -- the verifier looks in the wrong place entirely")

        from stego_core.errors import CapacityError

        try:
            _protect(cover_bytes, kind, b"X" * 10_000_000, f"{TEAM_ID}-{kind}-oversized", private_pem)
            manifest.append({"case": f"{kind}-oversized", "verdict": "DID NOT RAISE (BUG)"})
            print(f"[MISMATCH] {kind}-oversized: expected CapacityError, none raised")
        except CapacityError as exc:
            manifest.append({"case": f"{kind}-oversized", "settings": {"n_lsb": N_LSB}, "error": "CapacityError", "detail": str(exc)})
            print(f"[OK] {kind}-oversized: CapacityError raised as expected ({exc})")

    LOGS.mkdir(parents=True, exist_ok=True)
    manifest_path = LOGS / "sample-manifest.json"
    manifest_path.write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(), "cases": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote {manifest_path.relative_to(ROOT)} ({len(manifest)} cases)")
    print("Copy this table into README.md's 'Expected outputs' section.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
