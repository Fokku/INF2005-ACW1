"""Exercise real protect -> attack -> verify flows, including API downloads."""

import io
import wave

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from test_video_codec import _build_avi

from app import storage
from app.main import app
from stego_core import attacks, container, pipeline, signing
from stego_core.errors import CapacityError, FrameError, UnsupportedCoverError
from stego_core.verdict import Verdict


@pytest.fixture(params=["image", "rgba", "audio8", "audio16", "stereo", "video"])
def media(request):
    rng = np.random.default_rng(51)
    variant = request.param
    if variant in ("image", "rgba"):
        buf = io.BytesIO()
        Image.fromarray(rng.integers(0, 256, (96, 96, 4 if variant == "rgba" else 3), dtype=np.uint8)).save(
            buf, format="PNG"
        )
        return "image", buf.getvalue()
    width = 1 if variant == "audio8" else 2
    channels = 2 if variant == "stereo" else 1
    samples = rng.integers(
        0, 256 if width == 1 else 65536, 16000 * channels, dtype=np.uint8 if width == 1 else np.uint16
    )
    if variant == "video":
        return "video", _build_avi(samples.tobytes())
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav:
        wav.setparams((channels, width, 8000, 0, "NONE", "not compressed"))
        wav.writeframes(samples.tobytes())
    return "audio", buf.getvalue()


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("attack", ["lsb_scrub", "reencode"])
def test_large_cover_attack_reports_incomplete_search(kind, attack, keys):
    """Large real-world covers cannot be declared empty after a bounded search."""
    buf = io.BytesIO()
    if kind == "image":
        Image.new("RGBA", (512, 512), (120, 160, 200, 255)).save(buf, format="PNG")
    else:
        with wave.open(buf, "wb") as wav:
            wav.setparams((1, 2, 44100, 0, "NONE", "not compressed"))
            wav.writeframes(np.zeros(220500, dtype=np.int16).tobytes())
    protected = protect(buf.getvalue(), kind, keys, start=0)
    assert verify(protected.stego_bytes, kind, keys, start=0).verdict == Verdict.AUTHENTIC
    damaged = (
        attacks.lsb_scrub(protected.stego_bytes, kind, 2)
        if attack == "lsb_scrub"
        else attacks.reencode(protected.stego_bytes, kind)
    )
    result = verify(damaged, kind, keys, start=0)
    assert result.verdict == Verdict.CANNOT_VERIFY
    assert any("remaining locations were not searched" in reason for reason in result.reasons)
    assert result.signature_valid is None
    assert result.media_hash_recomputed is None


def protect(data, kind, keys, n_lsb=2, start=7):
    return pipeline.protect(
        pipeline.ProtectOptions(
            cover_bytes=data,
            cover_kind=kind,
            message=b"Section F evidence",
            message_mime="text/plain",
            n_lsb=n_lsb,
            media_id="section-f",
            metadata={},
            private_key_pem=keys[0],
            explicit_start=start,
        )
    )


def verify(data, kind, keys, n_lsb=2, start=7):
    return pipeline.verify(
        pipeline.VerifyOptions(data, kind, keys[1], n_lsb, "section-f", explicit_start=start)
    )


@pytest.mark.parametrize("attack", list(attacks.EXPECTED))
def test_attack_verdict(media, keys, attack):
    kind, original = media
    protected = protect(original, kind, keys)
    assert verify(protected.stego_bytes, kind, keys).verdict == Verdict.AUTHENTIC
    if attack == "crop" and kind == "video":
        with pytest.raises(UnsupportedCoverError):
            attacks.crop(protected.stego_bytes, kind)
        return
    if attack == "replay":
        target = attacks.flip_bits(original, kind)
        damaged = attacks.replay(protected.stego_bytes, target, kind, 2, 7)
    elif attack == "corrupt_payload":
        damaged = attacks.corrupt_payload(protected.stego_bytes, kind, 2, 7)
    elif attack == "lsb_scrub":
        damaged = attacks.lsb_scrub(protected.stego_bytes, kind, 2)
    else:
        damaged = getattr(attacks, attack)(protected.stego_bytes, kind)
    result = verify(damaged, kind, keys)
    assert result.verdict == attacks.EXPECTED[attack], result.reasons
    if attack in ("flip_bits", "crop", "replay"):
        assert result.signature_valid is True
        assert result.media_hash_embedded != result.media_hash_recomputed
    if attack == "corrupt_payload":
        assert any("CRC" in reason for reason in result.reasons)
        assert result.signature_valid is None
        assert result.media_hash_recomputed is None
    if kind == "video":
        before = attacks._load(protected.stego_bytes, kind)
        after = attacks._load(damaged, kind)
        assert before.chunk_spans == after.chunk_spans
        a, b = bytearray(protected.stego_bytes), bytearray(damaged)
        for pos, size in before.chunk_spans:
            a[pos : pos + size] = b"\0" * size
            b[pos : pos + size] = b"\0" * size
        assert a == b  # Container and video bytes are untouched.


@pytest.mark.parametrize("n_lsb", range(1, 9))
def test_frame_attacks_all_lsb_counts(media, keys, n_lsb):
    kind, original = media
    protected = protect(original, kind, keys, n_lsb)
    changed = attacks.corrupt_payload(protected.stego_bytes, kind, n_lsb, 7)
    assert verify(changed, kind, keys, n_lsb).verdict == Verdict.TAMPERED
    scrubbed = attacks.lsb_scrub(protected.stego_bytes, kind, n_lsb)
    assert verify(scrubbed, kind, keys, n_lsb).verdict == Verdict.PAYLOAD_MISSING
    before = attacks._load(protected.stego_bytes, kind).elements
    after = attacks._load(changed, kind).elements
    old_frame = attacks._frame(before, n_lsb, 7)
    from stego_core import lsb

    new_frame = lsb.bits_to_bytes(lsb.extract_bits(after, 7, len(old_frame) * 8, n_lsb))
    assert old_frame[: container.HEADER_SIZE] == new_frame[: container.HEADER_SIZE]
    assert old_frame[-4:] == new_frame[-4:]
    assert np.count_nonzero(lsb.bytes_to_bits(old_frame) ^ lsb.bytes_to_bits(new_frame)) == 1


def test_rejections(png_rgb, keys):
    protected = protect(png_rgb, "image", keys)
    with pytest.raises(ValueError, match="differ"):
        attacks.replay(protected.stego_bytes, png_rgb, "image", 2, 7)
    for fraction in (0, 1, -1, float("nan")):
        with pytest.raises(ValueError):
            attacks.crop(png_rgb, "image", fraction)
    with pytest.raises(ValueError):
        attacks.flip_bits(png_rgb, "image", (-1, 5))
    with pytest.raises(ValueError):
        attacks.lsb_scrub(png_rgb, "image", 9)
    with pytest.raises(FrameError):
        attacks.corrupt_payload(png_rgb, "image", 2, 7)
    with pytest.raises(FrameError):
        attacks.corrupt_payload(protected.stego_bytes, "image", 2, 10**9)
    small = io.BytesIO()
    Image.new("RGB", (2, 2)).save(small, format="PNG")
    with pytest.raises(CapacityError):
        attacks.replay(protected.stego_bytes, small.getvalue(), "image", 2, 7)


@pytest.mark.parametrize("attack", list(attacks.EXPECTED))
def test_api_download_and_verify(media, keys, attack, tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)
    kind, original = media
    suffix = {"image": "png", "audio": "wav", "video": "avi"}[kind]
    protected = protect(original, kind, keys)
    files = {"stego": (f"demo.stego.{suffix}", protected.stego_bytes)}
    if attack == "replay":
        files["other_cover"] = (f"target.{suffix}", attacks.flip_bits(original, kind))
    client = TestClient(app)
    response = client.post("/api/attack", files=files, data={"attack": attack, "n_lsb": 2, "start_offset": 7})
    if kind == "video" and attack == "crop":
        assert response.status_code == 415
        return
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["output"]["filename"] == f"demo.stego.{attack}.{suffix}"
    download = client.get(result["output"]["download_url"])
    assert download.status_code == 200
    assert verify(download.content, kind, keys).verdict.value == result["expected_verdict"]


@pytest.mark.parametrize(
    "data,status",
    [
        ({"attack": "replay"}, 400),
        ({"attack": "flip_bits", "n_lsb": 8}, 400),
        ({"attack": "lsb_scrub", "n_lsb": 9}, 422),
        ({"attack": "corrupt_payload", "start_offset": -1}, 422),
        ({"attack": "unknown"}, 422),
    ],
)
def test_api_validation(png_rgb, data, status):
    response = TestClient(app).post("/api/attack", files={"stego": ("a.png", png_rgb)}, data=data)
    assert response.status_code == status


def test_crop_can_destroy_frame(png_rgb, keys):
    protected = protect(png_rgb, "image", keys, start=10000)
    damaged = attacks.crop(protected.stego_bytes, "image", fraction=0.25)
    # Looking at a valid early offset in the retained rows cannot find the removed frame.
    assert verify(damaged, "image", keys, start=0).verdict == Verdict.PAYLOAD_MISSING


def test_derived_crop_needs_original_offset(png_rgb, keys):
    opts = pipeline.ProtectOptions(
        png_rgb, "image", b"crop", "text/plain", 2, "section-f", {}, keys[0], passphrase="section f"
    )
    protected = pipeline.protect(opts)
    damaged = attacks.crop(protected.stego_bytes, "image")
    explicit = verify(damaged, "image", keys, start=protected.start_offset)
    assert explicit.verdict == Verdict.TAMPERED
    derived = pipeline.verify(
        pipeline.VerifyOptions(damaged, "image", keys[1], 2, "section-f", passphrase="section f")
    )
    assert derived.verdict in (Verdict.WRONG_START_LOCATION, Verdict.TAMPERED)


def test_replay_preserves_signature_and_frame(media, keys):
    kind, original = media
    protected = protect(original, kind, keys, n_lsb=3)
    target = attacks.flip_bits(original, kind)
    result = attacks.replay(protected.stego_bytes, target, kind, 3, 7)
    assert attacks._frame(attacks._load(result, kind).elements, 3, 7) == attacks._frame(
        attacks._load(protected.stego_bytes, kind).elements, 3, 7
    )
    assert verify(result, kind, keys, n_lsb=3).signature_valid is True


def test_api_bad_uploads(png_rgb, wav_16_mono):
    client = TestClient(app)
    for files, data, status in [
        ({"stego": ("x.txt", b"invalid")}, {"attack": "flip_bits"}, 415),
        ({"stego": ("x.png", b"invalid")}, {"attack": "lsb_scrub"}, 415),
        ({"stego": ("x.png", png_rgb), "other_cover": ("x.wav", wav_16_mono)}, {"attack": "replay"}, 400),
        ({"stego": ("x.png", png_rgb)}, {"attack": "corrupt_payload", "start_offset": 999999}, 400),
    ]:
        response = client.post("/api/attack", files=files, data=data)
        assert response.status_code == status, response.text
