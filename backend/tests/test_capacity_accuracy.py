"""/api/capacity must agree with what /api/protect then does.

Regression for a meter that showed green and a Protect that refused the
message: the capacity check guessed the signed JSON at a flat 300 bytes, and
ignored the start offset, the AES-GCM overhead and the redundancy rounding.
Every test here runs the REAL /api/protect with the same form fields it sent
to /api/capacity, and checks the two answers match:

  * a message of exactly `max_message_bytes` protects successfully;
  * one byte more is reported `fits: false`, and (where the start is known)
    Protect refuses it too;
  * in derived mode that holds for ANY passphrase, because the capacity check
    sizes for the latest start location.derive_start can pick;
  * across a sweep around the limit, `fits` and the GUI meter's own formula
    `(message + frame_overhead_bytes) * redundancy <= capacity_bytes` both
    predict Protect's outcome byte for byte.
"""

from __future__ import annotations

import io
import json
import wave
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image
from test_video_codec import _build_avi

from app import storage
from app.main import app
from app.routers import capacity as capacity_router
from stego_core import location, signing

client = TestClient(app)

# Non-ASCII and characters JSON has to escape, so the test catches any
# estimate that counts characters instead of the real UTF-8 JSON bytes.
MEDIA_ID = "封面-capacity.png"
METADATA_JSON = json.dumps(
    {"team": "INF2005 ACW1", "note": 'naïve "quoted" \\ ✓', "purpose": "boundary"}, ensure_ascii=False
)
PASSPHRASES = ["correct horse", "battery staple", "a", "Ω-passphrase", "tr0ub4dor&3"]
SAMPLE_COVER = Path(__file__).resolve().parents[2] / "samples" / "image" / "original" / "cover.png"


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)


@pytest.fixture(scope="module")
def private_pem() -> bytes:
    return signing.generate_keypair()[0]


def _png(height: int, width: int, seed: int) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (height, width, 3), dtype=np.uint8), mode="RGB").save(
        buf, format="PNG"
    )
    return buf.getvalue()


def _wav_stereo(frames: int, seed: int) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(rng.integers(-30000, 30000, size=frames * 2, dtype=np.int16).tobytes())
    return buf.getvalue()


def _avi(samples: int, seed: int) -> bytes:
    rng = np.random.default_rng(seed)
    pcm = rng.integers(-30000, 30000, size=samples, dtype=np.int16).tobytes()
    return _build_avi(pcm, channels=1, sample_width=2, sample_rate=8000, n_pcm_chunks=4)


COVERS = {
    "image": ("cover.png", _png(72, 88, seed=41)),
    "audio": ("cover.wav", _wav_stereo(6000, seed=42)),
    "video": ("cover.avi", _avi(9000, seed=43)),
}
IMAGE = COVERS["image"]


def _fields(**overrides) -> dict[str, str]:
    """Form fields sent to BOTH endpoints: the same settings, the same names."""
    return {"media_id": MEDIA_ID, "metadata_json": METADATA_JSON, **overrides}


def _capacity(cover: tuple[str, bytes], fields: dict[str, str], payload_bytes: int | None = None) -> dict:
    filename, data = cover
    form = dict(fields)
    if payload_bytes is not None:
        form["payload_bytes"] = str(payload_bytes)
    r = client.post("/api/capacity", files={"cover": (filename, data)}, data=form)
    assert r.status_code == 200, r.text
    return r.json()


def _protect(cover: tuple[str, bytes], fields: dict[str, str], message_len: int, private_pem: bytes):
    filename, data = cover
    return client.post(
        "/api/protect",
        files={"cover": (filename, data), "private_key_pem": ("team.pem", private_pem)},
        data={**fields, "message_text": "m" * message_len},
    )


def _meter_fits(report: dict, message_len: int) -> bool:
    """The comparison frontend/src/components/CapacityMeter.tsx makes."""
    used = (message_len + report["frame_overhead_bytes"]) * report["redundancy"]
    return used <= report["capacity_bytes"]


def _assert_refused_for_capacity(response) -> None:
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "capacity_exceeded", response.text


# --------------------------------------------------------------------------- #
# The advertised limit really protects, one byte more really does not
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("kind", "n_lsb", "explicit_start"),
    [("image", 1, 1024), ("image", 3, 7), ("audio", 2, 0), ("video", 4, 333)],
)
def test_explicit_max_message_protects_and_one_more_is_refused(kind, n_lsb, explicit_start, private_pem):
    cover = COVERS[kind]
    fields = _fields(n_lsb=str(n_lsb), start_mode="explicit", explicit_start=str(explicit_start))
    largest = _capacity(cover, fields)["max_message_bytes"]
    assert largest > 0

    at_limit = _capacity(cover, fields, largest)
    assert at_limit["fits"] is True and _meter_fits(at_limit, largest)
    ok = _protect(cover, fields, largest, private_pem)
    assert ok.status_code == 200, ok.text
    assert ok.json()["start_offset"] == explicit_start

    over = _capacity(cover, fields, largest + 1)
    assert over["fits"] is False and not _meter_fits(over, largest + 1)
    _assert_refused_for_capacity(_protect(cover, fields, largest + 1, private_pem))


@pytest.mark.parametrize("n_lsb", [1, 3])
def test_derived_max_message_protects_whatever_the_passphrase(n_lsb, private_pem):
    """Capacity takes no passphrase, so it must size for the latest start any
    passphrase can derive. Every passphrase then fits the advertised maximum."""
    fields = _fields(n_lsb=str(n_lsb))  # start_mode defaults to derived on both endpoints
    largest = _capacity(IMAGE, fields)["max_message_bytes"]
    assert largest > 0
    assert _capacity(IMAGE, fields, largest)["fits"] is True
    assert _capacity(IMAGE, fields, largest + 1)["fits"] is False

    starts = set()
    for passphrase in PASSPHRASES:
        ok = _protect(IMAGE, {**fields, "passphrase": passphrase}, largest, private_pem)
        assert ok.status_code == 200, (passphrase, ok.text)
        starts.add(ok.json()["start_offset"])
    assert len(starts) > 1  # the passphrases really did land on different starts


def test_derived_limit_is_exactly_the_latest_derivable_start(private_pem):
    """Not just safe but tight: at the latest start derive_start can return,
    the derived-mode maximum is exactly the most that fits."""
    n_lsb = 2
    derived = _capacity(IMAGE, _fields(n_lsb=str(n_lsb)))
    n_elements = derived["total_elements"]
    span = n_elements - -(-location.reserved_frame_bits(n_elements, n_lsb) // n_lsb)
    latest = _fields(n_lsb=str(n_lsb), start_mode="explicit", explicit_start=str(span - 1))

    assert _capacity(IMAGE, latest)["max_message_bytes"] == derived["max_message_bytes"]
    assert _protect(IMAGE, latest, derived["max_message_bytes"], private_pem).status_code == 200
    _assert_refused_for_capacity(_protect(IMAGE, latest, derived["max_message_bytes"] + 1, private_pem))


VARIANTS = {
    "encrypted": {"encrypt_message": "true"},
    "sealed": {"seal_frame": "true"},
    "redundancy-3": {"redundancy": "3"},
    "all-of-them": {"encrypt_message": "true", "seal_frame": "true", "redundancy": "5", "n_lsb": "3"},
}


@pytest.mark.parametrize("variant", VARIANTS, ids=list(VARIANTS))
def test_variants_max_message_protects_and_one_more_is_refused(variant, private_pem):
    settings = {"n_lsb": "2", "passphrase": PASSPHRASES[0], **VARIANTS[variant]}

    explicit = _fields(**settings, start_mode="explicit", explicit_start="101")
    largest = _capacity(IMAGE, explicit)["max_message_bytes"]
    assert largest > 0
    at_limit = _capacity(IMAGE, explicit, largest)
    assert at_limit["fits"] is True and _meter_fits(at_limit, largest)
    assert _protect(IMAGE, explicit, largest, private_pem).status_code == 200
    over = _capacity(IMAGE, explicit, largest + 1)
    assert over["fits"] is False and not _meter_fits(over, largest + 1)
    _assert_refused_for_capacity(_protect(IMAGE, explicit, largest + 1, private_pem))

    derived = _fields(**settings)
    largest = _capacity(IMAGE, derived)["max_message_bytes"]
    assert largest > 0
    assert _capacity(IMAGE, derived, largest + 1)["fits"] is False
    for passphrase in PASSPHRASES[:3]:
        ok = _protect(IMAGE, {**derived, "passphrase": passphrase}, largest, private_pem)
        assert ok.status_code == 200, (passphrase, ok.text)


@pytest.mark.parametrize(
    "settings",
    [
        {"n_lsb": "1", "explicit_start": "1024"},
        {"n_lsb": "3", "explicit_start": "5", "redundancy": "3"},
        {"n_lsb": "5", "explicit_start": "0", "redundancy": "3", "seal_frame": "true"},
        {"n_lsb": "7", "explicit_start": "11", "encrypt_message": "true"},
    ],
    ids=["plain", "redundancy-3", "sealed-redundancy-3", "encrypted"],
)
def test_fits_matches_protect_across_the_boundary(settings, private_pem):
    """Byte by byte around the limit, `fits` and the meter's formula both
    predict exactly whether Protect accepts the message."""
    needs_key = settings.get("seal_frame") or settings.get("encrypt_message")
    fields = _fields(start_mode="explicit", **settings, **({"passphrase": "sweep"} if needs_key else {}))
    largest = _capacity(IMAGE, fields)["max_message_bytes"]
    outcomes = {}
    for size in range(max(0, largest - 7), largest + 8):
        report = _capacity(IMAGE, fields, size)
        protected = _protect(IMAGE, fields, size, private_pem)
        assert protected.status_code in (200, 400), protected.text
        outcomes[size] = protected.status_code == 200
        assert report["fits"] is outcomes[size], (size, report, protected.text)
        assert _meter_fits(report, size) is outcomes[size], (size, report)
    assert outcomes[largest] and not outcomes[largest + 1]


def test_committed_sample_with_gui_defaults(private_pem):
    """The reported case: samples/image/original/cover.png, GUI defaults,
    derived mode. The meter used to advertise 73440 bytes; Protect refused
    everything above about 69000 of them for the passphrase tried."""
    if not SAMPLE_COVER.is_file():
        pytest.skip("committed sample cover not present")
    sample = ("cover.png", SAMPLE_COVER.read_bytes())
    fields = {
        "n_lsb": "1",
        "media_id": "cover.png",
        "metadata_json": '{"team": "INF2005 ACW1", "purpose": "release check"}',
    }
    largest = _capacity(sample, fields)["max_message_bytes"]
    assert _capacity(sample, fields, largest)["fits"] is True
    assert _capacity(sample, fields, largest + 1)["fits"] is False
    ok = _protect(sample, {**fields, "passphrase": "demo passphrase"}, largest, private_pem)
    assert ok.status_code == 200, ok.text


# --------------------------------------------------------------------------- #
# Without a media ID or metadata: conservative, sized to the stated allowance
# --------------------------------------------------------------------------- #


def test_fallback_without_media_id_or_metadata_never_over_promises(private_pem):
    """Omitting both assumes a FALLBACK_MEDIA_ID_BYTES media ID and
    FALLBACK_METADATA_BYTES of metadata JSON beyond "{}". A frame carrying
    exactly that much fits the advertised maximum, and not one byte more."""
    base = {"n_lsb": "2", "start_mode": "explicit", "explicit_start": "64"}
    fallback = _capacity(IMAGE, base)
    exact = _capacity(IMAGE, _fields(**base))
    assert fallback["max_message_bytes"] < exact["max_message_bytes"]

    longest_media_id = "i" * capacity_router.FALLBACK_MEDIA_ID_BYTES
    filler = capacity_router.FALLBACK_METADATA_BYTES - len('"k":""')
    largest_metadata = json.dumps({"k": "x" * filler}, separators=(",", ":"))
    assert len(largest_metadata) == len("{}") + capacity_router.FALLBACK_METADATA_BYTES
    worst = {**base, "media_id": longest_media_id, "metadata_json": largest_metadata}

    assert _protect(IMAGE, worst, fallback["max_message_bytes"], private_pem).status_code == 200
    _assert_refused_for_capacity(_protect(IMAGE, worst, fallback["max_message_bytes"] + 1, private_pem))


# --------------------------------------------------------------------------- #
# Settings Protect refuses outright are refused here too
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("fields", "detail"),
    [
        ({"start_mode": "explicit"}, "explicit_start"),
        ({"start_mode": "explicit", "explicit_start": "-1"}, "start must be >= 0"),
        ({"metadata_json": "{not json"}, "metadata_json is not valid JSON"),
    ],
)
def test_capacity_refuses_what_protect_refuses(fields, detail, private_pem):
    r = client.post("/api/capacity", files={"cover": IMAGE}, data={"media_id": MEDIA_ID, **fields})
    assert r.status_code == 400 and detail in r.json()["detail"], r.text
    refused = _protect(IMAGE, {"media_id": MEDIA_ID, **fields}, 10, private_pem)
    assert refused.status_code == 400, refused.text


def test_explicit_start_past_the_end_fits_nothing(private_pem):
    fields = _fields(n_lsb="1", start_mode="explicit", explicit_start=str(72 * 88 * 3))
    report = _capacity(IMAGE, fields, 1)
    assert report["max_message_bytes"] == 0 and report["fits"] is False
    assert not _meter_fits(report, 1)
    _assert_refused_for_capacity(_protect(IMAGE, fields, 1, private_pem))


def test_start_reserve_is_reported_separately_and_included_in_the_overhead(png_rgb: bytes) -> None:
    """The GUI shows the frame overhead and the room lost before the start as two rows;
    their sum is still frame_overhead_bytes, which the meter's arithmetic relies on."""
    from fastapi.testclient import TestClient

    from app.main import app

    c = TestClient(app)
    base = {"n_lsb": "2", "payload_bytes": "100", "media_id": "m", "metadata_json": "{}"}
    explicit = c.post(
        "/api/capacity",
        files={"cover": ("c.png", png_rgb)},
        data={**base, "start_mode": "explicit", "explicit_start": "4000"},
    ).json()
    at_zero = c.post(
        "/api/capacity",
        files={"cover": ("c.png", png_rgb)},
        data={**base, "start_mode": "explicit", "explicit_start": "0"},
    ).json()
    assert explicit["start_reserve_bytes"] > at_zero["start_reserve_bytes"] >= 0
    assert (
        explicit["frame_overhead_bytes"] - explicit["start_reserve_bytes"]
        == at_zero["frame_overhead_bytes"] - at_zero["start_reserve_bytes"]
    )
