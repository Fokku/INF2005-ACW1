"""API tests for POST /api/steganalysis (steganalysis optional challenge, method by Ke Ying).

What the method really reports, measured on the committed samples (see also
evidence/logs/steganalysis-demo.txt):

  * The bundled sample covers are synthetic noise, so their value pairs are
    already equal and the whole-file chi-square reads p ~ 1.0 for cover AND
    stego alike. The call therefore comes from the byte-phase test, which
    flags every bundled stego sample and no bundled cover.
  * On a natural-looking cover (`natural_cover`, as the script's demo uses)
    the chi-square test does separate cover from stego: p ~ 0 on the cover,
    p ~ 1 inside the embedded windows.
"""

from __future__ import annotations

import json
import math
import wave
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_video_codec import _build_avi

from app.main import app
from stego_core import pipeline, signing
from stego_core import steganalysis as sa

client = TestClient(app)

ROOT = Path(__file__).resolve().parents[2]
COVER_PNG = ROOT / "samples/image/original/cover.png"
STEGO_PNG = ROOT / "samples/image/stego/image-large.stego.png"
COVER_WAV = ROOT / "samples/audio/original/cover.wav"
STEGO_WAV = ROOT / "samples/audio/stego/audio-large.stego.wav"
SAMPLE_START = 128  # explicit start used for every bundled image/audio stego sample (sample-manifest.json)
SAMPLE_N_LSB = 2

CONTRACT_KEYS = {
    "filename",
    "kind",
    "elements",
    "window",
    "chi_square_p",
    "phase_p",
    "phase_n_lsb_guess",
    "suspicious",
    "verdict",
    "summary",
    "suspected_region",
    "windows",
    "method",
}
WINDOW_KEYS = {"start", "end", "chi_square_p", "phase_p", "flagged"}


def _reject_nan(token: str) -> float:
    raise AssertionError(f"non-JSON float {token} in response")


def _analyse(name: str, data: bytes, **form) -> dict:
    r = client.post(
        "/api/steganalysis", files={"file": (name, data)}, data={k: str(v) for k, v in form.items()}
    )
    assert r.status_code == 200, r.text
    return json.loads(r.text, parse_constant=_reject_nan)


def _check_shape(body: dict, kind: str) -> None:
    assert CONTRACT_KEYS <= body.keys()
    assert body["kind"] == kind
    assert isinstance(body["suspicious"], bool) and body["verdict"] and body["summary"] and body["method"]
    for key in ("chi_square_p", "phase_p"):
        assert body[key] is None or 0.0 <= body[key] <= 1.0
    assert 0 < len(body["windows"]) <= 400
    previous_end = 0
    for w in body["windows"]:
        assert set(w) == WINDOW_KEYS
        assert w["start"] == previous_end < w["end"] <= body["elements"]  # contiguous, in order
        previous_end = w["end"]
        for key in ("chi_square_p", "phase_p"):
            assert w[key] is None or (math.isfinite(w[key]) and 0.0 <= w[key] <= 1.0)
        assert w["flagged"] == (w["phase_p"] is not None and w["phase_p"] < sa.PHASE_ALPHA)
    assert body["windows_flagged"] == sum(w["flagged"] for w in body["windows"])  # no merging here


@pytest.mark.parametrize(
    ("path", "kind"),
    [(COVER_PNG, "image"), (STEGO_PNG, "image"), (COVER_WAV, "audio"), (STEGO_WAV, "audio")],
    ids=lambda v: v.name if isinstance(v, Path) else v,
)
def test_response_shape_and_no_nan(path: Path, kind: str) -> None:
    body = _analyse(path.name, path.read_bytes())
    assert body["filename"] == path.name and body["window"] == sa.DEFAULT_WINDOW
    _check_shape(body, kind)


@pytest.mark.parametrize("path", [COVER_PNG, COVER_WAV], ids=lambda p: p.name)
def test_clean_cover_is_not_flagged(path: Path) -> None:
    body = _analyse(path.name, path.read_bytes())
    assert body["suspicious"] is False
    assert body["verdict"] == sa.VERDICT_CLEAN
    assert body["suspected_region"] is None and body["phase_n_lsb_guess"] is None
    assert body["phase_p"] >= sa.PHASE_ALPHA


@pytest.mark.parametrize("path", [STEGO_PNG, STEGO_WAV], ids=lambda p: p.name)
def test_stego_sample_is_flagged_at_its_start(path: Path) -> None:
    body = _analyse(path.name, path.read_bytes())
    assert body["suspicious"] is True
    assert body["verdict"] == sa.VERDICT_SUSPICIOUS
    region = body["suspected_region"]
    assert region["start"] <= SAMPLE_START < region["end"]
    assert region == {"start": 0, "end": 8192}  # what the CLI reports for these files at window 4096
    assert body["phase_p"] < sa.PHASE_ALPHA
    assert body["phase_n_lsb_guess"] == SAMPLE_N_LSB


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("cover.png", 0),
        ("image-short.stego.png", 1),
        ("cover.wav", 0),
        ("audio-short.stego.wav", 1),
    ],
)
def test_matches_committed_demo_evidence(name: str, flagged: int) -> None:
    """evidence/logs/steganalysis-demo.txt, 'bundled ...' rows, window 16384."""
    case = json.loads((ROOT / "evidence/steganalysis/steganalysis-report.json").read_text())["cases"][
        f"bundled {name}"
    ]
    path = next((ROOT / "samples").rglob(name))
    body = _analyse(name, path.read_bytes(), window=16384)
    assert body["windows_flagged"] == case["windows_flagged"] == flagged
    assert len(body["windows"]) == case["windows_total"]
    assert body["chi_square_p"] == pytest.approx(case["whole_file_p"], rel=1e-9)
    region = case["suspected_region"]
    expected = (
        None
        if region is None
        else {"start": region["first_flagged_window_begin"], "end": region["last_flagged_window_end"]}
    )
    assert body["suspected_region"] == expected


@pytest.fixture(scope="module")
def natural_pair() -> tuple[bytes, bytes, tuple[int, int]]:
    """A photo-like cover (the script's `natural_cover`) and a 1-LSB stego copy of it."""
    cover = sa.natural_cover(256)
    private_pem, _ = signing.generate_keypair()
    message = b"Explain how steganography can be used to embed hidden verification data. " * 50
    out = pipeline.protect(
        pipeline.ProtectOptions(
            cover_bytes=cover,
            cover_kind="image",
            message=message,
            message_mime="text/plain",
            n_lsb=1,
            media_id="steganalysis-api",
            metadata={},
            private_key_pem=private_pem,
            explicit_start=20000,
        )
    )
    return cover, out.stego_bytes, (20000, 20000 + out.frame_bytes * 8)


def test_natural_cover_chi_square_separates_cover_and_stego(natural_pair) -> None:
    cover, stego, (start, end) = natural_pair
    window = sa.DEFAULT_WINDOW

    clean = _analyse("natural.png", cover)
    _check_shape(clean, "image")
    assert clean["suspicious"] is False
    assert clean["chi_square_p"] < 0.05  # natural cover: unequal value pairs
    assert "natural cover" in clean["summary"]

    body = _analyse("natural.stego.png", stego)
    _check_shape(body, "image")
    assert body["suspicious"] is True
    region = body["suspected_region"]
    assert start - window < region["start"] <= start + window  # recovers the start to within a window
    assert end - window <= region["end"] < end + window
    inside = [w for w in body["windows"] if w["start"] >= start and w["end"] <= end]
    outside = [w for w in body["windows"] if w["end"] <= start or w["start"] >= end]
    assert inside and all(w["chi_square_p"] > 0.5 for w in inside)  # pairs evened out by embedding
    assert all(w["chi_square_p"] < 0.05 for w in outside)


def _avi_from_wav(path: Path) -> bytes:
    with wave.open(str(path)) as w:
        pcm = w.readframes(w.getnframes())
        return _build_avi(pcm, channels=w.getnchannels(), sample_rate=w.getframerate(), n_pcm_chunks=20)


@pytest.mark.parametrize(
    ("path", "suspicious"), [(COVER_WAV, False), (STEGO_WAV, True)], ids=["cover", "stego"]
)
def test_video_is_analysed_through_its_audio_track(path: Path, suspicious: bool) -> None:
    body = _analyse("clip.avi", _avi_from_wav(path))
    _check_shape(body, "video")
    assert body["suspicious"] is suspicious


def test_windows_are_downsampled_for_the_chart_without_losing_flags() -> None:
    """window=256 gives 861 windows for this WAV; the chart gets at most 400 entries."""
    body = _analyse(STEGO_WAV.name, STEGO_WAV.read_bytes(), window=256)
    assert body["windows_total"] == 220500 // 256
    assert body["windows_merged"] == 3 and len(body["windows"]) == math.ceil(861 / 3)
    assert body["windows"][0]["start"] == 0 and body["windows"][-1]["end"] == 861 * 256
    flagged = [w for w in body["windows"] if w["flagged"]]
    assert flagged and body["windows_flagged"] >= len(flagged)
    region = body["suspected_region"]
    assert flagged[0]["start"] <= region["start"] and region["end"] <= flagged[-1]["end"]
    assert all(w["flagged"] == (w["phase_p"] < sa.PHASE_ALPHA) for w in body["windows"])


def test_file_smaller_than_window_is_one_window() -> None:
    body = _analyse("cover-empty.png", (ROOT / "samples/image/original/cover-empty.png").read_bytes())
    assert body["window"] == body["elements"] == 3072
    assert len(body["windows"]) == 1 and body["suspicious"] is False


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("notes.txt", b"hello"),
        ("cover.jpg", b"\xff\xd8\xff"),
        ("broken.png", b"not a png"),
        ("x.wav", b"RIFF"),
    ],
)
def test_unsupported_file_is_415(name: str, data: bytes) -> None:
    r = client.post("/api/steganalysis", files={"file": (name, data)})
    assert r.status_code == 415
    assert r.json()["error"] == "unsupported_cover"


def test_window_below_minimum_is_rejected() -> None:
    r = client.post(
        "/api/steganalysis", files={"file": ("c.png", COVER_PNG.read_bytes())}, data={"window": "128"}
    )
    assert r.status_code == 422
