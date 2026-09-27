"""Unit tests for stego_core.steganalysis (Ke Ying's method, moved out of scripts/steganalysis.py).

The golden numbers below were produced by the ORIGINAL script before the move,
so these tests pin the library to exactly the same results.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pytest

from stego_core import steganalysis as sa

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "evidence/steganalysis/steganalysis-report.json"

EXACT = {"rel": 1e-9, "abs": 0.0}


@pytest.fixture(scope="module")
def golden_elements() -> np.ndarray:
    """natural_cover(256) with 6000 ASCII bytes written 2 bits per element at [20000, 44000)."""
    elements = sa.decode_elements(sa.natural_cover(256), "image").copy()
    text = (b"Explain how steganography can be used to embed hidden verification data. " * 200)[:6000]
    bits = np.unpackbits(np.frombuffer(text, np.uint8)).reshape(-1, 2)
    two = (bits[:, 0] << 1 | bits[:, 1]).astype(np.uint8)
    elements[20000 : 20000 + len(two)] = (elements[20000 : 20000 + len(two)] & 0xFC) | two
    return elements


def test_chi_square_and_phase_match_original_script(golden_elements: np.ndarray) -> None:
    el = golden_elements
    assert len(el) == 196608
    assert sa.chi_square_p(el) == (0.0, 127)
    p, df = sa.chi_square_p(el[:16384])
    assert (p, df) == (pytest.approx(1.9493888536709202e-201, **EXACT), 120)
    p, df = sa.chi_square_p(el[20480:24576])
    assert (p, df) == (pytest.approx(2.4536061586993967e-09, **EXACT), 100)
    p, n = sa.phase_test(el[:4096])
    assert (p, n) == (pytest.approx(0.13577676744716896, **EXACT), 4)
    p, n = sa.phase_test(el[20480:24576])
    assert (p, n) == (pytest.approx(8.304952493407831e-196, **EXACT), 2)


def test_analyze_elements_matches_original_script(golden_elements: np.ndarray) -> None:
    r = sa.analyze_elements(golden_elements, 4096)
    assert {k: r[k] for k in r if k != "windows"} == {
        "elements": 196608,
        "whole_file_p": 0.0,
        "whole_file_df": 127,
        "window": 4096,
        "windows_total": 48,
        "windows_flagged": 6,
        "suspected_region": {"first_flagged_window_begin": 20480, "last_flagged_window_end": 45056},
    }
    expected = [
        (12288, 1.1736718854317017e-29, 0.13092003896249407, 4),
        (16384, 8.801102632630788e-16, 0.00018225244580603913, 2),
        (20480, 2.4536061586993967e-09, 8.304952493407831e-196, 2),
        (24576, 3.472385368070514e-10, 5.684204254393567e-196, 2),
        (28672, 2.962708050073032e-09, 8.175126461190097e-196, 2),
        (32768, 2.620169137392492e-09, 6.758913087008176e-196, 2),
        (36864, 3.5464002462264934e-10, 6.758913087008176e-196, 2),
    ]
    for w, (begin, p, phase_p, guess) in zip(r["windows"][3:10], expected, strict=True):
        assert w["begin"] == begin and w["end"] == begin + 4096
        assert w["p"] == pytest.approx(p, **EXACT)
        assert w["phase_p"] == pytest.approx(phase_p, **EXACT)
        assert w["n_lsb_guess"] == guess
    assert sa.summary_line("golden", r) == (
        "golden                                       whole-file p=0.0000  "
        "flagged windows=6/48  suspected region: elements 20480-45056"
    )


@pytest.mark.parametrize(
    "rel",
    [
        "samples/image/original/cover.png",
        "samples/image/stego/image-short.stego.png",
        "samples/audio/original/cover.wav",
        "samples/audio/stego/audio-short.stego.wav",
    ],
)
def test_bundled_samples_match_committed_evidence(rel: str) -> None:
    """The committed demo report (window 16384) is reproduced exactly by the library."""
    case = json.loads(REPORT.read_text())["cases"][f"bundled {rel.split('/')[-1]}"]
    kind = sa.KIND_BY_SUFFIX[Path(rel).suffix]
    r = sa.analyze_elements(sa.decode_elements((ROOT / rel).read_bytes(), kind), 16384)
    for key in (
        "elements",
        "whole_file_df",
        "window",
        "windows_total",
        "windows_flagged",
        "suspected_region",
    ):
        assert r[key] == case[key], key
    assert r["whole_file_p"] == pytest.approx(case["whole_file_p"], **EXACT)


def test_chi_square_is_nan_when_too_few_pairs() -> None:
    p, df = sa.chi_square_p(np.arange(0, 4096 * 16, 16, dtype=np.uint16))  # every value seen once
    assert math.isnan(p) and df == 0


def test_assess_clamps_window_for_small_files_and_nulls_nan() -> None:
    rng = np.random.default_rng(5)
    small = rng.integers(0, 256, 3000, dtype=np.uint8)
    a = sa.assess(small, "image", 4096)
    assert a.window == 3000 and len(a.windows) == 1 and a.verdict == sa.VERDICT_CLEAN

    tiny = sa.assess(np.zeros(100, np.uint8), "image", 4096)
    assert tiny.windows == [] and tiny.verdict == sa.VERDICT_TOO_SMALL and not tiny.suspicious
    assert tiny.chi_square_p is None and tiny.phase_p is None

    audio = sa.assess(rng.integers(0, 65536, 8192, dtype=np.uint16), "audio", 4096)
    assert all(w.chi_square_p is None for w in audio.windows)  # 16-bit values rarely repeat


def test_assess_call_matches_the_scripts_flagging(golden_elements: np.ndarray) -> None:
    a = sa.assess(golden_elements, "image", 4096)
    assert a.suspicious and a.verdict == sa.VERDICT_SUSPICIOUS
    assert a.suspected_region == (20480, 45056)
    assert a.windows_flagged == sum(w.flagged for w in a.windows) == 6
    assert a.phase_p == min(w.phase_p for w in a.windows)
    assert a.phase_n_lsb_guess == 2
    assert "6 of 48 windows" in a.summary


def _w(start: int, chi: float | None, phase: float) -> sa.Window:
    return sa.Window(start, start + 10, chi, phase, phase < sa.PHASE_ALPHA)


def test_merge_windows_keeps_the_most_suspicious_value() -> None:
    windows = [_w(i * 10, 0.1, 0.5) for i in range(10)]
    windows[4] = _w(40, None, 1e-9)
    windows[7] = _w(70, 0.99, 0.2)
    merged, group = sa.merge_windows(windows, 4)
    assert group == 3 and len(merged) == 4
    assert [(m.start, m.end) for m in merged] == [(0, 30), (30, 60), (60, 90), (90, 100)]
    assert [m.flagged for m in merged] == [False, True, False, False]
    assert merged[1].phase_p == 1e-9 and merged[1].chi_square_p == 0.1  # None ignored
    assert merged[2].chi_square_p == 0.99
    assert sa.merge_windows(windows, 400) == (windows, 1)
