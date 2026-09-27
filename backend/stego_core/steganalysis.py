"""Steganalysis: can an outsider tell that a file carries an LSB payload? (optional challenge)

Method and original script by Ke Ying (`scripts/steganalysis.py`). The analysis
lives here so that the CLI script and the web API (`POST /api/steganalysis`)
share one implementation; the script now only adds its command line and the
evidence-generating `demo`.

Two statistical tests, both run over the flat element array the codecs produce
(PNG colour values, WAV samples, or the PCM audio track of an AVI):

  CHI-SQUARE PAIRS OF VALUES (Westfeld & Pfitzmann, 1999)
            LSB replacement with random-looking data equalises the counts of
            each value pair (2k, 2k+1). The chi-square statistic against the
            "pairs are equal" hypothesis therefore collapses in an embedded
            region (p-value near 1), while a natural cover keeps unequal pairs
            (p-value near 0). Pairs seen fewer than MIN_PAIR_TOTAL times are
            dropped, since the chi-square approximation is invalid for them.

  BYTE PHASE
            Our frame is byte-oriented (ASCII magic + base64 JSON), so an
            embedded bit-plane repeats with period 8/n_lsb elements and some
            phases are biased (e.g. the always-zero top bit of ASCII). A
            homogeneity chi-square of the ones-fraction across the phases gives
            a uniform p-value on a cover and a p-value near 0 on an embedded
            region, and the period that fits best is a guess of n_lsb.

Both are run on the whole file and on consecutive windows. The windows show
WHERE a payload sits: a window is flagged when its byte-phase p-value is below
PHASE_ALPHA, and the run from the first to the last flagged window is the
suspected region (it recovers the start location and length).

>>> HONEST LIMITATIONS (measured, see evidence/logs/steganalysis-demo.txt):
>>>
>>>  1. The whole-file chi-square only means something on a natural cover. The
>>>     bundled sample covers are synthetic noise whose pairs are ALREADY equal,
>>>     so cover and stego both score p ~ 1.0 there; on a natural cover a
>>>     partial payload is outvoted by the untouched rest and both score p ~ 0.
>>>     It is therefore reported, but it does not drive the call.
>>>  2. The call is the byte-phase test, which finds OUR byte-structured frame.
>>>     It detects every bundled stego sample and flags no bundled cover, but a
>>>     frame of truly random bytes (no ASCII/base64 structure) would evade it.

Keep this module PURE like the rest of stego_core: no web framework imports.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass, field

import numpy as np
from PIL import Image

from . import audio_codec, image_codec, video_codec
from .errors import UnsupportedCoverError

MIN_PAIR_TOTAL = 8  # pairs with fewer samples are dropped (chi-square validity)
PHASE_ALPHA = 1e-6  # a window is flagged when its byte-phase p-value is below this
DEFAULT_WINDOW = 4096
MIN_WINDOW = 256  # smallest window the API accepts; files smaller than this get no windows

KIND_BY_SUFFIX = {".png": "image", ".wav": "audio", ".avi": "video"}

METHOD = (
    "Two statistical tests look for the traces LSB replacement leaves in the lowest bits. "
    "The Westfeld-Pfitzmann chi-square test checks whether each pair of values (2k, 2k+1) has been "
    "evened out, as overwriting LSBs does (p near 1 means evened out), and the byte-phase test checks "
    "whether the low bits repeat with a byte-sized period, as an embedded text frame does. "
    f"The file is tested in consecutive windows; a window is flagged when its byte-phase p-value is "
    f"below {PHASE_ALPHA:.0e}, which also shows where the hidden data sits."
)

VERDICT_SUSPICIOUS = "Signs of LSB embedding"
VERDICT_CLEAN = "No evidence of LSB embedding"
VERDICT_TOO_SMALL = "Too small to analyse"


# --------------------------------------------------------------------------- tests


def _chi2_sf(chi2: float, df: int) -> float:
    """Chi-square survival function, Wilson-Hilferty normal approximation."""
    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2))


def chi_square_p(elements: np.ndarray) -> tuple[float, int]:
    """Return (p-value of 'pairs are equalised', degrees of freedom).

    The p-value is NaN (with 0 degrees of freedom) when fewer than three value
    pairs occur often enough to test, e.g. a small window of 16-bit audio.
    """
    values = elements.astype(np.int64)
    _pair_ids, inverse = np.unique(values >> 1, return_inverse=True)
    totals = np.bincount(inverse)
    ones = np.bincount(inverse, weights=(values & 1))
    keep = totals >= MIN_PAIR_TOTAL
    if keep.sum() < 3:
        return float("nan"), 0
    expected = totals[keep] / 2.0
    chi2 = float(np.sum((ones[keep] - expected) ** 2 / expected))
    df = int(keep.sum()) - 1
    return _chi2_sf(chi2, df), df


def phase_test(elements: np.ndarray) -> tuple[float, int]:
    """Byte-phase test. Our frame is byte-oriented ASCII/base64 JSON, so an embedded bit-plane
    repeats with period 8/n_lsb elements and some phases are biased (e.g. the always-zero ASCII
    top bit). Homogeneity chi-square of the ones-fraction across phases: covers give a uniform
    p, embedded regions give p near 0. Returns (smallest p over planes, guess of n_lsb).

    The guess is 0 when every plane was constant (silence or saturation), and p is then 1.0.
    """
    best_p, best_n = 1.0, 0
    for n in (1, 2, 4):
        period = 8 // n
        usable = len(elements) // period * period
        grid = elements[:usable].reshape(-1, period).astype(np.int64)
        for plane in range(n):
            ones = ((grid >> plane) & 1).sum(axis=0).astype(float)
            rows = grid.shape[0]
            frac = ones.sum() / (rows * period)
            if frac < 0.02 or frac > 0.98:  # constant plane (silence/saturation): nothing to test
                continue
            p_hat = frac
            chi2 = float(np.sum((ones - rows * p_hat) ** 2 / (rows * p_hat * (1 - p_hat))))
            p = _chi2_sf(chi2, period - 1) if chi2 > 0 else 1.0
            if p < best_p:
                best_p, best_n = p, n
    return best_p, best_n


# --------------------------------------------------------------------------- input


def decode_elements(data: bytes, kind: str) -> np.ndarray:
    """File bytes -> the flat element array the embedder writes into.

    A video cover is analysed through its PCM audio track, because that is
    where `video_codec` embeds. Undecodable data raises UnsupportedCoverError.
    """
    loaders = {"image": image_codec.load_png, "audio": audio_codec.load_wav, "video": video_codec.load_avi}
    if kind not in loaders:
        raise UnsupportedCoverError(f"unsupported steganalysis kind: {kind!r} (need image, audio or video)")
    return loaders[kind](data).elements


# --------------------------------------------------------------------------- analysis


def analyze_elements(elements: np.ndarray, window: int) -> dict:
    """Whole-file chi-square plus both tests per window (the CLI's raw report).

    Windows are consecutive and non-overlapping; a trailing partial window is
    not analysed. A window is flagged when its byte-phase p < PHASE_ALPHA.
    """
    whole_p, whole_df = chi_square_p(elements)
    windows = []
    for begin in range(0, len(elements) - window + 1, window):
        p, _ = chi_square_p(elements[begin : begin + window])
        pp, guess = phase_test(elements[begin : begin + window])
        windows.append({"begin": begin, "end": begin + window, "p": p, "phase_p": pp, "n_lsb_guess": guess})
    flagged = [w for w in windows if w["phase_p"] < PHASE_ALPHA]
    region = None
    if flagged:
        region = {
            "first_flagged_window_begin": flagged[0]["begin"],
            "last_flagged_window_end": flagged[-1]["end"],
        }
    return {
        "elements": len(elements),
        "whole_file_p": whole_p,
        "whole_file_df": whole_df,
        "window": window,
        "windows_total": len(windows),
        "windows_flagged": len(flagged),
        "suspected_region": region,
        "windows": windows,
    }


def summary_line(name: str, result: dict) -> str:
    """One CLI line for an `analyze_elements` result."""
    region = result["suspected_region"]
    where = (
        f"elements {region['first_flagged_window_begin']}-{region['last_flagged_window_end']}"
        if region
        else "none"
    )
    return (
        f"{name:<44} whole-file p={result['whole_file_p']:.4f}  "
        f"flagged windows={result['windows_flagged']}/{result['windows_total']}  suspected region: {where}"
    )


def _finite(value: float) -> float | None:
    """NaN/inf -> None, so a result can go straight into JSON."""
    return float(value) if math.isfinite(value) else None


@dataclass
class Window:
    start: int
    end: int
    chi_square_p: float | None  # None: too few repeated values to test
    phase_p: float | None
    flagged: bool


@dataclass
class Assessment:
    """`analyze_elements` plus the call a reader sees. Every float is finite or None."""

    kind: str
    elements: int
    window: int  # the window actually used (see `assess`)
    chi_square_p: float | None  # whole file
    phase_p: float | None  # strongest (smallest) per-window byte-phase p-value
    phase_n_lsb_guess: int | None  # only when suspicious; a rough guess (1, 2 or 4), not always right
    suspicious: bool
    verdict: str
    summary: str
    suspected_region: tuple[int, int] | None  # [start, end) element indices of the flagged run
    windows_flagged: int
    windows: list[Window] = field(default_factory=list)  # full resolution, in order


def _p_phrase(p: float) -> str:
    if p == 0.0:
        return "p < 1e-300"  # the float underflowed: vanishingly small
    return f"p = {p:.1e}" if p < 1e-3 else f"p = {p:.3f}"


def _explain(a: Assessment, windows_total: int) -> str:
    unit = "colour value" if a.kind == "image" else "sample"
    if a.suspicious:
        start, end = a.suspected_region
        lsbs = f"{a.phase_n_lsb_guess} LSB{'s' if a.phase_n_lsb_guess != 1 else ''}"
        return (
            f"{a.windows_flagged} of {windows_total} windows (elements {start:,}-{end:,}) show the repeating "
            f"byte pattern that hidden text leaves in the low bits (strongest byte-phase {_p_phrase(a.phase_p)}, "
            f"threshold {PHASE_ALPHA:.0e}). Its period hints at {lsbs} per {unit} (a rough estimate)."
        )
    if a.phase_p is None:
        return (
            f"The file has only {a.elements:,} {unit}s, fewer than the {MIN_WINDOW} needed for a "
            "reliable window, so it was not analysed."
        )
    first = (
        f"No window shows the repeating byte pattern that hidden text leaves in the low bits "
        f"(strongest byte-phase {_p_phrase(a.phase_p)}, threshold {PHASE_ALPHA:.0e})."
    )
    if a.chi_square_p is None:
        return first
    if a.chi_square_p < 0.05:
        return first + (
            f" Value pairs are unevenly balanced across the file (chi-square {_p_phrase(a.chi_square_p)}), "
            "as in an untouched natural cover."
        )
    return first + (
        f" Value pairs look evened out (chi-square {_p_phrase(a.chi_square_p)}), but noisy covers look "
        "like that too, so on its own that proves nothing."
    )


def assess(elements: np.ndarray, kind: str, window: int = DEFAULT_WINDOW) -> Assessment:
    """Run `analyze_elements` and turn it into a call with a plain-language summary.

    The call is the script's own: suspicious iff at least one window is
    flagged by the byte-phase test. The only difference from the CLI is that a
    file shorter than `window` (but at least MIN_WINDOW elements) is analysed
    as one whole-file window instead of getting none.
    """
    if MIN_WINDOW <= len(elements) < window:
        window = len(elements)
    raw = analyze_elements(elements, window)
    windows = [
        Window(
            start=w["begin"],
            end=w["end"],
            chi_square_p=_finite(w["p"]),
            phase_p=_finite(w["phase_p"]),
            flagged=w["phase_p"] < PHASE_ALPHA,
        )
        for w in raw["windows"]
    ]
    strongest = min(raw["windows"], key=lambda w: w["phase_p"], default=None)
    suspicious = raw["windows_flagged"] > 0
    region = raw["suspected_region"]
    result = Assessment(
        kind=kind,
        elements=raw["elements"],
        window=window,
        chi_square_p=_finite(raw["whole_file_p"]),
        phase_p=None if strongest is None else _finite(strongest["phase_p"]),
        phase_n_lsb_guess=(strongest["n_lsb_guess"] or None) if suspicious else None,
        suspicious=suspicious,
        verdict=VERDICT_SUSPICIOUS if suspicious else (VERDICT_CLEAN if windows else VERDICT_TOO_SMALL),
        summary="",
        suspected_region=(
            (region["first_flagged_window_begin"], region["last_flagged_window_end"]) if region else None
        ),
        windows_flagged=raw["windows_flagged"],
        windows=windows,
    )
    result.summary = _explain(result, raw["windows_total"])
    return result


def merge_windows(windows: list[Window], max_count: int) -> tuple[list[Window], int]:
    """Downsample a window list for a chart: at most `max_count` entries.

    Consecutive runs of `group = ceil(len / max_count)` windows become one
    entry spanning them. Each entry keeps the MOST SUSPICIOUS value of its
    members (highest chi-square p, lowest byte-phase p, flagged if any member
    was), so a flagged window never disappears from the chart and
    `flagged == (phase_p < PHASE_ALPHA)` still holds. Every window is still
    analysed at full resolution; only the display is coarser.

    Returns (entries, group); group == 1 means nothing was merged.
    """
    if max_count < 1:
        raise ValueError("max_count must be at least 1")
    group = max(1, math.ceil(len(windows) / max_count))
    if group == 1:
        return list(windows), 1
    merged = []
    for i in range(0, len(windows), group):
        members = windows[i : i + group]
        chis = [w.chi_square_p for w in members if w.chi_square_p is not None]
        phases = [w.phase_p for w in members if w.phase_p is not None]
        merged.append(
            Window(
                start=members[0].start,
                end=members[-1].end,
                chi_square_p=max(chis) if chis else None,
                phase_p=min(phases) if phases else None,
                flagged=any(w.flagged for w in members),
            )
        )
    return merged, group


# --------------------------------------------------------------------------- demo cover


def natural_cover(size: int = 512, seed: int = 7) -> bytes:
    """A smooth, photo-like synthetic PNG (unequal value pairs, unlike white noise).

    Used by the script's `demo` and by the tests to show the chi-square test on
    a cover it can actually read (the bundled sample covers are noise).
    """
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:size, 0:size]
    base = 110 + 60 * np.sin(x / 47.0) + 45 * np.cos(y / 61.0) + 25 * np.sin((x + y) / 19.0)
    # Sensor-like noise, then a contrast stretch. The stretch leaves every other grey level
    # under-populated, i.e. strongly unequal (2k, 2k+1) pairs, as tone-mapped photos have.
    channels = [
        np.clip((base + off + rng.normal(0, 0.6, base.shape) - 128) * 1.7 + 128, 0, 255)
        for off in (0, 12, -10)
    ]
    img = Image.fromarray(np.rint(np.stack(channels, axis=-1)).astype(np.uint8), "RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
