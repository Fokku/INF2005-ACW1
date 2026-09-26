"""Steganalysis of our own LSB stego objects (optional challenge).

Method: the Westfeld-Pfitzmann chi-square "pairs of values" attack. LSB replacement
with random-looking data equalises the counts of each value pair (2k, 2k+1), so in an
embedded region the chi-square statistic against the "equal pair" hypothesis collapses
(p-value near 1), while a natural cover keeps unequal pairs (p-value near 0).

Two views are reported:
  * whole-file p-value (is there a payload at all?)
  * per-window p-values (WHERE is it? this reveals the start location and length)

Usage (repo root, venv active):
    PYTHONPATH=backend python scripts/steganalysis.py analyze FILE [--window 4096]
    PYTHONPATH=backend python scripts/steganalysis.py demo --out evidence/steganalysis \
        [--photo PHOTO.jpg] [--wav SOUND.wav]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from stego_core import audio_codec, image_codec, pipeline, signing, video_codec  # noqa: E402

MIN_PAIR_TOTAL = 8  # pairs with fewer samples are dropped (chi-square validity)


def chi_square_p(elements: np.ndarray) -> tuple[float, int]:
    """Return (p-value of 'pairs are equalised', degrees of freedom)."""
    values = elements.astype(np.int64)
    pair_ids, inverse = np.unique(values >> 1, return_inverse=True)
    totals = np.bincount(inverse)
    ones = np.bincount(inverse, weights=(values & 1))
    keep = totals >= MIN_PAIR_TOTAL
    if keep.sum() < 3:
        return float("nan"), 0
    expected = totals[keep] / 2.0
    chi2 = float(np.sum((ones[keep] - expected) ** 2 / expected))
    df = int(keep.sum()) - 1
    # Wilson-Hilferty approximation of the chi-square survival function.
    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2)), df


def _chi2_sf(chi2: float, df: int) -> float:
    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    return 0.5 * math.erfc(z / math.sqrt(2))


def phase_test(elements: np.ndarray) -> tuple[float, int]:
    """Byte-phase test. Our frame is byte-oriented ASCII/base64 JSON, so an embedded bit-plane
    repeats with period 8/n_lsb elements and some phases are biased (e.g. the always-zero ASCII
    top bit). Homogeneity chi-square of the ones-fraction across phases: covers give a uniform
    p, embedded regions give p near 0. Returns (smallest p over planes, guess of n_lsb)."""
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


def load_elements(path: Path) -> np.ndarray:
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".png":
        return image_codec.load_png(data).elements
    if suffix == ".wav":
        return audio_codec.load_wav(data).elements
    if suffix == ".avi":  # video cover = its PCM audio track
        return video_codec.load_avi(data).elements
    raise SystemExit(f"unsupported file type: {suffix} (need .png, .wav or .avi)")


def analyze_elements(elements: np.ndarray, window: int) -> dict:
    whole_p, whole_df = chi_square_p(elements)
    windows = []
    for begin in range(0, len(elements) - window + 1, window):
        p, _ = chi_square_p(elements[begin : begin + window])
        pp, guess = phase_test(elements[begin : begin + window])
        windows.append({"begin": begin, "end": begin + window, "p": p, "phase_p": pp, "n_lsb_guess": guess})
    flagged = [w for w in windows if w["phase_p"] < 1e-6]
    region = None
    if flagged:
        region = {"first_flagged_window_begin": flagged[0]["begin"], "last_flagged_window_end": flagged[-1]["end"]}
    return {
        "elements": int(len(elements)),
        "whole_file_p": whole_p,
        "whole_file_df": whole_df,
        "window": window,
        "windows_total": len(windows),
        "windows_flagged": len(flagged),
        "suspected_region": region,
        "windows": windows,
    }


def summary_line(name: str, result: dict) -> str:
    region = result["suspected_region"]
    where = f"elements {region['first_flagged_window_begin']}-{region['last_flagged_window_end']}" if region else "none"
    return (
        f"{name:<44} whole-file p={result['whole_file_p']:.4f}  "
        f"flagged windows={result['windows_flagged']}/{result['windows_total']}  suspected region: {where}"
    )


def natural_cover(size: int = 512, seed: int = 7) -> bytes:
    """A smooth, photo-like synthetic PNG (unequal value pairs, unlike white noise)."""
    import io

    from PIL import Image

    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:size, 0:size]
    base = 110 + 60 * np.sin(x / 47.0) + 45 * np.cos(y / 61.0) + 25 * np.sin((x + y) / 19.0)
    # Sensor-like noise, then a contrast stretch. The stretch leaves every other grey level
    # under-populated, i.e. strongly unequal (2k, 2k+1) pairs, as tone-mapped photos have.
    channels = [np.clip((base + off + rng.normal(0, 0.6, base.shape) - 128) * 1.7 + 128, 0, 255) for off in (0, 12, -10)]
    img = Image.fromarray(np.rint(np.stack(channels, axis=-1)).astype(np.uint8), "RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _embed(kind: str, cover: bytes, message: bytes, private: bytes, n_lsb: int, start: int, encrypt: bool):
    opts = pipeline.ProtectOptions(
        cover_bytes=cover, cover_kind=kind, message=message, message_mime="text/plain",
        n_lsb=n_lsb, media_id=f"steganalysis-{kind}-{n_lsb}", metadata={}, private_key_pem=private,
        explicit_start=start, encrypt_message=encrypt, passphrase="steganalysis-demo" if encrypt else None,
    )
    return pipeline.protect(opts)


def _covers(photo: Path | None, wav: Path | None) -> list[tuple[str, str, str, bytes]]:
    """(label, kind, extension, bytes). A video cover is analysed via its PCM audio track."""
    covers = [("synthetic-photo", "image", "png", natural_cover())]
    if photo:
        import io

        from PIL import Image

        buf = io.BytesIO()
        Image.open(photo).convert("RGB").crop((0, 0, 640, 480)).save(buf, format="PNG")
        covers.append(("real-photo", "image", "png", buf.getvalue()))
    if wav:
        import wave

        sys.path.insert(0, str(ROOT / "backend/tests"))
        from test_video_codec import _build_avi  # reuse the tested AVI builder

        covers.append(("real-audio", "audio", "wav", wav.read_bytes()))
        with wave.open(str(wav)) as w:
            avi = _build_avi(w.readframes(w.getnframes()), channels=w.getnchannels(), sample_rate=w.getframerate(), n_pcm_chunks=20)
        covers.append(("real-video", "video", "avi", avi))
    return covers


def demo(out: Path, window: int, photo: Path | None, wav: Path | None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    private, _public = signing.generate_keypair()
    message = (ROOT / "docs/spec/INF2005-ACW1-spec-v5.md").read_text(encoding="utf-8")[:20000].encode()
    start = 20000
    report: dict = {"method": "chi-square pairs-of-values + byte-phase test, per window", "window": window, "cases": {}}

    def run(label: str, ext: str, data: bytes, truth: tuple[int, int] | None) -> None:
        path = out / f"tmp.{ext}"
        path.write_bytes(data)
        result = analyze_elements(load_elements(path), window)
        path.unlink()
        result["ground_truth_embedded_elements"] = None if truth is None else {"start": truth[0], "length": truth[1]}
        result["windows"] = []
        report["cases"][label] = result
        print(summary_line(label, result))
        if truth:
            print(f"{'':<44} ground truth: elements {truth[0]}-{truth[0] + truth[1]}")

    for name, kind, ext, cover in _covers(photo, wav):
        run(f"{name} original", ext, cover, None)
        for n_lsb in (1, 2):
            for encrypt in (False, True):
                outcome = _embed(kind, cover, message, private, n_lsb, start, encrypt)
                tag = "enc" if encrypt else "plain"
                (out / f"{name}.stego-{n_lsb}lsb-{tag}.{ext}").write_bytes(outcome.stego_bytes)
                run(f"{name} n_lsb={n_lsb} {tag}", ext, outcome.stego_bytes, (start, outcome.frame_bytes * 8 // n_lsb))

    for rel in ("samples/image/original/cover.png", "samples/image/stego/image-short.stego.png",
                "samples/audio/original/cover.wav", "samples/audio/stego/audio-short.stego.wav"):
        if (ROOT / rel).exists():
            run(f"bundled {rel.split('/')[-1]}", rel.rsplit(".", 1)[1], (ROOT / rel).read_bytes(), None)

    (out / "steganalysis-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"report: {out / 'steganalysis-report.json'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("file", type=Path)
    a.add_argument("--window", type=int, default=4096)
    d = sub.add_parser("demo")
    d.add_argument("--out", type=Path, default=ROOT / "evidence/steganalysis")
    d.add_argument("--window", type=int, default=16384)
    d.add_argument("--photo", type=Path, help="a real photo (any format PIL reads)")
    d.add_argument("--wav", type=Path, help="a real 16-bit PCM WAV; also builds a video cover from it")
    args = parser.parse_args()
    if args.cmd == "demo":
        demo(args.out, args.window, args.photo, args.wav)
        return
    result = analyze_elements(load_elements(args.file), args.window)
    print(summary_line(args.file.name, result))
    for w in result["windows"]:
        bar = "#" * int(round(w["p"] * 40)) if w["p"] == w["p"] else ""
        print(f"{w['begin']:>9}-{w['end']:<9} chi-p={w['p']:.3f} phase-p={w['phase_p']:.1e} n_lsb~{w['n_lsb_guess']} {bar}")


if __name__ == "__main__":
    main()
