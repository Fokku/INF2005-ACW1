"""Steganalysis of our own LSB stego objects (optional challenge).

Method: the Westfeld-Pfitzmann chi-square "pairs of values" attack. LSB replacement
with random-looking data equalises the counts of each value pair (2k, 2k+1), so in an
embedded region the chi-square statistic against the "equal pair" hypothesis collapses
(p-value near 1), while a natural cover keeps unequal pairs (p-value near 0).

Two views are reported:
  * whole-file p-value (is there a payload at all?)
  * per-window p-values (WHERE is it? this reveals the start location and length)

The analysis itself lives in backend/stego_core/steganalysis.py, shared with the web API
(POST /api/steganalysis); this script adds the command line and the evidence `demo`.

Usage (repo root, venv active):
    PYTHONPATH=backend python scripts/steganalysis.py analyze FILE [--window 4096]
    PYTHONPATH=backend python scripts/steganalysis.py demo --out evidence/steganalysis \
        [--photo PHOTO.jpg] [--wav SOUND.wav]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from stego_core import pipeline, signing  # noqa: E402
from stego_core.steganalysis import (  # noqa: E402,F401  (re-exported for anyone importing this script)
    KIND_BY_SUFFIX,
    MIN_PAIR_TOTAL,
    PHASE_ALPHA,
    _chi2_sf,
    analyze_elements,
    chi_square_p,
    decode_elements,
    natural_cover,
    phase_test,
    summary_line,
)


def load_elements(path: Path) -> np.ndarray:
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix not in KIND_BY_SUFFIX:
        raise SystemExit(f"unsupported file type: {suffix} (need .png, .wav or .avi)")
    return decode_elements(data, KIND_BY_SUFFIX[suffix])


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
