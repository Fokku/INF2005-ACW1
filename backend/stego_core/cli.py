"""`stego` command line tool.

Two jobs:
  1. Generate deterministic evidence and sample files for the submission,
     without clicking through the GUI (spec FR12, "reproducibility").
  2. A rescue path if the web UI misbehaves during the live demo.

The argument parsing below is COMPLETE. Each command's body calls into
`pipeline` / `signing`, which are the TODO parts.

    stego keygen   --out keys
    stego capacity --cover FILE --lsb N
    stego protect  --cover FILE --message FILE --lsb N --media-id ID \
                   --key keys/private/team_ed25519.pem --passphrase SECRET --out FILE
    stego verify   --stego FILE --pub keys/public/team_ed25519.pub.pem \
                   --lsb N --media-id ID --passphrase SECRET
    stego tamper   --stego FILE --attack flip_bits --out FILE
    stego serve    [--port 8000] [--reload]
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

from . import attacks, audio_codec, container, image_codec, lsb, pipeline, signing, video_codec
from .errors import StegoError, UnsupportedCoverError
from .verdict import Verdict

# Same extension convention as app/routers/capacity.py::_sniff_kind. The CLI
# stays independent of the `app` package (pipeline is the only module that
# reaches across stego_core; nothing here should import `app`), so the rule
# is duplicated rather than shared.
_KIND_BY_SUFFIX = {".png": "image", ".wav": "audio", ".avi": "video"}

# Mirrors app/routers/capacity.py::PAYLOAD_JSON_OVERHEAD_BYTES — a rough
# allowance for the signed JSON fields other than the message itself.
_PAYLOAD_JSON_OVERHEAD_BYTES = 300


def _sniff_kind(path: Path) -> str:
    try:
        return _KIND_BY_SUFFIX[path.suffix.lower()]
    except KeyError:
        raise UnsupportedCoverError(
            f"unrecognised cover extension: {path!s} (need .png, .wav, or .avi)"
        ) from None


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_pem, public_pem = signing.generate_keypair()
    out = Path(args.out)
    private_dir = out / "private"
    public_dir = out / "public"
    private_dir.mkdir(parents=True, exist_ok=True)
    public_dir.mkdir(parents=True, exist_ok=True)

    private_path = private_dir / f"{args.label}_ed25519.pem"
    public_path = public_dir / f"{args.label}_ed25519.pub.pem"
    private_path.write_bytes(private_pem)
    private_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600: demo-only, never commit
    public_path.write_bytes(public_pem)

    print(f"private key: {private_path}")
    print(f"public key:  {public_path}")
    print(f"fingerprint: {signing.fingerprint(public_pem)}")
    return 0


_LOAD_COVER = {"image": image_codec.load_png, "audio": audio_codec.load_wav, "video": video_codec.load_avi}


def _cmd_capacity(args: argparse.Namespace) -> int:
    cover_path = Path(args.cover)
    kind = _sniff_kind(cover_path)
    cover = _LOAD_COVER[kind](cover_path.read_bytes())

    total_elements = len(cover.elements)
    capacity_bits_ = lsb.capacity_bits(total_elements, args.lsb)
    capacity_bytes = capacity_bits_ // 8
    frame_overhead_bytes = (
        container.frame_size_bytes(0, signing.SIGNATURE_BYTES) + _PAYLOAD_JSON_OVERHEAD_BYTES
    )
    # Largest message: invert the payload's base64 inflation (raw = 3/4 of
    # its encoded size), same as app/routers/capacity.py.
    max_message_bytes = max(0, ((capacity_bytes - frame_overhead_bytes) * 3) // 4)

    print(f"cover kind:            {kind}")
    print(f"total elements:        {total_elements}")
    print(f"n_lsb:                 {args.lsb}")
    print(f"capacity:              {capacity_bits_} bits ({capacity_bytes} bytes)")
    print(f"frame overhead:        {frame_overhead_bytes} bytes (signature + header + JSON fields)")
    print(f"largest message:       {max_message_bytes} bytes")
    return 0


def _cmd_protect(args: argparse.Namespace) -> int:
    cover_path = Path(args.cover)
    kind = _sniff_kind(cover_path)
    opts = pipeline.ProtectOptions(
        cover_bytes=cover_path.read_bytes(),
        cover_kind=kind,
        message=Path(args.message).read_bytes(),
        message_mime=args.mime,
        n_lsb=args.lsb,
        media_id=args.media_id,
        metadata={},
        private_key_pem=Path(args.key).read_bytes(),
        passphrase=args.passphrase,
        explicit_start=args.start,
        encrypt_message=args.encrypt,
    )
    outcome = pipeline.protect(opts)
    Path(args.out).write_bytes(outcome.stego_bytes)

    print(f"wrote: {args.out}")
    print(f"start offset: {outcome.start_offset}")
    print(f"frame bytes:  {outcome.frame_bytes} (capacity: {outcome.capacity_bytes} bytes)")
    print(json.dumps(outcome.payload_json, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    stego_path = Path(args.stego)
    kind = _sniff_kind(stego_path)
    opts = pipeline.VerifyOptions(
        stego_bytes=stego_path.read_bytes(),
        cover_kind=kind,
        public_key_pem=Path(args.pub).read_bytes(),
        n_lsb=args.lsb,
        media_id=args.media_id,
        passphrase=args.passphrase,
        explicit_start=args.start,
    )
    outcome = pipeline.verify(opts)
    report = {
        "verdict": outcome.verdict.value,
        "reasons": outcome.reasons,
        "start_offset_used": outcome.start_offset_used,
        "signature_valid": outcome.signature_valid,
        "media_hash_embedded": outcome.media_hash_embedded,
        "media_hash_recomputed": outcome.media_hash_recomputed,
        "payload": outcome.payload_json,
    }
    print(json.dumps(report, indent=2))
    return 0 if outcome.verdict == Verdict.AUTHENTIC else 1


def _cmd_tamper(args: argparse.Namespace) -> int:
    stego_path = Path(args.stego)
    kind = _sniff_kind(stego_path)
    data = stego_path.read_bytes()

    if args.attack == "flip_bits":
        output = attacks.flip_bits(data, kind)
    elif args.attack == "crop":
        output = attacks.crop(data, kind)
    elif args.attack == "lsb_scrub":
        output = attacks.lsb_scrub(data, kind, args.lsb)
    elif args.attack == "reencode":
        output = attacks.reencode(data, kind)
    elif args.attack == "corrupt_payload":
        output = attacks.corrupt_payload(data, kind, args.lsb, args.start)
    else:
        if not args.other_cover:
            raise StegoError("--attack replay requires --other-cover")
        other_kind = _sniff_kind(Path(args.other_cover))
        if other_kind != kind:
            raise StegoError("replay target must have the same cover kind")
        output = attacks.replay(data, Path(args.other_cover).read_bytes(), kind, args.lsb, args.start)

    Path(args.out).write_bytes(output)
    print(f"wrote: {args.out}")
    print(f"expected verdict: {attacks.EXPECTED[args.attack].value}")
    print(attacks.DESCRIPTIONS[args.attack])
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run the API + built UI on one port. Complete — no TODO."""
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stego", description="ACW1 steganography tool")
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="generate a demo Ed25519 key pair")
    k.add_argument("--out", default="keys", help="directory holding public/ and private/")
    k.add_argument("--label", default="team", help="key file base name")
    k.set_defaults(func=_cmd_keygen)

    c = sub.add_parser("capacity", help="how much can this cover hold?")
    c.add_argument("--cover", required=True)
    c.add_argument("--lsb", type=int, default=1, choices=range(1, 9))
    c.set_defaults(func=_cmd_capacity)

    pr = sub.add_parser("protect", help="embed a signed payload into a cover")
    pr.add_argument("--cover", required=True)
    pr.add_argument("--message", required=True, help="file holding the message to hide")
    pr.add_argument("--mime", default="text/plain")
    pr.add_argument("--lsb", type=int, default=1, choices=range(1, 9))
    pr.add_argument("--media-id", required=True)
    pr.add_argument("--key", required=True, help="private key PEM")
    pr.add_argument("--passphrase", help="required for a derived start location and/or encryption")
    pr.add_argument("--start", type=int, help="explicit start offset instead of deriving one")
    pr.add_argument("--encrypt", action="store_true", help="AES-256-GCM the message")
    pr.add_argument("--out", required=True)
    pr.set_defaults(func=_cmd_protect)

    v = sub.add_parser("verify", help="extract and judge a stego object")
    v.add_argument("--stego", required=True)
    v.add_argument("--pub", required=True, help="public key PEM")
    v.add_argument("--lsb", type=int, default=1, choices=range(1, 9))
    v.add_argument("--media-id", required=True)
    v.add_argument("--passphrase")
    v.add_argument("--start", type=int)
    v.set_defaults(func=_cmd_verify)

    t = sub.add_parser("tamper", help="produce a negative test case")
    t.add_argument("--stego", required=True)
    t.add_argument(
        "--attack",
        required=True,
        choices=["flip_bits", "crop", "lsb_scrub", "reencode", "corrupt_payload", "replay"],
    )
    t.add_argument("--lsb", type=int, default=1, choices=range(1, 9))
    t.add_argument("--start", type=int, default=0)
    t.add_argument("--other-cover", help="for --attack replay")
    t.add_argument("--out", required=True)
    t.set_defaults(func=_cmd_tamper)

    s = sub.add_parser("serve", help="run the web UI + API on one port")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(func=_cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except NotImplementedError as exc:
        print(f"not implemented yet: {exc}", file=sys.stderr)
        print("see TODO.md — this command needs a stego_core function first", file=sys.stderr)
        return 2
    except StegoError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
