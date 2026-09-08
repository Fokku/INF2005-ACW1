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
import sys


def _cmd_keygen(args: argparse.Namespace) -> int:
    # TODO(team): signing.generate_keypair(), write keys/private/*.pem (0600)
    # and keys/public/*.pub.pem, print the fingerprint.
    raise NotImplementedError("TODO(team): stego keygen")


def _cmd_capacity(args: argparse.Namespace) -> int:
    # TODO(team): load the cover, print total elements, capacity in bits/bytes,
    # frame overhead and the largest message that fits.
    raise NotImplementedError("TODO(team): stego capacity")


def _cmd_protect(args: argparse.Namespace) -> int:
    # TODO(team): build ProtectOptions from args, call pipeline.protect(),
    # write the stego file, print the start offset and the payload JSON.
    raise NotImplementedError("TODO(team): stego protect")


def _cmd_verify(args: argparse.Namespace) -> int:
    # TODO(team): call pipeline.verify(), print the verdict and reasons as JSON,
    # and exit non-zero for anything other than Authentic so scripts can gate.
    raise NotImplementedError("TODO(team): stego verify")


def _cmd_tamper(args: argparse.Namespace) -> int:
    # TODO(team): dispatch to attacks.* and write the damaged copy.
    raise NotImplementedError("TODO(team): stego tamper")


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


if __name__ == "__main__":
    raise SystemExit(main())
