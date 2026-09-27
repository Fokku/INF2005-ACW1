"""Party A -> party B transfer evidence (spec Section 5, FR11/FR12). LOCAL SIMULATION.

The spec asks for "the stego object being sent from party A to party B (eg,
via email), party B downloads to his/her folder and extracts the hidden
message with proof of the message integrity, signature verification". A
script running unattended cannot log in to a real mail provider, so this one
runs the whole round trip on one machine with the Python standard library:

  party A   protects the PNG and WAV covers (pipeline.protect), saves them to
            party-a/outbox/, and composes an RFC 5322 email
            (email.message.EmailMessage) carrying both files as base64 MIME
            attachments, the same encoding a real mail provider carries.
  transit   smtplib delivers that email over a real SMTP conversation to a
            minimal SMTP receiver on 127.0.0.1 (ephemeral port, background
            thread). The receiver files it into party B's Maildir
            (mailbox.Maildir), as a local delivery agent would.
  party B   opens the Maildir, parses the email, saves the attachments to
            party-b/downloads/, compares each SHA-256 with party A's
            pre-send value, then runs pipeline.verify with party A's PUBLIC
            key, the media ID / LSB count / start mode stated in the email,
            and the passphrase shared out of band.
  controls  a wrong passphrase, and a copy of each download with one high
            bit flipped (a simulated in-transit change). Neither may verify
            as Authentic.

This is not a third-party mail provider. The real two-machine email transfer
is performed live in the demo (docs/demo-plan.md, row 6); see
evidence/transfer.md.

Keys: a dedicated transfer key pair, NOT the team key that signed samples/.
  private  keys/private/transfer-demo_ed25519.pem  (gitignored, generated if missing)
  public   keys/public/transfer-demo.pub.pem       (committed)
The private key is only read from or written to keys/private/. It is never
copied into --out and never printed.

Run from the repository root:

    PYTHONPATH=backend .venv/bin/python scripts/transfer_demo.py --out evidence/transfer

The exit status is 0 only if every check passes. Re-running replaces the
generated files under --out. Each payload carries a fresh nonce and timestamp
by design, so stego bytes and hashes change from run to run, but every check
must pass on every run.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import email.utils
import hashlib
import json
import mailbox
import os
import re
import shutil
import smtplib
import socketserver
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Self

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from stego_core import audio_codec, image_codec, pipeline, signing
from stego_core.verdict import Verdict

DEFAULT_OUT = ROOT / "evidence" / "transfer"
DEFAULT_IMAGE_COVER = ROOT / "samples" / "image" / "original" / "cover.png"
DEFAULT_AUDIO_COVER = ROOT / "samples" / "audio" / "original" / "cover.wav"
DEFAULT_MESSAGE = ROOT / "samples" / "payloads" / "custom.txt"
DEFAULT_PRIVATE_KEY = ROOT / "keys" / "private" / "transfer-demo_ed25519.pem"
DEFAULT_PUBLIC_KEY = ROOT / "keys" / "public" / "transfer-demo.pub.pem"

COMMAND = "PYTHONPATH=backend .venv/bin/python scripts/transfer_demo.py --out evidence/transfer"

PASSPHRASE = "acw1-demo-passphrase-2026"  # demo-only; the same value as scripts/make_samples.py
WRONG_PASSPHRASE = "not-the-shared-passphrase"
N_LSB = 2
START_MODE = "derived"

SENDER = "party-a@acw1.local"
RECIPIENT = "party-b@acw1.local"
SMTP_SERVER_NAME = "mx.acw1.local"
CLIENT_HELO_NAME = "party-a.acw1.local"  # never let smtplib announce this machine's real hostname

MAX_LINE = 1000  # RFC 5321 section 4.5.3.1.6: 998 characters plus CRLF
MAX_MESSAGE_BYTES = 32 * 1024 * 1024

GENERATED = ("party-a", "party-b", "transfer-report.json", "transfer-log.txt")


@dataclass(frozen=True)
class Item:
    """One file party A sends. Media IDs mirror the GUI walkthrough."""

    kind: str  # pipeline cover kind
    media_id: str
    filename: str
    maintype: str
    subtype: str


ITEMS = (
    Item("image", "P-transfer-image", "transfer-image.stego.png", "image", "png"),
    Item("audio", "P-transfer-audio", "transfer-audio.stego.wav", "audio", "wav"),
)
SUBJECT = "ACW1 protected media for verification: " + ", ".join(item.media_id for item in ITEMS)


# --------------------------------------------------------------------------- helpers


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _display(path: Path, base: Path) -> str:
    """A path relative to `base` (or the repo root) where possible, for the report."""
    path = Path(path).resolve()
    for anchor in (base.resolve(), ROOT):
        if path.is_relative_to(anchor):
            return path.relative_to(anchor).as_posix()
    return str(path)


class Log:
    """The human-readable transcript, echoed to stdout while it is built."""

    def __init__(self, echo: bool = True) -> None:
        self.lines: list[str] = []
        self.echo = echo

    def __call__(self, line: str = "") -> None:
        self.lines.append(line)
        if self.echo:
            print(line)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


class Checks:
    """Every expectation, recorded whether it passes or not."""

    def __init__(self, log: Log) -> None:
        self.items: list[dict] = []
        self._log = log

    def expect(self, name: str, ok: bool, detail: str = "") -> bool:
        ok = bool(ok)
        self.items.append({"check": name, "passed": ok, "detail": detail})
        self._log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" ({detail})" if detail else ""))
        return ok

    @property
    def all_passed(self) -> bool:
        return bool(self.items) and all(item["passed"] for item in self.items)


# --------------------------------------------------------------------------- keys


def load_or_create_keys(
    private_path: Path, public_path: Path, regenerate: bool = False, log: Log | None = None
) -> tuple[bytes, bytes, bool]:
    """Return (private_pem, public_pem, generated_now) for the transfer key pair.

    Generates a pair only when neither half exists. If just one half is
    present (for example a clone with the committed public key but not the
    teammate's private key) it refuses unless `regenerate` is set: silently
    minting a new pair would change a committed key.
    """
    log = log or Log(echo=False)
    if private_path.exists() and public_path.exists() and not regenerate:
        return private_path.read_bytes(), public_path.read_bytes(), False
    if (private_path.exists() or public_path.exists()) and not regenerate:
        present, missing = (
            (public_path, private_path) if public_path.exists() else (private_path, public_path)
        )
        raise SystemExit(
            f"{_display(present, ROOT)} exists but its other half {_display(missing, ROOT)} is not on "
            "this machine. Re-run with --regenerate-key to create a new transfer key pair (this "
            "rewrites the public key, so commit it together with the regenerated evidence)."
        )
    private_pem, public_pem = signing.generate_keypair()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    public_path.write_bytes(public_pem)
    log(f"generated a new transfer key pair; public half at {_display(public_path, ROOT)}")
    return private_pem, public_pem, True


def private_key_leaks(folder: Path, private_pem: bytes) -> list[str]:
    """Files under `folder` containing a PEM private-key marker or this key's base64 body."""
    lines = [line.strip() for line in private_pem.splitlines() if line.strip()]
    body = b"".join(line for line in lines if not line.startswith(b"-----"))
    hits = []
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            if b"PRIVATE KEY" in data or (body and body in data):
                hits.append(path.relative_to(folder).as_posix())
    return hits


# --------------------------------------------------------------------------- SMTP receiver


class _SMTPHandler(socketserver.StreamRequestHandler):
    """One SMTP session: HELO/EHLO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT."""

    timeout = 30  # seconds; a stalled client must not hang the script

    def _send(self, line: str) -> None:
        self.server.record("S", line)
        self.wfile.write(line.encode("ascii") + b"\r\n")

    def _read_data(self) -> tuple[bytes, int, int, bool] | None:
        """Read DATA up to the lone "." line, undoing dot-stuffing (RFC 5321 4.5.2)."""
        chunks: list[bytes] = []
        size = lines = unstuffed = 0
        at_line_start = True
        while True:
            raw = self.rfile.readline(MAX_LINE + 1)
            if not raw:
                return None  # the client went away mid-message
            if at_line_start and raw in (b".\r\n", b".\n"):
                return b"".join(chunks), lines, unstuffed, size > MAX_MESSAGE_BYTES
            if at_line_start and raw.startswith(b"."):
                raw = raw[1:]
                unstuffed += 1
            at_line_start = raw.endswith(b"\n")
            lines += at_line_start
            size += len(raw)
            if size <= MAX_MESSAGE_BYTES:
                chunks.append(raw)

    def handle(self) -> None:
        server = self.server
        self._send(f"220 {server.name} ESMTP ACW1 local receiver (simulation)")
        helo: str | None = None
        mail_from: str | None = None
        rcpts: list[str] = []
        while True:
            raw = self.rfile.readline(MAX_LINE + 1)
            if not raw:
                return
            line = raw.rstrip(b"\r\n").decode("ascii", "replace")
            server.record("C", line)
            if not raw.endswith(b"\n"):
                self._send("500 5.5.2 Line too long")
                return
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            if verb == "EHLO":
                helo, mail_from, rcpts = arg.strip() or "unknown", None, []
                for reply in (
                    f"250-{server.name} greets {helo}",
                    f"250-SIZE {MAX_MESSAGE_BYTES}",
                    "250-8BITMIME",
                    "250 HELP",
                ):
                    self._send(reply)
            elif verb == "HELO":
                helo, mail_from, rcpts = arg.strip() or "unknown", None, []
                self._send(f"250 {server.name}")
            elif verb == "MAIL":
                match = re.fullmatch(r"FROM:\s*<([^>]*)>\s*(.*)", arg, re.IGNORECASE)
                size = re.search(r"\bSIZE=(\d+)", match.group(2), re.IGNORECASE) if match else None
                if helo is None:
                    self._send("503 5.5.1 Send HELO/EHLO first")
                elif not match:
                    self._send("501 5.5.4 Syntax: MAIL FROM:<address>")
                elif size and int(size.group(1)) > MAX_MESSAGE_BYTES:
                    self._send("552 5.3.4 Message size exceeds fixed limit")
                else:
                    mail_from, rcpts = match.group(1), []
                    self._send("250 2.1.0 Sender OK")
            elif verb == "RCPT":
                match = re.fullmatch(r"TO:\s*<([^>]+)>.*", arg, re.IGNORECASE)
                if mail_from is None:
                    self._send("503 5.5.1 Send MAIL first")
                elif not match:
                    self._send("501 5.5.4 Syntax: RCPT TO:<address>")
                elif match.group(1).lower() not in server.mailboxes:
                    self._send(f"550 5.1.1 <{match.group(1)}>: mailbox unavailable")
                else:
                    rcpts.append(match.group(1))
                    self._send("250 2.1.5 Recipient OK")
            elif verb == "DATA":
                if not rcpts:
                    self._send("503 5.5.1 Send RCPT first")
                    continue
                self._send("354 End data with <CR><LF>.<CR><LF>")
                result = self._read_data()
                if result is None:
                    return
                data, n_lines, unstuffed, too_big = result
                server.record(
                    "C",
                    f"[message data: {len(data):,} bytes in {n_lines:,} lines; "
                    f"{unstuffed} dot-stuffed line(s) restored]",
                )
                server.record("C", ".")
                if too_big:
                    self._send("552 5.3.4 Message size exceeds fixed limit")
                else:
                    queue_id = server.deliver(data, helo or "unknown", mail_from or "", rcpts)
                    self._send(f"250 2.0.0 OK: queued as {queue_id}")
                mail_from, rcpts = None, []
            elif verb == "RSET":
                mail_from, rcpts = None, []
                self._send("250 2.0.0 OK")
            elif verb == "NOOP":
                self._send("250 2.0.0 OK")
            elif verb == "QUIT":
                self._send(f"221 2.0.0 {server.name} closing connection")
                return
            else:
                self._send("502 5.5.2 Command not recognised")


class _SMTPServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, maildir: Path, mailboxes: tuple[str, ...], name: str) -> None:
        super().__init__(("127.0.0.1", 0), _SMTPHandler)
        self.name = name
        self.mailboxes = {address.lower() for address in mailboxes}
        self.maildir_path = Path(maildir)
        self.maildir_path.parent.mkdir(parents=True, exist_ok=True)  # Maildir(create=True) makes one level
        self.maildir = mailbox.Maildir(self.maildir_path, create=True)
        self.transcript: list[str] = []
        self.deliveries: list[dict] = []
        self._lock = threading.Lock()

    def record(self, who: str, line: str) -> None:
        with self._lock:
            self.transcript.append(f"{who}: {line}")

    def deliver(self, data: bytes, helo: str, mail_from: str, rcpts: list[str]) -> str:
        """File one message into the Maildir, with trace headers like a real MTA adds."""
        received_at = _now()
        queue_id = sha256(data)[:12].upper()
        trace = (
            f"Return-Path: <{mail_from}>\r\n"
            f"Delivered-To: {', '.join(rcpts)}\r\n"
            f"Received: from {helo} (localhost [127.0.0.1])\r\n"
            f"\tby {self.name} (ACW1 local SMTP receiver) with ESMTP id {queue_id}\r\n"
            f"\tfor <{rcpts[0]}>; {email.utils.format_datetime(received_at)}\r\n"
        ).encode("ascii")
        # A local delivery agent stores the host's newline, not SMTP's CRLF.
        stored = (trace + data).replace(b"\r\n", b"\n")
        key = self.maildir.add(stored)
        path = self.maildir_path / "new" / key
        with self._lock:
            self.deliveries.append(
                {
                    "queue_id": queue_id,
                    "maildir_key": key,
                    "path": path,
                    "received_at": _iso(received_at),
                    "mail_from": mail_from,
                    "rcpt_to": list(rcpts),
                    "smtp_data_bytes": len(data),
                    "stored_bytes": path.stat().st_size,
                }
            )
        return queue_id


class LocalSMTPReceiver:
    """A minimal SMTP receiver on 127.0.0.1 that delivers into a Maildir.

    Written with socketserver because smtpd left the standard library in
    Python 3.12 and aiosmtpd is not a project dependency. Single-threaded on
    purpose: one session at a time, so shutdown() returns only after the
    session in progress has finished.
    """

    def __init__(
        self, maildir: Path, mailboxes: tuple[str, ...] = (RECIPIENT,), name: str = SMTP_SERVER_NAME
    ):
        self._args = (Path(maildir), tuple(mailboxes), name)
        self._server: _SMTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> Self:
        self._server = _SMTPServer(*self._args)
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        assert self._server is not None and self._thread is not None
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def transcript(self) -> list[str]:
        return list(self._server.transcript)

    @property
    def deliveries(self) -> list[dict]:
        return list(self._server.deliveries)


def send_via_smtp(host: str, port: int, raw: bytes, sender: str = SENDER, recipient: str = RECIPIENT) -> dict:
    """Party A's mail client: one real SMTP session through smtplib."""
    with smtplib.SMTP(host, port, local_hostname=CLIENT_HELO_NAME, timeout=30) as client:
        ehlo_code, _ = client.ehlo()
        refused = client.sendmail(sender, [recipient], raw)
    return {"ehlo_code": ehlo_code, "refused_recipients": refused}


# --------------------------------------------------------------------------- email


def email_body(files: list[dict]) -> str:
    blocks = [
        "Hi Party B,",
        "",
        "Attached are two files protected with the ACW1 stego tool. Please save both",
        "attachments to your downloads folder, check each file's SHA-256 against the",
        "value below, and then verify each one in the Verify tab.",
    ]
    for record in files:
        blocks += [
            "",
            f"File:        {record['filename']}",
            f"Cover kind:  {record['kind']}",
            f"Media ID:    {record['media_id']}",
            f"LSB count:   {record['n_lsb']}",
            f"Start mode:  {record['start_mode']} (from the shared passphrase)",
            f"Size:        {record['size']} bytes",
            f"SHA-256:     {record['sha256']}",
        ]
    blocks += [
        "",
        "The passphrase and my public key's fingerprint are not in this email. I have",
        "shared both with you separately (out of band). Please confirm that the public",
        "key you verify with has the fingerprint I gave you before trusting a verdict.",
        "",
        "Party A",
    ]
    return "\n".join(blocks) + "\n"


def compose_email(files: list[dict], outbox: Path, sent_at: datetime) -> EmailMessage:
    message = EmailMessage()
    message["From"] = f"Party A <{SENDER}>"
    message["To"] = f"Party B <{RECIPIENT}>"
    message["Subject"] = SUBJECT
    message["Date"] = email.utils.format_datetime(sent_at)
    message["Message-ID"] = email.utils.make_msgid(idstring="acw1-transfer", domain="acw1.local")
    message.set_content(email_body(files))
    for record in files:
        message.add_attachment(
            (outbox / record["filename"]).read_bytes(),
            maintype=record["maintype"],
            subtype=record["subtype"],
            filename=record["filename"],
        )
    return message


_FIELD = re.compile(r"^(File|Cover kind|Media ID|LSB count|Start mode|Size|SHA-256):\s+(.+)$")


def parse_instructions(body: str) -> dict[str, dict[str, str]]:
    """Party B reads the per-file settings back out of the email body."""
    files: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in body.splitlines():
        match = _FIELD.match(line.strip())
        if not match:
            continue
        key, value = match.groups()
        if key == "File":
            current = files.setdefault(value.strip(), {})
        elif current is not None:
            current[key] = value.strip()
    return files


def _safe_filename(name: str | None) -> str | None:
    """Keep only a plain base name, so an attachment cannot escape downloads/."""
    if not name:
        return None
    base = Path(name.replace("\\", "/")).name
    return base if base and not base.startswith(".") else None


# --------------------------------------------------------------------------- stego steps


def _verify(
    data: bytes, kind: str, media_id: str, public_pem: bytes, passphrase: str | None
) -> pipeline.VerifyOutcome:
    return pipeline.verify(
        pipeline.VerifyOptions(
            stego_bytes=data,
            cover_kind=kind,
            public_key_pem=public_pem,
            n_lsb=N_LSB,
            media_id=media_id,
            passphrase=passphrase,
            explicit_start=None,  # derived start mode
        )
    )


def _recovered_message(outcome: pipeline.VerifyOutcome) -> bytes | None:
    if not outcome.message_decrypted or not outcome.payload_json:
        return None
    return base64.b64decode(outcome.payload_json["message_b64"])


def summarize(outcome: pipeline.VerifyOutcome, original_message: bytes | None = None) -> dict:
    hash_match = None
    if outcome.media_hash_embedded is not None and outcome.media_hash_recomputed is not None:
        hash_match = outcome.media_hash_embedded == outcome.media_hash_recomputed
    summary = {
        "verdict": outcome.verdict.value,
        "reasons": list(outcome.reasons),
        "signature_valid": outcome.signature_valid,
        "hash_match": hash_match,
        "media_hash_embedded": outcome.media_hash_embedded,
        "media_hash_recomputed": outcome.media_hash_recomputed,
        "start_offset_used": outcome.start_offset_used,
        "message_decrypted": outcome.message_decrypted,
        "decryption_error": outcome.decryption_error,
    }
    if original_message is not None:
        recovered = _recovered_message(outcome)
        summary["recovered_message_sha256"] = sha256(recovered) if recovered is not None else None
        summary["message_matches_original"] = recovered == original_message
    return summary


def flip_high_bit(data: bytes, kind: str) -> tuple[bytes, dict]:
    """Flip the most significant bit of one element: the centre pixel's red
    channel for a PNG, the middle sample for a WAV. It lies outside the 2-bit
    LSB plane, so the embedded frame survives and only the media hash can
    notice, which is the in-transit change this control is about."""
    if kind == "image":
        cover = image_codec.load_png(data)
        row, col = cover.height // 2, cover.width // 2
        index = (row * cover.width + col) * cover.channels  # channel 0 = red
        where = {"pixel_row": row, "pixel_col": col, "channel": "red"}
        save = image_codec.save_png
    elif kind == "audio":
        cover = audio_codec.load_wav(data)
        index = len(cover.elements) // 2
        where = {"sample_index": index}
        save = audio_codec.save_wav
    else:
        raise ValueError(f"unsupported kind: {kind!r}")
    elements = cover.elements.copy()
    bit = elements.dtype.itemsize * 8 - 1
    before = int(elements[index])
    elements[index] = before ^ (1 << bit)
    return save(cover, elements), {
        **where,
        "element_index": index,
        "bit_flipped": bit,
        "value_before": before,
        "value_after": int(elements[index]),
    }


# --------------------------------------------------------------------------- the run


@dataclass
class TransferResult:
    out: Path
    report: dict
    log_text: str
    all_passed: bool


def _reset_output(out: Path, private_key: Path) -> None:
    if out.resolve() in (ROOT, ROOT.parent, Path(out.resolve().anchor)):
        raise SystemExit(f"refusing to use {out} as the output folder")
    if private_key.resolve().is_relative_to(out.resolve()):
        raise SystemExit("the private key must not live inside the output folder")
    out.mkdir(parents=True, exist_ok=True)
    for name in GENERATED:
        path = out / name
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def run_transfer(
    out: Path = DEFAULT_OUT,
    *,
    image_cover: Path = DEFAULT_IMAGE_COVER,
    audio_cover: Path = DEFAULT_AUDIO_COVER,
    message_path: Path = DEFAULT_MESSAGE,
    private_key: Path = DEFAULT_PRIVATE_KEY,
    public_key: Path = DEFAULT_PUBLIC_KEY,
    passphrase: str = PASSPHRASE,
    regenerate_key: bool = False,
    echo: bool = True,
) -> TransferResult:
    out = Path(out)
    log = Log(echo)
    checks = Checks(log)
    _reset_output(out, Path(private_key))
    generated_at = _now()
    covers = {"image": Path(image_cover), "audio": Path(audio_cover)}
    message = Path(message_path).read_bytes()

    log("ACW1 party A -> party B transfer (LOCAL SIMULATION)")
    log("In-process SMTP on 127.0.0.1 + Maildir, standard library only; not a third-party mail provider.")
    log(f"generated_at: {_iso(generated_at)}")
    log(f"command:      {COMMAND}")
    log()

    # ---- keys ----------------------------------------------------------------------
    log("== Keys ==")
    private_pem, public_pem, key_generated = load_or_create_keys(
        Path(private_key), Path(public_key), regenerate=regenerate_key, log=log
    )
    fingerprint = signing.fingerprint(public_pem)
    log(f"public key:   {_display(public_key, out)}")
    log(f"fingerprint:  {fingerprint}")
    log(f"private key:  {_display(private_key, out)} (read locally; never copied into the output)")
    probe = b"acw1 transfer key-pair probe"
    checks.expect(
        "the private and public transfer keys form a pair",
        signing.verify(public_pem, probe, signing.sign(private_pem, probe)),
    )
    log()

    # ---- party A: protect ------------------------------------------------------------
    log("== Party A: protect ==")
    log(f"message: {_display(message_path, out)} ({len(message)} bytes, SHA-256 {sha256(message)})")
    log(f"settings: n_lsb={N_LSB}, start mode={START_MODE}, message encrypted with AES-256-GCM")
    outbox = out / "party-a" / "outbox"
    outbox.mkdir(parents=True)
    sent_files: list[dict] = []
    for item in ITEMS:
        cover_bytes = covers[item.kind].read_bytes()
        outcome = pipeline.protect(
            pipeline.ProtectOptions(
                cover_bytes=cover_bytes,
                cover_kind=item.kind,
                message=message,
                message_mime="text/plain",
                n_lsb=N_LSB,
                media_id=item.media_id,
                metadata={
                    "purpose": "ACW1 party A to party B transfer evidence",
                    "sender": SENDER,
                    "recipient": RECIPIENT,
                },
                private_key_pem=private_pem,
                passphrase=passphrase,
                explicit_start=None,  # derived: the offset comes from the passphrase
                encrypt_message=True,
            )
        )
        (outbox / item.filename).write_bytes(outcome.stego_bytes)
        self_check = summarize(_verify(outcome.stego_bytes, item.kind, item.media_id, public_pem, passphrase))
        record = {
            "kind": item.kind,
            "media_id": item.media_id,
            "filename": item.filename,
            "maintype": item.maintype,
            "subtype": item.subtype,
            "n_lsb": N_LSB,
            "start_mode": START_MODE,
            "cover": _display(covers[item.kind], out),
            "cover_size": len(cover_bytes),
            "cover_sha256": sha256(cover_bytes),
            "stego": _display(outbox / item.filename, out),
            "size": len(outcome.stego_bytes),
            "sha256": sha256(outcome.stego_bytes),
            "start_offset": outcome.start_offset,
            "frame_bytes": outcome.frame_bytes,
            "capacity_bytes": outcome.capacity_bytes,
            "payload_timestamp": outcome.payload_json["timestamp"],
            "payload_nonce": outcome.payload_json["nonce"],
            "message_encrypted": outcome.payload_json["encrypted"],
            "pre_send_verdict": self_check["verdict"],
        }
        sent_files.append(record)
        log(f"[{item.kind}] {record['cover']} ({record['cover_size']:,} bytes)")
        log(f"        -> {record['stego']} ({record['size']:,} bytes)")
        log(
            f"        media ID {item.media_id}, derived start offset {outcome.start_offset}, "
            f"frame {outcome.frame_bytes} bytes of {outcome.capacity_bytes:,} capacity"
        )
        log(f"        SHA-256 before sending: {record['sha256']}")
        checks.expect(
            f"{item.kind}: party A's own pre-send check is Authentic", self_check["verdict"] == "Authentic"
        )
        checks.expect(
            f"{item.kind}: the signed payload marks the message as encrypted", record["message_encrypted"]
        )
    log()

    # ---- party A: compose ------------------------------------------------------------
    log("== Party A: compose the email ==")
    sent_at = _now()
    mail = compose_email(sent_files, outbox, sent_at)
    raw = mail.as_bytes(policy=email.policy.SMTP)
    sent_eml = out / "party-a" / "sent.eml"
    sent_eml.write_bytes(raw)
    parts = [
        (part.get_content_type(), part.get_filename(), part["Content-Transfer-Encoding"])
        for part in mail.walk()
    ]
    for header in ("From", "To", "Subject", "Date", "Message-ID"):
        log(f"{header + ':':12} {mail[header]}")
    for content_type, filename, cte in parts:
        log(f"  part: {content_type:<22} {filename or '-':<28} {cte or '-'}")
    log(f"raw message: {_display(sent_eml, out)} ({len(raw):,} bytes, SHA-256 {sha256(raw)})")
    log("body as party B will read it:")
    for line in mail.get_body(preferencelist=("plain",)).get_content().splitlines():
        log(f"  | {line}")
    attachment_ctes = {filename: cte for _, filename, cte in parts if filename}
    checks.expect(
        "both attachments are base64-encoded MIME parts",
        [attachment_ctes.get(f["filename"]) for f in sent_files] == ["base64"] * len(sent_files),
    )
    checks.expect("the passphrase is not in the email", passphrase.encode() not in raw)
    checks.expect("the public key fingerprint is not in the email", fingerprint.encode() not in raw)
    log()

    # ---- transit ---------------------------------------------------------------------
    maildir_path = out / "party-b" / "Maildir"
    with LocalSMTPReceiver(maildir_path) as receiver:
        log(
            f"== SMTP session with {SMTP_SERVER_NAME} on {receiver.host}:{receiver.port} (receiver's record) =="
        )
        smtp_result = send_via_smtp(receiver.host, receiver.port, raw)
        endpoint = {"host": receiver.host, "port": receiver.port}
    transcript = receiver.transcript
    deliveries = receiver.deliveries
    for line in transcript:
        log(line)
    log(f"smtplib.sendmail refused recipients: {smtp_result['refused_recipients'] or 'none'}")
    checks.expect("SMTP accepted the message for party B", smtp_result["refused_recipients"] == {})
    checks.expect("exactly one message was delivered", len(deliveries) == 1)
    log()

    # ---- party B: receive ----------------------------------------------------------
    log("== Party B: open the mailbox and download the attachments ==")
    inbox = mailbox.Maildir(maildir_path, factory=None, create=False)
    keys = sorted(inbox.keys())
    checks.expect("party B's Maildir holds one message", len(keys) == 1, f"{len(keys)} found")
    received_raw = inbox.get_bytes(keys[0]) if keys else b""
    received = email.message_from_bytes(received_raw, policy=email.policy.default)
    delivery = deliveries[0] if deliveries else {}
    if delivery:
        log(f"stored at: {_display(delivery['path'], out)} ({delivery['stored_bytes']:,} bytes)")
    log(f"From: {received['From']}  To: {received['To']}")
    log(f"Subject: {received['Subject']}")
    log(f"Received: {' '.join(str(received['Received']).split())}")
    checks.expect(
        "the received Message-ID matches the sent one", received["Message-ID"] == mail["Message-ID"]
    )
    checks.expect(
        "the email came from party A",
        received["From"] is not None and received["From"].addresses[0].addr_spec == SENDER,
    )
    body = received.get_body(preferencelist=("plain",))
    instructions = parse_instructions(body.get_content() if body is not None else "")

    downloads = out / "party-b" / "downloads"
    downloads.mkdir(parents=True)
    received_files: dict[str, dict] = {}
    for part in received.iter_attachments():
        filename = _safe_filename(part.get_filename())
        if filename is None:
            continue
        data = part.get_content()
        (downloads / filename).write_bytes(data)
        received_files[filename] = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "content_transfer_encoding": part["Content-Transfer-Encoding"],
            "saved_to": _display(downloads / filename, out),
            "size": len(data),
            "sha256": sha256(data),
            "data": data,
        }
    checks.expect(
        "both attachments arrived",
        sorted(received_files) == sorted(f["filename"] for f in sent_files),
        ", ".join(sorted(received_files)),
    )
    log()

    # ---- party B: compare and verify -------------------------------------------------
    log("== Party B: SHA-256 comparison and verification ==")
    log(f"public key: {_display(public_key, out)} (fingerprint {fingerprint}, confirmed out of band)")
    log("passphrase: shared out of band")
    extracted_dir = out / "party-b" / "extracted"
    extracted_dir.mkdir(parents=True)
    party_b_files: list[dict] = []
    for sent in sent_files:
        item = next(i for i in ITEMS if i.filename == sent["filename"])
        got = received_files.get(sent["filename"])
        told = instructions.get(sent["filename"], {})
        log(f"[{item.kind}] {sent['filename']}")
        if got is None:
            checks.expect(f"{item.kind}: attachment received", False)
            continue
        data = got.pop("data")
        sent_bytes = (outbox / sent["filename"]).read_bytes()
        settings = {
            "media_id": told.get("Media ID"),
            "n_lsb": int(told["LSB count"]) if told.get("LSB count", "").isdigit() else None,
            "start_mode": told.get("Start mode", "").split(" ")[0] or None,
        }
        record = {
            **got,
            "expected_content_type": f"{item.maintype}/{item.subtype}",
            "sha256_party_a": sent["sha256"],
            "sha256_in_email": told.get("SHA-256"),
            "sha256_match": got["sha256"] == sent["sha256"],
            "bytes_identical": data == sent_bytes,
            "settings_from_email": settings,
        }
        log(
            f"        content type {got['content_type']}, transfer encoding {got['content_transfer_encoding']}"
        )
        log(f"        saved to {got['saved_to']} ({got['size']:,} bytes)")
        log(f"        SHA-256 party A (before): {sent['sha256']}")
        log(f"        SHA-256 in the email:     {told.get('SHA-256')}")
        log(f"        SHA-256 party B (after):  {got['sha256']}")
        checks.expect(
            f"{item.kind}: content type is {item.maintype}/{item.subtype}",
            got["content_type"] == f"{item.maintype}/{item.subtype}",
        )
        checks.expect(
            f"{item.kind}: SHA-256 after download equals party A's SHA-256 before sending",
            record["sha256_match"],
        )
        checks.expect(
            f"{item.kind}: SHA-256 equals the value stated in the email", got["sha256"] == told.get("SHA-256")
        )
        checks.expect(
            f"{item.kind}: downloaded bytes are identical to party A's file", record["bytes_identical"]
        )
        checks.expect(
            f"{item.kind}: the email states the settings party A used",
            settings == {"media_id": item.media_id, "n_lsb": N_LSB, "start_mode": START_MODE},
            json.dumps(settings),
        )

        outcome = _verify(data, item.kind, settings["media_id"] or "", public_pem, passphrase)
        result = summarize(outcome, message)
        result["start_offset_party_a"] = sent["start_offset"]
        record["verification"] = result
        recovered = _recovered_message(outcome)
        if recovered is not None:
            message_file = extracted_dir / f"{Path(sent['filename']).stem.removesuffix('.stego')}.message.txt"
            message_file.write_bytes(recovered)
            record["extracted_message"] = _display(message_file, out)
        log(
            f"        verify: {result['verdict']}; signature valid {result['signature_valid']}; "
            f"media hash match {result['hash_match']}; start offset {result['start_offset_used']}"
        )
        log(f"        media hash signed:     {result['media_hash_embedded']}")
        log(f"        media hash recomputed: {result['media_hash_recomputed']}")
        if recovered is not None:
            log(
                f"        recovered message -> {record['extracted_message']}: {recovered.decode('utf-8', 'replace')}"
            )
        checks.expect(f"{item.kind}: verdict is Authentic", outcome.verdict == Verdict.AUTHENTIC)
        checks.expect(f"{item.kind}: signature valid", result["signature_valid"] is True)
        checks.expect(
            f"{item.kind}: recomputed media hash matches the signed hash", result["hash_match"] is True
        )
        checks.expect(
            f"{item.kind}: frame found at party A's derived start offset",
            result["start_offset_used"] == sent["start_offset"],
        )
        checks.expect(
            f"{item.kind}: decrypted message equals the original",
            result["message_decrypted"] and result["message_matches_original"],
        )
        party_b_files.append(record)
    log()

    # ---- negative controls -----------------------------------------------------------
    log("== Negative controls ==")
    tampered_dir = out / "party-b" / "tampered"
    tampered_dir.mkdir(parents=True)
    controls: list[dict] = []
    for record in party_b_files:
        item = next(i for i in ITEMS if i.filename == record["filename"])
        data = (downloads / record["filename"]).read_bytes()

        wrong = summarize(_verify(data, item.kind, item.media_id, public_pem, WRONG_PASSPHRASE), message)
        controls.append(
            {
                "control": "wrong_passphrase",
                "kind": item.kind,
                "file": record["saved_to"],
                "passphrase_used": WRONG_PASSPHRASE,
                "expected": "not Authentic, message not decrypted",
                **wrong,
            }
        )
        log(f"[{item.kind}] wrong passphrase on {record['saved_to']}: {wrong['verdict']}")
        log(f"        {'; '.join(wrong['reasons'])}")
        checks.expect(
            f"{item.kind}: wrong passphrase is not Authentic",
            wrong["verdict"] != "Authentic",
            wrong["verdict"],
        )
        checks.expect(
            f"{item.kind}: wrong passphrase does not decrypt the message", not wrong["message_decrypted"]
        )

        altered, change = flip_high_bit(data, item.kind)
        altered_path = (
            tampered_dir
            / f"{Path(item.filename).stem.removesuffix('.stego')}.high-bit-flipped.{item.subtype}"
        )
        altered_path.write_bytes(altered)
        tampered = summarize(_verify(altered, item.kind, item.media_id, public_pem, passphrase), message)
        altered_sha = sha256(altered)
        controls.append(
            {
                "control": "high_bit_flip_in_transit",
                "kind": item.kind,
                "file": _display(altered_path, out),
                "change": change,
                "sha256": altered_sha,
                "sha256_matches_party_a": altered_sha == record["sha256_party_a"],
                "expected": "Tampered",
                **tampered,
            }
        )
        log(f"[{item.kind}] one high bit flipped ({json.dumps(change)}) -> {_display(altered_path, out)}")
        log(f"        SHA-256 {altered_sha} (party A sent {record['sha256_party_a']})")
        log(
            f"        verify: {tampered['verdict']}; signature valid {tampered['signature_valid']}; "
            f"media hash match {tampered['hash_match']}"
        )
        checks.expect(
            f"{item.kind}: altered copy no longer matches party A's SHA-256",
            altered_sha != record["sha256_party_a"],
        )
        checks.expect(
            f"{item.kind}: altered copy verifies as Tampered",
            tampered["verdict"] == "Tampered",
            tampered["verdict"],
        )
        checks.expect(
            f"{item.kind}: the signature still holds but the media hash differs",
            tampered["signature_valid"] is True and tampered["hash_match"] is False,
        )
    log()

    # ---- wrap up ---------------------------------------------------------------------
    log("== Result ==")
    leaks = private_key_leaks(out, private_pem)
    checks.expect("no private key material in the output folder", not leaks, ", ".join(leaks))
    passed = sum(item["passed"] for item in checks.items)
    log(f"{'PASS' if checks.all_passed else 'FAIL'}: {passed}/{len(checks.items)} checks passed")

    for delivery_record in deliveries:
        delivery_record["path"] = _display(delivery_record["path"], out)
    report = {
        "title": "ACW1 party A -> party B transfer (local email simulation)",
        "scope": (
            "LOCAL SIMULATION. Party A's smtplib client delivers an RFC 5322 email with base64 MIME "
            "attachments over SMTP to an in-process receiver on 127.0.0.1, which files it into party "
            "B's Maildir. No third-party mail provider is involved. The real two-machine email "
            "transfer is performed live during the demo (docs/demo-plan.md row 6)."
        ),
        "command": COMMAND,
        "generated_at": _iso(generated_at),
        "all_passed": checks.all_passed,
        "summary": {"checks_total": len(checks.items), "checks_passed": passed},
        "settings": {
            "n_lsb": N_LSB,
            "start_mode": START_MODE,
            "encrypt_message": True,
            "passphrase": f"{passphrase} (demo-only; shared out of band, never in the email)",
            "wrong_passphrase_control": WRONG_PASSPHRASE,
            "message_file": _display(message_path, out),
            "message_bytes": len(message),
            "message_sha256": sha256(message),
        },
        "keys": {
            "public_key": _display(public_key, out),
            "fingerprint": fingerprint,
            "private_key_location": f"{_display(private_key, out)} (gitignored; never copied into this folder)",
            "generated_this_run": key_generated,
        },
        "party_a": {"sent_at": _iso(sent_at), "files": sent_files},
        "email": {
            "from": str(mail["From"]),
            "to": str(mail["To"]),
            "subject": str(mail["Subject"]),
            "date": str(mail["Date"]),
            "message_id": str(mail["Message-ID"]),
            "raw_file": _display(sent_eml, out),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "parts": [
                {"content_type": ct, "filename": fn, "content_transfer_encoding": cte}
                for ct, fn, cte in parts
            ],
        },
        "smtp": {
            **endpoint,
            "server_name": SMTP_SERVER_NAME,
            "client_helo": CLIENT_HELO_NAME,
            "refused_recipients": smtp_result["refused_recipients"],
            "transcript": transcript,
            "deliveries": deliveries,
        },
        "party_b": {
            "maildir": _display(maildir_path, out),
            "received_headers": {
                "return_path": str(received["Return-Path"]),
                "delivered_to": str(received["Delivered-To"]),
                "received": " ".join(str(received["Received"]).split()),
            },
            "files": party_b_files,
        },
        "negative_controls": controls,
        "checks": checks.items,
    }
    (out / "transfer-report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out / "transfer-log.txt").write_text(log.text(), encoding="utf-8")

    # Belt and braces: the report and log were written after the scan above.
    late_leaks = private_key_leaks(out, private_pem)
    all_passed = checks.all_passed and not late_leaks
    if late_leaks:
        print(f"FAIL: private key material found in {', '.join(late_leaks)}", file=sys.stderr)
    return TransferResult(out=out, report=report, log_text=log.text(), all_passed=all_passed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Party A -> party B local email transfer evidence (FR11/FR12)."
    )
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT, help="output folder (default: evidence/transfer)"
    )
    parser.add_argument(
        "--regenerate-key",
        action="store_true",
        help="create a new transfer key pair even if one exists (rewrites keys/public/transfer-demo.pub.pem)",
    )
    args = parser.parse_args(argv)
    result = run_transfer(args.out, regenerate_key=args.regenerate_key)
    print(
        f"\nwrote {_display(result.out / 'transfer-report.json', ROOT)} and {_display(result.out / 'transfer-log.txt', ROOT)}"
    )
    return 0 if result.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
