"""Party A -> party B transfer evidence (spec Section 5, FR11/FR12).

Runs scripts/transfer_demo.py's whole local email round trip (protect, MIME
email, SMTP to a 127.0.0.1 receiver, Maildir, download, verify) into a
temporary folder with a throwaway key pair, so it never touches keys/ or
evidence/. About one second on the real sample covers.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import importlib.util
import mailbox
import smtplib
import sys
from pathlib import Path

import pytest

from stego_core import pipeline
from stego_core.verdict import Verdict

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "transfer_demo.py"


@pytest.fixture(scope="module")
def transfer_demo():
    spec = importlib.util.spec_from_file_location("transfer_demo", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(scope="module")
def run(transfer_demo, tmp_path_factory):
    base = tmp_path_factory.mktemp("transfer")
    keys = base / "keys"
    result = transfer_demo.run_transfer(
        base / "out",
        private_key=keys / "private" / "transfer.pem",
        public_key=keys / "public" / "transfer.pub.pem",
        echo=False,
    )
    return result, keys / "public" / "transfer.pub.pem"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_every_check_passes(run):
    result, _ = run
    failed = [item for item in result.report["checks"] if not item["passed"]]
    assert result.all_passed, failed
    assert result.report["all_passed"] is True
    assert (result.out / "transfer-report.json").is_file()
    assert (result.out / "transfer-log.txt").is_file()


def test_email_carries_base64_attachments(run):
    result, _ = run
    raw = (result.out / "party-a" / "sent.eml").read_bytes()
    message = email.message_from_bytes(raw, policy=email.policy.default)
    attachments = {part.get_filename(): part for part in message.iter_attachments()}
    assert set(attachments) == {"transfer-image.stego.png", "transfer-audio.stego.wav"}
    assert attachments["transfer-image.stego.png"].get_content_type() == "image/png"
    assert attachments["transfer-audio.stego.wav"].get_content_type() == "audio/wav"
    assert all(part["Content-Transfer-Encoding"] == "base64" for part in attachments.values())
    assert b"acw1-demo-passphrase-2026" not in raw  # shared out of band only


def test_sha256_matches_on_both_sides(run):
    result, _ = run
    out = result.out
    for name in ("transfer-image.stego.png", "transfer-audio.stego.wav"):
        sent = out / "party-a" / "outbox" / name
        received = out / "party-b" / "downloads" / name
        assert _sha256(received) == _sha256(sent)
        assert received.read_bytes() == sent.read_bytes()
    for record in result.report["party_b"]["files"]:
        assert record["sha256"] == record["sha256_party_a"] == record["sha256_in_email"]
        assert record["sha256_match"] is True and record["bytes_identical"] is True


def test_received_files_verify_authentic_with_public_key(run):
    """Re-verify the downloaded files here rather than trusting the report."""
    result, public_key = run
    public_pem = public_key.read_bytes()
    message = (ROOT / "samples" / "payloads" / "custom.txt").read_bytes()
    for kind, name in (("image", "transfer-image.stego.png"), ("audio", "transfer-audio.stego.wav")):
        outcome = pipeline.verify(
            pipeline.VerifyOptions(
                stego_bytes=(result.out / "party-b" / "downloads" / name).read_bytes(),
                cover_kind=kind,
                public_key_pem=public_pem,
                n_lsb=2,
                media_id=f"P-transfer-{kind}",
                passphrase="acw1-demo-passphrase-2026",
            )
        )
        assert outcome.verdict == Verdict.AUTHENTIC, outcome.reasons
        assert outcome.signature_valid is True
        assert outcome.media_hash_embedded == outcome.media_hash_recomputed
        assert outcome.message_decrypted is True
    extracted = result.out / "party-b" / "extracted"
    assert (extracted / "transfer-image.message.txt").read_bytes() == message
    assert (extracted / "transfer-audio.message.txt").read_bytes() == message


def test_high_bit_flip_in_transit_is_tampered(run):
    result, public_key = run
    tampered = result.out / "party-b" / "tampered" / "transfer-image.high-bit-flipped.png"
    outcome = pipeline.verify(
        pipeline.VerifyOptions(
            stego_bytes=tampered.read_bytes(),
            cover_kind="image",
            public_key_pem=public_key.read_bytes(),
            n_lsb=2,
            media_id="P-transfer-image",
            passphrase="acw1-demo-passphrase-2026",
        )
    )
    assert outcome.verdict == Verdict.TAMPERED
    assert outcome.signature_valid is True
    assert outcome.media_hash_embedded != outcome.media_hash_recomputed
    controls = {(c["control"], c["kind"]): c for c in result.report["negative_controls"]}
    for kind in ("image", "audio"):
        flip = controls[("high_bit_flip_in_transit", kind)]
        assert flip["verdict"] == "Tampered" and flip["sha256_matches_party_a"] is False
        wrong = controls[("wrong_passphrase", kind)]
        assert wrong["verdict"] != "Authentic" and wrong["message_decrypted"] is False


def test_no_private_key_material_in_output(run, transfer_demo, tmp_path):
    result, _ = run
    for path in result.out.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path
    leaky = tmp_path / "leaky"
    leaky.mkdir()
    (leaky / "oops.txt").write_bytes(b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
    assert transfer_demo.private_key_leaks(leaky, b"irrelevant") == ["oops.txt"]


def test_smtp_receiver_unstuffs_dots_and_refuses_unknown_mailboxes(transfer_demo, tmp_path):
    raw = (
        b"From: a@acw1.local\r\nTo: party-b@acw1.local\r\nSubject: dots\r\n\r\n"
        b".leading dot survives\r\n..two dots survive\r\nplain line\r\n"
    )
    maildir = tmp_path / "Maildir"
    with transfer_demo.LocalSMTPReceiver(maildir) as receiver:
        transfer_demo.send_via_smtp(receiver.host, receiver.port, raw)
        with pytest.raises(smtplib.SMTPRecipientsRefused):
            transfer_demo.send_via_smtp(receiver.host, receiver.port, raw, recipient="nobody@acw1.local")
    inbox = mailbox.Maildir(maildir, factory=None)
    stored = [inbox.get_bytes(key) for key in inbox.iterkeys()]
    assert len(stored) == 1
    assert stored[0].endswith(b"\n\n.leading dot survives\n..two dots survive\nplain line\n")
    assert any("2 dot-stuffed line(s) restored" in line for line in receiver.transcript)


def test_existing_public_key_without_private_half_is_refused(transfer_demo, tmp_path):
    """Never silently replace a committed public key (the team-key trap)."""
    public = tmp_path / "public.pem"
    public.write_bytes(b"committed public key")
    with pytest.raises(SystemExit):
        transfer_demo.load_or_create_keys(tmp_path / "missing.pem", public)
    assert public.read_bytes() == b"committed public key"
