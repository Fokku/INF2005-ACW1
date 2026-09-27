"""End-to-end tests for the `stego` CLI (spec FR12 rescue path).

Drives `stego_core.cli.main` directly (no subprocess) against real PNG/WAV
covers, exercising the same pipeline the GUI and API use.
"""

from __future__ import annotations

import json
import wave

import numpy as np
import pytest
from PIL import Image

from stego_core import cli, signing


def _write_png(path) -> None:
    rng = np.random.default_rng(0)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    Image.fromarray(arr, mode="RGB").save(path)


def _write_wav(path) -> None:
    rng = np.random.default_rng(1)
    samples = rng.integers(-1000, 1000, size=8000, dtype=np.int16)
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(samples.tobytes())


@pytest.fixture
def cover_png(tmp_path):
    path = tmp_path / "cover.png"
    _write_png(path)
    return path


@pytest.fixture
def cover_wav(tmp_path):
    path = tmp_path / "cover.wav"
    _write_wav(path)
    return path


@pytest.fixture
def keys(tmp_path):
    out = tmp_path / "keys"
    assert cli.main(["keygen", "--out", str(out), "--label", "test"]) == 0
    private = out / "private" / "test_ed25519.pem"
    public = out / "public" / "test_ed25519.pub.pem"
    assert private.exists()
    assert public.exists()
    return private, public


def test_keygen_writes_pem_pair(tmp_path):
    out = tmp_path / "keys"
    assert cli.main(["keygen", "--out", str(out), "--label", "demo"]) == 0
    private_pem = (out / "private" / "demo_ed25519.pem").read_bytes()
    public_pem = (out / "public" / "demo_ed25519.pub.pem").read_bytes()
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_capacity_reports_bounds_for_png(cover_png, capsys):
    assert cli.main(["capacity", "--cover", str(cover_png), "--lsb", "2"]) == 0
    out = capsys.readouterr().out
    assert "cover kind:            image" in out
    assert "n_lsb:                 2" in out


def test_capacity_rejects_unknown_extension(tmp_path):
    bogus = tmp_path / "cover.bmp"
    bogus.write_bytes(b"not a real cover")
    assert cli.main(["capacity", "--cover", str(bogus), "--lsb", "1"]) == 2


def test_protect_then_verify_roundtrip_authentic(cover_png, keys, tmp_path):
    private, public = keys
    message = tmp_path / "message.txt"
    message.write_text("hello from the CLI roundtrip test")
    stego = tmp_path / "stego.png"

    assert (
        cli.main(
            [
                "protect",
                "--cover",
                str(cover_png),
                "--message",
                str(message),
                "--lsb",
                "2",
                "--media-id",
                "cli-test-1",
                "--key",
                str(private),
                "--start",
                "16",
                "--out",
                str(stego),
            ]
        )
        == 0
    )
    assert stego.exists()

    exit_code = cli.main(
        [
            "verify",
            "--stego",
            str(stego),
            "--pub",
            str(public),
            "--lsb",
            "2",
            "--media-id",
            "cli-test-1",
            "--start",
            "16",
        ]
    )
    assert exit_code == 0


def test_verify_reports_nonzero_for_wrong_key(cover_wav, keys, tmp_path):
    private, _public = keys
    other_public_pem = tmp_path / "other.pub.pem"
    _, wrong_pub_bytes = signing.generate_keypair()
    other_public_pem.write_bytes(wrong_pub_bytes)

    message = tmp_path / "message.txt"
    message.write_text("audio roundtrip message")
    stego = tmp_path / "stego.wav"

    assert (
        cli.main(
            [
                "protect",
                "--cover",
                str(cover_wav),
                "--message",
                str(message),
                "--lsb",
                "1",
                "--media-id",
                "cli-test-2",
                "--key",
                str(private),
                "--start",
                "8",
                "--out",
                str(stego),
            ]
        )
        == 0
    )

    exit_code = cli.main(
        [
            "verify",
            "--stego",
            str(stego),
            "--pub",
            str(other_public_pem),
            "--lsb",
            "1",
            "--media-id",
            "cli-test-2",
            "--start",
            "8",
        ]
    )
    assert exit_code == 1


def test_tamper_flip_bits_then_verify_reports_tampered(cover_png, keys, tmp_path):
    private, public = keys
    message = tmp_path / "message.txt"
    message.write_text("tamper me")
    stego = tmp_path / "stego.png"
    tampered = tmp_path / "tampered.png"

    assert (
        cli.main(
            [
                "protect",
                "--cover",
                str(cover_png),
                "--message",
                str(message),
                "--lsb",
                "2",
                "--media-id",
                "cli-test-3",
                "--key",
                str(private),
                "--start",
                "16",
                "--out",
                str(stego),
            ]
        )
        == 0
    )

    assert (
        cli.main(
            [
                "tamper",
                "--stego",
                str(stego),
                "--attack",
                "flip_bits",
                "--lsb",
                "2",
                "--start",
                "16",
                "--out",
                str(tampered),
            ]
        )
        == 0
    )
    assert tampered.exists()

    exit_code = cli.main(
        [
            "verify",
            "--stego",
            str(tampered),
            "--pub",
            str(public),
            "--lsb",
            "2",
            "--media-id",
            "cli-test-3",
            "--start",
            "16",
        ]
    )
    assert exit_code == 1


def test_tamper_replay_requires_other_cover(cover_png, tmp_path):
    exit_code = cli.main(
        [
            "tamper",
            "--stego",
            str(cover_png),
            "--attack",
            "replay",
            "--out",
            str(tmp_path / "out.png"),
        ]
    )
    assert exit_code == 2


# --------------------------------------------------------------------------- #
# keygen must not silently replace a key pair (the committed team key)
# --------------------------------------------------------------------------- #


def test_keygen_refuses_to_overwrite_an_existing_pair(tmp_path, capsys):
    out = tmp_path / "keys"
    assert cli.main(["keygen", "--out", str(out), "--label", "demo"]) == 0
    private = out / "private" / "demo_ed25519.pem"
    public = out / "public" / "demo_ed25519.pub.pem"
    before = private.read_bytes(), public.read_bytes()
    capsys.readouterr()

    assert cli.main(["keygen", "--out", str(out), "--label", "demo"]) == 2
    err = capsys.readouterr().err
    assert "refusing to overwrite" in err
    assert "--force" in err
    assert (private.read_bytes(), public.read_bytes()) == before

    assert cli.main(["keygen", "--out", str(out), "--label", "demo", "--force"]) == 0
    assert private.read_bytes() != before[0]
    assert public.read_bytes() != before[1]


def test_keygen_default_label_keeps_the_committed_team_public_key(tmp_path, capsys):
    """The repo ships keys/public/team_ed25519.pub.pem without its private key;
    a teammate running the one-time setup must not clobber it.
    """
    out = tmp_path / "keys"
    committed = out / "public" / "team_ed25519.pub.pem"
    committed.parent.mkdir(parents=True)
    _, team_public = signing.generate_keypair()
    committed.write_bytes(team_public)

    assert cli.main(["keygen", "--out", str(out)]) == 2
    assert str(committed) in capsys.readouterr().err
    assert committed.read_bytes() == team_public
    assert not (out / "private" / "team_ed25519.pem").exists()


# --------------------------------------------------------------------------- #
# tamper: --sealed needs --start, and --copies reaches every embedded copy
# --------------------------------------------------------------------------- #


def _write_other_png(path) -> None:
    rng = np.random.default_rng(7)
    Image.fromarray(rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8), mode="RGB").save(path)


@pytest.mark.parametrize("attack", ["corrupt_payload", "replay"])
def test_tamper_sealed_requires_start(attack, cover_png, tmp_path, capsys):
    """A key-less attack at a guessed start would write an undamaged file and
    still print 'expected verdict: Tampered'; refuse instead.
    """
    other = tmp_path / "other.png"
    _write_other_png(other)
    out = tmp_path / "out.png"
    argv = ["tamper", "--stego", str(cover_png), "--attack", attack, "--lsb", "2", "--sealed"]
    argv += ["--out", str(out)]
    if attack == "replay":
        argv += ["--other-cover", str(other)]
    assert cli.main(argv) == 2
    assert "--start" in capsys.readouterr().err
    assert not out.exists()


def test_tamper_rejects_an_even_copy_count(cover_png, tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main(
            ["tamper", "--stego", str(cover_png), "--attack", "corrupt_payload", "--copies", "2"]
            + ["--out", str(tmp_path / "out.png")]
        )
    assert exc.value.code == 2


@pytest.mark.parametrize("attack", ["corrupt_payload", "replay"])
@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
def test_tamper_with_copies_then_verify_reports_tampered(attack, sealed, cover_png, keys, tmp_path, capsys):
    private, public = keys
    message = tmp_path / "message.txt"
    message.write_text("three copies, all attacked")
    stego = tmp_path / "stego.png"
    base = ["--lsb", "2", "--media-id", "cli-copies", "--passphrase", "cli copies", "--copies", "3"]
    seal = ["--seal"] if sealed else []
    assert (
        cli.main(
            ["protect", "--cover", str(cover_png), "--message", str(message), "--key", str(private)]
            + ["--start", "16", "--out", str(stego), *seal, *base]
        )
        == 0
    )
    assert "copies:       3" in capsys.readouterr().out
    assert cli.main(["verify", "--stego", str(stego), "--pub", str(public), "--start", "16", *base]) == 0
    capsys.readouterr()

    tampered = tmp_path / "tampered.png"
    argv = ["tamper", "--stego", str(stego), "--attack", attack, "--lsb", "2", "--start", "16"]
    argv += ["--copies", "3", "--out", str(tampered)] + (["--sealed"] if sealed else [])
    if attack == "replay":
        other = tmp_path / "other.png"
        _write_other_png(other)
        argv += ["--other-cover", str(other)]
    assert cli.main(argv) == 0
    assert "expected verdict: Tampered" in capsys.readouterr().out

    assert cli.main(["verify", "--stego", str(tampered), "--pub", str(public), "--start", "16", *base]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "Tampered"
    assert report["sealed"] is sealed
