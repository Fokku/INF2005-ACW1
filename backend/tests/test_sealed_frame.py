"""Sealed frames (optional challenge "advanced start-location security").

Owner: Yeo Kai Yuan. Design: docs/design/start-location.md, section 7.

A sealed frame is nonce || AES-256-CTR(K_seal, frame). These tests cover the
primitives, the full protect -> verify workflow for every cover kind and
option that sealing has to coexist with, the verdicts an attacker or a wrong
key produces, and the honest limitations (key-less bit flipping, crop in
derived mode).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import zlib
from pathlib import Path

import numpy as np
import pytest
from PIL import Image
from test_video_codec import _build_avi

from stego_core import (
    attacks,
    audio_codec,
    cli,
    container,
    extraction,
    image_codec,
    kdf,
    location,
    lsb,
    pipeline,
    sealing,
    signing,
    video_codec,
)
from stego_core.errors import CapacityError, FrameError, StegoError
from stego_core.verdict import Verdict

MEDIA_ID = "sealed-demo"
PASSPHRASE = "correct horse battery staple"
MESSAGE = b"Sealed frames leave no plaintext magic, header or JSON in the LSB plane."
N_LSB = 2
NOT_FOUND = (Verdict.PAYLOAD_MISSING, Verdict.CANNOT_VERIFY)
_LOAD = {"image": image_codec.load_png, "audio": audio_codec.load_wav, "video": video_codec.load_avi}


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


@pytest.fixture(scope="module")
def other_keys():
    return signing.generate_keypair()


def _png(size: int = 64, seed: int = 11) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (size, size, 3), dtype=np.uint8), mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


def _cover(kind: str, wav_16_stereo: bytes) -> bytes:
    if kind == "image":
        return _png()
    if kind == "audio":
        return wav_16_stereo
    rng = np.random.default_rng(12)
    return _build_avi(rng.integers(0, 65536, 16000, dtype=np.uint16).tobytes())


def _protect(cover: bytes, kind: str, keys, **overrides) -> pipeline.ProtectOutcome:
    opts = {
        "cover_bytes": cover,
        "cover_kind": kind,
        "message": MESSAGE,
        "message_mime": "text/plain",
        "n_lsb": N_LSB,
        "media_id": MEDIA_ID,
        "metadata": {"team": "ACW1"},
        "private_key_pem": keys[0],
        "passphrase": PASSPHRASE,
        "seal_frame": True,
    }
    opts.update(overrides)
    return pipeline.protect(pipeline.ProtectOptions(**opts))


def _verify(stego: bytes, kind: str, public_pem: bytes, **overrides) -> pipeline.VerifyOutcome:
    opts = {
        "stego_bytes": stego,
        "cover_kind": kind,
        "public_key_pem": public_pem,
        "n_lsb": N_LSB,
        "media_id": MEDIA_ID,
        "passphrase": PASSPHRASE,
    }
    opts.update(overrides)
    return pipeline.verify(pipeline.VerifyOptions(**opts))


def _elements(stego: bytes, kind: str) -> np.ndarray:
    return _LOAD[kind](stego).elements


def _embedded_region(stego: bytes, kind: str, outcome: pipeline.ProtectOutcome) -> bytes:
    """The bytes actually written at the start (redundancy 1 layout)."""
    bits = lsb.extract_bits(_elements(stego, kind), outcome.start_offset, outcome.frame_bytes * 8, N_LSB)
    return lsb.bits_to_bytes(bits)


def _k_seal(media_id: str = MEDIA_ID, passphrase: str = PASSPHRASE) -> bytes:
    return kdf.derive_keys(passphrase, hashlib.sha256(media_id.encode("utf-8")).digest()).k_seal


# --------------------------------------------------------------------------- #
# Key derivation: K_seal is new, K_loc / K_enc must not move
# --------------------------------------------------------------------------- #

# Computed from kdf.derive_keys BEFORE K_seal existed. Every existing stego
# file's derived start (K_loc) and encrypted message (K_enc) depends on these.
PINNED_KEYS = [
    (
        "correct horse battery staple",
        "pin-media-001",
        "e0e5fcb75efa7f64162fbe4792a6fa25d8a3eda4e7b3b2613c5aeea31eba4f24",
        "e597209b7d0f8cd78cd2cf4b2d39157e50f1bd5288a266759a1bb1ac40f17b76",
    ),
    (
        "section f",
        "section-f",
        "568a6ef17c22ba995a57106209e08513020f9312acf097da6862d87d4fd4dc12",
        "625723452ae501c6c05a66d395522281275a26a3f9f22b7834decf726487d1cb",
    ),
]


@pytest.mark.parametrize("passphrase,media_id,k_loc_hex,k_enc_hex", PINNED_KEYS)
def test_adding_k_seal_leaves_k_loc_and_k_enc_byte_identical(passphrase, media_id, k_loc_hex, k_enc_hex):
    derived = kdf.derive_keys(passphrase, hashlib.sha256(media_id.encode("utf-8")).digest())
    assert derived.k_loc.hex() == k_loc_hex
    assert derived.k_enc.hex() == k_enc_hex
    assert len(derived.k_seal) == 32
    assert derived.k_seal not in (derived.k_loc, derived.k_enc)


REPO = Path(__file__).resolve().parents[2]
SAMPLE_PASSPHRASE = "acw1-demo-passphrase-2026"  # scripts/make_samples.py, demo-only


@pytest.mark.parametrize(
    "kind,name,explicit_start",
    [
        ("image", "image-derived-start.stego.png", None),  # depends on K_loc
        ("audio", "audio-derived-start.stego.wav", None),
        ("image", "image-custom.stego.png", 128),  # encrypted message: depends on K_enc
        ("audio", "audio-custom.stego.wav", 128),
    ],
)
def test_committed_samples_still_verify_after_adding_k_seal(kind, name, explicit_start):
    path = REPO / "samples" / kind / "stego" / name
    if not path.exists():
        pytest.skip(f"sample not present: {path}")
    media_id = f"P6-8-{kind}-derived" if explicit_start is None else f"P6-8-{kind}-custom"
    result = pipeline.verify(
        pipeline.VerifyOptions(
            path.read_bytes(),
            kind,
            (REPO / "keys/public/team_ed25519.pub.pem").read_bytes(),
            2,
            media_id,
            passphrase=SAMPLE_PASSPHRASE,
            explicit_start=explicit_start,
        )
    )
    assert result.verdict == Verdict.AUTHENTIC, result.reasons
    assert result.sealed is False
    if explicit_start is not None:
        assert result.message_decrypted is True


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #


def test_seal_round_trip_and_prefix_decrypt():
    key = bytes(range(32))
    frame = container.build_frame(b'{"x":1}', bytes(64), 2, False)
    sealed = sealing.seal(key, frame)
    assert len(sealed) == sealing.sealed_size(len(frame)) == len(frame) + 12
    assert container.MAGIC not in sealed
    assert sealing.unseal(key, sealed) == frame
    # CTR: the header opens on its own, before the verifier knows any length.
    header_prefix = sealed[: sealing.NONCE_SIZE + container.HEADER_SIZE]
    assert sealing.unseal(key, header_prefix) == frame[: container.HEADER_SIZE]


def test_every_seal_draws_a_fresh_nonce():
    """Same key and frame (reused passphrase + media ID) never reuse a keystream."""
    key = bytes(32)
    frame = container.build_frame(b'{"x":1}', bytes(64), 2, False)
    a, b = sealing.seal(key, frame), sealing.seal(key, frame)
    assert a[: sealing.NONCE_SIZE] != b[: sealing.NONCE_SIZE]
    assert a[sealing.NONCE_SIZE :] != b[sealing.NONCE_SIZE :]


def test_wrong_key_opens_to_noise_and_bad_inputs_are_rejected():
    frame = container.build_frame(b'{"x":1}', bytes(64), 2, False)
    sealed = sealing.seal(bytes(32), frame, nonce=bytes(12))
    assert sealing.unseal(b"\x01" * 32, sealed)[:4] != container.MAGIC
    with pytest.raises(FrameError):
        sealing.unseal(bytes(32), b"short")
    with pytest.raises(ValueError):
        sealing.seal(bytes(16), frame)
    with pytest.raises(ValueError):
        sealing.seal(bytes(32), frame, nonce=bytes(8))


def test_extract_sealed_frame_never_trusts_decrypted_lengths():
    """A header claiming a 4 GiB payload must fail the bounds check, not allocate."""
    key = _k_seal()
    head = container._HEADER_STRUCT.pack(container.MAGIC, 1, 0, N_LSB, 0xFFFFFFFF, signing.SIGNATURE_BYTES)
    sealed = sealing.seal(key, head)
    elements = np.zeros(4096, dtype=np.uint8)
    elements = lsb.embed_bits(elements, lsb.bytes_to_bits(sealed), 5, N_LSB)
    assert extraction.sealed_frame_at(elements, 5, N_LSB, key)
    with pytest.raises(FrameError, match="past the end"):
        extraction.extract_sealed_frame(elements, 5, N_LSB, key)
    # A header block that does not fit is "no sealed frame here", not a crash.
    assert not extraction.sealed_frame_at(elements, len(elements) - 3, N_LSB, key)


# --------------------------------------------------------------------------- #
# Round trips
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("redundancy", [1, 3])
@pytest.mark.parametrize("encrypt", [False, True], ids=["plain-msg", "encrypted-msg"])
@pytest.mark.parametrize("start", [None, 137], ids=["derived", "explicit"])
@pytest.mark.parametrize("kind", ["image", "audio"])
def test_sealed_round_trip_is_authentic(kind, start, encrypt, redundancy, keys, wav_16_stereo):
    cover = _cover(kind, wav_16_stereo)
    protected = _protect(
        cover, kind, keys, explicit_start=start, encrypt_message=encrypt, redundancy=redundancy
    )
    assert protected.sealed is True
    payload_bytes = json.dumps(
        protected.payload_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    frame_len = container.frame_size_bytes(len(payload_bytes), signing.SIGNATURE_BYTES)
    assert protected.frame_bytes == frame_len + sealing.NONCE_SIZE

    result = _verify(protected.stego_bytes, kind, keys[1], explicit_start=start, redundancy=redundancy)
    assert result.verdict == Verdict.AUTHENTIC, result.reasons
    assert result.sealed is True
    assert result.start_offset_used == protected.start_offset
    assert result.message_decrypted is encrypt
    # verify swaps in the decrypted plaintext when it can, so both cases read back MESSAGE.
    assert base64.b64decode(result.payload_json["message_b64"]) == MESSAGE


def test_sealed_video_round_trip(keys, wav_16_stereo):
    cover = _cover("video", wav_16_stereo)
    protected = _protect(cover, "video", keys, explicit_start=40)
    result = _verify(protected.stego_bytes, "video", keys[1], explicit_start=40)
    assert result.verdict == Verdict.AUTHENTIC, result.reasons
    assert result.sealed is True


@pytest.mark.parametrize("kind", ["image", "audio"])
def test_no_plaintext_structure_anywhere_in_the_lsb_plane(kind, keys, wav_16_stereo):
    cover = _cover(kind, wav_16_stereo)
    protected = _protect(cover, kind, keys, explicit_start=137)
    elements = _elements(protected.stego_bytes, kind)
    # Every element-aligned position at this LSB depth, not just the first 200k.
    assert location.scan_for_magic(elements, N_LSB, max_positions=len(elements)) is None
    region = _embedded_region(protected.stego_bytes, kind, protected)
    for marker in (container.MAGIC, b'"media_id"', MEDIA_ID.encode(), b"message_b64", MESSAGE[:16]):
        assert marker not in region
    # ...and yet the right key opens exactly the frame protect built.
    frame = sealing.unseal(_k_seal(), region)
    assert frame[:4] == container.MAGIC
    assert container.parse_frame(frame)[0] == json.dumps(
        protected.payload_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_unsealed_files_still_report_a_plaintext_frame(keys):
    protected = _protect(_png(), "image", keys, seal_frame=False, explicit_start=137)
    assert protected.sealed is False
    elements = _elements(protected.stego_bytes, "image")
    assert location.scan_for_magic(elements, N_LSB) == 137
    result = _verify(protected.stego_bytes, "image", keys[1], explicit_start=137)
    assert result.verdict == Verdict.AUTHENTIC
    assert result.sealed is False
    wrong_start = _verify(protected.stego_bytes, "image", keys[1], explicit_start=500)
    assert wrong_start.verdict == Verdict.WRONG_START_LOCATION
    assert wrong_start.sealed is False  # a plaintext frame was found, just elsewhere
    assert pipeline.SEALED_NOT_FOUND_HINT not in wrong_start.reasons


# --------------------------------------------------------------------------- #
# Wrong secrets and wrong keys
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("start", [None, 137], ids=["derived", "explicit"])
@pytest.mark.parametrize(
    "change", [{"passphrase": "wrong passphrase"}, {"media_id": "another-id"}], ids=["passphrase", "media-id"]
)
def test_wrong_secret_on_a_sealed_file_looks_like_no_payload(start, change, keys):
    protected = _protect(_png(), "image", keys, explicit_start=start)
    result = _verify(protected.stego_bytes, "image", keys[1], explicit_start=start, **change)
    assert result.verdict in NOT_FOUND
    assert result.verdict != Verdict.AUTHENTIC
    assert result.sealed is None
    assert result.payload_json is None
    assert result.signature_valid is None
    assert pipeline.SEALED_NOT_FOUND_HINT in result.reasons


def test_sealed_file_without_a_passphrase_says_it_is_needed(keys):
    protected = _protect(_png(), "image", keys, explicit_start=137)
    result = _verify(protected.stego_bytes, "image", keys[1], explicit_start=137, passphrase=None)
    assert result.verdict == Verdict.PAYLOAD_MISSING
    assert result.sealed is None
    assert pipeline.SEALED_NEEDS_PASSPHRASE_HINT in result.reasons


def test_large_sealed_cover_with_wrong_passphrase_cannot_verify(keys):
    """Too big to scan fully: absence cannot be confirmed, and the hint still applies."""
    protected = _protect(_png(size=300), "image", keys, explicit_start=137)
    result = _verify(protected.stego_bytes, "image", keys[1], explicit_start=137, passphrase="nope")
    assert result.verdict == Verdict.CANNOT_VERIFY
    assert result.sealed is None
    assert pipeline.SEALED_NOT_FOUND_HINT in result.reasons


def test_wrong_public_key_on_a_sealed_file_is_signature_invalid(keys, other_keys):
    protected = _protect(_png(), "image", keys)
    result = _verify(protected.stego_bytes, "image", other_keys[1])
    assert result.verdict == Verdict.SIGNATURE_INVALID
    assert result.sealed is True
    assert result.signature_valid is False


def test_seal_requires_a_passphrase(keys):
    with pytest.raises(StegoError, match="passphrase"):
        _protect(_png(), "image", keys, passphrase=None, explicit_start=0)


# --------------------------------------------------------------------------- #
# Tampering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["image", "audio"])
def test_high_bit_tamper_on_a_sealed_file_is_tampered(kind, keys, wav_16_stereo):
    protected = _protect(_cover(kind, wav_16_stereo), kind, keys)
    damaged = attacks.flip_bits(protected.stego_bytes, kind)  # high bits only, frame intact
    result = _verify(damaged, kind, keys[1])
    assert result.verdict == Verdict.TAMPERED, result.reasons
    assert result.sealed is True
    assert result.signature_valid is True
    assert result.media_hash_embedded != result.media_hash_recomputed


@pytest.mark.parametrize("n_lsb", [1, 2, 3, 8])
def test_keyless_bit_flip_inside_the_sealed_region_is_tampered(n_lsb, keys):
    protected = _protect(_png(), "image", keys, explicit_start=7, n_lsb=n_lsb)
    damaged = attacks.corrupt_payload(protected.stego_bytes, "image", n_lsb, 7, sealed=True)
    before = lsb.extract_bits(_elements(protected.stego_bytes, "image"), 7, protected.frame_bytes * 8, n_lsb)
    after = lsb.extract_bits(_elements(damaged, "image"), 7, protected.frame_bytes * 8, n_lsb)
    assert np.count_nonzero(before ^ after) == 1  # exactly one hidden bit changed
    result = _verify(damaged, "image", keys[1], explicit_start=7, n_lsb=n_lsb)
    assert result.verdict == Verdict.TAMPERED
    assert result.sealed is True
    assert any("CRC" in reason for reason in result.reasons)


def test_plaintext_attacks_explain_that_sealed_frames_are_opaque(keys):
    protected = _protect(_png(), "image", keys, explicit_start=7)
    with pytest.raises(FrameError, match="sealed frame"):
        attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, 7)
    with pytest.raises(FrameError, match="sealed frame"):
        attacks.replay(protected.stego_bytes, _png(seed=99), "image", N_LSB, 7)
    with pytest.raises(FrameError):
        attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, 10**9, sealed=True)


def test_keyless_replay_of_a_sealed_frame_is_tampered(keys):
    protected = _protect(_png(), "image", keys, explicit_start=7)
    replayed = attacks.replay(protected.stego_bytes, _png(seed=99), "image", N_LSB, 7, sealed=True)
    result = _verify(replayed, "image", keys[1], explicit_start=7)
    assert result.verdict == Verdict.TAMPERED
    assert result.sealed is True
    assert result.signature_valid is True
    assert result.media_hash_embedded != result.media_hash_recomputed


def test_ctr_is_malleable_so_the_signature_not_the_crc_catches_a_forged_edit(keys):
    """LIMITATION, demonstrated: without the key, edit the payload AND patch
    the encrypted CRC (CRC32 is affine, CTR maps ciphertext flips to plaintext
    flips). The forger only needs to guess WHERE a byte sits, which the
    canonical JSON skeleton makes easy; here it turns metadata "ACW1" into
    "ACW0" so the payload still parses. The CRC then passes, and only the
    Ed25519 signature notices."""
    protected = _protect(_png(), "image", keys, explicit_start=7)
    elements = _elements(protected.stego_bytes, "image")
    region = bytearray(_embedded_region(protected.stego_bytes, "image", protected))
    payload = json.dumps(
        protected.payload_json, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    target = container.HEADER_SIZE + payload.index(b'"team":"ACW1"') + len(b'"team":"ACW')

    body_start = sealing.NONCE_SIZE  # the CRC covers the whole plaintext frame body
    crc_start = len(region) - container.CRC_SIZE
    delta = bytearray(crc_start - body_start)
    delta[target] = ord("1") ^ ord("0")
    crc_delta = zlib.crc32(bytes(delta)) ^ zlib.crc32(bytes(len(delta)))  # affine: key-less
    region[body_start + target] ^= delta[target]
    for i, byte in enumerate(crc_delta.to_bytes(4, "big")):
        region[crc_start + i] ^= byte

    forged = lsb.embed_bits(elements, lsb.bytes_to_bits(bytes(region)), 7, N_LSB)
    stego = image_codec.save_png(image_codec.load_png(protected.stego_bytes), forged)
    result = _verify(stego, "image", keys[1], explicit_start=7)
    assert result.verdict == Verdict.SIGNATURE_INVALID, result.reasons
    assert result.sealed is True


def test_crop_moves_a_derived_start_so_a_sealed_frame_is_not_found(keys):
    """LIMITATION: the derived start depends on the element count, and a sealed
    frame cannot be scanned for, so a cropped derived-mode file reports
    not-found. With the original explicit offset the frame is found -> Tampered."""
    protected = _protect(_png(), "image", keys)
    cropped = attacks.crop(protected.stego_bytes, "image")
    derived = _verify(cropped, "image", keys[1])
    assert derived.verdict in NOT_FOUND
    assert derived.sealed is None
    explicit = _verify(cropped, "image", keys[1], explicit_start=protected.start_offset)
    assert explicit.verdict == Verdict.TAMPERED
    assert explicit.sealed is True


def test_redundancy_lets_a_sealed_frame_survive_lsb_noise(keys):
    cover = _png(size=128, seed=3)
    protected = _protect(cover, "image", keys, explicit_start=0, redundancy=3)
    noisy = attacks.lsb_noise(protected.stego_bytes, "image", N_LSB)
    result = _verify(noisy, "image", keys[1], explicit_start=0, redundancy=3)
    assert result.verdict == Verdict.AUTHENTIC, result.reasons
    assert result.sealed is True


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


def test_capacity_accounts_for_the_seal_nonce(keys):
    """Find the largest message whose unsealed frame fills a tiny cover; the
    same message sealed needs 12 more bytes and must be refused."""
    cover = _png(size=16)  # 768 elements; at n_lsb=8 that is exactly 768 bytes
    n_lsb = 8
    capacity = lsb.capacity_bits(16 * 16 * 3, n_lsb) // 8

    def unsealed_frame_bytes(message: bytes) -> int:
        return _protect(
            cover,
            "image",
            keys,
            message=message,
            seal_frame=False,
            passphrase=None,
            explicit_start=0,
            n_lsb=n_lsb,
        ).frame_bytes

    base = unsealed_frame_bytes(b"xxx")
    # base64 grows 4 bytes per 3 message bytes: pick the largest fitting length.
    extra = (capacity - base) // 4
    message = b"x" * (3 + extra * 3)
    assert capacity - 4 < unsealed_frame_bytes(message) <= capacity

    with pytest.raises(CapacityError, match="12-byte seal nonce"):
        _protect(cover, "image", keys, message=message, explicit_start=0, n_lsb=n_lsb)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_seal_round_trip_and_keyless_tamper(tmp_path, keys, capsys):
    cover = tmp_path / "cover.png"
    cover.write_bytes(_png())
    message = tmp_path / "message.txt"
    message.write_bytes(MESSAGE)
    private = tmp_path / "private.pem"
    private.write_bytes(keys[0])
    public = tmp_path / "public.pem"
    public.write_bytes(keys[1])
    stego = tmp_path / "stego.png"

    base = ["--lsb", "2", "--media-id", MEDIA_ID, "--passphrase", PASSPHRASE]
    assert (
        cli.main(
            [
                "protect",
                "--cover",
                str(cover),
                "--message",
                str(message),
                "--key",
                str(private),
                "--out",
                str(stego),
                "--start",
                "137",
                "--seal",
                *base,
            ]
        )
        == 0
    )
    assert "sealed:       yes" in capsys.readouterr().out

    assert cli.main(["verify", "--stego", str(stego), "--pub", str(public), "--start", "137", *base]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "Authentic"
    assert report["sealed"] is True

    tampered = tmp_path / "tampered.png"
    assert (
        cli.main(
            [
                "tamper",
                "--stego",
                str(stego),
                "--attack",
                "corrupt_payload",
                "--sealed",
                "--lsb",
                "2",
                "--start",
                "137",
                "--out",
                str(tampered),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert cli.main(["verify", "--stego", str(tampered), "--pub", str(public), "--start", "137", *base]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == "Tampered"


def test_cli_seal_without_passphrase_fails_cleanly(tmp_path, keys, capsys):
    cover = tmp_path / "cover.png"
    cover.write_bytes(_png())
    message = tmp_path / "message.txt"
    message.write_bytes(MESSAGE)
    private = tmp_path / "private.pem"
    private.write_bytes(keys[0])
    assert (
        cli.main(
            [
                "protect",
                "--cover",
                str(cover),
                "--message",
                str(message),
                "--key",
                str(private),
                "--media-id",
                MEDIA_ID,
                "--start",
                "0",
                "--seal",
                "--out",
                str(tmp_path / "o.png"),
            ]
        )
        == 2
    )
    assert "passphrase" in capsys.readouterr().err
