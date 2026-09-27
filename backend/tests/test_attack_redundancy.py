"""corrupt_payload and replay on files protected with several copies.

Robust embedding (stego_core/ecc.py) writes r back-to-back copies of the
header block, then r copies of the rest of the frame, and the verifier
majority-votes each block. An attack that changes or carries one copy is
simply outvoted: before these tests existed, the key-less sealed
corrupt_payload left a 3- or 5-copy file Authentic while predicting Tampered,
and the plaintext corrupt_payload / replay failed with a bare CRC mismatch.
Both attacks now take the copy count (API form field `redundancy`, CLI
`--copies`) and must end in Tampered, sealed or not.
"""

from __future__ import annotations

import io
import wave

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app import storage
from app.main import app
from stego_core import attacks, container, extraction, lsb, pipeline, sealing, signing
from stego_core.errors import FrameError
from stego_core.verdict import Verdict

N_LSB = 2
START = 512
MEDIA_ID = "attack-redundancy"
PASSPHRASE = "attack redundancy passphrase"
MESSAGE = b"every copy has to be attacked"


@pytest.fixture(scope="module")
def keys():
    return signing.generate_keypair()


def _png(seed: int, size: int = 96) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    Image.fromarray(rng.integers(0, 256, (size, size, 3), dtype=np.uint8)).save(buf, format="PNG")
    return buf.getvalue()


def _wav(seed: int, frames: int = 20000) -> bytes:
    rng = np.random.default_rng(seed)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as out:
        out.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
        out.writeframes(rng.integers(-30000, 30000, frames, dtype=np.int16).tobytes())
    return buf.getvalue()


def _cover(kind: str, seed: int) -> bytes:
    return _png(seed) if kind == "image" else _wav(seed)


def _protect(cover: bytes, kind: str, keys, redundancy: int, sealed: bool) -> pipeline.ProtectOutcome:
    return pipeline.protect(
        pipeline.ProtectOptions(
            cover_bytes=cover,
            cover_kind=kind,
            message=MESSAGE,
            message_mime="text/plain",
            n_lsb=N_LSB,
            media_id=MEDIA_ID,
            metadata={},
            private_key_pem=keys[0],
            passphrase=PASSPHRASE if sealed else None,
            explicit_start=START,
            redundancy=redundancy,
            seal_frame=sealed,
        )
    )


def _verify(stego: bytes, kind: str, keys, redundancy: int, sealed: bool) -> pipeline.VerifyOutcome:
    return pipeline.verify(
        pipeline.VerifyOptions(
            stego_bytes=stego,
            cover_kind=kind,
            public_key_pem=keys[1],
            n_lsb=N_LSB,
            media_id=MEDIA_ID,
            passphrase=PASSPHRASE if sealed else None,
            explicit_start=START,
            redundancy=redundancy,
        )
    )


def _hidden_bits(data: bytes, kind: str, n_bits: int) -> np.ndarray:
    return lsb.extract_bits(attacks._load(data, kind).elements, START, n_bits, N_LSB)


def _changed_offsets(before: bytes, after: bytes, kind: str, n_bits: int) -> list[int]:
    diff = _hidden_bits(before, kind, n_bits) ^ _hidden_bits(after, kind, n_bits)
    return np.flatnonzero(diff).tolist()


def _region_bits(protected: pipeline.ProtectOutcome, redundancy: int, sealed: bool) -> int:
    """Hidden bits from START that the embedded copies occupy (whole elements)."""
    header_block = extraction.SEALED_HEADER_BLOCK_SIZE if sealed else container.HEADER_SIZE
    header_elements = attacks._block_elements(header_block, N_LSB, redundancy)
    body_elements = attacks._block_elements(protected.frame_bytes - header_block, N_LSB, redundancy)
    return (header_elements + body_elements) * N_LSB


# --------------------------------------------------------------------------- #
# stego_core.attacks, verified with pipeline.verify
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
@pytest.mark.parametrize("redundancy", [3, 5])
def test_corrupt_payload_beats_the_majority_vote(kind, sealed, redundancy, keys):
    protected = _protect(_cover(kind, 1), kind, keys, redundancy, sealed)
    assert _verify(protected.stego_bytes, kind, keys, redundancy, sealed).verdict == Verdict.AUTHENTIC

    damaged = attacks.corrupt_payload(
        protected.stego_bytes, kind, N_LSB, START, sealed=sealed, redundancy=redundancy
    )
    result = _verify(damaged, kind, keys, redundancy, sealed)
    assert result.verdict == Verdict.TAMPERED, result.reasons
    assert result.sealed is sealed
    assert result.signature_valid is None  # the frame itself was rejected, before the signature

    # Exactly one bit per copy changed, one copy length apart, nothing else.
    changed = _changed_offsets(
        protected.stego_bytes, damaged, kind, _region_bits(protected, redundancy, sealed)
    )
    assert len(changed) == redundancy
    if sealed:
        # Key-less: the encrypted VERSION byte in every header block copy.
        block_bits = extraction.SEALED_HEADER_BLOCK_SIZE * 8
        version_bit = (sealing.NONCE_SIZE + len(container.MAGIC)) * 8
        assert changed == [copy * block_bits + version_bit for copy in range(redundancy)]
        assert any("unsupported frame version" in reason for reason in result.reasons)
    else:
        # The first payload bit of every body copy; the header block is untouched.
        body_offset = attacks._block_elements(container.HEADER_SIZE, N_LSB, redundancy) * N_LSB
        body_bits = (protected.frame_bytes - container.HEADER_SIZE) * 8
        assert changed == [body_offset + copy * body_bits for copy in range(redundancy)]
        assert any("CRC" in reason for reason in result.reasons)


@pytest.mark.parametrize("kind", ["image", "audio"])
@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
@pytest.mark.parametrize("redundancy", [3, 5])
def test_replay_carries_every_copy(kind, sealed, redundancy, keys):
    protected = _protect(_cover(kind, 1), kind, keys, redundancy, sealed)
    replayed = attacks.replay(
        protected.stego_bytes, _cover(kind, 2), kind, N_LSB, START, sealed=sealed, redundancy=redundancy
    )
    # The whole multi-copy region arrived unchanged, not just one voted copy.
    region = _region_bits(protected, redundancy, sealed)
    assert np.array_equal(
        _hidden_bits(replayed, kind, region), _hidden_bits(protected.stego_bytes, kind, region)
    )

    result = _verify(replayed, kind, keys, redundancy, sealed)
    assert result.verdict == Verdict.TAMPERED, result.reasons
    assert result.sealed is sealed
    assert result.signature_valid is True
    assert result.media_hash_embedded != result.media_hash_recomputed


@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
def test_single_copy_corruption_is_unchanged(sealed, keys):
    """redundancy=1 (the default) still flips exactly the first payload bit."""
    protected = _protect(_png(1), "image", keys, 1, sealed)
    damaged = attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, START, sealed=sealed)
    assert damaged == attacks.corrupt_payload(
        protected.stego_bytes, "image", N_LSB, START, sealed=sealed, redundancy=1
    )
    header_block = extraction.SEALED_HEADER_BLOCK_SIZE if sealed else container.HEADER_SIZE
    changed = _changed_offsets(protected.stego_bytes, damaged, "image", protected.frame_bytes * 8)
    assert changed == [header_block * 8]
    result = _verify(damaged, "image", keys, 1, sealed)
    assert result.verdict == Verdict.TAMPERED
    assert any("CRC" in reason for reason in result.reasons)


def test_a_single_flipped_copy_really_is_outvoted(keys):
    """Why every copy must be attacked: the old one-copy attack leaves a sealed
    3-copy file Authentic.
    """
    protected = _protect(_png(1), "image", keys, 3, sealed=True)
    one_copy = attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, START, sealed=True)
    assert _verify(one_copy, "image", keys, 3, sealed=True).verdict == Verdict.AUTHENTIC


@pytest.mark.parametrize("attack", ["corrupt_payload", "replay"])
def test_wrong_copy_count_names_the_right_one(attack, keys):
    three = _protect(_png(1), "image", keys, 3, sealed=False)
    one = _protect(_png(1), "image", keys, 1, sealed=False)

    def run(stego: bytes, redundancy: int) -> bytes:
        if attack == "replay":
            return attacks.replay(stego, _png(2), "image", N_LSB, START, redundancy=redundancy)
        return attacks.corrupt_payload(stego, "image", N_LSB, START, redundancy=redundancy)

    with pytest.raises(FrameError, match="embedded as 3 copies"):
        run(three.stego_bytes, 1)
    with pytest.raises(FrameError, match="embedded as 1 copy"):
        run(one.stego_bytes, 3)


def test_plaintext_attack_on_a_sealed_multi_copy_file_points_to_the_sealed_variant(keys):
    protected = _protect(_png(1), "image", keys, 3, sealed=True)
    with pytest.raises(FrameError, match=f"--sealed --start {START} --copies 3"):
        attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, START, redundancy=3)


@pytest.mark.parametrize("redundancy", [0, 2, 4, 11, -1])
def test_bad_redundancy_is_rejected(redundancy, keys):
    protected = _protect(_png(1), "image", keys, 1, sealed=False)
    with pytest.raises(ValueError, match="redundancy"):
        attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, START, redundancy=redundancy)
    with pytest.raises(ValueError, match="redundancy"):
        attacks.replay(protected.stego_bytes, _png(2), "image", N_LSB, START, redundancy=redundancy)


def test_sealed_multi_copy_attacks_need_room_for_the_header_block(keys):
    protected = _protect(_png(1), "image", keys, 5, sealed=True)
    n_elements = len(attacks._load(protected.stego_bytes, "image").elements)
    too_late = n_elements - 10  # fewer elements left than 5 sealed header copies need
    with pytest.raises(FrameError):
        attacks.corrupt_payload(protected.stego_bytes, "image", N_LSB, too_late, sealed=True, redundancy=5)
    with pytest.raises(FrameError):
        attacks.replay(protected.stego_bytes, _png(2), "image", N_LSB, too_late, sealed=True, redundancy=5)


# --------------------------------------------------------------------------- #
# The same flows through the API, the way the Attack Lab drives them
# --------------------------------------------------------------------------- #


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "OUT_DIR", tmp_path)
    return TestClient(app)


def _api_protect(client, private_pem: bytes, redundancy: int, sealed: bool) -> bytes:
    data = {
        "message_text": MESSAGE.decode(),
        "n_lsb": str(N_LSB),
        "media_id": MEDIA_ID,
        "start_mode": "explicit",
        "explicit_start": str(START),
        "redundancy": str(redundancy),
    }
    if sealed:
        data |= {"passphrase": PASSPHRASE, "seal_frame": "true"}
    r = client.post(
        "/api/protect",
        files={"cover": ("cover.png", _png(1)), "private_key_pem": ("k.pem", private_pem)},
        data=data,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["redundancy"] == redundancy
    assert body["sealed"] is sealed
    assert body["start_offset"] == START
    return client.get(body["stego"]["download_url"]).content


def _api_verify(client, stego: bytes, public_pem: bytes, redundancy: int, sealed: bool) -> dict:
    data = {
        "n_lsb": str(N_LSB),
        "media_id": MEDIA_ID,
        "start_mode": "explicit",
        "explicit_start": str(START),
        "redundancy": str(redundancy),
    }
    if sealed:
        data["passphrase"] = PASSPHRASE
    r = client.post(
        "/api/verify",
        files={"stego": ("s.png", stego), "public_key_pem": ("p.pem", public_pem)},
        data=data,
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("attack", ["corrupt_payload", "replay"])
@pytest.mark.parametrize("sealed", [False, True], ids=["plain", "sealed"])
@pytest.mark.parametrize("redundancy", [3, 5])
def test_api_attack_with_copies_verifies_tampered(client, keys, attack, sealed, redundancy):
    stego = _api_protect(client, keys[0], redundancy, sealed)
    assert _api_verify(client, stego, keys[1], redundancy, sealed)["verdict"] == "Authentic"

    files = {"stego": ("s.png", stego)}
    if attack == "replay":
        files["other_cover"] = ("other.png", _png(2))
    data = {
        "attack": attack,
        "n_lsb": str(N_LSB),
        "start_offset": str(START),
        "redundancy": str(redundancy),
        "sealed": "true" if sealed else "false",
    }
    r = client.post("/api/attack", files=files, data=data)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["expected_verdict"] == "Tampered"
    damaged = client.get(result["output"]["download_url"]).content

    report = _api_verify(client, damaged, keys[1], redundancy, sealed)
    assert report["verdict"] == result["expected_verdict"], report["reasons"]


def test_api_attack_without_copies_names_the_copy_count(client, keys):
    """An older client that omits `redundancy` gets a 400 that says what to send."""
    stego = _api_protect(client, keys[0], 3, sealed=False)
    r = client.post(
        "/api/attack",
        files={"stego": ("s.png", stego)},
        data={"attack": "corrupt_payload", "n_lsb": str(N_LSB), "start_offset": str(START)},
    )
    assert r.status_code == 400
    assert "redundancy 3" in r.json()["detail"]


@pytest.mark.parametrize("attack", ["corrupt_payload", "replay", "flip_bits", "lsb_noise"])
@pytest.mark.parametrize("redundancy", ["0", "2", "11", "-3"])
def test_api_bad_redundancy_is_400(client, attack, redundancy):
    files = {"stego": ("s.png", _png(1))}
    if attack == "replay":
        files["other_cover"] = ("other.png", _png(2))
    r = client.post(
        "/api/attack",
        files=files,
        data={"attack": attack, "n_lsb": str(N_LSB), "start_offset": str(START), "redundancy": redundancy},
    )
    assert r.status_code == 400, r.text
    assert "redundancy" in r.json()["detail"]
