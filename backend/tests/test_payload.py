"""Round-trip tests for FR3 (verification payload)."""

from __future__ import annotations

import os

import pytest

from stego_core import payload
from stego_core.errors import FrameError


def _sample_payload(**overrides) -> payload.Payload:
    fields = {
        "media_id": "P1-4-lena-001",
        "timestamp": "2026-09-08T12:00:00Z",
        "media_hash": "a" * 64,
        "nonce": payload.new_nonce(),
        "cover_kind": "image",
        "n_lsb": 2,
        "shape": [64, 64, 3],
        "message_mime": "text/plain",
        "message": b"hello world",
        "encrypted": False,
        "metadata": {"team": "P1-4"},
    }
    fields.update(overrides)
    return payload.Payload(**fields)


def test_new_nonce_is_16_bytes_hex_and_random() -> None:
    a, b = payload.new_nonce(), payload.new_nonce()
    assert len(a) == 32  # 16 bytes as hex
    bytes.fromhex(a)  # does not raise
    assert a != b


def test_serialize_is_canonical_and_deterministic() -> None:
    p = _sample_payload()
    assert payload.serialize(p) == payload.serialize(p)


def test_serialize_deserialize_roundtrip() -> None:
    p = _sample_payload()
    raw = payload.serialize(p)
    out = payload.deserialize(raw)
    assert out == p


def test_deserialize_rejects_garbage() -> None:
    with pytest.raises(FrameError):
        payload.deserialize(b"not json")


def test_deserialize_rejects_missing_fields() -> None:
    with pytest.raises(FrameError):
        payload.deserialize(b'{"media_id":"x"}')


def test_encrypt_decrypt_message_roundtrip() -> None:
    k_enc = os.urandom(32)
    aad = b"P1-4-lena-001"
    ciphertext = payload.encrypt_message(k_enc, b"secret message", aad)
    assert payload.decrypt_message(k_enc, ciphertext, aad) == b"secret message"


def test_decrypt_message_wrong_key_raises() -> None:
    ciphertext = payload.encrypt_message(os.urandom(32), b"secret message", b"aad")
    with pytest.raises(FrameError):
        payload.decrypt_message(os.urandom(32), ciphertext, b"aad")


def test_decrypt_message_tampered_ciphertext_raises() -> None:
    k_enc = os.urandom(32)
    ciphertext = bytearray(payload.encrypt_message(k_enc, b"secret message", b"aad"))
    ciphertext[-1] ^= 0xFF
    with pytest.raises(FrameError):
        payload.decrypt_message(k_enc, bytes(ciphertext), b"aad")


def test_decrypt_message_wrong_aad_raises() -> None:
    k_enc = os.urandom(32)
    ciphertext = payload.encrypt_message(k_enc, b"secret message", b"correct-aad")
    with pytest.raises(FrameError):
        payload.decrypt_message(k_enc, ciphertext, b"wrong-aad")
