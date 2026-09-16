"""Round-trip tests for FR4 (digital signature)."""

from __future__ import annotations

import pytest

from stego_core import signing
from stego_core.errors import KeyError_


def test_generate_keypair_produces_pem_bytes() -> None:
    private_pem, public_pem = signing.generate_keypair()
    assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_sign_then_verify_succeeds() -> None:
    private_pem, public_pem = signing.generate_keypair()
    message = b"payload bytes to authenticate"
    signature = signing.sign(private_pem, message)
    assert len(signature) == signing.SIGNATURE_BYTES
    assert signing.verify(public_pem, message, signature) is True


def test_verify_fails_for_tampered_message() -> None:
    private_pem, public_pem = signing.generate_keypair()
    signature = signing.sign(private_pem, b"original message")
    assert signing.verify(public_pem, b"different message", signature) is False


def test_verify_fails_for_wrong_key() -> None:
    private_pem, _ = signing.generate_keypair()
    _, other_public_pem = signing.generate_keypair()
    message = b"payload bytes"
    signature = signing.sign(private_pem, message)
    assert signing.verify(other_public_pem, message, signature) is False


def test_verify_raises_for_malformed_key() -> None:
    with pytest.raises(KeyError_):
        signing.verify(b"not a pem key", b"message", b"\x00" * 64)


def test_fingerprint_is_stable_and_key_specific() -> None:
    _, public_pem = signing.generate_keypair()
    _, other_public_pem = signing.generate_keypair()
    assert signing.fingerprint(public_pem) == signing.fingerprint(public_pem)
    assert signing.fingerprint(public_pem) != signing.fingerprint(other_public_pem)
    assert len(signing.fingerprint(public_pem)) == 64  # sha256 hex
