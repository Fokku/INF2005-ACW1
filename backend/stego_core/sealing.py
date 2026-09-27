"""Sealed frames: hide the frame's own structure (optional challenge, spec Section 8).

Owner: Yeo Kai Yuan. Design write-up: docs/design/start-location.md, section 7.

The baseline keeps the start location secret (`location.derive_start`), but the
frame it hides begins with a plaintext MAGIC b"ACW1", a plaintext header and a
canonical JSON payload. `location.scan_for_magic` finds that in milliseconds,
so the secret start only defeats a naive fixed-offset reader. A sealed frame
removes the structure an analyst would scan for:

    sealed = nonce (12 random bytes) || AES-256-CTR(K_seal, nonce || 0^32, frame)

where `frame` is the unchanged `container.build_frame` output. Nothing in the
embedded region is plaintext any more: without K_seal it is indistinguishable
from random bits, so a verifier with the wrong passphrase cannot even tell that
a payload is there.

>>> WHY CTR AND NOT AES-GCM (the obvious "use an AEAD" answer is wrong here):
>>>
>>>  1. The verifier must decrypt the 13-byte header BEFORE it knows how many
>>>     bytes to read (the lengths are inside it). CTR is a stream cipher, so
>>>     `unseal(key, nonce + first_13_ciphertext_bytes)` returns exactly the
>>>     first 13 plaintext bytes. An AEAD will not release any plaintext until
>>>     it has checked the tag over the WHOLE ciphertext, which we cannot size.
>>>  2. An AEAD collapses every failure into "authentication failed". A single
>>>     flipped LSB and a wrong passphrase would then look identical, and the
>>>     verdict table would lose the Tampered / Payload Missing distinction.
>>>     With CTR the header still opens after body damage, so the CRC reports
>>>     Tampered exactly as it does for an unsealed frame.
>>>
>>> CTR IS MALLEABLE. Flipping ciphertext bit i flips plaintext bit i, and
>>> CRC32 is affine, so an attacker WITHOUT the key who knows the frame length
>>> can flip a payload bit and patch the encrypted CRC to match
>>> (tests/test_sealed_frame.py demonstrates it). Sealing gives
>>> confidentiality of structure, not integrity. Integrity still comes from
>>> the CRC (accidents) and the Ed25519 signature (deliberate changes), which
>>> is why a forged-CRC edit ends as Signature Invalid, not Authentic.
>>>
>>> WHY A RANDOM NONCE PER EMBED: K_seal is a pure function of
>>> (passphrase, media_id). Teams reuse both, e.g. protecting several covers
>>> under one media ID or re-protecting the same cover. With a fixed or
>>> derived IV, two frames sealed under one key would share a keystream, and
>>> XORing the two embedded regions would cancel it: frame_a XOR frame_b, with
>>> the known MAGIC/JSON skeleton, leaks both. A 96-bit random nonce makes a
>>> repeat negligible (birthday bound ~2^48 embeds per key). The nonce is not
>>> secret; it only has to be unique, so it is stored in the clear in front.
>>>
>>> COUNTER LAYOUT: the 16-byte initial counter block is nonce || 00000000.
>>> The library increments it as one 128-bit integer, so the low 32 bits give
>>> 2^32 blocks (64 GiB) before a carry could touch the nonce. A frame is
>>> capped far below that by its uint32 PAYLOAD_LEN field (container.py).
>>>
>>> KEY SEPARATION: K_seal is its own HKDF-Expand output (info b"acw1-seal"),
>>> not K_enc or K_loc. K_enc drives AES-GCM, which is CTR internally with its
>>> own counter blocks, so reusing it here could make the two modes share
>>> keystream blocks. K_loc is an HMAC key. One key per purpose keeps every
>>> argument local; see kdf.py.

This module only transforms bytes. Where the sealed bytes live in the cover,
and how they are read back without trusting unchecked lengths, is
`pipeline.protect` and `extraction.extract_sealed_frame`.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import FrameError

NONCE_SIZE = 12  # bytes stored in the clear in front of the ciphertext
SEAL_OVERHEAD = NONCE_SIZE  # sealing adds exactly the nonce; CTR does not pad
KEY_SIZE = 32  # AES-256
_COUNTER_SUFFIX = bytes(4)  # low 32 bits of the counter block start at zero


def sealed_size(frame_len: int) -> int:
    """Bytes embedded for a frame of `frame_len` bytes once sealed."""
    return SEAL_OVERHEAD + frame_len


def _keystream_cipher(k_seal: bytes, nonce: bytes) -> Cipher:
    if not isinstance(k_seal, (bytes, bytearray)) or len(k_seal) != KEY_SIZE:
        raise ValueError(f"k_seal must be {KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"seal nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    return Cipher(algorithms.AES(bytes(k_seal)), modes.CTR(bytes(nonce) + _COUNTER_SUFFIX))


def seal(k_seal: bytes, frame: bytes, nonce: bytes | None = None) -> bytes:
    """Return nonce || AES-256-CTR(k_seal, frame).

    `nonce` exists for deterministic tests only. Production callers leave it
    as None so every embed draws a fresh one; see the module docstring for
    why a reused nonce under one key is fatal.
    """
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    encryptor = _keystream_cipher(k_seal, nonce).encryptor()
    return bytes(nonce) + encryptor.update(frame) + encryptor.finalize()


def unseal(k_seal: bytes, sealed: bytes) -> bytes:
    """Decrypt nonce || ciphertext back to the plaintext bytes it covers.

    Works on any PREFIX of a sealed frame, which is how the verifier opens the
    13-byte header before it knows the full length. There is no integrity
    check here by design: a wrong key returns random-looking bytes, and it is
    the caller's job to test them (MAGIC, then header, then CRC, then the
    signature). Raises FrameError if the input cannot even hold a nonce.
    """
    if len(sealed) < NONCE_SIZE:
        raise FrameError(
            f"sealed frame truncated: need at least {NONCE_SIZE} nonce bytes, have {len(sealed)}"
        )
    decryptor = _keystream_cipher(k_seal, sealed[:NONCE_SIZE]).decryptor()
    return decryptor.update(bytes(sealed[NONCE_SIZE:])) + decryptor.finalize()
