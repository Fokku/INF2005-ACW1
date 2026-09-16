"""Verification payload for FR3 - the structure that is actually hidden.

The spec requires media ID, timestamp, hash, nonce and team metadata. We also
include n_lsb, cover_kind and shape and sign them along with everything else.
Without that, a valid signed frame could be taken from one file and placed
into another, or a different n_lsb could be claimed, and there would be no
way to detect it. Binding these fields lets the verifier compare what was
extracted against what was signed and report Tampered if they differ.

serialize() must produce identical bytes for the same payload on both the
signing side and the verifying side, otherwise the signature check fails.
For that reason we use json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False): sorted keys and no extra whitespace remove any source
of variation between the two sides.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import FrameError

PAYLOAD_VERSION = 1
GCM_NONCE_BYTES = 12


@dataclass
class Payload:
    """The structure that is serialized, signed and embedded in the cover."""

    media_id: str  
    timestamp: str  
    media_hash: str  # produced by hashing.stable_media_hash(...)
    nonce: str  # 16 random bytes as hex, ensures no two payloads look identical
    cover_kind: str  # "image" or "audio"
    n_lsb: int  # 1..8, signed so it cannot be changed after the fact
    shape: list[int]  # [h, w, c] for image, [frames, channels] for audio 
    message_mime: str  # "text/plain", "image/png", "audio/wav", ...
    message: bytes  # the hidden message itself, plaintext or AES-GCM ciphertext
    encrypted: bool = False
    metadata: dict[str, str] = field(default_factory=dict)  # team number, author, purpose
    version: int = PAYLOAD_VERSION


def new_nonce() -> str:
    """Generates 16 random bytes, hex-encoded so it is JSON-safe."""
    return secrets.token_hex(16)


def serialize(payload: Payload) -> bytes:
    """Converts a Payload into the exact bytes that get signed.

    message is bytes, so it is base64-encoded first to keep the JSON valid.
    Each field is listed explicitly rather than using dataclasses.asdict, so
    that no field is silently added or renamed without this function being
    updated to match.
    """
    obj = {
        "version": payload.version,
        "media_id": payload.media_id,
        "timestamp": payload.timestamp,
        "media_hash": payload.media_hash,
        "nonce": payload.nonce,
        "cover_kind": payload.cover_kind,
        "n_lsb": payload.n_lsb,
        "shape": payload.shape,
        "message_mime": payload.message_mime,
        "message_b64": base64.b64encode(payload.message).decode("ascii"),
        "encrypted": payload.encrypted,
        "metadata": payload.metadata,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def deserialize(raw: bytes) -> Payload:
    """Reverses serialize(). If the input is malformed in any way such as invalid
    JSON, a missing field, invalid base64, a FrameError is raised instead of
    letting the exception propagate. The pipeline catches this and turns it
    into a verdict such as Tampered rather than an unhandled error.
    """
    try:
        obj = json.loads(raw.decode("utf-8"))
        return Payload(
            media_id=obj["media_id"],
            timestamp=obj["timestamp"],
            media_hash=obj["media_hash"],
            nonce=obj["nonce"],
            cover_kind=obj["cover_kind"],
            n_lsb=obj["n_lsb"],
            shape=obj["shape"],
            message_mime=obj["message_mime"],
            message=base64.b64decode(obj["message_b64"], validate=True),
            encrypted=obj["encrypted"],
            metadata=obj["metadata"],
            version=obj["version"],
        )
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise FrameError(f"malformed payload: {exc}") from exc


# The functions below implement the custom encrypted payload for confidentiality, in addition to integrity. 
# Signing already provides integrity; AES-GCM provides confidentiality and its own
# integrity check, so this effectively layers encryption on top of signing.


def encrypt_message(k_enc: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encryption. Output is nonce + ciphertext (the authentication
    tag is appended to the ciphertext automatically by the library).

    aad (additional authenticated data) is set to media_id, so this ciphertext
    cannot be moved to a different media item without detection.
    """
    nonce = os.urandom(GCM_NONCE_BYTES)
    ciphertext = AESGCM(k_enc).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_message(k_enc: bytes, blob: bytes, aad: bytes) -> bytes:
    """Reverses encrypt_message. If the key is incorrect or the ciphertext has
    been altered, GCM's authentication check fails, which is raised here as
    FrameError (resulting in a Tampered verdict rather than a crash).
    """
    if len(blob) < GCM_NONCE_BYTES:
        raise FrameError("encrypted message too short to contain a GCM nonce")
    nonce, ciphertext = blob[:GCM_NONCE_BYTES], blob[GCM_NONCE_BYTES:]
    try:
        return AESGCM(k_enc).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise FrameError("decryption failed: wrong key or tampered ciphertext") from exc
