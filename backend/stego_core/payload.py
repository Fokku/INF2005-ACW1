"""The verification payload — what actually gets hidden (spec FR3).

Required fields: media ID, timestamp, hash, nonce and team-defined metadata.
We also bind the embedding PARAMETERS into the payload, because they are signed:

    n_lsb, cover_kind, shape

>>> WHY BIND THE PARAMETERS: without them, an attacker can take a valid signed
>>> frame out of one file and drop it into another (replay / transplant), or
>>> claim a different n_lsb. With them, the verifier cross-checks what it sees
>>> against what was signed and reports `Tampered`.

Serialisation must be CANONICAL — the exact same bytes on both sides, or the
signature will not verify. Use json.dumps(obj, sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode("utf-8").
"""

from __future__ import annotations

from dataclasses import dataclass, field

PAYLOAD_VERSION = 1


@dataclass
class Payload:
    """The structure that is signed and embedded."""

    media_id: str  # human-chosen ID for this media item, e.g. "P1-4-lena-001"
    timestamp: str  # ISO-8601 UTC, e.g. "2026-09-08T12:00:00Z"
    media_hash: str  # hashing.stable_media_hash(...)
    nonce: str  # hex of 16 random bytes — freshness / replay evidence
    cover_kind: str  # "image" | "audio"
    n_lsb: int  # 1..8, bound so it cannot be swapped
    shape: list[int]  # [h, w, c] or [frames, channels] — bound so crops are caught
    message_mime: str  # "text/plain", "image/png", "audio/wav", ...
    message: bytes  # the hidden message itself (plaintext or AES-GCM ciphertext)
    encrypted: bool = False
    metadata: dict[str, str] = field(default_factory=dict)  # team, author, purpose, ...
    version: int = PAYLOAD_VERSION


def new_nonce() -> str:
    """16 random bytes as hex. TODO(team): implement — secrets.token_hex(16)."""
    raise NotImplementedError("TODO(team): new_nonce")


def serialize(payload: Payload) -> bytes:
    """Payload -> canonical bytes. This is exactly what gets signed.

    TODO(team): implement.

    Sketch: build a dict with every field, base64 the `message` bytes so it is
    JSON-safe, then json.dumps(sort_keys=True, separators=(",", ":")).encode().
    Both sides must produce byte-identical output — write a round-trip test.
    """
    raise NotImplementedError("TODO(team): serialize — see docstring")


def deserialize(raw: bytes) -> Payload:
    """Canonical bytes -> Payload. Inverse of `serialize`.

    Raise FrameError (from .errors) on anything malformed; the caller turns that
    into `Tampered`. TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): deserialize — see docstring")


# --------------------------------------------------------------------------- #
# The custom payload: "protects the hidden message's confidentiality and
# integrity" (spec Section 5). Signing gives integrity; AES-256-GCM gives
# confidentiality AND its own integrity tag.
# --------------------------------------------------------------------------- #


def encrypt_message(k_enc: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) || ciphertext || tag(16).

    Args:
        aad: additional authenticated data — pass the media_id so a ciphertext
             cannot be moved to a different media item.

    TODO(team): implement.
    Sketch: n = os.urandom(12); AESGCM(k_enc).encrypt(n, plaintext, aad); return n + ct
    """
    raise NotImplementedError("TODO(team): encrypt_message — see docstring")


def decrypt_message(k_enc: bytes, blob: bytes, aad: bytes) -> bytes:
    """Inverse of `encrypt_message`. Raises on a wrong key or a modified blob
    (that is GCM doing its job — surface it as `Tampered`).

    TODO(team): implement.
    """
    raise NotImplementedError("TODO(team): decrypt_message — see docstring")
