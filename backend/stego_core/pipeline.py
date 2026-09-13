"""protect() and verify() — the two end-to-end workflows (spec Section 7).

This is the ONLY module that imports every other one. Everything it calls is
already specified, so implementing this is mostly plumbing — but do it LAST,
after the pieces have tests.

    protect():  steps 1-6 of the required security workflow
    verify():   steps 7-10
"""

from __future__ import annotations

from dataclasses import dataclass

from .verdict import Verdict


@dataclass
class ProtectOptions:
    cover_bytes: bytes
    cover_kind: str  # "image" | "audio" | "video"
    message: bytes
    message_mime: str
    n_lsb: int
    media_id: str
    metadata: dict[str, str]
    private_key_pem: bytes
    passphrase: str | None = None  # required for derived start and/or encryption
    explicit_start: int | None = None  # set this to use EXPLICIT mode
    encrypt_message: bool = False


@dataclass
class ProtectOutcome:
    stego_bytes: bytes
    start_offset: int
    frame_bytes: int
    capacity_bytes: int
    payload_json: dict
    signature: bytes


def protect(opts: ProtectOptions) -> ProtectOutcome:
    """Embed a signed verification payload into a cover object.

    TODO(team): implement.

    Order of operations (each step is one call into another module):
      1. Decode the cover           image_codec.load_png / audio_codec.load_wav /
                                    video_codec.load_avi (embeds into the PCM
                                    audio track; frames are untouched)
      2. Hash it                    hashing.stable_media_hash(elements, n_lsb, header_fields)
      3. Derive keys (if needed)    kdf.derive_keys(passphrase, salt=sha256(media_id))
      4. Encrypt the message        payload.encrypt_message(k_enc, ...)   [optional]
      5. Build the payload          payload.Payload(...) with media_id, timestamp,
                                    media_hash, nonce, n_lsb, cover_kind, shape
      6. Serialize + sign           payload.serialize -> signing.sign(private_pem, ...)
      7. Build the frame            container.build_frame(...)
      8. CAPACITY CHECK             frame_size_bits vs lsb.capacity_bits — raise
                                    CapacityError with a helpful message; this is
                                    a REQUIRED demo case (spec Section 5)
      9. Choose the start           location.derive_start(...) or opts.explicit_start
     10. Embed                      lsb.bytes_to_bits -> lsb.embed_bits
     11. Re-encode                  image_codec.save_png / audio_codec.save_wav /
                                    video_codec.save_avi

    Step 2 must run on the ORIGINAL cover, and the same masked-hash formula must
    reproduce on the stego file — that is the whole point of the stable hash.
    """
    raise NotImplementedError("TODO(team): protect — see docstring")


@dataclass
class VerifyOptions:
    stego_bytes: bytes
    cover_kind: str
    public_key_pem: bytes
    n_lsb: int
    media_id: str
    passphrase: str | None = None
    explicit_start: int | None = None


@dataclass
class VerifyOutcome:
    verdict: Verdict
    reasons: list[str]
    payload_json: dict | None
    media_hash_embedded: str | None
    media_hash_recomputed: str | None
    start_offset_used: int | None


def verify(opts: VerifyOptions) -> VerifyOutcome:
    """Extract, check and judge. Never raises for a bad file — returns a verdict.

    TODO(team): implement.

    Order of operations:
      1. Decode the stego object. UnsupportedCoverError -> CANNOT_VERIFY.
      2. Resolve the start: explicit offset, or location.derive_start(...).
      3. Read HEADER_SIZE*8 bits there and container.parse_header(...).
         No MAGIC? -> location.scan_for_magic(...) decides between
         WRONG_START_LOCATION and PAYLOAD_MISSING.
      4. Read the rest of the frame using the lengths from the header, then
         container.parse_frame(...).
      5. signing.verify(public_pem, payload_bytes, signature).
      6. payload.deserialize, then recompute hashing.stable_media_hash with the
         n_lsb and header fields FROM THE SIGNED PAYLOAD, and compare.
      7. Cross-check the frame's n_lsb / shape / cover_kind against the signed
         values (catches parameter substitution and replay).
      8. Fill an ExtractionOutcome and call verdict.decide(...).

    Wrap each stage so an unexpected exception becomes CANNOT_VERIFY with the
    error in `reasons` — a crash during the live demo is worse than a verdict.
    """
    raise NotImplementedError("TODO(team): verify — see docstring")
