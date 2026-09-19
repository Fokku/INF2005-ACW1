"""protect() and verify() — the two end-to-end workflows (spec Section 7).

This is the ONLY module that imports every other one. Everything it calls is
already specified, so implementing this is mostly plumbing — but do it LAST,
after the pieces have tests.

    protect():  steps 1-6 of the required security workflow
    verify():   steps 7-10
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from . import (
    audio_codec,
    container,
    extraction,
    hashing,
    image_codec,
    kdf,
    location,
    lsb,
    signing,
    video_codec,
)
from . import payload as payload_mod
from .errors import CapacityError, FrameError, KeyError_, StegoError, UnsupportedCoverError
from .verdict import ExtractionOutcome, Verdict, decide


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


def _load_cover(cover_kind: str, cover_bytes: bytes):
    """Decode any of the three cover kinds into (cover, header_fields, shape).

    `header_fields` and `shape` are built the SAME way in protect and verify —
    that consistency is what makes the stable hash and the signed shape
    reproducible on both sides.
    """
    if cover_kind == "image":
        cover = image_codec.load_png(cover_bytes)
        header_fields = {
            "kind": "image",
            "height": cover.height,
            "width": cover.width,
            "channels": cover.channels,
        }
        shape = [cover.height, cover.width, cover.channels]
    elif cover_kind == "audio":
        cover = audio_codec.load_wav(cover_bytes)
        header_fields = {
            "kind": "audio",
            "rate": cover.sample_rate,
            "channels": cover.channels,
            "width": cover.sample_width,
        }
        shape = [cover.frames, cover.channels]
    elif cover_kind == "video":
        cover = video_codec.load_avi(cover_bytes)
        header_fields = {
            "kind": "video",
            "rate": cover.sample_rate,
            "channels": cover.channels,
            "width": cover.sample_width,
        }
        shape = [cover.frames, cover.channels]
    else:
        raise UnsupportedCoverError(f"unknown cover kind: {cover_kind!r}")
    return cover, header_fields, shape


def _save_cover(cover_kind: str, cover, elements) -> bytes:
    if cover_kind == "image":
        return image_codec.save_png(cover, elements)
    if cover_kind == "audio":
        return audio_codec.save_wav(cover, elements)
    if cover_kind == "video":
        return video_codec.save_avi(cover, elements)
    raise UnsupportedCoverError(f"unknown cover kind: {cover_kind!r}")


def protect(opts: ProtectOptions) -> ProtectOutcome:
    """Embed a signed verification payload into a cover object.

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
    cover, header_fields, shape = _load_cover(opts.cover_kind, opts.cover_bytes)
    elements = cover.elements
    n_elements = len(elements)

    media_hash = hashing.stable_media_hash(elements, opts.n_lsb, header_fields)

    derived = None
    if opts.passphrase:
        salt = hashlib.sha256(opts.media_id.encode("utf-8")).digest()
        derived = kdf.derive_keys(opts.passphrase, salt)

    message_bytes = opts.message
    encrypted = False
    if opts.encrypt_message:
        if derived is None:
            raise StegoError("a passphrase is required to encrypt the message")
        message_bytes = payload_mod.encrypt_message(
            derived.k_enc, message_bytes, aad=opts.media_id.encode("utf-8")
        )
        encrypted = True

    pl = payload_mod.Payload(
        media_id=opts.media_id,
        timestamp=datetime.now(UTC).isoformat(),
        media_hash=media_hash,
        nonce=payload_mod.new_nonce(),
        cover_kind=opts.cover_kind,
        n_lsb=opts.n_lsb,
        shape=shape,
        message_mime=opts.message_mime,
        message=message_bytes,
        encrypted=encrypted,
        metadata=opts.metadata,
    )
    payload_bytes = payload_mod.serialize(pl)
    signature = signing.sign(opts.private_key_pem, payload_bytes)
    frame = container.build_frame(payload_bytes, signature, opts.n_lsb, encrypted)

    # Required demo case (spec Section 5): a blanket "does this even fit
    # anywhere" check, with a message that names the shortfall directly,
    # rather than letting a cryptic CapacityError surface from deep inside
    # embed_bits for the common "message is too big" mistake.
    total_capacity_bits = lsb.capacity_bits(n_elements, opts.n_lsb)
    if len(frame) * 8 > total_capacity_bits:
        raise CapacityError(
            f"payload does not fit: the frame needs {len(frame)} bytes "
            f"({len(frame) * 8} bits) at n_lsb={opts.n_lsb}, but this cover only "
            f"has capacity for {total_capacity_bits // 8} bytes"
        )

    if opts.explicit_start is not None:
        start = opts.explicit_start
    else:
        if derived is None:
            raise StegoError("a passphrase is required for derived start-location mode")
        # Anchor the derivation to a fixed fraction of raw capacity (see
        # location.reserved_frame_bits) so the verifier — which does not yet
        # know the true frame size — lands on the exact same offset.
        start = location.derive_start(
            derived.k_loc,
            opts.media_id,
            opts.cover_kind,
            opts.n_lsb,
            n_elements,
            location.reserved_frame_bits(n_elements, opts.n_lsb),
        )

    # FR7: raw capacity alone does not guarantee room after the selected start.
    # Use the actual frame length here, not the derived-mode reservation.
    try:
        location.validate_start(n_elements, start, len(frame) * 8, opts.n_lsb)
    except ValueError as exc:
        raise StegoError(str(exc)) from exc

    bits = lsb.bytes_to_bits(frame)
    new_elements = lsb.embed_bits(elements, bits, start, opts.n_lsb)
    stego_bytes = _save_cover(opts.cover_kind, cover, new_elements)

    return ProtectOutcome(
        stego_bytes=stego_bytes,
        start_offset=start,
        frame_bytes=len(frame),
        capacity_bytes=total_capacity_bits // 8,
        payload_json=json.loads(payload_bytes),
        signature=signature,
    )


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
    signature_valid: bool | None = None


def _give_up(outcome: ExtractionOutcome, start: int | None, detail: str | None = None) -> VerifyOutcome:
    verdict, reasons = decide(outcome)
    if detail is not None:
        reasons.append(detail)
    return VerifyOutcome(
        verdict=verdict,
        reasons=reasons,
        payload_json=None,
        media_hash_embedded=None,
        media_hash_recomputed=None,
        start_offset_used=start,
        signature_valid=outcome.signature_valid,
    )


def verify(opts: VerifyOptions) -> VerifyOutcome:
    """Extract, check and judge. Never raises for a bad file — returns a verdict.

    Order of operations:
      1. Decode the stego object. UnsupportedCoverError -> CANNOT_VERIFY.
      2. Resolve the start: explicit offset, or location.derive_start(...).
      3. Read the magic at that start.
         No MAGIC? -> location.scan_for_magic(...) decides between
         WRONG_START_LOCATION and PAYLOAD_MISSING.
      4. extraction.extract_frame validates the header and lengths, then
         extracts the exact payload and signature bytes with a CRC check.
      5. signing.verify(public_pem, payload_bytes, signature).
      6. payload.deserialize, then recompute hashing.stable_media_hash with the
         n_lsb and header fields FROM THE SIGNED PAYLOAD, and compare.
      7. Cross-check the frame's n_lsb / shape / cover_kind against the signed
         values (catches parameter substitution and replay).
      8. Fill an ExtractionOutcome and call verdict.decide(...).

    Wrap each stage so an unexpected exception becomes CANNOT_VERIFY with the
    error in `reasons` — a crash during the live demo is worse than a verdict.
    """
    outcome = ExtractionOutcome()
    try:
        try:
            cover, header_fields, actual_shape = _load_cover(opts.cover_kind, opts.stego_bytes)
        except UnsupportedCoverError as exc:
            outcome.cover_supported = False
            outcome.error = str(exc)
            return _give_up(outcome, None)

        elements = cover.elements
        n_elements = len(elements)

        # --- 2. Resolve the start -------------------------------------------------
        start: int | None
        if opts.explicit_start is not None:
            start = opts.explicit_start
        elif opts.passphrase:
            salt = hashlib.sha256(opts.media_id.encode("utf-8")).digest()
            derived = kdf.derive_keys(opts.passphrase, salt)
            try:
                start = location.derive_start(
                    derived.k_loc,
                    opts.media_id,
                    opts.cover_kind,
                    opts.n_lsb,
                    n_elements,
                    location.reserved_frame_bits(n_elements, opts.n_lsb),
                )
            except CapacityError as exc:
                outcome.error = str(exc)
                return _give_up(outcome, None)
        else:
            outcome.error = "no passphrase or explicit start offset was supplied"
            return _give_up(outcome, None)

        # A location must hold the magic before we can recognize a frame.
        # If magic survives but the header is truncated, extraction reports
        # a damaged frame instead of treating it as a wrong location.
        try:
            location.validate_start(n_elements, start, len(container.MAGIC) * 8, opts.n_lsb)
        except (ValueError, CapacityError) as exc:
            outcome.error = str(exc)
            return _give_up(outcome, start)

        # --- 3. Distinguish absent magic from a present but damaged frame -----------
        magic_bits = lsb.extract_bits(elements, start, len(container.MAGIC) * 8, opts.n_lsb)
        outcome.magic_at_expected_start = lsb.bits_to_bytes(magic_bits) == container.MAGIC

        if not outcome.magic_at_expected_start:
            found = location.scan_for_magic(elements, opts.n_lsb, location.MAX_SCAN_POSITIONS)
            outcome.magic_found_elsewhere = found is not None
            magic_elements = -(-len(container.MAGIC) * 8 // opts.n_lsb)
            possible_starts = max(0, n_elements - magic_elements + 1)
            if found is None and possible_starts > location.MAX_SCAN_POSITIONS:
                outcome.error = (
                    f"no payload magic found in the first {location.MAX_SCAN_POSITIONS} candidate "
                    f"start locations at n_lsb={opts.n_lsb}; the remaining locations were not "
                    "searched, so payload absence cannot be confirmed. Check the original "
                    "passphrase, media ID, LSB count, or explicit start offset."
                )
            return _give_up(outcome, start)

        # --- 4. Read the rest of the frame ------------------------------------------
        try:
            frame = extraction.extract_frame(elements, start, opts.n_lsb)
            payload_bytes, signature = frame.payload_bytes, frame.signature
            frame_n_lsb = frame.n_lsb
            outcome.frame_parsed = True
            outcome.crc_ok = True
        except (FrameError, CapacityError) as exc:
            outcome.frame_parsed = False
            # Expected damaged-input status belongs to the existing frame-failed
            # rule. outcome.error is reserved for Cannot Verify conditions.
            return _give_up(outcome, start, detail=str(exc))

        # --- Deserialize the payload -------------------------------------------------
        try:
            pl = extraction.decode_payload(frame)
            outcome.payload_parsed = True
        except FrameError as exc:
            outcome.payload_parsed = False
            return _give_up(outcome, start, detail=str(exc))

        # --- 5. Signature ------------------------------------------------------------
        try:
            outcome.signature_valid = signing.verify(opts.public_key_pem, payload_bytes, signature)
        except KeyError_ as exc:
            outcome.public_key_usable = False
            outcome.error = str(exc)
            return _give_up(outcome, start)

        if not outcome.signature_valid:
            return _give_up(outcome, start)

        # --- 6. Recompute the media hash, using the SIGNED n_lsb but the ACTUAL
        # cover's own header fields (that's what "stable" means: reproducible
        # from the file itself, not taken on faith from the payload) ----------------
        media_hash_recomputed = hashing.stable_media_hash(elements, pl.n_lsb, header_fields)
        outcome.hash_match = media_hash_recomputed == pl.media_hash

        # --- 7. Cross-check frame/actual parameters against the signed payload -------
        # (the SIGNED shape vs the cover's ACTUAL shape is what catches a crop)
        outcome.params_match = (
            frame_n_lsb == pl.n_lsb
            and opts.cover_kind == pl.cover_kind
            and opts.media_id == pl.media_id
            and actual_shape == pl.shape
        )

        # --- Best-effort decrypt, for display only — never affects the verdict -------
        payload_json = json.loads(payload_bytes)
        if pl.encrypted and opts.passphrase:
            try:
                salt = hashlib.sha256(opts.media_id.encode("utf-8")).digest()
                derived = kdf.derive_keys(opts.passphrase, salt)
                plaintext = payload_mod.decrypt_message(
                    derived.k_enc, pl.message, aad=opts.media_id.encode("utf-8")
                )
                payload_json["message_b64"] = base64.b64encode(plaintext).decode("ascii")
            except FrameError:
                pass  # wrong passphrase for decryption alone does not change the verdict

        verdict, reasons = decide(outcome)
        return VerifyOutcome(
            verdict=verdict,
            reasons=reasons,
            payload_json=payload_json,
            media_hash_embedded=pl.media_hash,
            media_hash_recomputed=media_hash_recomputed,
            start_offset_used=start,
            signature_valid=outcome.signature_valid,
        )
    except StegoError as exc:
        outcome.error = str(exc)
        return _give_up(outcome, None)
    except Exception as exc:  # noqa: BLE001 - a crash during the live demo is worse than a verdict
        outcome.cover_supported = False
        outcome.error = f"unexpected error: {exc}"
        return _give_up(outcome, None)
