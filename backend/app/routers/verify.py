"""Verify: extract, check the signature and the hash, and return a verdict.

Covers steps 7-10 of the required security workflow (spec Section 7) and
FR8, FR9, FR10.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from stego_core import hashing, pipeline
from stego_core.errors import UnsupportedCoverError

from .. import storage
from ..schemas import CoverInfo, CoverKind, FileRef, PayloadInfo, StartMode, VerifyReport
from .capacity import _cover_info, _decode_cover, _sniff_kind

router = APIRouter()

_EXT_BY_MIME = {
    "text/plain": ".txt",
    "image/png": ".png",
    "audio/wav": ".wav",
    "application/json": ".json",
}


@router.post("/verify", response_model=VerifyReport)
async def verify(
    stego: UploadFile = File(..., description="the received PNG, WAV, or AVI"),
    public_key_pem: UploadFile | None = File(None),
    public_key_text: str | None = Form(None, description="pasted PEM, as an alternative to uploading"),
    n_lsb: int = Form(1, ge=1, le=8),
    media_id: str = Form(...),
    start_mode: StartMode = Form(StartMode.derived),
    explicit_start: int | None = Form(None),
    passphrase: str | None = Form(None),
) -> VerifyReport:
    """Judge a file and explain the judgement.

    This endpoint must NOT raise for a bad file. A missing payload, a wrong key
    and a corrupted frame are all normal outcomes with their own verdict. Only
    a genuinely broken request (no file at all) is an HTTP error.
    """
    if start_mode == StartMode.explicit and explicit_start is None:
        raise HTTPException(status_code=400, detail="explicit start mode requires an explicit_start offset")

    stego_bytes = await stego.read()

    try:
        kind = _sniff_kind(stego.filename or "")
    except UnsupportedCoverError as exc:
        fallback = CoverInfo(
            kind=CoverKind.image,
            filename=stego.filename or "stego",
            size_bytes=len(stego_bytes),
            sha256=hashing.sha256_hex(stego_bytes),
        )
        return VerifyReport(
            verdict="Cannot Verify",
            reasons=[str(exc)],
            stego=fallback,
            n_lsb=n_lsb,
            start_mode=start_mode,
            payload_found=False,
        )

    if public_key_pem is not None:
        public_key_bytes = await public_key_pem.read()
    elif public_key_text is not None:
        public_key_bytes = public_key_text.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="a public key (file or pasted text) is required")

    opts = pipeline.VerifyOptions(
        stego_bytes=stego_bytes,
        cover_kind=kind.value,
        public_key_pem=public_key_bytes,
        n_lsb=n_lsb,
        media_id=media_id,
        passphrase=passphrase or None,
        explicit_start=explicit_start if start_mode == StartMode.explicit else None,
    )
    outcome = pipeline.verify(opts)

    try:
        decoded = _decode_cover(kind, stego_bytes)
        cover_info = _cover_info(kind, stego.filename or "stego", stego_bytes, decoded)
    except UnsupportedCoverError:
        cover_info = CoverInfo(
            kind=kind,
            filename=stego.filename or "stego",
            size_bytes=len(stego_bytes),
            sha256=hashing.sha256_hex(stego_bytes),
        )

    payload_info = None
    if outcome.payload_json is not None:
        pd = outcome.payload_json
        message_bytes = base64.b64decode(pd["message_b64"])
        message_text = None
        message_file = None
        if pd["message_mime"].startswith("text/") and not pd["encrypted"]:
            try:
                message_text = message_bytes.decode("utf-8")
            except UnicodeDecodeError:
                message_text = None
        if message_text is None:
            # Either a non-text MIME, or an encrypted message pipeline.verify
            # could not decrypt (no/wrong passphrase) — offer it as a file
            # either way; pd["encrypted"] still truthfully records whether it
            # WAS sent encrypted, separately from whether we could read it.
            ext = _EXT_BY_MIME.get(pd["message_mime"], ".bin")
            message_file = FileRef(**storage.save(message_bytes, f"message{ext}"))

        payload_info = PayloadInfo(
            version=pd["version"],
            media_id=pd["media_id"],
            timestamp=pd["timestamp"],
            cover_kind=kind,
            n_lsb=pd["n_lsb"],
            shape=pd["shape"],
            media_hash=pd["media_hash"],
            nonce=pd["nonce"],
            metadata=pd["metadata"],
            message_mime=pd["message_mime"],
            message_encrypted=pd["encrypted"],
            message_text=message_text,
            message_file=message_file,
        )

    hash_match = None
    if outcome.media_hash_embedded is not None and outcome.media_hash_recomputed is not None:
        hash_match = outcome.media_hash_embedded == outcome.media_hash_recomputed

    payload_found = outcome.verdict.value not in ("Payload Missing", "Cannot Verify")

    return VerifyReport(
        verdict=outcome.verdict,
        reasons=outcome.reasons,
        stego=cover_info,
        n_lsb=n_lsb,
        start_mode=start_mode,
        start_offset_used=outcome.start_offset_used,
        payload_found=payload_found,
        signature_valid=outcome.signature_valid,
        media_hash_embedded=outcome.media_hash_embedded,
        media_hash_recomputed=outcome.media_hash_recomputed,
        hash_match=hash_match,
        payload=payload_info,
    )
