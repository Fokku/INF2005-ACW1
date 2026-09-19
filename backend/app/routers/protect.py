"""Protect: embed a signed verification payload into a cover object.

Covers steps 1-6 of the required security workflow (spec Section 7) and
FR3, FR4, FR5, FR6, FR7.
"""

from __future__ import annotations

import base64
import json

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from stego_core import image_codec, pipeline

from .. import storage
from ..schemas import CoverKind, FileRef, PayloadInfo, ProtectResult, StartMode
from .capacity import _cover_info, _decode_cover, _sniff_kind

router = APIRouter()

_SUFFIX = {CoverKind.image: ".png", CoverKind.audio: ".wav", CoverKind.video: ".avi"}


@router.post("/protect", response_model=ProtectResult)
async def protect(
    cover: UploadFile = File(..., description="PNG image, WAV audio, or AVI video"),
    message: UploadFile | None = File(None, description="message file, if not sending text"),
    message_text: str | None = Form(None, description="message typed into the GUI"),
    message_mime: str = Form("text/plain"),
    n_lsb: int = Form(1, ge=1, le=8),
    media_id: str = Form(..., description="team-chosen ID for this media item"),
    metadata_json: str = Form("{}", description="team-defined metadata as a JSON object"),
    start_mode: StartMode = Form(StartMode.derived),
    explicit_start: int | None = Form(None, description="element offset, when start_mode=explicit"),
    passphrase: str | None = Form(None, description="shared secret for the derived start / encryption"),
    encrypt_message: bool = Form(False),
    private_key_pem: UploadFile | None = File(None),
) -> ProtectResult:
    """Embed and sign, then return the stego file plus everything the demo needs
    to explain what happened.
    """
    if start_mode == StartMode.explicit and explicit_start is None:
        raise HTTPException(status_code=400, detail="explicit start mode requires an explicit_start offset")

    cover_bytes = await cover.read()
    kind = _sniff_kind(cover.filename or "")

    if message is not None:
        message_bytes = await message.read()
    elif message_text is not None:
        message_bytes = message_text.encode("utf-8")
    else:
        raise HTTPException(status_code=400, detail="either `message` or `message_text` is required")

    if private_key_pem is None:
        raise HTTPException(status_code=400, detail="a private key PEM is required to sign the payload")
    private_key_bytes = await private_key_pem.read()

    try:
        metadata = json.loads(metadata_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"metadata_json is not valid JSON: {exc}") from exc

    opts = pipeline.ProtectOptions(
        cover_bytes=cover_bytes,
        cover_kind=kind.value,
        message=message_bytes,
        message_mime=message_mime,
        n_lsb=n_lsb,
        media_id=media_id,
        metadata=metadata,
        private_key_pem=private_key_bytes,
        passphrase=passphrase or None,
        explicit_start=explicit_start if start_mode == StartMode.explicit else None,
        encrypt_message=encrypt_message,
    )
    outcome = pipeline.protect(opts)

    base_name = (cover.filename or "cover").rsplit(".", 1)[0]
    stego_ref = FileRef(**storage.save(outcome.stego_bytes, f"{base_name}.stego{_SUFFIX[kind]}"))

    diff_ref = None
    if kind == CoverKind.image:
        # A round-trip re-decode of the stego bytes, purely to render the
        # amplified LSB-plane comparison image for the GUI.
        stego_cover = image_codec.load_png(outcome.stego_bytes)
        diff_bytes = image_codec.lsb_plane_png(stego_cover, stego_cover.elements, n_lsb)
        diff_ref = FileRef(**storage.save(diff_bytes, f"{base_name}.diff.png"))

    cover_decoded = _decode_cover(kind, cover_bytes)
    cover_info = _cover_info(kind, cover.filename or "cover", cover_bytes, cover_decoded)

    pd = outcome.payload_json
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
        message_text=message_text if (not encrypt_message and message_mime.startswith("text/")) else None,
    )

    return ProtectResult(
        stego=stego_ref,
        cover=cover_info,
        n_lsb=n_lsb,
        start_mode=start_mode,
        start_offset=outcome.start_offset,
        payload=payload_info,
        signature_b64=base64.b64encode(outcome.signature).decode("ascii"),
        frame_bytes=outcome.frame_bytes,
        capacity_bytes=outcome.capacity_bytes,
        diff=diff_ref,
    )
