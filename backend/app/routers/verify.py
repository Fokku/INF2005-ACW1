"""Verify: extract, check the signature and the hash, and return a verdict.

Covers steps 7-10 of the required security workflow (spec Section 7) and
FR8, FR9, FR10.
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile

from ..schemas import StartMode, VerifyReport

router = APIRouter()


@router.post("/verify", response_model=VerifyReport)
async def verify(
    stego: UploadFile = File(..., description="the received PNG or WAV"),
    public_key_pem: UploadFile | None = File(None),
    public_key_text: str | None = Form(None, description="pasted PEM, as an alternative to uploading"),
    n_lsb: int = Form(1, ge=1, le=8),
    media_id: str = Form(...),
    start_mode: StartMode = Form(StartMode.derived),
    explicit_start: int | None = Form(None),
    passphrase: str | None = Form(None),
) -> VerifyReport:
    """Judge a file and explain the judgement.

    TODO(team): implement.

    Steps:
      1. Read the uploads; take the key from the file or the pasted text.
      2. Build pipeline.VerifyOptions and call pipeline.verify().
      3. If a message came back, storage.save() it so the GUI can display or
         PLAY it — the spec requires the GUI to be able to play/execute the
         payload, and that is what PayloadPreview does with the file URL.
      4. Fill in VerifyReport: verdict, reasons, both hashes, hash_match,
         signature_valid, start_offset_used and the decoded payload.

    This endpoint must NOT raise for a bad file. A missing payload, a wrong key
    and a corrupted frame are all normal outcomes with their own verdict. Only
    a genuinely broken request (no file at all) is an HTTP error.
    """
    raise NotImplementedError("TODO(team): app/routers/verify.py::verify")
