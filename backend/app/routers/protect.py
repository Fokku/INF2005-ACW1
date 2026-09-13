"""Protect: embed a signed verification payload into a cover object.

Covers steps 1-6 of the required security workflow (spec Section 7) and
FR3, FR4, FR5, FR6, FR7.
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile

from ..schemas import ProtectResult, StartMode

router = APIRouter()


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

    TODO(team): implement.

    Steps:
      1. Read the uploads; take the message from `message` or `message_text`.
      2. Sniff the cover kind (.png -> image, .wav -> audio, .avi -> video).
      3. Build pipeline.ProtectOptions from these fields and call pipeline.protect().
      4. storage.save() the stego bytes with a sensible filename
         (e.g. "lena.stego.png") so the download in the A-to-B demo is readable.
      5. For image covers, also save image_codec.lsb_plane_png() as `diff` —
         it makes the side-by-side comparison convincing. There is no video-side
         equivalent: the payload lives in the audio track, not the frames, so an
         `AudioCompare`-style before/after listen is the right comparison, not a
         visual diff.
      6. Fill in ProtectResult, including start_offset, frame_bytes,
         capacity_bytes and the decoded payload.

    Return the start_offset even in derived mode: the demo has to SHOW that the
    location was chosen by the key rather than fixed at the top-left corner
    (learning outcome 6).

    A CapacityError from the core already becomes a clean HTTP 400 via main.py.
    """
    raise NotImplementedError("TODO(team): app/routers/protect.py::protect")
