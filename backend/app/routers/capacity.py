"""Cover capacity check (spec Section 5: "is payload size larger than cover
object size?"). This is a REQUIRED demo case, so it gets its own endpoint and
its own panel in the UI.
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile

from ..schemas import CapacityReport

router = APIRouter()


@router.post("/capacity", response_model=CapacityReport)
async def check_capacity(
    cover: UploadFile = File(..., description="PNG or WAV cover object"),
    n_lsb: int = Form(1, ge=1, le=8),
    payload_bytes: int | None = Form(None, description="size of the message the user wants to hide"),
) -> CapacityReport:
    """Report how much this cover can hold, and whether the message fits.

    TODO(team): implement.

    Steps:
      1. data = await cover.read()
      2. Sniff the kind from the filename/content type: .png -> image, .wav -> audio.
      3. Decode with image_codec.load_png / audio_codec.load_wav (raises
         UnsupportedCoverError, which main.py already turns into HTTP 415).
      4. capacity_bits = lsb.capacity_bits(len(elements), n_lsb)
      5. overhead = container.frame_size_bytes(0, signing.SIGNATURE_BYTES)
         plus a realistic allowance for the JSON payload fields (~300 bytes) —
         document the number you choose.
      6. Fill in CapacityReport, including cover.sha256 and the ImageInfo /
         AudioInfo block, and set `fits`.

    Make the failure message specific: the demo case is "payload is bigger than
    the cover", and the marker wants to see the tool say so clearly.
    """
    raise NotImplementedError("TODO(team): app/routers/capacity.py::check_capacity")
