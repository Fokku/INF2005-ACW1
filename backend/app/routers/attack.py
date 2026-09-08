"""Attack Lab: generate the negative test cases on demand.

The spec needs at least three negative cases (Section 5) and lists an "attack
simulation module" as a candidate innovation (Section 8). Doing it in the GUI
makes the demo reproducible: press a button, get a tampered file, verify it,
watch the verdict change.
"""

from __future__ import annotations

from fastapi import APIRouter, File, Form, UploadFile

from stego_core.attacks import EXPECTED

from ..schemas import AttackKind, AttackResult

router = APIRouter()


@router.get("/attack/kinds")
async def kinds() -> list[dict[str, str]]:
    """List the available attacks and the verdict each one should produce.

    Complete — no TODO. The UI uses this to build the Attack Lab buttons, so the
    list stays in sync with `stego_core.attacks.EXPECTED` automatically.
    """
    labels = {
        "flip_bits": "Flip high bits in a region (visible/audible edit)",
        "crop": "Crop the image / truncate the audio",
        "lsb_scrub": "Zero the LSB plane (looks and sounds identical)",
        "reencode": "Re-encode via JPEG / resample the audio",
        "corrupt_payload": "Flip bits inside the embedded frame",
        "replay": "Transplant the frame into a different cover",
    }
    return [
        {"kind": k, "expected_verdict": v.value, "description": labels.get(k, k)} for k, v in EXPECTED.items()
    ]


@router.post("/attack", response_model=AttackResult)
async def run_attack(
    stego: UploadFile = File(...),
    attack: AttackKind = Form(...),
    n_lsb: int = Form(1, ge=1, le=8),
    start_offset: int = Form(0),
    other_cover: UploadFile | None = File(None, description="target cover for the replay attack"),
) -> AttackResult:
    """Damage a stego file in a controlled way and return the result.

    TODO(team): implement.

    Steps:
      1. Read the upload and sniff the cover kind.
      2. Dispatch to the matching function in stego_core.attacks.
      3. storage.save() the damaged file with a name that says what happened
         (e.g. "lena.stego.flip_bits.png") — these files go into samples/tampered/.
      4. Return AttackResult with EXPECTED[attack] as expected_verdict, so the
         demo can state the prediction before running Verify.
    """
    raise NotImplementedError("TODO(team): app/routers/attack.py::run_attack")
