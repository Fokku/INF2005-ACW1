"""Generate controlled negative verification cases for the Attack Lab."""

from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from stego_core import attacks

from .. import storage
from ..schemas import AttackKind, AttackResult, FileRef
from .capacity import _decode_cover, _sniff_kind

router = APIRouter()


@router.get("/attack/kinds")
async def kinds() -> list[dict[str, str]]:
    return [
        {"kind": key, "expected_verdict": verdict.value, "description": attacks.DESCRIPTIONS[key]}
        for key, verdict in attacks.EXPECTED.items()
    ]


@router.post("/attack", response_model=AttackResult)
async def run_attack(
    stego: UploadFile = File(...),
    attack: AttackKind = Form(...),
    n_lsb: int = Form(1, ge=1, le=8),
    start_offset: int = Form(0, ge=0),
    other_cover: UploadFile | None = File(None),
) -> AttackResult:
    kind = _sniff_kind(stego.filename or "")
    data = await stego.read()
    name = attack.value
    try:
        if attack == AttackKind.flip_bits:
            cover = _decode_cover(kind, data)
            if n_lsb >= cover.elements.dtype.itemsize * 8:
                raise ValueError("no high bits remain outside the LSB plane; use fewer LSBs for this demo")
            output = attacks.flip_bits(data, kind.value)
        elif attack == AttackKind.crop:
            output = attacks.crop(data, kind.value)
        elif attack == AttackKind.lsb_scrub:
            output = attacks.lsb_scrub(data, kind.value, n_lsb)
        elif attack == AttackKind.reencode:
            output = attacks.reencode(data, kind.value)
        elif attack == AttackKind.corrupt_payload:
            output = attacks.corrupt_payload(data, kind.value, n_lsb, start_offset)
        else:
            if other_cover is None:
                raise ValueError("a second cover is required for replay")
            if _sniff_kind(other_cover.filename or "") != kind:
                raise ValueError("replay target must have the same cover kind")
            output = attacks.replay(data, await other_cover.read(), kind.value, n_lsb, start_offset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    suffix = {"image": ".png", "audio": ".wav", "video": ".avi"}[kind.value]
    filename = f"{Path(stego.filename or 'cover').stem}.{name}{suffix}"
    return AttackResult(
        attack=attack,
        description=attacks.DESCRIPTIONS[name],
        expected_verdict=attacks.EXPECTED[name],
        output=FileRef(**storage.save(output, filename)),
    )
