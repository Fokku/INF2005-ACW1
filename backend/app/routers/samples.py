"""Demo samples: the curated files under `samples/`, one click away in the GUI.

`scripts/make_samples.py` protects the two covers with every positive and
negative case and records each case's verification settings in
`evidence/logs/sample-manifest.json`. This router turns that manifest into a
list the Verify tab can load directly — file, media ID, LSB count, start mode,
passphrase and public key — so a presenter never has to type settings on stage
(docs/demo-plan.md, "Contingencies": switch to the pre-generated file).

Only files a listed case names, inside `samples/`, and the public keys in
`keys/public/` are ever served. Private keys are never listed or served.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath, PureWindowsPath

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .. import storage

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
SAMPLES_DIR = ROOT / "samples"
MANIFEST = ROOT / "evidence" / "logs" / "sample-manifest.json"
TEAM_PUBLIC_KEY = "team_ed25519.pub.pem"
# Any real Ed25519 key other than the signer's demonstrates Signature Invalid.
# The Section F demo key is committed and did not sign the short-message samples
# these cases pair it with (the team key did). It did sign a file in samples/:
# samples/audio/stego/section-f-replay-source.wav, whose signed frame
# samples/audio/tampered/section-f-replay.wav replays (evidence/section-f.md).
# Neither is a sample case.
MISMATCHED_PUBLIC_KEY = "section-f-demo.pub.pem"
_SERVABLE = {".png", ".wav", ".avi"}


class SampleCase(BaseModel):
    id: str
    label: str
    kind: str  # "image" | "audio" | "video"
    file: str  # repo-relative path, forward slashes
    url: str
    expected_verdict: str
    media_id: str
    n_lsb: int
    start_mode: str  # "explicit" | "derived"
    explicit_start: int | None = None
    passphrase: str | None = None
    public_key: str  # a file name under keys/public/
    redundancy: int = 1
    note: str | None = None


_LABELS = {
    "short-authentic": "Short message",
    "large-authentic": "Large message",
    "custom-authentic": "Custom encrypted message",
    "tampered": "Tampered (high-bit flip)",
    "signature-invalid": "Signature Invalid (wrong public key)",
    "payload-missing": "Payload Missing (never protected)",
    "wrong-start-location": "Wrong Start Location (wrong passphrase)",
    "cannot-verify": "Cannot Verify (large unprotected cover)",
}


def _kind_of(path: str) -> str:
    return {".png": "image", ".wav": "audio", ".avi": "video"}[Path(path).suffix.lower()]


def _case_from_manifest(entry: dict, stego_by_kind: dict[str, str]) -> SampleCase | None:
    case_id = entry.get("case", "")
    settings = entry.get("settings", {})
    if "error" in entry or "media_id" not in settings:
        return None  # the oversized capacity case is a Protect-side demo, not a file

    prefix, _, rest = case_id.partition("-")
    file = entry.get("file")
    public_key = TEAM_PUBLIC_KEY
    note = settings.get("note")
    if file is None:
        # The manifest's Signature Invalid case reuses the short-message stego
        # file and verifies it with a mismatched key.
        file = stego_by_kind.get(prefix)
        if file is None:
            return None
        public_key = MISMATCHED_PUBLIC_KEY
        note = f"The file is genuine; it is verified with {MISMATCHED_PUBLIC_KEY}, a different key."
    file = file.replace("\\", "/")

    if "passphrase_used" in settings:
        passphrase = settings["passphrase_used"]
        note = note or "Verified with the wrong passphrase on purpose."
    else:
        passphrase = settings.get("passphrase")
    start_mode = settings.get("start_mode") or ("explicit" if "explicit_start" in settings else "derived")

    return SampleCase(
        id=case_id,
        label=f"{prefix.capitalize()} · {_LABELS.get(rest, rest)}",
        kind=_kind_of(file),
        file=file,
        url=f"/api/samples/file/{file.removeprefix('samples/')}",
        expected_verdict=entry.get("verdict") or settings.get("expected", ""),
        media_id=settings["media_id"],
        n_lsb=int(settings.get("n_lsb", 1)),
        start_mode=start_mode,
        explicit_start=settings.get("explicit_start") if start_mode == "explicit" else None,
        passphrase=passphrase,
        public_key=public_key,
        note=note,
    )


def _all_cases() -> list[SampleCase]:
    """Every verifiable case in the manifest, plus the README's Cannot Verify case,
    whether or not its file has been generated yet."""
    if not MANIFEST.is_file():
        return []
    entries = json.loads(MANIFEST.read_text(encoding="utf-8")).get("cases", [])

    stego_by_kind: dict[str, str] = {}
    for entry in entries:
        if entry.get("case", "").endswith("-short-authentic") and entry.get("file"):
            stego_by_kind[entry["case"].split("-", 1)[0]] = entry["file"]

    cases = [c for c in (_case_from_manifest(e, stego_by_kind) for e in entries) if c is not None]

    # README "Expected outputs": the full-size cover, never protected, is too
    # large for the bounded magic scan to prove absence -> Cannot Verify.
    big_cover = "samples/image/original/cover.png"
    if (ROOT / big_cover).is_file():
        cases.append(
            SampleCase(
                id="image-cannot-verify",
                label=f"Image · {_LABELS['cannot-verify']}",
                kind="image",
                file=big_cover,
                url=f"/api/samples/file/{big_cover.removeprefix('samples/')}",
                expected_verdict="Cannot Verify",
                media_id="P6-8-image-short",
                n_lsb=2,
                start_mode="explicit",
                explicit_start=128,
                public_key=TEAM_PUBLIC_KEY,
                note="The bounded magic scan stops before covering the whole file, so absence cannot be proven.",
            )
        )
    return cases


def list_cases() -> list[SampleCase]:
    """The cases whose file exists, i.e. the ones the Verify tab can load."""
    return [c for c in _all_cases() if (ROOT / c.file).is_file()]


def _is_plain_relative_path(path: str) -> bool:
    """True if `path` is a forward-slash relative path with no `..` step.

    Checked on the string alone, before `path` touches the filesystem. A NUL byte
    makes `resolve()` raise, which is a 500 instead of a 404. Worse, on the
    Windows demo host an absolute path joined onto SAMPLES_DIR replaces it, and
    `//host/share/x.png` (or `\\\\host\\share\\x.png`) names a network share:
    `resolve()` would open it over SMB, offering the presenter's NTLM credentials,
    before any containment check could refuse it. So NUL, backslashes, root,
    drive and UNC anchors and `..` are refused whatever the host OS is.
    """
    if not path or "\x00" in path or "\\" in path:
        return False
    posix = PurePosixPath(path)
    return not posix.is_absolute() and not PureWindowsPath(path).anchor and ".." not in posix.parts


@router.get("/samples", response_model=list[SampleCase])
async def samples() -> list[SampleCase]:
    return list_cases()


@router.get("/samples/file/{path:path}")
async def sample_file(path: str) -> FileResponse:
    """One case's file. Only a path some case in the manifest names is served
    (the GUI only ever requests `SampleCase.url`), and it is checked as a string
    before anything touches the filesystem. The resolved target must still lie
    inside samples/ and be PNG, WAV or AVI, so a symlink cannot lead out either."""
    listed = {case.file.removeprefix("samples/") for case in _all_cases()}
    if not _is_plain_relative_path(path) or path not in listed:
        raise HTTPException(status_code=404, detail="not a sample file")
    target = (SAMPLES_DIR / path).resolve()
    if not target.is_relative_to(SAMPLES_DIR.resolve()) or target.suffix.lower() not in _SERVABLE:
        raise HTTPException(status_code=404, detail="not a sample file")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="sample not found — run scripts/make_samples.py")
    return FileResponse(
        target,
        media_type=storage.MIME_BY_SUFFIX[target.suffix.lower()],
        filename=target.name,
        content_disposition_type="inline",
    )
