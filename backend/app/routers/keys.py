"""Key management (spec FR4).

Generating a key pair in the browser is a demo convenience. In a real
deployment the private key never leaves the signer's machine — say so during
the demo, and mention that these keys exist only for the assignment.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from stego_core import signing
from stego_core.errors import KeyError_

from .. import storage
from ..schemas import KeyInfo, KeyPairResult

router = APIRouter()

PUBLIC_KEYS_DIR = Path(__file__).resolve().parents[3] / "keys" / "public"


class PublicKeyFile(BaseModel):
    """A committed public key under keys/public/ (never a private key)."""

    name: str
    fingerprint: str
    public_key_pem: str
    url: str


@router.post("/keys/generate", response_model=KeyPairResult)
async def generate(label: str = "team") -> KeyPairResult:
    """Create a fresh Ed25519 key pair and offer both halves as downloads."""
    private_pem, public_pem = signing.generate_keypair()
    fp = signing.fingerprint(public_pem)
    return KeyPairResult(
        key=KeyInfo(
            key_id=fp[:16],
            label=label,
            public_key_pem=public_pem.decode(),
            fingerprint=fp,
        ),
        public_key_file=storage.save(public_pem, f"{label}_ed25519.pub.pem"),
        private_key_file=storage.save(private_pem, f"{label}_ed25519.pem"),
    )


@router.post("/keys/inspect", response_model=KeyInfo)
async def inspect(
    public_key_pem: str = Form(..., description="PEM text of an Ed25519 public key"),
) -> KeyInfo:
    """Show the fingerprint of a public key, so both parties can confirm they
    hold the same one before trusting a verdict."""
    try:
        fp = signing.fingerprint(public_key_pem.encode())
    except (KeyError_, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"not a usable public key: {exc}") from exc
    return KeyInfo(key_id=fp[:16], label="imported", public_key_pem=public_key_pem, fingerprint=fp)


def _is_plain_pem_name(name: str) -> bool:
    """True if `name` is a bare `.pem` file name: no directory, drive, backslash or NUL.

    Checked on the string alone, before `name` touches the filesystem. A NUL byte
    makes `resolve()` raise, which is a 500 instead of a 404. On the Windows demo
    host a backslash or a drive (`C:x.pem`) would point outside keys/public/, so
    both are refused whatever the host OS is.
    """
    return (
        name.endswith(".pem")
        and "\x00" not in name
        and PurePosixPath(name).name == name
        and PureWindowsPath(name).name == name
    )


def _committed_public_key(name: str) -> tuple[Path, PublicKeyFile] | None:
    """`keys/public/<name>` and its listing entry, or None if it must be neither listed nor served.

    The listing and the download both go through here, so they agree. The file
    must resolve to a file directly inside keys/public/ (a symlink cannot lead
    out), hold a usable Ed25519 public key (an unparseable or unsupported key is
    skipped, not a 500 for the whole list), and contain no private key block:
    `cryptography` reads only the first PEM block, so a public-then-private bundle
    parses as a public key and would otherwise be published whole.
    """
    if not _is_plain_pem_name(name):
        return None
    path = (PUBLIC_KEYS_DIR / name).resolve()
    if path.parent != PUBLIC_KEYS_DIR.resolve():
        return None
    try:
        pem = path.read_bytes()
        fp = signing.fingerprint(pem)
        text = pem.decode()
    except (OSError, KeyError_, UnicodeDecodeError):
        return None
    if "PRIVATE KEY" in text:
        return None
    return path, PublicKeyFile(name=name, fingerprint=fp, public_key_pem=text, url=f"/api/keys/public/{name}")


@router.get("/keys/public", response_model=list[PublicKeyFile])
async def public_keys() -> list[PublicKeyFile]:
    """The team's committed public keys, so the Verify tab can pick one without
    a file dialog. Only `keys/public/*.pem` is read; `keys/private/` never is."""
    keys = []
    for path in sorted(PUBLIC_KEYS_DIR.glob("*.pem")):
        found = _committed_public_key(path.name)
        if found is not None:
            keys.append(found[1])
    return keys


@router.get("/keys/public/{name}")
async def public_key_file(name: str) -> FileResponse:
    """Download one committed public key: exactly the files the listing shows."""
    found = _committed_public_key(name)
    if found is None:
        raise HTTPException(status_code=404, detail="public key not found")
    return FileResponse(found[0], media_type="application/x-pem-file", filename=name)
