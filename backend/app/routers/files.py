"""Serve stored output files. Complete — no TODO.

`/api/files/{id}`             inline, for <img src> and <audio src>
`/api/files/{id}?download=1`  Content-Disposition: attachment, for the
                              "party B downloads it to a folder" step
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from .. import storage

router = APIRouter()


def _safe_filename(name: str | None, fallback: str) -> str:
    """The name the browser saves the download as, not a filesystem path.

    `name` came in on a query string param, so it must be stripped of any
    directory components (path traversal) and header-breaking characters
    (CRLF response-splitting, stray quotes) before landing in
    Content-Disposition.
    """
    if not name:
        return fallback
    cleaned = Path(name).name.replace("\r", "").replace("\n", "").replace('"', "")
    return cleaned or fallback


@router.get("/files/{file_id}")
async def get_file(file_id: str, download: int = 0, filename: str | None = None) -> FileResponse:
    path = storage.resolve(file_id)
    if path is None:
        raise HTTPException(status_code=404, detail="file not found (outputs are not kept forever)")
    mime = storage.MIME_BY_SUFFIX.get(path.suffix.lower(), "application/octet-stream")
    headers = None
    if download:
        name = _safe_filename(filename, fallback=path.name)
        headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    return FileResponse(path, media_type=mime, headers=headers)
