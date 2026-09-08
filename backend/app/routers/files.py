"""Serve stored output files. Complete — no TODO.

`/api/files/{id}`             inline, for <img src> and <audio src>
`/api/files/{id}?download=1`  Content-Disposition: attachment, for the
                              "party B downloads it to a folder" step
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from .. import storage

router = APIRouter()


@router.get("/files/{file_id}")
async def get_file(file_id: str, download: int = 0) -> FileResponse:
    path = storage.resolve(file_id)
    if path is None:
        raise HTTPException(status_code=404, detail="file not found (outputs are not kept forever)")
    mime = storage.MIME_BY_SUFFIX.get(path.suffix.lower(), "application/octet-stream")
    headers = {"Content-Disposition": f'attachment; filename="{path.name}"'} if download else None
    return FileResponse(path, media_type=mime, headers=headers)
