"""Output file store.

Stego objects and extracted payloads are written to `out/` and handed to the
browser as URLs. They are NEVER base64-inlined in JSON: a 50 MB WAV would become
67 MB of JSON and neither <img> nor <audio> can stream that.

This module is COMPLETE — no TODO.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[2] / "out"

MIME_BY_SUFFIX = {
    ".png": "image/png",
    ".wav": "audio/wav",
    ".txt": "text/plain",
    ".json": "application/json",
    ".pem": "application/x-pem-file",
    ".bin": "application/octet-stream",
}


def _ensure_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def save(data: bytes, filename: str) -> dict:
    """Write bytes to out/<uuid><suffix> and return a FileRef-shaped dict."""
    _ensure_dir()
    suffix = Path(filename).suffix.lower() or ".bin"
    file_id = uuid.uuid4().hex
    path = OUT_DIR / f"{file_id}{suffix}"
    path.write_bytes(data)
    return {
        "file_id": file_id,
        "filename": filename,
        "mime": MIME_BY_SUFFIX.get(suffix, "application/octet-stream"),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "url": f"/api/files/{file_id}",
        "download_url": f"/api/files/{file_id}?download=1",
    }


def resolve(file_id: str) -> Path | None:
    """Find a stored file by id. Returns None if it does not exist."""
    if not file_id.isalnum():  # no path traversal
        return None
    _ensure_dir()
    for path in OUT_DIR.glob(f"{file_id}.*"):
        return path
    return None
