"""Browser-playable previews of covers the browser cannot play itself.

Chrome, Edge and Firefox do not play AVI, so a `<video>` element stays blank
for the video cover. The payload lives in the AVI's PCM audio track anyway
(`stego_core/video_codec.py`), so the GUI plays that track, re-wrapped as a
WAV, for the cover-versus-stego listening comparison.

Display only: the WAV is built from the decoded samples, never fed back into
embedding or verification.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, File, UploadFile

from stego_core import audio_codec, video_codec

from .. import storage
from ..schemas import FileRef

router = APIRouter()


@router.post("/preview/audio-track", response_model=FileRef)
async def audio_track(
    file: UploadFile = File(..., description="an AVI video with a PCM audio track"),
) -> FileRef:
    """Return the AVI's audio track as a WAV the browser can play."""
    cover = video_codec.load_avi(await file.read())
    track = audio_codec.AudioCover(
        elements=cover.elements,
        sample_rate=cover.sample_rate,
        channels=cover.channels,
        sample_width=cover.sample_width,
        frames=cover.frames,
    )
    wav = audio_codec.save_wav(track, cover.elements)
    return FileRef(**storage.save(wav, f"{Path(file.filename or 'video').stem}.audio-track.wav"))
