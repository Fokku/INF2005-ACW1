"""Steganalysis (optional challenge): does this file look like it carries an
LSB payload? Method by Ke Ying; the analysis lives in `stego_core.steganalysis`
and is shared with `scripts/steganalysis.py`.

The response models are defined here rather than in `schemas.py` because no
other endpoint uses them.

Chart downsampling: every window is analysed at the requested size, so the
call, the counts and `suspected_region` are exact. Only the `windows` list is
thinned for the UI chart: if a file yields more than MAX_CHART_WINDOWS windows,
runs of `windows_merged` consecutive windows become one entry that keeps the
most suspicious value of its members (highest chi-square p, lowest byte-phase
p, flagged if any member was). See `steganalysis.merge_windows`.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, File, Form, UploadFile
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from stego_core import steganalysis

from .capacity import _sniff_kind

router = APIRouter()

MAX_CHART_WINDOWS = 400


class SuspectedRegion(BaseModel):
    start: int = Field(description="first element of the first flagged window")
    end: int = Field(description="one past the last element of the last flagged window")


class SteganalysisWindow(BaseModel):
    start: int
    end: int
    chi_square_p: float | None = Field(
        description="pairs-of-values p-value; near 1 = pairs evened out. null if too few repeated values"
    )
    phase_p: float | None = Field(description="byte-phase p-value; near 0 = byte-periodic low bits")
    flagged: bool = Field(description="phase_p is below the flagging threshold (1e-6)")


class SteganalysisReport(BaseModel):
    filename: str
    kind: Literal["image", "audio", "video"]
    elements: int = Field(
        description="values analysed: colour values, audio samples, or the AVI's PCM samples"
    )
    window: int = Field(
        description="window size actually used (a file shorter than the request is one window)"
    )
    chi_square_p: float | None = Field(description="whole-file pairs-of-values p-value")
    phase_p: float | None = Field(description="strongest (smallest) per-window byte-phase p-value")
    phase_n_lsb_guess: int | None = Field(
        description="rough guess (1, 2 or 4) of LSBs per element; null unless suspicious"
    )
    suspicious: bool
    verdict: str
    summary: str
    suspected_region: SuspectedRegion | None
    windows: list[SteganalysisWindow]
    windows_total: int = Field(description="windows analysed at full resolution")
    windows_flagged: int = Field(description="flagged windows at full resolution")
    windows_merged: int = Field(description="analysed windows per entry of `windows` (1 = not downsampled)")
    method: str


@router.post("/steganalysis", response_model=SteganalysisReport)
async def run_steganalysis(
    file: UploadFile = File(..., description="PNG, WAV, or AVI file to examine"),
    window: int = Form(steganalysis.DEFAULT_WINDOW, ge=steganalysis.MIN_WINDOW),
) -> SteganalysisReport:
    """Look for statistical traces of LSB embedding, without any key."""
    filename = file.filename or "upload"
    kind = _sniff_kind(filename)
    data = await file.read()

    def analyse() -> steganalysis.Assessment:
        return steganalysis.assess(steganalysis.decode_elements(data, kind.value), kind.value, window)

    result = await run_in_threadpool(analyse)  # CPU-bound; keep the event loop free
    chart, merged = steganalysis.merge_windows(result.windows, MAX_CHART_WINDOWS)
    region = result.suspected_region
    return SteganalysisReport(
        filename=filename,
        kind=kind.value,
        elements=result.elements,
        window=result.window,
        chi_square_p=result.chi_square_p,
        phase_p=result.phase_p,
        phase_n_lsb_guess=result.phase_n_lsb_guess,
        suspicious=result.suspicious,
        verdict=result.verdict,
        summary=result.summary,
        suspected_region=SuspectedRegion(start=region[0], end=region[1]) if region else None,
        windows=[
            SteganalysisWindow(
                start=w.start, end=w.end, chi_square_p=w.chi_square_p, phase_p=w.phase_p, flagged=w.flagged
            )
            for w in chart
        ],
        windows_total=len(result.windows),
        windows_flagged=result.windows_flagged,
        windows_merged=merged,
        method=steganalysis.METHOD,
    )
