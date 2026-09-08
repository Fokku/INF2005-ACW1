"""FastAPI application.

Complete — no TODO. It wires the routers, maps `stego_core` exceptions to clean
HTTP responses, and serves the built frontend so the demo is a single process.

While the core is unimplemented, every endpoint that needs it returns HTTP 501
with `{"error": "not_implemented", "todo": "<function to write>"}`. The UI shows
that message, so you can click through the whole interface today and watch it
come alive as teammates fill the functions in.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from stego_core.errors import StegoError

from .routers import attack, capacity, files, keys, protect, verify
from .schemas import HealthResponse

log = logging.getLogger("acw1")

ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = ROOT / "frontend" / "dist"

app = FastAPI(
    title="ACW1 — Steganographic Image and Audio Integrity Verification",
    description=(
        "LSB-replacement steganography with SHA-256 hashing and Ed25519 digital "
        "signatures. Use this page to exercise the API while the web UI is being built."
    ),
    version="0.1.0",
)


@app.exception_handler(NotImplementedError)
async def _not_implemented(request: Request, exc: NotImplementedError) -> JSONResponse:
    """Turn an unimplemented core function into a helpful 501 for the UI."""
    return JSONResponse(
        status_code=501,
        content={
            "error": "not_implemented",
            "detail": "This feature is not implemented yet.",
            "todo": str(exc),
        },
    )


@app.exception_handler(StegoError)
async def _stego_error(request: Request, exc: StegoError) -> JSONResponse:
    status = 415 if exc.code == "unsupported_cover" else 400
    return JSONResponse(status_code=status, content={"error": exc.code, "detail": str(exc)})


app.include_router(keys.router, prefix="/api", tags=["keys"])
app.include_router(capacity.router, prefix="/api", tags=["capacity"])
app.include_router(protect.router, prefix="/api", tags=["protect"])
app.include_router(verify.router, prefix="/api", tags=["verify"])
app.include_router(attack.router, prefix="/api", tags=["attack"])
app.include_router(files.router, prefix="/api", tags=["files"])


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=app.version, frontend_built=FRONTEND_DIST.is_dir())


# Serve the built UI last, so /api/* always wins. In development the Vite dev
# server on :5173 proxies /api here instead, and this mount simply does not exist.
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="ui")
else:
    log.warning("frontend/dist not found — run `cd frontend && pnpm build`, or use `pnpm dev`")

    @app.get("/")
    async def _no_ui() -> dict[str, str]:
        return {
            "message": "API is running. The UI is not built.",
            "build_it": "cd frontend && pnpm install && pnpm build",
            "or_dev": "cd frontend && pnpm dev   (http://127.0.0.1:5173)",
            "api_docs": "/docs",
        }
