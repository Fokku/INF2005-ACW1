# Demo mode on Windows: one process, one URL, no Vite dev server.
# Run this in the lab, never `pnpm dev`. Usage: scripts\demo.ps1 [port]
param([int]$Port = 8000)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
& .\.venv\Scripts\Activate.ps1

if (-not (Test-Path "frontend\dist")) {
    Write-Host "==> Building the UI (first run only)"
    # "Stop" does not cover native commands: a failing pnpm only sets $LASTEXITCODE
    # (Windows PowerShell 5.1, and PowerShell 7 by default). Check it after each call,
    # as demo.sh's `set -e` does, so a failed build stops here instead of starting a
    # server with no UI.
    Push-Location frontend
    try {
        pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "pnpm install failed (exit code $LASTEXITCODE)" }
        pnpm build
        if ($LASTEXITCODE -ne 0) { throw "pnpm build failed (exit code $LASTEXITCODE)" }
    } catch {
        # dist did not exist before this build, so anything there now is partial.
        # Remove it, or the next run would see frontend\dist and skip the build.
        Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
        throw
    } finally {
        Pop-Location
    }
}

Write-Host "==> http://127.0.0.1:$Port"
$env:PYTHONPATH = (Join-Path (Get-Location) "backend")
python -m uvicorn app.main:app --port $Port --host 127.0.0.1
