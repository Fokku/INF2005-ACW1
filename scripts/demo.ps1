# Demo mode on Windows: one process, one URL, no Vite dev server.
# Run this in the lab, never `pnpm dev`. Usage: scripts\demo.ps1 [port]
param([int]$Port = 8000)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
& .\.venv\Scripts\Activate.ps1

if (-not (Test-Path "frontend\dist")) {
    Write-Host "==> Building the UI (first run only)"
    Push-Location frontend
    pnpm install --frozen-lockfile
    pnpm build
    Pop-Location
}

Write-Host "==> http://127.0.0.1:$Port"
$env:PYTHONPATH = (Join-Path (Get-Location) "backend")
python -m uvicorn app.main:app --port $Port --host 127.0.0.1
