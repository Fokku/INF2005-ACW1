# One-time setup for a fresh clone. Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> Python virtualenv"
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e "backend[dev]"

Write-Host "==> Frontend"
if (Get-Command pnpm -ErrorAction SilentlyContinue) {
    Push-Location frontend
    pnpm install --frozen-lockfile
    pnpm build
    Pop-Location
} else {
    Write-Host "pnpm not found - skipping the UI build."
}

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "  stego serve            # http://127.0.0.1:8000"
