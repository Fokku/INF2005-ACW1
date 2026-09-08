#!/usr/bin/env bash
# One-time setup for a fresh clone. Linux and macOS.
# Windows teammates: use setup.ps1 instead.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Python virtualenv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e "backend[dev]"

echo "==> Frontend"
if command -v pnpm >/dev/null 2>&1; then
  (cd frontend && pnpm install --frozen-lockfile && pnpm build)
else
  echo "pnpm not found — skipping the UI build. Install Node 25 + pnpm to rebuild it."
fi

echo
echo "Done. Next:"
echo "  source .venv/bin/activate"
echo "  stego serve            # http://127.0.0.1:8000"
