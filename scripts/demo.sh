#!/usr/bin/env bash
# Demo mode: one process, one URL, no Vite dev server.
# Run this in the lab, never `pnpm dev`.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv/bin/activate

if [ ! -d frontend/dist ]; then
  echo "==> Building the UI (first run only)"
  (cd frontend && pnpm install --frozen-lockfile && pnpm build)
fi

PORT="${1:-8000}"
echo "==> http://127.0.0.1:$PORT"
PYTHONPATH="$PWD/backend" python -m uvicorn app.main:app --port "$PORT" --host 127.0.0.1
