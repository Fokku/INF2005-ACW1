#!/usr/bin/env bash
# Development: API on :8000 with reload, Vite on :5173 proxying /api to it.
# Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv/bin/activate

PYTHONPATH="$PWD/backend" python -m uvicorn app.main:app --reload --port 8000 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT

(cd frontend && pnpm dev)
