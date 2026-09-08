#!/usr/bin/env bash
# Everything CI would run. Run before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> pytest"
(cd backend && python -m pytest -q)

echo "==> ruff"
(cd backend && python -m ruff check . && python -m ruff format --check .)

echo "==> frontend typecheck + lint"
(cd frontend && pnpm tsc -b --noEmit 2>/dev/null || pnpm tsc -b; pnpm lint)

echo
echo "All checks passed."
