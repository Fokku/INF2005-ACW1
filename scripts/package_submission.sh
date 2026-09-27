#!/usr/bin/env bash
# Build the Week 5 Friday submission archive (spec Section 9): source code, README, samples,
# evidence, public keys and the BUILT UI, so the marker needs only Python — no Node.
#
# Usage: ./scripts/package_submission.sh [TEAM]   ->  dist/<TEAM>-ACW1-submission.zip
# The archive is built from committed files (git archive), plus frontend/dist. Commit first.
set -euo pipefail
cd "$(dirname "$0")/.."
TEAM="${1:-P6-8}"
OUT_DIR="dist"
NAME="${TEAM}-ACW1-submission"

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree has uncommitted changes; commit them first so the archive matches git." >&2
  exit 1
fi

echo "==> Checking no private key is tracked or in history"
# Every PKCS#8 Ed25519 private key's base64 starts with this fixed DER prefix; tests that merely
# mention the "BEGIN PRIVATE KEY" marker do not contain it.
ED25519_PKCS8_PREFIX="MC4CAQAw""BQYDK2VwBCIEI"  # split so this script never matches itself
if git ls-files | grep -E '(^|/)keys/private/' >/dev/null \
  || git grep -l "$ED25519_PKCS8_PREFIX" $(git rev-list --all) -- . >/dev/null 2>&1; then
  echo "A private key is tracked or in git history. Stop and remove it before submitting." >&2
  exit 1
fi

echo "==> Building the UI"
(cd frontend && pnpm install --frozen-lockfile && pnpm build)

echo "==> Archiving"
mkdir -p "$OUT_DIR"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
git archive --format=tar --prefix="$NAME/" HEAD | tar -x -C "$STAGE"
cp -r frontend/dist "$STAGE/$NAME/frontend/dist"
(cd "$STAGE" && rm -f "$OLDPWD/$OUT_DIR/$NAME.zip" && zip -qr "$OLDPWD/$OUT_DIR/$NAME.zip" "$NAME")

echo "==> $OUT_DIR/$NAME.zip"
unzip -l "$OUT_DIR/$NAME.zip" | tail -1
echo "Contains frontend/dist: $(unzip -l "$OUT_DIR/$NAME.zip" | grep -c "frontend/dist/index.html") file(s) named index.html"
