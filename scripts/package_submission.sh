#!/usr/bin/env bash
# Build the Week 5 Friday submission archive (spec Section 9): source code, README, samples,
# evidence, public keys and the BUILT UI, so the marker needs only Python — no Node.
#
# Usage: ./scripts/package_submission.sh [TEAM]   ->  dist/<TEAM>-ACW1-submission.zip
# The archive is built from committed files (git archive), plus a fresh frontend/dist that
# replaces any committed copy. Commit first.
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
# Replace, never merge: if frontend/dist was ever committed, git archive has already staged that
# (possibly stale) copy, and `cp -r frontend/dist <existing dir>` would nest the fresh build inside
# it as frontend/dist/dist while the server kept serving the old one.
rm -rf "$STAGE/$NAME/frontend/dist"
cp -R frontend/dist "$STAGE/$NAME/frontend/"
(cd "$STAGE" && rm -f "$OLDPWD/$OUT_DIR/$NAME.zip" && zip -qr "$OLDPWD/$OUT_DIR/$NAME.zip" "$NAME")

echo "==> $OUT_DIR/$NAME.zip"
unzip -l "$OUT_DIR/$NAME.zip" | tail -1
# The archive must serve exactly the build made above: one frontend/dist, byte-identical to it.
# (grep >/dev/null, not grep -q: with pipefail, -q's early exit can fail the pipe with SIGPIPE.)
if unzip -l "$OUT_DIR/$NAME.zip" | grep "$NAME/frontend/dist/dist/" >/dev/null \
  || ! unzip -p "$OUT_DIR/$NAME.zip" "$NAME/frontend/dist/index.html" | cmp -s - frontend/dist/index.html; then
  echo "The archive's frontend/dist is not the fresh build. Do not submit it." >&2
  exit 1
fi
echo "Contains frontend/dist: $(unzip -l "$OUT_DIR/$NAME.zip" | grep -c "$NAME/frontend/dist/.*[^/]$") file(s), the fresh build"
if [ -n "$(git ls-files frontend/dist)" ]; then
  echo "Note: frontend/dist is committed. The archive ships the fresh build instead of that copy." >&2
  if [ -n "$(git status --porcelain -- frontend/dist)" ]; then
    echo "      The committed copy is stale: the fresh build differs from it." >&2
  fi
  echo "      It is meant to stay uncommitted (see .gitignore): git rm -r --cached frontend/dist" >&2
fi
