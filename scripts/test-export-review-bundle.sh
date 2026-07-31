#!/usr/bin/env bash
# Round-trip, determinism, and tamper checks for reviewer-bundle export.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/airlock-review-test.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
BASH_BIN="$(command -v bash)"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
else
  SHA256=(shasum -a 256)
fi

expect_failure() {
  local marker="$1"
  shift
  local output
  if output="$("$@" 2>&1 >/dev/null)"; then
    printf 'FAIL: expected command to fail: %s\n' "$*" >&2
    exit 1
  fi
  if ! printf '%s\n' "$output" | grep -Fq "$marker"; then
    printf 'FAIL: command rejected for the wrong reason: %s\n%s\n' "$*" "$output" >&2
    exit 1
  fi
}

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then
  printf 'FAIL: reviewer-bundle test requires a clean working tree\n' >&2
  exit 1
fi

mkdir -p "$STAGE/caller" "$STAGE/extracted"
(
  cd "$STAGE/caller"
  umask 022
  TZ=UTC "$ROOT/scripts/export-review-bundle.sh" first.tar.gz >/dev/null
)
(
  cd "$STAGE/caller"
  umask 077
  TZ=Pacific/Honolulu "$ROOT/scripts/export-review-bundle.sh" second.tar.gz >/dev/null
)
cmp "$STAGE/caller/first.tar.gz" "$STAGE/caller/second.tar.gz"

tar -xzf "$STAGE/caller/first.tar.gz" -C "$STAGE/extracted"
mkdir "$STAGE/reviewer-caller"
(
  cd "$STAGE/reviewer-caller"
  "$STAGE/extracted/airlock-review/VERIFY.sh" reconstructed >/dev/null
)
test "$(git -C "$STAGE/reviewer-caller/reconstructed" rev-parse HEAD)" = \
  "$(git -C "$ROOT" rev-parse HEAD)"

mkdir "$STAGE/no-sha-path"
ln -s "$(command -v dirname)" "$STAGE/no-sha-path/dirname"
ln -s "$(command -v basename)" "$STAGE/no-sha-path/basename"
if PATH="$STAGE/no-sha-path" "$BASH_BIN" \
  "$STAGE/extracted/airlock-review/VERIFY.sh" \
  "$STAGE/no-sha-worktree" >"$STAGE/no-sha.out" 2>&1; then
  printf 'FAIL: bundle verifier ran without a SHA-256 tool\n' >&2
  exit 1
fi
grep -q 'FAIL: need sha256sum or shasum' "$STAGE/no-sha.out"

expect_failure 'FAIL: refusing to overwrite existing path' \
  "$ROOT/scripts/export-review-bundle.sh" "$STAGE/caller/first.tar.gz"

ln -s "$STAGE/dangling-target.tar.gz" "$STAGE/caller/dangling-output.tar.gz"
expect_failure 'FAIL: refusing to overwrite existing path' \
  "$ROOT/scripts/export-review-bundle.sh" "$STAGE/caller/dangling-output.tar.gz"
if [[ -e "$STAGE/dangling-target.tar.gz" ]]; then
  printf 'FAIL: exporter created a dangling symlink target\n' >&2
  exit 1
fi

ln -s "$STAGE/dangling-worktree-target" "$STAGE/dangling-worktree"
expect_failure 'FAIL: refusing to replace existing path' \
  "$STAGE/extracted/airlock-review/VERIFY.sh" "$STAGE/dangling-worktree"
if [[ -e "$STAGE/dangling-worktree-target" ]]; then
  printf 'FAIL: bundle verifier created a dangling worktree target\n' >&2
  exit 1
fi

mkdir "$STAGE/existing-worktree"
expect_failure 'FAIL: refusing to replace existing path' \
  "$STAGE/extracted/airlock-review/VERIFY.sh" "$STAGE/existing-worktree"

cp -R "$STAGE/extracted/airlock-review" "$STAGE/broken-review"
printf 'not a git bundle\n' >"$STAGE/broken-review/airlock.bundle"
(
  cd "$STAGE/broken-review"
  "${SHA256[@]}" airlock.bundle SOURCE_COMMIT.txt VERIFY.sh >MANIFEST.sha256
)
expect_failure 'FAIL: could not reconstruct the reviewer worktree' \
  "$STAGE/broken-review/VERIFY.sh" "$STAGE/broken-worktree"
if [[ -e "$STAGE/broken-worktree" || -L "$STAGE/broken-worktree" ]]; then
  printf 'FAIL: verifier left its failed reconstruction behind\n' >&2
  exit 1
fi

printf 'tampered\n' >>"$STAGE/extracted/airlock-review/SOURCE_COMMIT.txt"
expect_failure 'FAIL: payload manifest verification failed' \
  "$STAGE/extracted/airlock-review/VERIFY.sh" "$STAGE/tampered-worktree"

git clone --quiet --shared "$ROOT" "$STAGE/dirty-repository"
touch "$STAGE/dirty-repository/untracked-review-input"
expect_failure 'FAIL: refusing to export a dirty working tree' \
  "$STAGE/dirty-repository/scripts/export-review-bundle.sh" "$STAGE/dirty.tar.gz"

git clone --quiet --depth 1 "file://$ROOT" "$STAGE/shallow-repository"
expect_failure 'FAIL: refusing to export an incomplete shallow repository' \
  "$STAGE/shallow-repository/scripts/export-review-bundle.sh" "$STAGE/shallow.tar.gz"

printf 'PASS: reviewer bundle round-trip, determinism, and tamper checks\n'
