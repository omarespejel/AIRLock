#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STWO_DIR="${AIRLOCK_STWO_DIR:-$ROOT/../stwo}"
PATCH="$ROOT/patches/stwo-relation-entry-accessors.patch"
REQUIRED_COMMIT="f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a"
TARGET="crates/constraint-framework/src/lib.rs"
REQUIRED_PATHS=(
  Cargo.toml
  Cargo.lock
  crates/stwo
  crates/constraint-framework
  crates/examples/Cargo.toml
  crates/examples/src/lib.rs
  crates/examples/src/wide_fibonacci
)
TMP_PATCH="$(mktemp "${TMPDIR:-/tmp}/airlock-stwo-patch.XXXXXX")"
trap 'rm -f "$TMP_PATCH"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# Git exports repository-local variables to hooks. Clear them before querying
# the sibling checkout so `git -C` cannot accidentally read AIRLock's objects.
while IFS= read -r variable; do
  unset "$variable"
done < <(git rev-parse --local-env-vars)

[[ -d "$STWO_DIR/.git" ]] || fail "missing sibling Stwo checkout at $STWO_DIR; run scripts/setup-stwo.sh"
[[ -f "$PATCH" ]] || fail "missing checked accessor patch at $PATCH"

actual_commit="$(git -C "$STWO_DIR" rev-parse HEAD)"
git -C "$STWO_DIR" cat-file -e "$REQUIRED_COMMIT^{commit}" 2>/dev/null || fail \
  "Stwo checkout does not contain required upstream baseline $REQUIRED_COMMIT"

for path in "${REQUIRED_PATHS[@]}"; do
  expected_object="$(git -C "$STWO_DIR" rev-parse "$REQUIRED_COMMIT:$path")"
  actual_object="$(git -C "$STWO_DIR" rev-parse "HEAD:$path")"
  [[ "$actual_object" == "$expected_object" ]] || fail \
    "Stwo HEAD $actual_commit changes required dependency source $path relative to $REQUIRED_COMMIT"
done

if ! git -C "$STWO_DIR" diff --cached --quiet; then
  fail "Stwo has staged changes; the exporter checkout must match the checked patch exactly"
fi

status="$(git -C "$STWO_DIR" status --porcelain --untracked-files=all)"
expected_status=" M $TARGET"
[[ "$status" == "$expected_status" ]] || fail \
  "unexpected Stwo working tree state; expected only '$expected_status', got '${status:-clean}'"

git -C "$STWO_DIR" diff --no-ext-diff --binary --unified=1 -- "$TARGET" >"$TMP_PATCH"
if ! cmp -s "$PATCH" "$TMP_PATCH"; then
  fail "Stwo accessor diff does not match $PATCH"
fi

printf 'PASS: Stwo dependency and held-out target sources at %s match upstream baseline %s plus the checked accessor patch\n' \
  "$actual_commit" "$REQUIRED_COMMIT"
