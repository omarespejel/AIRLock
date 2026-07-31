#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STWO_DIR="${AIRLOCK_STWO_DIR:-$ROOT/../stwo}"
ACCESSOR_PATCH="$ROOT/patches/stwo-relation-entry-accessors.patch"
CONSUMPTION_PATCH="$ROOT/patches/stwo-consumption-sink.patch"
REQUIRED_COMMIT="f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a"
REQUIRED_ACCESSOR_PATCH_SHA256="7782a94a63a40e86b760d76dc37d2a6833921c5dfad5073b62972d640b90742a"
REQUIRED_CONSUMPTION_PATCH_SHA256="cdef8d226336b766ceeeddcac410c535c1d669fce88081c58ddc8221371d9a23"
REQUIRED_SOURCE_ID="stwo@$REQUIRED_COMMIT+patches:accessor=$REQUIRED_ACCESSOR_PATCH_SHA256;consumption=$REQUIRED_CONSUMPTION_PATCH_SHA256"
SOURCE_ID_FILE="$ROOT/crates/airlock-stwo/src/lib.rs"
ACCESSOR_TARGET="crates/constraint-framework/src/lib.rs"
CONSUMPTION_TARGETS=(
  crates/stwo/Cargo.toml
  crates/stwo/src/core/pcs/mod.rs
  crates/stwo/src/core/pcs/verifier.rs
)
REQUIRED_PATHS=(
  Cargo.toml
  Cargo.lock
  crates/stwo
  crates/constraint-framework
  crates/examples/Cargo.toml
  crates/examples/src/lib.rs
  crates/examples/src/wide_fibonacci
)
TMP_ACCESSOR_PATCH="$(mktemp "${TMPDIR:-/tmp}/airlock-stwo-accessor-patch.XXXXXX")"
TMP_CONSUMPTION_INDEX="$(mktemp "${TMPDIR:-/tmp}/airlock-stwo-consumption-index.XXXXXX")"
trap 'rm -f "$TMP_ACCESSOR_PATCH" "$TMP_CONSUMPTION_INDEX"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

# Git exports repository-local variables to hooks. Clear them before querying
# the sibling checkout so `git -C` cannot accidentally read AIRLock's objects.
if ! GIT_LOCAL_ENV="$(git rev-parse --local-env-vars)"; then
  fail "could not discover repository-local Git environment variables"
fi
while IFS= read -r variable; do
  [[ -n "$variable" ]] && unset "$variable"
done <<<"$GIT_LOCAL_ENV"
unset GIT_LOCAL_ENV

if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA256=(shasum -a 256)
else
  fail "need sha256sum or shasum for SHA-256 verification"
fi

[[ -d "$STWO_DIR/.git" ]] || fail "missing sibling Stwo checkout at $STWO_DIR; run scripts/setup-stwo.sh"
[[ -f "$ACCESSOR_PATCH" ]] || fail "missing checked accessor patch at $ACCESSOR_PATCH"
[[ -f "$CONSUMPTION_PATCH" ]] || fail "missing checked consumption patch at $CONSUMPTION_PATCH"
[[ "$("${SHA256[@]}" "$ACCESSOR_PATCH" | awk '{print $1}')" == "$REQUIRED_ACCESSOR_PATCH_SHA256" ]] ||
  fail "accessor patch SHA-256 does not match the bound source identity"
[[ "$("${SHA256[@]}" "$CONSUMPTION_PATCH" | awk '{print $1}')" == "$REQUIRED_CONSUMPTION_PATCH_SHA256" ]] ||
  fail "consumption patch SHA-256 does not match the bound source identity"
grep -Fqx "pub const STWO_SOURCE_ID: &str = \"$REQUIRED_SOURCE_ID\";" "$SOURCE_ID_FILE" ||
  fail "STWO_SOURCE_ID does not bind the required baseline and patch digests"

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
expected_status="$(printf ' M %s\n' \
  "$ACCESSOR_TARGET" \
  "${CONSUMPTION_TARGETS[@]}")"
expected_status="${expected_status%$'\n'}"
[[ "$status" == "$expected_status" ]] || fail \
  "unexpected Stwo working tree state; expected only '$expected_status', got '${status:-clean}'"

git -C "$STWO_DIR" diff --no-ext-diff --binary --unified=1 --abbrev=8 -- \
  "$ACCESSOR_TARGET" >"$TMP_ACCESSOR_PATCH"
if ! cmp -s "$ACCESSOR_PATCH" "$TMP_ACCESSOR_PATCH"; then
  fail "Stwo accessor diff does not match $ACCESSOR_PATCH"
fi

GIT_INDEX_FILE="$TMP_CONSUMPTION_INDEX" git -C "$STWO_DIR" read-tree "$REQUIRED_COMMIT"
GIT_INDEX_FILE="$TMP_CONSUMPTION_INDEX" git -C "$STWO_DIR" apply --cached --check \
  "$CONSUMPTION_PATCH"
GIT_INDEX_FILE="$TMP_CONSUMPTION_INDEX" git -C "$STWO_DIR" apply --cached \
  "$CONSUMPTION_PATCH"
for path in "${CONSUMPTION_TARGETS[@]}"; do
  expected_object="$(
    GIT_INDEX_FILE="$TMP_CONSUMPTION_INDEX" git -C "$STWO_DIR" rev-parse ":$path"
  )"
  actual_object="$(git -C "$STWO_DIR" hash-object "$STWO_DIR/$path")"
  [[ "$actual_object" == "$expected_object" ]] || fail \
    "Stwo consumption target $path does not equal the checked patch result"
done

printf 'PASS: Stwo dependency and held-out target sources at %s match upstream baseline %s plus the checked accessor and consumption patches\n' \
  "$actual_commit" "$REQUIRED_COMMIT"
