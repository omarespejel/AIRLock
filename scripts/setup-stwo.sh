#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STWO_DIR="$ROOT/../stwo"
PATCHES=(
  "$ROOT/patches/stwo-relation-entry-accessors.patch"
  "$ROOT/patches/stwo-consumption-sink.patch"
  "$ROOT/patches/stwo-transcript-sink.patch"
)
REQUIRED_COMMIT="f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a"
TMP_ROOT="$(mktemp -d "$ROOT/../.airlock-stwo-setup.XXXXXX")"
TMP_STWO="$TMP_ROOT/stwo"
trap 'rm -rf "$TMP_ROOT"' EXIT

if [[ -e "$STWO_DIR" ]]; then
  printf 'FAIL: refusing to replace existing path %s\n' "$STWO_DIR" >&2
  exit 1
fi

git clone --filter=blob:none https://github.com/starkware-libs/stwo.git "$TMP_STWO"
git -C "$TMP_STWO" checkout --detach "$REQUIRED_COMMIT"
for patch in "${PATCHES[@]}"; do
  git -C "$TMP_STWO" apply --check "$patch"
  git -C "$TMP_STWO" apply "$patch"
done
AIRLOCK_STWO_DIR="$TMP_STWO" "$ROOT/scripts/verify-stwo-checkout.sh"
mv "$TMP_STWO" "$STWO_DIR"

"$ROOT/scripts/verify-stwo-checkout.sh"
