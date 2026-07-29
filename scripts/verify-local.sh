#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="${AIRLOCK_RUST_TOOLCHAIN:-nightly-2026-01-15}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/airlock-verify.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$ROOT"

run_expected_failure() {
  local name="$1"
  local expected="$2"
  shift 2

  local output="$TMP_DIR/${name}.log"
  if "$@" >"$output" 2>&1; then
    printf 'FAIL: %s unexpectedly succeeded\n' "$name" >&2
    cat "$output" >&2
    return 1
  fi
  if ! grep -Fq "$expected" "$output"; then
    printf 'FAIL: %s failed without expected marker: %s\n' "$name" "$expected" >&2
    cat "$output" >&2
    return 1
  fi
  printf 'PASS: %s failed closed (%s)\n' "$name" "$expected"
}

printf 'AIRLock local gate\n'
printf '  commit: %s\n' "$(git rev-parse HEAD)"
printf '  toolchain: %s\n' "$TOOLCHAIN"

cargo +"$TOOLCHAIN" fmt --all -- --check
cargo +"$TOOLCHAIN" clippy --workspace --all-targets --locked -- -D warnings
cargo +"$TOOLCHAIN" test --workspace --all-targets --locked

FIXED_OUTPUT="$TMP_DIR/q8-fixed.log"
cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_fixed.json >"$FIXED_OUTPUT" 2>&1
grep -Fq 'verdict=StaticPass release=BLOCKED' "$FIXED_OUTPUT"
printf 'PASS: fixed Q8 fixture passes AIR lint while release remains blocked\n'

run_expected_failure \
  q8-vulnerable \
  'TableMultiplicityOutsideSemanticSupport' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_vulnerable.json

run_expected_failure \
  encoder-mismatch \
  'AdmittedBoundExceedsEncoder' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/encoder_admissibility_mismatch.json

run_expected_failure \
  uncovered-surface \
  'required surfaces are not all COVERED' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- coverage \
  --manifest docs/coverage.yaml

run_expected_failure \
  protocol-out-of-model \
  'protocol lane is OUT_OF_MODEL' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- protocol

printf 'AIRLOCK LOCAL GATE PASSED\n'
