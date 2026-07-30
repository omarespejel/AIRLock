#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/airlock-verify.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$ROOT"

TOOLCHAIN="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$TOOLCHAIN" ]] || [[ "$(printf '%s\n' "$TOOLCHAIN" | wc -l | tr -d ' ')" != "1" ]]; then
  printf 'FAIL: rust-toolchain.toml must contain exactly one channel\n' >&2
  exit 1
fi

CURRENT_COMMIT="$(git rev-parse HEAD)"
if [[ -n "${AIRLOCK_EXPECTED_COMMIT:-}" ]] && [[ "$CURRENT_COMMIT" != "$AIRLOCK_EXPECTED_COMMIT" ]]; then
  printf 'FAIL: expected commit %s, checked out %s\n' "$AIRLOCK_EXPECTED_COMMIT" "$CURRENT_COMMIT" >&2
  exit 1
fi

require_clean_tree() {
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    printf 'FAIL: canonical validation requires a clean working tree\n' >&2
    git status --short >&2
    return 1
  fi
}

require_clean_tree

if git rev-parse --verify --quiet 'origin/main^{commit}' >/dev/null; then
  MERGE_BASE="$(git merge-base HEAD origin/main)"
  git diff --check "$MERGE_BASE"...HEAD
else
  git diff-tree --check --no-commit-id -r HEAD
fi

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
printf '  commit: %s\n' "$CURRENT_COMMIT"
printf '  toolchain: %s\n' "$TOOLCHAIN"

scripts/verify-stwo-checkout.sh
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

DEMO_OUTPUT="$TMP_DIR/stwo-demo"
DEMO_LOG="$TMP_DIR/stwo-demo.log"
scripts/demo-airlock.sh "$DEMO_OUTPUT" >"$DEMO_LOG"
for stage in \
  preflight \
  source-pin \
  build \
  verifier-boundary \
  transition-witness \
  held-out-witness \
  generated-regression \
  campaign-seal \
  fresh-verification; do
  grep -Fq "AIRLOCK_DEMO_STAGE stage=$stage status=PASS" "$DEMO_LOG"
done
grep -Fq 'AIRLOCK_DEMO_COMPLETE' "$DEMO_LOG"
test -s "$DEMO_OUTPUT/corrupt-oods-sample-regression.rs"
printf 'PASS: Stwo honest, mutation, replay-bundle, and generated-regression demo\n'

if [[ "$(git rev-parse HEAD)" != "$CURRENT_COMMIT" ]]; then
  printf 'FAIL: HEAD changed while validation was running\n' >&2
  exit 1
fi
require_clean_tree

printf 'AIRLOCK LOCAL GATE PASSED\n'
