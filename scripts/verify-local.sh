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

AIRLOCK_STWO_DIR="$ROOT/../stwo" scripts/verify-stwo-checkout.sh
cargo +"$TOOLCHAIN" fmt --all -- --check
cargo +"$TOOLCHAIN" clippy --workspace --all-targets --locked -- -D warnings
cargo +"$TOOLCHAIN" test --workspace --all-targets --locked
cargo +"$TOOLCHAIN" test --locked -p airlock-stwo \
  --features defective-verifier-mutant \
  defective_truncating_verifier_makes_cardinality_oracle_fire

FIXED_OUTPUT="$TMP_DIR/q8-fixed.log"
cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_fixed.json >"$FIXED_OUTPUT" 2>&1
grep -Fq 'verdict=StaticPass release=BLOCKED' "$FIXED_OUTPUT"
printf 'PASS: constrained Q8 fixture passes AIR lint while release remains blocked\n'

run_expected_failure \
  q8-vulnerable \
  'TableMultiplicityOutsideSemanticSupport' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_vulnerable.json

# Narrowing declared row support adds no constraint, so the same malicious
# witness remains available. The obligation must stay undischarged: an
# annotation may narrow a claim but can never establish one.
run_expected_failure \
  q8-annotation-only \
  'is a claim and cannot discharge it' \
  cargo +"$TOOLCHAIN" run --quiet --locked -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_annotation_only.json

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
EXPECTED_STAGE_SEQUENCE="preflight source-pin build verifier-boundary transition-witness held-out-witness generated-regression campaign-seal fresh-verification"
ACTUAL_STAGE_SEQUENCE="$(
  sed -n 's/^AIRLOCK_DEMO_STAGE stage=\([^ ]*\) status=PASS$/\1/p' "$DEMO_LOG" |
    paste -sd ' ' -
)"
if [[ "$ACTUAL_STAGE_SEQUENCE" != "$EXPECTED_STAGE_SEQUENCE" ]]; then
  printf 'FAIL: demo stage sequence mismatch\nexpected: %s\nactual:   %s\n' \
    "$EXPECTED_STAGE_SEQUENCE" "$ACTUAL_STAGE_SEQUENCE" >&2
  exit 1
fi
if [[ "$(grep -Fxc 'AIRLOCK_DEMO_COMPLETE' "$DEMO_LOG")" != "1" ]] ||
  [[ "$(tail -n 1 "$DEMO_LOG")" != "AIRLOCK_DEMO_COMPLETE" ]]; then
  printf 'FAIL: demo completion marker is missing, repeated, or not final\n' >&2
  exit 1
fi
test -s "$DEMO_OUTPUT/corrupt-oods-sample-regression.rs"
printf 'PASS: Stwo honest, mutation, replay-bundle, and generated-regression demo\n'

WITNESS_MATRIX="$TMP_DIR/witness-matrix.json"
WITNESS_MATRIX_GENERATE_LOG="$TMP_DIR/witness-matrix-generate.log"
WITNESS_MATRIX_VERIFY_LOG="$TMP_DIR/witness-matrix-verify.log"
WITNESS_MATRIX_SECOND="$TMP_DIR/witness-matrix-second.json"
WITNESS_MATRIX_SECOND_LOG="$TMP_DIR/witness-matrix-second.log"
cargo +"$TOOLCHAIN" run --quiet --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  witness-matrix --output "$WITNESS_MATRIX" >"$WITNESS_MATRIX_GENERATE_LOG"
grep -Fq '"status":"AIRLOCK_WITNESS_MATRIX_COMPLETE"' "$WITNESS_MATRIX_GENERATE_LOG"
grep -Fq '"total":128' "$WITNESS_MATRIX_GENERATE_LOG"
cargo +"$TOOLCHAIN" run --quiet --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  verify-witness-matrix --artifact "$WITNESS_MATRIX" >"$WITNESS_MATRIX_VERIFY_LOG"
grep -Fq '"status":"AIRLOCK_WITNESS_MATRIX_REPLAY_MATCHED"' "$WITNESS_MATRIX_VERIFY_LOG"
grep -Fq '"total":128' "$WITNESS_MATRIX_VERIFY_LOG"
cargo +"$TOOLCHAIN" run --quiet --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  witness-matrix --output "$WITNESS_MATRIX_SECOND" >"$WITNESS_MATRIX_SECOND_LOG"
cmp "$WITNESS_MATRIX" "$WITNESS_MATRIX_SECOND"
printf 'PASS: deterministic 128-case cross-target witness matrix and fresh replay\n'

if [[ "$(git rev-parse HEAD)" != "$CURRENT_COMMIT" ]]; then
  printf 'FAIL: HEAD changed while validation was running\n' >&2
  exit 1
fi
require_clean_tree

scripts/test-export-review-bundle.sh

printf 'AIRLOCK LOCAL GATE PASSED\n'
