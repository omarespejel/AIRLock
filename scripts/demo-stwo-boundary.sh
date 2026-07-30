#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$ROOT/rust-toolchain.toml")"

if [[ -n "${1:-}" ]]; then
  OUTPUT_ROOT="$1"
  if [[ -e "$OUTPUT_ROOT" ]]; then
    printf 'FAIL: demo output already exists: %s\n' "$OUTPUT_ROOT" >&2
    exit 1
  fi
  mkdir -p "$OUTPUT_ROOT"
else
  OUTPUT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/airlock-stwo-demo.XXXXXX")"
fi

cd "$ROOT"
scripts/verify-stwo-checkout.sh
cargo +"$TOOLCHAIN" build --quiet --locked -p airlock-stwo --bins

DEMO="$ROOT/target/debug/airlock-stwo-demo"
WORKER="$ROOT/target/debug/airlock-stwo-worker"
HONEST="$OUTPUT_ROOT/honest"
MUTATED="$OUTPUT_ROOT/corrupt-oods-sample"
REGRESSION="$OUTPUT_ROOT/corrupt-oods-sample-regression.rs"
WITNESS_HONEST="$OUTPUT_ROOT/witness-honest.json"
WITNESS_PRESERVING="$OUTPUT_ROOT/witness-preserving.json"
WITNESS_VIOLATING="$OUTPUT_ROOT/witness-violating.json"

run_witness_case() {
  local command="$1"
  local expected_verdict="$2"
  local evidence="$3"
  local result

  result="$("$DEMO" "$command" --output "$evidence")"
  test -s "$evidence"
  grep -Fq '"status":"AIRLOCK_WITNESS_REPLAY_EXPECTED"' <<<"$result"
  grep -Fq "\"verdict\":\"$expected_verdict\"" <<<"$result"
  grep -Fq '"artifact_sha256":"' <<<"$result"
  grep -Fq '"observation": {' "$evidence"
  grep -Fq "\"verdict\": \"$expected_verdict\"" "$evidence"
  grep -Fq '"audit_ir_sha256":"' "$evidence"
  grep -Fq '"report": {' "$evidence"
}

"$DEMO" honest --worker "$WORKER" --output "$HONEST"
"$DEMO" corrupt-sample --worker "$WORKER" --output "$MUTATED"
"$DEMO" verify --bundle "$HONEST" --worker "$WORKER"
"$DEMO" verify --bundle "$MUTATED" --worker "$WORKER"
"$DEMO" generate-regression --bundle "$MUTATED" --output "$REGRESSION"
run_witness_case witness-honest HONEST_ACCEPTED "$WITNESS_HONEST"
run_witness_case \
  witness-preserving \
  CONSTRAINT_PRESERVING_ACCEPTED \
  "$WITNESS_PRESERVING"
run_witness_case \
  witness-violating \
  CONSTRAINT_VIOLATION_REJECTED \
  "$WITNESS_VIOLATING"

test -s "$REGRESSION"
if grep -Fq "$ROOT" "$REGRESSION"; then
  printf 'FAIL: generated regression contains the local repository path\n' >&2
  exit 1
fi
rustfmt +"$TOOLCHAIN" --check "$REGRESSION"

CHECK_CRATE="$(mktemp -d "${TMPDIR:-/tmp}/airlock-regression-check.XXXXXX")"
trap 'rm -rf "$CHECK_CRATE"' EXIT
mkdir -p "$CHECK_CRATE/tests"
cp "$REGRESSION" "$CHECK_CRATE/tests/replay.rs"
ROOT_TOML="${ROOT//\\/\\\\}"
ROOT_TOML="${ROOT_TOML//\"/\\\"}"
printf '%s\n' \
  '[workspace]' \
  '[package]' \
  'name = "airlock-generated-regression"' \
  'version = "0.0.0"' \
  'edition = "2024"' \
  '' \
  '[dependencies]' \
  "airlock-stwo = { path = \"$ROOT_TOML/crates/airlock-stwo\" }" \
  'serde_json = "1.0"' \
  >"$CHECK_CRATE/Cargo.toml"
cargo +"$TOOLCHAIN" generate-lockfile --quiet --offline --manifest-path "$CHECK_CRATE/Cargo.toml"
cargo +"$TOOLCHAIN" test --quiet --locked --offline \
  --manifest-path "$CHECK_CRATE/Cargo.toml" \
  --target-dir "$ROOT/target"

if ! git diff --quiet || ! git diff --cached --quiet \
  || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  printf 'FAIL: campaign source checkout is not clean\n' >&2
  exit 1
fi
AIRLOCK_COMMIT="$(git rev-parse HEAD)"
SEAL_RESULT="$(
  "$DEMO" seal-campaign \
    --root "$OUTPUT_ROOT" \
    --airlock-commit "$AIRLOCK_COMMIT" \
    --coverage "$ROOT/docs/coverage.yaml"
)"
grep -Fq '"status":"AIRLOCK_CAMPAIGN_SEALED"' <<<"$SEAL_RESULT"
VERIFY_RESULT="$(
  "$DEMO" verify-campaign \
    --root "$OUTPUT_ROOT" \
    --expected-airlock-commit "$AIRLOCK_COMMIT" \
    --worker "$WORKER"
)"
grep -Fq '"status":"AIRLOCK_CAMPAIGN_REPLAY_MATCHED"' <<<"$VERIFY_RESULT"

printf 'AIRLOCK STWO DEMO PASSED output=%s\n' "$OUTPUT_ROOT"
