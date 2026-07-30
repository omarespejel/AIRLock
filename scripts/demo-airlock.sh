#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$ROOT/rust-toolchain.toml")"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

stage() {
  printf 'AIRLOCK_DEMO_STAGE stage=%s status=%s\n' "$1" "$2"
}

require_clean_tree() {
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    git status --short >&2
    fail "demo requires a clean source checkout"
  fi
}

if [[ "$#" != "1" ]] || [[ -z "$1" ]]; then
  fail "usage: scripts/demo-airlock.sh OUTPUT_DIRECTORY"
fi
OUTPUT_ROOT="$1"

cd "$ROOT"
stage preflight BEGIN
if [[ -z "$TOOLCHAIN" ]] || [[ "$(printf '%s\n' "$TOOLCHAIN" | wc -l | tr -d ' ')" != "1" ]]; then
  fail "rust-toolchain.toml must contain exactly one channel"
fi
require_clean_tree
if [[ -e "$OUTPUT_ROOT" ]] || [[ -L "$OUTPUT_ROOT" ]]; then
  fail "demo output already exists: $OUTPUT_ROOT"
fi
stage preflight PASS

stage source-pin BEGIN
AIRLOCK_STWO_DIR="$ROOT/../stwo" scripts/verify-stwo-checkout.sh
stage source-pin PASS

stage build BEGIN
cargo +"$TOOLCHAIN" build --quiet --locked --offline -p airlock-stwo --bins
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
DEMO="$TARGET_DIR/debug/airlock-stwo-demo"
WORKER="$TARGET_DIR/debug/airlock-stwo-worker"
[[ -x "$DEMO" ]] || fail "demo executable was not built"
[[ -x "$WORKER" ]] || fail "replay worker was not built"
stage build PASS

mkdir -p "$(dirname "$OUTPUT_ROOT")"
mkdir "$OUTPUT_ROOT" || fail "could not create demo output: $OUTPUT_ROOT"
HONEST="$OUTPUT_ROOT/honest"
MUTATED="$OUTPUT_ROOT/corrupt-oods-sample"
REGRESSION="$OUTPUT_ROOT/corrupt-oods-sample-regression.rs"
WITNESS_HONEST="$OUTPUT_ROOT/witness-honest.json"
WITNESS_PRESERVING="$OUTPUT_ROOT/witness-preserving.json"
WITNESS_VIOLATING="$OUTPUT_ROOT/witness-violating.json"
HELD_OUT_HONEST="$OUTPUT_ROOT/heldout-honest.json"
HELD_OUT_PRESERVING="$OUTPUT_ROOT/heldout-preserving.json"
HELD_OUT_VIOLATING="$OUTPUT_ROOT/heldout-violating.json"

run_typed_replay_case() {
  local command="$1"
  local expected_verdict="$2"
  local evidence="$3"
  local expected_status="$4"
  local result

  result="$("$DEMO" "$command" --output "$evidence")"
  test -s "$evidence"
  grep -Fq "\"status\":\"$expected_status\"" <<<"$result"
  grep -Fq "\"verdict\":\"$expected_verdict\"" <<<"$result"
  grep -Fq '"artifact_sha256":"' <<<"$result"
  grep -Fq '"observation": {' "$evidence"
  grep -Fq "\"verdict\": \"$expected_verdict\"" "$evidence"
  grep -Fq '"audit_ir_sha256": "' "$evidence"
  grep -Fq '"report": {' "$evidence"
}

stage verifier-boundary BEGIN
"$DEMO" honest --worker "$WORKER" --output "$HONEST" >/dev/null
"$DEMO" corrupt-sample --worker "$WORKER" --output "$MUTATED" >/dev/null
"$DEMO" verify --bundle "$HONEST" --worker "$WORKER" >/dev/null
"$DEMO" verify --bundle "$MUTATED" --worker "$WORKER" >/dev/null
stage verifier-boundary PASS

stage transition-witness BEGIN
run_typed_replay_case \
  witness-honest \
  HONEST_ACCEPTED \
  "$WITNESS_HONEST" \
  AIRLOCK_WITNESS_REPLAY_EXPECTED
run_typed_replay_case \
  witness-preserving \
  CONSTRAINT_PRESERVING_ACCEPTED \
  "$WITNESS_PRESERVING" \
  AIRLOCK_WITNESS_REPLAY_EXPECTED
run_typed_replay_case \
  witness-violating \
  CONSTRAINT_VIOLATION_REJECTED \
  "$WITNESS_VIOLATING" \
  AIRLOCK_WITNESS_REPLAY_EXPECTED
stage transition-witness PASS

stage held-out-witness BEGIN
run_typed_replay_case \
  held-out-honest \
  HONEST_ACCEPTED \
  "$HELD_OUT_HONEST" \
  AIRLOCK_HELD_OUT_REPLAY_EXPECTED
run_typed_replay_case \
  held-out-preserving \
  CONSTRAINT_PRESERVING_ACCEPTED \
  "$HELD_OUT_PRESERVING" \
  AIRLOCK_HELD_OUT_REPLAY_EXPECTED
run_typed_replay_case \
  held-out-violating \
  CONSTRAINT_VIOLATION_REJECTED \
  "$HELD_OUT_VIOLATING" \
  AIRLOCK_HELD_OUT_REPLAY_EXPECTED
stage held-out-witness PASS

stage generated-regression BEGIN
"$DEMO" generate-regression --bundle "$MUTATED" --output "$REGRESSION" >/dev/null
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
  --target-dir "$TARGET_DIR"
stage generated-regression PASS

require_clean_tree
AIRLOCK_COMMIT="$(git rev-parse HEAD)"
stage campaign-seal BEGIN
SEAL_RESULT="$(
  "$DEMO" seal-campaign \
    --root "$OUTPUT_ROOT" \
    --airlock-commit "$AIRLOCK_COMMIT" \
    --coverage "$ROOT/docs/coverage.yaml"
)"
grep -Fq '"status":"AIRLOCK_CAMPAIGN_SEALED"' <<<"$SEAL_RESULT"
stage campaign-seal PASS

stage fresh-verification BEGIN
VERIFY_RESULT="$(
  "$DEMO" verify-campaign \
    --root "$OUTPUT_ROOT" \
    --expected-airlock-commit "$AIRLOCK_COMMIT" \
    --worker "$WORKER"
)"
grep -Fq '"status":"AIRLOCK_CAMPAIGN_REPLAY_MATCHED"' <<<"$VERIFY_RESULT"
stage fresh-verification PASS

printf 'AIRLOCK_DEMO_COMPLETE\n'
