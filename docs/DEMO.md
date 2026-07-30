# AIRLock live demo

This demo shows AIRLock executing adversarial checks at two Stwo boundaries:
proof-sample handling and pre-commitment witness consistency. It produces a
portable evidence directory and freshly replays every recorded case before
reporting success.

The demo reports observed behavior for exact covered targets. It is not a proof
that Stwo, Circle FRI, or an application is sound.

## Prepare once

Requirements:

- a Unix shell, Git, and Rustup;
- the repository's pinned `nightly-2026-01-15` toolchain;
- the checked sibling Stwo source at `../stwo`;
- Cargo dependencies already present in the local cache.

The following setup may use the network:

```bash
scripts/setup-stwo.sh
cargo +nightly-2026-01-15 fetch --locked
```

After that setup, the demo passes `--offline` to every Cargo command.

## Run

Start from a clean AIRLock commit and choose an output path that does not exist:

```bash
git status --short
scripts/demo-airlock.sh /tmp/airlock-demo
```

The script rejects a dirty source checkout, an existing output path, a changed
Stwo source pin, a missing dependency cache, any unexpected verdict, or any
failed fresh replay.

## Terminal markers

A complete run prints these pass markers in order:

```text
AIRLOCK_DEMO_STAGE stage=preflight status=PASS
AIRLOCK_DEMO_STAGE stage=source-pin status=PASS
AIRLOCK_DEMO_STAGE stage=build status=PASS
AIRLOCK_DEMO_STAGE stage=verifier-boundary status=PASS
AIRLOCK_DEMO_STAGE stage=transition-witness status=PASS
AIRLOCK_DEMO_STAGE stage=held-out-witness status=PASS
AIRLOCK_DEMO_STAGE stage=generated-regression status=PASS
AIRLOCK_DEMO_STAGE stage=campaign-seal status=PASS
AIRLOCK_DEMO_STAGE stage=fresh-verification status=PASS
AIRLOCK_DEMO_COMPLETE
```

Every stage also prints a `BEGIN` marker. Only a fully sealed and freshly
verified campaign prints `AIRLOCK_DEMO_COMPLETE`.

## What executes

The fixed campaign contains eight cases:

1. One honest real proof through raw PCS and framework verification.
2. One verifier-derived OODS scalar corruption rejected at both layers.
3. Honest, relation-preserving, and relation-violating witness cases over the
   transition target.
4. The same three witness classes over Stwo's real
   `WideFibonacciEval<3>` target.

AIRLock also generates a path-independent Rust regression from the corrupted
sample case, compiles and runs it offline, seals every payload digest and size,
copies the complete coverage inventory, and freshly re-executes all eight
cases.

## Evidence

The output directory contains:

```text
airlock-demo/
|-- campaign.json
|-- SHA256SUMS
|-- SUMMARY.md
|-- coverage.yaml
|-- honest/
|-- corrupt-oods-sample/
|-- corrupt-oods-sample-regression.rs
|-- witness-honest.json
|-- witness-preserving.json
|-- witness-violating.json
|-- heldout-honest.json
|-- heldout-preserving.json
`-- heldout-violating.json
```

`campaign.json` binds the exact AIRLock commit, pinned Stwo source, replay
worker digest, case inventory, expected verdicts, non-claims, and payload
digests. `coverage.yaml` keeps unsupported and quarantined lanes visible beside
covered lanes.

Fresh verification requires every checked payload to be bounded UTF-8 text and
rejects the listed host-path, credential, AI-attribution, planning, and
development-history markers. Error messages name only the artifact and content
class, never the matched text.

## Verify again

```bash
target/debug/airlock-stwo-demo verify-campaign \
  --root /tmp/airlock-demo \
  --expected-airlock-commit "$(git rev-parse HEAD)" \
  --worker target/debug/airlock-stwo-worker
```

Expected status:

```text
AIRLOCK_CAMPAIGN_REPLAY_MATCHED
```

To demonstrate fail-closed evidence handling, copy the directory, change one
checked file, and rerun verification:

```bash
cp -R /tmp/airlock-demo /tmp/airlock-demo-tampered
printf '\nchanged\n' >> /tmp/airlock-demo-tampered/SUMMARY.md
target/debug/airlock-stwo-demo verify-campaign \
  --root /tmp/airlock-demo-tampered \
  --expected-airlock-commit "$(git rev-parse HEAD)" \
  --worker target/debug/airlock-stwo-worker
```

The command must fail with a checksum mismatch before fresh execution.

## Thirty-minute flow

1. Minutes 0-5: state the assurance lanes and non-claims.
2. Minutes 5-15: run the one-command demo and read the stage markers.
3. Minutes 15-20: inspect `SUMMARY.md`, `campaign.json`, and `coverage.yaml`.
4. Minutes 20-25: rerun verification, then show checksum tamper rejection.
5. Minutes 25-30: discuss how another component can enter the exporter and
   witness-adapter contracts, with unsupported shapes failing closed.

## Not established

- statement binding;
- executable transcript, Fiat-Shamir, or FRI assurance;
- broad Stwo or production-integration coverage;
- producer identity, machine attestation, or trusted time;
- a cryptographic soundness theorem or absence of other defects.
