# AIRLock

Adversarial soundness testing for Stwo / Circle-STARK AIRs.

AIRLock analyzes the constraints a verifier actually checks, searches for
malicious witnesses an honest prover would never construct, and refuses to
treat an AIR surface as reviewed when it is unmodeled, unsupported, or
inconclusive.

This repository does **not** claim that an integrated AIR is sound or that a
green AIRLock report establishes whole-system STARK security.

## Status (v0)

| Piece | State |
| --- | --- |
| AuditIR schema (`airlock-ir`) | landed |
| Static gate (`airlock-lint`) | schema/shape + parameter/phase closure + preprocessed integrity + Q8 support/functionality (confinement requires a constraint-derived certificate, never an annotation) + encoder bound + LogUp finalize |
| Verifier boundary contracts (`airlock-boundary`) | proof-neutral request/supply/consumption, typed transcript oracles, and exact witness-matrix contracts |
| Pinned Stwo adapter (`airlock-stwo`) | real demo proof, verifier-derived OODS requests, typed mutations of sampled values, commitments, decommitment hash witnesses, queried values, and PoW, raw-PCS/framework replay, phase-bound pre-commitment witness injection, one independently selected upstream Wide Fibonacci target, deterministic cross-target cell matrix, subprocess containment, verified replay bundles, generated Rust regression, sealed portable campaign |
| CLI (`airlock`) | `air`, `coverage`, `schema` |
| Stwo `AuditEvaluator` exporter | landed (`airlock-export`); concrete differential checks cover one synthetic cross-interaction AIR |
| cvc5 / Lean | later PRs |

Share a reviewable snapshot with `scripts/export-review-bundle.sh out.tar.gz`.
Send its SHA-256 through a trusted channel. A reviewer can then extract the
archive and run `VERIFY.sh` to check payload integrity, commit identity, and
reconstruction.

```bash
# First compare this digest exactly with the value received through the trusted
# channel. Use sha256sum on Linux or shasum on macOS.
sha256sum out.tar.gz
shasum -a 256 out.tar.gz

# Continue only after the outer digest matches.
mkdir airlock-review-input
tar -xzf out.tar.gz -C airlock-review-input
./airlock-review-input/airlock-review/VERIFY.sh
```

See [docs/SPEC.md](docs/SPEC.md) and [docs/coverage.yaml](docs/coverage.yaml).
The fail-closed boundary profiles are specified in
[docs/PARAMETER_BOUNDARIES.md](docs/PARAMETER_BOUNDARIES.md).

## Quick start

```bash
# One-time exporter dependency setup. Refuses to replace an existing ../stwo.
scripts/setup-stwo.sh

scripts/verify-local.sh

cargo +nightly-2026-01-15 test -p airlock-stwo --locked --offline

# Prove that the generic cardinality oracle fires against the local known-bad mutant.
cargo +nightly-2026-01-15 test -p airlock-stwo --locked --offline \
  --features defective-verifier-mutant \
  defective_truncating_verifier_makes_cardinality_oracle_fire

# Exporter-faithfulness differential against Stwo's concrete evaluators.
cargo +nightly-2026-01-15 test -p airlock-export \
  --test assert_evaluator_faithfulness --locked --offline

# Build, run, package, and freshly verify the complete offline demo.
scripts/demo-airlock.sh /tmp/airlock-demo

# Recheck a campaign against its source commit and the pinned worker.
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  verify-campaign \
  --root /tmp/airlock-demo \
  --expected-airlock-commit "$(git rev-parse HEAD)" \
  --worker "$TARGET_DIR/debug/airlock-stwo-worker"

# Direct phase-bound witness campaigns are also exposed by the demo binary.
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  witness-preserving

# The held-out target uses Stwo's real WideFibonacciEval<3>.
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  held-out-preserving

# Derive all 128 original-cell Increment/Decrement cases for both targets.
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  witness-matrix --output /tmp/airlock-witness-matrix.json

# Validate the artifact and freshly replay all 128 cases.
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  verify-witness-matrix --artifact /tmp/airlock-witness-matrix.json

# Execute a validated, source-pinned ReplayRequest JSON under the same bounded
# worker policy. A non-green result still writes its evidence bundle but exits
# unsuccessfully.
cargo +nightly-2026-01-15 run --locked --offline \
  -p airlock-stwo --bin airlock-stwo-demo -- \
  replay --request /tmp/replay-request.json \
  --output /tmp/replay-result

cargo +nightly-2026-01-15 run --locked --offline -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_vulnerable.json
# expects StaticFail (exit 1)

cargo +nightly-2026-01-15 run --locked --offline -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_fixed.json
# expects StaticPass (exit 0); overall release stays BLOCKED
```

See [docs/DEMO.md](docs/DEMO.md) for the 30-minute live-demo flow, expected
terminal markers, evidence inventory, and exact non-claims.

## AI reviewers

PRs are reviewed by **CodeRabbit** and **Qodo Merge**. See
[docs/AI_REVIEWERS.md](docs/AI_REVIEWERS.md).

Repository-wide agent rules live in [AGENTS.md](AGENTS.md). Contributions use
a local deterministic gate and PR-only merge discipline; AIRLock does not rely
on paid GitHub Actions. See [CONTRIBUTING.md](CONTRIBUTING.md). Report suspected
vulnerabilities through [private vulnerability reporting](SECURITY.md), not a
public issue.

## Language

Rust (toolchain pin: `nightly-2026-01-15`) for AuditIR, static gates, and Stwo
replay. Solver/Lean tracks remain separate lanes.

## Non-claims

- `StaticPass` is not Circle-FRI / Fiat–Shamir security.
- A green boundary report covers only the verifier-derived request, actual proof
  supply, observed sample consumption, and outcome invariants for the pinned
  target. It is not a protocol theorem.
- The executable Stwo adapter covers its deterministic demo component and
  declared paths in sampled values, commitments, decommitment hash witnesses,
  queried values, and the PoW nonce. Other proof containers, FRI internals,
  query positions, configuration, every Stwo component, and production
  integrations remain unsupported. The generic replay command validates a
  bounded request against this same pinned target; it does not broaden target
  coverage. A queried-values truncation currently records a verifier panic in
  both layers and remains non-green.
- The concrete exporter-faithfulness suite compares one synthetic
  cross-interaction AIR against Stwo's `AssertEvaluator`, checks a Stwo-generated
  LogUp trace against both implementations, and compares uncompressed relation
  entries with `RelationTrackerEvaluator`. Its deterministic malicious
  assignments validate those exercised mappings. Concrete evaluation rejects
  empty constraint sets and bounded-depth violations instead of reporting a
  vacuous result or exhausting the host stack. Relation compression is
  limited to explicitly annotated Stwo `LookupElements` implementations whose
  exact `-z` constant and `alpha`-power coefficients pass the exporter
  fingerprint; custom relation protocols and universal equivalence for every
  `FrameworkEval` remain unsupported.
- The pre-commitment witness adapter covers one original-phase M31 column in
  the pinned transition demo. It evaluates the exact mutated values in AuditIR
  before committing them, then regenerates a real Stwo proof and invokes the
  full verifier whenever proof generation succeeds. The checked campaigns
  cover the honest trace, an all-row constraint-preserving Increment mutation,
  and one single-cell Increment mutation at each of the 16 physical rows.
  Public, interaction, and reduction phases,
  other columns, semantic claims beyond the emitted AIR, and universal
  malicious-witness coverage remain unsupported. The direct witness demo is
  in-process; it is not the isolated replay worker or an OS sandbox.
- The held-out adapter covers exactly Stwo's upstream `WideFibonacciEval<3>` at
  log size 4. It derives the three original-column identities and verifier
  request from the real component, then runs an honest case, a coordinated
  same-row Increment mutation that preserves `c = a^2 + b^2`, and a
  third-column-only Increment that violates it at every physical row. It does
  not cover other `stwo-examples` components, arbitrary scalar operators,
  application semantics, transcript or FRI soundness, or broad Stwo behavior.
- The deterministic witness matrix applies `Increment` and `Decrement` once to
  every declared original-phase M31 cell in the transition and held-out
  adapters. The frozen matrix contains 128 cases: 16 relation-preserving
  mutations accepted by the full path and 112 relation violations rejected for
  a typed constraint cause. Exact generation and fresh replay are executable
  evidence for those tuples only. The matrix is not random or solver-complete
  search, does not cover other scalar operators or commitment phases, and does
  not prove that no other malicious witness is accepted.
- A green transcript report establishes only the declared event-order and
  validation prerequisites, exact PoW configuration, and query shape over one
  complete typed trace. It does not establish Fiat--Shamir or FRI security.
- Stwo replay containment supplies a parent-owned deadline and bounded I/O. It
  is not an operating-system sandbox or a resource-isolation boundary.
- Replay-bundle checksums establish deterministic internal consistency within
  the demo verifier-boundary lane. They do not cover the separate evidence and
  provenance lane or authenticate who produced a bundle. External publication
  must pin or sign the bundle digest separately.
- The generated Rust regression replays the exact request against the pinned
  demo adapter, is compiled and executed offline, and contains no local
  repository path. It does not broaden coverage beyond that component or prove
  Stwo, FRI, Fiat--Shamir, or application soundness.
- `UNKNOWN` / timeout / `UNSUPPORTED` are never green.
- Release status stays `BLOCKED` while any required assurance lane is not
  `COVERED`.

## License

Apache-2.0. See [LICENSE](LICENSE).
