# AIRLock

Adversarial soundness testing for Stwo / Circle-STARK AIRs.

AIRLock analyzes the constraints a verifier actually checks, searches for
malicious witnesses an honest prover would never construct, and refuses to
treat an AIR surface as reviewed when it is unmodeled, unsupported, or
inconclusive.

This repository does **not** claim that any current SparseProve AIR is sound,
or that a green AIRLock report establishes whole-system STARK security.

## Status (v0)

| Piece | State |
| --- | --- |
| AuditIR schema (`airlock-ir`) | landed |
| Static gate (`airlock-lint`) | schema/shape + parameter/phase closure + preprocessed integrity + Q8 support/functionality + encoder bound + LogUp finalize |
| Verifier boundary contracts (`airlock-boundary`) | proof-neutral request/supply/consumption and typed transcript oracles |
| Pinned Stwo adapter (`airlock-stwo`) | real demo proof, verifier-derived OODS requests, sample-only mutations, raw-PCS/framework replay, subprocess containment, verified replay bundles, generated Rust regression |
| CLI (`airlock`) | `air`, `coverage`, `schema` |
| Stwo `AuditEvaluator` exporter | landed (`airlock-export`); concrete differential checks cover one synthetic cross-interaction AIR |
| cvc5 / Lean / phase injection | later PRs |

See [docs/SPEC.md](docs/SPEC.md) and [docs/coverage.yaml](docs/coverage.yaml).
The fail-closed boundary profiles are specified in
[docs/PARAMETER_BOUNDARIES.md](docs/PARAMETER_BOUNDARIES.md).

## Quick start

```bash
# One-time exporter dependency setup. Refuses to replace an existing ../stwo.
scripts/setup-stwo.sh

scripts/verify-local.sh

cargo +nightly-2026-01-15 test -p airlock-stwo --locked

# Exporter-faithfulness differential against Stwo's concrete evaluators.
cargo +nightly-2026-01-15 test -p airlock-export \
  --test assert_evaluator_faithfulness --locked

# Honest proof, adversarial rejection, verified bundles, and Rust regression.
scripts/demo-stwo-boundary.sh

cargo +nightly-2026-01-15 run -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_vulnerable.json
# expects StaticFail (exit 1)

cargo +nightly-2026-01-15 run -p airlock-cli -- air \
  --manifest fixtures/seeded/q8_padded_table_fixed.json
# expects StaticPass (exit 0); overall release stays BLOCKED
```

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
- A green boundary report covers only the modeled request, supply, consumption,
  and outcome invariants for the pinned target. It is not a protocol theorem.
- The executable Stwo adapter covers its deterministic demo component and
  declared OODS-sample mutation paths, not other proof containers, every Stwo
  component, or any production integration.
- The concrete exporter-faithfulness suite compares one synthetic
  cross-interaction AIR against Stwo's `AssertEvaluator`, checks a Stwo-generated
  LogUp trace against both implementations, and compares uncompressed relation
  entries with `RelationTrackerEvaluator`. Its deterministic malicious
  assignments validate those exercised mappings. Relation compression is
  limited to explicitly annotated Stwo `LookupElements` implementations whose
  affine geometric shape passes the exporter fingerprint; custom relation
  protocols and universal equivalence for every `FrameworkEval` remain
  unsupported.
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
- Release status stays `BLOCKED` until all paper-relevant lanes are covered.

## License

Apache-2.0. See [LICENSE](LICENSE).
