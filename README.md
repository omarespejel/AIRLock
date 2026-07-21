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
| Static gate (`airlock-lint`) | Q8 support/functionality + encoder bound + LogUp finalize |
| CLI (`airlock`) | `air`, `coverage`, `schema` |
| Stwo `AuditEvaluator` exporter | not landed (fixtures are hand-authored) |
| cvc5 / Lean / phase injection | later PRs |

See [docs/SPEC.md](docs/SPEC.md) and [docs/coverage.yaml](docs/coverage.yaml).

## Quick start

```bash
cargo +nightly-2026-01-15 test --locked
cargo +nightly-2026-01-15 clippy --locked -- -D warnings

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

## Language

Rust (toolchain pin: `nightly-2026-01-15`) for AuditIR, static gates, and
future Stwo replay. Solver/Lean tracks remain separate lanes.

## Non-claims

- `StaticPass` is not Circle-FRI / Fiat–Shamir security.
- `UNKNOWN` / timeout / `UNSUPPORTED` are never green.
- Release status stays `BLOCKED` until all paper-relevant lanes are covered.
