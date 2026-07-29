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
| Static gate (`airlock-lint`) | schema + parameter closure + Q8 support/functionality + encoder bound + LogUp finalize |
| CLI (`airlock`) | `air`, `coverage`, `schema` |
| Stwo `AuditEvaluator` exporter | landed (`airlock-export`); needs RelationEntry accessors — see `docs/STWO_PATCH.md` |
| cvc5 / Lean / phase injection | later PRs |

See [docs/SPEC.md](docs/SPEC.md) and [docs/coverage.yaml](docs/coverage.yaml).

## Quick start

```bash
# One-time exporter dependency setup. Refuses to replace an existing ../stwo.
scripts/setup-stwo.sh

scripts/verify-local.sh

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

Rust (toolchain pin: `nightly-2026-01-15`) for AuditIR, static gates, and
future Stwo replay. Solver/Lean tracks remain separate lanes.

## Non-claims

- `StaticPass` is not Circle-FRI / Fiat–Shamir security.
- `UNKNOWN` / timeout / `UNSUPPORTED` are never green.
- Release status stays `BLOCKED` until all paper-relevant lanes are covered.

## License

Apache-2.0. See [LICENSE](LICENSE).
