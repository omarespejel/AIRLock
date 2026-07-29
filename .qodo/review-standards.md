# Qodo Review Standards — AIRLock

Use these standards for Qodo v2 / agentic review and as manual reviewer context.

Aligned with the SparseProve / stwo-ml reviewer process: soundness and claim
hygiene first; style last. Adapted for an AIR *assurance tool*, not a zkML
prover.

## Non-Negotiables

- No public claim may present AIRLock `StaticPass`, solver `UNSAT`, or mutation
  score as proving Circle-FRI, Fiat–Shamir, transcript composition, receipt
  parsing, or end-to-end SparseProve security.
- `UNKNOWN`, timeout, `UNSUPPORTED`, and unmodeled scope are never green and
  never `COVERED`.
- AuditIR must remain lossless enough for the declared lints: uncompressed
  relation entries, preprocessed semantic vs physical length, and either
  concrete values or a checked generator hash.
- Seeded defects (Q8 padded table support, encoder vs admitted bound, and later
  wraparound classes) must be rediscovered by generic rules, not hard-coded
  file/column names.
- Challenge-specific solver models are `BAD_CHALLENGE` (error-budget events),
  not automatic `CONFIRMED_SAT`.
- No secrets, private keys, or credentials may appear in prompts, logs, issues,
  PRs, or artifacts.
- Prover-controlled proof, shape, and transcript data must be validated before
  it can influence Fiat-Shamir challenges. Malformed input must return an error,
  not panic or truncate silently.
- Every expression referenced by exported AuditIR must be defined or inlined;
  extension-field values must retain every coordinate.

## Preferred Feedback

Good review comments identify:

- the exact file/line, IR field, FindingCode, or fixture;
- the violated invariant (support, functionality, no-wrap, coverage, phase);
- attacker capability or false-green failure mode;
- how to reproduce (`airlock air --manifest ...`, `cargo test`, fixture name);
- the smallest fix direction.

Bad review comments are generic, stylistic, or impossible to verify.

## Domain Checks

- For `crates/airlock-ir/**`, check schema completeness, phase annotations,
  coverage status enum honesty, and hash stability.
- For `crates/airlock-lint/**`, check that vulnerable fixtures fail and fixed
  fixtures do not silently drop findings; watch for analyzer false greens.
- For `fixtures/seeded/**`, check expected FindingCode lists and that padding /
  boundary shapes are covered (table length ± 1, powers of two).
- For `docs/**` and `README.md`, check claim scope before prose quality.
- For `crates/airlock-cli/**`, check exit codes at unsupported and malformed
  boundaries and reject any default command that turns incomplete coverage
  green.
- For `scripts/**`, check that the local gate verifies the reason an expected
  failure occurred instead of accepting any nonzero exit.
- For `.coderabbit.yaml` / `.pr_agent.toml`, check that reviewer instructions
  still prioritize soundness over style and keep agentic Qodo commands.

## Lane Reminder

| Lane | Owner |
| --- | --- |
| AIR relation | AIRLock |
| Statement binding | separate gate |
| Protocol / FRI / FS | separate gate |
| Evidence / provenance | separate gate |

A green AIR lane must not collapse the other three.
