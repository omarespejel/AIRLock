# AIRLock Agent Guide

Read this file before changing the repository. Then read
`.codex/START_HERE.md` and the files named there. Instructions in a nested
`AGENTS.md` override this file only for that subtree.

## Mission and trust boundary

AIRLock is adversarial assurance tooling for STARK systems. It analyzes what a
verifier checks and searches for witnesses and proof structures that honest
provers do not emit.

AIRLock is not itself a proof that Stwo, Circle FRI, SparseProve, or any other
system is sound. Keep these assurance lanes separate:

- AIR relation
- statement binding
- protocol, transcript, FRI, and Fiat-Shamir
- evidence and provenance

Only `COVERED` is green. `UNKNOWN`, timeout, `UNSUPPORTED`, `QUARANTINED`,
`OUT_OF_MODEL`, and an omitted surface must block the corresponding release
claim.

## Repository map

- `crates/airlock-ir`: lossless AuditIR contracts, coverage, and result types.
- `crates/airlock-lint`: generic static checks over AuditIR.
- `crates/airlock-boundary`: proof-neutral verifier request, observation,
  mutation-plan, outcome, and typed transcript contracts. Boundary and
  transcript result vocabularies remain separate assurance lanes.
- `crates/airlock-cli`: lane-specific commands and fail-closed exit behavior.
- `fixtures/seeded`: synthetic vulnerable/fixed regression pairs.
- `docs/SPEC.md`: current technical scope and non-goals.
- `docs/coverage.yaml`: explicit surface inventory.
- `scripts/verify-local.sh`: canonical local release gate.
- `.codex/START_HERE.md`: current handoff and read order.

## Working rules

- Start from a clean branch based on current `origin/main`. Do not take over a
  dirty or agent-owned checkout; create a worktree instead.
- Do not push directly to `main`. Use a focused, non-draft pull request unless
  the repository owner explicitly asks otherwise.
- Do not edit sibling Stwo, SparseProve, or other upstream repositories from an
  AIRLock task. Pin and report their exact commits instead.
- Never add secrets, customer data, private proof material, embargoed findings,
  or production exploit details. Follow `SECURITY.md` for disclosure.
- Prefer generic invariants over named-attack checks. Seeded fixtures prove
  rediscovery; they must not be the implementation's lookup table.
- AuditIR exporters must not drop expressions, limbs, phases, row support,
  preprocessed values, relation roles, or LogUp entries. A value referenced by
  emitted IR must be bound in the emitted artifact.
- Untrusted proof or manifest input must return a structured error. Do not use
  `assert!`, `expect`, unchecked indexing, or panic paths at verifier-facing
  boundaries.
- Every soundness-affecting change needs a negative or adversarial regression.
  Test both the vulnerable construction and the intended repair where possible.
- A passing test reports observed behavior. It does not by itself establish a
  cryptographic theorem or a public claim.

## Review rules

Reviewers should state the violated invariant, attacker capability or
false-green path, exact location, and smallest safe fix.

1. Flag any path that turns missing, unsupported, timed-out, or inconclusive
   analysis into a successful gate.
2. Flag lossy exports, unbound parameters, dropped extension-field limbs, or a
   mismatch between declared and consumed rows, phases, samples, or columns.
3. Flag prover-controlled data that influences a transcript before its shape,
   domain, or semantic role is validated.
4. Flag arithmetic claims whose admitted integer bounds exceed their field or
   encoder representation.
5. Flag prose that promotes an AIR-only result into statement, PCS, transcript,
   FRI, benchmark, or whole-system security.

Mechanical style belongs in formatters and lints. Human and AI review time goes
to correctness, security, evidence, and claim boundaries.

## Required validation

Run the canonical gate before every PR update that changes executable behavior
or repository controls:

```bash
scripts/verify-local.sh
```

If a required command cannot run, record the exact command and failure in the
PR. Never replace it with a green summary.

## Pull-request review

- State the assurance lane, exact validation commands, affected fixtures, and
  claim-boundary changes in the PR body.
- Obtain both CodeRabbit and Qodo review attempts. Resolve every actionable
  correctness or soundness thread.
- If a bot is unavailable or out of quota, retry once, record the condition,
  and perform an explicit manual review against this file. Bot availability is
  not a reason to waive unresolved findings.
- After the last reviewer activity or push, wait five quiet minutes and check
  the PR again before merging.
- Prefer rebase or squash. Do not merge with unresolved conversations.
