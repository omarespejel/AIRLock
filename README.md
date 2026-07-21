# AIRLock

Adversarial soundness testing for Stwo / Circle-STARK AIRs.

AIRLock analyzes the constraints a verifier actually checks, searches for
malicious witnesses an honest prover would never construct, and refuses to
treat an AIR surface as reviewed when it is unmodeled, unsupported, or
inconclusive.

This repository does **not** claim that any current SparseProve AIR is sound,
or that a green AIRLock report establishes whole-system STARK security.

## AI reviewers

PRs are reviewed by **CodeRabbit** and **Qodo Merge** using the same dual-bot
process as the SparseProve / `stwo-ml` research repos. See
[docs/AI_REVIEWERS.md](docs/AI_REVIEWERS.md).

## Language

Rust (nightly aligned with SparseProve / Stwo) for AuditIR, static gates, and
Stwo replay. Optional solver/Lean tracks are separate lanes.

## Status

Bootstrap in progress. Reviewer bots are configured first so subsequent
implementation PRs get automated hostile review.
