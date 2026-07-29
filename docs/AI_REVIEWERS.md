# AI Reviewers

AIRLock uses CodeRabbit and Qodo as independent review aids. Their job is to
find missed invariants and false-green paths, not to certify cryptographic
soundness.

| Reviewer | Configuration | Entry point |
| --- | --- | --- |
| CodeRabbit | [`.coderabbit.yaml`](../.coderabbit.yaml), schema v2 | Automatic PR review; `@coderabbitai review` to retry |
| Qodo | [`.pr_agent.toml`](../.pr_agent.toml) and [review standards](../.qodo/review-standards.md) | `/agentic_review` and `/agentic_describe` |

The root [`AGENTS.md`](../AGENTS.md) is the canonical rule set. Tool-specific
files add routing and presentation details; they must not weaken it.

## What is enforced

- `main` accepts changes through pull requests and rejects force pushes and
  deletion.
- All review conversations must be resolved before merge.
- The PR template records the exact local gate, assurance lane, coverage
  changes, reviewer state, and non-claims.
- `scripts/verify-local.sh` is the deterministic code and fixture gate.

AIRLock does not use paid GitHub Actions for this gate. CodeRabbit and Qodo are
not configured as required GitHub status checks because a quota or service
outage must not lock the repository. The process still requires both review
attempts and resolution of every actionable comment.

## Review process

1. Run `scripts/verify-local.sh` on the commit that will be pushed.
2. Open a normal, focused PR and complete the template.
3. Wait for both reviewers. Re-trigger a missing reviewer once.
4. Fix actionable correctness, soundness, security, test, and claim-scope
   findings. Do not dismiss a finding merely because another bot passed.
5. If a reviewer is unavailable or out of quota, record that condition and
   perform a manual review against `AGENTS.md`.
6. After the last push or reviewer activity, wait five quiet minutes and check
   the PR again.
7. Re-run the local gate, resolve all conversations, and rebase or squash merge.

Passing bot reviews are evidence that two review passes ran. They are not an
AIR theorem, protocol proof, benchmark validation, or release certificate.

## Reviewer focus

The highest-value review questions are:

- Did the exporter preserve every expression, limb, phase, row support, sample,
  preprocessed value, and relation entry consumed by the verifier?
- Can unsupported or inconclusive work become `COVERED` or return exit code 0?
- Can prover-controlled data influence the transcript before exact shape and
  domain validation?
- Do admitted integer bounds fit the field and every encoder?
- Does a public claim cross from the AIR lane into statement, protocol, FRI,
  transcript, evidence, or whole-system security?

Security-sensitive findings must follow `SECURITY.md`; do not ask a reviewer bot
to publish or summarize an embargoed report.

## Manual commands

Comment on the PR when an automatic review is missing:

```text
@coderabbitai review
```

```text
/agentic_review
/agentic_describe
```

Use `@coderabbitai configuration` to inspect CodeRabbit's resolved repository
configuration.
