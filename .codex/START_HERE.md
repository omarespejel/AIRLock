# Start Here

Read this file before relying on memory, an old task, or another worktree.

## Read order

1. `AGENTS.md`
2. `.codex/START_HERE.md`
3. `README.md`
4. `docs/SPEC.md`
5. `docs/coverage.yaml`
6. `Cargo.toml`
7. the crate or fixture being changed
8. `git status --short --branch`
9. `git log -5 --oneline --decorate`

## Canonical state

The default branch is `main`. GitHub issues and pull requests record work in
flight; copied worktrees and prior chat summaries do not override the current
branch.

AIRLock v0 contains AuditIR, static AIR checks, seeded defect fixtures,
proof-neutral verifier-boundary contracts, one pinned executable Stwo demo
adapter, and a lane-aware CLI. The boundary contract crate includes typed
transcript-policy oracles, while the Stwo adapter derives a real demo request,
compares raw-PCS and framework outcomes for modeled OODS-sample mutations, and
can replay them in a bounded child process with a self-verifying evidence
bundle. Other proof containers remain outside this adapter's coverage. The
runner is not an OS sandbox, and bundle checksums do not authenticate a
producer. Statement binding, protocol/FRI/Fiat-Shamir analysis, broad evidence
provenance, solver search, and malicious-witness injection remain separate or
unfinished lanes unless current code and coverage say otherwise.

## Before editing

```bash
git fetch origin --prune
git status --short --branch
scripts/verify-local.sh
```

Use a clean worktree from `origin/main` when the current checkout is dirty,
detached, or owned by another task.

## Before publishing a result

Confirm all of the following:

- the analyzed upstream commit is pinned;
- the exporter and AuditIR schema preserve every value used by the check;
- the coverage manifest lists the executable proof-system or AIR surface;
- the vulnerable fixture fails for the intended invariant;
- the fixed fixture passes that invariant without hiding another lane;
- unsupported lanes remain visibly blocked;
- the public wording states exactly what was and was not established.

## Handoff

For work that cannot finish in one task, leave a short checked-in note under
`.codex/handoffs/` with the branch, exact commit, completed validation, active
blocker, and next command. Remove or archive the note when the work merges so
stale handoffs do not become a second source of truth.
