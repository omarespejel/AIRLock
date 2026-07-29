# Contributing to AIRLock

AIRLock is security tooling. A small diff can change what the project calls
safe, so correctness, reproducibility, and explicit scope take priority over
speed.

## Before starting

Read `AGENTS.md`, `.codex/START_HERE.md`, `docs/SPEC.md`, and the relevant
coverage entries. For security findings, stop and use `SECURITY.md` instead of
the public tracker.

Create a clean branch from current `origin/main`:

```bash
git fetch origin --prune
git switch --create <type>/<short-name> origin/main
```

Use `feat/`, `fix/`, `docs/`, `test/`, or `chore/` as the branch prefix.

Enable the repository's pre-push gate once per clone:

```bash
scripts/install-git-hooks.sh
```

## Change design

- Keep AIR, statement, protocol/transcript, and evidence changes in separate
  PRs unless their coupling is necessary and documented.
- Add generic invariants, not special cases keyed to a fixture or component
  name.
- Add a vulnerable/fixed regression pair for soundness-affecting changes when
  practical.
- Update `docs/coverage.yaml` when a surface becomes covered, unsupported,
  quarantined, or unknown. Only `COVERED` is green.
- Do not raise a public claim above the strongest checked lane.

## Local gate

AIRLock intentionally does not use GitHub Actions for the canonical gate. Run
the deterministic local gate before opening a PR and after the final change:

```bash
scripts/verify-local.sh
```

The script checks formatting, Clippy, the workspace tests, vulnerable/fixed
fixture behavior, fail-closed coverage, and unimplemented-lane exits. Paste its
result and the exact commit into the PR.

## Pull requests

Open a normal, focused PR and complete the template. Direct pushes to `main`,
force pushes, and deletion of `main` are prohibited by repository rules.

AIRLock uses CodeRabbit and Qodo as independent review aids. Both should review
each PR, but neither replaces the local gate, a human decision, or a
cryptographic argument.

1. Wait for both review attempts.
2. Resolve actionable correctness, soundness, security, test, and claim-scope
   comments.
3. If a bot is unavailable or out of quota, retry once and record that fact in
   the PR. Perform a manual review against `AGENTS.md`; do not waive a known
   finding.
4. Wait five quiet minutes after the last push or reviewer activity.
5. Re-check the diff, conversations, and local gate before rebase or squash
   merge.

No reviewer should approve by counting passing tests alone. Tests establish
behavior for the tested cases; they do not prove whole-system soundness.
