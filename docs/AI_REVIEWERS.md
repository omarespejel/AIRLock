# AI reviewers (CodeRabbit + Qodo)

AIRLock uses the same dual-reviewer process as the SparseProve / `stwo-ml`
research repos:

| Bot | Config | Modern entrypoint |
| --- | --- | --- |
| **CodeRabbit** | [`.coderabbit.yaml`](../.coderabbit.yaml) (schema v2) | Auto-review on PRs; `@coderabbitai configuration` to dump resolved config |
| **Qodo Merge** (PR-Agent) | [`.pr_agent.toml`](../.pr_agent.toml) | `/agentic_describe` + `/agentic_review` on open/push |
| **Qodo standards** | [`.qodo/review-standards.md`](../.qodo/review-standards.md) | Paste / portal “review standards” context |

## Why these versions

- **CodeRabbit**: repository-root `.coderabbit.yaml` with
  `$schema=https://coderabbit.ai/integrations/schema.v2.json`, assertive
  profile, path instructions, and pre-merge custom checks. Config on the
  reviewed branch is what applies
  ([docs](https://docs.coderabbit.ai/getting-started/yaml-configuration)).
- **Qodo**: agentic commands (`/agentic_review`, `/agentic_describe`) rather
  than legacy-only `/review`. Repo-root `.pr_agent.toml` overrides defaults;
  settings take effect after merge to the default branch
  ([docs](https://docs.qodo.ai/install-and-configure/configuration-overview/configuration-file)).

## One-time GitHub App install

If the bots do not comment on the first PR:

1. Install **CodeRabbit** on `omarespejel/AIRLock`:
   https://github.com/apps/coderabbitai
2. Install **Qodo Merge** (CodiumPR / Qodo) on the same repo from the Qodo
   portal / GitHub App listing used for `stwo-ml`.
3. Confirm both apps have **Contents: Read** and **Pull requests: Read & Write**
   (and checks if commit-status failure is desired).

Org-wide installs that already cover `omarespejel/*` need no extra step.

## Local process (mirrors stwo-ml)

1. Open a normal (non-draft) PR.
2. Wait for CodeRabbit + Qodo agentic review.
3. Address actionable soundness findings; ignore pure prose taste unless it
   causes claim drift.
4. After the latest bot activity, wait at least **5 minutes**, re-check that no
   new actionable findings appeared, then merge (prefer rebase merge).

## Manual triggers

On a PR comment:

```text
@coderabbitai review
@coderabbitai configuration
```

```text
/agentic_review
/agentic_describe
```
