## Summary

-

Closes:

## Assurance Lane

- [ ] air-ir (AuditIR / schema / exporter)
- [ ] air-lint (static gate / fixtures)
- [ ] solver / witness-injection
- [ ] protocol or statement-binding (out of AIRLock core — call out explicitly)
- [ ] evidence / docs / claim boundaries
- [ ] reviewer-setup (CodeRabbit / Qodo / templates)

## Scope

- [ ] trusted IR or exporter faithfulness
- [ ] static analysis / FindingCode behavior
- [ ] seeded defect corpus
- [ ] docs or public claims
- [ ] no claim-boundary change

## Security and Coverage

- Coverage entries changed:
- Seeded vulnerable/fixed cases changed:
- Upstream commit or paper pinned:
- [ ] No private or embargoed vulnerability details are disclosed.
- [ ] Unmodeled, unsupported, quarantined, unknown, and timed-out work remains blocked.

## Validation

Commit tested:

List exact commands and results. The canonical command is:

```bash
scripts/verify-local.sh
```

Result:

## Reviewer Focus

-

## Reviewer State

- [ ] CodeRabbit reviewed the latest relevant diff, or unavailability is recorded below.
- [ ] Qodo reviewed the latest relevant diff, or unavailability is recorded below.
- [ ] All actionable correctness, security, and claim-scope threads are resolved.
- [ ] Five quiet minutes passed after the last push or reviewer activity.

Reviewer unavailability or manual replacement review:

## Non-Claims

- [ ] This PR does not claim Circle-FRI / Fiat–Shamir / end-to-end STARK security.
- [ ] This PR does not treat `UNKNOWN` / timeout / `UNSUPPORTED` as green.
- [ ] This PR does not present AIRLock results as whole-system production soundness.
- [ ] Seeded-defect expectations are stated when lint/IR behavior changes.
