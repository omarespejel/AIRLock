## Summary

-

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

## Validation

List exact commands and results:

```bash
cargo +nightly-2026-01-15 test --locked
cargo +nightly-2026-01-15 clippy --locked -- -D warnings
# when CLI exists:
# cargo +nightly-2026-01-15 run -p airlock-cli -- air --manifest fixtures/...
```

## Reviewer Focus

-

## Non-Claims

- [ ] This PR does not claim Circle-FRI / Fiat–Shamir / end-to-end STARK security.
- [ ] This PR does not treat `UNKNOWN` / timeout / `UNSUPPORTED` as green.
- [ ] This PR does not present AIRLock results as SparseProve production soundness.
- [ ] Seeded-defect expectations are stated when lint/IR behavior changes.
