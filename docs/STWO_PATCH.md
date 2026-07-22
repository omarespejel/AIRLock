# Required sibling Stwo patch

AIRLock's `airlock-export` path-depends on a sibling checkout:

```text
../stwo  @  41ba5a322c10841bbd50c36515b89fb8b29222d8
```

`RelationEntry` fields are private to `stwo-constraint-framework`. External
`EvalAtRow` overrides (including `AuditEvaluator`) need public accessors.

## Required API (already applied in the local sibling used for this PR)

In `crates/constraint-framework/src/lib.rs`, on `RelationEntry`:

```rust
pub fn relation(&self) -> &'a R { self.relation }
pub fn multiplicity(&self) -> &EF { &self.multiplicity }
pub fn values(&self) -> &'a [F] { self.values }
```

Without these getters, `AuditEvaluator::add_to_relation` cannot capture
uncompressed LogUp tuples from outside the Stwo crate.

## Upstream

This is a non-breaking additive API. Prefer landing it on the SparseProve
sibling branch / upstream Stwo rather than forking AIRLock's view of the AST.

## Verify pin

```bash
git -C ../stwo rev-parse HEAD
# expect 41ba5a322c10841bbd50c36515b89fb8b29222d8 (plus the accessor patch)
```
