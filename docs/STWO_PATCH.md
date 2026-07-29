# Required sibling Stwo patch

AIRLock's `airlock-export` path-depends on a sibling checkout:

```text
../stwo source baseline  @  f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a
```

`RelationEntry` fields are private to `stwo-constraint-framework`. External
`EvalAtRow` overrides (including `AuditEvaluator`) need public accessors.

Create the exact checkout from a fresh AIRLock clone with:

```bash
scripts/setup-stwo.sh
```

The setup script refuses to replace an existing `../stwo`, checks out the
reachable upstream baseline in detached mode, applies
`patches/stwo-relation-entry-accessors.patch`, and verifies the resulting diff.

## Required API

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

Until that API lands upstream, `scripts/verify-local.sh` fails unless the
sibling checkout has byte-identical `Cargo.toml`, `Cargo.lock`, `crates/stwo`,
and `crates/constraint-framework` objects relative to the baseline, plus the
exact checked patch. This permits descendants that change only unrelated Stwo
examples while preventing dependency drift. Extra staged, tracked, or untracked
changes fail the gate.

The commit above is a required source baseline. It is not automatically written
to `AuditManifest.stwo_commit`: a hardcoded value would misreport provenance
when the dependency includes a patch. Callers may populate provenance only
after independently verifying the complete source identity.

## Verify pin

```bash
scripts/verify-stwo-checkout.sh
```
