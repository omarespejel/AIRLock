# Required sibling Stwo patches

AIRLock's `airlock-export` path-depends on a sibling checkout:

```text
../stwo source baseline  @  f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a
```

`RelationEntry` fields are private to `stwo-constraint-framework`. External
`EvalAtRow` overrides (including `AuditEvaluator`) need public accessors.
AIRLock also needs an opt-in observer at the PCS sample-read boundary so
consumption is measured rather than reconstructed.

Create the exact checkout from a fresh AIRLock clone with:

```bash
scripts/setup-stwo.sh
```

The setup script refuses to replace an existing `../stwo`, checks out the
reachable upstream baseline in detached mode, applies
`patches/stwo-relation-entry-accessors.patch` and
`patches/stwo-consumption-sink.patch`, and verifies the resulting diff.

## Required API

In `crates/constraint-framework/src/lib.rs`, on `RelationEntry`:

```rust
pub fn relation(&self) -> &'a R { self.relation }
pub fn multiplicity(&self) -> &EF { &self.multiplicity }
pub fn values(&self) -> &'a [F] { self.values }
```

Without these getters, `AuditEvaluator::add_to_relation` cannot capture
uncompressed LogUp tuples from outside the Stwo crate.

The consumption patch adds the non-default `airlock-consumption` feature and a
`ConsumptionSink` hook to `CommitmentSchemeVerifier`. AIRLock records a read
only when the verifier pairs one requested point with one supplied value. The
feature does not alter transcript inputs, verification order, or verifier
outcomes. Without the feature, AIRLock does not claim observed consumption.

The checked patch digests are:

```text
7782a94a63a40e86b760d76dc37d2a6833921c5dfad5073b62972d640b90742a  patches/stwo-relation-entry-accessors.patch
be3708dd459c3e17caa615ffcfc034b6b20b9ae4a996327f8ff8f2464145b3b3  patches/stwo-consumption-sink.patch
```

`scripts/verify-stwo-checkout.sh` also checks that `STWO_SOURCE_ID` contains
the upstream baseline and both digests before any AIRLock result is accepted.

## Upstream

The accessor patch is a non-breaking additive API that may eventually be useful
upstream. The consumption patch is audit instrumentation and is not proposed as
an upstream production change.

Until that API lands upstream, `scripts/verify-local.sh` fails unless the
sibling checkout has byte-identical `Cargo.toml`, `Cargo.lock`, `crates/stwo`,
`crates/constraint-framework`, and held-out `wide_fibonacci` target sources
relative to the baseline, plus both exact checked patches. Other Stwo examples
remain outside the held-out target claim. Extra staged, tracked, or untracked
changes fail the gate.

The commit above is a required source baseline. It is not automatically written
to `AuditManifest.stwo_commit`: a hardcoded value would misreport provenance
when the dependency includes a patch. Callers may populate provenance only
after independently verifying the complete source identity.

## Verify pin

```bash
scripts/verify-stwo-checkout.sh
```
