# AIRLock specification (v0)

## Mission

Build a Stwo-native assurance stack that analyzes verifier-emitted AIRs,
searches for malicious witnesses, and refuses to mark unmodeled or inconclusive
surfaces green.

AIRLock is **not** a whole-system STARK soundness verifier.

## Lanes

| Lane | Owner | v0 status |
| --- | --- | --- |
| AIR relation | `airlock air` | static gate over AuditIR |
| Statement binding | separate | `OUT_OF_MODEL` |
| Verifier boundary | `airlock-boundary`, `airlock-stwo` | contracts, one pinned executable demo adapter, and its replay records |
| Protocol / FRI / FS | `airlock-boundary` | typed transcript contract/oracle only; executable transcript capture remains `UNINSTANTIATED` |
| Evidence / provenance | separate | `NOT_RUN`; replay bundles do not establish authorship or external provenance |

## Coverage statuses

Only `COVERED` is green. `UNSUPPORTED`, `QUARANTINED`, and `UNKNOWN` fail closed
for release claims.

A coverage surface is a proof-system relation, component, statement boundary,
or protocol/evidence lane analyzed by AIRLock. Development commands and shell
utilities are validated by the repository gate; they are not cryptographic
coverage surfaces.

## AuditIR requirements (lossless bar)

An export is not faithful enough for `COVERED` unless it retains:

- uncompressed relation entries (name, role, tuple, multiplicity, row support, phase);
- an explicit relation-compression contract whose implementation is checked
  against the exported tuple;
- preprocessed `semantic_length` vs `physical_length` plus concrete values **or**
  checked generator identity + values hash;
- commitment phases for columns and challenges;
- a typed declaration, semantic role, and availability phase for every formal
  parameter referenced by an expression;
- LogUp finalization flag;
- semantic annotations for columns on covered surfaces.

Before semantic analysis, the generic linter also requires:

- an exact Stwo Circle domain (`domain_size = 2^log_size`, `1 <= log_size <= 30`);
- unique component, constraint, column, and preprocessed identities;
- nonempty column masks, consistent interaction indices, and every expression
  read to resolve to a declared column and declared mask offset;
- nonempty labels for named `Other` semantic annotations;
- canonical M31 representatives for base constants and every QM31 limb;
- row ranges to be nonempty and contained in the component domain;
- preprocessed physical length to equal the component domain, with semantic length
  no larger than physical length;
- concrete preprocessed values to be canonical M31 representatives and match their
  declared content hash;
- formal roles to match availability phases, and every relation input to be
  available strictly before that relation's challenge phase;
- every entry sharing a relation name, including across components, to agree on
  arity and challenge phase;
- semantic-contract inputs, claims, and outputs to resolve exactly to typed
  public declarations, with every public declaration listed in the contract;
  and
- integer obligations to have unique names and undecomposed biased encoders to
  fit injectively in one M31 cell, with admitted bounds representable on both
  sides of zero.

The v0 linter has no generator registry. Generator-only declarations therefore
remain High even when their id and hash are well formed; `checked generator`
means a future resolver must regenerate the values and verify that hash.

`ExprEvaluator` alone is insufficient: it turns preprocessed columns into
`Param(id)` and compresses LogUp tuples. V0 fixtures hand-author AuditIR;
`airlock-export` adds `AuditEvaluator` that records uncompressed relations and
merges semantic annotations (preprocessed values, row support, roles). Export
rewrites known preprocessed `Param`s to `Column` ids, requires relation
annotations, and retains full `SecureCol` / QM31 `Const` limbs (AuditIR schema
`0.4.0`).

`AuditEvaluator` numbers columns independently inside each commitment tree,
matching Stwo's `InfoEvaluator`, `AssertEvaluator`, and relation tracker. Export
also compares the complete per-interaction mask schedule with
`InfoEvaluator::mask_offsets` and fails closed on divergence. The concrete
AuditIR evaluator accepts only exact, canonical assignments, takes
preprocessed values from the manifest, reproduces Stwo's bit-reversed
Circle-domain offset reads, and rejects missing values, unknown values,
generator-only preprocessing, invalid domains, and undefined inverses.

The checked differential surface is deliberately small. One nonconstant
synthetic AIR exercises previous/current/next-row reads, independent original
and interaction-tree column numbering, all four QM31 coordinates, and
deterministic malicious cell mutations. A second fixture compares every
uncompressed relation tuple and multiplicity with Stwo's
`RelationTrackerEvaluator`, accepts a real Stwo-generated LogUp interaction
trace and claimed sum in both evaluators, and rejects every single-cell
mutation in the exported relation. Agreement on those fixtures supports the
exported mapping they exercise; it is not a general proof that all
`FrameworkEval` implementations export faithfully.

Requires sibling Stwo `../stwo` whose dependency trees match upstream baseline
`f0d79b0f…`, plus the exact checked
RelationEntry accessor patch documented in `docs/STWO_PATCH.md`. The canonical
gate verifies both before testing the exporter. Generated evaluator
intermediates are inlined; they are never emitted as unconstrained AuditIR
parameters. Export fails when a referenced parameter has no declaration, a
declaration is unused, or one name is used at conflicting field sorts. Standard
LogUp claims and challenges are declared automatically; component-specific
parameters require explicit annotations. A relation is represented with one
Fiat--Shamir `alpha` and explicit powers `1, alpha, alpha^2, ...`, matching
Stwo's `LookupElements`, rather than treating each power as independent.
Export requires an explicit `StwoLookupElements` compression annotation and
symbolically fingerprints the relation's concrete `combine` implementation.
It rejects zero-arity, nonlinear, cross-term, reordered, non-geometric, or
otherwise unsupported compression instead of silently reinterpreting it. The
annotation remains the trusted statement that those coefficients come from the
named Fiat--Shamir challenges; arbitrary custom relation protocols are outside
this covered surface. The required build pin is not presented as observed
manifest provenance.

## Static findings (v0)

| Code | Meaning |
| --- | --- |
| `INVALID_SCHEMA_IDENTITY` | manifest schema id/version does not match the implemented AuditIR contract |
| `INVALID_MANIFEST_STRUCTURE` | component identity, domain, constraint, or relation shape is inconsistent |
| `INVALID_COLUMN_CONTRACT` | column declarations are duplicated, mistyped, or do not cover expression reads |
| `INVALID_PREPROCESSED_CONTRACT` | preprocessed length, source, values, or hash is inconsistent |
| `INVALID_ROW_SUPPORT` | support is empty, duplicated, reversed, or outside the component domain |
| `INVALID_ENCODER_CONTRACT` | encoder width or bias is malformed |
| `TABLE_MULTIPLICITY_OUTSIDE_SEMANTIC_SUPPORT` | Q8 class |
| `NONFUNCTIONAL_LOOKUP_KEY` | key maps to multiple values on allowed rows |
| `ADMITTED_BOUND_EXCEEDS_ENCODER` | H1 class |
| `LOGUP_NOT_FINALIZED` | missing finalize |
| `MISSING_SEMANTIC_ANNOTATION` | blocks COVERED when required |
| `INVALID_PARAMETER_CONTRACT` | undeclared, unused, duplicate, leaked, or mistyped formal parameter |

## Result vocabulary

Prefer fine-grained verdicts later: `CONFIRMED_SAT`, `BAD_CHALLENGE`,
`UNSAT_SOLVER`, `UNSAT_CHECKED`, `UNKNOWN`, `OUT_OF_MODEL`. Never treat timeout
as `UNSAT`.

## Verifier-boundary contracts

`airlock-boundary` records three independently meaningful cardinalities for a
pinned verifier target: what the verifier requested, what the proof supplied,
and what the verifier consumed. An accepted run is not green if any pair
differs. Panics, timeouts, unsupported adapters, malformed artifacts, and source
identity mismatches fail closed.

Mutation plans are structured and replayable. They identify an honest seed,
record distinct SHA-256 digests of the canonical seed and post-mutation
artifacts, and contain an ordered sequence of generic structural or scalar
edits. Statically known no-op mutations are rejected; findings do not look up
named historical defects. `airlock-boundary` remains proof-system neutral.
`airlock-stwo` instantiates it against a deterministic real Stwo component: it
builds an honest proof, derives OODS sample requests from the verifier's
component masks, applies generic structural or scalar mutations only within
those sampled-value containers, and replays the case at both the raw PCS and
ordinary framework layers. Its source identity is pinned to the checked Stwo
baseline and accessor patch. For accepted runs, both layers' sample-consumption
counts are reconstructed from the same pinned inner-PCS `zip` control flow;
runtime outcomes come from the real verifier. This covers only the demo
component and OODS-sample paths. Commitments, decommitments, query values, PoW,
FRI internals, other components, and production integrations remain outside
the executable coverage claim. It does not claim protocol, transcript, FRI, or
whole-system soundness.

The same crate defines a typed transcript trace. Every prover-controlled value
must name its proof path and pass all validation rules declared for that path
before absorption. Every challenge and query draw must have a contract listing
its required absorptions, optional domain separator, and proof-of-work
precondition. Query count and domain size are exact contract fields. Named
proof-of-work checks pin their bits and nonce path, and an absorbed nonce must
match the exact bytes that passed validation and work verification. Query count
is derived from recorded positions, and every position must belong to the
contracted domain. Missing,
duplicate, unmodeled, or reordered events fail closed. Zero-work nonce behavior
must be chosen explicitly as disallowed, canonical-zero, or arbitrary; AIRLock
does not silently promote one policy into a vulnerability.

Absorbed values and challenge outputs are recorded by canonical SHA-256
digests; nonce bytes and query positions are retained directly. The complete
ordered trace is content addressed. This is an evidence and
ordering contract only. The executable adapter and any Fiat--Shamir security
reduction remain separate work.

## Isolated replay records

`airlock-stwo-worker` accepts a bounded, content-addressed replay request and
returns one validated differential replay. The parent runner copies the worker
into a private randomized directory, hashes the exact bytes it executes, owns
the deadline, drains bounded stdout and stderr, and
classifies timeout, process failure, oversized output, malformed output, and
response mismatch separately. Only an honest acceptance or expected mutation
rejection may satisfy `is_expected`; every process anomaly fails closed.

The replay-bundle writer publishes a new directory containing exactly
`request.json`, `report.json`, and `SHA256SUMS`. The verifier checks file
inventory, size limits, canonical schemas, checksums, pinned source and target,
request linkage, and every replay report. The bundle belongs to the executable
verifier-boundary lane; it is not a separate evidence-assurance result. The
runner is subprocess containment, not an OS sandbox. The bundle is deterministic
and self-consistent, but it is not signed and therefore does not authenticate
its producer.

`airlock-stwo-demo` exposes honest replay, OODS-sample corruption, bundle
verification, and path-independent Rust-regression generation. Run commands
exit successfully only when the replay bundle is internally consistent and its
verdict matches the requested case. The verify command additionally requires a
fresh execution with the supplied worker to reproduce the stored record
exactly. A valid timeout, panic, process failure, or counterexample remains a
replay record but cannot pass the demo or release gate. Generated regressions
must not contain the local repository path and are compiled and executed in a
temporary offline Cargo project.

## Seeded defects

1. Q8 padded `(0,0)` table with free multiplicity — must fail.
2. Fixed Q8 with multiplicity confined to semantic rows — must not raise Q8 codes.
3. Encoder abs_bound > biased 28-bit capacity — must fail High.

The parameter-boundary suite additionally tests domain and table lengths at
`N-1`, `N`, and `N+1`, Stwo domain endpoints, support policies, content hashes,
M31 canonical values, encoder widths `0/1/8/127/128`, and asymmetric biases.

## Non-goals for v0

- cvc5 / Picus / Lean
- Circle-FRI security ledger
- Broad Stwo component and production-integration coverage beyond the demo adapter
- Live SparseProve exporter (feature-flagged later)
