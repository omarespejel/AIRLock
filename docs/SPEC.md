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
| Verifier boundary | `airlock-boundary`, `airlock-stwo` | contracts, one pinned executable integration adapter, and its replay records |
| Witness consistency | `airlock-boundary`, `airlock-stwo` | one original-phase demo column plus one independently selected upstream three-column held-out target; separate AuditIR evaluation, real proof regeneration, and full verifier replay when proof generation succeeds |
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
  a relation's declared `row_support` is recorded as a claim and is never used as
  the yardstick for checking itself;
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
also compares every non-empty per-interaction mask schedule with
`InfoEvaluator::mask_offsets` and fails closed on divergence. Empty interaction
slots contain no reads and are normalized away in this comparison. The concrete
AuditIR evaluator accepts only exact, canonical assignments, resolves columns
once per evaluation, takes preprocessed values from the manifest, reproduces
Stwo's bit-reversed Circle-domain offset reads, and rejects vacuous hold
queries, over-deep expressions, missing values, unknown values, generator-only
preprocessing, invalid domains, and undefined inverses.

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
the concrete `z` and `alpha` values held by the exported `FrameworkEval`.
AIRLock symbolically fingerprints the relation's concrete `combine`
implementation and checks the exact constant `-z` and coefficients
`1, alpha, alpha^2, ...`. It rejects zero-arity, nonlinear, cross-term,
reordered, non-geometric, challenge-mismatched, or oversized compression
instead of silently reinterpreting it. Deriving those concrete values from the
Fiat--Shamir transcript remains outside this exporter-faithfulness lane;
arbitrary custom relation protocols are also unsupported. The required build
pin is not presented as observed manifest provenance.

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
component masks, and applies typed mutations to sampled values, commitments,
decommitment hash witnesses, queried values, or the PoW nonce before replaying
the case at both the raw PCS and ordinary framework layers. Its source identity
is pinned to the checked Stwo
baseline plus the accessor and opt-in consumption-sink patches. Both layers'
sample-consumption counts are recorded at the pinned PCS sample-read site by an
observer that does not change the verifier transcript or verdict. Rejected or
panicked executions retain any reads completed before failure; AIRLock never
substitutes modeled counts. Runtime outcomes come from the real verifier. This
covers only the demo component and the declared proof paths. Other
decommitment fields, FRI internals, query positions, proof configuration, other
components, and production integrations remain outside the executable coverage
claim. It does not claim protocol, transcript, FRI, or whole-system soundness.
Truncating a queried-values column currently records a panic in both verifier
layers; that result is reproducible evidence but never green.

The executable proof-mutation grammar is exact:

| Proof path | Indices | Supported edit |
| --- | --- | --- |
| `commitments` | none | container edit |
| `sampled_values` | tree, column | container edit |
| `sampled_values` | tree, column, value | scalar edit |
| `decommitments.hash_witness` | tree | container edit |
| `queried_values` | tree, column | container edit |
| `proof_of_work` | none | scalar edit |

Container edits are drop, truncate, duplicate, and swap. Scalar edits are
zero, one, maximum, increment, decrement, and bit flip. Every other path or
index shape returns a typed adapter error. Isolated replay records the worker
failure and remains non-green; it cannot count as exercised coverage.

The adapter executes drop, truncate, duplicate, and swap operations against a
real verifier-requested two-sample column. A byte-identical swap is rejected as
a no-op rather than counted as coverage. The feature-gated
`defective-verifier-mutant` target is a local known-bad verifier used only to
prove that accepted cardinality mismatches make the generic oracle emit a
counterexample. Its result is never classified as an upstream Stwo finding.

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

## Phase-bound witness replay

`airlock-boundary` defines proof-system-neutral witness paths, mutation plans,
proof-generation outcomes, and a fail-closed oracle. Every cell path names its
commitment phase, AuditIR column, and physical row. Mutation plans bind the
target, pinned source, case id, exact operations, and canonical pre/post witness
digests. A generated proof must carry its digest and a verifier outcome; a
prover rejection must not claim that the verifier ran. A relation-violating
campaign is expected only when the adapter assigns the typed
`constraint_violation` cause to a prover rejection. Unrelated prover rejection
or an unattributed verifier rejection remains non-green. Prover rejection,
verifier rejection, and infrastructure-failure kinds use the same canonical
machine-readable syntax. Infrastructure reports retain that kind as structured
data; consumers do not need to infer it from diagnostic prose. The
`constraint_violation` cause is valid only with the canonical
`constraints_not_satisfied` category; contradictory cause/category pairs are
malformed rather than green.

`StwoWitnessAdapter` instantiates this contract for the pinned transition demo.
It exports the same `FrameworkEval` to AuditIR, discovers its sole original
trace column from the exported phase metadata, applies canonical M31 mutations
before commitment, evaluates that exact vector with the concrete AuditIR
evaluator, and supplies the same vector to Stwo's commitment builder. If Stwo
produces a proof, the adapter runs the complete framework verifier and records
the outcome. The AuditIR manifest and generated proof are content addressed.

The checked campaign contains three independent cases: the honest zero trace;
an all-row Increment mutation to a constant-one trace that still satisfies the
relation and passes the full verifier; and one single-cell Increment mutation at
each of the 16 physical rows, each of which violates AuditIR and is rejected by
Stwo's prover as constraints-not-satisfied. This is
evidence that the scoped exporter, concrete evaluator, committed witness, and
real proof path agree on those cases. It is not a semantic application oracle,
a solver search, or proof that no other witness is accepted. Public,
interaction, reduction-phase, other-column, and other-scalar mutation requests
fail as unsupported.

`HeldOutAdapter` applies the same contracts to the target selected in issue
`#14` before its adapter existed: Stwo's upstream `WideFibonacciEval<3>` at log
size 4. It exports the real evaluator, checks the exact set of three original
column identities, retains their physical mask-declaration order explicitly,
and derives the OODS request from the real component. Its honest witness uses
`a = 0`, `b = -1/2`, and `c = 1/4` in M31. Incrementing all three cells at the
same row gives `a = 1`, `b = 1/2`, and `c = 5/4`, which still satisfies
`c = a^2 + b^2`; incrementing only `c` violates the relation. The checked
matrix exercises both mutations at every one of the 16 physical rows through
AuditIR and Stwo's real prove-and-verify path. Unsupported phases, columns,
rows, scalar operators, and all other Stwo examples fail closed or remain
outside coverage. This is one held-out adapter-generality check, not a
statistical benchmark or broad Stwo assurance.

## Cross-target witness matrix

`airlock-boundary` defines a proof-neutral matrix contract over a target's
exact source identity, AuditIR digest, phase, ordered columns, physical row
count, ordered scalar operators, cases, aggregate counts, and explicit
non-claims. Validation reconstructs the complete Cartesian-product inventory
and canonical case identities. Every case must contain exactly one declared
cell mutation, a valid `WitnessObservation`, and the report recomputed by
`evaluate_witness`. Counts and completion status are derived from those
reports, not trusted from serialized fields. A structurally valid blocked
campaign remains writable and freshly reproducible so AIRLock does not discard
the evidence it is meant to find; it still fails every completion gate.

The pinned Stwo policy `stwo-original-m31-cell-matrix-v1` fixes two targets in
order: the transition demo and `WideFibonacciEval<3>`. It fixes
`Phase1Original`, canonical M31 cells, and the ordered operators `Increment`
then `Decrement`. Every declared original column, physical row, and operator is
replayed once through concrete AuditIR evaluation and the real Stwo
proof-generation path. This produces 32 transition cases and 96 held-out
cases. In the current frozen matrix, 16 mutations preserve the relation and
pass the full verifier; 112 violate AuditIR and receive a typed
constraints-not-satisfied prover rejection.

The JSON artifact is deterministic and externally content addressed by its
SHA-256. Static verification rejects a changed schema, policy, source, target,
AuditIR digest, capability, tuple, order, observation, report, count, status,
or non-claim inventory. Fresh verification regenerates all 128 cases and
requires exact artifact equality, which also detects a structurally valid but
changed witness digest or proof result.

A complete matrix means only that the two scoped adapters agreed with their
exported AuditIR oracle over those exact mutations. It is not random fuzzing,
solver-complete search, broad malicious-witness coverage, statement binding,
transcript or FRI analysis, producer authentication, or a soundness theorem.
Other phases, scalar operators, targets, and Stwo components remain
unsupported.

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

`airlock-stwo-demo` exposes honest replay, OODS-sample corruption, a generic
bounded `ReplayRequest` JSON command, demo and held-out witness replay, bundle
verification, and path-independent Rust-regression generation. The generic
command rejects oversized, unknown-field, wrong-source, and wrong-target
requests before worker launch. Request-file replay requires Unix atomic
no-follow opening and fails closed on other hosts. Run commands
exit successfully only when the replay bundle is internally consistent and its
verdict matches the requested case. The verify command additionally requires a
fresh execution with the supplied worker to reproduce the stored record
exactly. A valid timeout, panic, process failure, or counterexample remains a
replay record but cannot pass the demo or release gate. Generated regressions
must not contain the local repository path and are compiled and executed in a
temporary offline Cargo project.

## Fixed campaign artifacts

The Stwo demo can persist complete typed witness replays and seal the fixed
transition-demo and independently selected held-out inventory into `campaign.json`,
`SUMMARY.md`, a byte-for-byte
coverage snapshot, and top-level `SHA256SUMS`. The manifest binds a
caller-pinned 40-character AIRLock Git commit, the exact Stwo source identity,
the SHA-256 of the exact replay worker shared by both boundary cases, eight case
identities and verdicts, fixed non-claims, and every payload digest and size.
Verification enforces a strict root and nested inventory, reads every file
through a predeclared bound without following symbolic links, recomputes all
reports and digests, reconstructs the generated regression, and reruns both
boundary cases, all three transition-demo witness cases, and all three
held-out witness cases. Every checksum-validated payload must be UTF-8 and free
of local absolute paths, credential markers, AI attribution, internal planning
terms, and prior-version narrative. The matched marker is never echoed in an
error.

The summary and manifest are deterministic for identical executions. They
contain no timestamps or local paths. The source commit remains a
caller-supplied pin; the unsigned campaign does not prove authorship, trusted
publication time, machine identity, broad Stwo coverage, or cryptographic
soundness. Statement binding and executable transcript, Fiat--Shamir, and FRI
assurance remain unsupported and appear beside the successful cases.

## External demo surface

`scripts/demo-airlock.sh OUTPUT_DIRECTORY` is the supported one-command demo.
It rejects a dirty source checkout or an existing output path before building,
verifies the pinned sibling Stwo source, and passes `--offline` to every Cargo
operation. It then executes the verifier-boundary, transition-witness,
held-out-witness, generated-regression, campaign-seal, and fresh-verification
stages. Each stage emits stable `AIRLOCK_DEMO_STAGE` begin/pass markers; only a
complete run emits `AIRLOCK_DEMO_COMPLETE`.

The resulting directory is the fixed campaign artifact described above. It is
portable and self-verifying, but unsigned: its checksums establish consistency,
not producer identity, machine attestation, or trusted time. A passing demo is
executable evidence for the exact covered surfaces, not a proof of
cryptographic soundness or absence of defects elsewhere.

## Seeded defects

1. Q8 padded `(0,0)` table with free multiplicity and `row_support: all` — must fail.
2. Q8 with `row_support` narrowed to the semantic rows but **no confining
   constraint** — must still fail. Narrowing a declaration adds no constraint, so
   the same malicious witness remains available and the obligation is
   undischarged.
3. Q8 with a verifier-owned selector and the constraint
   `(1 - table_active) * table_mult = 0` — must not raise Q8 codes. The discharge
   is attributed to that constraint, reported as a confinement certificate.
4. Encoder abs_bound > biased 28-bit capacity — must fail High.

The parameter-boundary suite additionally tests domain and table lengths at
`N-1`, `N`, and `N+1`, Stwo domain endpoints, support policies, content hashes,
M31 canonical values, encoder widths `0/1/8/127/128`, and asymmetric biases.

## Non-goals for v0

- cvc5 / Picus / Lean
- Circle-FRI security ledger
- Broad Stwo component and production-integration coverage beyond the demo adapter
- Live application-component exporter
