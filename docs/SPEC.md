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
| Protocol / FRI / FS | separate | `UNINSTANTIATED` |
| Evidence / provenance | separate | `NOT_RUN` |

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
- canonical M31 representatives for base constants and every QM31 limb;
- row ranges to be nonempty and contained in the component domain;
- preprocessed physical length to equal the component domain, with semantic length
  no larger than physical length;
- concrete preprocessed values to be canonical M31 representatives and match their
  declared content hash;
- formal roles to match availability phases, and every relation input to be
  available strictly before that relation's challenge phase; and
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
`0.3.0`).

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
Stwo's `LookupElements`, rather than treating each power as independent. The
required build pin is not presented as observed manifest provenance.

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
- Live SparseProve exporter (feature-flagged later)
