# Parameter-boundary profiles

AIRLock tests the edges of each declared contract, not only one known-good
configuration. These checks run over AuditIR before Q8, encoder-admissibility,
or future solver results are interpreted.

An empty manifest or a component with no syntactically nontrivial constraint or
relation entry fails High. Constant-zero constraints and zero-multiplicity
relations do not count as work; a constant-nonzero constraint also fails as
unsatisfiable. This static check does not replace solver-based vacuity analysis.

## Domain profiles

- `domain_size` must equal `2^log_size` exactly.
- Stwo Circle domains use `1 <= log_size <= 30`.
- Tests cover `N-1`, `N`, `N+1`, and both Stwo log-size boundaries.

## Preprocessed profiles

- `physical_length` must equal the component domain.
- `semantic_length` may be smaller, but never larger, than physical length.
- Concrete vectors must have exactly `physical_length` canonical M31 values.
- Their canonical BLAKE3 hash must be present and correct.
- Generator-only declarations stay blocked until a registered resolver can
  regenerate the column and verify its hash. A name and hash alone are not
  treated as evidence.

The matrix tests semantic and physical lengths at `N-1`, `N`, and `N+1`, as
well as missing, malformed, stale, and correctly recomputed hashes.

## Support and read profiles

- Ranges are half-open, nonempty, and contained in the component domain.
- Named row-class sets are nonempty and contain no duplicates.
- Every expression column read must resolve to one column declaration at an
  offset listed in that column's mask.
- Declared masks are nonempty; offsets are unique; and a supplied Stwo
  interaction index must match the column kind.
- Column kind fixes its commitment phase: public preprocessed, original witness,
  or interaction.
- Every column or formal parameter used by a relation must be available strictly
  before that relation's challenge phase; same-phase dependencies fail closed.
- Entries sharing a relation name must agree on tuple arity and challenge phase.
- Contract public-input names resolve to exactly one `PublicInput` parameter or
  `Phase0Public` column; public-output names resolve to exactly one
  `PublicOutput` column.
  Empty, duplicate, overlapping, dangling, and omitted public names fail closed.
- M31 constants and every limb of QM31 constants use canonical representatives;
  implicit modular reduction is rejected at the manifest boundary.

## Integer-encoder profiles

For `code = x + bias` in `bits` bits, AIRLock computes the symmetric integer
capacity as:

```text
min(bias, 2^bits - 1 - bias)
```

Without an explicit limb decomposition, the declaration is invalid when `bits`
is outside `1..=30`: the complete power-of-two code space must fit injectively
in one canonical M31 cell. The bias must be nonnegative and lie inside that code
space, and the admitted absolute bound must fit on both sides of the bias.
Obligation names are nonempty and unique. Tests cover exact capacity, capacity
plus one, asymmetric bias, negative bias, and widths `0`, `1`, `8`, `30`, `31`,
`127`, and `128`.

## Claim boundary

Constant-only M31 and QM31 expression trees are evaluated exactly. Wrapped zero
constraints and multiplicities do not count as proof work; constant nonzero or
undefined expressions fail closed.

Passing these profiles establishes internal consistency of the AuditIR shape.
It does not establish that an exporter observed every production component,
that the semantic annotations are correct, or that statement binding,
Fiat-Shamir, FRI, and proof parsing are sound. Those lanes remain separately
blocked until their own checks run.
