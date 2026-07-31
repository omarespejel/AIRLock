//! Confinement certificates for table-side multiplicity.
//!
//! A declared `row_support` is a *claim* about where a table multiplicity may be
//! nonzero. It is supplied by the same party whose AIR is under test, so it can
//! never discharge itself. This module looks for the only evidence that can:
//! a constraint in the component that forces the multiplicity expression to zero
//! on every row outside semantic support.
//!
//! The recognized shape is a product constraint
//!
//! ```text
//! guard * multiplicity = 0
//! ```
//!
//! where `guard` evaluates to a nonzero value on every padding row, using only
//! preprocessed columns whose concrete values are present in the artifact. If the
//! product is constrained to zero and the guard is nonzero on a row, the
//! multiplicity is zero on that row. That inference is derived from observed
//! data, never from the declaration under test.
//!
//! Anything not recognized yields no certificate, so the obligation stays
//! undischarged and the caller reports it. This module fails closed.

use std::collections::BTreeMap;

use airlock_ir::{
    BaseExpr, ColumnKind, CommitmentPhase, ComponentManifest, ExtExpr, PreprocessedColumn,
    RelationEntry, RowSupport,
};

/// M31 prime. Guard evaluation is exact in the base field.
const P: u64 = (1 << 31) - 1;
const MAX_CONFINEMENT_EXPRESSION_DEPTH: usize = 128;
const MAX_CONFINEMENT_EXPRESSION_NODES: usize = 1 << 16;
const MAX_CONFINEMENT_EVALUATION_STEPS: u64 = 1 << 24;

/// Evidence that an AIR constraint confines a multiplicity to semantic support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfinementCertificate {
    /// Constraint that discharges the obligation.
    pub constraint_id: String,
    /// Preprocessed columns the guard depends on.
    pub guard_columns: Vec<String>,
}

/// Search for a constraint that forces `relation.multiplicity` to zero on
/// `[semantic_length, physical_length)`.
pub(crate) fn confinement_certificate(
    component: &ComponentManifest,
    relation: &RelationEntry,
    prep: &BTreeMap<&str, &PreprocessedColumn>,
    semantic_length: u64,
    physical_length: u64,
) -> Option<ConfinementCertificate> {
    if physical_length <= semantic_length {
        return None;
    }
    base_expression_complexity(&relation.multiplicity)?;
    let mut remaining_evaluation_steps = MAX_CONFINEMENT_EVALUATION_STEPS;
    for constraint in &component.constraints {
        if ext_expression_complexity(&constraint.expression).is_none() {
            continue;
        }
        // The constraint must actually apply on the padding rows it is meant to
        // discharge; a constraint scoped away from them proves nothing there.
        if !row_support_covers(&constraint.row_support, semantic_length, physical_length) {
            continue;
        }
        let Some(factors) = flatten_ext_product(&constraint.expression) else {
            continue;
        };
        // `g * m = 0` with `g != 0` forces `m = 0`, and `m = 0` exactly when
        // `-m = 0`, so a factor matching the multiplicity up to sign is enough.
        // Table-side relations carry a negated multiplicity by convention.
        let Some(multiplicity_position) = factors
            .iter()
            .position(|factor| strip_neg(factor) == strip_neg(&relation.multiplicity))
        else {
            continue;
        };

        let guards: Vec<&BaseExpr> = factors
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != multiplicity_position)
            .map(|(_, factor)| *factor)
            .collect();
        if guards.is_empty() {
            continue;
        }
        if guards
            .iter()
            .any(|guard| !uses_only_fixed_columns(guard, component))
        {
            continue;
        }
        let Some(guard_nodes) = guards.iter().try_fold(0u64, |total, guard| {
            let nodes = u64::try_from(base_expression_complexity(guard)?).ok()?;
            total.checked_add(nodes)
        }) else {
            continue;
        };
        if !reserve_evaluation_work(
            &mut remaining_evaluation_steps,
            guard_nodes,
            physical_length - semantic_length,
        ) {
            continue;
        }

        // Every guard factor must be nonzero on every padding row. A product is
        // zero when any factor is zero, so one vanishing factor leaves the
        // multiplicity unconstrained on that row.
        let all_padding_guarded = (semantic_length..physical_length).all(|row| {
            guards.iter().all(|guard| {
                matches!(evaluate_base_at_row(guard, prep, row, physical_length), Some(value) if value != 0)
            })
        });
        if !all_padding_guarded {
            continue;
        }

        let mut guard_columns = Vec::new();
        for guard in &guards {
            collect_columns(guard, &mut guard_columns);
        }
        guard_columns.sort();
        guard_columns.dedup();

        return Some(ConfinementCertificate {
            constraint_id: constraint.id.clone(),
            guard_columns,
        });
    }
    None
}

enum ExpressionRef<'a> {
    Base(&'a BaseExpr),
    Ext(&'a ExtExpr),
}

fn base_expression_complexity(expression: &BaseExpr) -> Option<usize> {
    expression_complexity(ExpressionRef::Base(expression))
}

fn ext_expression_complexity(expression: &ExtExpr) -> Option<usize> {
    expression_complexity(ExpressionRef::Ext(expression))
}

fn expression_complexity(root: ExpressionRef<'_>) -> Option<usize> {
    let mut nodes = 0usize;
    let mut stack = vec![(root, 1usize)];
    while let Some((expression, depth)) = stack.pop() {
        nodes += 1;
        if depth > MAX_CONFINEMENT_EXPRESSION_DEPTH || nodes > MAX_CONFINEMENT_EXPRESSION_NODES {
            return None;
        }
        let child_depth = depth + 1;
        match expression {
            ExpressionRef::Base(BaseExpr::Add { lhs, rhs })
            | ExpressionRef::Base(BaseExpr::Mul { lhs, rhs }) => {
                stack.push((ExpressionRef::Base(rhs), child_depth));
                stack.push((ExpressionRef::Base(lhs), child_depth));
            }
            ExpressionRef::Base(BaseExpr::Neg { inner })
            | ExpressionRef::Base(BaseExpr::Inv { inner }) => {
                stack.push((ExpressionRef::Base(inner), child_depth));
            }
            ExpressionRef::Ext(ExtExpr::Add { lhs, rhs })
            | ExpressionRef::Ext(ExtExpr::Mul { lhs, rhs }) => {
                stack.push((ExpressionRef::Ext(rhs), child_depth));
                stack.push((ExpressionRef::Ext(lhs), child_depth));
            }
            ExpressionRef::Ext(ExtExpr::Neg { inner }) => {
                stack.push((ExpressionRef::Ext(inner), child_depth));
            }
            ExpressionRef::Ext(ExtExpr::SecureCol { parts }) => {
                for part in parts.iter().rev() {
                    stack.push((ExpressionRef::Base(part), child_depth));
                }
            }
            ExpressionRef::Ext(ExtExpr::FromBase { inner }) => {
                stack.push((ExpressionRef::Base(inner), child_depth));
            }
            ExpressionRef::Base(
                BaseExpr::Param { .. } | BaseExpr::Const { .. } | BaseExpr::Column { .. },
            )
            | ExpressionRef::Ext(ExtExpr::Param { .. } | ExtExpr::Const { .. }) => {}
        }
    }
    Some(nodes)
}

fn reserve_evaluation_work(remaining: &mut u64, expression_nodes: u64, rows: u64) -> bool {
    let Some(steps) = expression_nodes.checked_mul(rows) else {
        return false;
    };
    let Some(updated) = remaining.checked_sub(steps) else {
        return false;
    };
    *remaining = updated;
    true
}

/// Whether every column in an expression is a verifier-owned phase-0 column.
fn uses_only_fixed_columns(expression: &BaseExpr, component: &ComponentManifest) -> bool {
    match expression {
        BaseExpr::Column { id, .. } => {
            let mut declarations = component.columns.iter().filter(|column| column.id == *id);
            declarations.next().is_some_and(|column| {
                declarations.next().is_none()
                    && column.kind == ColumnKind::Preprocessed
                    && column.commitment_phase == CommitmentPhase::Phase0Public
            })
        }
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            uses_only_fixed_columns(lhs, component) && uses_only_fixed_columns(rhs, component)
        }
        BaseExpr::Neg { inner } => uses_only_fixed_columns(inner, component),
        BaseExpr::Const { .. } => true,
        BaseExpr::Param { .. } | BaseExpr::Inv { .. } => false,
    }
}

/// Whether a constraint's declared support includes every padding row.
fn row_support_covers(support: &RowSupport, semantic_length: u64, physical_length: u64) -> bool {
    match support {
        RowSupport::All => true,
        RowSupport::Range { start, end } => *start <= semantic_length && *end >= physical_length,
        // Class-named support cannot be reduced to concrete indices without a
        // per-row classification, which the artifact does not carry. Fail closed
        // unless the class set explicitly admits padding.
        RowSupport::Classes { classes } => classes
            .iter()
            .any(|class| matches!(class, airlock_ir::RowClass::Padding)),
    }
}

/// Flatten an extension-field product into base-field factors.
///
/// Returns `None` for any shape this module does not model, so an unmodeled
/// constraint cannot be mistaken for a certificate.
fn flatten_ext_product(expression: &ExtExpr) -> Option<Vec<&BaseExpr>> {
    let mut factors = Vec::new();
    push_ext_factors(expression, &mut factors)?;
    if factors.is_empty() {
        None
    } else {
        Some(factors)
    }
}

fn push_ext_factors<'a>(expression: &'a ExtExpr, out: &mut Vec<&'a BaseExpr>) -> Option<()> {
    match expression {
        ExtExpr::Mul { lhs, rhs } => {
            push_ext_factors(lhs, out)?;
            push_ext_factors(rhs, out)
        }
        ExtExpr::FromBase { inner } => {
            push_base_factors(inner, out);
            Some(())
        }
        // The exporter lifts a base-field constraint as `SecureCol([e, 0, 0, 0])`.
        // That is zero exactly when `e` is zero, so it is equivalent to `FromBase`.
        // Any nonzero upper limb is a genuine extension-field constraint this
        // module does not model.
        ExtExpr::SecureCol { parts } => {
            let [first, rest @ ..] = parts;
            if !rest
                .iter()
                .all(|part| matches!(part, BaseExpr::Const { value: 0 }))
            {
                return None;
            }
            push_base_factors(first, out);
            Some(())
        }
        // A negated product is zero exactly when the product is zero.
        ExtExpr::Neg { inner } => push_ext_factors(inner, out),
        _ => None,
    }
}

/// Remove negations. A product is zero regardless of the sign of a factor.
fn strip_neg(expression: &BaseExpr) -> &BaseExpr {
    match expression {
        BaseExpr::Neg { inner } => strip_neg(inner),
        other => other,
    }
}

fn push_base_factors<'a>(expression: &'a BaseExpr, out: &mut Vec<&'a BaseExpr>) {
    match expression {
        BaseExpr::Mul { lhs, rhs } => {
            push_base_factors(lhs, out);
            push_base_factors(rhs, out);
        }
        other => out.push(other),
    }
}

/// Evaluate a base expression at one row using preprocessed concrete values.
///
/// Returns `None` when the expression depends on anything not fixed by the
/// artifact — a witness column, a parameter, an inverse, or a preprocessed
/// column without values — so the caller cannot treat it as a guard.
fn evaluate_base_at_row(
    expression: &BaseExpr,
    prep: &BTreeMap<&str, &PreprocessedColumn>,
    row: u64,
    physical_length: u64,
) -> Option<u64> {
    match expression {
        BaseExpr::Const { value } => Some(u64::from(*value) % P),
        BaseExpr::Column { id, offset } => {
            let column = prep.get(id.as_str())?;
            let values = column.values.as_ref()?;
            // Offsets wrap on the evaluation domain.
            let len = u64::try_from(values.len()).ok()?;
            if len == 0 || len != physical_length {
                return None;
            }
            let shifted = (row as i128 + i128::from(*offset)).rem_euclid(i128::from(len));
            let index = usize::try_from(shifted).ok()?;
            values.get(index).map(|value| u64::from(*value) % P)
        }
        BaseExpr::Add { lhs, rhs } => {
            let lhs = evaluate_base_at_row(lhs, prep, row, physical_length)?;
            let rhs = evaluate_base_at_row(rhs, prep, row, physical_length)?;
            Some((lhs + rhs) % P)
        }
        BaseExpr::Mul { lhs, rhs } => {
            let lhs = evaluate_base_at_row(lhs, prep, row, physical_length)?;
            let rhs = evaluate_base_at_row(rhs, prep, row, physical_length)?;
            Some((lhs * rhs) % P)
        }
        BaseExpr::Neg { inner } => {
            let inner = evaluate_base_at_row(inner, prep, row, physical_length)?;
            Some((P - inner) % P)
        }
        // Parameters are challenge-dependent and inverses are partial; neither can
        // establish a per-row nonzero guard from the artifact alone.
        BaseExpr::Param { .. } | BaseExpr::Inv { .. } => None,
    }
}

fn collect_columns(expression: &BaseExpr, out: &mut Vec<String>) {
    match expression {
        BaseExpr::Column { id, .. } => out.push(id.clone()),
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_columns(lhs, out);
            collect_columns(rhs, out);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => collect_columns(inner, out),
        BaseExpr::Const { .. } | BaseExpr::Param { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_work_budget_is_global_and_fails_closed() {
        let mut remaining = MAX_CONFINEMENT_EVALUATION_STEPS;
        assert!(reserve_evaluation_work(&mut remaining, 1, 1 << 23));
        assert!(reserve_evaluation_work(&mut remaining, 1, 1 << 23));
        assert_eq!(remaining, 0);
        assert!(!reserve_evaluation_work(&mut remaining, 1, 1));
        assert!(!reserve_evaluation_work(&mut remaining, u64::MAX, 2));
    }
}
