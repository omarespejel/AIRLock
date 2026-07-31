//! Conservative algebraic degree bounds for AuditIR constraint expressions.
//!
//! Stwo components declare `max_constraint_log_degree_bound`, the log-size of the
//! domain the composition polynomial needs. This module independently derives a
//! structural upper bound from the exported expression and fails closed when the
//! expression is non-polynomial, exceeds the analysis budget, or overflows.

use airlock_ir::{BaseExpr, ComponentManifest, ExtExpr, Finding, FindingCode, Severity};

const MAX_DEGREE_EXPRESSION_DEPTH: usize = 128;
const MAX_DEGREE_EXPRESSION_NODES: usize = 1 << 16;

/// Result of deriving a structural polynomial-degree upper bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegreeAnalysis {
    /// Conservative upper bound in the trace variables.
    Polynomial(u32),
    /// An inverse depends on a non-constant trace expression.
    NonPolynomial,
    /// Degree arithmetic exceeded `u32`.
    ArithmeticOverflow,
    /// The hostile expression exceeded the local analysis budget.
    ComplexityLimitExceeded,
}

#[derive(Default)]
struct AnalysisBudget {
    nodes: usize,
}

impl AnalysisBudget {
    fn enter(&mut self, depth: usize) -> Result<(), DegreeAnalysis> {
        self.nodes += 1;
        if depth > MAX_DEGREE_EXPRESSION_DEPTH || self.nodes > MAX_DEGREE_EXPRESSION_NODES {
            Err(DegreeAnalysis::ComplexityLimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Structural degree upper bound for a base-field expression.
pub fn base_degree(expression: &BaseExpr) -> DegreeAnalysis {
    base_degree_inner(expression, &mut AnalysisBudget::default(), 1)
}

fn base_degree_inner(
    expression: &BaseExpr,
    budget: &mut AnalysisBudget,
    depth: usize,
) -> DegreeAnalysis {
    if let Err(result) = budget.enter(depth) {
        return result;
    }
    match expression {
        BaseExpr::Param { .. } | BaseExpr::Const { .. } => DegreeAnalysis::Polynomial(0),
        BaseExpr::Column { .. } => DegreeAnalysis::Polynomial(1),
        BaseExpr::Add { lhs, rhs } => combine_max(
            base_degree_inner(lhs, budget, depth + 1),
            base_degree_inner(rhs, budget, depth + 1),
        ),
        BaseExpr::Mul { lhs, rhs } => combine_product(
            base_degree_inner(lhs, budget, depth + 1),
            base_degree_inner(rhs, budget, depth + 1),
        ),
        BaseExpr::Neg { inner } => base_degree_inner(inner, budget, depth + 1),
        BaseExpr::Inv { inner } => match base_degree_inner(inner, budget, depth + 1) {
            DegreeAnalysis::Polynomial(0) => DegreeAnalysis::Polynomial(0),
            DegreeAnalysis::Polynomial(_) | DegreeAnalysis::NonPolynomial => {
                DegreeAnalysis::NonPolynomial
            }
            result => result,
        },
    }
}

/// Structural degree upper bound for an extension-field expression.
pub fn ext_degree(expression: &ExtExpr) -> DegreeAnalysis {
    ext_degree_inner(expression, &mut AnalysisBudget::default(), 1)
}

fn ext_degree_inner(
    expression: &ExtExpr,
    budget: &mut AnalysisBudget,
    depth: usize,
) -> DegreeAnalysis {
    if let Err(result) = budget.enter(depth) {
        return result;
    }
    match expression {
        ExtExpr::Param { .. } | ExtExpr::Const { .. } => DegreeAnalysis::Polynomial(0),
        ExtExpr::FromBase { inner } => base_degree_inner(inner, budget, depth + 1),
        ExtExpr::SecureCol { parts } => {
            parts
                .iter()
                .fold(DegreeAnalysis::Polynomial(0), |accumulator, part| {
                    combine_max(accumulator, base_degree_inner(part, budget, depth + 1))
                })
        }
        ExtExpr::Add { lhs, rhs } => combine_max(
            ext_degree_inner(lhs, budget, depth + 1),
            ext_degree_inner(rhs, budget, depth + 1),
        ),
        ExtExpr::Mul { lhs, rhs } => combine_product(
            ext_degree_inner(lhs, budget, depth + 1),
            ext_degree_inner(rhs, budget, depth + 1),
        ),
        ExtExpr::Neg { inner } => ext_degree_inner(inner, budget, depth + 1),
    }
}

fn combine_max(lhs: DegreeAnalysis, rhs: DegreeAnalysis) -> DegreeAnalysis {
    match (lhs, rhs) {
        (DegreeAnalysis::ComplexityLimitExceeded, _)
        | (_, DegreeAnalysis::ComplexityLimitExceeded) => DegreeAnalysis::ComplexityLimitExceeded,
        (DegreeAnalysis::ArithmeticOverflow, _) | (_, DegreeAnalysis::ArithmeticOverflow) => {
            DegreeAnalysis::ArithmeticOverflow
        }
        (DegreeAnalysis::NonPolynomial, _) | (_, DegreeAnalysis::NonPolynomial) => {
            DegreeAnalysis::NonPolynomial
        }
        (DegreeAnalysis::Polynomial(lhs), DegreeAnalysis::Polynomial(rhs)) => {
            DegreeAnalysis::Polynomial(lhs.max(rhs))
        }
    }
}

fn combine_product(lhs: DegreeAnalysis, rhs: DegreeAnalysis) -> DegreeAnalysis {
    match (lhs, rhs) {
        (DegreeAnalysis::Polynomial(lhs), DegreeAnalysis::Polynomial(rhs)) => {
            lhs.checked_add(rhs).map_or(
                DegreeAnalysis::ArithmeticOverflow,
                DegreeAnalysis::Polynomial,
            )
        }
        (lhs, rhs) => combine_max(lhs, rhs),
    }
}

/// Conservative log-degree bound for a degree bound over `2^log_size` rows.
///
/// Returns `None` when adding `ceil(log2(degree))` would overflow.
pub fn required_log_degree_bound(log_size: u32, degree: u32) -> Option<u32> {
    let extra = match degree {
        0 | 1 => 0,
        d => u32::BITS - (d - 1).leading_zeros(),
    };
    log_size.checked_add(extra)
}

/// Flag a declared log-degree bound below the structural upper bound.
pub fn lint_declared_degree_bound(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let declared = component.declared_max_constraint_log_degree_bound;
    if declared.is_none() && !component.constraints.is_empty() {
        findings.push(Finding {
            code: FindingCode::MissingDeclaredDegreeBound,
            severity: Severity::High,
            component: Some(component.name.clone()),
            message: format!(
                "component declares no max constraint log-degree bound, so its {} constraint(s) cannot be checked against a declaration",
                component.constraints.len()
            ),
            related: vec![component.name.clone()],
        });
    }

    let mut worst: Option<(u32, &str)> = None;
    for constraint in &component.constraints {
        match ext_degree(&constraint.expression) {
            DegreeAnalysis::Polynomial(degree) => {
                if worst.is_none_or(|(current, _)| degree > current) {
                    worst = Some((degree, constraint.id.as_str()));
                }
            }
            DegreeAnalysis::NonPolynomial => findings.push(Finding {
                code: FindingCode::NonPolynomialConstraint,
                severity: Severity::High,
                component: Some(component.name.clone()),
                message: format!(
                    "constraint `{}` contains an inverse depending on a trace expression, so no finite polynomial degree bound can admit it",
                    constraint.id
                ),
                related: vec![constraint.id.clone()],
            }),
            DegreeAnalysis::ArithmeticOverflow => findings.push(incomplete_finding(
                component,
                constraint.id.as_str(),
                "degree arithmetic overflowed",
            )),
            DegreeAnalysis::ComplexityLimitExceeded => findings.push(incomplete_finding(
                component,
                constraint.id.as_str(),
                "expression exceeded the degree-analysis depth or node limit",
            )),
        }
    }

    if let (Some(declared), Some((degree, constraint_id))) = (declared, worst) {
        match required_log_degree_bound(component.log_size, degree) {
            Some(required) if declared < required => findings.push(Finding {
                code: FindingCode::DeclaredDegreeUnderreport,
                severity: Severity::High,
                component: Some(component.name.clone()),
                message: format!(
                    "declared max constraint log-degree bound {declared} is below the {required} required by constraint `{constraint_id}` with structural degree bound {degree} over a 2^{} row trace",
                    component.log_size
                ),
                related: vec![constraint_id.to_owned()],
            }),
            Some(_) => {}
            None => findings.push(incomplete_finding(
                component,
                constraint_id,
                "required log-degree bound overflowed",
            )),
        }
    }
    findings
}

fn incomplete_finding(component: &ComponentManifest, constraint_id: &str, reason: &str) -> Finding {
    Finding {
        code: FindingCode::DegreeAnalysisIncomplete,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: format!("constraint `{constraint_id}` could not be degree-checked: {reason}"),
        related: vec![constraint_id.to_owned()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_bound_matches_ceil_log2() {
        assert_eq!(required_log_degree_bound(5, 0), Some(5));
        assert_eq!(required_log_degree_bound(5, 1), Some(5));
        assert_eq!(required_log_degree_bound(5, 2), Some(6));
        assert_eq!(required_log_degree_bound(5, 3), Some(7));
        assert_eq!(required_log_degree_bound(5, 4), Some(7));
        assert_eq!(required_log_degree_bound(5, 5), Some(8));
        assert_eq!(required_log_degree_bound(5, 8), Some(8));
        assert_eq!(required_log_degree_bound(5, 9), Some(9));
        assert_eq!(required_log_degree_bound(u32::MAX, 2), None);
    }

    #[test]
    fn degree_is_a_structural_upper_bound_for_modeled_operators() {
        let col = BaseExpr::column("a");
        assert_eq!(base_degree(&col), DegreeAnalysis::Polynomial(1));
        assert_eq!(
            base_degree(&BaseExpr::constant(7)),
            DegreeAnalysis::Polynomial(0)
        );
        assert_eq!(
            base_degree(&BaseExpr::param("z")),
            DegreeAnalysis::Polynomial(0)
        );

        let square = BaseExpr::Mul {
            lhs: Box::new(col.clone()),
            rhs: Box::new(col.clone()),
        };
        assert_eq!(base_degree(&square), DegreeAnalysis::Polynomial(2));
        assert_eq!(
            base_degree(&BaseExpr::Add {
                lhs: Box::new(square.clone()),
                rhs: Box::new(col.clone()),
            }),
            DegreeAnalysis::Polynomial(2)
        );
        assert_eq!(
            base_degree(&BaseExpr::Add {
                lhs: Box::new(col.clone()),
                rhs: Box::new(BaseExpr::Neg {
                    inner: Box::new(col.clone()),
                }),
            }),
            DegreeAnalysis::Polynomial(1),
            "syntactic cancellation is deliberately not normalized"
        );
        assert_eq!(
            base_degree(&BaseExpr::Inv {
                inner: Box::new(BaseExpr::constant(3)),
            }),
            DegreeAnalysis::Polynomial(0)
        );
        assert_eq!(
            base_degree(&BaseExpr::Inv {
                inner: Box::new(col),
            }),
            DegreeAnalysis::NonPolynomial
        );
    }

    #[test]
    fn degree_is_invariant_under_identifier_renaming() {
        let build = |name: &str| BaseExpr::Mul {
            lhs: Box::new(BaseExpr::column(name)),
            rhs: Box::new(BaseExpr::Add {
                lhs: Box::new(BaseExpr::column(name)),
                rhs: Box::new(BaseExpr::constant(1)),
            }),
        };
        assert_eq!(base_degree(&build("a")), base_degree(&build("renamed")));
    }

    #[test]
    fn secure_column_uses_largest_coordinate_bound() {
        let expr = ExtExpr::SecureCol {
            parts: [
                BaseExpr::constant(0),
                BaseExpr::Mul {
                    lhs: Box::new(BaseExpr::column("a")),
                    rhs: Box::new(BaseExpr::column("b")),
                },
                BaseExpr::column("c"),
                BaseExpr::constant(1),
            ],
        };
        assert_eq!(ext_degree(&expr), DegreeAnalysis::Polynomial(2));
    }

    #[test]
    fn oversized_expression_fails_closed() {
        let mut expression = BaseExpr::constant(1);
        for _ in 0..=MAX_DEGREE_EXPRESSION_DEPTH {
            expression = BaseExpr::Neg {
                inner: Box::new(expression),
            };
        }
        assert_eq!(
            base_degree(&expression),
            DegreeAnalysis::ComplexityLimitExceeded
        );
    }
}
