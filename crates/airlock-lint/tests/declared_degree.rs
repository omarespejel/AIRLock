//! Adversarial regressions for the declared constraint log-degree bound.
//!
//! `declared_max_constraint_log_degree_bound` was exported and never checked
//! against the exported expressions, so a component could understate it and pass
//! the static gate. These tests pin both directions: understatement is blocked,
//! and over-declaration is not a finding because a larger bound is sound.

use airlock_ir::{
    BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest, ConstraintDecl, ExtExpr,
    FindingCode, RowSupport, SemanticContract, SemanticType, Severity,
};
use airlock_lint::{LintOptions, lint_component};

const LOG_SIZE: u32 = 5;

/// Component over a 32-row trace with one constraint of the requested degree.
///
/// Degree is built as a product of `degree` distinct column reads.
fn component_with_degree(
    declared_bound: u32,
    degree: u32,
    divide_by_column: bool,
) -> ComponentManifest {
    let ids: Vec<String> = (0..degree.max(1)).map(|i| format!("c{i}")).collect();

    let mut product = BaseExpr::constant(1);
    for id in &ids {
        product = BaseExpr::Mul {
            lhs: Box::new(product),
            rhs: Box::new(BaseExpr::column(id)),
        };
    }
    if divide_by_column {
        product = BaseExpr::Mul {
            lhs: Box::new(product),
            rhs: Box::new(BaseExpr::Inv {
                inner: Box::new(BaseExpr::column(&ids[0])),
            }),
        };
    }

    ComponentManifest {
        name: "degree-fixture".into(),
        log_size: LOG_SIZE,
        domain_size: 1 << LOG_SIZE,
        columns: ids
            .iter()
            .map(|id| ColumnDecl {
                id: id.clone(),
                name: id.clone(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase1Original,
                offsets: vec![0],
                kind: ColumnKind::Witness,
                semantic_type: SemanticType::Unknown,
                declared_range: None,
                declared_support: None,
            })
            .collect(),
        parameters: vec![],
        constraints: vec![ConstraintDecl {
            id: "product".into(),
            expression: ExtExpr::FromBase { inner: product },
            row_support: RowSupport::All,
            source_location: None,
            semantic_claim: None,
        }],
        relations: vec![],
        preprocessed: vec![],
        declared_max_constraint_log_degree_bound: Some(declared_bound),
        contract: SemanticContract::default(),
        logup_finalized: true,
    }
}

fn underreports(findings: &[airlock_ir::Finding]) -> bool {
    findings.iter().any(|finding| {
        finding.code == FindingCode::DeclaredDegreeUnderreport && finding.severity == Severity::High
    })
}

fn has_code(findings: &[airlock_ir::Finding], code: FindingCode) -> bool {
    findings
        .iter()
        .any(|finding| finding.code == code && finding.severity == Severity::High)
}

/// A degree-3 constraint needs `log_size + 2`; declaring `log_size + 1` is an
/// understatement and must block.
#[test]
fn understated_degree_bound_is_blocked() {
    let findings = lint_component(
        &component_with_degree(LOG_SIZE + 1, 3, false),
        &LintOptions::default(),
    );
    assert!(
        underreports(&findings),
        "a degree-3 constraint under a {}-bound must be reported: {findings:?}",
        LOG_SIZE + 1
    );
}

/// The required bound is sound and must stay silent, so the lint cannot be satisfied
/// by simply always firing.
#[test]
fn required_degree_bound_is_accepted() {
    let findings = lint_component(
        &component_with_degree(LOG_SIZE + 1, 2, false),
        &LintOptions::default(),
    );
    assert!(
        !underreports(&findings),
        "the required bound must not be reported: {findings:?}"
    );
}

/// Stwo components routinely declare more headroom than they need. A larger bound
/// is sound and must not be a finding.
#[test]
fn over_declared_degree_bound_is_not_a_finding() {
    let findings = lint_component(
        &component_with_degree(LOG_SIZE + 4, 2, false),
        &LintOptions::default(),
    );
    assert!(
        !underreports(&findings),
        "over-declaration is sound and must not be reported: {findings:?}"
    );
}

/// Dividing by a column yields a rational function, which no bound can admit.
#[test]
fn undefined_degree_is_blocked_at_every_bound() {
    for bound in [LOG_SIZE, LOG_SIZE + 1, LOG_SIZE + 16] {
        let findings = lint_component(
            &component_with_degree(bound, 2, true),
            &LintOptions::default(),
        );
        assert!(
            has_code(&findings, FindingCode::NonPolynomialConstraint),
            "a non-polynomial constraint must be reported at bound {bound}: {findings:?}"
        );
    }
}

/// Degree must depend on structure, not on identifier spelling, so the lint
/// cannot be evaded by renaming columns.
#[test]
fn degree_verdict_is_invariant_under_renaming() {
    let mut component = component_with_degree(LOG_SIZE + 1, 3, false);
    let before = underreports(&lint_component(&component, &LintOptions::default()));

    for column in &mut component.columns {
        column.id = format!("renamed_{}", column.id);
        column.name = column.id.clone();
    }
    // Rebuild the same product over the renamed columns.
    let mut product = BaseExpr::constant(1);
    for column in &component.columns {
        product = BaseExpr::Mul {
            lhs: Box::new(product),
            rhs: Box::new(BaseExpr::column(&column.id)),
        };
    }
    component.constraints[0].expression = ExtExpr::FromBase { inner: product };

    let after = underreports(&lint_component(&component, &LintOptions::default()));
    assert_eq!(before, after, "renaming must not change the degree verdict");
}

/// A missing declared bound leaves the degree analysis unrun. Reporting nothing
/// would turn absent analysis into a passing gate, which AGENTS.md review rule 1
/// forbids.
#[test]
fn missing_declared_bound_is_reported_when_constraints_exist() {
    let mut component = component_with_degree(LOG_SIZE + 1, 2, false);
    component.declared_max_constraint_log_degree_bound = None;

    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        has_code(&findings, FindingCode::MissingDeclaredDegreeBound),
        "a constrained component with no declared bound must not pass silently"
    );
    assert!(
        findings.iter().any(|f| f
            .message
            .contains("declares no max constraint log-degree bound")),
        "expected the missing-bound finding: {findings:?}"
    );
}

#[test]
fn missing_bound_does_not_hide_non_polynomial_constraints() {
    let mut component = component_with_degree(LOG_SIZE + 1, 2, true);
    component.declared_max_constraint_log_degree_bound = None;

    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        has_code(&findings, FindingCode::MissingDeclaredDegreeBound),
        "the missing declaration must be reported: {findings:?}"
    );
    assert!(
        has_code(&findings, FindingCode::NonPolynomialConstraint),
        "analysis must continue after the missing-declaration finding: {findings:?}"
    );
}

#[test]
fn required_bound_overflow_is_blocked_without_panicking() {
    let mut component = component_with_degree(u32::MAX, 2, false);
    component.log_size = u32::MAX;

    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        has_code(&findings, FindingCode::DegreeAnalysisIncomplete),
        "overflow must produce a structured blocking finding: {findings:?}"
    );
}

/// A component with no constraints has nothing to bound, so silence is correct.
#[test]
fn missing_declared_bound_is_silent_without_constraints() {
    let mut component = component_with_degree(LOG_SIZE + 1, 2, false);
    component.declared_max_constraint_log_degree_bound = None;
    component.constraints.clear();

    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        !findings.iter().any(|f| f
            .message
            .contains("declares no max constraint log-degree bound")),
        "an unconstrained component needs no bound: {findings:?}"
    );
}
