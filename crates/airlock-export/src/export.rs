//! Turn an evaluated [`AuditEvaluator`] into an AuditIR component.

use airlock_ir::{
    AuditManifest, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest, ConstraintDecl,
    RelationEntry, RowSupport, SemanticType,
};
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, PREPROCESSED_TRACE_IDX};

use crate::annotations::ExportAnnotations;
use crate::convert::{convert_base, convert_ext, multiplicity_as_base};
use crate::evaluator::AuditEvaluator;
use crate::AIRLOCK_EXPORT_VERSION;

/// Pinned sibling Stwo commit required by this exporter.
pub const STWO_PIN_COMMIT: &str = "41ba5a322c10841bbd50c36515b89fb8b29222d8";

/// Export failures.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// InfoEvaluator / AuditEvaluator structural mismatch.
    #[error("exporter faithfulness check failed: {0}")]
    Faithfulness(String),
    /// Missing required semantic annotation.
    #[error("missing export annotation: {0}")]
    MissingAnnotation(String),
}

/// Export a `FrameworkEval` component into AuditIR, merging semantic annotations.
pub fn export_component<E: FrameworkEval>(
    eval: &E,
    annotations: ExportAnnotations,
) -> Result<AuditManifest, ExportError> {
    let auditor = eval.evaluate(AuditEvaluator::new());
    let info = eval.evaluate(InfoEvaluator::empty());

    if auditor.constraints.len() != info.n_constraints {
        return Err(ExportError::Faithfulness(format!(
            "constraint count mismatch: audit={} info={}",
            auditor.constraints.len(),
            info.n_constraints
        )));
    }
    let audit_prep: Vec<_> = auditor
        .preprocessed_columns
        .iter()
        .map(|c| c.id.clone())
        .collect();
    let info_prep: Vec<_> = info
        .preprocessed_columns
        .iter()
        .map(|c| c.id.clone())
        .collect();
    if audit_prep != info_prep {
        return Err(ExportError::Faithfulness(format!(
            "preprocessed id order mismatch: audit={audit_prep:?} info={info_prep:?}"
        )));
    }
    if !auditor.relations.is_empty() && !auditor.logup_finalized {
        return Err(ExportError::Faithfulness(
            "relations recorded but LogUp was not finalized".into(),
        ));
    }

    let component = build_component(&auditor, eval, annotations)?;
    let mut manifest = AuditManifest::new(AIRLOCK_EXPORT_VERSION, vec![component]);
    manifest.stwo_commit = Some(STWO_PIN_COMMIT.to_string());
    Ok(manifest)
}

fn build_component<E: FrameworkEval>(
    auditor: &AuditEvaluator,
    eval: &E,
    annotations: ExportAnnotations,
) -> Result<ComponentManifest, ExportError> {
    let log_size = eval.log_size();
    let domain_size = 1u64 << log_size;

    let mut columns: Vec<ColumnDecl> = Vec::new();

    for prep in &auditor.preprocessed_columns {
        let attachment = annotations.preprocessed.get(&prep.id).ok_or_else(|| {
            ExportError::MissingAnnotation(format!("preprocessed column `{}`", prep.id))
        })?;
        columns.push(ColumnDecl {
            id: prep.id.clone(),
            name: prep.id.clone(),
            interaction: Some(PREPROCESSED_TRACE_IDX as u32),
            commitment_phase: CommitmentPhase::Phase0Public,
            offsets: vec![0],
            kind: ColumnKind::Preprocessed,
            semantic_type: attachment.semantic_type.clone(),
            declared_range: None,
            declared_support: Some(RowSupport::Range {
                start: 0,
                end: attachment.semantic_length,
            }),
        });
    }

    for raw in &auditor.relations {
        for value in &raw.values {
            push_column_from_expr(&mut columns, value, &annotations);
        }
        let mult = multiplicity_as_base(&raw.multiplicity);
        push_column_from_ir(&mut columns, &mult, &annotations);
    }

    let constraints = auditor
        .constraints
        .iter()
        .enumerate()
        .map(|(index, expr)| ConstraintDecl {
            id: format!("constraint_{index}"),
            expression: convert_ext(expr),
            row_support: RowSupport::All,
            source_location: Some(format!("{}::constraint_{index}", annotations.component_name)),
            semantic_claim: None,
        })
        .collect();

    let mut relations = Vec::new();
    for raw in &auditor.relations {
        let ann = annotations
            .relations
            .get(&raw.relation_name)
            .cloned()
            .unwrap_or_default();
        relations.push(RelationEntry {
            relation: raw.relation_name.clone(),
            role: ann.role,
            tuple: raw.values.iter().map(convert_base).collect(),
            multiplicity: multiplicity_as_base(&raw.multiplicity),
            row_support: ann.row_support,
            challenge_phase: ann.challenge_phase,
            source_location: Some(raw.source.clone()),
        });
    }

    let preprocessed = annotations
        .preprocessed
        .iter()
        .map(|(id, attachment)| attachment.to_ir(id.clone()))
        .collect();

    Ok(ComponentManifest {
        name: annotations.component_name,
        log_size,
        domain_size,
        columns,
        constraints,
        relations,
        preprocessed,
        declared_max_constraint_log_degree_bound: Some(eval.max_constraint_log_degree_bound()),
        contract: annotations.contract,
        logup_finalized: auditor.logup_finalized,
    })
}

fn push_column_from_expr(
    columns: &mut Vec<ColumnDecl>,
    expr: &stwo_constraint_framework::expr::BaseExpr,
    annotations: &ExportAnnotations,
) {
    push_column_from_ir(columns, &convert_base(expr), annotations);
}

fn push_column_from_ir(
    columns: &mut Vec<ColumnDecl>,
    expr: &airlock_ir::BaseExpr,
    annotations: &ExportAnnotations,
) {
    let airlock_ir::BaseExpr::Column { id, offset } = expr else {
        return;
    };
    if columns.iter().any(|c| c.id == *id) {
        return;
    }
    let semantic = annotations
        .column_semantics
        .get(id)
        .cloned()
        .unwrap_or(SemanticType::Unknown);
    columns.push(ColumnDecl {
        id: id.clone(),
        name: id.clone(),
        interaction: None,
        commitment_phase: annotations.witness_phase,
        offsets: vec![*offset],
        kind: ColumnKind::Witness,
        semantic_type: semantic,
        declared_range: None,
        declared_support: None,
    });
}
