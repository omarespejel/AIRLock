//! Turn an evaluated [`AuditEvaluator`] into an AuditIR component.

use std::collections::HashSet;

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    ConstraintDecl, ExtExpr, RelationEntry, RowSupport, SemanticType,
};
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, PREPROCESSED_TRACE_IDX};

use crate::annotations::ExportAnnotations;
use crate::convert::{convert_base, convert_ext, multiplicity_as_base, ConvertError};
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
    /// Lossy or malformed Stwo→AuditIR conversion.
    #[error("export conversion failed: {0}")]
    Conversion(#[from] ConvertError),
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
    let preprocessed_ids: HashSet<String> = auditor
        .preprocessed_columns
        .iter()
        .map(|c| c.id.clone())
        .collect();

    let mut columns: Vec<ColumnDecl> = Vec::new();

    for prep in &auditor.preprocessed_columns {
        if columns.iter().any(|c| c.id == prep.id) {
            continue;
        }
        let attachment = annotations.preprocessed.get(&prep.id).ok_or_else(|| {
            ExportError::MissingAnnotation(format!("preprocessed column `{}`", prep.id))
        })?;
        if attachment.values.is_none() && attachment.generator_id.is_none() {
            return Err(ExportError::MissingAnnotation(format!(
                "preprocessed column `{}` lacks values or generator_id",
                prep.id
            )));
        }
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
            let ir = convert_base(value, &preprocessed_ids)?;
            collect_columns_from_base(&mut columns, &ir, &annotations);
        }
        let mult = multiplicity_as_base(&raw.multiplicity, &preprocessed_ids)?;
        collect_columns_from_base(&mut columns, &mult, &annotations);
    }

    let mut constraints = Vec::with_capacity(auditor.constraints.len());
    for (index, expr) in auditor.constraints.iter().enumerate() {
        let expression = convert_ext(expr, &preprocessed_ids)?;
        collect_columns_from_ext(&mut columns, &expression, &annotations);
        constraints.push(ConstraintDecl {
            id: format!("constraint_{index}"),
            expression,
            row_support: RowSupport::All,
            source_location: Some(format!("{}::constraint_{index}", annotations.component_name)),
            semantic_claim: None,
        });
    }

    let mut relations = Vec::new();
    for raw in &auditor.relations {
        let ann = annotations.relations.get(&raw.relation_name).ok_or_else(|| {
            ExportError::MissingAnnotation(format!("relation `{}`", raw.relation_name))
        })?;
        let mut tuple = Vec::with_capacity(raw.values.len());
        for value in &raw.values {
            tuple.push(convert_base(value, &preprocessed_ids)?);
        }
        relations.push(RelationEntry {
            relation: raw.relation_name.clone(),
            role: ann.role,
            tuple,
            multiplicity: multiplicity_as_base(&raw.multiplicity, &preprocessed_ids)?,
            row_support: ann.row_support.clone(),
            challenge_phase: ann.challenge_phase,
            source_location: Some(raw.source.clone()),
        });
    }

    let mut preprocessed = Vec::new();
    for (id, attachment) in &annotations.preprocessed {
        if attachment.values.is_none() && attachment.generator_id.is_none() {
            return Err(ExportError::MissingAnnotation(format!(
                "preprocessed column `{id}` lacks values or generator_id"
            )));
        }
        preprocessed.push(attachment.to_ir(id.clone()));
    }

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

fn collect_columns_from_base(
    columns: &mut Vec<ColumnDecl>,
    expr: &BaseExpr,
    annotations: &ExportAnnotations,
) {
    match expr {
        BaseExpr::Column { id, offset } => {
            push_or_merge_column(columns, id, *offset, annotations);
        }
        BaseExpr::Param { .. } | BaseExpr::Const { .. } => {}
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_columns_from_base(columns, lhs, annotations);
            collect_columns_from_base(columns, rhs, annotations);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => {
            collect_columns_from_base(columns, inner, annotations);
        }
    }
}

fn collect_columns_from_ext(
    columns: &mut Vec<ColumnDecl>,
    expr: &ExtExpr,
    annotations: &ExportAnnotations,
) {
    match expr {
        ExtExpr::Param { .. } | ExtExpr::Const { .. } => {}
        ExtExpr::FromBase { inner } => collect_columns_from_base(columns, inner, annotations),
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                collect_columns_from_base(columns, part, annotations);
            }
        }
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            collect_columns_from_ext(columns, lhs, annotations);
            collect_columns_from_ext(columns, rhs, annotations);
        }
        ExtExpr::Neg { inner } => collect_columns_from_ext(columns, inner, annotations),
    }
}

fn push_or_merge_column(
    columns: &mut Vec<ColumnDecl>,
    id: &str,
    offset: i32,
    annotations: &ExportAnnotations,
) {
    if let Some(existing) = columns.iter_mut().find(|c| c.id == id) {
        if !existing.offsets.contains(&offset) {
            existing.offsets.push(offset);
        }
        return;
    }
    let semantic = annotations
        .column_semantics
        .get(id)
        .cloned()
        .unwrap_or(SemanticType::Unknown);
    columns.push(ColumnDecl {
        id: id.to_string(),
        name: id.to_string(),
        interaction: None,
        commitment_phase: annotations.witness_phase,
        offsets: vec![offset],
        kind: ColumnKind::Witness,
        semantic_type: semantic,
        declared_range: None,
        declared_support: None,
    });
}
