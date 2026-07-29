//! Turn an evaluated [`AuditEvaluator`] into an AuditIR component.

use std::any::Any;
use std::collections::{BTreeMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    ConstraintDecl, ExtExpr, FieldSort, ParameterDecl, ParameterRole, RelationEntry, RowSupport,
    SemanticType,
};
use stwo::core::poly::circle::MAX_CIRCLE_DOMAIN_LOG_SIZE;
use stwo_constraint_framework::{
    FrameworkEval, INTERACTION_TRACE_IDX, InfoEvaluator, PREPROCESSED_TRACE_IDX,
};

use crate::AIRLOCK_EXPORT_VERSION;
use crate::annotations::ExportAnnotations;
use crate::convert::{ConvertError, convert_base, convert_ext, multiplicity_as_base};
use crate::evaluator::AuditEvaluator;

/// Upstream Stwo source baseline required by the checked accessor patch.
///
/// This is a build policy pin, not observed runtime provenance. Exported
/// manifests leave `stwo_commit` unset unless a caller independently verifies
/// and attaches the checkout identity.
pub const REQUIRED_STWO_BASE_COMMIT: &str = "f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a";

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
    let auditor = catch_unwind(AssertUnwindSafe(|| {
        eval.evaluate(AuditEvaluator::new(eval.log_size()))
    }))
    .map_err(|payload| {
        ExportError::Faithfulness(format!(
            "AuditEvaluator panicked: {}",
            panic_message(payload.as_ref())
        ))
    })?;

    if !auditor.structural_errors.is_empty() {
        return Err(ExportError::Faithfulness(format!(
            "AuditEvaluator structural errors: {}",
            auditor.structural_errors.join("; ")
        )));
    }
    let info = catch_unwind(AssertUnwindSafe(|| eval.evaluate(InfoEvaluator::empty()))).map_err(
        |payload| {
            ExportError::Faithfulness(format!(
                "InfoEvaluator panicked: {}",
                panic_message(payload.as_ref())
            ))
        },
    )?;
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
    Ok(AuditManifest::new(AIRLOCK_EXPORT_VERSION, vec![component]))
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

fn build_component<E: FrameworkEval>(
    auditor: &AuditEvaluator,
    eval: &E,
    annotations: ExportAnnotations,
) -> Result<ComponentManifest, ExportError> {
    let log_size = eval.log_size();
    if log_size > MAX_CIRCLE_DOMAIN_LOG_SIZE {
        return Err(ExportError::Faithfulness(format!(
            "log_size {log_size} exceeds Stwo's maximum Circle domain log size {MAX_CIRCLE_DOMAIN_LOG_SIZE}"
        )));
    }
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
        validate_preprocessed_attachment(&prep.id, attachment, domain_size)?;
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
            source_location: Some(format!(
                "{}::constraint_{index}",
                annotations.component_name
            )),
            semantic_claim: None,
        });
    }

    let mut relations = Vec::new();
    for raw in &auditor.relations {
        let ann = annotations
            .relations
            .get(&raw.relation_name)
            .ok_or_else(|| {
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
    let mut emitted_prep = HashSet::new();
    for prep in &auditor.preprocessed_columns {
        if !emitted_prep.insert(prep.id.clone()) {
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
        validate_preprocessed_attachment(&prep.id, attachment, domain_size)?;
        preprocessed.push(attachment.to_ir(prep.id.clone()));
    }
    for id in annotations.preprocessed.keys() {
        if !emitted_prep.contains(id) {
            return Err(ExportError::MissingAnnotation(format!(
                "preprocessed annotation `{id}` was not observed by AuditEvaluator"
            )));
        }
    }

    let parameters = build_parameter_declarations(auditor, &constraints, &relations, &annotations)?;

    Ok(ComponentManifest {
        name: annotations.component_name,
        log_size,
        domain_size,
        columns,
        parameters,
        constraints,
        relations,
        preprocessed,
        declared_max_constraint_log_degree_bound: Some(eval.max_constraint_log_degree_bound()),
        contract: annotations.contract,
        logup_finalized: auditor.logup_finalized,
    })
}

fn build_parameter_declarations(
    auditor: &AuditEvaluator,
    constraints: &[ConstraintDecl],
    relations: &[RelationEntry],
    annotations: &ExportAnnotations,
) -> Result<Vec<ParameterDecl>, ExportError> {
    let mut declared = BTreeMap::<String, ParameterDecl>::new();

    if !auditor.relations.is_empty() {
        insert_parameter(
            &mut declared,
            ParameterDecl {
                name: "claimed_sum".into(),
                field: FieldSort::Qm31,
                role: ParameterRole::PublicClaim,
                available_after: CommitmentPhase::Phase0Public,
            },
        )?;
    }

    for raw in &auditor.relations {
        let relation = annotations
            .relations
            .get(&raw.relation_name)
            .ok_or_else(|| {
                ExportError::MissingAnnotation(format!("relation `{}`", raw.relation_name))
            })?;
        insert_parameter(
            &mut declared,
            ParameterDecl {
                name: format!("{}_z", raw.relation_name),
                field: FieldSort::Qm31,
                role: ParameterRole::FiatShamirChallenge,
                available_after: relation.challenge_phase,
            },
        )?;
        if raw.values.len() > 1 {
            insert_parameter(
                &mut declared,
                ParameterDecl {
                    name: format!("{}_alpha", raw.relation_name),
                    field: FieldSort::Qm31,
                    role: ParameterRole::FiatShamirChallenge,
                    available_after: relation.challenge_phase,
                },
            )?;
        }
    }

    for (name, annotation) in &annotations.parameters {
        if declared.contains_key(name) {
            return Err(ExportError::MissingAnnotation(format!(
                "parameter `{name}` is derived automatically and must not be annotated twice"
            )));
        }
        insert_parameter(
            &mut declared,
            ParameterDecl {
                name: name.clone(),
                field: annotation.field,
                role: annotation.role,
                available_after: annotation.available_after,
            },
        )?;
    }

    let mut referenced = BTreeMap::<String, FieldSort>::new();
    for constraint in constraints {
        collect_ext_parameters(&constraint.expression, &mut referenced)?;
    }
    for relation in relations {
        for value in &relation.tuple {
            collect_base_parameters(value, &mut referenced)?;
        }
        collect_base_parameters(&relation.multiplicity, &mut referenced)?;
    }

    for (name, field) in &referenced {
        if is_generated_intermediate(name) {
            return Err(ExportError::Faithfulness(format!(
                "generated intermediate `{name}` escaped into AuditIR"
            )));
        }
        let Some(declaration) = declared.get(name) else {
            return Err(ExportError::MissingAnnotation(format!(
                "formal parameter `{name}` has no typed role and phase"
            )));
        };
        if declaration.field != *field {
            return Err(ExportError::Faithfulness(format!(
                "formal parameter `{name}` is referenced as {field:?} but declared as {:?}",
                declaration.field
            )));
        }
    }

    for name in declared.keys() {
        if !referenced.contains_key(name) {
            return Err(ExportError::MissingAnnotation(format!(
                "parameter declaration `{name}` is not referenced by the exported relation"
            )));
        }
    }

    Ok(declared.into_values().collect())
}

fn is_generated_intermediate(name: &str) -> bool {
    name.strip_prefix("intermediate").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn insert_parameter(
    parameters: &mut BTreeMap<String, ParameterDecl>,
    declaration: ParameterDecl,
) -> Result<(), ExportError> {
    if let Some(existing) = parameters.get(&declaration.name) {
        if existing != &declaration {
            return Err(ExportError::Faithfulness(format!(
                "conflicting declarations for parameter `{}`",
                declaration.name
            )));
        }
        return Ok(());
    }
    parameters.insert(declaration.name.clone(), declaration);
    Ok(())
}

fn collect_base_parameters(
    expr: &BaseExpr,
    parameters: &mut BTreeMap<String, FieldSort>,
) -> Result<(), ExportError> {
    match expr {
        BaseExpr::Param { name } => insert_parameter_sort(parameters, name, FieldSort::M31)?,
        BaseExpr::Const { .. } | BaseExpr::Column { .. } => {}
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_base_parameters(lhs, parameters)?;
            collect_base_parameters(rhs, parameters)?;
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => {
            collect_base_parameters(inner, parameters)?;
        }
    }
    Ok(())
}

fn collect_ext_parameters(
    expr: &ExtExpr,
    parameters: &mut BTreeMap<String, FieldSort>,
) -> Result<(), ExportError> {
    match expr {
        ExtExpr::Param { name } => insert_parameter_sort(parameters, name, FieldSort::Qm31)?,
        ExtExpr::Const { .. } => {}
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                collect_base_parameters(part, parameters)?;
            }
        }
        ExtExpr::FromBase { inner } => collect_base_parameters(inner, parameters)?,
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            collect_ext_parameters(lhs, parameters)?;
            collect_ext_parameters(rhs, parameters)?;
        }
        ExtExpr::Neg { inner } => collect_ext_parameters(inner, parameters)?,
    }
    Ok(())
}

fn insert_parameter_sort(
    parameters: &mut BTreeMap<String, FieldSort>,
    name: &str,
    field: FieldSort,
) -> Result<(), ExportError> {
    if let Some(existing) = parameters.insert(name.to_string(), field)
        && existing != field
    {
        return Err(ExportError::Faithfulness(format!(
            "formal parameter `{name}` is referenced in both {existing:?} and {field:?}"
        )));
    }
    Ok(())
}

fn validate_preprocessed_attachment(
    id: &str,
    attachment: &crate::annotations::PreprocessedAttachment,
    domain_size: u64,
) -> Result<(), ExportError> {
    if attachment.physical_length != domain_size {
        return Err(ExportError::MissingAnnotation(format!(
            "preprocessed column `{id}` physical_length {} does not match component domain_size {domain_size}",
            attachment.physical_length
        )));
    }
    if attachment.semantic_length > attachment.physical_length {
        return Err(ExportError::MissingAnnotation(format!(
            "preprocessed column `{id}` semantic_length {} exceeds physical_length {}",
            attachment.semantic_length, attachment.physical_length
        )));
    }
    if let Some(values) = &attachment.values
        && values.len() as u64 != attachment.physical_length
    {
        return Err(ExportError::MissingAnnotation(format!(
            "preprocessed column `{id}` values.len()={} != physical_length {}",
            values.len(),
            attachment.physical_length
        )));
    }
    if let Some(values) = &attachment.values
        && let Some(value) = values.iter().find(|value| **value >= airlock_ir::M31_P)
    {
        return Err(ExportError::MissingAnnotation(format!(
            "preprocessed column `{id}` contains noncanonical M31 value {value}"
        )));
    }
    Ok(())
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
    let (interaction, kind, commitment_phase) = classify_trace_column(id, annotations);
    columns.push(ColumnDecl {
        id: id.to_string(),
        name: id.to_string(),
        interaction,
        commitment_phase,
        offsets: vec![offset],
        kind,
        semantic_type: semantic,
        declared_range: None,
        declared_support: None,
    });
}

/// Map Stwo `trace_{interaction}_column_{j}` ids onto AuditIR kind/phase.
fn classify_trace_column(
    id: &str,
    annotations: &ExportAnnotations,
) -> (Option<u32>, ColumnKind, CommitmentPhase) {
    let interaction = id
        .strip_prefix("trace_")
        .and_then(|rest| rest.split("_column_").next())
        .and_then(|idx| idx.parse::<u32>().ok());
    match interaction {
        Some(idx) if idx == PREPROCESSED_TRACE_IDX as u32 => (
            Some(idx),
            ColumnKind::Preprocessed,
            CommitmentPhase::Phase0Public,
        ),
        Some(idx) if idx == INTERACTION_TRACE_IDX as u32 => (
            Some(idx),
            ColumnKind::Interaction,
            CommitmentPhase::Phase2Interaction,
        ),
        Some(idx) => (Some(idx), ColumnKind::Witness, annotations.witness_phase),
        None => (None, ColumnKind::Witness, annotations.witness_phase),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annotations::ParameterAnnotation;

    fn parameter_constraint(name: &str) -> ConstraintDecl {
        ConstraintDecl {
            id: "parameter_constraint".into(),
            expression: ExtExpr::Param { name: name.into() },
            row_support: RowSupport::All,
            source_location: None,
            semantic_claim: None,
        }
    }

    #[test]
    fn parameter_closure_rejects_untyped_symbols() {
        let auditor = AuditEvaluator::new(1);
        let err = build_parameter_declarations(
            &auditor,
            &[parameter_constraint("mystery")],
            &[],
            &ExportAnnotations::default(),
        )
        .expect_err("unknown formal symbols must fail closed");

        assert!(err.to_string().contains("no typed role and phase"), "{err}");
    }

    #[test]
    fn parameter_closure_rejects_escaped_intermediates() {
        let auditor = AuditEvaluator::new(1);
        let err = build_parameter_declarations(
            &auditor,
            &[parameter_constraint("intermediate0")],
            &[],
            &ExportAnnotations::default(),
        )
        .expect_err("generated intermediates must never become formal parameters");

        assert!(err.to_string().contains("escaped into AuditIR"), "{err}");
    }

    #[test]
    fn parameter_closure_accepts_typed_component_parameters() {
        let auditor = AuditEvaluator::new(1);
        let mut annotations = ExportAnnotations::default();
        annotations.parameters.insert(
            "public_digest".into(),
            ParameterAnnotation {
                field: FieldSort::Qm31,
                role: ParameterRole::PublicInput,
                available_after: CommitmentPhase::Phase0Public,
            },
        );

        let declarations = build_parameter_declarations(
            &auditor,
            &[parameter_constraint("public_digest")],
            &[],
            &annotations,
        )
        .expect("typed parameter should close the expression");

        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].name, "public_digest");
        assert_eq!(declarations[0].field, FieldSort::Qm31);
        assert_eq!(declarations[0].role, ParameterRole::PublicInput);
    }

    #[test]
    fn parameter_closure_rejects_field_sort_mismatch() {
        let auditor = AuditEvaluator::new(1);
        let mut annotations = ExportAnnotations::default();
        annotations.parameters.insert(
            "wrong_field".into(),
            ParameterAnnotation {
                field: FieldSort::M31,
                role: ParameterRole::PublicInput,
                available_after: CommitmentPhase::Phase0Public,
            },
        );

        let err = build_parameter_declarations(
            &auditor,
            &[parameter_constraint("wrong_field")],
            &[],
            &annotations,
        )
        .expect_err("field-sort mismatch must fail closed");

        assert!(err.to_string().contains("referenced as Qm31"), "{err}");
    }
}
