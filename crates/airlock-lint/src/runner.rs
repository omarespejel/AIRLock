//! Lint orchestration.

use std::collections::{BTreeMap, BTreeSet};

use airlock_ir::{
    AuditManifest, CommitmentPhase, Finding, FindingCode, IR_SCHEMA_ID, IR_SCHEMA_VERSION,
    SemanticType, Severity,
};

use crate::encoder::lint_encoder_bounds;
use crate::logup::lint_logup_finalization;
use crate::lookup::{lint_lookup_functionality, lint_table_multiplicity_support};
use crate::parameter::lint_parameter_contract;
use crate::preprocessed::lint_preprocessed_contract;
use crate::structure::lint_component_structure;

/// Options for the static gate.
#[derive(Clone, Debug, Default)]
pub struct LintOptions {
    /// Emit Medium findings for missing semantic annotations.
    pub require_semantic_annotations: bool,
}

/// Lint one component.
pub fn lint_component(
    component: &airlock_ir::ComponentManifest,
    options: &LintOptions,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(lint_component_structure(component));
    findings.extend(lint_preprocessed_contract(component));
    findings.extend(lint_table_multiplicity_support(component));
    findings.extend(lint_lookup_functionality(component));
    findings.extend(lint_encoder_bounds(component));
    findings.extend(lint_logup_finalization(component));
    findings.extend(lint_parameter_contract(component));

    if options.require_semantic_annotations {
        for column in &component.columns {
            if matches!(column.semantic_type, SemanticType::Unknown) {
                findings.push(Finding {
                    code: airlock_ir::FindingCode::MissingSemanticAnnotation,
                    severity: airlock_ir::Severity::Medium,
                    component: Some(component.name.clone()),
                    message: format!(
                        "column `{}` lacks a semantic annotation required for COVERED status",
                        column.id
                    ),
                    related: vec![column.id.clone()],
                });
            }
        }
    }
    findings
}

/// Lint every component in a manifest.
pub fn lint_manifest(manifest: &AuditManifest, options: &LintOptions) -> Vec<Finding> {
    let mut findings = Vec::new();
    if manifest.schema != IR_SCHEMA_ID || manifest.schema_version != IR_SCHEMA_VERSION {
        findings.push(Finding {
            code: FindingCode::InvalidSchemaIdentity,
            severity: Severity::High,
            component: None,
            message: format!(
                "manifest identifies schema {}@{}, but this analyzer requires {}@{}",
                manifest.schema, manifest.schema_version, IR_SCHEMA_ID, IR_SCHEMA_VERSION
            ),
            related: vec![manifest.schema.clone(), manifest.schema_version.clone()],
        });
    }
    if manifest.components.is_empty() {
        findings.push(Finding {
            code: FindingCode::InvalidManifestStructure,
            severity: Severity::High,
            component: None,
            message: "manifest contains no components to analyze".into(),
            related: vec![],
        });
    }
    let mut component_names = BTreeSet::new();
    let mut relation_contracts = BTreeMap::<String, (usize, CommitmentPhase, String)>::new();
    for component in &manifest.components {
        if !component_names.insert(component.name.as_str()) {
            findings.push(Finding {
                code: FindingCode::InvalidManifestStructure,
                severity: Severity::High,
                component: Some(component.name.clone()),
                message: format!(
                    "component name `{}` appears more than once in the manifest",
                    component.name
                ),
                related: vec![component.name.clone()],
            });
        }
        for relation in &component.relations {
            if relation.relation.trim().is_empty() || relation.tuple.is_empty() {
                continue;
            }
            let contract = (
                relation.tuple.len(),
                relation.challenge_phase,
                component.name.clone(),
            );
            match relation_contracts.get(relation.relation.as_str()) {
                Some((arity, phase, owner))
                    if owner != &component.name
                        && (*arity != contract.0 || *phase != contract.1) =>
                {
                    findings.push(Finding {
                        code: FindingCode::InvalidManifestStructure,
                        severity: Severity::High,
                        component: Some(component.name.clone()),
                        message: format!(
                            "relation `{}` uses arity {} at {:?}, conflicting with arity {} at {:?} in component `{owner}`",
                            relation.relation, contract.0, contract.1, arity, phase
                        ),
                        related: vec![
                            relation.relation.clone(),
                            owner.clone(),
                            component.name.clone(),
                        ],
                    });
                }
                Some(_) => {}
                None => {
                    relation_contracts.insert(relation.relation.clone(), contract);
                }
            }
        }
    }
    findings.extend(
        manifest
            .components
            .iter()
            .flat_map(|component| lint_component(component, options)),
    );
    findings
}
