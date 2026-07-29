//! Lint orchestration.

use airlock_ir::{AuditManifest, Finding, SemanticType};

use crate::encoder::lint_encoder_bounds;
use crate::logup::lint_logup_finalization;
use crate::lookup::{lint_lookup_functionality, lint_table_multiplicity_support};

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
    findings.extend(lint_table_multiplicity_support(component));
    findings.extend(lint_lookup_functionality(component));
    findings.extend(lint_encoder_bounds(component));
    findings.extend(lint_logup_finalization(component));

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
    manifest
        .components
        .iter()
        .flat_map(|component| lint_component(component, options))
        .collect()
}
