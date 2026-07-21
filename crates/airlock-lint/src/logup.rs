//! LogUp finalization lint.

use airlock_ir::{ComponentManifest, Finding, FindingCode, Severity};

/// Every component that records relation entries must finalize LogUp exactly once.
pub fn lint_logup_finalization(component: &ComponentManifest) -> Vec<Finding> {
    if component.relations.is_empty() {
        return Vec::new();
    }
    if component.logup_finalized {
        return Vec::new();
    }
    vec![Finding {
        code: FindingCode::LogupNotFinalized,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: format!(
            "component `{}` records {} relation entries but LogUp is not marked finalized",
            component.name,
            component.relations.len()
        ),
        related: component
            .relations
            .iter()
            .map(|r| r.relation.clone())
            .collect(),
    }]
}
