//! Integrity checks for preprocessed AuditIR columns.

use std::collections::BTreeSet;

use airlock_ir::{ColumnKind, ComponentManifest, Finding, FindingCode, Severity};

/// Reject preprocessed declarations whose shape or concrete values are not
/// bound to the component domain and their canonical content hash.
pub fn lint_preprocessed_contract(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut ids = BTreeSet::new();

    for preprocessed in &component.preprocessed {
        if preprocessed.id.trim().is_empty() || !ids.insert(preprocessed.id.as_str()) {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed id `{}` must be nonempty and unique",
                    preprocessed.id
                ),
                vec![preprocessed.id.clone()],
            ));
        }
        if preprocessed.physical_length != component.domain_size {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed `{}` physical_length {} does not match component domain_size {}",
                    preprocessed.id, preprocessed.physical_length, component.domain_size
                ),
                vec![preprocessed.id.clone()],
            ));
        }
        if preprocessed.semantic_length > preprocessed.physical_length {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed `{}` semantic_length {} exceeds physical_length {}",
                    preprocessed.id, preprocessed.semantic_length, preprocessed.physical_length
                ),
                vec![preprocessed.id.clone()],
            ));
        }

        let matching_columns: Vec<_> = component
            .columns
            .iter()
            .filter(|column| column.id == preprocessed.id)
            .collect();
        if matching_columns.len() != 1 || matching_columns[0].kind != ColumnKind::Preprocessed {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed `{}` must resolve to exactly one preprocessed column declaration",
                    preprocessed.id
                ),
                vec![preprocessed.id.clone()],
            ));
        }

        if let Some(hash) = &preprocessed.values_hash
            && !valid_hash(hash)
        {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed `{}` has a malformed values_hash",
                    preprocessed.id
                ),
                vec![preprocessed.id.clone()],
            ));
        }

        match (&preprocessed.values, &preprocessed.generator_id) {
            (None, None) => findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed `{}` has neither concrete values nor a generator",
                    preprocessed.id
                ),
                vec![preprocessed.id.clone()],
            )),
            (None, Some(generator)) => {
                if generator.trim().is_empty() || preprocessed.values_hash.is_none() {
                    findings.push(preprocessed_finding(
                        component,
                        format!(
                            "preprocessed `{}` generator declarations require a nonempty id and values_hash",
                            preprocessed.id
                        ),
                        vec![preprocessed.id.clone()],
                    ));
                }
            }
            (Some(values), _) => {
                if u64::try_from(values.len()).ok() != Some(preprocessed.physical_length) {
                    findings.push(preprocessed_finding(
                        component,
                        format!(
                            "preprocessed `{}` has {} values but physical_length {}",
                            preprocessed.id,
                            values.len(),
                            preprocessed.physical_length
                        ),
                        vec![preprocessed.id.clone()],
                    ));
                }
                if values.iter().any(|value| *value >= airlock_ir::M31_P) {
                    findings.push(preprocessed_finding(
                        component,
                        format!(
                            "preprocessed `{}` contains a value outside canonical M31 representatives",
                            preprocessed.id
                        ),
                        vec![preprocessed.id.clone()],
                    ));
                }
                let expected = airlock_ir::hash_u32_values(values);
                if preprocessed.values_hash.as_deref() != Some(expected.as_str()) {
                    findings.push(preprocessed_finding(
                        component,
                        format!(
                            "preprocessed `{}` values_hash does not bind its concrete values",
                            preprocessed.id
                        ),
                        vec![preprocessed.id.clone()],
                    ));
                }
            }
        }
    }

    for column in component
        .columns
        .iter()
        .filter(|column| column.kind == ColumnKind::Preprocessed)
    {
        let attachment_count = component
            .preprocessed
            .iter()
            .filter(|preprocessed| preprocessed.id == column.id)
            .count();
        if attachment_count != 1 {
            findings.push(preprocessed_finding(
                component,
                format!(
                    "preprocessed column `{}` must have exactly one value or generator declaration",
                    column.id
                ),
                vec![column.id.clone()],
            ));
        }
    }

    findings
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn preprocessed_finding(
    component: &ComponentManifest,
    message: impl Into<String>,
    related: Vec<String>,
) -> Finding {
    Finding {
        code: FindingCode::InvalidPreprocessedContract,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: message.into(),
        related,
    }
}
