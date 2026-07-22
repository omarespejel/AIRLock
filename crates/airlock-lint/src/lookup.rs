//! Table multiplicity and lookup functionality lints.

use std::collections::BTreeMap;

use airlock_ir::{
    BaseExpr, ComponentManifest, Finding, FindingCode, PreprocessedColumn, RelationRole,
    RowSupport, Severity,
};

/// Rows where a table-side multiplicity may be nonzero must lie inside semantic support.
///
/// This is the Q8 golden class: witness-controlled `table_mult` free on padding rows whose
/// preprocessed `(key, value)` is outside the semantic table.
pub fn lint_table_multiplicity_support(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let prep: BTreeMap<&str, &PreprocessedColumn> = component
        .preprocessed
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();

    for relation in component
        .relations
        .iter()
        .filter(|r| r.role == RelationRole::Table)
    {
        let Some(support) = semantic_support_for_table_relation(component, relation, &prep) else {
            findings.push(Finding {
                code: FindingCode::Other,
                severity: Severity::Medium,
                component: Some(component.name.clone()),
                message: format!(
                    "table relation `{}` lacks recoverable semantic support metadata; cannot prove multiplicity is confined",
                    relation.relation
                ),
                related: vec![relation.relation.clone()],
            });
            continue;
        };

        let semantic_length = support.semantic_length;
        if multiplicity_may_escape_support(&relation.row_support, &relation.multiplicity, &support)
        {
            findings.push(Finding {
                code: FindingCode::TableMultiplicityOutsideSemanticSupport,
                severity: Severity::Critical,
                component: Some(component.name.clone()),
                message: format!(
                    "table relation `{}` allows nonzero multiplicity outside semantic support [0, {})",
                    relation.relation, semantic_length
                ),
                related: vec![relation.relation.clone()],
            });
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct SemanticSupport {
    semantic_length: u64,
    physical_length: u64,
}

fn semantic_support_for_table_relation<'a>(
    component: &'a ComponentManifest,
    relation: &airlock_ir::RelationEntry,
    prep: &BTreeMap<&str, &'a PreprocessedColumn>,
) -> Option<SemanticSupport> {
    if let RowSupport::Range { start, end } = &relation.row_support
        && *start == 0
        && *end > 0
    {
        return Some(SemanticSupport {
            semantic_length: *end,
            physical_length: component.domain_size,
        });
    }

    for expr in &relation.tuple {
        let id = match expr {
            BaseExpr::Column { id, .. } | BaseExpr::Param { name: id } => id.as_str(),
            _ => continue,
        };
        if let Some(column) = prep.get(id) {
            return Some(SemanticSupport {
                semantic_length: column.semantic_length,
                physical_length: column.physical_length.max(component.domain_size),
            });
        }
    }
    None
}

fn multiplicity_may_escape_support(
    row_support: &RowSupport,
    multiplicity: &BaseExpr,
    support: &SemanticSupport,
) -> bool {
    if support.physical_length <= support.semantic_length {
        return false;
    }
    if matches!(multiplicity, BaseExpr::Const { value: 0 }) {
        return false;
    }
    match row_support {
        RowSupport::All => true,
        // Overlaps any padding index: end past semantic length and start before physical end.
        RowSupport::Range { start, end } => {
            *end > support.semantic_length && *start < support.physical_length
        }
        RowSupport::Classes { classes } => {
            classes.is_empty()
                || classes
                    .iter()
                    .any(|c| matches!(c, airlock_ir::RowClass::Padding))
        }
    }
}

/// Over rows where table multiplicity may be nonzero, each key must map to one value.
pub fn lint_lookup_functionality(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let prep: BTreeMap<&str, &PreprocessedColumn> = component
        .preprocessed
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();

    for relation in component
        .relations
        .iter()
        .filter(|r| r.role == RelationRole::Table)
    {
        if relation.tuple.len() < 2 {
            continue;
        }
        let (Some(key_id), Some(value_id)) =
            (column_id(&relation.tuple[0]), column_id(&relation.tuple[1]))
        else {
            continue;
        };
        let (Some(keys), Some(values)) = (prep.get(key_id), prep.get(value_id)) else {
            continue;
        };
        let Some(key_vals) = keys.values.as_ref() else {
            continue;
        };
        let Some(value_vals) = values.values.as_ref() else {
            continue;
        };
        let semantic = keys.semantic_length.min(values.semantic_length);
        let physical = keys
            .physical_length
            .max(values.physical_length)
            .max(component.domain_size)
            .min(key_vals.len() as u64)
            .min(value_vals.len() as u64);

        let allowed_end = match &relation.row_support {
            RowSupport::Range { end, .. } => (*end).min(physical),
            RowSupport::All => physical,
            RowSupport::Classes { classes } if classes.contains(&airlock_ir::RowClass::Padding) => {
                physical
            }
            RowSupport::Classes { .. } => semantic,
        };

        let mut map: BTreeMap<u32, u32> = BTreeMap::new();
        for row in 0..allowed_end as usize {
            let key = key_vals[row];
            let value = value_vals[row];
            if let Some(prev) = map.insert(key, value)
                && prev != value
            {
                findings.push(Finding {
                    code: FindingCode::NonfunctionalLookupKey,
                    severity: Severity::Critical,
                    component: Some(component.name.clone()),
                    message: format!(
                        "table relation `{}` is non-functional on allowed rows: key {key} maps to both {prev} and {value}",
                        relation.relation
                    ),
                    related: vec![
                        relation.relation.clone(),
                        key_id.to_string(),
                        value_id.to_string(),
                    ],
                });
                break;
            }
        }

        if allowed_end > semantic {
            let mut semantic_map: BTreeMap<u32, u32> = BTreeMap::new();
            for row in 0..semantic as usize {
                semantic_map.insert(key_vals[row], value_vals[row]);
            }
            for row in semantic as usize..allowed_end as usize {
                let key = key_vals[row];
                let value = value_vals[row];
                if let Some(&sem_value) = semantic_map.get(&key)
                    && sem_value != value
                {
                    findings.push(Finding {
                        code: FindingCode::NonfunctionalLookupKey,
                        severity: Severity::Critical,
                        component: Some(component.name.clone()),
                        message: format!(
                            "padding row {row} remaps key {key} from semantic value {sem_value} to {value} while multiplicity may be nonzero"
                        ),
                        related: vec![relation.relation.clone()],
                    });
                    break;
                }
            }
        }
    }

    findings
}

fn column_id(expr: &BaseExpr) -> Option<&str> {
    match expr {
        BaseExpr::Column { id, .. } | BaseExpr::Param { name: id } => Some(id.as_str()),
        _ => None,
    }
}
