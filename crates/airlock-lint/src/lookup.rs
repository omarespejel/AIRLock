//! Table multiplicity and lookup functionality lints.

use std::collections::BTreeMap;

use airlock_ir::{
    BaseExpr, ComponentManifest, Finding, FindingCode, PreprocessedColumn, RelationRole,
    RowSupport, Severity,
};

use crate::confinement::{ConfinementCertificate, confinement_certificate};

/// Rows where a table-side multiplicity may be nonzero must lie inside semantic support.
///
/// This is the Q8 golden class: witness-controlled `table_mult` free on padding rows whose
/// preprocessed `(key, value)` is outside the semantic table.
pub fn lint_table_multiplicity_support(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obligation in table_multiplicity_obligations(component) {
        match &obligation.evidence {
            ConfinementEvidence::NoSemanticMetadata => findings.push(Finding {
                code: FindingCode::Other,
                severity: Severity::Medium,
                component: Some(component.name.clone()),
                message: format!(
                    "table relation `{}` lacks recoverable semantic support metadata; cannot prove multiplicity is confined",
                    obligation.relation
                ),
                related: vec![obligation.relation.clone()],
            }),
            ConfinementEvidence::Unproven => findings.push(Finding {
                code: FindingCode::TableMultiplicityOutsideSemanticSupport,
                severity: Severity::Critical,
                component: Some(component.name.clone()),
                message: format!(
                    "table relation `{}` has no constraint confining multiplicity to semantic support [0, {}); \
                     declared row support `{}` is a claim and cannot discharge it",
                    obligation.relation,
                    obligation.semantic_length,
                    describe_row_support(&obligation.declared_row_support)
                ),
                related: vec![obligation.relation.clone()],
            }),
            ConfinementEvidence::NoPaddingRows
            | ConfinementEvidence::ConstantZeroMultiplicity
            | ConfinementEvidence::Certified(_) => {}
        }
    }
    findings
}

/// Why a table multiplicity is, or is not, confined to semantic support.
///
/// Only the last three variants discharge the obligation, and each rests on
/// observed data. A declared `row_support` is never evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfinementEvidence {
    /// Semantic support could not be recovered from preprocessed table data.
    NoSemanticMetadata,
    /// No evidence confines the multiplicity to semantic support.
    Unproven,
    /// The physical domain has no rows outside semantic support.
    NoPaddingRows,
    /// The multiplicity expression is the literal zero.
    ConstantZeroMultiplicity,
    /// An AIR constraint forces the multiplicity to zero on every padding row.
    Certified(ConfinementCertificate),
}

/// One table-multiplicity confinement obligation and the evidence for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableMultiplicityObligation {
    /// Relation the obligation belongs to.
    pub relation: String,
    /// Semantic support length derived from preprocessed table data.
    pub semantic_length: u64,
    /// Physical domain length.
    pub physical_length: u64,
    /// Declared row support, recorded as a claim rather than as evidence.
    pub declared_row_support: RowSupport,
    /// Evidence for or against confinement.
    pub evidence: ConfinementEvidence,
}

impl TableMultiplicityObligation {
    /// Whether observed data confines the multiplicity to semantic support.
    pub fn is_confined(&self) -> bool {
        matches!(
            self.evidence,
            ConfinementEvidence::NoPaddingRows
                | ConfinementEvidence::ConstantZeroMultiplicity
                | ConfinementEvidence::Certified(_)
        )
    }

    /// Certificate that discharged the obligation, when one exists.
    pub fn certificate(&self) -> Option<&ConfinementCertificate> {
        match &self.evidence {
            ConfinementEvidence::Certified(certificate) => Some(certificate),
            _ => None,
        }
    }
}

/// Derive every table-multiplicity confinement obligation in a component.
///
/// Semantic support comes only from preprocessed table data; the relation's
/// declared `row_support` is recorded for reporting but never consulted when
/// deciding whether the obligation is discharged.
pub fn table_multiplicity_obligations(
    component: &ComponentManifest,
) -> Vec<TableMultiplicityObligation> {
    let prep: BTreeMap<&str, &PreprocessedColumn> = component
        .preprocessed
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();

    component
        .relations
        .iter()
        .filter(|relation| relation.role == RelationRole::Table)
        .map(|relation| {
            let Some(support) = semantic_support_for_table_relation(component, relation, &prep)
            else {
                return TableMultiplicityObligation {
                    relation: relation.relation.clone(),
                    semantic_length: 0,
                    physical_length: component.domain_size,
                    declared_row_support: relation.row_support.clone(),
                    evidence: ConfinementEvidence::NoSemanticMetadata,
                };
            };
            let evidence = if support.physical_length <= support.semantic_length {
                ConfinementEvidence::NoPaddingRows
            } else if matches!(relation.multiplicity, BaseExpr::Const { value: 0 }) {
                ConfinementEvidence::ConstantZeroMultiplicity
            } else {
                match confinement_certificate(
                    component,
                    relation,
                    &prep,
                    support.semantic_length,
                    support.physical_length,
                ) {
                    Some(certificate) => ConfinementEvidence::Certified(certificate),
                    None => ConfinementEvidence::Unproven,
                }
            };
            TableMultiplicityObligation {
                relation: relation.relation.clone(),
                semantic_length: support.semantic_length,
                physical_length: support.physical_length,
                declared_row_support: relation.row_support.clone(),
                evidence,
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
struct SemanticSupport {
    semantic_length: u64,
    physical_length: u64,
}

/// Semantic support is derived only from preprocessed table data.
///
/// It must never be read from `relation.row_support`: that is the declaration
/// under test, and using it as the yardstick makes the escape check compare a
/// value against itself.
fn semantic_support_for_table_relation<'a>(
    component: &'a ComponentManifest,
    relation: &airlock_ir::RelationEntry,
    prep: &BTreeMap<&str, &'a PreprocessedColumn>,
) -> Option<SemanticSupport> {
    for expr in &relation.tuple {
        let BaseExpr::Column { id, .. } = expr else {
            continue;
        };
        if let Some(column) = prep.get(id.as_str()) {
            return Some(SemanticSupport {
                semantic_length: column.semantic_length,
                physical_length: column.physical_length.max(component.domain_size),
            });
        }
    }
    None
}

/// Render a declared row support for a finding message.
fn describe_row_support(support: &RowSupport) -> String {
    match support {
        RowSupport::All => "all".into(),
        RowSupport::Range { start, end } => format!("[{start}, {end})"),
        RowSupport::Classes { classes } => format!("{classes:?}"),
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
        // Declared lengths are untrusted: `lint_preprocessed_contract` reports an
        // inconsistent `semantic_length`/`physical_length` pair, but every lint still
        // runs, so clamp both to the concrete value arrays before either can drive
        // indexing. Without this, a manifest declaring `semantic_length` above the
        // supplied value count reaches the row loops below and aborts the process,
        // destroying the findings already computed.
        let bound = (key_vals.len() as u64).min(value_vals.len() as u64);
        let semantic = keys
            .semantic_length
            .min(values.semantic_length)
            .min(bound);
        let physical = keys
            .physical_length
            .max(values.physical_length)
            .max(component.domain_size)
            .min(bound);

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
    // Preprocessed exports use Column ids. Do not treat formal Params as columns:
    // a Param name that collides with a preprocessed id must not resolve as that column.
    match expr {
        BaseExpr::Column { id, .. } => Some(id.as_str()),
        _ => None,
    }
}
