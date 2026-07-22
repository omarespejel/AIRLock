//! End-to-end: Stwo FrameworkEval → AuditEvaluator → AuditIR → static lints.

use airlock_export::{
    export_component, ExportAnnotations, PreprocessedAttachment, RelationAnnotation,
    STWO_PIN_COMMIT,
};
use airlock_ir::{
    CommitmentPhase, FindingCode, RelationRole, RowSupport, SemanticContract, SemanticType,
};
use airlock_lint::{lint_manifest, LintOptions};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{relation, EvalAtRow, FrameworkEval, RelationEntry};

relation!(SiLU, 2);

const SEMANTIC: u64 = 16;
const LOG_SIZE: u32 = 5; // 32-row domain

struct SiluTableAir;

impl FrameworkEval for SiluTableAir {
    fn log_size(&self) -> u32 {
        LOG_SIZE
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        LOG_SIZE + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let code = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "table_code".into(),
        });
        let silu = eval.get_preprocessed_column(PreProcessedColumnId {
            id: "table_silu".into(),
        });
        let mult = eval.next_trace_mask();
        // Table/yield side uses negative multiplicity convention.
        let multiplicity = -E::EF::from(mult);
        eval.add_to_relation(RelationEntry::new(
            &SiLU::dummy(),
            multiplicity,
            &[code, silu],
        ));
        eval.finalize_logup();
        eval
    }
}

fn table_values() -> (Vec<u32>, Vec<u32>) {
    let physical = 1u64 << LOG_SIZE;
    let mut codes = Vec::with_capacity(physical as usize);
    let mut silus = Vec::with_capacity(physical as usize);
    for row in 0..physical {
        if row < SEMANTIC {
            codes.push(row as u32);
            silus.push(if row == 0 { 1 } else { row as u32 + 1 });
        } else {
            codes.push(0);
            silus.push(0);
        }
    }
    (codes, silus)
}

fn annotations(vulnerable: bool) -> ExportAnnotations {
    let (codes, silus) = table_values();
    let row_support = if vulnerable {
        RowSupport::All
    } else {
        RowSupport::Range {
            start: 0,
            end: SEMANTIC,
        }
    };
    let mut relations = indexmap::IndexMap::new();
    relations.insert(
        "SiLU".into(),
        RelationAnnotation {
            role: RelationRole::Table,
            row_support,
            challenge_phase: CommitmentPhase::Phase2Interaction,
        },
    );
    let mut preprocessed = indexmap::IndexMap::new();
    preprocessed.insert(
        "table_code".into(),
        PreprocessedAttachment {
            semantic_length: SEMANTIC,
            physical_length: 1 << LOG_SIZE,
            values: Some(codes),
            generator_id: None,
            semantic_type: SemanticType::TableKey,
        },
    );
    preprocessed.insert(
        "table_silu".into(),
        PreprocessedAttachment {
            semantic_length: SEMANTIC,
            physical_length: 1 << LOG_SIZE,
            values: Some(silus),
            generator_id: None,
            semantic_type: SemanticType::TableValue,
        },
    );
    let mut column_semantics = indexmap::IndexMap::new();
    column_semantics.insert(
        "trace_1_column_0".into(),
        SemanticType::TableMultiplicity,
    );

    ExportAnnotations {
        component_name: if vulnerable {
            "silu-table-vulnerable".into()
        } else {
            "silu-table-fixed".into()
        },
        contract: SemanticContract {
            reference_semantics_id: Some("q8-silu-table-v1".into()),
            assumptions: vec![
                "LogUp acceptance implies exact multiset balance under separately stated assumptions"
                    .into(),
            ],
            ..SemanticContract::default()
        },
        relations,
        preprocessed,
        column_semantics,
        witness_phase: CommitmentPhase::Phase1Original,
    }
}

#[test]
fn stwo_pin_matches_documented_commit() {
    assert_eq!(
        STWO_PIN_COMMIT,
        "41ba5a322c10841bbd50c36515b89fb8b29222d8"
    );
}

#[test]
fn export_vulnerable_silu_table_fails_q8_lints() {
    let air = SiluTableAir;
    let manifest = export_component(&air, annotations(true)).expect("export");
    assert_eq!(manifest.stwo_commit.as_deref(), Some(STWO_PIN_COMMIT));
    assert_eq!(manifest.components.len(), 1);
    assert!(manifest.components[0].logup_finalized);
    assert_eq!(manifest.components[0].relations.len(), 1);
    assert_eq!(manifest.components[0].relations[0].tuple.len(), 2);

    let findings = lint_manifest(&manifest, &LintOptions::default());
    let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
    assert!(
        codes.contains(&FindingCode::TableMultiplicityOutsideSemanticSupport),
        "missing support finding: {findings:?}"
    );
    assert!(
        codes.contains(&FindingCode::NonfunctionalLookupKey),
        "missing functionality finding: {findings:?}"
    );
}

#[test]
fn export_fixed_silu_table_passes_q8_lints() {
    let air = SiluTableAir;
    let manifest = export_component(&air, annotations(false)).expect("export");
    let findings = lint_manifest(&manifest, &LintOptions::default());
    assert!(
        findings.iter().all(|f| {
            f.code != FindingCode::TableMultiplicityOutsideSemanticSupport
                && f.code != FindingCode::NonfunctionalLookupKey
        }),
        "fixed export should not raise Q8 findings: {findings:?}"
    );
}

#[test]
fn export_requires_preprocessed_attachments() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    ann.preprocessed.clear();
    let err = export_component(&air, ann).expect_err("must require attachments");
    let msg = err.to_string();
    assert!(msg.contains("preprocessed"), "{msg}");
}

#[test]
fn export_requires_relation_annotations() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    ann.relations.clear();
    let err = export_component(&air, ann).expect_err("must require relation annotations");
    let msg = err.to_string();
    assert!(msg.contains("relation"), "{msg}");
}

#[test]
fn export_requires_preprocessed_values_or_generator() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    for attachment in ann.preprocessed.values_mut() {
        attachment.values = None;
        attachment.generator_id = None;
    }
    let err = export_component(&air, ann).expect_err("must require values or generator");
    let msg = err.to_string();
    assert!(
        msg.contains("values or generator_id"),
        "{msg}"
    );
}

#[test]
fn exported_column_ids_drop_offset_suffix() {
    let air = SiluTableAir;
    let manifest = export_component(&air, annotations(false)).expect("export");
    let ids: Vec<_> = manifest.components[0]
        .columns
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert!(ids.contains(&"table_code"));
    assert!(ids.contains(&"trace_1_column_0"));
    assert!(!ids.iter().any(|id| id.contains("_offset_")));
    assert!(matches!(
        &manifest.components[0].relations[0].tuple[0],
        airlock_ir::BaseExpr::Column { id, offset: 0 } if id == "table_code"
    ));
}
