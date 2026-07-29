//! End-to-end: Stwo FrameworkEval → AuditEvaluator → AuditIR → static lints.

use std::cell::Cell;
use std::collections::BTreeSet;

use airlock_export::{
    ExportAnnotations, PreprocessedAttachment, REQUIRED_STWO_BASE_COMMIT, RelationAnnotation,
    RelationCompression, export_component,
};
use airlock_ir::{
    BaseExpr, CommitmentPhase, ExtExpr, FieldSort, FindingCode, ParameterRole, RelationRole,
    RowSupport, SemanticContract, SemanticType,
};
use airlock_lint::{LintOptions, lint_manifest};
use num_traits::One;
use stwo::core::Fraction;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry, relation};

relation!(SiLU, 2);

const SEMANTIC: u64 = 16;
const LOG_SIZE: u32 = 5; // 32-row domain

struct SiluTableAir;

struct IntermediateAir;

struct OversizedAir;

struct EmptyFinalizeAir {
    calls: usize,
}

struct LateDirectLogupWriteAir;

struct DirectRawLogupWriteAir;

struct PanickingLogSizeAir;

struct PanickingDegreeAir;

struct CountedMetadataAir {
    log_size_calls: Cell<usize>,
    degree_calls: Cell<usize>,
}

struct UndersizedAir;

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

impl FrameworkEval for IntermediateAir {
    fn log_size(&self) -> u32 {
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        6
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let x = eval.next_trace_mask();
        let x_squared = eval.add_intermediate(x.clone() * x);
        let lifted = eval.add_extension_intermediate(E::EF::from(x_squared));
        eval.add_constraint(lifted);
        eval
    }
}

impl FrameworkEval for OversizedAir {
    fn log_size(&self) -> u32 {
        stwo::core::poly::circle::MAX_CIRCLE_DOMAIN_LOG_SIZE + 1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size() + 1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        eval
    }
}

impl FrameworkEval for EmptyFinalizeAir {
    fn log_size(&self) -> u32 {
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        5
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        for _ in 0..self.calls {
            eval.finalize_logup();
        }
        eval
    }
}

impl FrameworkEval for LateDirectLogupWriteAir {
    fn log_size(&self) -> u32 {
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        5
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let value = eval.next_trace_mask();
        eval.add_to_relation(RelationEntry::new(
            &SiLU::dummy(),
            E::EF::one(),
            &[value.clone(), value],
        ));
        eval.finalize_logup();
        eval.write_logup_frac(Fraction::new(E::EF::one(), E::EF::one()));
        eval
    }
}

impl FrameworkEval for DirectRawLogupWriteAir {
    fn log_size(&self) -> u32 {
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        5
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        eval.write_logup_frac(Fraction::new(E::EF::one(), E::EF::one()));
        eval
    }
}

impl FrameworkEval for PanickingLogSizeAir {
    fn log_size(&self) -> u32 {
        panic!("log-size panic")
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        5
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        eval
    }
}

impl FrameworkEval for PanickingDegreeAir {
    fn log_size(&self) -> u32 {
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        panic!("degree-bound panic")
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        eval
    }
}

impl FrameworkEval for CountedMetadataAir {
    fn log_size(&self) -> u32 {
        self.log_size_calls.set(self.log_size_calls.get() + 1);
        4
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.degree_calls.set(self.degree_calls.get() + 1);
        5
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        eval
    }
}

impl FrameworkEval for UndersizedAir {
    fn log_size(&self) -> u32 {
        0
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
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
            compression: RelationCompression::StwoLookupElements,
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
    column_semantics.insert("trace_1_column_0".into(), SemanticType::TableMultiplicity);

    ExportAnnotations {
        component_name: if vulnerable {
            "silu-table-vulnerable".into()
        } else {
            "silu-table-fixed".into()
        },
        contract: SemanticContract {
            public_claims: vec!["claimed_sum".into()],
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
        parameters: indexmap::IndexMap::new(),
        witness_phase: CommitmentPhase::Phase1Original,
    }
}

#[test]
fn required_stwo_baseline_matches_documented_commit() {
    assert_eq!(
        REQUIRED_STWO_BASE_COMMIT,
        "f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a"
    );
}

#[test]
fn export_vulnerable_silu_table_fails_q8_lints() {
    let air = SiluTableAir;
    let manifest = export_component(&air, annotations(true)).expect("export");
    assert_eq!(manifest.stwo_commit, None);
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
fn exported_constraints_inline_generated_intermediates() {
    let manifest = export_component(&SiluTableAir, annotations(false)).expect("export");
    let mut params = BTreeSet::new();
    for constraint in &manifest.components[0].constraints {
        collect_ext_params(&constraint.expression, &mut params);
    }

    assert!(
        params.iter().all(|name| !name.starts_with("intermediate")),
        "generated intermediates must be inlined: {params:?}"
    );
    for expected in ["SiLU_alpha", "SiLU_z"] {
        assert!(
            params.contains(expected),
            "inlining must retain relation challenge `{expected}`: {params:?}"
        );
    }
    assert!(!params.contains("column_size"));
    assert!(!params.contains("SiLU_alpha0"));
    assert!(!params.contains("SiLU_alpha1"));

    let declared: BTreeSet<_> = manifest.components[0]
        .parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect();
    let referenced: BTreeSet<_> = params.iter().map(String::as_str).collect();
    assert_eq!(declared, referenced);

    let claimed_sum = manifest.components[0]
        .parameters
        .iter()
        .find(|parameter| parameter.name == "claimed_sum")
        .expect("claimed_sum declaration");
    assert_eq!(claimed_sum.field, FieldSort::Qm31);
    assert_eq!(claimed_sum.role, ParameterRole::PublicClaim);
    assert_eq!(claimed_sum.available_after, CommitmentPhase::Phase0Public);
    assert_eq!(
        manifest.components[0].contract.public_claims,
        vec!["claimed_sum".to_string()]
    );

    for challenge in manifest.components[0]
        .parameters
        .iter()
        .filter(|parameter| parameter.name.starts_with("SiLU_"))
    {
        assert_eq!(challenge.field, FieldSort::Qm31);
        assert_eq!(challenge.role, ParameterRole::FiatShamirChallenge);
        assert_eq!(
            challenge.available_after,
            CommitmentPhase::Phase2Interaction
        );
    }
}

#[test]
fn explicit_framework_intermediates_are_inlined() {
    let manifest = export_component(
        &IntermediateAir,
        ExportAnnotations {
            component_name: "explicit-intermediate".into(),
            contract: SemanticContract::default(),
            relations: indexmap::IndexMap::new(),
            preprocessed: indexmap::IndexMap::new(),
            column_semantics: indexmap::IndexMap::new(),
            parameters: indexmap::IndexMap::new(),
            witness_phase: CommitmentPhase::Phase1Original,
        },
    )
    .expect("export");

    let mut params = BTreeSet::new();
    for constraint in &manifest.components[0].constraints {
        collect_ext_params(&constraint.expression, &mut params);
    }
    assert!(params.is_empty(), "unexpected free parameters: {params:?}");
    assert!(manifest.components[0].parameters.is_empty());
}

#[test]
fn export_rejects_domains_larger_than_stwo_supports() {
    let err = export_component(&OversizedAir, ExportAnnotations::default())
        .expect_err("unsupported Circle domain must fail closed");
    assert!(err.to_string().contains("Circle domain range"), "{err}");
}

#[test]
fn export_rejects_domains_smaller_than_stwo_supports() {
    let err = export_component(&UndersizedAir, ExportAnnotations::default())
        .expect_err("unsupported Circle domain must fail closed");
    assert!(err.to_string().contains("Circle domain range"), "{err}");
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
fn export_rejects_preprocessed_length_mismatch() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    let attachment = ann.preprocessed.get_mut("table_code").unwrap();
    attachment.physical_length = 8;
    let err = export_component(&air, ann).expect_err("must reject length mismatch");
    assert!(err.to_string().contains("physical_length"), "{}", err);
}

#[test]
fn export_rejects_self_consistent_preprocessed_length_outside_component_domain() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    let attachment = ann.preprocessed.get_mut("table_code").unwrap();
    attachment.physical_length = 8;
    attachment.values.as_mut().unwrap().truncate(8);
    let err = export_component(&air, ann).expect_err("component domain must bind prep length");
    assert!(err.to_string().contains("domain_size"), "{err}");
}

#[test]
fn export_rejects_noncanonical_m31_preprocessed_values() {
    let air = SiluTableAir;
    let mut ann = annotations(false);
    ann.preprocessed
        .get_mut("table_code")
        .unwrap()
        .values
        .as_mut()
        .unwrap()[0] = airlock_ir::M31_P;
    let err = export_component(&air, ann).expect_err("noncanonical M31 value must fail");
    assert!(err.to_string().contains("noncanonical M31"), "{err}");
}

#[test]
fn empty_logup_finalization_fails_without_panicking() {
    let no_finalize =
        export_component(&EmptyFinalizeAir { calls: 0 }, ExportAnnotations::default())
            .expect("an empty component need not finalize LogUp");
    assert!(!no_finalize.components[0].logup_finalized);

    for calls in [1, 2] {
        let err = export_component(&EmptyFinalizeAir { calls }, ExportAnnotations::default())
            .expect_err("empty LogUp finalization must fail closed");
        assert!(err.to_string().contains("already finalized"), "{err}");
    }
}

#[test]
fn direct_logup_write_after_finalization_fails_closed() {
    let err = export_component(&LateDirectLogupWriteAir, ExportAnnotations::default())
        .expect_err("a direct late LogUp write must fail closed");
    assert!(err.to_string().contains("write_logup_frac"), "{err}");
}

#[test]
fn direct_raw_logup_fraction_fails_closed() {
    let err = export_component(&DirectRawLogupWriteAir, ExportAnnotations::default())
        .expect_err("a raw LogUp fraction cannot bypass relation capture");
    assert!(
        err.to_string().contains("uncompressed relation capture"),
        "{err}"
    );
}

#[test]
fn framework_metadata_panics_become_faithfulness_errors() {
    let log_size = export_component(&PanickingLogSizeAir, ExportAnnotations::default())
        .expect_err("log-size panic must not escape exporter");
    assert!(
        log_size.to_string().contains("log-size panic"),
        "{log_size}"
    );

    let degree = export_component(&PanickingDegreeAir, ExportAnnotations::default())
        .expect_err("degree-bound panic must not escape exporter");
    assert!(
        degree.to_string().contains("degree-bound panic"),
        "{degree}"
    );
}

#[test]
fn framework_metadata_is_read_exactly_once() {
    let air = CountedMetadataAir {
        log_size_calls: Cell::new(0),
        degree_calls: Cell::new(0),
    };
    export_component(&air, ExportAnnotations::default()).expect("export");
    assert_eq!(air.log_size_calls.get(), 1);
    assert_eq!(air.degree_calls.get(), 1);
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
    assert!(msg.contains("values or generator_id"), "{msg}");
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

#[test]
fn exported_interaction_columns_use_interaction_kind() {
    let air = SiluTableAir;
    let manifest = export_component(&air, annotations(false)).expect("export");
    let interaction_cols: Vec<_> = manifest.components[0]
        .columns
        .iter()
        .filter(|c| c.id.starts_with("trace_2_"))
        .collect();
    assert!(
        !interaction_cols.is_empty(),
        "expected LogUp interaction columns from finalize"
    );
    for col in interaction_cols {
        assert_eq!(col.kind, airlock_ir::ColumnKind::Interaction);
        assert_eq!(col.interaction, Some(2));
        assert_eq!(
            col.commitment_phase,
            airlock_ir::CommitmentPhase::Phase2Interaction
        );
    }
}

fn collect_base_params(expr: &BaseExpr, params: &mut BTreeSet<String>) {
    match expr {
        BaseExpr::Param { name } => {
            params.insert(name.clone());
        }
        BaseExpr::Const { .. } | BaseExpr::Column { .. } => {}
        BaseExpr::Add { lhs, rhs } | BaseExpr::Mul { lhs, rhs } => {
            collect_base_params(lhs, params);
            collect_base_params(rhs, params);
        }
        BaseExpr::Neg { inner } | BaseExpr::Inv { inner } => collect_base_params(inner, params),
    }
}

fn collect_ext_params(expr: &ExtExpr, params: &mut BTreeSet<String>) {
    match expr {
        ExtExpr::Param { name } => {
            params.insert(name.clone());
        }
        ExtExpr::Const { .. } => {}
        ExtExpr::SecureCol { parts } => {
            for part in parts {
                collect_base_params(part, params);
            }
        }
        ExtExpr::FromBase { inner } => collect_base_params(inner, params),
        ExtExpr::Add { lhs, rhs } | ExtExpr::Mul { lhs, rhs } => {
            collect_ext_params(lhs, params);
            collect_ext_params(rhs, params);
        }
        ExtExpr::Neg { inner } => collect_ext_params(inner, params),
    }
}
