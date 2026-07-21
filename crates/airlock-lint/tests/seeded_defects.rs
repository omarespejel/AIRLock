//! Seeded defect builders and integration tests for the static gate.

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    FindingCode, IntegerEncoding, PreprocessedColumn, RelationEntry, RelationRole, RowSupport,
    SemanticContract, SemanticType, SignedEncoding, Severity,
};
use airlock_lint::{lint_component, LintOptions};

const SEMANTIC: u64 = 16;
const PHYSICAL: u64 = 32;

fn q8_component(vulnerable: bool) -> ComponentManifest {
    let mut codes = Vec::with_capacity(PHYSICAL as usize);
    let mut silus = Vec::with_capacity(PHYSICAL as usize);
    for row in 0..PHYSICAL {
        if row < SEMANTIC {
            // Distinct semantic mapping: code = row, silu = row + 1 (except 0 -> 1).
            codes.push(row as u32);
            silus.push(if row == 0 { 1 } else { row as u32 + 1 });
        } else {
            // Padding collapses to (0, 0) — the Q8 class defect when mult is free.
            codes.push(0);
            silus.push(0);
        }
    }

    let row_support = if vulnerable {
        RowSupport::All
    } else {
        RowSupport::Range {
            start: 0,
            end: SEMANTIC,
        }
    };

    ComponentManifest {
        name: if vulnerable {
            "stage-a-nonlinear-q8-vulnerable".into()
        } else {
            "stage-a-nonlinear-q8-fixed".into()
        },
        log_size: PHYSICAL.trailing_zeros(),
        domain_size: PHYSICAL,
        columns: vec![
            ColumnDecl {
                id: "table_code".into(),
                name: "table_code".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::TableKey,
                declared_range: None,
                declared_support: Some(RowSupport::Range {
                    start: 0,
                    end: SEMANTIC,
                }),
            },
            ColumnDecl {
                id: "table_silu".into(),
                name: "table_silu".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::TableValue,
                declared_range: None,
                declared_support: Some(RowSupport::Range {
                    start: 0,
                    end: SEMANTIC,
                }),
            },
            ColumnDecl {
                id: "table_mult".into(),
                name: "table_mult".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase1Original,
                offsets: vec![0],
                kind: ColumnKind::Witness,
                semantic_type: SemanticType::TableMultiplicity,
                declared_range: None,
                declared_support: Some(if vulnerable {
                    RowSupport::All
                } else {
                    RowSupport::Range {
                        start: 0,
                        end: SEMANTIC,
                    }
                }),
            },
        ],
        constraints: vec![],
        relations: vec![RelationEntry {
            relation: "SiLU".into(),
            role: RelationRole::Table,
            tuple: vec![BaseExpr::column("table_code"), BaseExpr::column("table_silu")],
            multiplicity: BaseExpr::column("table_mult"),
            row_support,
            challenge_phase: CommitmentPhase::Phase2Interaction,
            source_location: Some("fixtures::q8".into()),
        }],
        preprocessed: vec![
            PreprocessedColumn {
                id: "table_code".into(),
                semantic_length: SEMANTIC,
                physical_length: PHYSICAL,
                values_hash: Some(airlock_ir::hash_u32_values(&codes)),
                values: Some(codes),
                generator_id: None,
            },
            PreprocessedColumn {
                id: "table_silu".into(),
                semantic_length: SEMANTIC,
                physical_length: PHYSICAL,
                values_hash: Some(airlock_ir::hash_u32_values(&silus)),
                values: Some(silus),
                generator_id: None,
            },
        ],
        declared_max_constraint_log_degree_bound: Some(5),
        contract: SemanticContract {
            reference_semantics_id: Some("q8-silu-table-v1".into()),
            assumptions: vec![
                "LogUp acceptance implies exact multiset balance under separately stated assumptions"
                    .into(),
            ],
            ..SemanticContract::default()
        },
        logup_finalized: true,
    }
}

fn encoder_mismatch_component() -> ComponentManifest {
    ComponentManifest {
        name: "down-encoder-mismatch".into(),
        log_size: 4,
        domain_size: 16,
        columns: vec![],
        constraints: vec![],
        relations: vec![],
        preprocessed: vec![],
        declared_max_constraint_log_degree_bound: Some(3),
        contract: SemanticContract {
            integer_obligations: vec![IntegerEncoding {
                name: "regular_down_projection".into(),
                encoding: SignedEncoding::BiasedBits {
                    bias: 1 << 27,
                    bits: 28,
                },
                // DeepSeek-style admitted bound that exceeds 28-bit biased abs capacity.
                abs_bound: 369_098_752,
            }],
            ..SemanticContract::default()
        },
        logup_finalized: true,
    }
}

#[test]
fn q8_vulnerable_fixture_is_caught_without_hardcoded_column_names() {
    let component = q8_component(true);
    let findings = lint_component(&component, &LintOptions::default());
    let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
    assert!(
        codes.contains(&FindingCode::TableMultiplicityOutsideSemanticSupport),
        "expected support finding, got {findings:?}"
    );
    assert!(
        codes.contains(&FindingCode::NonfunctionalLookupKey),
        "expected nonfunctional key finding, got {findings:?}"
    );
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    // Generic: messages mention relation name SiLU, not a hard-coded Rust path.
    assert!(findings.iter().all(|f| f.message.contains("SiLU")
        || f.code == FindingCode::NonfunctionalLookupKey
        || f.code == FindingCode::TableMultiplicityOutsideSemanticSupport));
}

#[test]
fn q8_fixed_fixture_passes_support_and_functionality() {
    let component = q8_component(false);
    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        findings.iter().all(|f| {
            f.code != FindingCode::TableMultiplicityOutsideSemanticSupport
                && f.code != FindingCode::NonfunctionalLookupKey
        }),
        "fixed fixture should not trigger Q8 findings: {findings:?}"
    );
}

#[test]
fn encoder_admissibility_mismatch_is_high() {
    let findings = lint_component(&encoder_mismatch_component(), &LintOptions::default());
    assert!(findings.iter().any(|f| {
        f.code == FindingCode::AdmittedBoundExceedsEncoder && f.severity == Severity::High
    }));
}

#[test]
fn logup_unfinalized_is_flagged() {
    let mut component = q8_component(false);
    component.logup_finalized = false;
    let findings = lint_component(&component, &LintOptions::default());
    assert!(findings
        .iter()
        .any(|f| f.code == FindingCode::LogupNotFinalized));
}

#[test]
fn coverage_manifest_fail_closed_on_missing_surface() {
    let coverage = airlock_ir::CoverageManifest {
        schema: "airlock.coverage".into(),
        surfaces: vec![airlock_ir::SurfaceEntry {
            name: "fused-stage-a-q7".into(),
            status: airlock_ir::CoverageStatus::Unsupported,
            note: Some("pilot".into()),
            profile_region: None,
        }],
    };
    assert!(coverage.require_listed(&["fused-stage-a-q7"]).is_ok());
    assert!(coverage.require_listed(&["grouped-down-legacy"]).is_err());
    assert!(!coverage.all_required_covered(&["fused-stage-a-q7"]));
}

#[test]
fn gate_report_never_collapses_lanes_to_sound_true() {
    let component = q8_component(true);
    let findings = lint_component(&component, &LintOptions::default());
    let report = airlock_ir::GateReport::from_static_findings("0.1.0", findings);
    assert_eq!(report.overall_release_status, "BLOCKED");
    assert!(report
        .lanes
        .iter()
        .any(|l| l.lane == airlock_ir::AnalysisLane::Protocol
            && l.status == "UNINSTANTIATED"));
}

#[test]
fn audit_manifest_roundtrips_json() {
    let manifest = AuditManifest::new("0.1.0", vec![q8_component(true)]);
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let parsed: AuditManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.components[0].name, manifest.components[0].name);
    assert_eq!(parsed.schema, airlock_ir::IR_SCHEMA_ID);
}
