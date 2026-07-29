//! Generate checked-in seeded fixtures from the same builders used in tests.
//!
//! ```bash
//! cargo +nightly-2026-01-15 test -p airlock-lint write_seeded_fixtures -- --ignored --nocapture
//! ```

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    IntegerEncoding, PreprocessedColumn, RelationEntry, RelationRole, RowSupport, SemanticContract,
    SemanticType, SignedEncoding,
};
use std::fs;
use std::path::PathBuf;

fn repo_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/seeded")
}

fn q8(vulnerable: bool) -> ComponentManifest {
    const SEMANTIC: u64 = 16;
    const PHYSICAL: u64 = 32;
    let mut codes = Vec::new();
    let mut silus = Vec::new();
    for row in 0..PHYSICAL {
        if row < SEMANTIC {
            codes.push(row as u32);
            silus.push(if row == 0 { 1 } else { row as u32 + 1 });
        } else {
            codes.push(0);
            silus.push(0);
        }
    }
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
        parameters: vec![],
        constraints: vec![],
        relations: vec![RelationEntry {
            relation: "SiLU".into(),
            role: RelationRole::Table,
            tuple: vec![
                BaseExpr::column("table_code"),
                BaseExpr::column("table_silu"),
            ],
            multiplicity: BaseExpr::column("table_mult"),
            row_support: if vulnerable {
                RowSupport::All
            } else {
                RowSupport::Range {
                    start: 0,
                    end: SEMANTIC,
                }
            },
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
        contract: SemanticContract::default(),
        logup_finalized: true,
    }
}

#[test]
#[ignore = "writes fixtures/seeded; run explicitly when regenerating"]
fn write_seeded_fixtures() {
    let dir = repo_fixtures();
    fs::create_dir_all(&dir).unwrap();

    let vulnerable = AuditManifest::new("0.1.0", vec![q8(true)]);
    fs::write(
        dir.join("q8_padded_table_vulnerable.json"),
        serde_json::to_string_pretty(&vulnerable).unwrap(),
    )
    .unwrap();

    let fixed = AuditManifest::new("0.1.0", vec![q8(false)]);
    fs::write(
        dir.join("q8_padded_table_fixed.json"),
        serde_json::to_string_pretty(&fixed).unwrap(),
    )
    .unwrap();

    let encoder = AuditManifest::new(
        "0.1.0",
        vec![ComponentManifest {
            name: "down-encoder-mismatch".into(),
            log_size: 4,
            domain_size: 16,
            columns: vec![],
            parameters: vec![],
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
                    abs_bound: 369_098_752,
                }],
                ..SemanticContract::default()
            },
            logup_finalized: true,
        }],
    );
    fs::write(
        dir.join("encoder_admissibility_mismatch.json"),
        serde_json::to_string_pretty(&encoder).unwrap(),
    )
    .unwrap();
}
