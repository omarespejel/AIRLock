//! Adversarial regressions for untrusted declared lengths in the static gate.
//!
//! A manifest is untrusted input. `lint_preprocessed_contract` reports an
//! inconsistent `semantic_length`/`physical_length` pair, but `lint_component`
//! runs every lint unconditionally, so a later lint must never consume a
//! declared length without reconciling it against the concrete value arrays.
//! Indexing on an unreconciled length aborts the process and destroys the
//! findings already computed.

use airlock_ir::{
    BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest, FindingCode,
    PreprocessedColumn, RelationEntry, RelationRole, RowClass, RowSupport, SemanticContract,
    SemanticType,
};
use airlock_lint::{LintOptions, lint_component};

/// Table component whose declared `semantic_length` exceeds the supplied values.
///
/// Keys are distinct so the functionality loop cannot terminate early on a
/// duplicate-key break before reaching an out-of-range row.
fn overlong_semantic_length_component(
    row_support: RowSupport,
    semantic_length: u64,
) -> ComponentManifest {
    let keys = vec![0u32, 1, 2, 3];
    let values = vec![0u32, 0, 0, 0];
    let physical_length = keys.len() as u64;

    ComponentManifest {
        name: "overlong-semantic-length".into(),
        log_size: 2,
        domain_size: physical_length,
        columns: vec![
            ColumnDecl {
                id: "k".into(),
                name: "k".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::TableKey,
                declared_range: None,
                declared_support: None,
            },
            ColumnDecl {
                id: "v".into(),
                name: "v".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::TableValue,
                declared_range: None,
                declared_support: None,
            },
            ColumnDecl {
                id: "m".into(),
                name: "m".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase1Original,
                offsets: vec![0],
                kind: ColumnKind::Witness,
                semantic_type: SemanticType::TableMultiplicity,
                declared_range: None,
                declared_support: None,
            },
        ],
        parameters: vec![],
        constraints: vec![],
        relations: vec![RelationEntry {
            relation: "OverlongTable".into(),
            role: RelationRole::Table,
            tuple: vec![BaseExpr::column("k"), BaseExpr::column("v")],
            multiplicity: BaseExpr::column("m"),
            row_support,
            challenge_phase: CommitmentPhase::Phase2Interaction,
            source_location: Some("tests::untrusted_lengths".into()),
        }],
        preprocessed: vec![
            PreprocessedColumn {
                id: "k".into(),
                semantic_length,
                physical_length,
                values_hash: Some(airlock_ir::hash_u32_values(&keys)),
                values: Some(keys),
                generator_id: None,
            },
            PreprocessedColumn {
                id: "v".into(),
                semantic_length,
                physical_length,
                values_hash: Some(airlock_ir::hash_u32_values(&values)),
                values: Some(values),
                generator_id: None,
            },
        ],
        declared_max_constraint_log_degree_bound: Some(2),
        contract: SemanticContract::default(),
        logup_finalized: true,
    }
}

/// The class arm previously read `semantic_length` unclamped, so a declared
/// length above the supplied value count indexed past the end of the array.
#[test]
fn lookup_functionality_does_not_index_past_declared_values() {
    let component = overlong_semantic_length_component(
        RowSupport::Classes {
            classes: vec![RowClass::Active],
        },
        9,
    );

    let findings = lint_component(&component, &LintOptions::default());

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidPreprocessedContract),
        "the declared/physical length inconsistency must still be reported: {findings:#?}"
    );
}

/// The same reconciliation must hold at the extreme, where an unclamped length
/// would also overflow a `usize` range on 32-bit targets.
#[test]
fn lookup_functionality_survives_saturating_semantic_length() {
    for row_support in [
        RowSupport::Classes {
            classes: vec![RowClass::Active],
        },
        RowSupport::Classes {
            classes: vec![RowClass::SemanticTable],
        },
        RowSupport::All,
        RowSupport::Range {
            start: 0,
            end: u64::MAX,
        },
    ] {
        let component = overlong_semantic_length_component(row_support.clone(), u64::MAX);
        let findings = lint_component(&component, &LintOptions::default());
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::InvalidPreprocessedContract),
            "row support {row_support:?} must report the length inconsistency without aborting"
        );
    }
}

/// A padding-class support previously took the clamped `physical` path. Keep a
/// case on it so a future refactor cannot regress the clamped arm either.
#[test]
fn lookup_functionality_clamps_padding_class_support() {
    let component = overlong_semantic_length_component(
        RowSupport::Classes {
            classes: vec![RowClass::Padding],
        },
        9,
    );

    let findings = lint_component(&component, &LintOptions::default());

    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidPreprocessedContract),
        "padding-class support must also reconcile declared lengths: {findings:#?}"
    );
}
