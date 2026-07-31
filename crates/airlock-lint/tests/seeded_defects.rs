//! Seeded defect builders and integration tests for the static gate.

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    ConstraintDecl, ExtExpr, FieldSort, FindingCode, IntegerEncoding, ParameterDecl, ParameterRole,
    PreprocessedColumn, RelationEntry, RelationRole, RowSupport, SemanticContract, SemanticType,
    Severity, SignedEncoding,
};
use airlock_lint::{
    LintOptions, TableMultiplicityObligation, lint_component, lint_manifest,
    table_multiplicity_obligations,
};

const SEMANTIC: u64 = 16;
const PHYSICAL: u64 = 32;

/// Which Q8 variant to build.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Q8Variant {
    /// Row support `all`: the declaration itself admits padding rows.
    Vulnerable,
    /// Row support narrowed to semantic rows, but no constraint enforces it.
    /// This is a claim, not a repair.
    AnnotationOnly,
    /// A verifier-owned selector plus `(1 - table_active) * table_mult = 0`.
    Constrained,
}

/// Legacy two-way accessor kept for the many callers that only need a Q8-shaped
/// component to mutate.
///
/// Note that **neither** variant passes the Q8 lints: `true` declares `all` row
/// support and `false` narrows the declaration without adding a constraint. Use
/// `q8_variant(Q8Variant::Constrained)` for the variant that is actually repaired.
fn q8_component(vulnerable: bool) -> ComponentManifest {
    q8_variant(if vulnerable {
        Q8Variant::Vulnerable
    } else {
        Q8Variant::AnnotationOnly
    })
}

fn q8_variant(variant: Q8Variant) -> ComponentManifest {
    let vulnerable = variant == Q8Variant::Vulnerable;
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
        name: match variant {
            Q8Variant::Vulnerable => "stage-a-nonlinear-q8-vulnerable".into(),
            Q8Variant::AnnotationOnly => "stage-a-nonlinear-q8-annotation-only".into(),
            Q8Variant::Constrained => "stage-a-nonlinear-q8-constrained".into(),
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
        ]
        .into_iter()
        .chain(
            (variant == Q8Variant::Constrained).then(|| ColumnDecl {
                id: "table_active".into(),
                name: "table_active".into(),
                interaction: None,
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::Selector,
                declared_range: None,
                declared_support: None,
            }),
        )
        .collect(),
        parameters: vec![],
        constraints: if variant == Q8Variant::Constrained {
            vec![ConstraintDecl {
                id: "q8-table-mult-confinement".into(),
                // (1 - table_active) * table_mult = 0 forces the multiplicity to
                // zero on every row where table_active is 0, i.e. the padding rows.
                expression: ExtExpr::FromBase {
                    inner: BaseExpr::Mul {
                        lhs: Box::new(BaseExpr::Add {
                            lhs: Box::new(BaseExpr::constant(1)),
                            rhs: Box::new(BaseExpr::Neg {
                                inner: Box::new(BaseExpr::column("table_active")),
                            }),
                        }),
                        rhs: Box::new(BaseExpr::column("table_mult")),
                    },
                },
                row_support: RowSupport::All,
                source_location: Some("fixtures::q8".into()),
                semantic_claim: Some("table multiplicity vanishes off semantic support".into()),
            }]
        } else {
            vec![]
        },
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
        ]
        .into_iter()
        .chain((variant == Q8Variant::Constrained).then(|| {
            let actives: Vec<u32> = (0..PHYSICAL)
                .map(|row| u32::from(row < SEMANTIC))
                .collect();
            PreprocessedColumn {
                id: "table_active".into(),
                semantic_length: SEMANTIC,
                physical_length: PHYSICAL,
                values_hash: Some(airlock_ir::hash_u32_values(&actives)),
                values: Some(actives),
                generator_id: None,
            }
        }))
        .collect(),
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
                // DeepSeek-style admitted bound that exceeds 28-bit biased abs capacity.
                abs_bound: 369_098_752,
            }],
            ..SemanticContract::default()
        },
        logup_finalized: true,
    }
}

fn parameter_constraint(name: &str) -> ConstraintDecl {
    ConstraintDecl {
        id: "formal-parameter".into(),
        expression: ExtExpr::Param { name: name.into() },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
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
fn q8_annotation_only_repair_does_not_discharge_the_obligation() {
    // Narrowing `row_support` is a claim about where multiplicity may be nonzero.
    // It adds no constraint, so the same malicious witness remains available and
    // the obligation must stay undischarged.
    let component = q8_variant(Q8Variant::AnnotationOnly);
    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        findings.iter().any(
            |f| f.code == FindingCode::TableMultiplicityOutsideSemanticSupport
                && f.severity == Severity::Critical
        ),
        "an annotation-only repair must not reach a pass state: {findings:?}"
    );
}

#[test]
fn q8_constrained_repair_discharges_the_obligation() {
    let component = q8_variant(Q8Variant::Constrained);
    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        findings.iter().all(|f| {
            f.code != FindingCode::TableMultiplicityOutsideSemanticSupport
                && f.code != FindingCode::NonfunctionalLookupKey
        }),
        "a real confinement constraint should discharge the Q8 obligation: {findings:?}"
    );

    // The discharge must be attributable to an actual constraint, not to metadata.
    let obligations = table_multiplicity_obligations(&component);
    let silu = obligations
        .iter()
        .find(|o| o.relation == "SiLU")
        .expect("SiLU obligation");
    let certificate = silu
        .certificate()
        .expect("confinement must be certified by a constraint");
    assert_eq!(certificate.constraint_id, "q8-table-mult-confinement");
    assert_eq!(certificate.guard_columns, vec!["table_active".to_string()]);
    assert!(silu.is_confined());
}

/// The property that closes the class: holding the AIR fixed and editing only
/// declared metadata must never improve the outcome.
#[test]
fn declared_row_support_cannot_change_the_confinement_outcome() {
    let mut baseline = q8_variant(Q8Variant::AnnotationOnly);
    let baseline_confined = table_multiplicity_obligations(&baseline)
        .iter()
        .all(TableMultiplicityObligation::is_confined);
    assert!(!baseline_confined, "baseline must be unconfined");

    for support in [
        RowSupport::All,
        RowSupport::Range {
            start: 0,
            end: SEMANTIC,
        },
        RowSupport::Range { start: 0, end: 1 },
        RowSupport::Classes {
            classes: vec![airlock_ir::RowClass::SemanticTable],
        },
        RowSupport::Classes {
            classes: vec![airlock_ir::RowClass::Active],
        },
    ] {
        baseline.relations[0].row_support = support.clone();
        for column in &mut baseline.columns {
            if column.id == "table_mult" {
                column.declared_support = Some(support.clone());
            }
        }
        let confined = table_multiplicity_obligations(&baseline)
            .iter()
            .all(TableMultiplicityObligation::is_confined);
        assert!(
            !confined,
            "declared support {support:?} must not discharge the obligation without a constraint"
        );
    }
}

#[test]
fn encoder_admissibility_mismatch_is_high() {
    let findings = lint_component(&encoder_mismatch_component(), &LintOptions::default());
    assert!(findings.iter().any(|f| {
        f.code == FindingCode::AdmittedBoundExceedsEncoder && f.severity == Severity::High
    }));
}

#[test]
fn undeclared_and_escaped_parameters_fail_closed() {
    let mut component = q8_component(false);
    component.constraints = vec![
        parameter_constraint("unknown_claim"),
        parameter_constraint("intermediate0"),
    ];

    let findings = lint_component(&component, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidParameterContract
            && finding.message.contains("unknown_claim")
            && finding.message.contains("no declaration")
    }));
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidParameterContract
            && finding.message.contains("intermediate0")
            && finding.message.contains("escaped")
    }));
}

#[test]
fn exact_typed_parameter_contract_passes() {
    let mut component = q8_component(false);
    component.constraints = vec![parameter_constraint("public_digest")];
    component.parameters = vec![ParameterDecl {
        name: "public_digest".into(),
        field: FieldSort::Qm31,
        role: ParameterRole::PublicInput,
        available_after: CommitmentPhase::Phase0Public,
    }];
    component.contract.public_inputs = vec!["public_digest".into()];

    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        findings
            .iter()
            .all(|finding| finding.code != FindingCode::InvalidParameterContract),
        "typed closure should pass: {findings:?}"
    );
}

#[test]
fn duplicate_unused_and_mistyped_parameters_fail_closed() {
    let mut component = q8_component(false);
    component.constraints = vec![parameter_constraint("wrong_field")];
    component.parameters = vec![
        ParameterDecl {
            name: "wrong_field".into(),
            field: FieldSort::M31,
            role: ParameterRole::PublicInput,
            available_after: CommitmentPhase::Phase0Public,
        },
        ParameterDecl {
            name: "unused".into(),
            field: FieldSort::Qm31,
            role: ParameterRole::PublicClaim,
            available_after: CommitmentPhase::Phase0Public,
        },
        ParameterDecl {
            name: "unused".into(),
            field: FieldSort::Qm31,
            role: ParameterRole::PublicClaim,
            available_after: CommitmentPhase::Phase0Public,
        },
    ];

    let findings = lint_component(&component, &LintOptions::default());
    for marker in [
        "declared more than once",
        "never referenced",
        "declared as M31",
    ] {
        assert!(
            findings.iter().any(|finding| {
                finding.code == FindingCode::InvalidParameterContract
                    && finding.message.contains(marker)
            }),
            "missing `{marker}` finding: {findings:?}"
        );
    }
}

#[test]
fn logup_unfinalized_is_flagged() {
    let mut component = q8_component(false);
    component.logup_finalized = false;
    let findings = lint_component(&component, &LintOptions::default());
    assert!(
        findings
            .iter()
            .any(|f| f.code == FindingCode::LogupNotFinalized)
    );
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
    let report = airlock_ir::GateReport::from_static_findings("0.1.0", "0.1.0", findings);
    assert_eq!(report.overall_release_status, "BLOCKED");
    assert!(
        report
            .lanes
            .iter()
            .any(|l| l.lane == airlock_ir::AnalysisLane::Protocol && l.status == "UNINSTANTIATED")
    );
}

#[test]
fn audit_manifest_roundtrips_json() {
    let manifest = AuditManifest::new("0.1.0", vec![q8_component(true)]);
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let parsed: AuditManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.components[0].name, manifest.components[0].name);
    assert_eq!(parsed.schema, airlock_ir::IR_SCHEMA_ID);
}

#[test]
fn stale_or_foreign_audit_schema_fails_closed() {
    let mut manifest = AuditManifest::new("0.1.0", vec![q8_component(false)]);
    manifest.schema_version = "0.2.0".into();
    let findings = lint_manifest(&manifest, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidSchemaIdentity && finding.severity == Severity::High
    }));

    manifest.schema_version = airlock_ir::IR_SCHEMA_VERSION.into();
    manifest.schema = "foreign.audit-ir".into();
    let findings = lint_manifest(&manifest, &LintOptions::default());
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidSchemaIdentity)
    );
}

#[test]
fn preprocessed_contract_rejects_domain_mismatch_and_noncanonical_values() {
    let mut domain_mismatch = q8_component(false);
    let preprocessed = &mut domain_mismatch.preprocessed[0];
    preprocessed.physical_length = PHYSICAL - 1;
    preprocessed
        .values
        .as_mut()
        .unwrap()
        .truncate((PHYSICAL - 1) as usize);
    preprocessed.values_hash = Some(airlock_ir::hash_u32_values(
        preprocessed.values.as_ref().unwrap(),
    ));
    let findings = lint_component(&domain_mismatch, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("domain_size")
    }));

    let mut noncanonical = q8_component(false);
    let preprocessed = &mut noncanonical.preprocessed[0];
    preprocessed.values.as_mut().unwrap()[0] = airlock_ir::M31_P;
    preprocessed.values_hash = Some(airlock_ir::hash_u32_values(
        preprocessed.values.as_ref().unwrap(),
    ));
    let findings = lint_component(&noncanonical, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("canonical M31")
    }));
}

#[test]
fn preprocessed_contract_closes_column_attachment_mapping() {
    let mut missing = q8_component(false);
    missing.preprocessed.clear();
    let findings = lint_component(&missing, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("exactly one value or generator")
    }));

    let mut orphaned = q8_component(false);
    orphaned.preprocessed[0].id = "orphaned_table".into();
    let findings = lint_component(&orphaned, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("exactly one preprocessed column")
    }));

    let mut wrong_kind = q8_component(false);
    wrong_kind.columns[0].kind = ColumnKind::Witness;
    let findings = lint_component(&wrong_kind, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("exactly one preprocessed column")
    }));
}
