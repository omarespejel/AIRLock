//! Boundary profiles for structural, table, phase, and encoder contracts.

use airlock_ir::{
    AuditManifest, BaseExpr, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest,
    ConstraintDecl, ExtExpr, FindingCode, IntegerEncoding, ParameterDecl, ParameterRole,
    PreprocessedColumn, RelationEntry, RelationRole, RowClass, RowSupport,
    STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE, STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE, SemanticContract,
    SemanticType, SignedEncoding,
};
use airlock_lint::{
    LintOptions, lint_component, lint_component_structure, lint_encoder_bounds, lint_manifest,
};

const N: u64 = 16;

fn valid_component() -> ComponentManifest {
    let values: Vec<u32> = (0..N as u32).collect();
    ComponentManifest {
        name: "boundary-profile".into(),
        log_size: 4,
        domain_size: N,
        columns: vec![
            ColumnDecl {
                id: "table".into(),
                name: "table".into(),
                interaction: Some(0),
                commitment_phase: CommitmentPhase::Phase0Public,
                offsets: vec![0],
                kind: ColumnKind::Preprocessed,
                semantic_type: SemanticType::TableKey,
                declared_range: None,
                declared_support: Some(RowSupport::Range { start: 0, end: 8 }),
            },
            ColumnDecl {
                id: "multiplicity".into(),
                name: "multiplicity".into(),
                interaction: Some(1),
                commitment_phase: CommitmentPhase::Phase1Original,
                offsets: vec![0],
                kind: ColumnKind::Witness,
                semantic_type: SemanticType::TableMultiplicity,
                declared_range: None,
                declared_support: Some(RowSupport::Range { start: 0, end: 8 }),
            },
        ],
        parameters: vec![],
        constraints: vec![],
        relations: vec![RelationEntry {
            relation: "BoundaryTable".into(),
            role: RelationRole::Table,
            tuple: vec![BaseExpr::column("table")],
            multiplicity: BaseExpr::column("multiplicity"),
            row_support: RowSupport::Range { start: 0, end: 8 },
            challenge_phase: CommitmentPhase::Phase2Interaction,
            source_location: None,
        }],
        preprocessed: vec![PreprocessedColumn {
            id: "table".into(),
            semantic_length: 8,
            physical_length: N,
            values_hash: Some(airlock_ir::hash_u32_values(&values)),
            values: Some(values),
            generator_id: None,
        }],
        declared_max_constraint_log_degree_bound: Some(5),
        contract: SemanticContract::default(),
        logup_finalized: true,
    }
}

fn component_at_log_size(log_size: u32) -> ComponentManifest {
    let mut component = valid_component();
    let domain_size = 1u64 << log_size;
    component.log_size = log_size;
    component.domain_size = domain_size;
    component.columns.clear();
    component.relations.clear();
    component.preprocessed.clear();
    component.logup_finalized = false;
    component.columns = vec![ColumnDecl {
        id: "value".into(),
        name: "value".into(),
        interaction: Some(1),
        commitment_phase: CommitmentPhase::Phase1Original,
        offsets: vec![0],
        kind: ColumnKind::Witness,
        semantic_type: SemanticType::Unknown,
        declared_range: None,
        declared_support: Some(RowSupport::All),
    }];
    component.constraints = vec![ConstraintDecl {
        id: "value-is-zero".into(),
        expression: ExtExpr::FromBase {
            inner: BaseExpr::column("value"),
        },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    }];
    component
}

fn encoder_component(encoding: SignedEncoding, abs_bound: u128) -> ComponentManifest {
    let mut component = valid_component();
    component.contract.integer_obligations = vec![IntegerEncoding {
        name: "encoded".into(),
        encoding,
        abs_bound,
    }];
    component
}

fn has_code(component: &ComponentManifest, code: FindingCode) -> bool {
    lint_component(component, &LintOptions::default())
        .iter()
        .any(|finding| finding.code == code)
}

#[test]
fn exact_power_of_two_domain_is_required() {
    let valid = valid_component();
    assert!(!has_code(&valid, FindingCode::InvalidManifestStructure));

    for log_size in [
        STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE,
        STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE,
    ] {
        let endpoint = component_at_log_size(log_size);
        assert!(
            lint_component(&endpoint, &LintOptions::default()).is_empty(),
            "supported Stwo endpoint log_size={log_size} must pass"
        );
    }

    for domain_size in [N - 1, N + 1] {
        let mut component = valid.clone();
        component.domain_size = domain_size;
        assert!(has_code(&component, FindingCode::InvalidManifestStructure));
    }

    let mut below_stwo = valid.clone();
    below_stwo.log_size = STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE - 1;
    below_stwo.domain_size = 1;
    assert!(has_code(&below_stwo, FindingCode::InvalidManifestStructure));

    let mut above_stwo = valid;
    above_stwo.log_size = STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE + 1;
    above_stwo.domain_size = 1 << (STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE + 1);
    assert!(has_code(&above_stwo, FindingCode::InvalidManifestStructure));
}

#[test]
fn preprocessed_length_matrix_fails_outside_exact_contract() {
    for semantic_length in [N - 1, N] {
        let mut component = valid_component();
        component.preprocessed[0].semantic_length = semantic_length;
        assert!(!has_code(
            &component,
            FindingCode::InvalidPreprocessedContract
        ));
    }

    let mut semantic_too_large = valid_component();
    semantic_too_large.preprocessed[0].semantic_length = N + 1;
    assert!(has_code(
        &semantic_too_large,
        FindingCode::InvalidPreprocessedContract
    ));

    for physical_length in [N - 1, N + 1] {
        let mut component = valid_component();
        component.preprocessed[0].physical_length = physical_length;
        component.preprocessed[0].values = Some((0..physical_length as u32).collect());
        component.preprocessed[0].values_hash = Some(airlock_ir::hash_u32_values(
            component.preprocessed[0].values.as_ref().unwrap(),
        ));
        assert!(has_code(
            &component,
            FindingCode::InvalidPreprocessedContract
        ));
    }
}

#[test]
fn concrete_preprocessed_values_are_content_addressed_and_canonical() {
    let mut missing_hash = valid_component();
    missing_hash.preprocessed[0].values_hash = None;
    assert!(has_code(
        &missing_hash,
        FindingCode::InvalidPreprocessedContract
    ));

    let mut wrong_hash = valid_component();
    wrong_hash.preprocessed[0].values_hash = Some("0".repeat(64));
    assert!(has_code(
        &wrong_hash,
        FindingCode::InvalidPreprocessedContract
    ));

    let mut noncanonical = valid_component();
    noncanonical.preprocessed[0].values.as_mut().unwrap()[0] = airlock_ir::M31_P;
    noncanonical.preprocessed[0].values_hash = Some(airlock_ir::hash_u32_values(
        noncanonical.preprocessed[0].values.as_ref().unwrap(),
    ));
    assert!(has_code(
        &noncanonical,
        FindingCode::InvalidPreprocessedContract
    ));
}

#[test]
fn generator_only_preprocessed_data_stays_blocked_without_a_resolver() {
    let mut component = valid_component();
    component.preprocessed[0].values = None;
    component.preprocessed[0].generator_id = Some("unregistered-generator-v1".into());
    component.preprocessed[0].values_hash = Some("0".repeat(64));

    let findings = lint_component(&component, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidPreprocessedContract
            && finding.message.contains("no registered resolver")
    }));
}

#[test]
fn row_support_policy_matrix_rejects_empty_reversed_and_out_of_domain_ranges() {
    let invalid = [
        RowSupport::Range { start: 0, end: 0 },
        RowSupport::Range { start: 9, end: 8 },
        RowSupport::Range {
            start: 0,
            end: N + 1,
        },
        RowSupport::Classes { classes: vec![] },
        RowSupport::Classes {
            classes: vec![RowClass::Active, RowClass::Active],
        },
    ];

    for support in invalid {
        let mut component = valid_component();
        component.relations[0].row_support = support;
        assert!(has_code(&component, FindingCode::InvalidRowSupport));
    }

    let mut valid_classes = valid_component();
    valid_classes.relations[0].row_support = RowSupport::Classes {
        classes: vec![RowClass::SemanticTable],
    };
    assert!(!has_code(&valid_classes, FindingCode::InvalidRowSupport));
}

#[test]
fn every_expression_read_must_match_a_declared_column_and_offset() {
    let mut unknown = valid_component();
    unknown.relations[0].tuple[0] = BaseExpr::column("missing");
    assert!(has_code(&unknown, FindingCode::InvalidColumnContract));

    let mut wrong_offset = valid_component();
    wrong_offset.relations[0].tuple[0] = BaseExpr::Column {
        id: "table".into(),
        offset: 1,
    };
    assert!(has_code(&wrong_offset, FindingCode::InvalidColumnContract));

    let mut duplicate = valid_component();
    duplicate.columns.push(duplicate.columns[0].clone());
    assert!(has_code(&duplicate, FindingCode::InvalidColumnContract));
}

#[test]
fn column_metadata_and_relation_shapes_fail_closed() {
    let mut empty_mask = valid_component();
    empty_mask.columns[1].offsets.clear();
    assert!(has_code(&empty_mask, FindingCode::InvalidColumnContract));

    let mut duplicate_offset = valid_component();
    duplicate_offset.columns[1].offsets.push(0);
    assert!(has_code(
        &duplicate_offset,
        FindingCode::InvalidColumnContract
    ));

    let mut wrong_phase = valid_component();
    wrong_phase.columns[1].commitment_phase = CommitmentPhase::Phase2Interaction;
    assert!(has_code(&wrong_phase, FindingCode::InvalidColumnContract));

    let mut wrong_interaction = valid_component();
    wrong_interaction.columns[1].interaction = Some(2);
    assert!(has_code(
        &wrong_interaction,
        FindingCode::InvalidColumnContract
    ));

    let mut reversed_range = valid_component();
    reversed_range.columns[1].declared_range = Some((1, -1));
    assert!(has_code(
        &reversed_range,
        FindingCode::InvalidColumnContract
    ));

    let mut named_other_label = valid_component();
    named_other_label.columns[1].semantic_type = SemanticType::Other {
        label: "lookup accumulator".into(),
    };
    assert!(
        !lint_component_structure(&named_other_label)
            .iter()
            .any(|finding| {
                finding.code == FindingCode::InvalidColumnContract
                    && finding.message.contains("without a nonempty label")
            })
    );

    let mut empty_other_label = named_other_label;
    empty_other_label.columns[1].semantic_type = SemanticType::Other {
        label: "   ".into(),
    };
    assert!(has_code(
        &empty_other_label,
        FindingCode::InvalidColumnContract
    ));

    let mut empty_name = valid_component();
    empty_name.name.clear();
    assert!(has_code(&empty_name, FindingCode::InvalidManifestStructure));

    let mut empty_tuple = valid_component();
    empty_tuple.relations[0].tuple.clear();
    assert!(has_code(
        &empty_tuple,
        FindingCode::InvalidManifestStructure
    ));

    let mut early_challenge = valid_component();
    early_challenge.relations[0].challenge_phase = CommitmentPhase::Phase1Original;
    assert!(has_code(
        &early_challenge,
        FindingCode::InvalidManifestStructure
    ));

    let interaction = ColumnDecl {
        id: "interaction".into(),
        name: "interaction".into(),
        interaction: Some(2),
        commitment_phase: CommitmentPhase::Phase2Interaction,
        offsets: vec![0],
        kind: ColumnKind::Interaction,
        semantic_type: SemanticType::Other {
            label: "lookup accumulator".into(),
        },
        declared_range: None,
        declared_support: None,
    };
    let mut cyclic_relation = valid_component();
    cyclic_relation.columns.push(interaction.clone());
    cyclic_relation.relations[0].tuple[0] = BaseExpr::column("interaction");
    assert!(
        lint_component_structure(&cyclic_relation)
            .iter()
            .any(|finding| {
                finding.code == FindingCode::InvalidColumnContract
                    && finding.message.contains("not committed before")
            })
    );

    let mut later_relation = valid_component();
    later_relation.columns.push(interaction);
    later_relation.relations[0].challenge_phase = CommitmentPhase::Phase3Reduction;
    later_relation.relations[0].tuple[0] = BaseExpr::column("interaction");
    assert!(
        !lint_component_structure(&later_relation)
            .iter()
            .any(|finding| {
                finding.code == FindingCode::InvalidColumnContract
                    && finding.message.contains("not committed before")
            })
    );
}

#[test]
fn relation_names_have_one_arity_and_challenge_phase() {
    let mut consistent = valid_component();
    let mut second_side = consistent.relations[0].clone();
    second_side.role = RelationRole::Query;
    consistent.relations.push(second_side);
    assert!(
        !lint_component_structure(&consistent)
            .iter()
            .any(|finding| finding.message.contains("identity contract"))
    );

    let mut arity_mismatch = valid_component();
    let mut wider = arity_mismatch.relations[0].clone();
    wider.tuple.push(BaseExpr::constant(0));
    arity_mismatch.relations.push(wider);
    assert!(
        lint_component_structure(&arity_mismatch)
            .iter()
            .any(|finding| finding.message.contains("identity contract"))
    );

    let mut phase_mismatch = valid_component();
    let mut later = phase_mismatch.relations[0].clone();
    later.challenge_phase = CommitmentPhase::Phase3Reduction;
    phase_mismatch.relations.push(later);
    assert!(
        lint_component_structure(&phase_mismatch)
            .iter()
            .any(|finding| finding.message.contains("identity contract"))
    );
}

#[test]
fn constraint_identity_and_support_fail_closed() {
    let constraint = ConstraintDecl {
        id: "duplicate".into(),
        expression: ExtExpr::Const { limbs: [0; 4] },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    };

    let mut duplicate = valid_component();
    duplicate.constraints = vec![constraint.clone(), constraint.clone()];
    assert!(has_code(&duplicate, FindingCode::InvalidManifestStructure));

    let mut empty_id = valid_component();
    empty_id.constraints = vec![ConstraintDecl {
        id: String::new(),
        ..constraint.clone()
    }];
    assert!(has_code(&empty_id, FindingCode::InvalidManifestStructure));

    let mut invalid_support = valid_component();
    invalid_support.constraints = vec![ConstraintDecl {
        row_support: RowSupport::Range { start: N, end: N },
        ..constraint
    }];
    assert!(has_code(&invalid_support, FindingCode::InvalidRowSupport));
}

#[test]
fn expression_constants_must_use_canonical_field_representatives() {
    let mut base = valid_component();
    base.relations[0].tuple[0] = BaseExpr::constant(airlock_ir::M31_P);
    assert!(lint_component_structure(&base).iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding.message.contains("noncanonical M31 constant")
    }));

    let mut extension = component_at_log_size(4);
    extension.constraints[0].expression = ExtExpr::Const {
        limbs: [0, airlock_ir::M31_P, 0, 0],
    };
    assert!(lint_component_structure(&extension).iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding.message.contains("noncanonical QM31")
    }));
}

#[test]
fn biased_encoder_uses_declared_bias_and_handles_width_endpoints_without_panics() {
    let one_bit = encoder_component(SignedEncoding::BiasedBits { bias: 1, bits: 1 }, 0);
    assert!(lint_encoder_bounds(&one_bit).is_empty());

    let exact = encoder_component(SignedEncoding::BiasedBits { bias: 128, bits: 8 }, 127);
    assert!(lint_encoder_bounds(&exact).is_empty());

    let outside = encoder_component(SignedEncoding::BiasedBits { bias: 128, bits: 8 }, 128);
    assert!(
        lint_encoder_bounds(&outside)
            .iter()
            .any(|finding| { finding.code == FindingCode::AdmittedBoundExceedsEncoder })
    );

    let asymmetric = encoder_component(SignedEncoding::BiasedBits { bias: 0, bits: 8 }, 1);
    assert!(
        lint_encoder_bounds(&asymmetric)
            .iter()
            .any(|finding| { finding.code == FindingCode::AdmittedBoundExceedsEncoder })
    );

    for encoding in [
        SignedEncoding::BiasedBits { bias: 0, bits: 0 },
        SignedEncoding::BiasedBits { bias: 0, bits: 31 },
        SignedEncoding::BiasedBits {
            bias: 1i128 << 126,
            bits: 127,
        },
        SignedEncoding::BiasedBits { bias: 0, bits: 128 },
        SignedEncoding::BiasedBits { bias: -1, bits: 8 },
        SignedEncoding::BiasedBits { bias: 256, bits: 8 },
    ] {
        let component = encoder_component(encoding, 0);
        assert!(
            lint_encoder_bounds(&component)
                .iter()
                .any(|finding| { finding.code == FindingCode::InvalidEncoderContract })
        );
    }

    let max_single_field_width = encoder_component(
        SignedEncoding::BiasedBits {
            bias: 1i128 << 29,
            bits: 30,
        },
        (1u128 << 29) - 1,
    );
    assert!(lint_encoder_bounds(&max_single_field_width).is_empty());
}

#[test]
fn integer_obligation_names_are_nonempty_and_unique() {
    let mut empty = encoder_component(SignedEncoding::CenteredM31, 1);
    empty.contract.integer_obligations[0].name.clear();
    assert!(
        lint_encoder_bounds(&empty)
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidEncoderContract)
    );

    let mut duplicate = encoder_component(SignedEncoding::CenteredM31, 1);
    duplicate
        .contract
        .integer_obligations
        .push(duplicate.contract.integer_obligations[0].clone());
    assert!(
        lint_encoder_bounds(&duplicate)
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidEncoderContract)
    );
}

#[test]
fn parameter_roles_bind_their_availability_phase() {
    let mut component = valid_component();
    component.parameters = vec![ParameterDecl {
        name: "challenge".into(),
        field: airlock_ir::FieldSort::Qm31,
        role: ParameterRole::FiatShamirChallenge,
        available_after: CommitmentPhase::Phase0Public,
    }];
    component.constraints = vec![ConstraintDecl {
        id: "challenge-use".into(),
        expression: ExtExpr::Param {
            name: "challenge".into(),
        },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    }];

    let findings = lint_component(&component, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidParameterContract
            && finding.message.contains("availability phase")
    }));

    for available_after in [
        CommitmentPhase::Phase2Interaction,
        CommitmentPhase::Phase3Reduction,
    ] {
        let mut valid_challenge = component_at_log_size(4);
        valid_challenge.parameters = vec![ParameterDecl {
            name: "challenge".into(),
            field: airlock_ir::FieldSort::Qm31,
            role: ParameterRole::FiatShamirChallenge,
            available_after,
        }];
        valid_challenge.constraints[0].expression = ExtExpr::Param {
            name: "challenge".into(),
        };
        assert!(
            !lint_component(&valid_challenge, &LintOptions::default())
                .iter()
                .any(|finding| finding.code == FindingCode::InvalidParameterContract),
            "valid Fiat-Shamir challenge phase {available_after:?} must pass"
        );
    }

    let mut cyclic_relation = valid_component();
    cyclic_relation.parameters = vec![ParameterDecl {
        name: "relation_challenge".into(),
        field: airlock_ir::FieldSort::M31,
        role: ParameterRole::FiatShamirChallenge,
        available_after: CommitmentPhase::Phase2Interaction,
    }];
    cyclic_relation.relations[0].tuple[0] = BaseExpr::param("relation_challenge");
    let findings = lint_component(&cyclic_relation, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidParameterContract
            && finding.message.contains("does not precede")
    }));

    cyclic_relation.relations[0].challenge_phase = CommitmentPhase::Phase3Reduction;
    let findings = lint_component(&cyclic_relation, &LintOptions::default());
    assert!(!findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidParameterContract
            && finding.message.contains("does not precede")
    }));

    let mut whitespace_name = valid_component();
    whitespace_name.parameters = vec![ParameterDecl {
        name: "   ".into(),
        field: airlock_ir::FieldSort::M31,
        role: ParameterRole::PublicInput,
        available_after: CommitmentPhase::Phase0Public,
    }];
    whitespace_name.relations[0].tuple[0] = BaseExpr::param("   ");
    assert!(
        lint_component(&whitespace_name, &LintOptions::default())
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidParameterContract)
    );
}

#[test]
fn duplicate_component_names_fail_at_manifest_boundary() {
    let component = valid_component();
    let manifest = AuditManifest::new("test", vec![component.clone(), component]);
    let findings = lint_manifest(&manifest, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding.message.contains("appears more than once")
    }));
}

#[test]
fn relation_identity_is_consistent_across_components() {
    let first = valid_component();
    let mut compatible = valid_component();
    compatible.name = "compatible".into();
    compatible.relations[0].role = RelationRole::Query;
    let findings = lint_manifest(
        &AuditManifest::new("test", vec![first.clone(), compatible]),
        &LintOptions::default(),
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.message.contains("conflicting with arity"))
    );

    let mut incompatible = valid_component();
    incompatible.name = "incompatible".into();
    incompatible.relations[0].tuple.push(BaseExpr::constant(0));
    let findings = lint_manifest(
        &AuditManifest::new("test", vec![first, incompatible]),
        &LintOptions::default(),
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.message.contains("conflicting with arity"))
    );

    let first = valid_component();
    let mut incompatible_phase = valid_component();
    incompatible_phase.name = "incompatible-phase".into();
    incompatible_phase.relations[0].challenge_phase = CommitmentPhase::Phase3Reduction;
    let findings = lint_manifest(
        &AuditManifest::new("test", vec![first, incompatible_phase]),
        &LintOptions::default(),
    );
    let phase_finding = findings
        .iter()
        .find(|finding| finding.message.contains("conflicting with arity"))
        .expect("cross-component challenge-phase mismatch must fail closed");
    assert!(phase_finding.message.contains("Phase3Reduction"));
    assert!(phase_finding.message.contains("Phase2Interaction"));
}

#[test]
fn semantic_contract_names_are_total_typed_and_unambiguous() {
    let mut valid = valid_component();
    valid.parameters.push(ParameterDecl {
        name: "statement_input".into(),
        field: airlock_ir::FieldSort::M31,
        role: ParameterRole::PublicInput,
        available_after: CommitmentPhase::Phase0Public,
    });
    valid.parameters.push(ParameterDecl {
        name: "receipt_claim".into(),
        field: airlock_ir::FieldSort::Qm31,
        role: ParameterRole::PublicClaim,
        available_after: CommitmentPhase::Phase0Public,
    });
    valid.relations[0].tuple[0] = BaseExpr::param("statement_input");
    valid.constraints.push(ConstraintDecl {
        id: "bind-receipt-claim".into(),
        expression: ExtExpr::Param {
            name: "receipt_claim".into(),
        },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    });
    valid.contract.public_inputs = vec!["statement_input".into()];
    valid.contract.public_claims = vec!["receipt_claim".into()];
    valid.columns[1].semantic_type = SemanticType::PublicOutput;
    valid.contract.public_outputs = vec!["multiplicity".into()];
    assert!(
        !lint_component_structure(&valid)
            .iter()
            .any(|finding| finding.message.contains("public "))
    );

    let mut column_input = valid_component();
    column_input.columns[0].semantic_type = SemanticType::PublicInput;
    column_input.contract.public_inputs = vec!["table".into()];
    assert!(
        !lint_component_structure(&column_input)
            .iter()
            .any(|finding| finding.message.contains("public input"))
    );

    let mut missing_input = valid_component();
    missing_input.contract.public_inputs = vec!["missing".into()];
    assert!(
        lint_component_structure(&missing_input)
            .iter()
            .any(|finding| finding
                .message
                .contains("public input `missing` must resolve"))
    );

    let mut wrong_input_role = valid_component();
    wrong_input_role.parameters.push(ParameterDecl {
        name: "claim".into(),
        field: airlock_ir::FieldSort::M31,
        role: ParameterRole::PublicClaim,
        available_after: CommitmentPhase::Phase0Public,
    });
    wrong_input_role.contract.public_inputs = vec!["claim".into()];
    assert!(
        lint_component_structure(&wrong_input_role)
            .iter()
            .any(|finding| finding
                .message
                .contains("public input `claim` must resolve"))
    );

    let mut witness_input = valid_component();
    witness_input.columns[1].semantic_type = SemanticType::PublicInput;
    witness_input.contract.public_inputs = vec!["multiplicity".into()];
    assert!(
        lint_component_structure(&witness_input)
            .iter()
            .any(|finding| finding.message.contains("Phase0Public column"))
    );

    let mut omitted_input = valid_component();
    omitted_input.parameters.push(ParameterDecl {
        name: "statement_input".into(),
        field: airlock_ir::FieldSort::M31,
        role: ParameterRole::PublicInput,
        available_after: CommitmentPhase::Phase0Public,
    });
    assert!(
        lint_component_structure(&omitted_input)
            .iter()
            .any(|finding| finding
                .message
                .contains("omitted from the semantic contract"))
    );

    let mut missing_output = valid_component();
    missing_output.contract.public_outputs = vec!["missing".into()];
    assert!(
        lint_component_structure(&missing_output)
            .iter()
            .any(|finding| finding
                .message
                .contains("public output `missing` must resolve"))
    );

    let mut missing_claim = valid_component();
    missing_claim.contract.public_claims = vec!["missing".into()];
    assert!(
        lint_component_structure(&missing_claim)
            .iter()
            .any(|finding| finding
                .message
                .contains("public claim `missing` must resolve"))
    );

    let mut omitted_claim = valid_component();
    omitted_claim.parameters.push(ParameterDecl {
        name: "receipt_claim".into(),
        field: airlock_ir::FieldSort::Qm31,
        role: ParameterRole::PublicClaim,
        available_after: CommitmentPhase::Phase0Public,
    });
    assert!(
        lint_component_structure(&omitted_claim)
            .iter()
            .any(|finding| finding
                .message
                .contains("PublicClaim parameter `receipt_claim` is omitted"))
    );

    let mut wrong_output_type = valid_component();
    wrong_output_type.contract.public_outputs = vec!["multiplicity".into()];
    assert!(
        lint_component_structure(&wrong_output_type)
            .iter()
            .any(|finding| {
                finding
                    .message
                    .contains("public output `multiplicity` must resolve")
            })
    );

    let mut omitted_output = valid_component();
    omitted_output.columns[1].semantic_type = SemanticType::PublicOutput;
    assert!(
        lint_component_structure(&omitted_output)
            .iter()
            .any(|finding| finding
                .message
                .contains("omitted from the semantic contract"))
    );

    let mut duplicate_and_empty = valid_component();
    duplicate_and_empty.contract.public_inputs = vec![" ".into(), "same".into(), "same".into()];
    assert!(
        lint_component_structure(&duplicate_and_empty)
            .iter()
            .any(|finding| finding.message.contains("names must not be empty"))
    );
    assert!(
        lint_component_structure(&duplicate_and_empty)
            .iter()
            .any(|finding| finding.message.contains("appears more than once"))
    );

    let mut overlapping = valid_component();
    overlapping.contract.public_inputs = vec!["value".into()];
    overlapping.contract.public_outputs = vec!["value".into()];
    assert!(
        lint_component_structure(&overlapping)
            .iter()
            .any(|finding| finding.message.contains("both inputs and outputs"))
    );
}

#[test]
fn empty_manifests_and_vacuous_components_never_report_static_pass() {
    let empty = AuditManifest::new("test", vec![]);
    let findings = lint_manifest(&empty, &LintOptions::default());
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding.message.contains("no components")
    }));

    let mut vacuous = valid_component();
    vacuous.relations.clear();
    vacuous.logup_finalized = false;
    assert!(lint_component_structure(&vacuous).iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding
                .message
                .contains("no syntactically nontrivial constraint")
    }));

    let mut zero_constraint = vacuous.clone();
    zero_constraint.constraints = vec![ConstraintDecl {
        id: "zero".into(),
        expression: ExtExpr::Const { limbs: [0; 4] },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    }];
    assert!(has_code(
        &zero_constraint,
        FindingCode::InvalidManifestStructure
    ));

    let mut wrapped_zero_constraint = vacuous.clone();
    wrapped_zero_constraint.constraints = vec![ConstraintDecl {
        id: "wrapped-zero".into(),
        expression: ExtExpr::Add {
            lhs: Box::new(ExtExpr::Const {
                limbs: [7, 11, 13, 17],
            }),
            rhs: Box::new(ExtExpr::Neg {
                inner: Box::new(ExtExpr::Const {
                    limbs: [7, 11, 13, 17],
                }),
            }),
        },
        row_support: RowSupport::All,
        source_location: None,
        semantic_claim: None,
    }];
    assert!(has_code(
        &wrapped_zero_constraint,
        FindingCode::InvalidManifestStructure
    ));

    let mut zero_relation = valid_component();
    zero_relation.relations[0].multiplicity = BaseExpr::constant(0);
    assert!(has_code(
        &zero_relation,
        FindingCode::InvalidManifestStructure
    ));

    let mut wrapped_zero_relation = valid_component();
    wrapped_zero_relation.relations[0].multiplicity = BaseExpr::Add {
        lhs: Box::new(BaseExpr::constant(9)),
        rhs: Box::new(BaseExpr::Neg {
            inner: Box::new(BaseExpr::constant(9)),
        }),
    };
    assert!(has_code(
        &wrapped_zero_relation,
        FindingCode::InvalidManifestStructure
    ));

    let mut impossible_constraint = component_at_log_size(4);
    impossible_constraint.constraints[0].expression = ExtExpr::Const {
        limbs: [1, 0, 0, 0],
    };
    assert!(
        lint_component_structure(&impossible_constraint)
            .iter()
            .any(|finding| {
                finding.code == FindingCode::InvalidManifestStructure
                    && finding.message.contains("cannot be satisfied")
            })
    );

    let mut wrapped_impossible = component_at_log_size(4);
    wrapped_impossible.constraints[0].expression = ExtExpr::Neg {
        inner: Box::new(ExtExpr::Const {
            limbs: [1, 0, 0, 0],
        }),
    };
    assert!(
        lint_component_structure(&wrapped_impossible)
            .iter()
            .any(|finding| {
                finding.code == FindingCode::InvalidManifestStructure
                    && finding.message.contains("constant nonzero")
            })
    );

    let mut undefined = component_at_log_size(4);
    undefined.constraints[0].expression = ExtExpr::FromBase {
        inner: BaseExpr::Inv {
            inner: Box::new(BaseExpr::constant(0)),
        },
    };
    assert!(lint_component_structure(&undefined).iter().any(|finding| {
        finding.code == FindingCode::InvalidManifestStructure
            && finding.message.contains("undefined constant-field")
    }));
}
