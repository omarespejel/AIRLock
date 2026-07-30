use airlock_boundary::{
    ProofGenerationOutcome, ProofRejectionCause, ScalarMutation, VerificationOutcome,
    WitnessCellPath, WitnessMutationOperation, WitnessPhase, WitnessVerdict,
};
use airlock_stwo::{StwoWitnessAdapter, StwoWitnessError};

fn replace(
    adapter: &StwoWitnessAdapter,
    phase: WitnessPhase,
    row: usize,
    value: ScalarMutation,
) -> WitnessMutationOperation {
    WitnessMutationOperation::ReplaceM31 {
        path: WitnessCellPath::new(phase, adapter.original_column_id(), row),
        value,
    }
}

#[test]
fn honest_witness_is_bound_to_audit_ir_and_the_full_verifier() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");
    let replay = adapter.replay_honest().expect("honest replay");

    replay.validate().expect("self-consistent replay");
    assert!(replay.observation.audit_ir_constraints_hold);
    assert!(matches!(
        replay.observation.proof_generation,
        ProofGenerationOutcome::Generated { .. }
    ));
    assert_eq!(
        replay.observation.verifier,
        Some(VerificationOutcome::Accepted)
    );
    assert_eq!(replay.report.verdict, WitnessVerdict::HonestAccepted);
    assert!(replay.report.verdict.is_expected());
}

#[test]
fn constraint_preserving_mutation_regenerates_and_verifies_a_real_proof() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");
    let replay = adapter
        .replay_mutation(
            "constant-one-witness",
            adapter.increment_all_rows_operations(),
        )
        .expect("constraint-preserving replay");

    assert!(replay.observation.audit_ir_constraints_hold);
    assert!(matches!(
        replay.observation.proof_generation,
        ProofGenerationOutcome::Generated { .. }
    ));
    assert_eq!(
        replay.observation.verifier,
        Some(VerificationOutcome::Accepted)
    );
    assert_eq!(
        replay.report.verdict,
        WitnessVerdict::ConstraintPreservingAccepted
    );
    assert!(replay.report.verdict.is_expected());
}

#[test]
fn incrementing_each_single_cell_is_rejected_before_verifier_replay() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");
    for row in 0..adapter.row_count() {
        let replay = adapter
            .replay_mutation(
                format!("single-cell-violation-{row}"),
                vec![
                    adapter
                        .increment_one_row_operation(row)
                        .expect("in-range row"),
                ],
            )
            .expect("constraint-violating replay");

        assert!(!replay.observation.audit_ir_constraints_hold, "row {row}");
        assert!(
            matches!(
                replay.observation.proof_generation,
                ProofGenerationOutcome::Rejected {
                    cause: ProofRejectionCause::ConstraintViolation,
                    ref kind,
                    ..
                } if kind == "constraints_not_satisfied"
            ),
            "row {row}"
        );
        assert_eq!(replay.observation.verifier, None, "row {row}");
        assert_eq!(
            replay.report.verdict,
            WitnessVerdict::ConstraintViolationRejected,
            "row {row}"
        );
        assert!(replay.report.verdict.is_expected(), "row {row}");
    }
}

#[test]
fn unsupported_phases_columns_rows_and_scalars_fail_closed() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");

    let phase = adapter
        .replay_mutation(
            "interaction-phase",
            vec![replace(
                &adapter,
                WitnessPhase::Interaction,
                0,
                ScalarMutation::Increment,
            )],
        )
        .expect_err("unsupported phase");
    assert!(matches!(
        phase,
        StwoWitnessError::UnsupportedPhase(WitnessPhase::Interaction)
    ));

    let column = adapter
        .replay_mutation(
            "foreign-column",
            vec![WitnessMutationOperation::ReplaceM31 {
                path: WitnessCellPath::new(WitnessPhase::Original, "trace_1_column_9", 0),
                value: ScalarMutation::Increment,
            }],
        )
        .expect_err("unsupported column");
    assert!(matches!(column, StwoWitnessError::UnsupportedColumn(_)));

    let row = adapter
        .replay_mutation(
            "foreign-row",
            vec![replace(
                &adapter,
                WitnessPhase::Original,
                adapter.row_count(),
                ScalarMutation::Increment,
            )],
        )
        .expect_err("out-of-range row");
    assert!(matches!(row, StwoWitnessError::RowOutOfBounds { .. }));

    let scalar = adapter
        .replay_mutation(
            "unsupported-scalar",
            vec![replace(
                &adapter,
                WitnessPhase::Original,
                0,
                ScalarMutation::Maximum,
            )],
        )
        .expect_err("unsupported scalar");
    assert!(matches!(scalar, StwoWitnessError::UnsupportedScalar { .. }));

    let flip_bit = adapter
        .replay_mutation(
            "unsupported-flip-bit",
            vec![replace(
                &adapter,
                WitnessPhase::Original,
                0,
                ScalarMutation::FlipBit { bit: 0 },
            )],
        )
        .expect_err("unsupported flip-bit scalar");
    assert!(matches!(
        flip_bit,
        StwoWitnessError::UnsupportedScalar { .. }
    ));

    let valid_operation = adapter
        .increment_one_row_operation(0)
        .expect("in-range row");
    let invalid_case_ids = [
        String::new(),
        "a".repeat(129),
        " leading-space".to_owned(),
        "trailing-space ".to_owned(),
        "invalid/character".to_owned(),
    ];
    for case_id in invalid_case_ids {
        let error = adapter
            .replay_mutation(case_id.clone(), vec![valid_operation.clone()])
            .expect_err("invalid campaign id");
        assert_eq!(error, StwoWitnessError::InvalidCaseId(case_id));
    }
}

#[test]
fn vacuous_mutations_and_tampered_reports_are_not_expected() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");
    let unchanged = adapter
        .replay_mutation(
            "no-op",
            vec![replace(
                &adapter,
                WitnessPhase::Original,
                0,
                ScalarMutation::Zero,
            )],
        )
        .expect_err("no-op mutation");
    assert!(matches!(unchanged, StwoWitnessError::InvalidPlan(_)));

    let mut replay = adapter.replay_honest().expect("honest replay");
    replay.report.verdict = WitnessVerdict::Counterexample;
    assert!(matches!(
        replay.validate(),
        Err(StwoWitnessError::InvalidReplay(_))
    ));
}
