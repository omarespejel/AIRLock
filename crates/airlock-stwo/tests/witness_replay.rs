use airlock_boundary::{
    ProofGenerationOutcome, ScalarMutation, VerificationOutcome, WitnessCellPath,
    WitnessMutationOperation, WitnessPhase, WitnessVerdict,
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
    let operations = (0..adapter.row_count())
        .map(|row| {
            replace(
                &adapter,
                WitnessPhase::Original,
                row,
                ScalarMutation::Increment,
            )
        })
        .collect();
    let replay = adapter
        .replay_mutation("constant-one-witness", operations)
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
fn every_single_cell_relation_violation_is_rejected_before_verifier_replay() {
    let adapter = StwoWitnessAdapter::new().expect("adapter");
    for row in 0..adapter.row_count() {
        let replay = adapter
            .replay_mutation(
                format!("single-cell-violation-{row}"),
                vec![replace(
                    &adapter,
                    WitnessPhase::Original,
                    row,
                    ScalarMutation::Increment,
                )],
            )
            .expect("constraint-violating replay");

        assert!(!replay.observation.audit_ir_constraints_hold, "row {row}");
        assert!(
            matches!(
                replay.observation.proof_generation,
                ProofGenerationOutcome::Rejected { ref kind, .. }
                    if kind == "constraints_not_satisfied"
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
