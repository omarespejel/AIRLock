use std::panic::{AssertUnwindSafe, catch_unwind};

use airlock_boundary::{
    ProofGenerationOutcome, ProofRejectionCause, ScalarMutation, VerificationOutcome,
    WitnessCellPath, WitnessMutationOperation, WitnessPhase, WitnessVerdict,
};
use airlock_stwo::{HeldOutAdapter, HeldOutError, STWO_HELD_OUT_TARGET};

fn replace(
    phase: WitnessPhase,
    column: &str,
    row: usize,
    value: ScalarMutation,
) -> WitnessMutationOperation {
    WitnessMutationOperation::ReplaceM31 {
        path: WitnessCellPath::new(phase, column, row),
        value,
    }
}

#[test]
fn held_out_request_and_columns_come_from_the_upstream_component() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");

    assert_eq!(adapter.contract().target, STWO_HELD_OUT_TARGET);
    assert_eq!(
        adapter.original_column_ids(),
        ["trace_1_column_0", "trace_1_column_1", "trace_1_column_2"]
    );
    let original_requests = adapter
        .contract()
        .requested
        .iter()
        .filter(|entry| entry.path.indices.first() == Some(&1))
        .collect::<Vec<_>>();
    assert_eq!(original_requests.len(), 3);
    for (column, entry) in original_requests.into_iter().enumerate() {
        assert_eq!(entry.path.field, "sampled_values");
        assert_eq!(entry.path.indices, [1, column]);
        assert_eq!(entry.count, 1);
    }
}

#[test]
fn honest_held_out_witness_proves_and_verifies() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");
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
}

#[test]
fn coordinated_increment_preserves_the_relation_at_every_row() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");

    for row in 0..adapter.row_count() {
        let replay = adapter
            .replay_mutation(
                format!("wide-fibonacci-preserving-row-{row}"),
                adapter
                    .preserving_operations_at_row(row)
                    .expect("in-range row"),
            )
            .expect("constraint-preserving replay");

        assert!(replay.observation.audit_ir_constraints_hold, "row {row}");
        assert!(matches!(
            replay.observation.proof_generation,
            ProofGenerationOutcome::Generated { .. }
        ));
        assert_eq!(
            replay.observation.verifier,
            Some(VerificationOutcome::Accepted),
            "row {row}"
        );
        assert_eq!(
            replay.report.verdict,
            WitnessVerdict::ConstraintPreservingAccepted,
            "row {row}"
        );
    }
}

#[test]
fn incrementing_only_the_output_is_rejected_at_every_row() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");

    for row in 0..adapter.row_count() {
        let replay = adapter
            .replay_mutation(
                format!("wide-fibonacci-violating-row-{row}"),
                vec![adapter.increment_operation(2, row).expect("in-range row")],
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
    }
}

#[test]
fn unsupported_held_out_mutations_return_errors_without_unwinding() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");
    let column = adapter.original_column_ids()[0].clone();
    let cases = vec![
        replace(
            WitnessPhase::Interaction,
            &column,
            0,
            ScalarMutation::Increment,
        ),
        replace(
            WitnessPhase::Original,
            "trace_1_column_99",
            0,
            ScalarMutation::Increment,
        ),
        replace(
            WitnessPhase::Original,
            &column,
            adapter.row_count(),
            ScalarMutation::Increment,
        ),
        replace(WitnessPhase::Original, &column, 0, ScalarMutation::Maximum),
        replace(
            WitnessPhase::Original,
            &column,
            0,
            ScalarMutation::FlipBit { bit: 0 },
        ),
    ];

    for (index, operation) in cases.into_iter().enumerate() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            adapter.replay_mutation(format!("unsupported-{index}"), vec![operation])
        }));
        assert!(result.is_ok(), "case {index} unwound");
        assert!(
            result.expect("checked unwind").is_err(),
            "case {index} did not fail closed"
        );
    }

    assert!(matches!(
        adapter.increment_operation(3, 0),
        Err(HeldOutError::ColumnOutOfBounds { .. })
    ));
}

#[test]
fn tampered_held_out_replays_do_not_validate() {
    let adapter = HeldOutAdapter::new().expect("held-out adapter");

    let mut report = adapter.replay_honest().expect("honest replay");
    report.report.verdict = WitnessVerdict::Counterexample;
    assert!(matches!(
        report.validate(),
        Err(HeldOutError::InvalidReplay(_))
    ));

    let mut contract = adapter.replay_honest().expect("honest replay");
    contract.contract.target = "semantic-substitution".to_owned();
    assert!(matches!(
        contract.validate(),
        Err(HeldOutError::InvalidReplay(_))
    ));

    let mut request = adapter.replay_honest().expect("honest replay");
    request.contract.requested[0].count += 1;
    assert!(matches!(
        request.validate(),
        Err(HeldOutError::InvalidReplay(_))
    ));

    let mut audit_ir = adapter.replay_honest().expect("honest replay");
    audit_ir.observation.audit_ir_sha256 = "a".repeat(64);
    assert!(matches!(
        audit_ir.validate(),
        Err(HeldOutError::InvalidReplay(_))
    ));
}
