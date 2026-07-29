//! Generic verifier-boundary oracles.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    BoundaryContract, BoundaryContractError, BoundaryObservation, BoundaryPath, CaseKind,
    VerificationOutcome,
};

/// Severity for verifier-boundary findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundarySeverity {
    /// Informational coverage or execution status.
    Informational,
    /// High-confidence invariant violation that blocks the modeled lane.
    High,
}

/// Stable verifier-boundary finding codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryFindingCode {
    /// Verifier-boundary contract or observation is malformed.
    InvalidBoundaryContract,
    /// Verifier accepted a proof whose supplied cardinality differs from its request.
    BoundaryCardinalityMismatch,
    /// Verifier accepted proof data that was not consumed exactly.
    IgnoredProofData,
    /// Verifier accepted without consuming everything it requested.
    RequestedDataNotConsumed,
    /// Verifier panicked or aborted on untrusted proof input.
    VerifierPanic,
    /// Honest prover output was rejected by the matching verifier.
    HonestBaselineRejected,
    /// A mutated proof was unexpectedly accepted.
    UnexpectedMutationAccepted,
    /// Boundary execution timed out and remains inconclusive.
    BoundaryTimeout,
    /// Boundary target is not modeled by the current adapter.
    BoundaryUnsupported,
}

/// One verifier-boundary finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryFinding {
    /// Stable finding identity.
    pub code: BoundaryFindingCode,
    /// Blocking importance inside the modeled lane.
    pub severity: BoundarySeverity,
    /// Human-readable diagnostic.
    pub message: String,
    /// Stable paths, layers, or labels related to the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

/// Fail-closed verdict for one boundary execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryVerdict {
    /// Honest proof accepted and every measured cardinality matched.
    Accepted,
    /// Mutated proof was rejected with a typed error.
    Rejected,
    /// A generic invariant produced a replayable counterexample.
    Counterexample,
    /// The verifier panicked or aborted.
    Panic,
    /// Execution did not finish within its budget.
    Timeout,
    /// Cross-layer behavior violates a declared relation.
    Divergence,
    /// The adapter or artifact is unsupported or malformed.
    Unsupported,
}

impl BoundaryVerdict {
    /// Whether this execution is an expected, conclusive result.
    pub const fn is_green(self) -> bool {
        matches!(self, Self::Accepted | Self::Rejected)
    }
}

/// Report for one verifier-boundary execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryReport {
    /// Target verifier or proof surface.
    pub target: String,
    /// Exact source identity exercised by this report.
    pub upstream_commit: String,
    /// Test-case identity.
    pub case_id: String,
    /// Target verifier layer.
    pub layer: String,
    /// Final boundary verdict.
    pub verdict: BoundaryVerdict,
    /// Generic invariant findings.
    pub findings: Vec<BoundaryFinding>,
}

/// Evaluate one verifier execution against its independently derived request contract.
pub fn evaluate_boundary(
    contract: &BoundaryContract,
    observation: &BoundaryObservation,
) -> BoundaryReport {
    if let Err(error) = validate_artifacts(contract, observation) {
        return report(
            observation,
            BoundaryVerdict::Unsupported,
            vec![finding(
                BoundaryFindingCode::InvalidBoundaryContract,
                BoundarySeverity::High,
                format!("invalid boundary artifact: {error}"),
                vec![],
            )],
        );
    }

    match &observation.outcome {
        VerificationOutcome::Panicked { message } => report(
            observation,
            BoundaryVerdict::Panic,
            vec![finding(
                BoundaryFindingCode::VerifierPanic,
                BoundarySeverity::High,
                format!(
                    "verifier panicked on {} case: {message}",
                    case_name(observation)
                ),
                vec![observation.layer.clone()],
            )],
        ),
        VerificationOutcome::TimedOut => report(
            observation,
            BoundaryVerdict::Timeout,
            vec![finding(
                BoundaryFindingCode::BoundaryTimeout,
                BoundarySeverity::Informational,
                "boundary execution timed out; no security conclusion is available".to_owned(),
                vec![observation.layer.clone()],
            )],
        ),
        VerificationOutcome::Unsupported { reason } => report(
            observation,
            BoundaryVerdict::Unsupported,
            vec![finding(
                BoundaryFindingCode::BoundaryUnsupported,
                BoundarySeverity::Informational,
                format!("boundary adapter does not support this case: {reason}"),
                vec![observation.layer.clone()],
            )],
        ),
        VerificationOutcome::Rejected { kind, message } => {
            if observation.case_kind == CaseKind::Honest {
                report(
                    observation,
                    BoundaryVerdict::Counterexample,
                    vec![finding(
                        BoundaryFindingCode::HonestBaselineRejected,
                        BoundarySeverity::High,
                        format!("honest proof was rejected as {kind}: {message}"),
                        vec![observation.layer.clone()],
                    )],
                )
            } else {
                report(observation, BoundaryVerdict::Rejected, vec![])
            }
        }
        VerificationOutcome::Accepted => evaluate_accepted(contract, observation),
    }
}

fn validate_artifacts(
    contract: &BoundaryContract,
    observation: &BoundaryObservation,
) -> Result<(), BoundaryContractError> {
    contract.validate()?;
    observation.validate()?;
    if contract.target != observation.target {
        return Err(BoundaryContractError::TargetMismatch {
            expected: contract.target.clone(),
            observed: observation.target.clone(),
        });
    }
    if contract.upstream_commit != observation.upstream_commit {
        return Err(BoundaryContractError::UpstreamCommitMismatch {
            expected: contract.upstream_commit.clone(),
            observed: observation.upstream_commit.clone(),
        });
    }
    Ok(())
}

fn evaluate_accepted(
    contract: &BoundaryContract,
    observation: &BoundaryObservation,
) -> BoundaryReport {
    let requested = count_map(&contract.requested);
    let supplied = count_map(&observation.supplied);
    let consumed = count_map(&observation.consumed);
    let mut findings = vec![];

    let request_supply = mismatches(&requested, &supplied);
    if !request_supply.is_empty() {
        findings.push(finding(
            BoundaryFindingCode::BoundaryCardinalityMismatch,
            BoundarySeverity::High,
            "verifier accepted proof data whose cardinality differs from its request".to_owned(),
            request_supply,
        ));
    }

    let supply_consumption = mismatches(&supplied, &consumed);
    if !supply_consumption.is_empty() {
        findings.push(finding(
            BoundaryFindingCode::IgnoredProofData,
            BoundarySeverity::High,
            "verifier accepted proof data that was not consumed exactly".to_owned(),
            supply_consumption,
        ));
    }

    let request_consumption = mismatches(&requested, &consumed);
    if !request_consumption.is_empty() {
        findings.push(finding(
            BoundaryFindingCode::RequestedDataNotConsumed,
            BoundarySeverity::High,
            "verifier accepted without consuming exactly the data it requested".to_owned(),
            request_consumption,
        ));
    }

    if findings.is_empty() && observation.case_kind == CaseKind::Mutated {
        findings.push(finding(
            BoundaryFindingCode::UnexpectedMutationAccepted,
            BoundarySeverity::High,
            "verifier accepted a mutated proof without a declared acceptance contract".to_owned(),
            vec![observation.layer.clone()],
        ));
    }

    let verdict = if findings.is_empty() {
        BoundaryVerdict::Accepted
    } else {
        BoundaryVerdict::Counterexample
    };
    report(observation, verdict, findings)
}

fn report(
    observation: &BoundaryObservation,
    verdict: BoundaryVerdict,
    findings: Vec<BoundaryFinding>,
) -> BoundaryReport {
    BoundaryReport {
        target: observation.target.clone(),
        upstream_commit: observation.upstream_commit.clone(),
        case_id: observation.case_id.clone(),
        layer: observation.layer.clone(),
        verdict,
        findings,
    }
}

fn finding(
    code: BoundaryFindingCode,
    severity: BoundarySeverity,
    message: String,
    related: Vec<String>,
) -> BoundaryFinding {
    BoundaryFinding {
        code,
        severity,
        message,
        related,
    }
}

fn case_name(observation: &BoundaryObservation) -> &'static str {
    match observation.case_kind {
        CaseKind::Honest => "honest",
        CaseKind::Mutated => "mutated",
    }
}

fn count_map(entries: &[crate::CountAtPath]) -> BTreeMap<BoundaryPath, usize> {
    entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.count))
        .collect()
}

fn mismatches(
    left: &BTreeMap<BoundaryPath, usize>,
    right: &BTreeMap<BoundaryPath, usize>,
) -> Vec<String> {
    let paths: BTreeSet<&BoundaryPath> = left.keys().chain(right.keys()).collect();
    paths
        .into_iter()
        .filter_map(|path| {
            let left_count = left.get(path);
            let right_count = right.get(path);
            (left_count != right_count).then(|| format_path(path, left_count, right_count))
        })
        .collect()
}

fn format_path(path: &BoundaryPath, left: Option<&usize>, right: Option<&usize>) -> String {
    let indices = path
        .indices
        .iter()
        .map(|index| format!("[{index}]"))
        .collect::<String>();
    format!(
        "{}{indices}:left={}:right={}",
        path.field,
        left.map_or_else(|| "missing".to_owned(), usize::to_string),
        right.map_or_else(|| "missing".to_owned(), usize::to_string)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CountAtPath, MutationOperation, MutationPlan};

    fn path() -> BoundaryPath {
        BoundaryPath::new("sampled_values", vec![1, 0])
    }

    fn contract(count: usize) -> BoundaryContract {
        BoundaryContract::new(
            "tiny-proof",
            "0123456789abcdef",
            vec![CountAtPath::new(path(), count)],
        )
    }

    fn mutation() -> MutationPlan {
        MutationPlan {
            seed_id: "honest-1".to_owned(),
            seed_artifact_sha256: "11".repeat(32),
            mutated_artifact_sha256: "22".repeat(32),
            operations: vec![MutationOperation::Drop {
                path: path(),
                index: 1,
            }],
        }
    }

    fn observation(
        kind: CaseKind,
        supplied: usize,
        consumed: usize,
        outcome: VerificationOutcome,
    ) -> BoundaryObservation {
        BoundaryObservation {
            target: "tiny-proof".to_owned(),
            upstream_commit: "0123456789abcdef".to_owned(),
            case_id: "case-1".to_owned(),
            layer: "raw_pcs".to_owned(),
            case_kind: kind,
            mutation: (kind == CaseKind::Mutated).then(mutation),
            supplied: vec![CountAtPath::new(path(), supplied)],
            consumed: vec![CountAtPath::new(path(), consumed)],
            outcome,
        }
    }

    #[test]
    fn honest_exact_acceptance_is_green() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(CaseKind::Honest, 2, 2, VerificationOutcome::Accepted),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Accepted);
        assert!(report.verdict.is_green());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn rejected_mutation_is_green() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(
                CaseKind::Mutated,
                1,
                0,
                VerificationOutcome::Rejected {
                    kind: "invalid_structure".to_owned(),
                    message: "sample count mismatch".to_owned(),
                },
            ),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Rejected);
        assert!(report.verdict.is_green());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn accepted_missing_value_is_a_counterexample() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(CaseKind::Mutated, 1, 1, VerificationOutcome::Accepted),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Counterexample);
        assert!(
            report.findings.iter().any(|finding| {
                finding.code == BoundaryFindingCode::BoundaryCardinalityMismatch
            })
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == BoundaryFindingCode::RequestedDataNotConsumed })
        );
    }

    #[test]
    fn accepted_extra_value_cannot_be_ignored() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(CaseKind::Mutated, 3, 2, VerificationOutcome::Accepted),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Counterexample);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == BoundaryFindingCode::IgnoredProofData)
        );
    }

    #[test]
    fn accepted_count_preserving_mutation_is_never_green() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(CaseKind::Mutated, 2, 2, VerificationOutcome::Accepted),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Counterexample);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::UnexpectedMutationAccepted
        );
    }

    #[test]
    fn accepted_unchanged_mutation_artifact_is_unsupported() {
        let mut unchanged = observation(CaseKind::Mutated, 2, 2, VerificationOutcome::Accepted);
        let mutation = unchanged.mutation.as_mut().expect("mutated case");
        mutation.mutated_artifact_sha256 = mutation.seed_artifact_sha256.clone();

        let report = evaluate_boundary(&contract(2), &unchanged);
        assert_eq!(report.verdict, BoundaryVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::InvalidBoundaryContract
        );
    }

    #[test]
    fn malformed_rejection_category_is_unsupported() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(
                CaseKind::Mutated,
                1,
                0,
                VerificationOutcome::Rejected {
                    kind: " Invalid Structure ".to_owned(),
                    message: "bad proof".to_owned(),
                },
            ),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::InvalidBoundaryContract
        );
    }

    #[test]
    fn verifier_panic_is_never_green() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(
                CaseKind::Mutated,
                1,
                0,
                VerificationOutcome::Panicked {
                    message: "assertion failed".to_owned(),
                },
            ),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Panic);
        assert!(!report.verdict.is_green());
        assert_eq!(report.findings[0].code, BoundaryFindingCode::VerifierPanic);
    }

    #[test]
    fn rejected_honest_proof_is_a_completeness_counterexample() {
        let report = evaluate_boundary(
            &contract(2),
            &observation(
                CaseKind::Honest,
                2,
                2,
                VerificationOutcome::Rejected {
                    kind: "invalid".to_owned(),
                    message: "unexpected".to_owned(),
                },
            ),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Counterexample);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::HonestBaselineRejected
        );
    }

    #[test]
    fn timeout_and_unsupported_stay_non_green() {
        let timeout = evaluate_boundary(
            &contract(2),
            &observation(CaseKind::Mutated, 1, 0, VerificationOutcome::TimedOut),
        );
        assert_eq!(timeout.verdict, BoundaryVerdict::Timeout);
        assert!(!timeout.verdict.is_green());

        let unsupported = evaluate_boundary(
            &contract(2),
            &observation(
                CaseKind::Mutated,
                1,
                0,
                VerificationOutcome::Unsupported {
                    reason: "foreign proof".to_owned(),
                },
            ),
        );
        assert_eq!(unsupported.verdict, BoundaryVerdict::Unsupported);
        assert!(!unsupported.verdict.is_green());
    }

    #[test]
    fn malformed_artifacts_fail_closed() {
        let mut invalid = contract(2);
        invalid.requested.push(CountAtPath::new(path(), 2));
        let report = evaluate_boundary(
            &invalid,
            &observation(CaseKind::Honest, 2, 2, VerificationOutcome::Accepted),
        );
        assert_eq!(report.verdict, BoundaryVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::InvalidBoundaryContract
        );
    }

    #[test]
    fn source_identity_mismatch_fails_closed() {
        let mut wrong_target = observation(CaseKind::Honest, 2, 2, VerificationOutcome::Accepted);
        wrong_target.target = "another-proof".to_owned();
        let report = evaluate_boundary(&contract(2), &wrong_target);
        assert_eq!(report.verdict, BoundaryVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::InvalidBoundaryContract
        );

        let mut wrong_commit = observation(CaseKind::Honest, 2, 2, VerificationOutcome::Accepted);
        wrong_commit.upstream_commit = "different".to_owned();
        let report = evaluate_boundary(&contract(2), &wrong_commit);
        assert_eq!(report.verdict, BoundaryVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            BoundaryFindingCode::InvalidBoundaryContract
        );
    }
}
