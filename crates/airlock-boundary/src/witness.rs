//! Proof-system-neutral contracts for pre-commitment witness injection.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CaseKind, ScalarMutation, VerificationOutcome};

/// Stable schema identifier for witness-injection artifacts.
pub const WITNESS_SCHEMA_ID: &str = "airlock.witness-observation";

/// Serialized witness-injection artifact version.
pub const WITNESS_SCHEMA_VERSION: &str = "0.1.0";

/// Maximum number of operations accepted by one witness-mutation plan.
pub const MAX_WITNESS_MUTATIONS: usize = 128;

/// Commitment phase owning a witness cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessPhase {
    /// Public or preprocessed values fixed before the original trace.
    Public,
    /// Original prover trace committed before relation challenges.
    Original,
    /// Interaction trace derived after relation challenges.
    Interaction,
    /// Later reduction or composition data.
    Reduction,
}

/// Stable address of one field cell before it is committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCellPath {
    /// Commitment phase that must own the column.
    pub phase: WitnessPhase,
    /// AuditIR column identity.
    pub column: String,
    /// Physical row in the committed evaluation order.
    pub row: usize,
}

impl WitnessCellPath {
    /// Construct a phase-bound witness-cell path.
    pub fn new(phase: WitnessPhase, column: impl Into<String>, row: usize) -> Self {
        Self {
            phase,
            column: column.into(),
            row,
        }
    }
}

/// One deterministic pre-commitment witness mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum WitnessMutationOperation {
    /// Replace one M31 cell using a canonical scalar strategy.
    ReplaceM31 {
        /// Exact phase, column, and row.
        path: WitnessCellPath,
        /// Deterministic scalar mutation.
        value: ScalarMutation,
    },
}

/// Content-addressed mutation plan applied before witness commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMutationPlan {
    /// Stable target name.
    pub target: String,
    /// Exact upstream source identity.
    pub upstream_commit: String,
    /// Stable seed identity.
    pub seed_id: String,
    /// SHA-256 of the canonical seed witness.
    pub seed_witness_sha256: String,
    /// SHA-256 of the canonical mutated witness.
    pub mutated_witness_sha256: String,
    /// Ordered pre-commitment mutations.
    pub operations: Vec<WitnessMutationOperation>,
}

impl WitnessMutationPlan {
    /// Validate replay identity and fail closed on vacuous or ambiguous plans.
    pub fn validate(&self) -> Result<(), WitnessContractError> {
        if self.target.trim().is_empty() {
            return Err(WitnessContractError::EmptyTarget);
        }
        if self.upstream_commit.trim().is_empty() {
            return Err(WitnessContractError::EmptyUpstreamCommit);
        }
        if self.seed_id.trim().is_empty() {
            return Err(WitnessContractError::EmptySeedId);
        }
        if !is_sha256(&self.seed_witness_sha256) {
            return Err(WitnessContractError::InvalidDigest("seed_witness_sha256"));
        }
        if !is_sha256(&self.mutated_witness_sha256) {
            return Err(WitnessContractError::InvalidDigest(
                "mutated_witness_sha256",
            ));
        }
        if self.seed_witness_sha256 == self.mutated_witness_sha256 {
            return Err(WitnessContractError::UnchangedWitness);
        }
        if self.operations.is_empty() || self.operations.len() > MAX_WITNESS_MUTATIONS {
            return Err(WitnessContractError::InvalidOperationCount(
                self.operations.len(),
            ));
        }
        for operation in &self.operations {
            let WitnessMutationOperation::ReplaceM31 { path, .. } = operation;
            if path.column.trim().is_empty() {
                return Err(WitnessContractError::EmptyColumn);
            }
        }
        Ok(())
    }
}

/// Outcome of regenerating a proof from an injected witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofGenerationOutcome {
    /// A complete proof was generated from the committed mutated witness.
    Generated {
        /// SHA-256 of the generated proof artifact.
        proof_sha256: String,
    },
    /// The prover rejected the witness with a typed result.
    Rejected {
        /// Stable rejection category.
        kind: String,
        /// Diagnostic message.
        message: String,
    },
    /// Proof generation failed for an adapter or prover infrastructure reason.
    InfrastructureFailure {
        /// Stable failure category.
        kind: String,
        /// Diagnostic message.
        message: String,
    },
    /// Proof generation unwound or aborted.
    Panicked {
        /// Captured panic diagnostic.
        message: String,
    },
    /// The proof-generation deadline expired.
    TimedOut,
    /// The adapter cannot construct this witness or phase.
    Unsupported {
        /// Unsupported surface description.
        reason: String,
    },
}

/// One AuditIR and real-prover observation over the same injected witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessObservation {
    /// Schema identity.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Stable target identity.
    pub target: String,
    /// Exact upstream source identity.
    pub upstream_commit: String,
    /// Stable campaign case id.
    pub case_id: String,
    /// Honest or mutated witness.
    pub case_kind: CaseKind,
    /// Mutation record for an adversarial case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<WitnessMutationPlan>,
    /// SHA-256 of the exact AuditIR manifest used as the relation oracle.
    pub audit_ir_sha256: String,
    /// Whether every concretely evaluated AuditIR constraint was zero.
    pub audit_ir_constraints_hold: bool,
    /// Result of committing the witness and regenerating a proof.
    pub proof_generation: ProofGenerationOutcome,
    /// Full verifier outcome when proof generation produced an artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<VerificationOutcome>,
}

impl WitnessObservation {
    /// Validate artifact identity and cross-field consistency.
    pub fn validate(&self) -> Result<(), WitnessContractError> {
        if self.schema != WITNESS_SCHEMA_ID || self.schema_version != WITNESS_SCHEMA_VERSION {
            return Err(WitnessContractError::WrongSchema {
                schema: self.schema.clone(),
                version: self.schema_version.clone(),
            });
        }
        if self.target.trim().is_empty() {
            return Err(WitnessContractError::EmptyTarget);
        }
        if self.upstream_commit.trim().is_empty() {
            return Err(WitnessContractError::EmptyUpstreamCommit);
        }
        if self.case_id.trim().is_empty() {
            return Err(WitnessContractError::EmptyCaseId);
        }
        if !is_sha256(&self.audit_ir_sha256) {
            return Err(WitnessContractError::InvalidDigest("audit_ir_sha256"));
        }
        match (self.case_kind, &self.mutation) {
            (CaseKind::Honest, None) => {}
            (CaseKind::Honest, Some(_)) => {
                return Err(WitnessContractError::UnexpectedMutation);
            }
            (CaseKind::Mutated, Some(plan)) => {
                plan.validate()?;
                if plan.target != self.target || plan.upstream_commit != self.upstream_commit {
                    return Err(WitnessContractError::MutationIdentityMismatch);
                }
                if plan.seed_id != self.case_id {
                    return Err(WitnessContractError::MutationCaseMismatch);
                }
            }
            (CaseKind::Mutated, None) => return Err(WitnessContractError::MissingMutation),
        }
        match (&self.proof_generation, &self.verifier) {
            (ProofGenerationOutcome::Generated { proof_sha256 }, Some(_)) => {
                if !is_sha256(proof_sha256) {
                    return Err(WitnessContractError::InvalidDigest("proof_sha256"));
                }
            }
            (ProofGenerationOutcome::Generated { .. }, None) => {
                return Err(WitnessContractError::MissingVerifierOutcome);
            }
            (_, Some(_)) => return Err(WitnessContractError::UnexpectedVerifierOutcome),
            (_, None) => {}
        }
        Ok(())
    }
}

/// Stable witness-injection finding categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WitnessFindingCode {
    /// Artifact identity or shape is malformed.
    InvalidWitnessContract,
    /// AuditIR and the real proof path disagree on an invalid witness.
    InvalidWitnessAccepted,
    /// AuditIR accepts a witness that the real proof path cannot complete.
    ConstraintPreservingWitnessRejected,
    /// Honest baseline does not satisfy the exported relation.
    HonestRelationRejected,
    /// A verifier or prover panic occurred.
    Panic,
    /// Adapter or prover infrastructure failed before a conclusive result.
    InfrastructureFailure,
    /// A bounded operation timed out.
    Timeout,
    /// The requested phase or target is unsupported.
    Unsupported,
}

/// One finding attached to a witness-injection report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessFinding {
    /// Stable finding category.
    pub code: WitnessFindingCode,
    /// Human-readable diagnostic.
    pub message: String,
}

/// Fail-closed classification of one injected witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WitnessVerdict {
    /// Honest relation-holding witness proved and verified.
    HonestAccepted,
    /// Mutated relation-holding witness proved and verified.
    ConstraintPreservingAccepted,
    /// Relation-violating witness was rejected by the prover or verifier.
    ConstraintViolationRejected,
    /// A relation-violating witness reached verifier acceptance.
    Counterexample,
    /// The honest witness does not satisfy the exported AuditIR relation.
    HonestRelationFailure,
    /// A relation-holding witness failed to prove or verify.
    CompletenessFailure,
    /// Adapter or prover infrastructure failed before a conclusive result.
    InfrastructureFailure,
    /// A verifier or prover panic occurred.
    Panic,
    /// A bounded operation timed out.
    Timeout,
    /// The campaign or artifact is unsupported or malformed.
    Unsupported,
}

impl WitnessVerdict {
    /// Whether this scoped campaign produced its expected conclusive outcome.
    pub const fn is_expected(self) -> bool {
        matches!(
            self,
            Self::HonestAccepted
                | Self::ConstraintPreservingAccepted
                | Self::ConstraintViolationRejected
        )
    }
}

/// Recomputed witness-injection report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReport {
    /// Stable campaign case id.
    pub case_id: String,
    /// Fail-closed result.
    pub verdict: WitnessVerdict,
    /// Findings explaining non-expected outcomes.
    pub findings: Vec<WitnessFinding>,
}

/// Classify one validated AuditIR/prover/verifier observation.
pub fn evaluate_witness(observation: &WitnessObservation) -> WitnessReport {
    if let Err(error) = observation.validate() {
        return report(
            observation,
            WitnessVerdict::Unsupported,
            WitnessFindingCode::InvalidWitnessContract,
            error.to_string(),
        );
    }

    if let Some(verdict) = exceptional_verdict(observation) {
        return verdict;
    }

    match (
        observation.case_kind,
        observation.audit_ir_constraints_hold,
        &observation.proof_generation,
        &observation.verifier,
    ) {
        (
            CaseKind::Honest,
            true,
            ProofGenerationOutcome::Generated { .. },
            Some(VerificationOutcome::Accepted),
        ) => expected(observation, WitnessVerdict::HonestAccepted),
        (CaseKind::Honest, false, _, _) => report(
            observation,
            WitnessVerdict::HonestRelationFailure,
            WitnessFindingCode::HonestRelationRejected,
            "honest witness does not satisfy the exported AuditIR relation".to_owned(),
        ),
        (
            CaseKind::Mutated,
            true,
            ProofGenerationOutcome::Generated { .. },
            Some(VerificationOutcome::Accepted),
        ) => expected(observation, WitnessVerdict::ConstraintPreservingAccepted),
        (CaseKind::Mutated, true, _, _) | (CaseKind::Honest, true, _, _) => report(
            observation,
            WitnessVerdict::CompletenessFailure,
            WitnessFindingCode::ConstraintPreservingWitnessRejected,
            "AuditIR relation holds, but the real proof path did not accept the witness".to_owned(),
        ),
        (
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::Generated { .. },
            Some(VerificationOutcome::Accepted),
        ) => report(
            observation,
            WitnessVerdict::Counterexample,
            WitnessFindingCode::InvalidWitnessAccepted,
            "real verifier accepted a witness that violates the exported AuditIR relation"
                .to_owned(),
        ),
        (CaseKind::Mutated, false, _, _) => {
            expected(observation, WitnessVerdict::ConstraintViolationRejected)
        }
    }
}

fn exceptional_verdict(observation: &WitnessObservation) -> Option<WitnessReport> {
    // Validation permits verifier outcomes only after Generated. The verifier-side
    // alternatives below therefore classify generated proofs; adapters must not
    // attach a captured verifier result to any other proof-generation outcome.
    match (&observation.proof_generation, &observation.verifier) {
        (ProofGenerationOutcome::InfrastructureFailure { message, .. }, _) => Some(report(
            observation,
            WitnessVerdict::InfrastructureFailure,
            WitnessFindingCode::InfrastructureFailure,
            message.clone(),
        )),
        (ProofGenerationOutcome::Panicked { message }, _)
        | (_, Some(VerificationOutcome::Panicked { message })) => Some(report(
            observation,
            WitnessVerdict::Panic,
            WitnessFindingCode::Panic,
            message.clone(),
        )),
        (ProofGenerationOutcome::TimedOut, _) | (_, Some(VerificationOutcome::TimedOut)) => {
            Some(report(
                observation,
                WitnessVerdict::Timeout,
                WitnessFindingCode::Timeout,
                "witness campaign timed out".to_owned(),
            ))
        }
        (ProofGenerationOutcome::Unsupported { reason }, _)
        | (_, Some(VerificationOutcome::Unsupported { reason })) => Some(report(
            observation,
            WitnessVerdict::Unsupported,
            WitnessFindingCode::Unsupported,
            reason.clone(),
        )),
        _ => None,
    }
}

fn expected(observation: &WitnessObservation, verdict: WitnessVerdict) -> WitnessReport {
    WitnessReport {
        case_id: observation.case_id.clone(),
        verdict,
        findings: vec![],
    }
}

fn report(
    observation: &WitnessObservation,
    verdict: WitnessVerdict,
    code: WitnessFindingCode,
    message: String,
) -> WitnessReport {
    WitnessReport {
        case_id: observation.case_id.clone(),
        verdict,
        findings: vec![WitnessFinding { code, message }],
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Malformed witness artifacts cannot become expected results.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WitnessContractError {
    /// Unknown schema identity or version.
    #[error("unexpected witness schema `{schema}` version `{version}`")]
    WrongSchema {
        /// Supplied schema.
        schema: String,
        /// Supplied version.
        version: String,
    },
    /// Target identity is empty.
    #[error("witness target must not be empty")]
    EmptyTarget,
    /// Source identity is empty.
    #[error("witness upstream commit must not be empty")]
    EmptyUpstreamCommit,
    /// Seed identity is empty.
    #[error("witness seed id must not be empty")]
    EmptySeedId,
    /// Case identity is empty.
    #[error("witness case id must not be empty")]
    EmptyCaseId,
    /// Mutation column identity is empty.
    #[error("witness mutation column must not be empty")]
    EmptyColumn,
    /// Canonical digest is malformed.
    #[error("invalid SHA-256 digest in `{0}`")]
    InvalidDigest(&'static str),
    /// Mutation did not alter the canonical witness.
    #[error("witness mutation did not change the canonical artifact")]
    UnchangedWitness,
    /// Mutation operation list is empty or exceeds its bound.
    #[error("invalid witness mutation operation count {0}")]
    InvalidOperationCount(usize),
    /// Honest observations cannot contain a mutation.
    #[error("honest witness observation unexpectedly contains a mutation")]
    UnexpectedMutation,
    /// Mutated observations require a plan.
    #[error("mutated witness observation is missing its mutation plan")]
    MissingMutation,
    /// Mutation target/source differs from the observation.
    #[error("witness mutation identity does not match its observation")]
    MutationIdentityMismatch,
    /// Mutation case identity differs from the observation.
    #[error("witness mutation case id does not match its observation")]
    MutationCaseMismatch,
    /// Generated proofs require a verifier execution.
    #[error("generated witness proof is missing its verifier outcome")]
    MissingVerifierOutcome,
    /// A verifier outcome cannot exist without a generated proof.
    #[error("witness observation contains a verifier outcome without a generated proof")]
    UnexpectedVerifierOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated() -> ProofGenerationOutcome {
        ProofGenerationOutcome::Generated {
            proof_sha256: "44".repeat(32),
        }
    }

    fn mutation() -> WitnessMutationPlan {
        WitnessMutationPlan {
            target: "target".to_owned(),
            upstream_commit: "source".to_owned(),
            seed_id: "case".to_owned(),
            seed_witness_sha256: "11".repeat(32),
            mutated_witness_sha256: "22".repeat(32),
            operations: vec![WitnessMutationOperation::ReplaceM31 {
                path: WitnessCellPath::new(WitnessPhase::Original, "trace_1_column_0", 0),
                value: ScalarMutation::Increment,
            }],
        }
    }

    fn observation(
        kind: CaseKind,
        holds: bool,
        proof_generation: ProofGenerationOutcome,
        verifier: Option<VerificationOutcome>,
    ) -> WitnessObservation {
        WitnessObservation {
            schema: WITNESS_SCHEMA_ID.to_owned(),
            schema_version: WITNESS_SCHEMA_VERSION.to_owned(),
            target: "target".to_owned(),
            upstream_commit: "source".to_owned(),
            case_id: "case".to_owned(),
            case_kind: kind,
            mutation: (kind == CaseKind::Mutated).then(mutation),
            audit_ir_sha256: "33".repeat(32),
            audit_ir_constraints_hold: holds,
            proof_generation,
            verifier,
        }
    }

    #[test]
    fn honest_and_constraint_preserving_witnesses_are_expected() {
        let honest = evaluate_witness(&observation(
            CaseKind::Honest,
            true,
            generated(),
            Some(VerificationOutcome::Accepted),
        ));
        assert_eq!(honest.verdict, WitnessVerdict::HonestAccepted);
        assert!(honest.verdict.is_expected());

        let mutated = evaluate_witness(&observation(
            CaseKind::Mutated,
            true,
            generated(),
            Some(VerificationOutcome::Accepted),
        ));
        assert_eq!(
            mutated.verdict,
            WitnessVerdict::ConstraintPreservingAccepted
        );
        assert!(mutated.verdict.is_expected());
    }

    #[test]
    fn relation_violation_must_not_reach_verifier_acceptance() {
        let rejected = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::Rejected {
                kind: "constraints_not_satisfied".to_owned(),
                message: "relation is nonzero".to_owned(),
            },
            None,
        ));
        assert_eq!(
            rejected.verdict,
            WitnessVerdict::ConstraintViolationRejected
        );
        assert!(rejected.verdict.is_expected());

        let accepted = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            generated(),
            Some(VerificationOutcome::Accepted),
        ));
        assert_eq!(accepted.verdict, WitnessVerdict::Counterexample);
        assert_eq!(
            accepted.findings[0].code,
            WitnessFindingCode::InvalidWitnessAccepted
        );
    }

    #[test]
    fn relation_holding_rejection_is_a_completeness_failure() {
        let result = evaluate_witness(&observation(
            CaseKind::Mutated,
            true,
            ProofGenerationOutcome::Rejected {
                kind: "constraints_not_satisfied".to_owned(),
                message: "unexpected".to_owned(),
            },
            None,
        ));
        assert_eq!(result.verdict, WitnessVerdict::CompletenessFailure);
        assert!(!result.verdict.is_expected());
    }

    #[test]
    fn honest_relation_rejection_is_an_exporter_failure() {
        let result = evaluate_witness(&observation(
            CaseKind::Honest,
            false,
            ProofGenerationOutcome::Rejected {
                kind: "constraints_not_satisfied".to_owned(),
                message: "unexpected".to_owned(),
            },
            None,
        ));
        assert_eq!(result.verdict, WitnessVerdict::HonestRelationFailure);
        assert_eq!(
            result.findings[0].code,
            WitnessFindingCode::HonestRelationRejected
        );
        assert!(!result.verdict.is_expected());
    }

    #[test]
    fn malformed_or_exceptional_observations_fail_closed() {
        let mut malformed = observation(
            CaseKind::Mutated,
            true,
            generated(),
            Some(VerificationOutcome::Accepted),
        );
        malformed
            .mutation
            .as_mut()
            .expect("mutation")
            .operations
            .clear();
        assert_eq!(
            evaluate_witness(&malformed).verdict,
            WitnessVerdict::Unsupported
        );

        let panic = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::Panicked {
                message: "panic".to_owned(),
            },
            None,
        ));
        assert_eq!(panic.verdict, WitnessVerdict::Panic);
        assert!(!panic.verdict.is_expected());

        let timeout = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::TimedOut,
            None,
        ));
        assert_eq!(timeout.verdict, WitnessVerdict::Timeout);
        assert!(!timeout.verdict.is_expected());

        let unsupported = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::Unsupported {
                reason: "phase is outside the adapter".to_owned(),
            },
            None,
        ));
        assert_eq!(unsupported.verdict, WitnessVerdict::Unsupported);
        assert!(!unsupported.verdict.is_expected());

        let infrastructure_failure = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::InfrastructureFailure {
                kind: "prover".to_owned(),
                message: "prover infrastructure failed".to_owned(),
            },
            None,
        ));
        assert_eq!(
            infrastructure_failure.verdict,
            WitnessVerdict::InfrastructureFailure
        );
        assert!(!infrastructure_failure.verdict.is_expected());

        let unexpected_verifier = evaluate_witness(&observation(
            CaseKind::Mutated,
            false,
            ProofGenerationOutcome::Rejected {
                kind: "constraints_not_satisfied".to_owned(),
                message: "rejected".to_owned(),
            },
            Some(VerificationOutcome::Rejected {
                kind: "invalid_structure".to_owned(),
                message: "must not be attached".to_owned(),
            }),
        ));
        assert_eq!(unexpected_verifier.verdict, WitnessVerdict::Unsupported);
        assert_eq!(
            unexpected_verifier.findings[0].code,
            WitnessFindingCode::InvalidWitnessContract
        );
        assert!(!unexpected_verifier.verdict.is_expected());
    }
}
