//! Proof-system-neutral contracts for deterministic witness-mutation matrices.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CaseKind, ScalarMutation, WitnessCellPath, WitnessMutationOperation, WitnessObservation,
    WitnessPhase, WitnessReport, WitnessVerdict, evaluate_witness,
};

/// Stable schema identifier for witness-matrix artifacts.
pub const WITNESS_MATRIX_SCHEMA_ID: &str = "airlock.witness-matrix";

/// Serialized witness-matrix artifact version.
pub const WITNESS_MATRIX_SCHEMA_VERSION: &str = "0.1.0";

/// Declared mutation surface for one target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMatrixCapability {
    /// Stable target identity.
    pub target: String,
    /// Exact upstream source identity.
    pub upstream_commit: String,
    /// SHA-256 of the AuditIR relation used to classify mutations.
    pub audit_ir_sha256: String,
    /// Commitment phase containing every declared column.
    pub phase: WitnessPhase,
    /// Complete ordered column inventory.
    pub columns: Vec<String>,
    /// Physical rows in every declared column.
    pub row_count: usize,
    /// Complete ordered scalar-operator inventory.
    pub operators: Vec<ScalarMutation>,
}

/// One matrix cell replayed through AuditIR and a real proof path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMatrixCase {
    /// Canonical identity derived from the mutation tuple.
    pub case_id: String,
    /// Exact single-cell mutation.
    pub operation: WitnessMutationOperation,
    /// AuditIR, proof-generation, and verifier observation.
    pub observation: WitnessObservation,
    /// Recomputed fail-closed classification.
    pub report: WitnessReport,
}

/// Aggregate counts that retain relation-preserving and violating behavior.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMatrixCounts {
    /// Total matrix cases.
    pub total: usize,
    /// Relation-preserving mutations accepted by the proof path.
    pub constraint_preserving_accepted: usize,
    /// Relation-violating mutations rejected for a typed constraint cause.
    pub constraint_violation_rejected: usize,
    /// Every other fail-closed verdict.
    pub blocked: usize,
}

impl WitnessMatrixCounts {
    fn from_cases(cases: &[WitnessMatrixCase]) -> Self {
        let mut counts = Self {
            total: cases.len(),
            ..Self::default()
        };
        for case in cases {
            match case.report.verdict {
                WitnessVerdict::ConstraintPreservingAccepted => {
                    counts.constraint_preserving_accepted += 1;
                }
                WitnessVerdict::ConstraintViolationRejected => {
                    counts.constraint_violation_rejected += 1;
                }
                _ => counts.blocked += 1,
            }
        }
        counts
    }
}

/// Completion state for an exact mutation matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WitnessMatrixStatus {
    /// Every declared case produced one of the two expected mutation verdicts.
    Complete,
    /// At least one declared case was inconclusive or contradicted the oracle.
    Blocked,
}

/// Complete matrix for one declared target surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMatrixTarget {
    /// Exact declared mutation surface.
    pub capability: WitnessMatrixCapability,
    /// Canonically ordered complete case inventory.
    pub cases: Vec<WitnessMatrixCase>,
    /// Recomputed aggregate counts.
    pub counts: WitnessMatrixCounts,
    /// Recomputed completion state.
    pub status: WitnessMatrixStatus,
}

/// Cross-target deterministic malicious-witness campaign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessMatrixCampaign {
    /// Schema identity.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Stable matrix policy identity.
    pub matrix_id: String,
    /// Complete ordered target inventory.
    pub targets: Vec<WitnessMatrixTarget>,
    /// Explicit statements that a complete matrix does not establish.
    pub non_claims: Vec<String>,
}

impl WitnessMatrixCampaign {
    /// Validate identities, exact inventories, reports, counts, and status.
    pub fn validate(&self) -> Result<(), WitnessMatrixError> {
        if self.schema != WITNESS_MATRIX_SCHEMA_ID
            || self.schema_version != WITNESS_MATRIX_SCHEMA_VERSION
        {
            return Err(WitnessMatrixError::WrongSchema {
                schema: self.schema.clone(),
                version: self.schema_version.clone(),
            });
        }
        if !is_identifier(&self.matrix_id) {
            return Err(WitnessMatrixError::InvalidMatrixId);
        }
        if self.targets.is_empty() {
            return Err(WitnessMatrixError::EmptyTargets);
        }
        if self.non_claims.is_empty()
            || self.non_claims.iter().any(|claim| claim.trim().is_empty())
            || !all_unique(self.non_claims.iter().map(String::as_str))
        {
            return Err(WitnessMatrixError::InvalidNonClaims);
        }

        let mut targets = BTreeSet::new();
        for target in &self.targets {
            if !targets.insert(target.capability.target.as_str()) {
                return Err(WitnessMatrixError::DuplicateTarget(
                    target.capability.target.clone(),
                ));
            }
            target.validate()?;
        }
        Ok(())
    }

    /// Require a structurally valid campaign with no blocked target or case.
    pub fn require_complete(&self) -> Result<(), WitnessMatrixError> {
        self.validate()?;
        if let Some(target) = self
            .targets
            .iter()
            .find(|target| target.status != WitnessMatrixStatus::Complete)
        {
            return Err(WitnessMatrixError::CampaignBlocked(
                target.capability.target.clone(),
            ));
        }
        Ok(())
    }
}

impl WitnessMatrixTarget {
    /// Build a target with counts and status derived from its cases.
    pub fn from_cases(capability: WitnessMatrixCapability, cases: Vec<WitnessMatrixCase>) -> Self {
        let counts = WitnessMatrixCounts::from_cases(&cases);
        let status = if counts.blocked == 0 {
            WitnessMatrixStatus::Complete
        } else {
            WitnessMatrixStatus::Blocked
        };
        Self {
            capability,
            cases,
            counts,
            status,
        }
    }

    fn validate(&self) -> Result<(), WitnessMatrixError> {
        self.capability.validate()?;
        let expected_count = self
            .capability
            .columns
            .len()
            .checked_mul(self.capability.row_count)
            .and_then(|count| count.checked_mul(self.capability.operators.len()))
            .ok_or(WitnessMatrixError::InventoryOverflow)?;
        if self.cases.len() != expected_count {
            return Err(WitnessMatrixError::WrongCaseCount {
                target: self.capability.target.clone(),
                expected: expected_count,
                actual: self.cases.len(),
            });
        }

        let mut index = 0;
        for column in &self.capability.columns {
            for row in 0..self.capability.row_count {
                for operator in &self.capability.operators {
                    let case = &self.cases[index];
                    let expected_id = witness_matrix_case_id(column, row, *operator)?;
                    let expected_operation = WitnessMutationOperation::ReplaceM31 {
                        path: WitnessCellPath::new(self.capability.phase, column, row),
                        value: *operator,
                    };
                    if case.case_id != expected_id || case.operation != expected_operation {
                        return Err(WitnessMatrixError::WrongCaseTuple {
                            target: self.capability.target.clone(),
                            index,
                        });
                    }
                    case.validate(&self.capability)?;
                    index += 1;
                }
            }
        }

        let expected_counts = WitnessMatrixCounts::from_cases(&self.cases);
        let expected_status = if expected_counts.blocked == 0 {
            WitnessMatrixStatus::Complete
        } else {
            WitnessMatrixStatus::Blocked
        };
        if self.counts != expected_counts || self.status != expected_status {
            return Err(WitnessMatrixError::WrongAggregate(
                self.capability.target.clone(),
            ));
        }
        Ok(())
    }
}

impl WitnessMatrixCapability {
    fn validate(&self) -> Result<(), WitnessMatrixError> {
        if self.target.trim().is_empty() || self.upstream_commit.trim().is_empty() {
            return Err(WitnessMatrixError::InvalidCapabilityIdentity);
        }
        if !is_sha256(&self.audit_ir_sha256) {
            return Err(WitnessMatrixError::InvalidAuditIrDigest);
        }
        if self.columns.is_empty()
            || self.columns.iter().any(|column| !is_identifier(column))
            || !all_unique(self.columns.iter().map(String::as_str))
            || self.row_count == 0
        {
            return Err(WitnessMatrixError::InvalidCapabilityShape);
        }
        if self.operators.is_empty()
            || !all_unique(
                self.operators
                    .iter()
                    .map(|operator| scalar_mutation_label(*operator)),
            )
        {
            return Err(WitnessMatrixError::InvalidOperatorInventory);
        }
        Ok(())
    }
}

impl WitnessMatrixCase {
    fn validate(&self, capability: &WitnessMatrixCapability) -> Result<(), WitnessMatrixError> {
        self.observation
            .validate()
            .map_err(|error| WitnessMatrixError::InvalidObservation(error.to_string()))?;
        if self.observation.case_kind != CaseKind::Mutated
            || self.observation.target != capability.target
            || self.observation.upstream_commit != capability.upstream_commit
            || self.observation.audit_ir_sha256 != capability.audit_ir_sha256
            || self.observation.case_id != self.case_id
        {
            return Err(WitnessMatrixError::CaseIdentityMismatch(
                self.case_id.clone(),
            ));
        }
        let plan = self
            .observation
            .mutation
            .as_ref()
            .ok_or_else(|| WitnessMatrixError::CaseIdentityMismatch(self.case_id.clone()))?;
        if plan.operations.as_slice() != std::slice::from_ref(&self.operation) {
            return Err(WitnessMatrixError::CaseOperationMismatch(
                self.case_id.clone(),
            ));
        }
        let recomputed = evaluate_witness(&self.observation);
        if self.report != recomputed {
            return Err(WitnessMatrixError::WrongCaseReport(self.case_id.clone()));
        }
        Ok(())
    }
}

/// Derive the canonical case identity for one matrix tuple.
pub fn witness_matrix_case_id(
    column: &str,
    row: usize,
    mutation: ScalarMutation,
) -> Result<String, WitnessMatrixError> {
    if !is_identifier(column) {
        return Err(WitnessMatrixError::InvalidCaseColumn);
    }
    Ok(format!(
        "m31-{}-{column}-row-{row:08}",
        scalar_mutation_label(mutation)
    ))
}

fn scalar_mutation_label(mutation: ScalarMutation) -> String {
    match mutation {
        ScalarMutation::Zero => "zero".to_owned(),
        ScalarMutation::One => "one".to_owned(),
        ScalarMutation::Maximum => "maximum".to_owned(),
        ScalarMutation::Increment => "increment".to_owned(),
        ScalarMutation::Decrement => "decrement".to_owned(),
        ScalarMutation::FlipBit { bit } => format!("flip-bit-{bit}"),
    }
}

fn all_unique<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Malformed, incomplete, or contradictory matrices never become complete.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WitnessMatrixError {
    /// Unknown schema identity or version.
    #[error("unexpected witness-matrix schema `{schema}` version `{version}`")]
    WrongSchema {
        /// Supplied schema.
        schema: String,
        /// Supplied version.
        version: String,
    },
    /// Matrix policy identity is malformed.
    #[error("witness-matrix policy id is malformed")]
    InvalidMatrixId,
    /// A campaign without targets cannot establish an executed matrix.
    #[error("witness-matrix target inventory must not be empty")]
    EmptyTargets,
    /// Non-claims must be present, nonempty, and unique.
    #[error("witness-matrix non-claim inventory is malformed")]
    InvalidNonClaims,
    /// Target identity appears more than once.
    #[error("duplicate witness-matrix target `{0}`")]
    DuplicateTarget(String),
    /// Capability target or source identity is empty.
    #[error("witness-matrix capability identity is malformed")]
    InvalidCapabilityIdentity,
    /// AuditIR identity is not canonical SHA-256.
    #[error("witness-matrix AuditIR digest is malformed")]
    InvalidAuditIrDigest,
    /// Columns or rows do not declare a nonempty unique surface.
    #[error("witness-matrix capability shape is malformed")]
    InvalidCapabilityShape,
    /// Operators are empty or duplicated.
    #[error("witness-matrix operator inventory is malformed")]
    InvalidOperatorInventory,
    /// Inventory size overflowed.
    #[error("witness-matrix inventory size overflowed")]
    InventoryOverflow,
    /// Serialized case count differs from the declared Cartesian product.
    #[error("target `{target}` requires {expected} matrix cases, found {actual}")]
    WrongCaseCount {
        /// Target identity.
        target: String,
        /// Declared Cartesian-product size.
        expected: usize,
        /// Serialized case count.
        actual: usize,
    },
    /// Case order or tuple differs from the declared Cartesian product.
    #[error("target `{target}` has the wrong matrix tuple at index {index}")]
    WrongCaseTuple {
        /// Target identity.
        target: String,
        /// Wrong case index.
        index: usize,
    },
    /// Case column cannot be represented canonically.
    #[error("witness-matrix case column is malformed")]
    InvalidCaseColumn,
    /// Existing observation contract is malformed.
    #[error("invalid witness-matrix observation: {0}")]
    InvalidObservation(String),
    /// Observation identity differs from its target and case.
    #[error("witness-matrix case `{0}` has contradictory identity")]
    CaseIdentityMismatch(String),
    /// Mutation plan differs from the declared single operation.
    #[error("witness-matrix case `{0}` has contradictory operations")]
    CaseOperationMismatch(String),
    /// Stored report differs from the proof-neutral oracle.
    #[error("witness-matrix case `{0}` has a stale or contradictory report")]
    WrongCaseReport(String),
    /// Counts or status differ from the case inventory.
    #[error("witness-matrix target `{0}` has contradictory aggregate fields")]
    WrongAggregate(String),
    /// At least one case did not produce an expected conclusive verdict.
    #[error("witness-matrix target `{0}` is blocked")]
    CampaignBlocked(String),
}
