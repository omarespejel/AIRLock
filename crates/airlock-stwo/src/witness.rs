//! Phase-bound pre-commitment witness injection for the pinned demo AIR.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

use airlock_boundary::{
    CONSTRAINT_VIOLATION_REJECTION_KIND, CaseKind, MAX_WITNESS_MUTATIONS, ProofGenerationOutcome,
    ProofRejectionCause, ScalarMutation, WITNESS_SCHEMA_ID, WITNESS_SCHEMA_VERSION,
    WitnessCellPath, WitnessMutationOperation, WitnessMutationPlan, WitnessObservation,
    WitnessPhase, WitnessReport, evaluate_witness,
};
use airlock_export::{ConcreteAssignment, ExportAnnotations, constraints_hold, export_component};
use airlock_ir::{AuditManifest, ColumnKind, CommitmentPhase, M31_P, SemanticType, hash_manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::adapter::{capture_verifier, verify_framework};
use crate::fixture::{
    DEMO_LOG_ROWS, DemoFixtureBuildError, build_demo_fixture_with_values, transition_eval,
};
use crate::{STWO_SOURCE_ID, proof_sha256};

/// Stable identity of the scoped pre-commitment witness campaign.
pub const STWO_DEMO_WITNESS_TARGET: &str = "stwo-demo-transition-witness-v1";

const MAX_CASE_ID_BYTES: usize = 128;
const DEMO_ORIGINAL_COLUMN_ID: &str = "trace_1_column_0";

/// AuditIR and real-proof replay of one phase-bound witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StwoWitnessReplay {
    /// Exact AuditIR/prover/verifier observation.
    pub observation: WitnessObservation,
    /// Recomputed fail-closed classification.
    pub report: WitnessReport,
}

impl StwoWitnessReplay {
    /// Revalidate artifact identity and recompute the report.
    pub fn validate(&self) -> Result<(), StwoWitnessError> {
        self.observation
            .validate()
            .map_err(|error| StwoWitnessError::InvalidReplay(error.to_string()))?;
        if self.observation.target != STWO_DEMO_WITNESS_TARGET
            || self.observation.upstream_commit != STWO_SOURCE_ID
        {
            return Err(StwoWitnessError::InvalidReplay(
                "witness replay is not bound to the pinned target and source".to_owned(),
            ));
        }
        let canonical_audit_ir_sha256 = canonical_audit_ir_sha256()?;
        if self.observation.audit_ir_sha256 != canonical_audit_ir_sha256 {
            return Err(StwoWitnessError::InvalidReplay(
                "witness AuditIR digest differs from the exported component".to_owned(),
            ));
        }
        let recomputed = evaluate_witness(&self.observation);
        if recomputed != self.report {
            return Err(StwoWitnessError::InvalidReplay(
                "witness report does not match its observation".to_owned(),
            ));
        }
        Ok(())
    }
}

fn canonical_audit_ir_sha256() -> Result<&'static str, StwoWitnessError> {
    static DIGEST: OnceLock<Result<String, StwoWitnessError>> = OnceLock::new();
    match DIGEST
        .get_or_init(|| StwoWitnessAdapter::new().and_then(|adapter| adapter.audit_ir_sha256()))
    {
        Ok(digest) => Ok(digest),
        Err(error) => Err(error.clone()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DemoWitness {
    original_column: Vec<u32>,
}

impl DemoWitness {
    fn honest() -> Self {
        Self {
            original_column: vec![0; 1 << DEMO_LOG_ROWS],
        }
    }
}

/// Executable bridge from AuditIR assignments to a real Stwo proof path.
pub struct StwoWitnessAdapter {
    manifest: AuditManifest,
    column_id: String,
    seed: DemoWitness,
}

impl StwoWitnessAdapter {
    /// Export and validate the pinned demo AIR used by this campaign.
    pub fn new() -> Result<Self, StwoWitnessError> {
        let mut annotations = ExportAnnotations {
            component_name: STWO_DEMO_WITNESS_TARGET.to_owned(),
            ..ExportAnnotations::default()
        };
        annotations.column_semantics.insert(
            DEMO_ORIGINAL_COLUMN_ID.to_owned(),
            SemanticType::Other {
                label: "demo_transition_state".to_owned(),
            },
        );
        let manifest = export_component(&transition_eval(), annotations)
            .map_err(|error| StwoWitnessError::Export(error.to_string()))?;
        let component = manifest
            .components
            .first()
            .ok_or(StwoWitnessError::MissingComponent)?;
        let mut witness_columns = component.columns.iter().filter(|column| {
            column.kind == ColumnKind::Witness
                && column.commitment_phase == CommitmentPhase::Phase1Original
        });
        let column_id = witness_columns
            .next()
            .ok_or(StwoWitnessError::MissingOriginalColumn)?
            .id
            .clone();
        if witness_columns.next().is_some() {
            return Err(StwoWitnessError::AmbiguousOriginalColumns);
        }
        if column_id != DEMO_ORIGINAL_COLUMN_ID {
            return Err(StwoWitnessError::OriginalColumnIdentityMismatch {
                expected: DEMO_ORIGINAL_COLUMN_ID.to_owned(),
                actual: column_id,
            });
        }
        Ok(Self {
            manifest,
            column_id,
            seed: DemoWitness::honest(),
        })
    }

    /// AuditIR column accepted by the scoped original-phase adapter.
    pub fn original_column_id(&self) -> &str {
        &self.column_id
    }

    /// Physical row count of the committed original column.
    pub fn row_count(&self) -> usize {
        self.seed.original_column.len()
    }

    /// SHA-256 of the exact exported AuditIR manifest.
    pub fn audit_ir_sha256(&self) -> Result<String, StwoWitnessError> {
        hash_manifest(&self.manifest)
            .map_err(|error| StwoWitnessError::Serialization(error.to_string()))
            .map(|digest| digest.0)
    }

    /// Regenerate and verify the unmodified witness.
    pub fn replay_honest(&self) -> Result<StwoWitnessReplay, StwoWitnessError> {
        self.replay("honest-witness", CaseKind::Honest, self.seed.clone(), None)
    }

    /// Build the deterministic all-row increment used by the preserving demo case.
    pub fn increment_all_rows_operations(&self) -> Vec<WitnessMutationOperation> {
        (0..self.row_count())
            .map(|row| self.increment_operation(row))
            .collect()
    }

    /// Build one deterministic original-column increment after validating its row.
    pub fn increment_one_row_operation(
        &self,
        row: usize,
    ) -> Result<WitnessMutationOperation, StwoWitnessError> {
        self.mutation_operation(row, ScalarMutation::Increment)
    }

    /// Build one typed original-column scalar mutation after validating its row.
    pub fn mutation_operation(
        &self,
        row: usize,
        mutation: ScalarMutation,
    ) -> Result<WitnessMutationOperation, StwoWitnessError> {
        if row >= self.row_count() {
            return Err(StwoWitnessError::RowOutOfBounds {
                row,
                rows: self.row_count(),
            });
        }
        Ok(WitnessMutationOperation::ReplaceM31 {
            path: WitnessCellPath::new(WitnessPhase::Original, &self.column_id, row),
            value: mutation,
        })
    }

    /// Apply phase-bound cell mutations before commitment and replay the real proof path.
    pub fn replay_mutation(
        &self,
        case_id: impl Into<String>,
        operations: Vec<WitnessMutationOperation>,
    ) -> Result<StwoWitnessReplay, StwoWitnessError> {
        let case_id = case_id.into();
        validate_case_id(&case_id)?;
        if operations.is_empty() || operations.len() > MAX_WITNESS_MUTATIONS {
            return Err(StwoWitnessError::InvalidOperationCount(operations.len()));
        }
        let seed_witness_sha256 = witness_sha256(&self.seed)?;
        let mut witness = self.seed.clone();
        for operation in &operations {
            self.apply_operation(&mut witness, operation)?;
        }
        let mutated_witness_sha256 = witness_sha256(&witness)?;
        let plan = WitnessMutationPlan {
            target: STWO_DEMO_WITNESS_TARGET.to_owned(),
            upstream_commit: STWO_SOURCE_ID.to_owned(),
            seed_id: case_id.clone(),
            seed_witness_sha256,
            mutated_witness_sha256,
            operations,
        };
        plan.validate()
            .map_err(|error| StwoWitnessError::InvalidPlan(error.to_string()))?;
        self.replay(&case_id, CaseKind::Mutated, witness, Some(plan))
    }

    fn apply_operation(
        &self,
        witness: &mut DemoWitness,
        operation: &WitnessMutationOperation,
    ) -> Result<(), StwoWitnessError> {
        let WitnessMutationOperation::ReplaceM31 { path, value } = operation;
        if path.phase != WitnessPhase::Original {
            return Err(StwoWitnessError::UnsupportedPhase(path.phase));
        }
        if path.column != self.column_id {
            return Err(StwoWitnessError::UnsupportedColumn(path.column.clone()));
        }
        let cell =
            witness
                .original_column
                .get_mut(path.row)
                .ok_or(StwoWitnessError::RowOutOfBounds {
                    row: path.row,
                    rows: self.row_count(),
                })?;
        *cell = mutate_m31(*cell, *value, path)?;
        Ok(())
    }

    fn replay(
        &self,
        case_id: &str,
        case_kind: CaseKind,
        witness: DemoWitness,
        mutation: Option<WitnessMutationPlan>,
    ) -> Result<StwoWitnessReplay, StwoWitnessError> {
        let component = self
            .manifest
            .components
            .first()
            .ok_or(StwoWitnessError::MissingComponent)?;
        let assignment = ConcreteAssignment {
            columns: BTreeMap::from([(self.column_id.clone(), witness.original_column.clone())]),
            ..ConcreteAssignment::default()
        };
        let audit_ir_constraints_hold = constraints_hold(component, &assignment)
            .map_err(|error| StwoWitnessError::ConcreteEvaluation(error.to_string()))?;
        let audit_ir_sha256 = self.audit_ir_sha256()?;

        let (proof_generation, verifier) = match catch_unwind(AssertUnwindSafe(|| {
            build_demo_fixture_with_values(&witness.original_column)
        })) {
            Ok(Ok(fixture)) => {
                let digest = proof_sha256(&fixture.proof)
                    .map_err(|error| StwoWitnessError::Serialization(error.to_string()))?;
                let verifier = capture_verifier(|| {
                    verify_framework(&fixture.component, fixture.config, fixture.proof)
                });
                (
                    ProofGenerationOutcome::Generated {
                        proof_sha256: digest,
                    },
                    Some(verifier),
                )
            }
            Ok(Err(DemoFixtureBuildError::ConstraintsNotSatisfied)) => (
                ProofGenerationOutcome::Rejected {
                    cause: ProofRejectionCause::ConstraintViolation,
                    kind: CONSTRAINT_VIOLATION_REJECTION_KIND.to_owned(),
                    message: "Stwo prover rejected the committed witness".to_owned(),
                },
                None,
            ),
            Ok(Err(DemoFixtureBuildError::InvalidWitnessLength { expected, actual })) => (
                ProofGenerationOutcome::InfrastructureFailure {
                    kind: "invalid_witness_length".to_owned(),
                    message: format!("adapter supplied {actual} witness rows; expected {expected}"),
                },
                None,
            ),
            Ok(Err(DemoFixtureBuildError::NoncanonicalWitness { row, value })) => (
                ProofGenerationOutcome::InfrastructureFailure {
                    kind: "noncanonical_witness".to_owned(),
                    message: format!(
                        "adapter supplied noncanonical M31 value {value} at witness row {row}"
                    ),
                },
                None,
            ),
            Ok(Err(DemoFixtureBuildError::Prover(message))) => (
                ProofGenerationOutcome::InfrastructureFailure {
                    kind: "prover".to_owned(),
                    message,
                },
                None,
            ),
            Err(payload) => (
                ProofGenerationOutcome::Panicked {
                    message: panic_message(payload),
                },
                None,
            ),
        };

        let observation = WitnessObservation {
            schema: WITNESS_SCHEMA_ID.to_owned(),
            schema_version: WITNESS_SCHEMA_VERSION.to_owned(),
            target: STWO_DEMO_WITNESS_TARGET.to_owned(),
            upstream_commit: STWO_SOURCE_ID.to_owned(),
            case_id: case_id.to_owned(),
            case_kind,
            mutation,
            audit_ir_sha256,
            audit_ir_constraints_hold,
            proof_generation,
            verifier,
        };
        let report = evaluate_witness(&observation);
        let replay = StwoWitnessReplay {
            observation,
            report,
        };
        replay.validate()?;
        Ok(replay)
    }

    fn increment_operation(&self, row: usize) -> WitnessMutationOperation {
        WitnessMutationOperation::ReplaceM31 {
            path: WitnessCellPath::new(WitnessPhase::Original, &self.column_id, row),
            value: ScalarMutation::Increment,
        }
    }
}

fn mutate_m31(
    current: u32,
    mutation: ScalarMutation,
    path: &WitnessCellPath,
) -> Result<u32, StwoWitnessError> {
    Ok(match mutation {
        ScalarMutation::Zero => 0,
        ScalarMutation::One => 1,
        ScalarMutation::Increment => {
            if current + 1 == M31_P {
                0
            } else {
                current + 1
            }
        }
        ScalarMutation::Decrement => {
            if current == 0 {
                M31_P - 1
            } else {
                current - 1
            }
        }
        ScalarMutation::Maximum | ScalarMutation::FlipBit { .. } => {
            return Err(StwoWitnessError::UnsupportedScalar {
                path: path.clone(),
                mutation,
            });
        }
    })
}

fn witness_sha256(witness: &DemoWitness) -> Result<String, StwoWitnessError> {
    let row_count = u64::try_from(witness.original_column.len())
        .map_err(|error| StwoWitnessError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"airlock.demo-witness.v1\0");
    hasher.update(row_count.to_le_bytes());
    for value in &witness.original_column {
        hasher.update(value.to_le_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_case_id(case_id: &str) -> Result<(), StwoWitnessError> {
    if case_id.is_empty()
        || case_id.len() > MAX_CASE_ID_BYTES
        || case_id.trim() != case_id
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StwoWitnessError::InvalidCaseId(case_id.to_owned()));
    }
    Ok(())
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

/// Failure to construct or validate the scoped Stwo witness campaign.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StwoWitnessError {
    /// Stwo `FrameworkEval` export failed.
    #[error("could not export the demo AIR: {0}")]
    Export(String),
    /// Export unexpectedly contained no component.
    #[error("demo AuditIR manifest contains no component")]
    MissingComponent,
    /// Export unexpectedly contained no original-phase witness column.
    #[error("demo AuditIR manifest contains no original-phase witness column")]
    MissingOriginalColumn,
    /// The scoped fixture must contain exactly one original witness column.
    #[error("demo AuditIR manifest contains multiple original-phase witness columns")]
    AmbiguousOriginalColumns,
    /// Exported original column does not match the annotated identity.
    #[error("demo original column identity changed from `{expected}` to `{actual}`")]
    OriginalColumnIdentityMismatch {
        /// Identity carrying the semantic annotation.
        expected: String,
        /// Identity discovered from the exported phase metadata.
        actual: String,
    },
    /// Campaign case identity is malformed.
    #[error("invalid witness campaign case id `{0}`")]
    InvalidCaseId(String),
    /// Mutation list is empty or exceeds the bounded adapter contract.
    #[error("invalid witness mutation operation count {0}")]
    InvalidOperationCount(usize),
    /// Mutation plan failed proof-neutral validation.
    #[error("invalid witness mutation plan: {0}")]
    InvalidPlan(String),
    /// This adapter does not model the selected phase.
    #[error("witness phase {0:?} is unsupported by the demo adapter")]
    UnsupportedPhase(WitnessPhase),
    /// This adapter does not model the selected column.
    #[error("witness column `{0}` is unsupported by the demo adapter")]
    UnsupportedColumn(String),
    /// Physical row is outside the committed column.
    #[error("witness row {row} is out of bounds for {rows} rows")]
    RowOutOfBounds {
        /// Invalid row.
        row: usize,
        /// Physical row count.
        rows: usize,
    },
    /// Scalar strategy has no canonical M31 definition in this adapter.
    #[error("scalar mutation {mutation:?} is unsupported at {path:?}")]
    UnsupportedScalar {
        /// Exact witness cell.
        path: WitnessCellPath,
        /// Unsupported scalar strategy.
        mutation: ScalarMutation,
    },
    /// Concrete AuditIR evaluation failed.
    #[error("could not evaluate the injected AuditIR assignment: {0}")]
    ConcreteEvaluation(String),
    /// Canonical artifact hashing failed.
    #[error("could not serialize the witness campaign: {0}")]
    Serialization(String),
    /// Stored replay does not recompute to the same report.
    #[error("invalid Stwo witness replay: {0}")]
    InvalidReplay(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_digest_uses_the_documented_binary_encoding() {
        let honest = DemoWitness::honest();
        assert_eq!(
            witness_sha256(&honest).expect("digest"),
            "91da262c96adc1716f37274d6614b77c8d6efdddce370d1946beb4415d81526b"
        );

        let mut changed = honest;
        changed.original_column[0] = 1;
        assert_ne!(
            witness_sha256(&changed).expect("changed digest"),
            "91da262c96adc1716f37274d6614b77c8d6efdddce370d1946beb4415d81526b"
        );
    }

    #[test]
    fn self_consistently_rewritten_audit_ir_digest_does_not_validate() {
        let adapter = StwoWitnessAdapter::new().expect("adapter");
        let mut replay = adapter.replay_honest().expect("replay");
        replay.observation.audit_ir_sha256 = "aa".repeat(32);
        replay.report = evaluate_witness(&replay.observation);

        let error = replay
            .validate()
            .expect_err("non-canonical AuditIR digest must fail");
        assert!(error.to_string().contains("exported component"), "{error}");
    }
}
