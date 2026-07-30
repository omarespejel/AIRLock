//! Held-out nonlinear Stwo target for adapter-generality checks.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use airlock_boundary::{
    BoundaryContract, CONSTRAINT_VIOLATION_REJECTION_KIND, CaseKind, MAX_WITNESS_MUTATIONS,
    ProofGenerationOutcome, ProofRejectionCause, ScalarMutation, WitnessCellPath,
    WitnessMutationOperation, WitnessMutationPlan, WitnessObservation, WitnessPhase, WitnessReport,
    evaluate_witness,
};
use airlock_export::{ConcreteAssignment, ExportAnnotations, constraints_hold, export_component};
use airlock_ir::{AuditManifest, ColumnKind, CommitmentPhase, M31_P, SemanticType, hash_manifest};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stwo::core::ColumnVec;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, ProvingError, prove};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_examples::wide_fibonacci::{WideFibonacciComponent, WideFibonacciEval};
use thiserror::Error;

use crate::adapter::{capture_verifier, derive_component_contract, verify_framework};
use crate::{DemoProof, STWO_SOURCE_ID, proof_sha256};

/// Stable identity of the held-out target selected before implementation.
pub const STWO_HELD_OUT_TARGET: &str = "stwo-held-out-wide-fibonacci-3-v1";

/// Honest held-out campaign case.
pub const HELD_OUT_HONEST_CASE: &str = "wide-fibonacci-honest";

/// Coordinated relation-preserving held-out campaign case.
pub const HELD_OUT_PRESERVING_CASE: &str = "wide-fibonacci-preserving";

/// Single-cell relation-violating held-out campaign case.
pub const HELD_OUT_VIOLATING_CASE: &str = "wide-fibonacci-violating";

const HELD_OUT_LOG_ROWS: u32 = 4;
const HELD_OUT_COLUMN_COUNT: usize = 3;
const MAX_CASE_ID_BYTES: usize = 128;
const ORIGINAL_COLUMN_IDS: [&str; HELD_OUT_COLUMN_COUNT] =
    ["trace_1_column_0", "trace_1_column_1", "trace_1_column_2"];
const COLUMN_LABELS: [&str; HELD_OUT_COLUMN_COUNT] =
    ["wide_fibonacci_a", "wide_fibonacci_b", "wide_fibonacci_c"];
const NEGATIVE_HALF: u32 = (M31_P - 1) / 2;
const ONE_QUARTER: u32 = (M31_P + 1) / 4;

type HeldOutComponent = WideFibonacciComponent<HELD_OUT_COLUMN_COUNT>;

/// Request derivation and witness replay for one held-out target case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutReplay {
    /// Exact request derived from the held-out component masks.
    pub contract: BoundaryContract,
    /// AuditIR, proof-generation, and verifier observation.
    pub observation: WitnessObservation,
    /// Recomputed fail-closed witness report.
    pub report: WitnessReport,
}

impl HeldOutReplay {
    /// Revalidate identities and recompute the proof-neutral report.
    pub fn validate(&self) -> Result<(), HeldOutError> {
        self.contract
            .validate()
            .map_err(|error| HeldOutError::InvalidReplay(error.to_string()))?;
        self.observation
            .validate()
            .map_err(|error| HeldOutError::InvalidReplay(error.to_string()))?;
        if self.contract.target != STWO_HELD_OUT_TARGET
            || self.contract.upstream_commit != STWO_SOURCE_ID
            || self.observation.target != self.contract.target
            || self.observation.upstream_commit != self.contract.upstream_commit
        {
            return Err(HeldOutError::InvalidReplay(
                "held-out replay is not bound to the frozen target and source".to_owned(),
            ));
        }
        let canonical = HeldOutAdapter::new()?;
        if self.contract != *canonical.contract() {
            return Err(HeldOutError::InvalidReplay(
                "held-out request differs from the verifier-derived component request".to_owned(),
            ));
        }
        if self.observation.audit_ir_sha256 != canonical.audit_ir_sha256()? {
            return Err(HeldOutError::InvalidReplay(
                "held-out AuditIR digest differs from the exported component".to_owned(),
            ));
        }
        let recomputed = evaluate_witness(&self.observation);
        if recomputed != self.report {
            return Err(HeldOutError::InvalidReplay(
                "held-out report does not match its observation".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct HeldOutWitness {
    columns: Vec<Vec<u32>>,
}

impl HeldOutWitness {
    fn honest() -> Self {
        let rows = 1 << HELD_OUT_LOG_ROWS;
        Self {
            columns: vec![
                vec![0; rows],
                vec![NEGATIVE_HALF; rows],
                vec![ONE_QUARTER; rows],
            ],
        }
    }
}

/// Executable adapter for the independently selected nonlinear held-out
/// component.
pub struct HeldOutAdapter {
    manifest: AuditManifest,
    column_ids: Vec<String>,
    seed: HeldOutWitness,
    contract: BoundaryContract,
}

impl HeldOutAdapter {
    /// Export the real upstream evaluator and derive its verifier request.
    pub fn new() -> Result<Self, HeldOutError> {
        let mut annotations = ExportAnnotations {
            component_name: STWO_HELD_OUT_TARGET.to_owned(),
            ..ExportAnnotations::default()
        };
        for (column_id, label) in ORIGINAL_COLUMN_IDS.into_iter().zip(COLUMN_LABELS) {
            annotations.column_semantics.insert(
                column_id.to_owned(),
                SemanticType::Other {
                    label: label.to_owned(),
                },
            );
        }
        let manifest = export_component(&held_out_eval(), annotations)
            .map_err(|error| HeldOutError::Export(error.to_string()))?;
        let component = manifest
            .components
            .first()
            .ok_or(HeldOutError::MissingComponent)?;
        let exported_column_ids = component
            .columns
            .iter()
            .filter(|column| {
                column.kind == ColumnKind::Witness
                    && column.commitment_phase == CommitmentPhase::Phase1Original
            })
            .map(|column| column.id.clone())
            .collect::<Vec<_>>();
        let mut actual = exported_column_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected = ORIGINAL_COLUMN_IDS.to_vec();
        expected.sort_unstable();
        if actual != expected {
            return Err(HeldOutError::OriginalColumnIdentityMismatch(
                exported_column_ids,
            ));
        }
        // AuditIR expression traversal does not promise mask-declaration order.
        // Keep the physical evaluator order explicit after checking exact identity.
        let column_ids = ORIGINAL_COLUMN_IDS.map(str::to_owned).to_vec();

        let verifier_component = held_out_component();
        let config = PcsConfig::default();
        let contract = derive_component_contract(
            STWO_HELD_OUT_TARGET,
            STWO_SOURCE_ID,
            &verifier_component,
            config,
        )?;
        Ok(Self {
            manifest,
            column_ids,
            seed: HeldOutWitness::honest(),
            contract,
        })
    }

    /// Verifier-derived request for the frozen target.
    pub fn contract(&self) -> &BoundaryContract {
        &self.contract
    }

    /// Original-phase AuditIR columns in evaluator read order.
    pub fn original_column_ids(&self) -> &[String] {
        &self.column_ids
    }

    /// Physical row count for every held-out column.
    pub fn row_count(&self) -> usize {
        self.seed.columns[0].len()
    }

    /// SHA-256 of the exact exported AuditIR manifest.
    pub fn audit_ir_sha256(&self) -> Result<String, HeldOutError> {
        hash_manifest(&self.manifest)
            .map(|digest| digest.0)
            .map_err(|error| HeldOutError::Serialization(error.to_string()))
    }

    /// Regenerate and verify the unmodified held-out witness.
    pub fn replay_honest(&self) -> Result<HeldOutReplay, HeldOutError> {
        self.replay(
            HELD_OUT_HONEST_CASE,
            CaseKind::Honest,
            self.seed.clone(),
            None,
        )
    }

    /// Replay the frozen coordinated Increment plan at row zero.
    pub fn replay_preserving(&self) -> Result<HeldOutReplay, HeldOutError> {
        self.replay_mutation(
            HELD_OUT_PRESERVING_CASE,
            self.preserving_operations_at_row(0)?,
        )
    }

    /// Replay the frozen single-cell Increment plan at row zero.
    pub fn replay_violating(&self) -> Result<HeldOutReplay, HeldOutError> {
        self.replay_mutation(
            HELD_OUT_VIOLATING_CASE,
            vec![self.increment_operation(2, 0)?],
        )
    }

    /// Coordinated Increment operations that preserve `c = a^2 + b^2`.
    pub fn preserving_operations_at_row(
        &self,
        row: usize,
    ) -> Result<Vec<WitnessMutationOperation>, HeldOutError> {
        (0..HELD_OUT_COLUMN_COUNT)
            .map(|column| self.increment_operation(column, row))
            .collect()
    }

    /// Increment one derived column at a physical row.
    pub fn increment_operation(
        &self,
        column: usize,
        row: usize,
    ) -> Result<WitnessMutationOperation, HeldOutError> {
        self.mutation_operation(column, row, ScalarMutation::Increment)
    }

    /// Build one typed original-column scalar mutation after validating its cell.
    pub fn mutation_operation(
        &self,
        column: usize,
        row: usize,
        mutation: ScalarMutation,
    ) -> Result<WitnessMutationOperation, HeldOutError> {
        let column_id = self
            .column_ids
            .get(column)
            .ok_or(HeldOutError::ColumnOutOfBounds {
                column,
                columns: self.column_ids.len(),
            })?;
        if row >= self.row_count() {
            return Err(HeldOutError::RowOutOfBounds {
                row,
                rows: self.row_count(),
            });
        }
        Ok(WitnessMutationOperation::ReplaceM31 {
            path: WitnessCellPath::new(WitnessPhase::Original, column_id, row),
            value: mutation,
        })
    }

    /// Apply phase-bound operations before commitment and replay the real path.
    pub fn replay_mutation(
        &self,
        case_id: impl Into<String>,
        operations: Vec<WitnessMutationOperation>,
    ) -> Result<HeldOutReplay, HeldOutError> {
        let case_id = case_id.into();
        validate_case_id(&case_id)?;
        if operations.is_empty() || operations.len() > MAX_WITNESS_MUTATIONS {
            return Err(HeldOutError::InvalidOperationCount(operations.len()));
        }
        let seed_witness_sha256 = witness_sha256(&self.seed)?;
        let mut witness = self.seed.clone();
        for operation in &operations {
            self.apply_operation(&mut witness, operation)?;
        }
        let mutated_witness_sha256 = witness_sha256(&witness)?;
        let plan = WitnessMutationPlan {
            target: STWO_HELD_OUT_TARGET.to_owned(),
            upstream_commit: STWO_SOURCE_ID.to_owned(),
            seed_id: case_id.clone(),
            seed_witness_sha256,
            mutated_witness_sha256,
            operations,
        };
        plan.validate()
            .map_err(|error| HeldOutError::InvalidPlan(error.to_string()))?;
        self.replay(&case_id, CaseKind::Mutated, witness, Some(plan))
    }

    fn apply_operation(
        &self,
        witness: &mut HeldOutWitness,
        operation: &WitnessMutationOperation,
    ) -> Result<(), HeldOutError> {
        let WitnessMutationOperation::ReplaceM31 { path, value } = operation;
        if path.phase != WitnessPhase::Original {
            return Err(HeldOutError::UnsupportedPhase(path.phase));
        }
        let column = self
            .column_ids
            .iter()
            .position(|column| column == &path.column)
            .ok_or_else(|| HeldOutError::UnsupportedColumn(path.column.clone()))?;
        let rows = self.row_count();
        let cell =
            witness.columns[column]
                .get_mut(path.row)
                .ok_or(HeldOutError::RowOutOfBounds {
                    row: path.row,
                    rows,
                })?;
        *cell = mutate_m31(*cell, *value, path)?;
        Ok(())
    }

    fn replay(
        &self,
        case_id: &str,
        case_kind: CaseKind,
        witness: HeldOutWitness,
        mutation: Option<WitnessMutationPlan>,
    ) -> Result<HeldOutReplay, HeldOutError> {
        let component = self
            .manifest
            .components
            .first()
            .ok_or(HeldOutError::MissingComponent)?;
        let assignment = ConcreteAssignment {
            columns: self
                .column_ids
                .iter()
                .cloned()
                .zip(witness.columns.iter().cloned())
                .collect::<BTreeMap<_, _>>(),
            ..ConcreteAssignment::default()
        };
        let audit_ir_constraints_hold = constraints_hold(component, &assignment)
            .map_err(|error| HeldOutError::ConcreteEvaluation(error.to_string()))?;
        let audit_ir_sha256 = self.audit_ir_sha256()?;

        let (proof_generation, verifier) =
            match catch_unwind(AssertUnwindSafe(|| build_held_out_fixture(&witness))) {
                Ok(Ok(fixture)) => {
                    let digest = proof_sha256(&fixture.proof)
                        .map_err(|error| HeldOutError::Serialization(error.to_string()))?;
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
                Ok(Err(HeldOutFixtureBuildError::ConstraintsNotSatisfied)) => (
                    ProofGenerationOutcome::Rejected {
                        cause: ProofRejectionCause::ConstraintViolation,
                        kind: CONSTRAINT_VIOLATION_REJECTION_KIND.to_owned(),
                        message: "Stwo prover rejected the committed held-out witness".to_owned(),
                    },
                    None,
                ),
                Ok(Err(error @ HeldOutFixtureBuildError::InvalidShape { .. }))
                | Ok(Err(error @ HeldOutFixtureBuildError::InvalidColumnLength { .. }))
                | Ok(Err(error @ HeldOutFixtureBuildError::NoncanonicalWitness { .. }))
                | Ok(Err(error @ HeldOutFixtureBuildError::Prover(_))) => (
                    ProofGenerationOutcome::InfrastructureFailure {
                        kind: "held_out_fixture".to_owned(),
                        message: error.to_string(),
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
            schema: airlock_boundary::WITNESS_SCHEMA_ID.to_owned(),
            schema_version: airlock_boundary::WITNESS_SCHEMA_VERSION.to_owned(),
            target: STWO_HELD_OUT_TARGET.to_owned(),
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
        let replay = HeldOutReplay {
            contract: self.contract.clone(),
            observation,
            report,
        };
        replay.validate()?;
        Ok(replay)
    }
}

struct HeldOutFixture {
    component: HeldOutComponent,
    proof: DemoProof,
    config: PcsConfig,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
enum HeldOutFixtureBuildError {
    #[error("held-out witness has {actual_columns} columns; expected {expected_columns}")]
    InvalidShape {
        expected_columns: usize,
        actual_columns: usize,
    },
    #[error("held-out column {column} has {actual_rows} rows; expected {expected_rows}")]
    InvalidColumnLength {
        column: usize,
        expected_rows: usize,
        actual_rows: usize,
    },
    #[error("held-out witness column {column} row {row} has noncanonical M31 value {value}")]
    NoncanonicalWitness {
        column: usize,
        row: usize,
        value: u32,
    },
    #[error("Stwo prover rejected the held-out witness because constraints are not satisfied")]
    ConstraintsNotSatisfied,
    #[error("Stwo prover failed for the held-out witness: {0}")]
    Prover(String),
}

fn build_held_out_fixture(
    witness: &HeldOutWitness,
) -> Result<HeldOutFixture, HeldOutFixtureBuildError> {
    if witness.columns.len() != HELD_OUT_COLUMN_COUNT {
        return Err(HeldOutFixtureBuildError::InvalidShape {
            expected_columns: HELD_OUT_COLUMN_COUNT,
            actual_columns: witness.columns.len(),
        });
    }
    let expected_rows = 1 << HELD_OUT_LOG_ROWS;
    for (column, values) in witness.columns.iter().enumerate() {
        if values.len() != expected_rows {
            return Err(HeldOutFixtureBuildError::InvalidColumnLength {
                column,
                expected_rows,
                actual_rows: values.len(),
            });
        }
        for (row, value) in values.iter().copied().enumerate() {
            if value >= M31_P {
                return Err(HeldOutFixtureBuildError::NoncanonicalWitness { column, row, value });
            }
        }
    }

    let config = PcsConfig::default();
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(HELD_OUT_LOG_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    let domain = CanonicCoset::new(HELD_OUT_LOG_ROWS).circle_domain();
    let trace: ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> = witness
        .columns
        .iter()
        .map(|column| {
            let mut values = Col::<CpuBackend, BaseField>::zeros(expected_rows);
            for (row, value) in column.iter().copied().enumerate() {
                values.set(row, BaseField::from(value));
            }
            CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(domain, values)
        })
        .collect();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let component = held_out_component();
    let proof = match prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    ) {
        Ok(proof) => proof,
        Err(ProvingError::ConstraintsNotSatisfied) => {
            return Err(HeldOutFixtureBuildError::ConstraintsNotSatisfied);
        }
        Err(error) => return Err(HeldOutFixtureBuildError::Prover(error.to_string())),
    };
    Ok(HeldOutFixture {
        component,
        proof,
        config,
    })
}

fn held_out_eval() -> WideFibonacciEval<HELD_OUT_COLUMN_COUNT> {
    WideFibonacciEval {
        log_n_rows: HELD_OUT_LOG_ROWS,
    }
}

fn held_out_component() -> HeldOutComponent {
    HeldOutComponent::new(
        &mut TraceLocationAllocator::default(),
        held_out_eval(),
        SecureField::zero(),
    )
}

fn mutate_m31(
    current: u32,
    mutation: ScalarMutation,
    path: &WitnessCellPath,
) -> Result<u32, HeldOutError> {
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
            return Err(HeldOutError::UnsupportedScalar {
                path: path.clone(),
                mutation,
            });
        }
    })
}

fn witness_sha256(witness: &HeldOutWitness) -> Result<String, HeldOutError> {
    let column_count = u64::try_from(witness.columns.len())
        .map_err(|error| HeldOutError::Serialization(error.to_string()))?;
    let row_count = u64::try_from(witness.columns.first().map_or(0, Vec::len))
        .map_err(|error| HeldOutError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"airlock.held-out-wide-fibonacci-witness.v1\0");
    hasher.update(column_count.to_le_bytes());
    hasher.update(row_count.to_le_bytes());
    for column in &witness.columns {
        for value in column {
            hasher.update(value.to_le_bytes());
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_case_id(case_id: &str) -> Result<(), HeldOutError> {
    if case_id.is_empty()
        || case_id.len() > MAX_CASE_ID_BYTES
        || case_id.trim() != case_id
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HeldOutError::InvalidCaseId(case_id.to_owned()));
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

/// Failure to represent or replay the held-out target.
#[derive(Debug, Error)]
pub enum HeldOutError {
    /// Stwo `FrameworkEval` export failed.
    #[error("could not export the held-out AIR: {0}")]
    Export(String),
    /// Export unexpectedly contained no component.
    #[error("held-out AuditIR manifest contains no component")]
    MissingComponent,
    /// Exported columns differ from the evaluator-derived declaration.
    #[error("held-out original column identities changed: {0:?}")]
    OriginalColumnIdentityMismatch(Vec<String>),
    /// Verifier request derivation failed.
    #[error(transparent)]
    Boundary(#[from] crate::StwoBoundaryError),
    /// Campaign case identity is malformed.
    #[error("invalid held-out case id `{0}`")]
    InvalidCaseId(String),
    /// Mutation list is empty or exceeds the bounded contract.
    #[error("invalid held-out mutation operation count {0}")]
    InvalidOperationCount(usize),
    /// Mutation plan failed proof-neutral validation.
    #[error("invalid held-out mutation plan: {0}")]
    InvalidPlan(String),
    /// This adapter does not model the selected phase.
    #[error("witness phase {0:?} is unsupported by the held-out adapter")]
    UnsupportedPhase(WitnessPhase),
    /// This adapter does not model the selected column.
    #[error("witness column `{0}` is unsupported by the held-out adapter")]
    UnsupportedColumn(String),
    /// Declarative target column index is outside the exported set.
    #[error("held-out column {column} is out of bounds for {columns} columns")]
    ColumnOutOfBounds { column: usize, columns: usize },
    /// Physical row is outside the committed columns.
    #[error("witness row {row} is out of bounds for {rows} rows")]
    RowOutOfBounds { row: usize, rows: usize },
    /// Scalar strategy has no canonical definition in this adapter.
    #[error("scalar mutation {mutation:?} is unsupported at {path:?}")]
    UnsupportedScalar {
        path: WitnessCellPath,
        mutation: ScalarMutation,
    },
    /// Concrete AuditIR evaluation failed.
    #[error("could not evaluate the held-out AuditIR assignment: {0}")]
    ConcreteEvaluation(String),
    /// Canonical artifact hashing failed.
    #[error("could not serialize the held-out campaign: {0}")]
    Serialization(String),
    /// Stored replay does not recompute to the same report.
    #[error("invalid held-out replay: {0}")]
    InvalidReplay(String),
}
