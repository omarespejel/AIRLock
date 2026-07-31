//! Small deterministic Stwo proof used to exercise the executable adapter.

use airlock_ir::M31_P;
use num_traits::Zero;
use stwo::core::ColumnVec;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::{Col, Column, CpuBackend};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, ProvingError, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
};

use crate::StwoBoundaryError;
use thiserror::Error;

/// Logarithm of the demo trace height.
pub const DEMO_LOG_ROWS: u32 = 4;

/// Framework component type used by the adapter's deterministic fixture.
pub type DemoComponent = FrameworkComponent<TransitionEval>;

/// Concrete proof type produced by the deterministic fixture.
pub type DemoProof = StarkProof<Blake2sMerkleHasher>;

/// A one-column transition relation that requests current and next-row values.
#[derive(Clone, Copy)]
pub struct TransitionEval {
    log_rows: u32,
}

impl FrameworkEval for TransitionEval {
    fn log_size(&self) -> u32 {
        self.log_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let [current, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
        eval.add_constraint(next - current);
        eval
    }
}

/// Honest proof, matching component, and verifier-owned PCS configuration.
pub struct DemoFixture {
    /// AIR component used by both prover and verifier.
    pub component: DemoComponent,
    /// Honest proof seed.
    pub proof: DemoProof,
    /// Verifier-owned configuration. The proof's embedded copy is not trusted.
    pub config: PcsConfig,
}

/// Failure to build a proof from an explicit pre-commitment witness.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DemoFixtureBuildError {
    /// The witness does not contain exactly one full demo column.
    #[error("demo witness has {actual} rows; expected {expected}")]
    InvalidWitnessLength {
        /// Required physical row count.
        expected: usize,
        /// Supplied physical row count.
        actual: usize,
    },
    /// A witness cell is not a canonical M31 representative.
    #[error("demo witness row {row} contains noncanonical M31 value {value}")]
    NoncanonicalWitness {
        /// Invalid physical row.
        row: usize,
        /// Invalid representative.
        value: u32,
    },
    /// Stwo's prover detected that the committed trace violates the AIR.
    #[error("Stwo prover rejected the witness because constraints are not satisfied")]
    ConstraintsNotSatisfied,
    /// Another pinned Stwo proving failure occurred.
    #[error("Stwo prover failed: {0}")]
    Prover(String),
}

/// Build a deterministic, real prove-and-verify fixture against pinned Stwo.
pub fn build_demo_fixture() -> Result<DemoFixture, StwoBoundaryError> {
    build_demo_fixture_with_values(&[0; 1 << DEMO_LOG_ROWS]).map_err(StwoBoundaryError::from)
}

impl From<DemoFixtureBuildError> for StwoBoundaryError {
    fn from(error: DemoFixtureBuildError) -> Self {
        match error {
            DemoFixtureBuildError::InvalidWitnessLength { expected, actual } => {
                Self::InvalidWitnessLength { expected, actual }
            }
            DemoFixtureBuildError::NoncanonicalWitness { row, value } => {
                Self::NoncanonicalWitness { row, value }
            }
            DemoFixtureBuildError::ConstraintsNotSatisfied => Self::ConstraintsNotSatisfied,
            DemoFixtureBuildError::Prover(message) => Self::Prover(message),
        }
    }
}

pub(crate) fn transition_eval() -> TransitionEval {
    TransitionEval {
        log_rows: DEMO_LOG_ROWS,
    }
}

pub(crate) fn build_demo_verifier_with_config(config: PcsConfig) -> (DemoComponent, PcsConfig) {
    let component = DemoComponent::new(
        &mut TraceLocationAllocator::default(),
        transition_eval(),
        SecureField::zero(),
    );
    (component, config)
}

pub(crate) fn build_demo_verifier() -> (DemoComponent, PcsConfig) {
    let component = DemoComponent::new(
        &mut TraceLocationAllocator::default(),
        transition_eval(),
        SecureField::zero(),
    );
    (component, PcsConfig::default())
}

/// Build the deterministic fixture under an explicit PCS configuration.
///
/// Used to exercise a zero-work profile, which the default configuration does not
/// select. The configuration is verifier-owned; the proof's embedded copy is not
/// trusted.
pub(crate) fn build_demo_fixture_with_config(
    witness: &[u32],
    config: PcsConfig,
) -> Result<DemoFixture, DemoFixtureBuildError> {
    build_demo_fixture_inner(witness, Some(config))
}

pub(crate) fn build_demo_fixture_with_values(
    witness: &[u32],
) -> Result<DemoFixture, DemoFixtureBuildError> {
    build_demo_fixture_inner(witness, None)
}

fn build_demo_fixture_inner(
    witness: &[u32],
    config_override: Option<PcsConfig>,
) -> Result<DemoFixture, DemoFixtureBuildError> {
    let expected = 1usize << DEMO_LOG_ROWS;
    if witness.len() != expected {
        return Err(DemoFixtureBuildError::InvalidWitnessLength {
            expected,
            actual: witness.len(),
        });
    }
    for (row, value) in witness.iter().copied().enumerate() {
        if value >= M31_P {
            return Err(DemoFixtureBuildError::NoncanonicalWitness { row, value });
        }
    }

    let (component, config) = match config_override {
        Some(config) => build_demo_verifier_with_config(config),
        None => build_demo_verifier(),
    };
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(DEMO_LOG_ROWS + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(prover_channel);

    let mut values = Col::<CpuBackend, BaseField>::zeros(expected);
    for (index, value) in witness.iter().copied().enumerate() {
        values.set(index, BaseField::from(value));
    }
    let domain = CanonicCoset::new(DEMO_LOG_ROWS).circle_domain();
    let trace: ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> =
        vec![CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
            domain, values,
        )];
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let proof = match prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    ) {
        Ok(proof) => proof,
        Err(ProvingError::ConstraintsNotSatisfied) => {
            return Err(DemoFixtureBuildError::ConstraintsNotSatisfied);
        }
        Err(error) => return Err(DemoFixtureBuildError::Prover(error.to_string())),
    };

    Ok(DemoFixture {
        component,
        proof,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_fixture_errors_survive_boundary_conversion() {
        let length = StwoBoundaryError::from(DemoFixtureBuildError::InvalidWitnessLength {
            expected: 16,
            actual: 15,
        });
        assert!(matches!(
            length,
            StwoBoundaryError::InvalidWitnessLength {
                expected: 16,
                actual: 15
            }
        ));

        let representative = StwoBoundaryError::from(DemoFixtureBuildError::NoncanonicalWitness {
            row: 3,
            value: M31_P,
        });
        assert!(matches!(
            representative,
            StwoBoundaryError::NoncanonicalWitness {
                row: 3,
                value: M31_P
            }
        ));
    }
}
