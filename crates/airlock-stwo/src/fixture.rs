//! Small deterministic Stwo proof used to exercise the executable adapter.

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
use stwo::prover::{CommitmentSchemeProver, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
};

use crate::StwoBoundaryError;

/// Logarithm of the demo trace height.
pub const DEMO_LOG_ROWS: u32 = 4;

/// Framework component type used by the adapter's deterministic fixture.
pub type DemoComponent = FrameworkComponent<TransitionEval>;

/// Concrete proof type produced by the deterministic fixture.
pub type DemoProof = StarkProof<Blake2sMerkleHasher>;

/// A one-column transition relation that requests current and next-row values.
#[derive(Clone)]
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

/// Build a deterministic, real prove-and-verify fixture against pinned Stwo.
pub fn build_demo_fixture() -> Result<DemoFixture, StwoBoundaryError> {
    let config = PcsConfig::default();
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

    let mut values = Col::<CpuBackend, BaseField>::zeros(1 << DEMO_LOG_ROWS);
    for index in 0..values.len() {
        values.set(index, BaseField::zero());
    }
    let domain = CanonicCoset::new(DEMO_LOG_ROWS).circle_domain();
    let trace: ColumnVec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> =
        vec![CircleEvaluation::<CpuBackend, _, BitReversedOrder>::new(
            domain, values,
        )];
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(prover_channel);

    let component = DemoComponent::new(
        &mut TraceLocationAllocator::default(),
        TransitionEval {
            log_rows: DEMO_LOG_ROWS,
        },
        SecureField::zero(),
    );
    let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|error| StwoBoundaryError::Prover(error.to_string()))?;

    Ok(DemoFixture {
        component,
        proof,
        config,
    })
}
