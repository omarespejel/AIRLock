//! Real Stwo request derivation and differential verifier replay.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use airlock_boundary::{
    BoundaryContract, BoundaryObservation, BoundaryPath, BoundaryReport, BoundaryVerdict, CaseKind,
    CountAtPath, MutationOperation, MutationPlan, VerificationOutcome, evaluate_boundary,
};
use serde::{Deserialize, Serialize};
use stwo::core::air::{Component, Components};
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::utils::try_get_lifting_log_size;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
use stwo::core::verifier::{COMPOSITION_LOG_SPLIT, VerificationError, verify};
use thiserror::Error;

use crate::STWO_SOURCE_ID;
use crate::fixture::{DemoComponent, DemoFixture, DemoProof, build_demo_fixture};
use crate::mutation::{StwoMutationError, mutate_proof};

/// Replay result for one verifier layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerReplay {
    /// Concrete boundary observation.
    pub observation: BoundaryObservation,
    /// Proof-neutral invariant report.
    pub report: BoundaryReport,
}

/// Aggregate status for a raw-PCS versus framework replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DifferentialVerdict {
    /// Both layers produced the same conclusive green boundary result.
    Consistent,
    /// At least one layer produced a replayable invariant counterexample.
    Counterexample,
    /// The layers produced materially different conclusive results.
    Divergence,
    /// At least one layer panicked or aborted.
    Panic,
    /// At least one layer timed out.
    Timeout,
    /// At least one layer or artifact was unsupported or malformed.
    Unsupported,
}

impl DifferentialVerdict {
    /// Only a consistent pair of conclusive green results is green.
    pub const fn is_green(self) -> bool {
        matches!(self, Self::Consistent)
    }
}

/// Content-addressed replay of one proof through two real Stwo boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DifferentialReplay {
    /// Verifier-derived request shared by both layers.
    pub contract: BoundaryContract,
    /// Raw PCS execution.
    pub raw_pcs: LayerReplay,
    /// Ordinary framework execution.
    pub framework: LayerReplay,
    /// Fail-closed cross-layer result.
    pub verdict: DifferentialVerdict,
}

/// Executable adapter over one deterministic real Stwo component.
pub struct StwoBoundaryAdapter {
    target: String,
    source_id: String,
    fixture: DemoFixture,
}

impl StwoBoundaryAdapter {
    /// Build the deterministic real-proof adapter against the pinned source.
    pub fn new(target: impl Into<String>) -> Result<Self, StwoBoundaryError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(StwoBoundaryError::EmptyTarget);
        }
        Ok(Self {
            target,
            source_id: STWO_SOURCE_ID.to_owned(),
            fixture: build_demo_fixture()?,
        })
    }

    /// Honest proof seed used by caller-defined mutation campaigns.
    pub fn honest_proof(&self) -> &DemoProof {
        &self.fixture.proof
    }

    /// Derive exact per-column sample counts from the component's verifier masks.
    pub fn contract(&self) -> Result<BoundaryContract, StwoBoundaryError> {
        derive_contract(
            &self.target,
            &self.source_id,
            &self.fixture.component,
            self.fixture.config,
        )
    }

    /// Replay the unmodified honest proof through both layers.
    pub fn replay_honest(&self) -> Result<DifferentialReplay, StwoBoundaryError> {
        self.replay(&self.fixture.proof, CaseKind::Honest, None)
    }

    /// Apply generic operations, bind the pre/post proof digests, and replay both layers.
    pub fn replay_mutation(
        &self,
        case_id: impl Into<String>,
        operations: Vec<MutationOperation>,
    ) -> Result<DifferentialReplay, StwoBoundaryError> {
        let case_id = case_id.into();
        let mutated = mutate_proof(&case_id, &self.fixture.proof, operations)?;
        self.replay(&mutated.proof, CaseKind::Mutated, Some(mutated.plan))
    }

    /// Locate the first concrete query scalar for a deterministic corruption test.
    pub fn first_queried_value_path(&self) -> Result<BoundaryPath, StwoBoundaryError> {
        for (tree_index, columns) in self.fixture.proof.0.queried_values.iter().enumerate() {
            for (column_index, values) in columns.iter().enumerate() {
                if !values.is_empty() {
                    return Ok(BoundaryPath::new(
                        "queried_values",
                        vec![tree_index, column_index, 0],
                    ));
                }
            }
        }
        Err(StwoBoundaryError::MissingQueriedValue)
    }

    fn replay(
        &self,
        proof: &DemoProof,
        case_kind: CaseKind,
        mutation: Option<MutationPlan>,
    ) -> Result<DifferentialReplay, StwoBoundaryError> {
        let contract = self.contract()?;
        let case_id = mutation
            .as_ref()
            .map_or_else(|| "honest-baseline".to_owned(), |plan| plan.seed_id.clone());
        let supplied = supplied_counts(proof);

        let raw_outcome = capture_verifier(|| {
            verify_raw_pcs(&self.fixture.component, self.fixture.config, proof.clone())
        });
        let raw_consumed = if matches!(raw_outcome, VerificationOutcome::Accepted) {
            consumed_by_raw_zip(&contract.requested, &supplied)
        } else {
            vec![]
        };
        let raw_observation = observation(
            &self.target,
            &self.source_id,
            &case_id,
            "raw_pcs",
            case_kind,
            mutation.clone(),
            supplied.clone(),
            raw_consumed,
            raw_outcome,
        );
        let raw_report = evaluate_boundary(&contract, &raw_observation);

        let framework_outcome = capture_verifier(|| {
            verify_framework(&self.fixture.component, self.fixture.config, proof.clone())
        });
        let framework_consumed = if matches!(framework_outcome, VerificationOutcome::Accepted) {
            contract.requested.clone()
        } else {
            vec![]
        };
        let framework_observation = observation(
            &self.target,
            &self.source_id,
            &case_id,
            "framework",
            case_kind,
            mutation,
            supplied,
            framework_consumed,
            framework_outcome,
        );
        let framework_report = evaluate_boundary(&contract, &framework_observation);
        let verdict = classify(&raw_report, &framework_report);

        Ok(DifferentialReplay {
            contract,
            raw_pcs: LayerReplay {
                observation: raw_observation,
                report: raw_report,
            },
            framework: LayerReplay {
                observation: framework_observation,
                report: framework_report,
            },
            verdict,
        })
    }
}

fn derive_contract(
    target: &str,
    source_id: &str,
    component: &DemoComponent,
    config: PcsConfig,
) -> Result<BoundaryContract, StwoBoundaryError> {
    let components = Components {
        components: vec![component],
        n_preprocessed_columns: 0,
    };
    let max_log_degree_bound = max_log_degree_bound(&components, config)?;
    let point = CirclePoint::<SecureField>::get_point(7);
    let mut sample_points = components.mask_points(point, max_log_degree_bound, false);
    sample_points.push(vec![vec![point]; 2 * SECURE_EXTENSION_DEGREE]);

    let mut requested = vec![];
    for (tree_index, columns) in sample_points.iter().enumerate() {
        for (column_index, points) in columns.iter().enumerate() {
            requested.push(CountAtPath::new(
                BoundaryPath::new("sampled_values", vec![tree_index, column_index]),
                points.len(),
            ));
        }
    }
    let contract = BoundaryContract::new(target, source_id, requested);
    contract
        .validate()
        .map_err(|error| StwoBoundaryError::Contract(error.to_string()))?;
    Ok(contract)
}

fn max_log_degree_bound(
    components: &Components<'_>,
    config: PcsConfig,
) -> Result<u32, StwoBoundaryError> {
    let composition_bound = components.composition_log_degree_bound();
    let split_bound = composition_bound
        .checked_sub(COMPOSITION_LOG_SPLIT)
        .ok_or(StwoBoundaryError::InvalidDegreeBound { composition_bound })?;
    let lifting_log_size =
        try_get_lifting_log_size(&config, split_bound + config.fri_config.log_blowup_factor)
            .map_err(|error| StwoBoundaryError::Contract(error.to_string()))?;
    lifting_log_size
        .checked_sub(config.fri_config.log_blowup_factor)
        .ok_or(StwoBoundaryError::InvalidDegreeBound { composition_bound })
}

fn verify_framework(
    component: &DemoComponent,
    config: PcsConfig,
    proof: DemoProof,
) -> Result<(), VerifierFailure> {
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    register_trace_commitments(component, &proof, verifier_channel, commitment_scheme)?;
    verify(&[component], verifier_channel, commitment_scheme, proof).map_err(VerifierFailure::from)
}

fn verify_raw_pcs(
    component: &DemoComponent,
    config: PcsConfig,
    proof: DemoProof,
) -> Result<(), VerifierFailure> {
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    register_trace_commitments(component, &proof, verifier_channel, commitment_scheme)?;

    let components = Components {
        components: vec![component],
        n_preprocessed_columns: 0,
    };
    let max_log_degree_bound = max_log_degree_bound(&components, config)
        .map_err(|error| VerifierFailure::invalid_structure(error.to_string()))?;
    let _random_coeff = verifier_channel.draw_secure_felt();
    let composition_root = proof
        .commitments
        .last()
        .copied()
        .ok_or_else(|| VerifierFailure::invalid_structure("missing composition commitment"))?;
    commitment_scheme.commit(
        composition_root,
        &[max_log_degree_bound; 2 * SECURE_EXTENSION_DEGREE],
        verifier_channel,
    );
    let oods_point = CirclePoint::<SecureField>::get_random_point(verifier_channel);
    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(vec![vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);
    commitment_scheme
        .verify_values(sample_points, proof.0, verifier_channel)
        .map_err(VerifierFailure::from)
}

fn register_trace_commitments(
    component: &DemoComponent,
    proof: &DemoProof,
    channel: &mut Blake2sM31Channel,
    scheme: &mut CommitmentSchemeVerifier<Blake2sM31MerkleChannel>,
) -> Result<(), VerifierFailure> {
    let sizes = component.trace_log_degree_bounds();
    let expected_commitments = sizes.len() + 1;
    if proof.commitments.len() != expected_commitments {
        return Err(VerifierFailure::invalid_structure(format!(
            "expected {expected_commitments} commitments, got {}",
            proof.commitments.len()
        )));
    }
    for (tree_index, log_sizes) in sizes.iter().enumerate() {
        let root = proof.commitments.get(tree_index).copied().ok_or_else(|| {
            VerifierFailure::invalid_structure(format!(
                "missing trace commitment at tree {tree_index}"
            ))
        })?;
        scheme.commit(root, log_sizes, channel);
    }
    Ok(())
}

fn supplied_counts(proof: &DemoProof) -> Vec<CountAtPath> {
    let mut supplied = vec![];
    for (tree_index, columns) in proof.sampled_values.iter().enumerate() {
        for (column_index, values) in columns.iter().enumerate() {
            supplied.push(CountAtPath::new(
                BoundaryPath::new("sampled_values", vec![tree_index, column_index]),
                values.len(),
            ));
        }
    }
    supplied
}

fn consumed_by_raw_zip(requested: &[CountAtPath], supplied: &[CountAtPath]) -> Vec<CountAtPath> {
    let supplied = supplied
        .iter()
        .map(|entry| (entry.path.clone(), entry.count))
        .collect::<BTreeMap<_, _>>();
    requested
        .iter()
        .map(|entry| {
            CountAtPath::new(
                entry.path.clone(),
                entry
                    .count
                    .min(supplied.get(&entry.path).copied().unwrap_or(0)),
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn observation(
    target: &str,
    source_id: &str,
    case_id: &str,
    layer: &str,
    case_kind: CaseKind,
    mutation: Option<MutationPlan>,
    supplied: Vec<CountAtPath>,
    consumed: Vec<CountAtPath>,
    outcome: VerificationOutcome,
) -> BoundaryObservation {
    BoundaryObservation {
        target: target.to_owned(),
        upstream_commit: source_id.to_owned(),
        case_id: case_id.to_owned(),
        layer: layer.to_owned(),
        case_kind,
        mutation,
        supplied,
        consumed,
        outcome,
    }
}

fn capture_verifier(run: impl FnOnce() -> Result<(), VerifierFailure>) -> VerificationOutcome {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(())) => VerificationOutcome::Accepted,
        Ok(Err(error)) => VerificationOutcome::Rejected {
            kind: error.kind,
            message: error.message,
        },
        Err(payload) => VerificationOutcome::Panicked {
            message: panic_message(payload),
        },
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

fn classify(raw: &BoundaryReport, framework: &BoundaryReport) -> DifferentialVerdict {
    use BoundaryVerdict as B;

    if matches!(raw.verdict, B::Unsupported) || matches!(framework.verdict, B::Unsupported) {
        return DifferentialVerdict::Unsupported;
    }
    if matches!(raw.verdict, B::Timeout) || matches!(framework.verdict, B::Timeout) {
        return DifferentialVerdict::Timeout;
    }
    if matches!(raw.verdict, B::Panic) || matches!(framework.verdict, B::Panic) {
        return DifferentialVerdict::Panic;
    }
    if raw.verdict != framework.verdict {
        return DifferentialVerdict::Divergence;
    }
    match raw.verdict {
        B::Accepted | B::Rejected => DifferentialVerdict::Consistent,
        B::Counterexample | B::Divergence => DifferentialVerdict::Counterexample,
        B::Panic => DifferentialVerdict::Panic,
        B::Timeout => DifferentialVerdict::Timeout,
        B::Unsupported => DifferentialVerdict::Unsupported,
    }
}

struct VerifierFailure {
    kind: String,
    message: String,
}

impl VerifierFailure {
    fn invalid_structure(message: impl Into<String>) -> Self {
        Self {
            kind: "invalid_structure".to_owned(),
            message: message.into(),
        }
    }
}

impl From<VerificationError> for VerifierFailure {
    fn from(error: VerificationError) -> Self {
        let kind = match &error {
            VerificationError::InvalidStructure(_) => "invalid_structure",
            VerificationError::Merkle(_) => "merkle",
            VerificationError::OodsNotMatching => "oods_not_matching",
            VerificationError::Fri(_) => "fri",
            VerificationError::ProofOfWork => "proof_of_work",
            VerificationError::InvalidLiftingLogSize(_) => "invalid_lifting_log_size",
            VerificationError::InvalidCanonicCosetLogSize(_) => "invalid_coset_log_size",
        };
        Self {
            kind: kind.to_owned(),
            message: error.to_string(),
        }
    }
}

/// Adapter construction, replay, or evidence error.
#[derive(Debug, Error)]
pub enum StwoBoundaryError {
    /// Target identity is required for stable evidence.
    #[error("Stwo adapter target must not be empty")]
    EmptyTarget,
    /// Honest proof generation failed.
    #[error("Stwo prover failed: {0}")]
    Prover(String),
    /// Verifier-derived contract could not be constructed.
    #[error("invalid Stwo boundary contract: {0}")]
    Contract(String),
    /// Composition degree bound is not representable under this configuration.
    #[error("invalid composition log degree bound {composition_bound}")]
    InvalidDegreeBound {
        /// Component-reported bound.
        composition_bound: u32,
    },
    /// The fixture unexpectedly contains no opened query value.
    #[error("honest Stwo proof contains no queried value")]
    MissingQueriedValue,
    /// Mutation could not be represented or applied.
    #[error(transparent)]
    Mutation(#[from] StwoMutationError),
}

#[cfg(test)]
mod tests {
    use airlock_boundary::{BoundaryPath, MutationOperation, ScalarMutation};

    use super::*;

    #[test]
    fn request_contract_comes_from_real_two_point_component_mask() {
        let adapter = StwoBoundaryAdapter::new("stwo-demo").expect("adapter");
        let contract = adapter.contract().expect("contract");
        let trace_path = BoundaryPath::new("sampled_values", vec![1, 0]);
        let trace_request = contract
            .requested
            .iter()
            .find(|entry| entry.path == trace_path)
            .expect("trace request");
        assert_eq!(trace_request.count, 2);
    }

    #[test]
    fn honest_real_proof_is_consistent_across_layers() {
        let adapter = StwoBoundaryAdapter::new("stwo-demo").expect("adapter");
        let replay = adapter.replay_honest().expect("replay");
        assert_eq!(replay.verdict, DifferentialVerdict::Consistent);
        assert!(replay.verdict.is_green());
        assert_eq!(replay.raw_pcs.report.verdict, BoundaryVerdict::Accepted);
        assert_eq!(replay.framework.report.verdict, BoundaryVerdict::Accepted);
    }

    #[test]
    fn corrupted_real_query_is_rejected_by_both_layers() {
        let adapter = StwoBoundaryAdapter::new("stwo-demo").expect("adapter");
        let path = adapter.first_queried_value_path().expect("query path");
        let replay = adapter
            .replay_mutation(
                "corrupt-first-query",
                vec![MutationOperation::ReplaceScalar {
                    path,
                    value: ScalarMutation::Increment,
                }],
            )
            .expect("replay");
        assert_eq!(replay.verdict, DifferentialVerdict::Consistent);
        assert_eq!(replay.raw_pcs.report.verdict, BoundaryVerdict::Rejected);
        assert_eq!(replay.framework.report.verdict, BoundaryVerdict::Rejected);
    }

    #[test]
    fn unsupported_mutation_path_fails_closed() {
        let adapter = StwoBoundaryAdapter::new("stwo-demo").expect("adapter");
        let error = adapter
            .replay_mutation(
                "foreign-path",
                vec![MutationOperation::Drop {
                    path: BoundaryPath::new("fri_proof.unknown", vec![]),
                    index: 0,
                }],
            )
            .expect_err("unsupported path");
        assert!(matches!(
            error,
            StwoBoundaryError::Mutation(StwoMutationError::UnsupportedPath(_))
        ));
    }
}
