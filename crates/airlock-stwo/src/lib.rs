//! Executable AIRLock integration adapter for the pinned Stwo demo.
//!
//! This crate generates a small honest Stwo proof, derives verifier requests
//! from the component masks, applies proof-system-neutral mutation plans, and
//! replays each case through both the raw PCS and ordinary framework paths.
//! Its witness campaign intentionally composes the separate AuditIR and
//! verifier-boundary lanes so their observations can be compared. Their
//! coverage and verdicts remain independent.
//! It does not establish Stwo, FRI, Fiat--Shamir, or application soundness.

mod adapter;
mod campaign;
mod fixture;
mod heldout;
mod isolation;
mod mutation;
mod regression;
mod replay_bundle;
mod request;
mod temp;
mod transcript;
mod witness;
mod witness_matrix;

pub use adapter::{
    DifferentialReplay, DifferentialVerdict, LayerReplay, StwoBoundaryAdapter, StwoBoundaryError,
};
pub use campaign::{
    CAMPAIGN_SCHEMA_ID, CAMPAIGN_SCHEMA_VERSION, CampaignCase, CampaignError, CampaignFile,
    CampaignManifest, VerifiedCampaign, read_verified_held_out_replay,
    read_verified_witness_replay, seal_campaign, verify_campaign, write_held_out_replay,
    write_witness_replay,
};
pub use fixture::{DemoComponent, DemoProof, build_demo_fixture};
pub use heldout::{
    HELD_OUT_HONEST_CASE, HELD_OUT_PRESERVING_CASE, HELD_OUT_VIOLATING_CASE, HeldOutAdapter,
    HeldOutError, HeldOutReplay, STWO_HELD_OUT_TARGET,
};
pub use isolation::{
    IsolatedReplayError, IsolatedReplayRecord, ProcessTermination, run_isolated_replay,
    run_isolated_replay_with_worker_digest,
};
pub use mutation::{MutatedProof, StwoMutationError, mutate_proof, proof_sha256};
pub use regression::generate_regression_source;
pub use replay_bundle::{
    ReplayBundleError, ReplayBundleFiles, VerifiedReplayBundle, read_verified_replay_bundle,
    verify_replay_bundle, write_replay_bundle,
};
pub use request::{
    ReplayCase, ReplayRequest, ReplayRequestError, execute_replay_request, replay_request_sha256,
};
pub use transcript::{
    FRI_QUERY_POSITIONS_DRAW, ObservedTranscriptRun, QUERY_POW, QUERY_POW_NONCE_ABSORPTION,
    TranscriptObserveError, demo_transcript_contract, observe_demo_transcript,
};
pub use witness::{
    STWO_DEMO_WITNESS_TARGET, StwoWitnessAdapter, StwoWitnessError, StwoWitnessReplay,
};
pub use witness_matrix::{
    MAX_WITNESS_MATRIX_BYTES, STWO_WITNESS_MATRIX_ID, StwoWitnessMatrixError,
    read_stwo_witness_matrix, run_stwo_witness_matrix, validate_stwo_witness_matrix,
    verify_stwo_witness_matrix_fresh, write_stwo_witness_matrix,
};

/// Upstream source commit whose dependency trees are pinned by AIRLock.
pub const STWO_UPSTREAM_BASELINE: &str = "f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a";

/// Stable identity of the only executable component covered by this adapter.
pub const STWO_DEMO_TARGET: &str = "stwo-demo-transition-v1";

/// Stable source identity used in boundary artifacts.
///
/// `scripts/verify-stwo-checkout.sh` independently checks that the sibling
/// checkout equals this baseline plus AIRLock's two checked patches.
pub const STWO_SOURCE_ID: &str = "stwo@f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a+patches:accessor=7782a94a63a40e86b760d76dc37d2a6833921c5dfad5073b62972d640b90742a;consumption=cdef8d226336b766ceeeddcac410c535c1d669fce88081c58ddc8221371d9a23;transcript=da841076b861f00a1a128d5aaa49f092a36809d17bf43520fb25f1dafd2d1746";
