//! Executable AIRLock adapter for the pinned Stwo verifier boundary.
//!
//! This crate generates a small honest Stwo proof, derives verifier requests
//! from the component masks, applies proof-system-neutral mutation plans, and
//! replays each case through both the raw PCS and ordinary framework paths.
//! It does not establish Stwo, FRI, Fiat--Shamir, or application soundness.

mod adapter;
mod fixture;
mod mutation;

pub use adapter::{
    DifferentialReplay, DifferentialVerdict, LayerReplay, StwoBoundaryAdapter, StwoBoundaryError,
};
pub use fixture::{DemoComponent, DemoProof, build_demo_fixture};
pub use mutation::{MutatedProof, StwoMutationError, mutate_proof, proof_sha256};

/// Upstream source commit whose dependency trees are pinned by AIRLock.
pub const STWO_UPSTREAM_BASELINE: &str = "f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a";

/// Stable identity of the only executable component covered by this adapter.
pub const STWO_DEMO_TARGET: &str = "stwo-demo-transition-v1";

/// Stable source identity used in boundary artifacts.
///
/// `scripts/verify-stwo-checkout.sh` independently checks that the sibling
/// checkout equals this baseline plus AIRLock's accessor-only patch.
pub const STWO_SOURCE_ID: &str = "stwo@f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a+patch:7782a94a63a40e86b760d76dc37d2a6833921c5dfad5073b62972d640b90742a";
