//! Proof-system-neutral contracts for adversarial verifier-boundary testing.
//!
//! This crate models what a verifier requests, what a proof supplies, and what
//! the verifier consumes. It does not interpret a Stwo proof and does not claim
//! that the absence of a counterexample establishes protocol soundness.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod model;
mod mutation;
mod oracle;

pub use model::{
    BOUNDARY_SCHEMA_ID, BOUNDARY_SCHEMA_VERSION, BoundaryContract, BoundaryContractError,
    BoundaryObservation, BoundaryPath, CaseKind, CountAtPath, OutcomeClass, VerificationOutcome,
};
pub use mutation::{MutationOperation, MutationPlan, MutationPlanError, ScalarMutation};
pub use oracle::{
    BoundaryFinding, BoundaryFindingCode, BoundaryReport, BoundarySeverity, BoundaryVerdict,
    evaluate_boundary,
};
