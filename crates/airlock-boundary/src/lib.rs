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
mod path;
mod transcript;
mod transcript_oracle;
mod witness;

pub use model::{
    BOUNDARY_SCHEMA_ID, BOUNDARY_SCHEMA_VERSION, BoundaryContract, BoundaryContractError,
    BoundaryObservation, CaseKind, CountAtPath, OutcomeClass, VerificationOutcome,
};
pub use mutation::{MutationOperation, MutationPlan, MutationPlanError, ScalarMutation};
pub use oracle::{
    BoundaryFinding, BoundaryFindingCode, BoundaryReport, BoundarySeverity, BoundaryVerdict,
    evaluate_boundary,
};
pub use path::{ArtifactPath, BoundaryPath};
pub use transcript::{
    AbsorbKind, AbsorptionRequirement, DomainSeparatorRequirement, DrawKind, DrawRequirement,
    PathValidationRequirement, PowRequirement, QueryShape, TRANSCRIPT_SCHEMA_ID,
    TRANSCRIPT_SCHEMA_VERSION, TranscriptContract, TranscriptContractError, TranscriptEvent,
    TranscriptInventory, TranscriptRecorder, TranscriptSource, TranscriptStep, TranscriptTrace,
    ValidationOutcome, ValidationRule, ZeroPowNoncePolicy,
};
pub use transcript_oracle::{
    TranscriptFinding, TranscriptFindingCode, TranscriptReport, TranscriptSeverity,
    TranscriptVerdict, evaluate_transcript,
};
pub use witness::{
    CONSTRAINT_VIOLATION_REJECTION_KIND, MAX_WITNESS_MUTATIONS, ProofGenerationOutcome,
    ProofRejectionCause, WITNESS_SCHEMA_ID, WITNESS_SCHEMA_VERSION, WitnessCellPath,
    WitnessContractError, WitnessFinding, WitnessFindingCode, WitnessMutationOperation,
    WitnessMutationPlan, WitnessObservation, WitnessPhase, WitnessReport, WitnessVerdict,
    evaluate_witness,
};
