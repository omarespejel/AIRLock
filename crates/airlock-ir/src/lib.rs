//! AIRLock AuditIR: machine-readable representation of an instantiated AIR.
//!
//! This crate does **not** claim cryptographic soundness. It defines the data
//! model that static analysis, solvers, and Lean tracks consume.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod coverage;
mod expr;
mod hash;
mod manifest;
mod result;
mod schema;

pub use coverage::{
    COVERAGE_SCHEMA_ID, CoverageManifest, CoverageManifestError, CoverageStatus, SurfaceEntry,
};
pub use expr::{BaseExpr, ExtExpr, FieldSort};
pub use hash::{ContentHash, canonical_json, content_hash, hash_manifest, hash_u32_values};
pub use manifest::{
    AuditManifest, ColumnDecl, ColumnKind, CommitmentPhase, ComponentManifest, ConstraintDecl,
    IntegerEncoding, ParameterDecl, ParameterRole, PreprocessedColumn, RelationEntry, RelationRole,
    RowClass, RowSupport, SemanticContract, SemanticType, SignedEncoding,
};
pub use result::{AnalysisLane, Finding, FindingCode, GateReport, LaneStatus, Severity, Verdict};
pub use schema::{IR_SCHEMA_ID, IR_SCHEMA_VERSION};

/// M31 prime modulus used by Stwo base field.
pub const M31_P: u32 = (1 << 31) - 1;
