//! Export Stwo `FrameworkEval` surfaces into AIRLock AuditIR.
//!
//! # Why this crate exists
//!
//! [`stwo_constraint_framework::expr::ExprEvaluator`] records constraints but:
//! - turns preprocessed columns into `Param(id)` without values;
//! - compresses LogUp tuples with formal challenges before retention.
//!
//! [`AuditEvaluator`] keeps **uncompressed** relation entries and preprocessed
//! column ids so static support/functionality lints can run. Concrete
//! preprocessed values and row-support semantics are attached via
//! [`ExportAnnotations`] (the semantic contract), not invented from the AIR AST.
//!
//! Requires a sibling Stwo checkout at `../stwo` pinned to
//! `41ba5a322c10841bbd50c36515b89fb8b29222d8`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod annotations;
mod convert;
mod evaluator;
mod export;

pub use annotations::{
    ExportAnnotations, PreprocessedAttachment, RelationAnnotation,
};
pub use evaluator::{AuditEvaluator, RawRelationEntry};
pub use export::{export_component, ExportError, STWO_PIN_COMMIT};

/// Crate version string embedded in exported manifests.
pub const AIRLOCK_EXPORT_VERSION: &str = env!("CARGO_PKG_VERSION");
