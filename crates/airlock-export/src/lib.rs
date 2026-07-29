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
//! Requires a sibling Stwo checkout at `../stwo` whose dependency source trees
//! match upstream baseline `f0d79b0fad440dcb0aaf1e20470fdbb37993ea2a`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod annotations;
mod concrete;
mod convert;
mod evaluator;
mod export;

pub use annotations::{
    ExportAnnotations, ParameterAnnotation, PreprocessedAttachment, RelationAnnotation,
    RelationCompression,
};
pub use concrete::{
    ConcreteAssignment, ConcreteEvaluationError, EvaluatedConstraint, EvaluatedRelation,
    constraints_hold, evaluate_constraints, evaluate_relations,
};
pub use evaluator::{AuditEvaluator, RawRelationEntry};
pub use export::{ExportError, REQUIRED_STWO_BASE_COMMIT, export_component};

/// Crate version string embedded in exported manifests.
pub const AIRLOCK_EXPORT_VERSION: &str = env!("CARGO_PKG_VERSION");
