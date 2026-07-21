//! Static semantic analysis over AuditIR.
//!
//! These lints are necessary but not sufficient for soundness. They exist to
//! catch high-value Stwo-specific defect classes before human review.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod encoder;
mod lookup;
mod logup;
mod runner;

pub use encoder::lint_encoder_bounds;
pub use lookup::{lint_lookup_functionality, lint_table_multiplicity_support};
pub use logup::lint_logup_finalization;
pub use runner::{lint_component, lint_manifest, LintOptions};
