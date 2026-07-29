//! Static semantic analysis over AuditIR.
//!
//! These lints are necessary but not sufficient for soundness. They exist to
//! catch high-value Stwo-specific defect classes before human review.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod encoder;
mod logup;
mod lookup;
mod parameter;
mod runner;

pub use encoder::lint_encoder_bounds;
pub use logup::lint_logup_finalization;
pub use lookup::{lint_lookup_functionality, lint_table_multiplicity_support};
pub use parameter::lint_parameter_contract;
pub use runner::{LintOptions, lint_component, lint_manifest};
