//! Static semantic analysis over AuditIR.
//!
//! These lints are necessary but not sufficient for soundness. They exist to
//! catch high-value Stwo-specific defect classes before human review.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod confinement;
mod degree;
mod encoder;
mod logup;
mod lookup;
mod parameter;
mod preprocessed;
mod runner;
mod structure;

pub use confinement::ConfinementCertificate;
pub use degree::{base_degree, ext_degree, lint_declared_degree_bound, required_log_degree_bound};
pub use encoder::lint_encoder_bounds;
pub use logup::lint_logup_finalization;
pub use lookup::{
    ConfinementEvidence, TableMultiplicityObligation, lint_lookup_functionality,
    lint_table_multiplicity_support, table_multiplicity_obligations,
};
pub use parameter::lint_parameter_contract;
pub use preprocessed::lint_preprocessed_contract;
pub use runner::{LintOptions, lint_component, lint_manifest};
pub use structure::lint_component_structure;
