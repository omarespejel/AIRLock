//! Schema identity for AuditIR documents.

/// Stable schema identifier embedded in every manifest.
pub const IR_SCHEMA_ID: &str = "airlock.audit-ir";

/// Schema version. Bump on breaking IR changes.
pub const IR_SCHEMA_VERSION: &str = "0.2.0";
