//! Schema identity for AuditIR documents.

/// Stable schema identifier embedded in every manifest.
pub const IR_SCHEMA_ID: &str = "airlock.audit-ir";

/// Schema version. Bump when the serialized contract changes.
pub const IR_SCHEMA_VERSION: &str = "0.3.0";
