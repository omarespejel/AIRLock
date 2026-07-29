//! Schema identity for AuditIR documents.

/// Stable schema identifier embedded in every manifest.
pub const IR_SCHEMA_ID: &str = "airlock.audit-ir";

/// Schema version. Bump when the serialized contract changes.
pub const IR_SCHEMA_VERSION: &str = "0.4.0";

/// Minimum Stwo Circle-domain log size supported by this AuditIR schema.
pub const STWO_MIN_CIRCLE_DOMAIN_LOG_SIZE: u32 = 1;

/// Maximum Stwo Circle-domain log size supported by this AuditIR schema.
pub const STWO_MAX_CIRCLE_DOMAIN_LOG_SIZE: u32 = 30;
