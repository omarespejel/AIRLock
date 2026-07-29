//! Semantic annotations merged onto an AuditEvaluator export.

use airlock_ir::{
    CommitmentPhase, FieldSort, ParameterRole, PreprocessedColumn, RelationRole, RowSupport,
    SemanticContract, SemanticType,
};
use indexmap::IndexMap;
use stwo::core::fields::qm31::SecureField;

/// Annotations that cannot be recovered from `FrameworkEval` alone.
#[derive(Clone, Debug)]
pub struct ExportAnnotations {
    /// Component display name.
    pub component_name: String,
    /// Semantic contract.
    pub contract: SemanticContract,
    /// Per-relation role + row support (keyed by relation name).
    pub relations: IndexMap<String, RelationAnnotation>,
    /// Concrete preprocessed columns keyed by Stwo `PreProcessedColumnId.id`.
    pub preprocessed: IndexMap<String, PreprocessedAttachment>,
    /// Optional column semantic types keyed by AuditIR column id.
    pub column_semantics: IndexMap<String, SemanticType>,
    /// Explicit declarations for component-specific formal parameters.
    ///
    /// Standard LogUp challenges and `claimed_sum` are derived automatically.
    pub parameters: IndexMap<String, ParameterAnnotation>,
    /// Default commitment phase for original-trace witness columns.
    pub witness_phase: CommitmentPhase,
}

impl Default for ExportAnnotations {
    fn default() -> Self {
        Self {
            component_name: "unnamed".into(),
            contract: SemanticContract::default(),
            relations: IndexMap::new(),
            preprocessed: IndexMap::new(),
            column_semantics: IndexMap::new(),
            parameters: IndexMap::new(),
            witness_phase: CommitmentPhase::Phase1Original,
        }
    }
}

/// Semantic declaration for a formal parameter not derived by the exporter.
#[derive(Clone, Debug)]
pub struct ParameterAnnotation {
    /// Field containing the parameter.
    pub field: FieldSort,
    /// Verifier-visible role.
    pub role: ParameterRole,
    /// Earliest phase after which the value is available.
    pub available_after: CommitmentPhase,
}

/// Per-relation semantic annotation.
#[derive(Clone, Debug)]
pub struct RelationAnnotation {
    /// Compression rule the exporter is allowed to reconstruct.
    pub compression: RelationCompression,
    /// Query vs table.
    pub role: RelationRole,
    /// Rows where multiplicity may be nonzero.
    pub row_support: RowSupport,
    /// Challenge phase after which interaction may depend on this relation.
    pub challenge_phase: CommitmentPhase,
}

/// Relation-compression contracts supported by the exporter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationCompression {
    /// Stwo's `LookupElements`: `x_0 + alpha*x_1 + ... - z`.
    ///
    /// The reference values must be the concrete challenges held by the
    /// `FrameworkEval` instance being exported. They are used only to verify
    /// that its `Relation::combine` implementation matches the symbolic
    /// reconstruction; the exported AuditIR still uses formal parameters.
    StwoLookupElements {
        /// Concrete `z` challenge in Stwo coordinate order.
        z: [u32; 4],
        /// Concrete `alpha` challenge in Stwo coordinate order.
        alpha: [u32; 4],
    },
}

impl RelationCompression {
    /// Declare the concrete challenges used by Stwo's `LookupElements`.
    pub fn stwo_lookup_elements(z: SecureField, alpha: SecureField) -> Self {
        Self::StwoLookupElements {
            z: z.to_m31_array().map(|value| value.0),
            alpha: alpha.to_m31_array().map(|value| value.0),
        }
    }
}

/// Preprocessed column values + lengths for linting.
#[derive(Clone, Debug)]
pub struct PreprocessedAttachment {
    /// Semantic length.
    pub semantic_length: u64,
    /// Physical length.
    pub physical_length: u64,
    /// Optional concrete values.
    pub values: Option<Vec<u32>>,
    /// Optional generator id.
    pub generator_id: Option<String>,
    /// Semantic type override.
    pub semantic_type: SemanticType,
}

impl PreprocessedAttachment {
    /// Build an AuditIR preprocessed column.
    pub fn to_ir(&self, id: impl Into<String>) -> PreprocessedColumn {
        let id = id.into();
        let values_hash = self
            .values
            .as_ref()
            .map(|values| airlock_ir::hash_u32_values(values));
        PreprocessedColumn {
            id,
            semantic_length: self.semantic_length,
            physical_length: self.physical_length,
            values_hash,
            values: self.values.clone(),
            generator_id: self.generator_id.clone(),
        }
    }
}
