//! Semantic annotations merged onto an AuditEvaluator export.

use airlock_ir::{
    CommitmentPhase, PreprocessedColumn, RelationRole, RowSupport, SemanticContract, SemanticType,
};
use indexmap::IndexMap;

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
            witness_phase: CommitmentPhase::Phase1Original,
        }
    }
}

/// Per-relation semantic annotation.
#[derive(Clone, Debug)]
pub struct RelationAnnotation {
    /// Query vs table.
    pub role: RelationRole,
    /// Rows where multiplicity may be nonzero.
    pub row_support: RowSupport,
    /// Challenge phase after which interaction may depend on this relation.
    pub challenge_phase: CommitmentPhase,
}

impl Default for RelationAnnotation {
    fn default() -> Self {
        Self {
            role: RelationRole::Query,
            row_support: RowSupport::All,
            challenge_phase: CommitmentPhase::Phase2Interaction,
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
