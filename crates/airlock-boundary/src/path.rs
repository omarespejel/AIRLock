//! Neutral paths into nested proof or transcript artifacts.

use serde::{Deserialize, Serialize};

/// A stable path to a nested artifact container or scalar.
///
/// `field` names the top-level field and `indices` selects nested tree,
/// column, layer, or scalar positions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPath {
    /// Stable top-level field name.
    pub field: String,
    /// Nested container indices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indices: Vec<usize>,
}

impl ArtifactPath {
    /// Construct a path from a field name and nested indices.
    pub fn new(field: impl Into<String>, indices: impl Into<Vec<usize>>) -> Self {
        Self {
            field: field.into(),
            indices: indices.into(),
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.field.trim().is_empty()
    }
}

/// Compatibility alias for verifier-boundary callers.
pub type BoundaryPath = ArtifactPath;
