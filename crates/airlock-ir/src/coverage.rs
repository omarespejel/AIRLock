//! Coverage statuses for executable proof surfaces.

use serde::{Deserialize, Serialize};

/// Four-state coverage model. Only [`CoverageStatus::Covered`] may be green.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    /// Modeled and all required gates completed for the declared profile.
    Covered,
    /// Executable but not modeled by the current analyzer.
    Unsupported,
    /// Unavailable from supported entry points; excluded from claims.
    Quarantined,
    /// Modeled but analysis timed out or could not conclude.
    Unknown,
}

impl CoverageStatus {
    /// Whether this status may be reported as release-green for the AIR lane.
    pub fn is_green(self) -> bool {
        matches!(self, Self::Covered)
    }
}

/// One executable surface in the coverage manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceEntry {
    /// Surface name (e.g. `fused-stage-a-q7`).
    pub name: String,
    /// Coverage status.
    pub status: CoverageStatus,
    /// Human rationale / next action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Profile / shape region this status applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_region: Option<String>,
}

/// Repository coverage manifest (`docs/airlock/coverage.toml` equivalent as YAML/JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageManifest {
    /// Schema label.
    pub schema: String,
    /// Surfaces.
    pub surfaces: Vec<SurfaceEntry>,
}

impl CoverageManifest {
    /// Fail closed if any executable name is missing.
    pub fn require_listed(&self, names: &[&str]) -> Result<(), Vec<String>> {
        let missing: Vec<String> = names
            .iter()
            .copied()
            .filter(|name| !self.surfaces.iter().any(|s| s.name == *name))
            .map(str::to_string)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    /// Returns false if any required surface is not COVERED.
    pub fn all_required_covered(&self, required: &[&str]) -> bool {
        required.iter().all(|name| {
            self.surfaces
                .iter()
                .find(|s| s.name == *name)
                .is_some_and(|s| s.status == CoverageStatus::Covered)
        })
    }
}
