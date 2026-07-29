//! Coverage statuses for executable proof surfaces.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable schema identifier for repository coverage manifests.
pub const COVERAGE_SCHEMA_ID: &str = "airlock.coverage";

/// Structural errors that make a coverage manifest unsafe to evaluate.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoverageManifestError {
    /// The manifest does not identify the supported schema.
    #[error("unexpected coverage schema `{found}`; expected `{COVERAGE_SCHEMA_ID}`")]
    WrongSchema {
        /// Schema value supplied by the manifest.
        found: String,
    },
    /// An empty inventory could make omitted surfaces look green.
    #[error("coverage manifest must list at least one surface")]
    Empty,
    /// Empty names cannot be required reliably.
    #[error("coverage surface names must not be empty")]
    EmptyName,
    /// Duplicate names make status selection order-dependent.
    #[error("duplicate coverage surface `{0}`")]
    DuplicateName(String),
}

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
    /// Validate the manifest shape before using statuses in a release decision.
    pub fn validate(&self) -> Result<(), CoverageManifestError> {
        if self.schema != COVERAGE_SCHEMA_ID {
            return Err(CoverageManifestError::WrongSchema {
                found: self.schema.clone(),
            });
        }
        if self.surfaces.is_empty() {
            return Err(CoverageManifestError::Empty);
        }

        let mut names = BTreeSet::new();
        for surface in &self.surfaces {
            if surface.name.trim().is_empty() {
                return Err(CoverageManifestError::EmptyName);
            }
            if !names.insert(surface.name.as_str()) {
                return Err(CoverageManifestError::DuplicateName(surface.name.clone()));
            }
        }
        Ok(())
    }

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
        if required.is_empty() || self.validate().is_err() {
            return false;
        }
        required.iter().all(|name| {
            self.surfaces
                .iter()
                .find(|s| s.name == *name)
                .is_some_and(|s| s.status == CoverageStatus::Covered)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(name: &str, status: CoverageStatus) -> SurfaceEntry {
        SurfaceEntry {
            name: name.to_owned(),
            status,
            note: None,
            profile_region: None,
        }
    }

    #[test]
    fn validation_rejects_wrong_schema() {
        let manifest = CoverageManifest {
            schema: "airlock.coverage.v2".to_owned(),
            surfaces: vec![surface("a", CoverageStatus::Covered)],
        };
        assert!(matches!(
            manifest.validate(),
            Err(CoverageManifestError::WrongSchema { .. })
        ));
    }

    #[test]
    fn validation_rejects_empty_inventory() {
        let manifest = CoverageManifest {
            schema: COVERAGE_SCHEMA_ID.to_owned(),
            surfaces: vec![],
        };
        assert_eq!(manifest.validate(), Err(CoverageManifestError::Empty));
    }

    #[test]
    fn validation_rejects_empty_and_duplicate_names() {
        let empty_name = CoverageManifest {
            schema: COVERAGE_SCHEMA_ID.to_owned(),
            surfaces: vec![surface(" ", CoverageStatus::Covered)],
        };
        assert_eq!(empty_name.validate(), Err(CoverageManifestError::EmptyName));

        let duplicate = CoverageManifest {
            schema: COVERAGE_SCHEMA_ID.to_owned(),
            surfaces: vec![
                surface("a", CoverageStatus::Covered),
                surface("a", CoverageStatus::Unsupported),
            ],
        };
        assert_eq!(
            duplicate.validate(),
            Err(CoverageManifestError::DuplicateName("a".to_owned()))
        );
    }

    #[test]
    fn validation_accepts_unique_nonempty_surfaces() {
        let manifest = CoverageManifest {
            schema: COVERAGE_SCHEMA_ID.to_owned(),
            surfaces: vec![
                surface("a", CoverageStatus::Covered),
                surface("b", CoverageStatus::Unsupported),
            ],
        };
        assert_eq!(manifest.validate(), Ok(()));
        assert!(!manifest.all_required_covered(&[]));
        assert!(manifest.all_required_covered(&["a"]));
        assert!(!manifest.all_required_covered(&["a", "b"]));
    }
}
