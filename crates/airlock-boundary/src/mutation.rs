//! Structured, proof-system-neutral mutation plans.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::BoundaryPath;

/// A deterministic sequence of mutations applied to an honest proof seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationPlan {
    /// Stable identity of the honest proof or fixture being mutated.
    pub seed_id: String,
    /// SHA-256 digest of the canonical honest artifact bytes.
    pub seed_artifact_sha256: String,
    /// SHA-256 digest of the canonical post-mutation artifact bytes.
    pub mutated_artifact_sha256: String,
    /// Ordered mutations.
    pub operations: Vec<MutationOperation>,
}

impl MutationPlan {
    /// Validate that the plan can be replayed deterministically by an adapter.
    pub fn validate(&self) -> Result<(), MutationPlanError> {
        if self.seed_id.trim().is_empty() {
            return Err(MutationPlanError::EmptySeedId);
        }
        if !is_sha256(&self.seed_artifact_sha256) {
            return Err(MutationPlanError::InvalidArtifactDigest {
                field: "seed_artifact_sha256",
            });
        }
        if !is_sha256(&self.mutated_artifact_sha256) {
            return Err(MutationPlanError::InvalidArtifactDigest {
                field: "mutated_artifact_sha256",
            });
        }
        if self.seed_artifact_sha256 == self.mutated_artifact_sha256 {
            return Err(MutationPlanError::UnchangedArtifact);
        }
        if self.operations.is_empty() {
            return Err(MutationPlanError::EmptyOperations);
        }
        for (operation_index, operation) in self.operations.iter().enumerate() {
            let path = match operation {
                MutationOperation::Drop { path, .. }
                | MutationOperation::Duplicate { path, .. }
                | MutationOperation::Swap { path, .. }
                | MutationOperation::Truncate { path, .. }
                | MutationOperation::ReplaceScalar { path, .. } => path,
            };
            if path.field.trim().is_empty() {
                return Err(MutationPlanError::EmptyPath {
                    operation: operation_index,
                });
            }
            if let MutationOperation::Swap { left, right, .. } = operation
                && left == right
            {
                return Err(MutationPlanError::EqualSwapIndices {
                    operation: operation_index,
                });
            }
        }
        Ok(())
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// One structural or scalar proof mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationOperation {
    /// Delete one entry from a nested proof container.
    Drop {
        /// Container path.
        path: BoundaryPath,
        /// Entry index.
        index: usize,
    },
    /// Duplicate one existing entry in place.
    Duplicate {
        /// Container path.
        path: BoundaryPath,
        /// Entry index.
        index: usize,
    },
    /// Swap two entries.
    Swap {
        /// Container path.
        path: BoundaryPath,
        /// First index.
        left: usize,
        /// Second index.
        right: usize,
    },
    /// Truncate a container to a deterministic length.
    Truncate {
        /// Container path.
        path: BoundaryPath,
        /// New length.
        new_len: usize,
    },
    /// Replace one scalar using a type-independent strategy interpreted by the adapter.
    ReplaceScalar {
        /// Scalar path.
        path: BoundaryPath,
        /// Replacement strategy.
        value: ScalarMutation,
    },
}

/// Common scalar mutations that adapters can map to native proof types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScalarMutation {
    /// Additive identity.
    Zero,
    /// Multiplicative identity.
    One,
    /// Largest canonical value of the native scalar representation.
    Maximum,
    /// Increment in the native representation.
    Increment,
    /// Decrement in the native representation.
    Decrement,
    /// Flip one bit in the serialized scalar.
    FlipBit {
        /// Zero-based bit index.
        bit: usize,
    },
}

/// Malformed mutation plans cannot be executed or reported as coverage.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MutationPlanError {
    /// Seed identity is empty.
    #[error("mutation seed id must not be empty")]
    EmptySeedId,
    /// Artifact evidence must use canonical lowercase SHA-256.
    #[error("{field} must be a 64-character lowercase SHA-256 digest")]
    InvalidArtifactDigest {
        /// Invalid field name.
        field: &'static str,
    },
    /// A mutation that leaves the canonical artifact unchanged is not evidence.
    #[error("mutation output is byte-identical to its honest seed")]
    UnchangedArtifact,
    /// A mutated case with no operations is indistinguishable from its seed.
    #[error("mutation plan must contain at least one operation")]
    EmptyOperations,
    /// One operation has no target path.
    #[error("mutation operation {operation} has an empty target path")]
    EmptyPath {
        /// Operation index.
        operation: usize,
    },
    /// Swapping one entry with itself is statically known to be a no-op.
    #[error("mutation operation {operation} swaps an entry with itself")]
    EqualSwapIndices {
        /// Operation index.
        operation: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_plan_round_trips_without_losing_replay_data() {
        let plan = MutationPlan {
            seed_id: "seed-7".to_owned(),
            seed_artifact_sha256: "11".repeat(32),
            mutated_artifact_sha256: "22".repeat(32),
            operations: vec![
                MutationOperation::Truncate {
                    path: BoundaryPath::new("sampled_values", vec![1, 0]),
                    new_len: 1,
                },
                MutationOperation::ReplaceScalar {
                    path: BoundaryPath::new("pow_nonce", vec![]),
                    value: ScalarMutation::FlipBit { bit: 9 },
                },
            ],
        };
        plan.validate().expect("valid plan");
        let encoded = serde_json::to_string(&plan).expect("serialize plan");
        let decoded: MutationPlan = serde_json::from_str(&encoded).expect("deserialize plan");
        assert_eq!(decoded, plan);
    }

    #[test]
    fn empty_mutation_plan_fails_closed() {
        let plan = MutationPlan {
            seed_id: "seed".to_owned(),
            seed_artifact_sha256: "11".repeat(32),
            mutated_artifact_sha256: "22".repeat(32),
            operations: vec![],
        };
        assert_eq!(plan.validate(), Err(MutationPlanError::EmptyOperations));
    }

    #[test]
    fn unchanged_mutation_artifact_fails_closed() {
        let plan = MutationPlan {
            seed_id: "seed".to_owned(),
            seed_artifact_sha256: "11".repeat(32),
            mutated_artifact_sha256: "11".repeat(32),
            operations: vec![MutationOperation::Truncate {
                path: BoundaryPath::new("proof", vec![]),
                new_len: 1,
            }],
        };
        assert_eq!(plan.validate(), Err(MutationPlanError::UnchangedArtifact));
    }

    #[test]
    fn equal_index_swap_fails_closed() {
        let plan = MutationPlan {
            seed_id: "seed".to_owned(),
            seed_artifact_sha256: "11".repeat(32),
            mutated_artifact_sha256: "22".repeat(32),
            operations: vec![MutationOperation::Swap {
                path: BoundaryPath::new("proof", vec![]),
                left: 2,
                right: 2,
            }],
        };
        assert_eq!(
            plan.validate(),
            Err(MutationPlanError::EqualSwapIndices { operation: 0 })
        );
    }

    #[test]
    fn malformed_artifact_digest_fails_closed() {
        let plan = MutationPlan {
            seed_id: "seed".to_owned(),
            seed_artifact_sha256: "ABC".to_owned(),
            mutated_artifact_sha256: "22".repeat(32),
            operations: vec![MutationOperation::Drop {
                path: BoundaryPath::new("proof", vec![]),
                index: 0,
            }],
        };
        assert_eq!(
            plan.validate(),
            Err(MutationPlanError::InvalidArtifactDigest {
                field: "seed_artifact_sha256"
            })
        );
    }

    #[test]
    fn unknown_nested_mutation_fields_are_rejected() {
        let json = r#"{
            "seed_id":"seed",
            "seed_artifact_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
            "mutated_artifact_sha256":"2222222222222222222222222222222222222222222222222222222222222222",
            "operations":[{
                "kind":"drop",
                "path":{"field":"proof","indices":[]},
                "index":0,
                "ignored":true
            }]
        }"#;
        let error = serde_json::from_str::<MutationPlan>(json).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));
    }
}
