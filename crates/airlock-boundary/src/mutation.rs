//! Structured, proof-system-neutral mutation plans.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::BoundaryPath;

/// A deterministic sequence of mutations applied to an honest proof seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPlan {
    /// Stable identity of the honest proof or fixture being mutated.
    pub seed_id: String,
    /// Ordered mutations.
    pub operations: Vec<MutationOperation>,
}

impl MutationPlan {
    /// Validate that the plan can be replayed deterministically by an adapter.
    pub fn validate(&self) -> Result<(), MutationPlanError> {
        if self.seed_id.trim().is_empty() {
            return Err(MutationPlanError::EmptySeedId);
        }
        if self.operations.is_empty() {
            return Err(MutationPlanError::EmptyOperations);
        }
        for (operation, path) in self
            .operations
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                let path = match operation {
                    MutationOperation::Drop { path, .. }
                    | MutationOperation::Duplicate { path, .. }
                    | MutationOperation::Swap { path, .. }
                    | MutationOperation::Truncate { path, .. }
                    | MutationOperation::ReplaceScalar { path, .. } => path,
                };
                (index, path)
            })
        {
            if path.field.trim().is_empty() {
                return Err(MutationPlanError::EmptyPath { operation });
            }
        }
        Ok(())
    }
}

/// One structural or scalar proof mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
    /// A mutated case with no operations is indistinguishable from its seed.
    #[error("mutation plan must contain at least one operation")]
    EmptyOperations,
    /// One operation has no target path.
    #[error("mutation operation {operation} has an empty target path")]
    EmptyPath {
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
            operations: vec![],
        };
        assert_eq!(plan.validate(), Err(MutationPlanError::EmptyOperations));
    }
}
