//! Deterministic mutation of the concrete Stwo proof fixture.

use airlock_boundary::{BoundaryPath, MutationOperation, MutationPlan, ScalarMutation};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use stwo::core::fields::qm31::SecureField;
use thiserror::Error;

use crate::DemoProof;

/// A mutated proof paired with replayable, content-addressed evidence.
#[derive(Debug)]
pub struct MutatedProof {
    /// Mutated concrete proof.
    pub proof: DemoProof,
    /// Generic mutation plan and canonical pre/post digests.
    pub plan: MutationPlan,
}

/// Apply generic mutation operations to a concrete Stwo proof.
pub fn mutate_proof(
    seed_id: impl Into<String>,
    seed: &DemoProof,
    operations: Vec<MutationOperation>,
) -> Result<MutatedProof, StwoMutationError> {
    if operations.is_empty() {
        return Err(StwoMutationError::EmptyOperations);
    }

    let seed_artifact_sha256 = proof_sha256(seed)?;
    let mut proof = seed.clone();
    for operation in &operations {
        apply_operation(&mut proof, operation)?;
    }
    let mutated_artifact_sha256 = proof_sha256(&proof)?;
    let plan = MutationPlan {
        seed_id: seed_id.into(),
        seed_artifact_sha256,
        mutated_artifact_sha256,
        operations,
    };
    plan.validate()
        .map_err(|error| StwoMutationError::InvalidPlan(error.to_string()))?;
    Ok(MutatedProof { proof, plan })
}

/// SHA-256 of the deterministic JSON representation of a concrete proof.
pub fn proof_sha256(proof: &DemoProof) -> Result<String, StwoMutationError> {
    let bytes = serde_json::to_vec(proof)
        .map_err(|error| StwoMutationError::Serialization(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn apply_operation(
    proof: &mut DemoProof,
    operation: &MutationOperation,
) -> Result<(), StwoMutationError> {
    match operation {
        MutationOperation::Drop { path, index } => {
            mutate_container(proof, path, ContainerMutation::Drop(*index))
        }
        MutationOperation::Duplicate { path, index } => {
            mutate_container(proof, path, ContainerMutation::Duplicate(*index))
        }
        MutationOperation::Swap { path, left, right } => {
            mutate_container(proof, path, ContainerMutation::Swap(*left, *right))
        }
        MutationOperation::Truncate { path, new_len } => {
            mutate_container(proof, path, ContainerMutation::Truncate(*new_len))
        }
        MutationOperation::ReplaceScalar { path, value } => replace_scalar(proof, path, *value),
    }
}

#[derive(Clone, Copy)]
enum ContainerMutation {
    Drop(usize),
    Duplicate(usize),
    Swap(usize, usize),
    Truncate(usize),
}

fn mutate_container(
    proof: &mut DemoProof,
    path: &BoundaryPath,
    mutation: ContainerMutation,
) -> Result<(), StwoMutationError> {
    match (path.field.as_str(), path.indices.as_slice()) {
        ("sampled_values", [tree, column]) => {
            let values = nested_column_mut(&mut proof.0.sampled_values.0, *tree, *column, path)?;
            mutate_vec(values, mutation, path)
        }
        _ => Err(StwoMutationError::UnsupportedPath(path.clone())),
    }
}

fn nested_column_mut<'a, T>(
    trees: &'a mut [Vec<Vec<T>>],
    tree: usize,
    column: usize,
    path: &BoundaryPath,
) -> Result<&'a mut Vec<T>, StwoMutationError> {
    trees
        .get_mut(tree)
        .and_then(|columns| columns.get_mut(column))
        .ok_or_else(|| StwoMutationError::PathOutOfBounds(path.clone()))
}

fn mutate_vec<T: Clone>(
    values: &mut Vec<T>,
    mutation: ContainerMutation,
    path: &BoundaryPath,
) -> Result<(), StwoMutationError> {
    match mutation {
        ContainerMutation::Drop(index) => {
            if index >= values.len() {
                return Err(StwoMutationError::IndexOutOfBounds {
                    path: path.clone(),
                    index,
                    len: values.len(),
                });
            }
            values.remove(index);
        }
        ContainerMutation::Duplicate(index) => {
            let value =
                values
                    .get(index)
                    .cloned()
                    .ok_or_else(|| StwoMutationError::IndexOutOfBounds {
                        path: path.clone(),
                        index,
                        len: values.len(),
                    })?;
            values.insert(index, value);
        }
        ContainerMutation::Swap(left, right) => {
            if left >= values.len() {
                return Err(StwoMutationError::IndexOutOfBounds {
                    path: path.clone(),
                    index: left,
                    len: values.len(),
                });
            }
            if right >= values.len() {
                return Err(StwoMutationError::IndexOutOfBounds {
                    path: path.clone(),
                    index: right,
                    len: values.len(),
                });
            }
            values.swap(left, right);
        }
        ContainerMutation::Truncate(new_len) => {
            if new_len >= values.len() {
                return Err(StwoMutationError::InvalidTruncation {
                    path: path.clone(),
                    new_len,
                    len: values.len(),
                });
            }
            values.truncate(new_len);
        }
    }
    Ok(())
}

fn replace_scalar(
    proof: &mut DemoProof,
    path: &BoundaryPath,
    mutation: ScalarMutation,
) -> Result<(), StwoMutationError> {
    match (path.field.as_str(), path.indices.as_slice()) {
        ("sampled_values", [tree, column, index]) => {
            let values = nested_column_mut(&mut proof.0.sampled_values.0, *tree, *column, path)?;
            let len = values.len();
            let value =
                values
                    .get_mut(*index)
                    .ok_or_else(|| StwoMutationError::IndexOutOfBounds {
                        path: path.clone(),
                        index: *index,
                        len,
                    })?;
            apply_secure_field(value, mutation, path)
        }
        _ => Err(StwoMutationError::UnsupportedPath(path.clone())),
    }
}

fn apply_secure_field(
    value: &mut SecureField,
    mutation: ScalarMutation,
    path: &BoundaryPath,
) -> Result<(), StwoMutationError> {
    *value = match mutation {
        ScalarMutation::Zero => SecureField::zero(),
        ScalarMutation::One => SecureField::one(),
        ScalarMutation::Increment => *value + SecureField::one(),
        ScalarMutation::Decrement => *value - SecureField::one(),
        ScalarMutation::Maximum | ScalarMutation::FlipBit { .. } => {
            return Err(StwoMutationError::UnsupportedScalar {
                path: path.clone(),
                mutation,
            });
        }
    };
    Ok(())
}

/// Mutation failures are evidence failures, never green boundary results.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StwoMutationError {
    /// No operation was supplied.
    #[error("at least one mutation operation is required")]
    EmptyOperations,
    /// Proof serialization failed.
    #[error("failed to serialize proof canonically: {0}")]
    Serialization(String),
    /// The requested proof path is outside the adapter's public schema.
    #[error("unsupported Stwo proof path: {0:?}")]
    UnsupportedPath(BoundaryPath),
    /// A tree, column, or scalar path does not exist in this proof.
    #[error("Stwo proof path is out of bounds: {0:?}")]
    PathOutOfBounds(BoundaryPath),
    /// An operation index does not exist in its target container.
    #[error("index {index} is out of bounds for {path:?} with length {len}")]
    IndexOutOfBounds {
        /// Target path.
        path: BoundaryPath,
        /// Invalid index.
        index: usize,
        /// Actual length.
        len: usize,
    },
    /// Truncation must make the canonical artifact strictly shorter.
    #[error("cannot truncate {path:?} from length {len} to {new_len}")]
    InvalidTruncation {
        /// Target path.
        path: BoundaryPath,
        /// Requested new length.
        new_len: usize,
        /// Actual length.
        len: usize,
    },
    /// Bit index exceeds the scalar representation.
    #[error("bit {bit} is out of bounds for {path:?}; scalar has {bits} bits")]
    BitOutOfBounds {
        /// Target path.
        path: BoundaryPath,
        /// Invalid bit.
        bit: usize,
        /// Scalar width.
        bits: usize,
    },
    /// Scalar strategy is not canonically defined for the selected field type.
    #[error("scalar mutation {mutation:?} is unsupported at {path:?}")]
    UnsupportedScalar {
        /// Target path.
        path: BoundaryPath,
        /// Unsupported strategy.
        mutation: ScalarMutation,
    },
    /// Constructed mutation plan failed proof-neutral validation.
    #[error("constructed mutation plan is invalid: {0}")]
    InvalidPlan(String),
}

#[cfg(test)]
mod tests {
    use airlock_boundary::{BoundaryPath, MutationOperation};

    use super::*;
    use crate::build_demo_fixture;

    #[test]
    fn mutation_is_content_addressed_and_replayable() {
        let fixture = build_demo_fixture().expect("fixture");
        let path = first_nonempty_sample_path(&fixture.proof).expect("sampled value");
        let mutated = mutate_proof(
            "demo-honest",
            &fixture.proof,
            vec![MutationOperation::ReplaceScalar {
                path,
                value: ScalarMutation::Increment,
            }],
        )
        .expect("mutation");

        assert_ne!(
            mutated.plan.seed_artifact_sha256,
            mutated.plan.mutated_artifact_sha256
        );
        mutated.plan.validate().expect("valid generic plan");
    }

    #[test]
    fn out_of_bounds_mutation_fails_without_panicking() {
        let fixture = build_demo_fixture().expect("fixture");
        let error = mutate_proof(
            "demo-honest",
            &fixture.proof,
            vec![MutationOperation::Drop {
                path: BoundaryPath::new("sampled_values", vec![999, 0]),
                index: 0,
            }],
        )
        .expect_err("out-of-bounds path must fail");
        assert!(matches!(error, StwoMutationError::PathOutOfBounds(_)));
    }

    fn first_nonempty_sample_path(proof: &DemoProof) -> Option<BoundaryPath> {
        for (tree_index, columns) in proof.0.sampled_values.iter().enumerate() {
            for (column_index, values) in columns.iter().enumerate() {
                if !values.is_empty() {
                    return Some(BoundaryPath::new(
                        "sampled_values",
                        vec![tree_index, column_index, 0],
                    ));
                }
            }
        }
        None
    }
}
