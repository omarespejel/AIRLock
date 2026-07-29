//! Content-addressed requests for deterministic Stwo replay workers.

use airlock_boundary::{CaseKind, MutationOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DifferentialReplay, STWO_DEMO_TARGET, STWO_SOURCE_ID, StwoBoundaryAdapter, StwoBoundaryError,
};

/// Stable schema identifier for isolated replay requests.
pub const REPLAY_REQUEST_SCHEMA: &str = "airlock.stwo-replay-request";

/// Serialized isolated replay request version.
pub const REPLAY_REQUEST_VERSION: &str = "0.1.0";

const MAX_MUTATION_OPERATIONS: usize = 128;
const MAX_CASE_ID_BYTES: usize = 128;

/// Honest or adversarial execution requested from the isolated worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayCase {
    /// Regenerate and verify the unmodified deterministic proof.
    Honest,
    /// Regenerate the proof, apply generic mutations, and verify both layers.
    Mutation {
        /// Stable identity for this mutation campaign case.
        case_id: String,
        /// Ordered generic operations applied to the honest proof.
        operations: Vec<MutationOperation>,
    },
}

/// Complete, pinned input to one isolated Stwo replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    /// Request schema identity.
    pub schema: String,
    /// Request schema version.
    pub schema_version: String,
    /// Fixed executable component identity.
    pub target: String,
    /// Exact pinned Stwo source identity.
    pub upstream_commit: String,
    /// Requested proof case.
    pub case: ReplayCase,
}

impl ReplayRequest {
    /// Construct the canonical honest replay request.
    pub fn honest() -> Self {
        Self::new(ReplayCase::Honest)
    }

    /// Construct a canonical mutation request.
    pub fn mutation(case_id: impl Into<String>, operations: Vec<MutationOperation>) -> Self {
        Self::new(ReplayCase::Mutation {
            case_id: case_id.into(),
            operations,
        })
    }

    fn new(case: ReplayCase) -> Self {
        Self {
            schema: REPLAY_REQUEST_SCHEMA.to_owned(),
            schema_version: REPLAY_REQUEST_VERSION.to_owned(),
            target: STWO_DEMO_TARGET.to_owned(),
            upstream_commit: STWO_SOURCE_ID.to_owned(),
            case,
        }
    }

    /// Validate provenance and bounded replay input before worker launch.
    pub fn validate(&self) -> Result<(), ReplayRequestError> {
        if self.schema != REPLAY_REQUEST_SCHEMA || self.schema_version != REPLAY_REQUEST_VERSION {
            return Err(ReplayRequestError::WrongSchema {
                schema: self.schema.clone(),
                version: self.schema_version.clone(),
            });
        }
        if self.target != STWO_DEMO_TARGET {
            return Err(ReplayRequestError::WrongTarget(self.target.clone()));
        }
        if self.upstream_commit != STWO_SOURCE_ID {
            return Err(ReplayRequestError::WrongSource(
                self.upstream_commit.clone(),
            ));
        }
        if let ReplayCase::Mutation {
            case_id,
            operations,
        } = &self.case
        {
            validate_case_id(case_id)?;
            if operations.is_empty() || operations.len() > MAX_MUTATION_OPERATIONS {
                return Err(ReplayRequestError::InvalidOperationCount(operations.len()));
            }
        }
        Ok(())
    }

    /// Stable case identity expected in both verifier-layer observations.
    pub fn case_id(&self) -> &str {
        match &self.case {
            ReplayCase::Honest => "honest-baseline",
            ReplayCase::Mutation { case_id, .. } => case_id,
        }
    }

    /// Bind a worker response to this request's exact case and mutation plan.
    pub(crate) fn validate_replay(
        &self,
        replay: &DifferentialReplay,
    ) -> Result<(), ReplayRequestError> {
        self.validate()?;
        replay.validate()?;
        for observation in [&replay.raw_pcs.observation, &replay.framework.observation] {
            if observation.case_id != self.case_id() {
                return Err(ReplayRequestError::ResponseMismatch(
                    "worker replay case id differs from the request".to_owned(),
                ));
            }
            match (&self.case, observation.case_kind, &observation.mutation) {
                (ReplayCase::Honest, CaseKind::Honest, None) => {}
                (
                    ReplayCase::Mutation {
                        case_id,
                        operations,
                    },
                    CaseKind::Mutated,
                    Some(plan),
                ) if plan.seed_id == *case_id && plan.operations == *operations => {}
                _ => {
                    return Err(ReplayRequestError::ResponseMismatch(
                        "worker replay case or mutation plan differs from the request".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Execute one validated request in the current process.
///
/// CLI and service callers should normally invoke this through
/// [`crate::run_isolated_replay`]. The direct entry point exists for the worker
/// process and deterministic unit tests.
pub fn execute_replay_request(
    request: &ReplayRequest,
) -> Result<DifferentialReplay, ReplayRequestError> {
    request.validate()?;
    let adapter = StwoBoundaryAdapter::new()?;
    let replay = match &request.case {
        ReplayCase::Honest => adapter.replay_honest()?,
        ReplayCase::Mutation {
            case_id,
            operations,
        } => adapter.replay_mutation(case_id.clone(), operations.clone())?,
    };
    request.validate_replay(&replay)?;
    Ok(replay)
}

/// SHA-256 of the canonical JSON request representation.
pub fn replay_request_sha256(request: &ReplayRequest) -> Result<String, ReplayRequestError> {
    request.validate()?;
    let bytes = serde_json::to_vec(request)
        .map_err(|error| ReplayRequestError::Serialization(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_case_id(case_id: &str) -> Result<(), ReplayRequestError> {
    if case_id.is_empty()
        || case_id.len() > MAX_CASE_ID_BYTES
        || case_id.trim() != case_id
        || !case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ReplayRequestError::InvalidCaseId(case_id.to_owned()));
    }
    Ok(())
}

/// Invalid, stale, or unexecutable isolated replay request.
#[derive(Debug, Error)]
pub enum ReplayRequestError {
    /// Unknown request schema.
    #[error("unexpected replay request schema `{schema}` version `{version}`")]
    WrongSchema {
        /// Supplied schema.
        schema: String,
        /// Supplied version.
        version: String,
    },
    /// Request attempts to relabel the fixed demo component.
    #[error("unsupported replay target `{0}`")]
    WrongTarget(String),
    /// Request source identity does not match the compiled adapter.
    #[error("replay source identity does not match the compiled adapter: `{0}`")]
    WrongSource(String),
    /// Mutation case identity is malformed.
    #[error("invalid replay case id `{0}`")]
    InvalidCaseId(String),
    /// Mutation list is empty or exceeds the bounded worker contract.
    #[error("invalid mutation operation count {0}")]
    InvalidOperationCount(usize),
    /// Canonical request serialization failed.
    #[error("failed to serialize replay request: {0}")]
    Serialization(String),
    /// Worker response did not describe the requested case.
    #[error("isolated replay response mismatch: {0}")]
    ResponseMismatch(String),
    /// Real Stwo fixture, mutation, or replay failure.
    #[error(transparent)]
    Replay(#[from] StwoBoundaryError),
}

#[cfg(test)]
mod tests {
    use airlock_boundary::{MutationOperation, ScalarMutation};

    use super::*;

    #[test]
    fn request_identity_is_pinned_and_content_addressed() {
        let request = ReplayRequest::honest();
        request.validate().expect("valid request");
        assert_eq!(request.target, STWO_DEMO_TARGET);
        assert_eq!(request.upstream_commit, STWO_SOURCE_ID);
        assert_eq!(
            replay_request_sha256(&request).expect("digest"),
            replay_request_sha256(&request).expect("digest")
        );
    }

    #[test]
    fn relabeled_and_vacuous_requests_fail_closed() {
        let mut relabeled = ReplayRequest::honest();
        relabeled.target = "production-receipt".to_owned();
        assert!(matches!(
            relabeled.validate(),
            Err(ReplayRequestError::WrongTarget(_))
        ));

        let empty = ReplayRequest::mutation("empty", vec![]);
        assert!(matches!(
            empty.validate(),
            Err(ReplayRequestError::InvalidOperationCount(0))
        ));
    }

    #[test]
    fn direct_worker_execution_replays_a_real_mutation() {
        let adapter = StwoBoundaryAdapter::new().expect("adapter");
        let path = adapter
            .first_sampled_value_path()
            .expect("sampled-value path");
        let request = ReplayRequest::mutation(
            "corrupt-oods-sample",
            vec![MutationOperation::ReplaceScalar {
                path,
                value: ScalarMutation::Increment,
            }],
        );
        let replay = execute_replay_request(&request).expect("replay");
        assert!(replay.verdict.is_expected());
    }

    #[test]
    fn response_must_match_the_requested_case_and_operations() {
        let adapter = StwoBoundaryAdapter::new().expect("adapter");
        let path = adapter
            .first_sampled_value_path()
            .expect("sampled-value path");

        let mutated_as_honest = adapter
            .replay_mutation(
                "honest-baseline",
                vec![MutationOperation::ReplaceScalar {
                    path: path.clone(),
                    value: ScalarMutation::Increment,
                }],
            )
            .expect("mutated replay");
        assert!(matches!(
            ReplayRequest::honest().validate_replay(&mutated_as_honest),
            Err(ReplayRequestError::ResponseMismatch(_))
        ));

        let request = ReplayRequest::mutation(
            "same-id",
            vec![MutationOperation::ReplaceScalar {
                path: path.clone(),
                value: ScalarMutation::Increment,
            }],
        );
        let substituted = adapter
            .replay_mutation(
                "same-id",
                vec![MutationOperation::ReplaceScalar {
                    path,
                    value: ScalarMutation::Decrement,
                }],
            )
            .expect("substituted replay");
        assert!(matches!(
            request.validate_replay(&substituted),
            Err(ReplayRequestError::ResponseMismatch(_))
        ));
    }
}
