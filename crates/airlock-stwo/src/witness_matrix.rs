//! Deterministic cross-target witness-mutation matrix for the pinned Stwo adapter.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use airlock_boundary::{
    ScalarMutation, WITNESS_MATRIX_SCHEMA_ID, WITNESS_MATRIX_SCHEMA_VERSION, WitnessMatrixCampaign,
    WitnessMatrixCapability, WitnessMatrixCase, WitnessMatrixError, WitnessMatrixTarget,
    WitnessPhase, witness_matrix_case_id,
};
use serde_json::to_vec_pretty;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    HeldOutAdapter, HeldOutError, STWO_DEMO_WITNESS_TARGET, STWO_HELD_OUT_TARGET, STWO_SOURCE_ID,
    StwoWitnessAdapter, StwoWitnessError,
};

/// Stable identity of the frozen two-target, two-operator matrix.
pub const STWO_WITNESS_MATRIX_ID: &str = "stwo-original-m31-cell-matrix-v1";

/// Maximum accepted serialized matrix size.
pub const MAX_WITNESS_MATRIX_BYTES: u64 = 32 << 20;

const OPERATORS: [ScalarMutation; 2] = [ScalarMutation::Increment, ScalarMutation::Decrement];

const NON_CLAIMS: [&str; 6] = [
    "The matrix is not a solver-complete witness search.",
    "The matrix does not establish broad Stwo assurance.",
    "Statement binding is unsupported.",
    "Executable transcript, Fiat-Shamir, and FRI assurance is unsupported.",
    "Producer authentication and trusted time are unsupported.",
    "Observed executions do not establish cryptographic soundness.",
];

/// Generate the complete frozen matrix through AuditIR and real Stwo paths.
pub fn run_stwo_witness_matrix() -> Result<WitnessMatrixCampaign, StwoWitnessMatrixError> {
    let transition = StwoWitnessAdapter::new()?;
    let held_out = HeldOutAdapter::new()?;
    let targets = vec![
        run_transition_target(&transition)?,
        run_held_out_target(&held_out)?,
    ];
    let campaign = WitnessMatrixCampaign {
        schema: WITNESS_MATRIX_SCHEMA_ID.to_owned(),
        schema_version: WITNESS_MATRIX_SCHEMA_VERSION.to_owned(),
        matrix_id: STWO_WITNESS_MATRIX_ID.to_owned(),
        targets,
        non_claims: NON_CLAIMS.map(str::to_owned).to_vec(),
    };
    validate_stwo_witness_matrix(&campaign)?;
    Ok(campaign)
}

/// Validate the generic contract and exact AIRLock Stwo matrix policy.
pub fn validate_stwo_witness_matrix(
    campaign: &WitnessMatrixCampaign,
) -> Result<(), StwoWitnessMatrixError> {
    campaign.validate()?;
    if campaign.matrix_id != STWO_WITNESS_MATRIX_ID
        || campaign.non_claims != NON_CLAIMS
        || campaign.targets.len() != 2
    {
        return Err(StwoWitnessMatrixError::WrongPolicy);
    }

    let transition = StwoWitnessAdapter::new()?;
    let held_out = HeldOutAdapter::new()?;
    let expected = [
        transition_capability(&transition)?,
        held_out_capability(&held_out)?,
    ];
    if campaign
        .targets
        .iter()
        .map(|target| &target.capability)
        .ne(expected.iter())
    {
        return Err(StwoWitnessMatrixError::WrongPolicy);
    }
    Ok(())
}

/// Write a structurally valid matrix without replacing an existing artifact.
///
/// Blocked campaigns remain writable so a counterexample, panic, timeout, or
/// inconclusive result is not discarded. Callers must separately require
/// completion before reporting a successful gate.
pub fn write_stwo_witness_matrix(
    path: &Path,
    campaign: &WitnessMatrixCampaign,
) -> Result<String, StwoWitnessMatrixError> {
    validate_stwo_witness_matrix(campaign)?;
    let mut bytes = to_vec_pretty(campaign)
        .map_err(|error| StwoWitnessMatrixError::Malformed(error.to_string()))?;
    bytes.push(b'\n');
    enforce_size(bytes.len() as u64)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| StwoWitnessMatrixError::Io(error.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| StwoWitnessMatrixError::Io(error.to_string()))?;
    Ok(sha256_bytes(&bytes))
}

/// Read and structurally validate a matrix without executing fresh proofs.
pub fn read_stwo_witness_matrix(
    path: &Path,
) -> Result<(WitnessMatrixCampaign, String), StwoWitnessMatrixError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| StwoWitnessMatrixError::Io(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| StwoWitnessMatrixError::Io(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(StwoWitnessMatrixError::NotRegularFile);
    }
    enforce_size(metadata.len())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_WITNESS_MATRIX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| StwoWitnessMatrixError::Io(error.to_string()))?;
    enforce_size(bytes.len() as u64)?;
    let campaign: WitnessMatrixCampaign = serde_json::from_slice(&bytes)
        .map_err(|error| StwoWitnessMatrixError::Malformed(error.to_string()))?;
    validate_stwo_witness_matrix(&campaign)?;
    Ok((campaign, sha256_bytes(&bytes)))
}

/// Freshly execute the matrix and require exact agreement with the artifact.
///
/// This comparison also permits a reproducible blocked campaign. Callers must
/// separately require completion before reporting a successful gate.
pub fn verify_stwo_witness_matrix_fresh(
    campaign: &WitnessMatrixCampaign,
) -> Result<(), StwoWitnessMatrixError> {
    validate_stwo_witness_matrix(campaign)?;
    let fresh = run_stwo_witness_matrix()?;
    if fresh != *campaign {
        return Err(StwoWitnessMatrixError::FreshReplayMismatch);
    }
    Ok(())
}

fn run_transition_target(
    adapter: &StwoWitnessAdapter,
) -> Result<WitnessMatrixTarget, StwoWitnessMatrixError> {
    let capability = transition_capability(adapter)?;
    let mut cases = Vec::with_capacity(capability.row_count * capability.operators.len());
    for column in &capability.columns {
        for row in 0..capability.row_count {
            for operator in &capability.operators {
                let operation = adapter.mutation_operation(row, *operator)?;
                let case_id = witness_matrix_case_id(column, row, *operator)?;
                let replay = adapter.replay_mutation(&case_id, vec![operation.clone()])?;
                cases.push(WitnessMatrixCase {
                    case_id,
                    operation,
                    observation: replay.observation,
                    report: replay.report,
                });
            }
        }
    }
    Ok(WitnessMatrixTarget::from_cases(capability, cases))
}

fn run_held_out_target(
    adapter: &HeldOutAdapter,
) -> Result<WitnessMatrixTarget, StwoWitnessMatrixError> {
    let capability = held_out_capability(adapter)?;
    let mut cases = Vec::with_capacity(
        capability.columns.len() * capability.row_count * capability.operators.len(),
    );
    for (column_index, column) in capability.columns.iter().enumerate() {
        for row in 0..capability.row_count {
            for operator in &capability.operators {
                let operation = adapter.mutation_operation(column_index, row, *operator)?;
                let case_id = witness_matrix_case_id(column, row, *operator)?;
                let replay = adapter.replay_mutation(&case_id, vec![operation.clone()])?;
                cases.push(WitnessMatrixCase {
                    case_id,
                    operation,
                    observation: replay.observation,
                    report: replay.report,
                });
            }
        }
    }
    Ok(WitnessMatrixTarget::from_cases(capability, cases))
}

fn transition_capability(
    adapter: &StwoWitnessAdapter,
) -> Result<WitnessMatrixCapability, StwoWitnessMatrixError> {
    Ok(WitnessMatrixCapability {
        target: STWO_DEMO_WITNESS_TARGET.to_owned(),
        upstream_commit: STWO_SOURCE_ID.to_owned(),
        audit_ir_sha256: adapter.audit_ir_sha256()?,
        phase: WitnessPhase::Original,
        columns: vec![adapter.original_column_id().to_owned()],
        row_count: adapter.row_count(),
        operators: OPERATORS.to_vec(),
    })
}

fn held_out_capability(
    adapter: &HeldOutAdapter,
) -> Result<WitnessMatrixCapability, StwoWitnessMatrixError> {
    Ok(WitnessMatrixCapability {
        target: STWO_HELD_OUT_TARGET.to_owned(),
        upstream_commit: STWO_SOURCE_ID.to_owned(),
        audit_ir_sha256: adapter.audit_ir_sha256()?,
        phase: WitnessPhase::Original,
        columns: adapter.original_column_ids().to_vec(),
        row_count: adapter.row_count(),
        operators: OPERATORS.to_vec(),
    })
}

fn enforce_size(size: u64) -> Result<(), StwoWitnessMatrixError> {
    if size == 0 || size > MAX_WITNESS_MATRIX_BYTES {
        return Err(StwoWitnessMatrixError::InvalidSize(size));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Failure to generate, validate, persist, or freshly replay the Stwo matrix.
#[derive(Debug, Error)]
pub enum StwoWitnessMatrixError {
    /// Transition adapter failure.
    #[error(transparent)]
    Transition(#[from] StwoWitnessError),
    /// Held-out adapter failure.
    #[error(transparent)]
    HeldOut(#[from] HeldOutError),
    /// Proof-neutral campaign contract failure.
    #[error(transparent)]
    Contract(#[from] WitnessMatrixError),
    /// Matrix does not match the exact two-target Stwo policy.
    #[error("witness matrix differs from the frozen AIRLock Stwo policy")]
    WrongPolicy,
    /// Artifact is empty or exceeds the fixed bound.
    #[error("witness-matrix artifact has invalid size {0} bytes")]
    InvalidSize(u64),
    /// Artifact path is not a regular file.
    #[error("witness-matrix artifact must be a regular file")]
    NotRegularFile,
    /// Filesystem operation failed.
    #[error("witness-matrix I/O failed: {0}")]
    Io(String),
    /// JSON is malformed or cannot be serialized.
    #[error("malformed witness-matrix artifact: {0}")]
    Malformed(String),
    /// Fresh proofs did not reproduce the stored campaign.
    #[error("stored witness matrix does not match fresh execution")]
    FreshReplayMismatch,
}

#[cfg(test)]
mod tests {
    use airlock_boundary::{
        ProofGenerationOutcome, WitnessMatrixError, WitnessMatrixTarget, evaluate_witness,
    };

    use super::*;
    use crate::temp::PrivateTempDir;

    #[test]
    fn frozen_matrix_replays_every_declared_tuple_and_fails_closed() {
        let campaign = run_stwo_witness_matrix().expect("run matrix");
        validate_stwo_witness_matrix(&campaign).expect("validate matrix");
        assert_eq!(campaign.targets.len(), 2);
        assert_eq!(
            campaign
                .targets
                .iter()
                .map(|target| target.counts.total)
                .sum::<usize>(),
            128
        );
        assert_eq!(
            campaign
                .targets
                .iter()
                .map(|target| target.counts.constraint_preserving_accepted)
                .sum::<usize>(),
            16
        );
        assert_eq!(
            campaign
                .targets
                .iter()
                .map(|target| target.counts.constraint_violation_rejected)
                .sum::<usize>(),
            112
        );

        let mut missing_case = campaign.clone();
        missing_case.targets[0].cases.pop();
        assert!(matches!(
            validate_stwo_witness_matrix(&missing_case),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::WrongCaseCount { .. }
            ))
        ));

        let mut reordered = campaign.clone();
        reordered.targets[0].cases.swap(0, 1);
        assert!(matches!(
            validate_stwo_witness_matrix(&reordered),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::WrongCaseTuple { .. }
            ))
        ));

        let mut target_specific = campaign.clone();
        target_specific.targets.pop();
        assert!(matches!(
            validate_stwo_witness_matrix(&target_specific),
            Err(StwoWitnessMatrixError::WrongPolicy)
        ));

        let mut duplicate_target = campaign.clone();
        duplicate_target.targets[1] = duplicate_target.targets[0].clone();
        assert!(matches!(
            validate_stwo_witness_matrix(&duplicate_target),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::DuplicateTarget(_)
            ))
        ));

        let mut wrong_source = campaign.clone();
        wrong_source.targets[0].capability.upstream_commit = "other-source".to_owned();
        assert!(matches!(
            validate_stwo_witness_matrix(&wrong_source),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::CaseIdentityMismatch(_)
            ))
        ));

        let mut wrong_digest = campaign.clone();
        wrong_digest.targets[0].capability.audit_ir_sha256 = "aa".repeat(32);
        assert!(matches!(
            validate_stwo_witness_matrix(&wrong_digest),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::CaseIdentityMismatch(_)
            ))
        ));

        let mut smaller_capability = campaign.clone();
        smaller_capability.targets[0].capability.operators.pop();
        assert!(matches!(
            validate_stwo_witness_matrix(&smaller_capability),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::WrongCaseCount { .. }
            ))
        ));

        let mut stale_report = campaign.clone();
        stale_report.targets[0].cases[0].report.verdict =
            airlock_boundary::WitnessVerdict::Unsupported;
        assert!(matches!(
            validate_stwo_witness_matrix(&stale_report),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::WrongCaseReport(_)
            ))
        ));

        let mut wrong_count = campaign.clone();
        wrong_count.targets[0].counts.total += 1;
        assert!(matches!(
            validate_stwo_witness_matrix(&wrong_count),
            Err(StwoWitnessMatrixError::Contract(
                WitnessMatrixError::WrongAggregate(_)
            ))
        ));

        let mut blocked = campaign.clone();
        let first = &mut blocked.targets[0].cases[0];
        first.observation.proof_generation = ProofGenerationOutcome::Unsupported {
            reason: "injected unsupported result".to_owned(),
        };
        first.observation.verifier = None;
        first.report = evaluate_witness(&first.observation);
        blocked.targets[0] = WitnessMatrixTarget::from_cases(
            blocked.targets[0].capability.clone(),
            blocked.targets[0].cases.clone(),
        );
        validate_stwo_witness_matrix(&blocked).expect("blocked evidence remains valid");
        assert!(matches!(
            blocked.require_complete(),
            Err(WitnessMatrixError::CampaignBlocked(_))
        ));

        let directory = PrivateTempDir::create_in(&std::env::temp_dir(), ".airlock-matrix-")
            .expect("create temp directory");
        let path = directory.path().join("matrix.json");
        let written_sha = write_stwo_witness_matrix(&path, &campaign).expect("write matrix");
        let (read, read_sha) = read_stwo_witness_matrix(&path).expect("read matrix");
        assert_eq!(read, campaign);
        assert_eq!(read_sha, written_sha);
        assert!(write_stwo_witness_matrix(&path, &campaign).is_err());

        let blocked_path = directory.path().join("blocked-matrix.json");
        write_stwo_witness_matrix(&blocked_path, &blocked).expect("preserve blocked evidence");
        let (read_blocked, _) =
            read_stwo_witness_matrix(&blocked_path).expect("read blocked evidence");
        assert!(matches!(
            read_blocked.require_complete(),
            Err(WitnessMatrixError::CampaignBlocked(_))
        ));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&path, directory.path().join("matrix-link.json"))
                .expect("create symlink");
            assert!(read_stwo_witness_matrix(&directory.path().join("matrix-link.json")).is_err());
        }

        let mut valid_but_tampered = campaign;
        valid_but_tampered.targets[0].cases[0]
            .observation
            .mutation
            .as_mut()
            .expect("mutation")
            .mutated_witness_sha256 = "ab".repeat(32);
        validate_stwo_witness_matrix(&valid_but_tampered)
            .expect("content digest remains structurally valid");
        assert!(matches!(
            verify_stwo_witness_matrix_fresh(&valid_but_tampered),
            Err(StwoWitnessMatrixError::FreshReplayMismatch)
        ));
    }
}
