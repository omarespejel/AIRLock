//! Fixed-inventory, self-verifying evidence for the pinned Stwo campaign.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlock_boundary::{CaseKind, WitnessVerdict};
use airlock_ir::{CoverageManifest, CoverageStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DifferentialVerdict, IsolatedReplayError, ReplayBundleError, STWO_SOURCE_ID,
    StwoWitnessAdapter, StwoWitnessError, StwoWitnessReplay, generate_regression_source,
    read_verified_replay_bundle, run_isolated_replay,
};

/// Stable schema identifier for a sealed campaign.
pub const CAMPAIGN_SCHEMA_ID: &str = "airlock.stwo-campaign";

/// Serialized campaign-manifest version.
pub const CAMPAIGN_SCHEMA_VERSION: &str = "0.1.0";

const MANIFEST_FILE: &str = "campaign.json";
const CHECKSUM_FILE: &str = "SHA256SUMS";
const SUMMARY_FILE: &str = "SUMMARY.md";
const COVERAGE_FILE: &str = "coverage.yaml";
const HONEST_BUNDLE: &str = "honest";
const MUTATED_BUNDLE: &str = "corrupt-oods-sample";
const REGRESSION_FILE: &str = "corrupt-oods-sample-regression.rs";
const WITNESS_HONEST_FILE: &str = "witness-honest.json";
const WITNESS_PRESERVING_FILE: &str = "witness-preserving.json";
const WITNESS_VIOLATING_FILE: &str = "witness-violating.json";
const MAX_ARTIFACT_BYTES: u64 = 8 << 20;
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
const MAX_SUMMARY_BYTES: u64 = 64 << 10;
const MAX_COVERAGE_BYTES: u64 = 1 << 20;
const MAX_REGRESSION_BYTES: u64 = 1 << 20;
const MAX_CHECKSUM_BYTES: u64 = 16 << 10;

const NON_CLAIMS: [&str; 5] = [
    "Statement binding is unsupported.",
    "Executable transcript, Fiat-Shamir, and FRI assurance is unsupported.",
    "Broad evidence provenance and producer authentication is unsupported.",
    "Broad Stwo and production-integration coverage is unsupported.",
    "Observed executions do not establish a cryptographic soundness theorem.",
];

const PAYLOAD_PATHS: [&str; 12] = [
    "corrupt-oods-sample/SHA256SUMS",
    "corrupt-oods-sample/report.json",
    "corrupt-oods-sample/request.json",
    REGRESSION_FILE,
    COVERAGE_FILE,
    "honest/SHA256SUMS",
    "honest/report.json",
    "honest/request.json",
    SUMMARY_FILE,
    WITNESS_HONEST_FILE,
    WITNESS_PRESERVING_FILE,
    WITNESS_VIOLATING_FILE,
];

/// One fixed campaign case and its expected typed verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCase {
    /// Stable campaign case identity.
    pub case_id: String,
    /// Independent assurance lane exercised by the case.
    pub lane: String,
    /// Relative path containing the typed result.
    pub artifact: String,
    /// Exact serialized verdict required for this case.
    pub expected_verdict: String,
}

/// Digest and bounded size of one campaign payload file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignFile {
    /// Fixed forward-slash relative path.
    pub path: String,
    /// SHA-256 of the exact bytes.
    pub sha256: String,
    /// Exact byte count.
    pub size_bytes: u64,
}

/// Deterministic manifest for the complete executable campaign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignManifest {
    /// Manifest schema identity.
    pub schema: String,
    /// Manifest schema version.
    pub schema_version: String,
    /// Exact reviewed AIRLock source commit.
    pub airlock_commit: String,
    /// Exact pinned Stwo source identity.
    pub stwo_source_id: String,
    /// SHA-256 of the exact isolated replay worker used by both boundary cases.
    pub replay_worker_sha256: String,
    /// Frozen executable case inventory.
    pub cases: Vec<CampaignCase>,
    /// Fixed non-claims shown beside successful executions.
    pub non_claims: Vec<String>,
    /// Every payload file except this manifest and top-level checksums.
    pub payload_files: Vec<CampaignFile>,
}

impl CampaignManifest {
    fn validate(&self, expected_airlock_commit: &str) -> Result<(), CampaignError> {
        if self.schema != CAMPAIGN_SCHEMA_ID || self.schema_version != CAMPAIGN_SCHEMA_VERSION {
            return Err(CampaignError::WrongSchema {
                schema: self.schema.clone(),
                version: self.schema_version.clone(),
            });
        }
        validate_commit(expected_airlock_commit)?;
        if self.airlock_commit != expected_airlock_commit {
            return Err(CampaignError::WrongAirlockCommit {
                expected: expected_airlock_commit.to_owned(),
                actual: self.airlock_commit.clone(),
            });
        }
        if self.stwo_source_id != STWO_SOURCE_ID {
            return Err(CampaignError::WrongStwoSource(self.stwo_source_id.clone()));
        }
        if !is_sha256(&self.replay_worker_sha256) {
            return Err(CampaignError::InvalidWorkerDigest(
                self.replay_worker_sha256.clone(),
            ));
        }
        if self.cases != expected_cases() {
            return Err(CampaignError::WrongCaseInventory);
        }
        if self.non_claims != expected_non_claims() {
            return Err(CampaignError::WrongNonClaims);
        }
        if self.payload_files.len() != PAYLOAD_PATHS.len()
            || self
                .payload_files
                .iter()
                .map(|file| file.path.as_str())
                .ne(PAYLOAD_PATHS)
            || self.payload_files.iter().any(|file| {
                !is_sha256(&file.sha256)
                    || file.size_bytes == 0
                    || file.size_bytes > max_bytes_for(&file.path)
            })
        {
            return Err(CampaignError::WrongPayloadInventory);
        }
        Ok(())
    }
}

/// A campaign returned only after static checks and fresh execution agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCampaign {
    /// Validated deterministic manifest.
    pub manifest: CampaignManifest,
    /// SHA-256 of the manifest bytes.
    pub manifest_sha256: String,
    /// SHA-256 of the top-level checksum document.
    pub checksums_sha256: String,
}

/// Write one complete witness replay without overwriting an existing file.
pub fn write_witness_replay(
    output: &Path,
    replay: &StwoWitnessReplay,
) -> Result<String, CampaignError> {
    replay.validate()?;
    let bytes = pretty_json(replay)?;
    enforce_size(output_name(output), bytes.len() as u64, MAX_ARTIFACT_BYTES)?;
    write_new_file(output, &bytes)?;
    Ok(sha256_bytes(&bytes))
}

/// Read and validate one complete witness replay.
pub fn read_verified_witness_replay(path: &Path) -> Result<StwoWitnessReplay, CampaignError> {
    let bytes = read_bounded(path, output_name(path), MAX_ARTIFACT_BYTES)?;
    let replay: StwoWitnessReplay = serde_json::from_slice(&bytes)
        .map_err(|error| CampaignError::MalformedArtifact(error.to_string()))?;
    replay.validate()?;
    Ok(replay)
}

/// Seal an already executed fixed campaign with a manifest and checksums.
pub fn seal_campaign(
    root: &Path,
    airlock_commit: &str,
    coverage_source: &Path,
) -> Result<VerifiedCampaign, CampaignError> {
    validate_commit(airlock_commit)?;
    inspect_unsealed_root(root)?;
    validate_boundary_and_witness_artifacts(root)?;
    validate_regression(root)?;
    let replay_worker_sha256 = recorded_worker_sha256(root)?;

    let coverage = read_bounded(coverage_source, "coverage source", MAX_COVERAGE_BYTES)?;
    validate_coverage(&coverage)?;
    let summary = summary_document(airlock_commit, &replay_worker_sha256);

    let outputs = [
        root.join(COVERAGE_FILE),
        root.join(SUMMARY_FILE),
        root.join(MANIFEST_FILE),
        root.join(CHECKSUM_FILE),
    ];
    let mut created = vec![];
    let result = (|| {
        write_new_file(&outputs[0], &coverage)?;
        created.push(outputs[0].clone());
        write_new_file(&outputs[1], summary.as_bytes())?;
        created.push(outputs[1].clone());

        let payload_files = payload_records(root)?;
        let manifest = CampaignManifest {
            schema: CAMPAIGN_SCHEMA_ID.to_owned(),
            schema_version: CAMPAIGN_SCHEMA_VERSION.to_owned(),
            airlock_commit: airlock_commit.to_owned(),
            stwo_source_id: STWO_SOURCE_ID.to_owned(),
            replay_worker_sha256,
            cases: expected_cases(),
            non_claims: expected_non_claims(),
            payload_files,
        };
        manifest.validate(airlock_commit)?;
        let manifest_bytes = pretty_json(&manifest)?;
        enforce_size(
            MANIFEST_FILE,
            manifest_bytes.len() as u64,
            MAX_MANIFEST_BYTES,
        )?;
        write_new_file(&outputs[2], &manifest_bytes)?;
        created.push(outputs[2].clone());

        let checksums = complete_checksums(root)?;
        let checksum_bytes = checksum_document(&checksums);
        enforce_size(
            CHECKSUM_FILE,
            checksum_bytes.len() as u64,
            MAX_CHECKSUM_BYTES,
        )?;
        write_new_file(&outputs[3], &checksum_bytes)?;
        created.push(outputs[3].clone());

        read_campaign(root, airlock_commit)
    })();
    if result.is_err() {
        for path in created.iter().rev() {
            let _ = fs::remove_file(path);
        }
    }
    result
}

/// Verify the sealed campaign and rerun every recorded executable case.
pub fn verify_campaign(
    root: &Path,
    expected_airlock_commit: &str,
    worker: &Path,
) -> Result<VerifiedCampaign, CampaignError> {
    let verified = read_campaign(root, expected_airlock_commit)?;
    fresh_boundary_replay(root, worker)?;
    fresh_witness_replay(root)?;
    validate_regression(root)?;
    Ok(verified)
}

fn read_campaign(
    root: &Path,
    expected_airlock_commit: &str,
) -> Result<VerifiedCampaign, CampaignError> {
    inspect_sealed_root(root)?;
    let checksum_bytes =
        read_bounded(&root.join(CHECKSUM_FILE), CHECKSUM_FILE, MAX_CHECKSUM_BYTES)?;
    let checksums = parse_checksum_document(&checksum_bytes)?;
    let expected_paths = PAYLOAD_PATHS
        .iter()
        .copied()
        .chain(std::iter::once(MANIFEST_FILE))
        .collect::<BTreeSet<_>>();
    if checksums
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_paths
    {
        return Err(CampaignError::WrongChecksumInventory);
    }
    for (path, expected_digest) in &checksums {
        let bytes = read_bounded(
            &root.join(path),
            expected_path_name(path)?,
            max_bytes_for(path),
        )?;
        if sha256_bytes(&bytes) != *expected_digest {
            return Err(CampaignError::ChecksumMismatch(path.clone()));
        }
    }

    let manifest_bytes =
        read_bounded(&root.join(MANIFEST_FILE), MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
    let manifest: CampaignManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| CampaignError::MalformedArtifact(error.to_string()))?;
    manifest.validate(expected_airlock_commit)?;
    if manifest.replay_worker_sha256 != recorded_worker_sha256(root)? {
        return Err(CampaignError::WorkerDigestMismatch);
    }
    if manifest.payload_files != payload_records(root)? {
        return Err(CampaignError::PayloadDigestMismatch);
    }

    let summary = read_bounded(&root.join(SUMMARY_FILE), SUMMARY_FILE, MAX_SUMMARY_BYTES)?;
    if summary
        != summary_document(expected_airlock_commit, &manifest.replay_worker_sha256).as_bytes()
    {
        return Err(CampaignError::SummaryMismatch);
    }
    let coverage = read_bounded(&root.join(COVERAGE_FILE), COVERAGE_FILE, MAX_COVERAGE_BYTES)?;
    validate_coverage(&coverage)?;
    validate_boundary_and_witness_artifacts(root)?;

    Ok(VerifiedCampaign {
        manifest,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        checksums_sha256: sha256_bytes(&checksum_bytes),
    })
}

fn validate_boundary_and_witness_artifacts(root: &Path) -> Result<(), CampaignError> {
    let honest = read_verified_replay_bundle(&root.join(HONEST_BUNDLE))?;
    let honest_replay = honest
        .report
        .replay
        .as_ref()
        .ok_or(CampaignError::MissingReplay("honest"))?;
    if honest.report.case_id != "honest-baseline"
        || honest_replay.verdict != DifferentialVerdict::HonestAccepted
    {
        return Err(CampaignError::WrongRecordedVerdict("honest"));
    }

    let mutated = read_verified_replay_bundle(&root.join(MUTATED_BUNDLE))?;
    let mutated_replay = mutated
        .report
        .replay
        .as_ref()
        .ok_or(CampaignError::MissingReplay("corrupt-oods-sample"))?;
    if mutated.report.case_id != "corrupt-oods-sample"
        || mutated_replay.verdict != DifferentialVerdict::MutationRejected
    {
        return Err(CampaignError::WrongRecordedVerdict("corrupt-oods-sample"));
    }

    for (path, case_id, verdict) in [
        (
            WITNESS_HONEST_FILE,
            "honest-witness",
            WitnessVerdict::HonestAccepted,
        ),
        (
            WITNESS_PRESERVING_FILE,
            "constant-one-witness",
            WitnessVerdict::ConstraintPreservingAccepted,
        ),
        (
            WITNESS_VIOLATING_FILE,
            "single-cell-violation",
            WitnessVerdict::ConstraintViolationRejected,
        ),
    ] {
        let replay = read_verified_witness_replay(&root.join(path))?;
        if replay.report.case_id != case_id || replay.report.verdict != verdict {
            return Err(CampaignError::WrongRecordedVerdict(path));
        }
    }
    Ok(())
}

fn fresh_boundary_replay(root: &Path, worker: &Path) -> Result<(), CampaignError> {
    for bundle in [HONEST_BUNDLE, MUTATED_BUNDLE] {
        let recorded = read_verified_replay_bundle(&root.join(bundle))?;
        if !recorded.report.is_expected() {
            return Err(CampaignError::WrongRecordedVerdict(bundle));
        }
        let replayed = run_isolated_replay(
            worker,
            &recorded.report.worker_args,
            &recorded.request,
            Duration::from_millis(recorded.report.timeout_ms),
        )?;
        if replayed != recorded.report {
            return Err(CampaignError::FreshReplayMismatch(bundle));
        }
    }
    Ok(())
}

fn recorded_worker_sha256(root: &Path) -> Result<String, CampaignError> {
    let honest = read_verified_replay_bundle(&root.join(HONEST_BUNDLE))?
        .report
        .worker_sha256;
    let mutated = read_verified_replay_bundle(&root.join(MUTATED_BUNDLE))?
        .report
        .worker_sha256;
    if honest != mutated || !is_sha256(&honest) {
        return Err(CampaignError::WorkerDigestMismatch);
    }
    Ok(honest)
}

fn fresh_witness_replay(root: &Path) -> Result<(), CampaignError> {
    let adapter = StwoWitnessAdapter::new()?;
    for path in [
        WITNESS_HONEST_FILE,
        WITNESS_PRESERVING_FILE,
        WITNESS_VIOLATING_FILE,
    ] {
        let recorded = read_verified_witness_replay(&root.join(path))?;
        let fresh = match recorded.observation.case_kind {
            CaseKind::Honest => adapter.replay_honest()?,
            CaseKind::Mutated => {
                let plan = recorded
                    .observation
                    .mutation
                    .as_ref()
                    .ok_or(CampaignError::MissingMutation(path))?;
                adapter.replay_mutation(
                    recorded.observation.case_id.clone(),
                    plan.operations.clone(),
                )?
            }
        };
        if fresh != recorded {
            return Err(CampaignError::FreshReplayMismatch(path));
        }
    }
    Ok(())
}

fn validate_regression(root: &Path) -> Result<(), CampaignError> {
    let bundle = read_verified_replay_bundle(&root.join(MUTATED_BUNDLE))?;
    let verdict = bundle
        .report
        .replay
        .as_ref()
        .ok_or(CampaignError::MissingReplay("corrupt-oods-sample"))?
        .verdict;
    let expected = generate_regression_source(&bundle.request, verdict)
        .map_err(|error| CampaignError::Regression(error.to_string()))?;
    let actual = read_bounded(
        &root.join(REGRESSION_FILE),
        REGRESSION_FILE,
        MAX_REGRESSION_BYTES,
    )?;
    if actual != expected.as_bytes() {
        return Err(CampaignError::RegressionMismatch);
    }
    Ok(())
}

fn validate_coverage(bytes: &[u8]) -> Result<(), CampaignError> {
    let coverage: CoverageManifest = serde_yaml::from_slice(bytes)
        .map_err(|error| CampaignError::MalformedCoverage(error.to_string()))?;
    coverage
        .validate()
        .map_err(|error| CampaignError::MalformedCoverage(error.to_string()))?;
    for (name, expected) in [
        ("stwo-demo-verifier-boundary", CoverageStatus::Covered),
        ("stwo-demo-replay-artifact", CoverageStatus::Covered),
        ("stwo-demo-witness-consistency", CoverageStatus::Covered),
        ("stwo-demo-campaign-artifact", CoverageStatus::Covered),
        ("stwo-verifier-boundary", CoverageStatus::Unsupported),
        ("broad-evidence-provenance", CoverageStatus::Unsupported),
        ("stwo-transcript", CoverageStatus::Unsupported),
    ] {
        let actual = coverage
            .surfaces
            .iter()
            .find(|surface| surface.name == name)
            .map(|surface| surface.status);
        if actual != Some(expected) {
            return Err(CampaignError::WrongCoverageStatus {
                name: name.to_owned(),
                expected,
                actual,
            });
        }
    }
    Ok(())
}

fn inspect_unsealed_root(root: &Path) -> Result<(), CampaignError> {
    inspect_root(
        root,
        &[
            HONEST_BUNDLE,
            MUTATED_BUNDLE,
            REGRESSION_FILE,
            WITNESS_HONEST_FILE,
            WITNESS_PRESERVING_FILE,
            WITNESS_VIOLATING_FILE,
        ],
    )
}

fn inspect_sealed_root(root: &Path) -> Result<(), CampaignError> {
    inspect_root(
        root,
        &[
            CHECKSUM_FILE,
            MANIFEST_FILE,
            SUMMARY_FILE,
            COVERAGE_FILE,
            HONEST_BUNDLE,
            MUTATED_BUNDLE,
            REGRESSION_FILE,
            WITNESS_HONEST_FILE,
            WITNESS_PRESERVING_FILE,
            WITNESS_VIOLATING_FILE,
        ],
    )
}

fn inspect_root(root: &Path, expected: &[&str]) -> Result<(), CampaignError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| CampaignError::Io {
        operation: "inspect campaign root",
        path: root.to_path_buf(),
        message: error.to_string(),
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CampaignError::NotDirectory(root.to_path_buf()));
    }
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| CampaignError::Io {
        operation: "list campaign root",
        path: root.to_path_buf(),
        message: error.to_string(),
    })? {
        let entry = entry.map_err(|error| CampaignError::Io {
            operation: "read campaign root entry",
            path: root.to_path_buf(),
            message: error.to_string(),
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CampaignError::UnexpectedEntry("non-UTF-8 name".to_owned()))?;
        let file_type = entry.file_type().map_err(|error| CampaignError::Io {
            operation: "inspect campaign root entry",
            path: entry.path(),
            message: error.to_string(),
        })?;
        let expected_directory = matches!(name.as_str(), HONEST_BUNDLE | MUTATED_BUNDLE);
        if !expected.contains(name.as_str())
            || file_type.is_symlink()
            || (expected_directory && !file_type.is_dir())
            || (!expected_directory && !file_type.is_file())
        {
            return Err(CampaignError::UnexpectedEntry(name));
        }
        actual.insert(name);
    }
    if actual.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(CampaignError::IncompleteInventory);
    }
    Ok(())
}

fn payload_records(root: &Path) -> Result<Vec<CampaignFile>, CampaignError> {
    PAYLOAD_PATHS
        .iter()
        .map(|path| {
            let bytes = read_bounded(
                &root.join(path),
                expected_path_name(path)?,
                max_bytes_for(path),
            )?;
            Ok(CampaignFile {
                path: (*path).to_owned(),
                sha256: sha256_bytes(&bytes),
                size_bytes: bytes.len() as u64,
            })
        })
        .collect()
}

fn complete_checksums(root: &Path) -> Result<BTreeMap<String, String>, CampaignError> {
    PAYLOAD_PATHS
        .iter()
        .copied()
        .chain(std::iter::once(MANIFEST_FILE))
        .map(|path| {
            let bytes = read_bounded(
                &root.join(path),
                expected_path_name(path)?,
                max_bytes_for(path),
            )?;
            Ok((path.to_owned(), sha256_bytes(&bytes)))
        })
        .collect()
}

fn expected_cases() -> Vec<CampaignCase> {
    [
        (
            "honest-baseline",
            "verifier_boundary",
            "honest/report.json",
            "HONEST_ACCEPTED",
        ),
        (
            "corrupt-oods-sample",
            "verifier_boundary",
            "corrupt-oods-sample/report.json",
            "MUTATION_REJECTED",
        ),
        (
            "honest-witness",
            "witness_consistency",
            WITNESS_HONEST_FILE,
            "HONEST_ACCEPTED",
        ),
        (
            "constant-one-witness",
            "witness_consistency",
            WITNESS_PRESERVING_FILE,
            "CONSTRAINT_PRESERVING_ACCEPTED",
        ),
        (
            "single-cell-violation",
            "witness_consistency",
            WITNESS_VIOLATING_FILE,
            "CONSTRAINT_VIOLATION_REJECTED",
        ),
    ]
    .into_iter()
    .map(|(case_id, lane, artifact, expected_verdict)| CampaignCase {
        case_id: case_id.to_owned(),
        lane: lane.to_owned(),
        artifact: artifact.to_owned(),
        expected_verdict: expected_verdict.to_owned(),
    })
    .collect()
}

fn expected_non_claims() -> Vec<String> {
    NON_CLAIMS.into_iter().map(str::to_owned).collect()
}

fn summary_document(airlock_commit: &str, replay_worker_sha256: &str) -> String {
    format!(
        "# AIRLock Stwo Campaign\n\n\
Source: `{airlock_commit}`\n\n\
Pinned Stwo: `{STWO_SOURCE_ID}`\n\n\
Replay worker: `{replay_worker_sha256}`\n\n\
## Executed\n\n\
- Honest real proof through raw PCS and framework verification.\n\
- Generic OODS scalar corruption rejected at both verifier layers.\n\
- Honest, relation-preserving, and relation-violating phase-bound witness replay.\n\
- Deterministic replay bundles and a generated Rust regression.\n\n\
## Not Established\n\n\
{}\n",
        NON_CLAIMS
            .iter()
            .map(|claim| format!("- {claim}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn validate_commit(commit: &str) -> Result<(), CampaignError> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CampaignError::InvalidAirlockCommit(commit.to_owned()));
    }
    Ok(())
}

fn pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CampaignError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| CampaignError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CampaignError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CampaignError::Io {
            operation: "create campaign file",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(CampaignError::Io {
            operation: "write campaign file",
            path: path.to_path_buf(),
            message: error.to_string(),
        });
    }
    Ok(())
}

fn read_bounded(path: &Path, name: &'static str, max_bytes: u64) -> Result<Vec<u8>, CampaignError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| CampaignError::Io {
        operation: "open campaign file",
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let metadata = file.metadata().map_err(|error| CampaignError::Io {
        operation: "inspect campaign file",
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CampaignError::UnexpectedEntry(name.to_owned()));
    }
    let mut bytes = Vec::with_capacity((metadata.len().min(max_bytes) + 1) as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CampaignError::Io {
            operation: "read campaign file",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    enforce_size(name, bytes.len() as u64, max_bytes)?;
    Ok(bytes)
}

fn enforce_size(name: &'static str, actual: u64, maximum: u64) -> Result<(), CampaignError> {
    if actual > maximum {
        return Err(CampaignError::FileTooLarge {
            name,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn checksum_document(checksums: &BTreeMap<String, String>) -> Vec<u8> {
    let mut document = String::new();
    for (name, digest) in checksums {
        document.push_str(digest);
        document.push_str("  ");
        document.push_str(name);
        document.push('\n');
    }
    document.into_bytes()
}

fn parse_checksum_document(bytes: &[u8]) -> Result<BTreeMap<String, String>, CampaignError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| CampaignError::MalformedChecksums(error.to_string()))?;
    let mut parsed = BTreeMap::new();
    for line in text.lines() {
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(CampaignError::MalformedChecksums(line.to_owned()));
        };
        if !is_sha256(digest)
            || expected_path_name(name).is_err()
            || parsed.insert(name.to_owned(), digest.to_owned()).is_some()
        {
            return Err(CampaignError::MalformedChecksums(line.to_owned()));
        }
    }
    Ok(parsed)
}

fn expected_path_name(path: &str) -> Result<&'static str, CampaignError> {
    PAYLOAD_PATHS
        .iter()
        .copied()
        .chain([MANIFEST_FILE, CHECKSUM_FILE])
        .find(|expected| *expected == path)
        .ok_or_else(|| CampaignError::UnexpectedEntry(path.to_owned()))
}

fn max_bytes_for(path: &str) -> u64 {
    match path {
        MANIFEST_FILE => MAX_MANIFEST_BYTES,
        CHECKSUM_FILE | "honest/SHA256SUMS" | "corrupt-oods-sample/SHA256SUMS" => {
            MAX_CHECKSUM_BYTES
        }
        SUMMARY_FILE => MAX_SUMMARY_BYTES,
        COVERAGE_FILE => MAX_COVERAGE_BYTES,
        REGRESSION_FILE => MAX_REGRESSION_BYTES,
        _ => MAX_ARTIFACT_BYTES,
    }
}

fn output_name(path: &Path) -> &'static str {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(WITNESS_HONEST_FILE) => WITNESS_HONEST_FILE,
        Some(WITNESS_PRESERVING_FILE) => WITNESS_PRESERVING_FILE,
        Some(WITNESS_VIOLATING_FILE) => WITNESS_VIOLATING_FILE,
        _ => "witness replay",
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Campaign construction or verification failure.
#[derive(Debug, Error)]
pub enum CampaignError {
    /// Replay-bundle validation failed.
    #[error(transparent)]
    ReplayBundle(#[from] ReplayBundleError),
    /// Fresh isolated replay failed.
    #[error(transparent)]
    IsolatedReplay(#[from] IsolatedReplayError),
    /// Witness replay validation or execution failed.
    #[error(transparent)]
    Witness(#[from] StwoWitnessError),
    /// Existing path is not a real directory.
    #[error("campaign root is not a real directory: {}", .0.display())]
    NotDirectory(PathBuf),
    /// Root contains an unknown, symbolic, or wrongly typed entry.
    #[error("unexpected campaign entry `{0}`")]
    UnexpectedEntry(String),
    /// Fixed root inventory is incomplete.
    #[error("campaign root inventory is incomplete")]
    IncompleteInventory,
    /// AIRLock source identity is not a lowercase 40-byte Git commit.
    #[error("invalid AIRLock commit `{0}`")]
    InvalidAirlockCommit(String),
    /// Manifest schema identity or version is unsupported.
    #[error("unexpected campaign schema `{schema}` version `{version}`")]
    WrongSchema {
        /// Supplied schema.
        schema: String,
        /// Supplied version.
        version: String,
    },
    /// Manifest is not bound to the expected AIRLock source.
    #[error("campaign AIRLock commit mismatch: expected `{expected}`, got `{actual}`")]
    WrongAirlockCommit {
        /// Caller-pinned source commit.
        expected: String,
        /// Manifest source commit.
        actual: String,
    },
    /// Manifest is not bound to the pinned Stwo source.
    #[error("campaign has unexpected Stwo source `{0}`")]
    WrongStwoSource(String),
    /// Manifest worker digest is malformed.
    #[error("campaign has invalid replay-worker digest `{0}`")]
    InvalidWorkerDigest(String),
    /// Boundary records or manifest disagree on the exact worker bytes.
    #[error("campaign boundary records do not share the manifest replay-worker digest")]
    WorkerDigestMismatch,
    /// Executable case inventory differs from the frozen contract.
    #[error("campaign case inventory differs from the frozen contract")]
    WrongCaseInventory,
    /// Non-claims differ from the frozen contract.
    #[error("campaign non-claims differ from the frozen contract")]
    WrongNonClaims,
    /// Manifest payload inventory is malformed.
    #[error("campaign payload inventory differs from the fixed contract")]
    WrongPayloadInventory,
    /// Top-level checksum inventory is malformed.
    #[error("campaign checksum inventory differs from the fixed contract")]
    WrongChecksumInventory,
    /// A top-level digest does not match its file.
    #[error("campaign checksum mismatch for `{0}`")]
    ChecksumMismatch(String),
    /// Manifest payload digests do not match the exact bytes.
    #[error("campaign payload digest records do not match the exact files")]
    PayloadDigestMismatch,
    /// Human summary does not match the deterministic source-bound text.
    #[error("campaign summary does not match its manifest")]
    SummaryMismatch,
    /// A required replay record is absent.
    #[error("campaign case `{0}` has no completed replay")]
    MissingReplay(&'static str),
    /// A mutated witness record has no mutation plan.
    #[error("campaign witness artifact `{0}` has no mutation plan")]
    MissingMutation(&'static str),
    /// A recorded verdict differs from the frozen case contract.
    #[error("campaign artifact `{0}` has the wrong recorded verdict")]
    WrongRecordedVerdict(&'static str),
    /// Fresh execution differs from the sealed record.
    #[error("fresh replay differs from sealed artifact `{0}`")]
    FreshReplayMismatch(&'static str),
    /// Generated regression could not be reconstructed.
    #[error("could not reconstruct generated regression: {0}")]
    Regression(String),
    /// Generated regression bytes differ from the verified replay.
    #[error("generated regression does not match the verified replay")]
    RegressionMismatch,
    /// Coverage snapshot cannot be trusted.
    #[error("malformed campaign coverage snapshot: {0}")]
    MalformedCoverage(String),
    /// A required surface has the wrong coverage status.
    #[error("coverage surface `{name}` has status {actual:?}; expected {expected:?}")]
    WrongCoverageStatus {
        /// Surface identity.
        name: String,
        /// Required status.
        expected: CoverageStatus,
        /// Observed status or absence.
        actual: Option<CoverageStatus>,
    },
    /// JSON serialization failed.
    #[error("failed to serialize campaign artifact: {0}")]
    Serialization(String),
    /// JSON artifact is malformed or has unknown fields.
    #[error("malformed campaign artifact: {0}")]
    MalformedArtifact(String),
    /// Checksum document is malformed.
    #[error("malformed campaign SHA256SUMS: {0}")]
    MalformedChecksums(String),
    /// File exceeds its pre-read bound.
    #[error("campaign file {name} is {actual} bytes; maximum is {maximum}")]
    FileTooLarge {
        /// Fixed file identity.
        name: &'static str,
        /// Observed size.
        actual: u64,
        /// Maximum size.
        maximum: u64,
    },
    /// Filesystem operation failed.
    #[error("{operation} failed at {}: {message}", path.display())]
    Io {
        /// Operation attempted.
        operation: &'static str,
        /// File or directory path.
        path: PathBuf,
        /// Captured error without platform-specific source ownership.
        message: String,
    },
}
