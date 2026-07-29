//! Deterministic, self-verifying replay bundles for isolated replay.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{IsolatedReplayError, IsolatedReplayRecord, ReplayRequest};

const REQUEST_FILE: &str = "request.json";
const REPORT_FILE: &str = "report.json";
const CHECKSUM_FILE: &str = "SHA256SUMS";
const MAX_REQUEST_FILE_BYTES: u64 = 1 << 20;
const MAX_REPORT_FILE_BYTES: u64 = 8 << 20;
const MAX_CHECKSUM_FILE_BYTES: u64 = 4096;

/// Digests of every file in a completed replay bundle directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBundleFiles {
    /// SHA-256 of `request.json` bytes.
    pub request_file_sha256: String,
    /// SHA-256 of `report.json` bytes.
    pub report_file_sha256: String,
    /// SHA-256 of `SHA256SUMS` bytes.
    pub checksums_file_sha256: String,
}

/// Write a deterministic replay bundle into an exclusively created directory.
///
/// A failed write removes the partial directory. Concurrent readers may still
/// observe a partial directory, which strict inventory validation rejects.
pub fn write_replay_bundle(
    output_dir: &Path,
    request: &ReplayRequest,
    report: &IsolatedReplayRecord,
) -> Result<ReplayBundleFiles, ReplayBundleError> {
    report.validate(request)?;
    let parent = output_dir
        .parent()
        .ok_or_else(|| ReplayBundleError::MissingParent(output_dir.to_path_buf()))?;
    if !parent.is_dir() {
        return Err(ReplayBundleError::MissingParent(parent.to_path_buf()));
    }

    let request_bytes = pretty_json(request)?;
    let report_bytes = pretty_json(report)?;
    enforce_size(
        REQUEST_FILE,
        request_bytes.len() as u64,
        MAX_REQUEST_FILE_BYTES,
    )?;
    enforce_size(
        REPORT_FILE,
        report_bytes.len() as u64,
        MAX_REPORT_FILE_BYTES,
    )?;

    let request_sha256 = sha256_bytes(&request_bytes);
    let report_sha256 = sha256_bytes(&report_bytes);
    let mut checksums = BTreeMap::new();
    checksums.insert(REQUEST_FILE, request_sha256.clone());
    checksums.insert(REPORT_FILE, report_sha256.clone());
    let checksum_bytes = checksum_document(&checksums);
    let checksums_sha256 = sha256_bytes(&checksum_bytes);

    match fs::create_dir(output_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ReplayBundleError::OutputExists(output_dir.to_path_buf()));
        }
        Err(error) => {
            return Err(ReplayBundleError::Io {
                operation: "create replay bundle directory",
                path: output_dir.to_path_buf(),
                message: error.to_string(),
            });
        }
    }
    let result = (|| {
        write_new_file(&output_dir.join(REQUEST_FILE), &request_bytes)?;
        write_new_file(&output_dir.join(REPORT_FILE), &report_bytes)?;
        write_new_file(&output_dir.join(CHECKSUM_FILE), &checksum_bytes)?;
        Ok(ReplayBundleFiles {
            request_file_sha256: request_sha256,
            report_file_sha256: report_sha256,
            checksums_file_sha256: checksums_sha256,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output_dir);
    }
    result
}

/// Verify file inventory, checksums, schemas, source and target, and report linkage.
pub fn verify_replay_bundle(output_dir: &Path) -> Result<ReplayBundleFiles, ReplayBundleError> {
    let metadata = fs::symlink_metadata(output_dir).map_err(|error| ReplayBundleError::Io {
        operation: "inspect replay bundle directory",
        path: output_dir.to_path_buf(),
        message: error.to_string(),
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ReplayBundleError::NotDirectory(output_dir.to_path_buf()));
    }
    let expected = BTreeSet::from([
        REQUEST_FILE.to_owned(),
        REPORT_FILE.to_owned(),
        CHECKSUM_FILE.to_owned(),
    ]);
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(output_dir).map_err(|error| ReplayBundleError::Io {
        operation: "list replay bundle directory",
        path: output_dir.to_path_buf(),
        message: error.to_string(),
    })? {
        let entry = entry.map_err(|error| ReplayBundleError::Io {
            operation: "read replay bundle directory entry",
            path: output_dir.to_path_buf(),
            message: error.to_string(),
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ReplayBundleError::UnexpectedFile("non-UTF-8 name".to_owned()))?;
        let file_type = entry.file_type().map_err(|error| ReplayBundleError::Io {
            operation: "inspect replay bundle file",
            path: entry.path(),
            message: error.to_string(),
        })?;
        if !file_type.is_file() || file_type.is_symlink() || !expected.contains(&name) {
            return Err(ReplayBundleError::UnexpectedFile(name));
        }
        observed.insert(name);
    }
    if observed != expected {
        return Err(ReplayBundleError::IncompleteInventory);
    }

    let request_bytes = read_bounded(
        &output_dir.join(REQUEST_FILE),
        REQUEST_FILE,
        MAX_REQUEST_FILE_BYTES,
    )?;
    let report_bytes = read_bounded(
        &output_dir.join(REPORT_FILE),
        REPORT_FILE,
        MAX_REPORT_FILE_BYTES,
    )?;
    let checksum_bytes = read_bounded(
        &output_dir.join(CHECKSUM_FILE),
        CHECKSUM_FILE,
        MAX_CHECKSUM_FILE_BYTES,
    )?;

    let request_sha256 = sha256_bytes(&request_bytes);
    let report_sha256 = sha256_bytes(&report_bytes);
    let checksums = parse_checksum_document(&checksum_bytes)?;
    if checksums.get(REQUEST_FILE) != Some(&request_sha256)
        || checksums.get(REPORT_FILE) != Some(&report_sha256)
        || checksums.len() != 2
    {
        return Err(ReplayBundleError::ChecksumMismatch);
    }

    let request: ReplayRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| ReplayBundleError::MalformedArtifact(error.to_string()))?;
    let report: IsolatedReplayRecord = serde_json::from_slice(&report_bytes)
        .map_err(|error| ReplayBundleError::MalformedArtifact(error.to_string()))?;
    report.validate(&request)?;

    Ok(ReplayBundleFiles {
        request_file_sha256: request_sha256,
        report_file_sha256: report_sha256,
        checksums_file_sha256: sha256_bytes(&checksum_bytes),
    })
}

fn pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReplayBundleError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ReplayBundleError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), ReplayBundleError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ReplayBundleError::Io {
            operation: "create replay bundle file",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| ReplayBundleError::Io {
            operation: "write replay bundle file",
            path: path.to_path_buf(),
            message: error.to_string(),
        })
}

fn read_bounded(
    path: &Path,
    name: &'static str,
    max_bytes: u64,
) -> Result<Vec<u8>, ReplayBundleError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| ReplayBundleError::Io {
        operation: "open replay bundle file",
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let metadata = file.metadata().map_err(|error| ReplayBundleError::Io {
        operation: "inspect opened replay bundle file",
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ReplayBundleError::UnexpectedFile(name.to_owned()));
    }
    let mut bytes = Vec::with_capacity((metadata.len().min(max_bytes) + 1) as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ReplayBundleError::Io {
            operation: "read replay bundle file",
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    enforce_size(name, bytes.len() as u64, max_bytes)?;
    Ok(bytes)
}

fn enforce_size(name: &'static str, actual: u64, maximum: u64) -> Result<(), ReplayBundleError> {
    if actual > maximum {
        return Err(ReplayBundleError::FileTooLarge {
            name,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn checksum_document(checksums: &BTreeMap<&str, String>) -> Vec<u8> {
    let mut document = String::new();
    for (name, digest) in checksums {
        document.push_str(digest);
        document.push_str("  ");
        document.push_str(name);
        document.push('\n');
    }
    document.into_bytes()
}

fn parse_checksum_document(bytes: &[u8]) -> Result<BTreeMap<String, String>, ReplayBundleError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ReplayBundleError::MalformedChecksums(error.to_string()))?;
    let mut parsed = BTreeMap::new();
    for line in text.lines() {
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(ReplayBundleError::MalformedChecksums(line.to_owned()));
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || !matches!(name, REQUEST_FILE | REPORT_FILE)
            || parsed.insert(name.to_owned(), digest.to_owned()).is_some()
        {
            return Err(ReplayBundleError::MalformedChecksums(line.to_owned()));
        }
    }
    Ok(parsed)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Replay-bundle construction or verification failure.
#[derive(Debug, Error)]
pub enum ReplayBundleError {
    /// Replay report does not validate against the request.
    #[error(transparent)]
    Replay(#[from] IsolatedReplayError),
    /// Output directory already exists and will not be overwritten.
    #[error("replay bundle output already exists: {}", .0.display())]
    OutputExists(PathBuf),
    /// Parent directory is absent or not a directory.
    #[error("replay bundle output parent is unavailable: {}", .0.display())]
    MissingParent(PathBuf),
    /// Existing path is not a real directory.
    #[error("replay bundle path is not a directory: {}", .0.display())]
    NotDirectory(PathBuf),
    /// Directory contains an unknown, nested, or symbolic-link entry.
    #[error("unexpected replay bundle entry `{0}`")]
    UnexpectedFile(String),
    /// One or more required files is absent.
    #[error("replay bundle file inventory is incomplete")]
    IncompleteInventory,
    /// Bounded replay bundle file exceeds its contract.
    #[error("replay bundle file {name} is {actual} bytes; maximum is {maximum}")]
    FileTooLarge {
        /// Fixed replay bundle filename.
        name: &'static str,
        /// Observed size.
        actual: u64,
        /// Maximum accepted size.
        maximum: u64,
    },
    /// JSON serialization failed.
    #[error("failed to serialize replay bundle artifact: {0}")]
    Serialization(String),
    /// JSON artifact is malformed or has unknown fields.
    #[error("malformed replay bundle artifact: {0}")]
    MalformedArtifact(String),
    /// Checksum file is malformed.
    #[error("malformed SHA256SUMS: {0}")]
    MalformedChecksums(String),
    /// File digest does not match `SHA256SUMS`.
    #[error("replay bundle checksum mismatch")]
    ChecksumMismatch,
    /// Filesystem operation failed.
    #[error("{operation} failed at {}: {message}", path.display())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected local path.
        path: PathBuf,
        /// Operating-system diagnostic.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::temp::PrivateTempDir;

    #[test]
    fn bounded_reader_enforces_the_limit_while_reading() {
        let directory = PrivateTempDir::create_in(&std::env::temp_dir(), ".airlock-read-")
            .expect("private test directory");
        let path = directory.path().join("oversized");
        fs::write(&path, vec![0_u8; 4097]).expect("write oversized test file");

        assert!(matches!(
            read_bounded(&path, "oversized", 4096),
            Err(ReplayBundleError::FileTooLarge {
                actual: 4097,
                maximum: 4096,
                ..
            })
        ));
    }
}
