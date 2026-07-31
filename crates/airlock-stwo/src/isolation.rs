//! Subprocess containment for untrusted verifier replay.

use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::temp::PrivateTempDir;
use crate::{
    DifferentialReplay, ReplayRequest, ReplayRequestError, STWO_DEMO_TARGET, STWO_SOURCE_ID,
    replay_request_sha256,
};

/// Stable schema identifier for isolated replay record.
pub const ISOLATED_REPLAY_SCHEMA: &str = "airlock.stwo-isolated-replay";

/// Serialized isolated replay record version.
pub const ISOLATED_REPLAY_VERSION: &str = "0.1.0";

const MAX_REQUEST_BYTES: usize = 1 << 20;
const MAX_CAPTURE_BYTES: usize = 4 << 20;
const MAX_WORKER_ARGS: usize = 16;
const MAX_WORKER_ARG_BYTES: usize = 256;
const MAX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(target_os = "linux")]
const EXEC_BUSY_RETRY_LIMIT: usize = 3;
#[cfg(target_os = "linux")]
const EXEC_BUSY_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Hash and length of one captured byte stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamDigest {
    /// SHA-256 over every captured byte.
    pub sha256: String,
    /// Total stream size before any storage cap.
    pub byte_len: u64,
    /// Whether bytes beyond the in-memory cap were discarded after hashing.
    pub truncated: bool,
}

/// Process-level termination class. Only `Completed` may be expected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessTermination {
    /// Worker exited successfully and returned a validated replay.
    Completed,
    /// Worker exited unsuccessfully or was terminated by a signal.
    ExitFailure {
        /// Platform exit code, absent when no code is available.
        code: Option<i32>,
    },
    /// Worker exceeded the caller-owned deadline and was killed.
    TimedOut,
    /// Worker completed but its response was absent, oversized, or malformed.
    InvalidOutput {
        /// Stable reason category without untrusted raw output.
        reason: InvalidOutputReason,
    },
}

/// Stable reason for refusing worker output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum InvalidOutputReason {
    /// Parent could not write the complete request to worker stdin.
    RequestWriteFailed,
    /// Stdout exceeded the bounded response contract.
    StdoutTooLarge,
    /// Stderr exceeded the bounded diagnostic contract.
    StderrTooLarge,
    /// Successful worker emitted no response.
    MissingResponse,
    /// Stdout was not a canonical replay document.
    MalformedResponse,
    /// Parsed replay was inconsistent or did not match the request.
    ResponseMismatch,
}

/// Canonical process-contained replay record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedReplayRecord {
    /// Record schema identity.
    pub schema: String,
    /// Record schema version.
    pub schema_version: String,
    /// Fixed executable component identity.
    pub target: String,
    /// Exact pinned Stwo source identity.
    pub upstream_commit: String,
    /// Stable request case identity.
    pub case_id: String,
    /// Canonical request digest.
    pub request_sha256: String,
    /// Hash of the exact worker executable bytes.
    pub worker_sha256: String,
    /// Worker arguments, excluding its local filesystem path.
    pub worker_args: Vec<String>,
    /// Parent-owned deadline.
    pub timeout_ms: u64,
    /// Process termination class.
    pub termination: ProcessTermination,
    /// Complete replay, present only for a validated successful response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<DifferentialReplay>,
    /// Hash and size of worker stdout.
    pub stdout: StreamDigest,
    /// Hash and size of worker stderr.
    pub stderr: StreamDigest,
}

impl IsolatedReplayRecord {
    /// Whether execution completed with the expected verdict and quiet stderr.
    pub fn is_expected(&self) -> bool {
        matches!(self.termination, ProcessTermination::Completed)
            && self.stderr.byte_len == 0
            && self
                .replay
                .as_ref()
                .is_some_and(|replay| replay.verdict.is_expected())
    }

    /// Validate this record against the exact replay request.
    pub fn validate(&self, request: &ReplayRequest) -> Result<(), IsolatedReplayError> {
        request.validate()?;
        if self.schema != ISOLATED_REPLAY_SCHEMA || self.schema_version != ISOLATED_REPLAY_VERSION {
            return Err(IsolatedReplayError::InvalidRecord(
                "unexpected isolated replay record schema".to_owned(),
            ));
        }
        if self.target != request.target
            || self.target != STWO_DEMO_TARGET
            || self.upstream_commit != request.upstream_commit
            || self.upstream_commit != STWO_SOURCE_ID
            || self.case_id != request.case_id()
        {
            return Err(IsolatedReplayError::InvalidRecord(
                "isolated replay source and target does not match its request".to_owned(),
            ));
        }
        if self.request_sha256 != replay_request_sha256(request)? {
            return Err(IsolatedReplayError::InvalidRecord(
                "isolated replay request digest mismatch".to_owned(),
            ));
        }
        validate_hex_digest(&self.worker_sha256, "worker")?;
        validate_worker_args(&self.worker_args)?;
        validate_stream_digest(&self.stdout, "stdout")?;
        validate_stream_digest(&self.stderr, "stderr")?;
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT.as_millis() as u64 {
            return Err(IsolatedReplayError::InvalidRecord(
                "isolated replay timeout is outside the supported range".to_owned(),
            ));
        }
        match (&self.termination, &self.replay) {
            (ProcessTermination::Completed, Some(replay)) => {
                validate_replay_response(request, replay)?;
                let canonical_stdout = canonical_worker_stdout(replay)?;
                if self.stdout.truncated
                    || self.stdout.byte_len != canonical_stdout.len() as u64
                    || self.stdout.sha256 != sha256_bytes(&canonical_stdout)
                {
                    return Err(IsolatedReplayError::InvalidRecord(
                        "completed worker stdout does not match its canonical replay".to_owned(),
                    ));
                }
            }
            (ProcessTermination::Completed, None) => {
                return Err(IsolatedReplayError::InvalidRecord(
                    "completed worker record has no replay".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(IsolatedReplayError::InvalidRecord(
                    "non-completed worker record unexpectedly contains a replay".to_owned(),
                ));
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Run a JSON replay worker under a parent-owned timeout.
///
/// The worker must read one [`ReplayRequest`] from stdin and write exactly one
/// [`DifferentialReplay`] JSON document to stdout on success.
pub fn run_isolated_replay(
    program: &Path,
    worker_args: &[String],
    request: &ReplayRequest,
    timeout: Duration,
) -> Result<IsolatedReplayRecord, IsolatedReplayError> {
    run_isolated_replay_inner(program, worker_args, request, timeout, None)
}

/// Run a replay only when the private worker copy matches a pinned digest.
///
/// The digest check happens after copying the executable into the private
/// directory and before spawning it, closing both substitution and path-race
/// windows at the execution boundary.
pub fn run_isolated_replay_with_worker_digest(
    program: &Path,
    worker_args: &[String],
    request: &ReplayRequest,
    timeout: Duration,
    expected_worker_sha256: &str,
) -> Result<IsolatedReplayRecord, IsolatedReplayError> {
    validate_hex_digest(expected_worker_sha256, "expected worker")?;
    run_isolated_replay_inner(
        program,
        worker_args,
        request,
        timeout,
        Some(expected_worker_sha256),
    )
}

fn run_isolated_replay_inner(
    program: &Path,
    worker_args: &[String],
    request: &ReplayRequest,
    timeout: Duration,
    expected_worker_sha256: Option<&str>,
) -> Result<IsolatedReplayRecord, IsolatedReplayError> {
    request.validate()?;
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(IsolatedReplayError::InvalidTimeout(timeout));
    }
    validate_worker_args(worker_args)?;
    let request_bytes = serde_json::to_vec(request)
        .map_err(|error| IsolatedReplayError::Serialization(error.to_string()))?;
    if request_bytes.len() > MAX_REQUEST_BYTES {
        return Err(IsolatedReplayError::RequestTooLarge(request_bytes.len()));
    }
    let worker_dir = PrivateTempDir::create_in(&std::env::temp_dir(), ".airlock-worker-")
        .map_err(|error| IsolatedReplayError::WorkerIdentity(error.to_string()))?;
    let copied_worker = worker_dir.path().join(format!(
        "airlock-replay-worker{}",
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::copy(program, &copied_worker).map_err(|error| {
        IsolatedReplayError::WorkerIdentity(format!(
            "copy {} into private execution directory: {error}",
            program.display()
        ))
    })?;
    let worker_sha256 = sha256_file(&copied_worker)?;
    if expected_worker_sha256.is_some_and(|expected| expected != worker_sha256) {
        return Err(IsolatedReplayError::WorkerDigestMismatch);
    }

    let mut command = Command::new(&copied_worker);
    command
        .args(worker_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Put the worker in its own process group so a descendant cannot outlive the
    // deadline while holding the captured pipes open. Killing only the direct
    // child leaves such a grandchild attached to stdout, and the reader joins
    // below would then block past the wall clock the caller asked for.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = spawn_private_worker(&mut command)
        .map_err(|error| IsolatedReplayError::Spawn(error.to_string()))?;
    let process_group_id = child.id();
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or(IsolatedReplayError::MissingChildPipe("stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or(IsolatedReplayError::MissingChildPipe("stdout"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or(IsolatedReplayError::MissingChildPipe("stderr"))?;

    let writer = thread::spawn(move || {
        child_stdin.write_all(&request_bytes)?;
        child_stdin.flush()
    });
    let stdout_reader = thread::spawn(move || capture_stream(child_stdout));
    let stderr_reader = thread::spawn(move || capture_stream(child_stderr));

    let started = Instant::now();
    let mut observed_status = None;
    let (status, timed_out) = loop {
        if observed_status.is_none() {
            observed_status = child
                .try_wait()
                .map_err(|error| IsolatedReplayError::Wait(error.to_string()))?;
        }
        if writer.is_finished()
            && stdout_reader.is_finished()
            && stderr_reader.is_finished()
            && let Some(status) = observed_status
        {
            break (status, false);
        }
        if started.elapsed() >= timeout {
            // Retain and signal the original process group even after the leader
            // exits. A descendant may still own one of the captured pipes.
            terminate_process_group(process_group_id)?;
            let status = if let Some(status) = observed_status {
                status
            } else {
                child
                    .kill()
                    .map_err(|error| IsolatedReplayError::Kill(error.to_string()))?;
                child
                    .wait()
                    .map_err(|error| IsolatedReplayError::Wait(error.to_string()))?
            };
            break (status, true);
        }
        thread::sleep(POLL_INTERVAL);
    };

    let write_result = writer
        .join()
        .map_err(|_| IsolatedReplayError::ThreadPanicked("stdin writer"))?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| IsolatedReplayError::ThreadPanicked("stdout reader"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| IsolatedReplayError::ThreadPanicked("stderr reader"))??;

    let mut termination = if timed_out {
        ProcessTermination::TimedOut
    } else if !status.success() {
        ProcessTermination::ExitFailure {
            code: status.code(),
        }
    } else if write_result.is_err() {
        ProcessTermination::InvalidOutput {
            reason: InvalidOutputReason::RequestWriteFailed,
        }
    } else if stdout.truncated {
        ProcessTermination::InvalidOutput {
            reason: InvalidOutputReason::StdoutTooLarge,
        }
    } else if stderr.truncated {
        ProcessTermination::InvalidOutput {
            reason: InvalidOutputReason::StderrTooLarge,
        }
    } else if stdout.bytes.is_empty() {
        ProcessTermination::InvalidOutput {
            reason: InvalidOutputReason::MissingResponse,
        }
    } else {
        ProcessTermination::Completed
    };

    let replay = if matches!(termination, ProcessTermination::Completed) {
        match serde_json::from_slice::<DifferentialReplay>(&stdout.bytes) {
            Ok(replay) => match (
                validate_replay_response(request, &replay),
                canonical_worker_stdout(&replay),
            ) {
                (Ok(()), Ok(canonical)) if canonical == stdout.bytes => Some(replay),
                _ => {
                    termination = ProcessTermination::InvalidOutput {
                        reason: InvalidOutputReason::ResponseMismatch,
                    };
                    None
                }
            },
            Err(_) => {
                termination = ProcessTermination::InvalidOutput {
                    reason: InvalidOutputReason::MalformedResponse,
                };
                None
            }
        }
    } else {
        None
    };

    let record = IsolatedReplayRecord {
        schema: ISOLATED_REPLAY_SCHEMA.to_owned(),
        schema_version: ISOLATED_REPLAY_VERSION.to_owned(),
        target: request.target.clone(),
        upstream_commit: request.upstream_commit.clone(),
        case_id: request.case_id().to_owned(),
        request_sha256: replay_request_sha256(request)?,
        worker_sha256,
        worker_args: worker_args.to_vec(),
        timeout_ms: timeout.as_millis() as u64,
        termination,
        replay,
        stdout: stdout.digest(),
        stderr: stderr.digest(),
    };
    record.validate(request)?;
    Ok(record)
}

fn spawn_private_worker(command: &mut Command) -> std::io::Result<std::process::Child> {
    #[cfg(target_os = "linux")]
    {
        for attempt in 0..=EXEC_BUSY_RETRY_LIMIT {
            match command.spawn() {
                Ok(child) => return Ok(child),
                Err(error)
                    if error.raw_os_error() == Some(libc::ETXTBSY)
                        && attempt < EXEC_BUSY_RETRY_LIMIT =>
                {
                    thread::sleep(EXEC_BUSY_RETRY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded worker spawn loop always returns");
    }

    #[cfg(not(target_os = "linux"))]
    command.spawn()
}

fn validate_replay_response(
    request: &ReplayRequest,
    replay: &DifferentialReplay,
) -> Result<(), IsolatedReplayError> {
    request
        .validate_replay(replay)
        .map_err(|error| IsolatedReplayError::InvalidRecord(error.to_string()))?;
    if replay.contract.target != request.target
        || replay.contract.upstream_commit != request.upstream_commit
        || replay.raw_pcs.observation.case_id != request.case_id()
        || replay.framework.observation.case_id != request.case_id()
    {
        return Err(IsolatedReplayError::InvalidRecord(
            "worker response does not match its request".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_worker_stdout(replay: &DifferentialReplay) -> Result<Vec<u8>, IsolatedReplayError> {
    let mut bytes = serde_json::to_vec(replay)
        .map_err(|error| IsolatedReplayError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

struct CapturedStream {
    bytes: Vec<u8>,
    sha256: String,
    byte_len: u64,
    truncated: bool,
}

impl CapturedStream {
    fn digest(&self) -> StreamDigest {
        StreamDigest {
            sha256: self.sha256.clone(),
            byte_len: self.byte_len,
            truncated: self.truncated,
        }
    }
}

fn capture_stream(mut reader: impl Read) -> std::io::Result<CapturedStream> {
    let mut stored = Vec::new();
    let mut hasher = Sha256::new();
    let mut byte_len = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        byte_len = byte_len.saturating_add(count as u64);
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(stored.len());
        stored.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(CapturedStream {
        bytes: stored,
        sha256: format!("{:x}", hasher.finalize()),
        byte_len,
        truncated: byte_len > MAX_CAPTURE_BYTES as u64,
    })
}

fn sha256_file(path: &Path) -> Result<String, IsolatedReplayError> {
    let mut file = File::open(path).map_err(|error| {
        IsolatedReplayError::WorkerIdentity(format!("open {}: {error}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            IsolatedReplayError::WorkerIdentity(format!("read {}: {error}", path.display()))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_stream_digest(
    stream: &StreamDigest,
    label: &'static str,
) -> Result<(), IsolatedReplayError> {
    validate_hex_digest(&stream.sha256, label)?;
    if stream.truncated != (stream.byte_len > MAX_CAPTURE_BYTES as u64) {
        return Err(IsolatedReplayError::InvalidRecord(format!(
            "{label} truncation flag does not match its byte length"
        )));
    }
    if stream.byte_len == 0 && stream.sha256 != sha256_bytes(&[]) {
        return Err(IsolatedReplayError::InvalidRecord(format!(
            "empty {label} stream has the wrong SHA-256"
        )));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_hex_digest(digest: &str, label: &'static str) -> Result<(), IsolatedReplayError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(IsolatedReplayError::InvalidRecord(format!(
            "{label} SHA-256 is not canonical lowercase hex"
        )));
    }
    Ok(())
}

fn validate_worker_args(args: &[String]) -> Result<(), IsolatedReplayError> {
    if args.len() > MAX_WORKER_ARGS
        || args
            .iter()
            .any(|arg| arg.is_empty() || arg.len() > MAX_WORKER_ARG_BYTES)
    {
        return Err(IsolatedReplayError::InvalidWorkerArguments);
    }
    Ok(())
}

/// Isolation, worker, or record construction error.
#[derive(Debug, Error)]
pub enum IsolatedReplayError {
    /// Request is stale or malformed.
    #[error(transparent)]
    Request(#[from] ReplayRequestError),
    /// Deadline is zero or exceeds the bounded runner policy.
    #[error("invalid isolated replay timeout {0:?}")]
    InvalidTimeout(Duration),
    /// Canonical request exceeds the worker input cap.
    #[error("isolated replay request is too large: {0} bytes")]
    RequestTooLarge(usize),
    /// Worker executable could not be hashed.
    #[error("could not identify worker executable: {0}")]
    WorkerIdentity(String),
    /// Private worker copy does not match the caller-pinned executable digest.
    #[error("isolated replay worker digest does not match the expected digest")]
    WorkerDigestMismatch,
    /// Worker argument vector exceeds the deterministic process contract.
    #[error("invalid isolated replay worker arguments")]
    InvalidWorkerArguments,
    /// Worker process could not be launched.
    #[error("could not spawn isolated replay worker: {0}")]
    Spawn(String),
    /// Child process pipe was unavailable.
    #[error("isolated replay worker has no {0} pipe")]
    MissingChildPipe(&'static str),
    /// Child status could not be observed.
    #[error("could not wait for isolated replay worker: {0}")]
    Wait(String),
    /// Timed-out worker could not be killed.
    #[error("could not kill timed-out replay worker: {0}")]
    Kill(String),
    /// Reader or writer helper thread panicked.
    #[error("isolated replay {0} thread panicked")]
    ThreadPanicked(&'static str),
    /// Child stream read failed.
    #[error("isolated replay stream read failed: {0}")]
    StreamRead(#[from] std::io::Error),
    /// Request or record serialization failed.
    #[error("isolated replay serialization failed: {0}")]
    Serialization(String),
    /// Replay record is internally inconsistent or relabeled.
    #[error("invalid isolated replay record: {0}")]
    InvalidRecord(String),
}

/// Signal the worker's whole process group on timeout.
///
/// The worker is spawned with `process_group(0)`, so its process-group id equals
/// its process id and a negative process-group target reaches every descendant.
/// This bounds captured-pipe drainage in the presence of grandchildren; it is
/// not an OS sandbox.
#[cfg(unix)]
fn terminate_process_group(pid: u32) -> Result<(), IsolatedReplayError> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    let pid = i32::try_from(pid)
        .map_err(|error| IsolatedReplayError::Kill(format!("invalid process-group id: {error}")))?;
    match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(IsolatedReplayError::Kill(format!(
            "signal replay worker process group: {error}"
        ))),
    }
}

/// Non-Unix targets have no process groups; the direct child kill still applies.
#[cfg(not(unix))]
fn terminate_process_group(_pid: u32) -> Result<(), IsolatedReplayError> {
    Ok(())
}
