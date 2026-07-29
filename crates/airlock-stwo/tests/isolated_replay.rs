use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use airlock_boundary::{MutationOperation, ScalarMutation};
use airlock_stwo::{
    ProcessTermination, ReplayBundleError, ReplayRequest, StwoBoundaryAdapter, run_isolated_replay,
    verify_replay_bundle, write_replay_bundle,
};
use sha2::{Digest, Sha256};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_airlock-stwo-worker"))
}

fn temp_parent(label: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "airlock-stwo-{label}-{}-{counter}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("create isolated test directory");
    path
}

fn remove_test_dir(path: &Path) {
    fs::remove_dir_all(path).expect("remove isolated test directory");
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read test worker");
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn write_script(parent: &Path, name: &str, body: &[u8]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = parent.join(name);
    fs::write(&path, body).expect("write test script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .expect("make test script executable");
    path
}

#[test]
fn real_worker_replays_honest_and_mutated_proofs() {
    let honest = ReplayRequest::honest();
    let honest_record = run_isolated_replay(&worker(), &[], &honest, Duration::from_secs(5))
        .expect("honest isolated replay");
    assert!(honest_record.is_expected());
    assert!(matches!(
        honest_record.termination,
        ProcessTermination::Completed
    ));

    let adapter = StwoBoundaryAdapter::new().expect("adapter");
    let path = adapter
        .first_sampled_value_path()
        .expect("sampled-value path");
    let mutated = ReplayRequest::mutation(
        "corrupt-oods-sample",
        vec![MutationOperation::ReplaceScalar {
            path,
            value: ScalarMutation::Increment,
        }],
    );
    let mutation_record = run_isolated_replay(&worker(), &[], &mutated, Duration::from_secs(5))
        .expect("mutated isolated replay");
    assert!(mutation_record.is_expected());
    assert!(mutation_record.replay.is_some());
}

#[cfg(unix)]
#[test]
fn process_failure_timeout_and_malformed_output_are_not_expected() {
    let request = ReplayRequest::honest();
    let parent = temp_parent("process-outcomes");
    let exit_worker = write_script(&parent, "exit.sh", b"#!/bin/sh\nexit 37\n");

    let exit = run_isolated_replay(&exit_worker, &[], &request, Duration::from_secs(1))
        .expect("exit replay record");
    assert!(!exit.is_expected());
    assert!(
        matches!(
            exit.termination,
            ProcessTermination::ExitFailure { code: Some(37) }
        ),
        "unexpected termination: {:?}",
        exit.termination
    );

    let timeout_worker = write_script(&parent, "timeout.sh", b"#!/bin/sh\nsleep 2\n");

    let timeout = run_isolated_replay(&timeout_worker, &[], &request, Duration::from_millis(50))
        .expect("timeout replay record");
    assert!(!timeout.is_expected());
    assert!(matches!(timeout.termination, ProcessTermination::TimedOut));

    let malformed_worker = write_script(
        &parent,
        "malformed.sh",
        b"#!/bin/sh\ncat >/dev/null\nprintf not-json\n",
    );

    let malformed = run_isolated_replay(&malformed_worker, &[], &request, Duration::from_secs(1))
        .expect("malformed output replay record");
    assert!(!malformed.is_expected());
    assert!(matches!(
        malformed.termination,
        ProcessTermination::InvalidOutput { .. }
    ));
    remove_test_dir(&parent);
}

#[cfg(unix)]
#[test]
fn worker_digest_is_bound_to_the_private_executed_copy() {
    use std::os::unix::fs::PermissionsExt;

    let parent = temp_parent("worker-copy");
    let original = parent.join("replaceable-worker.sh");
    fs::write(
        &original,
        b"#!/bin/sh\nprintf '#!/bin/sh\\nexit 99\\n' > \"$1\"\nexit 23\n",
    )
    .expect("write replaceable worker");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o700))
        .expect("make worker executable");
    let before = sha256_file(&original);

    let record = run_isolated_replay(
        &original,
        &[original.to_string_lossy().into_owned()],
        &ReplayRequest::honest(),
        Duration::from_secs(1),
    )
    .expect("replacement replay record");

    assert!(matches!(
        record.termination,
        ProcessTermination::ExitFailure { code: Some(23) }
    ));
    assert_eq!(record.worker_sha256, before);
    assert_ne!(sha256_file(&original), before);
    remove_test_dir(&parent);
}

#[test]
fn replay_bundle_is_deterministic_and_tamper_evident() {
    let request = ReplayRequest::honest();
    let report = run_isolated_replay(&worker(), &[], &request, Duration::from_secs(5))
        .expect("isolated replay");
    let second_report = run_isolated_replay(&worker(), &[], &request, Duration::from_secs(5))
        .expect("second isolated replay");
    assert_eq!(report, second_report);

    let mut inconsistent = report.clone();
    inconsistent.stdout.sha256 = "0".repeat(64);
    assert!(inconsistent.validate(&request).is_err());

    let parent = temp_parent("replay-bundle");
    let first = parent.join("first");
    let second = parent.join("second");

    let first_files = write_replay_bundle(&first, &request, &report).expect("write first bundle");
    let second_files =
        write_replay_bundle(&second, &request, &second_report).expect("write second bundle");
    assert_eq!(first_files, second_files);
    assert_eq!(
        verify_replay_bundle(&first).expect("verify first"),
        first_files
    );
    assert!(matches!(
        write_replay_bundle(&first, &request, &report),
        Err(ReplayBundleError::OutputExists(_))
    ));

    fs::write(first.join("report.json"), b"{}\n").expect("tamper report");
    assert!(matches!(
        verify_replay_bundle(&first),
        Err(ReplayBundleError::ChecksumMismatch)
    ));

    fs::write(second.join("unexpected.txt"), b"extra").expect("write extra file");
    assert!(matches!(
        verify_replay_bundle(&second),
        Err(ReplayBundleError::UnexpectedFile(_))
    ));
    remove_test_dir(&parent);
}
