use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use airlock_boundary::{MutationOperation, ScalarMutation};
use airlock_stwo::{
    EvidenceBundleError, ProcessTermination, ReplayRequest, StwoBoundaryAdapter,
    run_isolated_replay, verify_evidence_bundle, write_evidence_bundle,
};

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

#[test]
fn real_worker_replays_honest_and_mutated_proofs() {
    let honest = ReplayRequest::honest();
    let honest_evidence = run_isolated_replay(&worker(), &[], &honest, Duration::from_secs(5))
        .expect("honest isolated replay");
    assert!(honest_evidence.is_expected());
    assert!(matches!(
        honest_evidence.termination,
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
    let mutation_evidence = run_isolated_replay(&worker(), &[], &mutated, Duration::from_secs(5))
        .expect("mutated isolated replay");
    assert!(mutation_evidence.is_expected());
    assert!(mutation_evidence.replay.is_some());
}

#[cfg(unix)]
#[test]
fn process_failure_timeout_and_malformed_output_are_not_expected() {
    let request = ReplayRequest::honest();

    let exit = run_isolated_replay(
        Path::new("/bin/sh"),
        &["-c".to_owned(), "exit 37".to_owned()],
        &request,
        Duration::from_secs(1),
    )
    .expect("exit evidence");
    assert!(!exit.is_expected());
    assert!(matches!(
        exit.termination,
        ProcessTermination::ExitFailure { code: Some(37) }
    ));

    let timeout = run_isolated_replay(
        Path::new("/bin/sh"),
        &["-c".to_owned(), "sleep 2".to_owned()],
        &request,
        Duration::from_millis(50),
    )
    .expect("timeout evidence");
    assert!(!timeout.is_expected());
    assert!(matches!(timeout.termination, ProcessTermination::TimedOut));

    let malformed = run_isolated_replay(
        Path::new("/bin/sh"),
        &[
            "-c".to_owned(),
            "cat >/dev/null; printf not-json".to_owned(),
        ],
        &request,
        Duration::from_secs(1),
    )
    .expect("malformed output evidence");
    assert!(!malformed.is_expected());
    assert!(matches!(
        malformed.termination,
        ProcessTermination::InvalidOutput { .. }
    ));
}

#[test]
fn evidence_bundle_is_deterministic_and_tamper_evident() {
    let request = ReplayRequest::honest();
    let report = run_isolated_replay(&worker(), &[], &request, Duration::from_secs(5))
        .expect("isolated replay");
    let second_report = run_isolated_replay(&worker(), &[], &request, Duration::from_secs(5))
        .expect("second isolated replay");
    assert_eq!(report, second_report);

    let mut inconsistent = report.clone();
    inconsistent.stdout.sha256 = "0".repeat(64);
    assert!(inconsistent.validate(&request).is_err());

    let parent = temp_parent("evidence");
    let first = parent.join("first");
    let second = parent.join("second");

    let first_files = write_evidence_bundle(&first, &request, &report).expect("write first bundle");
    let second_files =
        write_evidence_bundle(&second, &request, &second_report).expect("write second bundle");
    assert_eq!(first_files, second_files);
    assert_eq!(
        verify_evidence_bundle(&first).expect("verify first"),
        first_files
    );

    fs::write(first.join("report.json"), b"{}\n").expect("tamper report");
    assert!(matches!(
        verify_evidence_bundle(&first),
        Err(EvidenceBundleError::ChecksumMismatch)
    ));

    fs::write(second.join("unexpected.txt"), b"extra").expect("write extra file");
    assert!(matches!(
        verify_evidence_bundle(&second),
        Err(EvidenceBundleError::UnexpectedFile(_))
    ));
    remove_test_dir(&parent);
}
