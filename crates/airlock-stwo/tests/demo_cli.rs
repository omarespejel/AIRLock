use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use airlock_boundary::{BoundaryPath, MutationOperation};
use airlock_stwo::{
    DifferentialVerdict, ProcessTermination, ReplayRequest, StwoBoundaryAdapter,
    read_verified_replay_bundle, run_isolated_replay, write_replay_bundle,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_airlock-stwo-demo"))
}

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_airlock-stwo-worker"))
}

fn temp_parent(label: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "airlock-stwo-cli-{label}-{}-{counter}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("create CLI test directory");
    path
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(demo()).args(args).output().expect("run demo")
}

fn as_str(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
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
fn cli_runs_verifies_and_renders_the_pinned_demo() {
    let parent = temp_parent("expected");
    let honest = parent.join("honest");
    let mutated = parent.join("mutated");
    let regression = parent.join("regression.rs");

    let honest_run = run(&[
        "honest",
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&honest),
    ]);
    assert!(honest_run.status.success());
    assert!(String::from_utf8_lossy(&honest_run.stdout).contains("AIRLOCK_REPLAY_EXPECTED"));

    let mutation_run = run(&[
        "corrupt-sample",
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&mutated),
    ]);
    assert!(mutation_run.status.success());
    assert!(String::from_utf8_lossy(&mutation_run.stdout).contains("MutationRejected"));

    for bundle in [&honest, &mutated] {
        let verified = run(&[
            "verify",
            "--bundle",
            as_str(bundle),
            "--worker",
            as_str(&worker()),
        ]);
        assert!(verified.status.success());
        assert!(
            String::from_utf8_lossy(&verified.stdout).contains("AIRLOCK_BUNDLE_REPLAY_MATCHED")
        );
    }

    let generated = run(&[
        "generate-regression",
        "--bundle",
        as_str(&mutated),
        "--output",
        as_str(&regression),
    ]);
    assert!(generated.status.success());
    let source = fs::read_to_string(&regression).expect("generated regression");
    assert!(source.contains("DifferentialVerdict::MutationRejected"));
    assert!(!source.contains(as_str(&parent)));

    let overwrite = run(&[
        "generate-regression",
        "--bundle",
        as_str(&mutated),
        "--output",
        as_str(&regression),
    ]);
    assert!(!overwrite.status.success());

    for (command, expected_verdict) in [
        ("witness-honest", "HONEST_ACCEPTED"),
        ("witness-preserving", "CONSTRAINT_PRESERVING_ACCEPTED"),
        ("witness-violating", "CONSTRAINT_VIOLATION_REJECTED"),
    ] {
        let output = run(&[command]);
        assert!(output.status.success(), "{command}");
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("witness JSON");
        assert_eq!(
            document["status"], "AIRLOCK_WITNESS_REPLAY_EXPECTED",
            "{command}"
        );
        assert_eq!(document["verdict"], expected_verdict, "{command}");
        assert_eq!(
            document["audit_ir_sha256"]
                .as_str()
                .expect("AuditIR digest")
                .len(),
            64,
            "{command}"
        );
        if command == "witness-honest" {
            assert!(document["seed_witness_sha256"].is_null(), "{command}");
            assert!(document["mutated_witness_sha256"].is_null(), "{command}");
        } else {
            assert_eq!(
                document["seed_witness_sha256"]
                    .as_str()
                    .expect("seed digest")
                    .len(),
                64,
                "{command}"
            );
            assert_eq!(
                document["mutated_witness_sha256"]
                    .as_str()
                    .expect("mutated digest")
                    .len(),
                64,
                "{command}"
            );
        }
    }

    for (command, expected_verdict) in [
        ("held-out-honest", "HONEST_ACCEPTED"),
        ("held-out-preserving", "CONSTRAINT_PRESERVING_ACCEPTED"),
        ("held-out-violating", "CONSTRAINT_VIOLATION_REJECTED"),
    ] {
        let output = run(&[command]);
        assert!(output.status.success(), "{command}");
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("held-out JSON");
        assert_eq!(
            document["status"], "AIRLOCK_HELD_OUT_REPLAY_EXPECTED",
            "{command}"
        );
        assert_eq!(document["verdict"], expected_verdict, "{command}");
        assert_eq!(
            document["target"], "stwo-held-out-wide-fibonacci-3-v1",
            "{command}"
        );
        assert_eq!(document["requested_paths"], 11, "{command}");
    }
    fs::remove_dir_all(parent).expect("remove CLI test directory");
}

#[test]
fn replay_command_executes_bounded_requests_and_keeps_non_green_evidence() {
    let parent = temp_parent("generic-replay");
    let rejected_request = parent.join("drop-commitment.json");
    let rejected_bundle = parent.join("drop-commitment");
    let request = ReplayRequest::mutation(
        "drop-commitment",
        vec![MutationOperation::Drop {
            path: BoundaryPath::new("commitments", vec![]),
            index: 0,
        }],
    );
    fs::write(
        &rejected_request,
        serde_json::to_vec_pretty(&request).expect("encode request"),
    )
    .expect("write request");
    let rejected = run(&[
        "replay",
        "--request",
        as_str(&rejected_request),
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&rejected_bundle),
    ]);
    assert!(rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stdout).contains("MutationRejected"));

    let adapter = StwoBoundaryAdapter::new().expect("adapter");
    let (tree, column, _) = adapter
        .honest_proof()
        .0
        .queried_values
        .iter()
        .enumerate()
        .find_map(|(tree, columns)| {
            columns
                .iter()
                .enumerate()
                .find(|(_, values)| !values.is_empty())
                .map(|(column, values)| (tree, column, values))
        })
        .expect("nonempty queried-values column");
    let panic_request = parent.join("truncate-queries.json");
    let panic_bundle = parent.join("truncate-queries");
    let request = ReplayRequest::mutation(
        "truncate-queries",
        vec![MutationOperation::Truncate {
            path: BoundaryPath::new("queried_values", vec![tree, column]),
            new_len: 0,
        }],
    );
    fs::write(
        &panic_request,
        serde_json::to_vec_pretty(&request).expect("encode request"),
    )
    .expect("write request");
    let panicked = run(&[
        "replay",
        "--request",
        as_str(&panic_request),
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&panic_bundle),
    ]);
    assert!(!panicked.status.success());
    let retained = read_verified_replay_bundle(&panic_bundle).expect("retained panic bundle");
    assert_eq!(
        retained.report.replay.expect("completed replay").verdict,
        DifferentialVerdict::Panic
    );

    fs::remove_dir_all(parent).expect("remove CLI test directory");
}

#[test]
fn replay_command_rejects_unknown_and_oversized_requests_before_execution() {
    let parent = temp_parent("invalid-replay");
    let unknown_request = parent.join("unknown.json");
    let unknown_bundle = parent.join("unknown-bundle");
    let mut request = serde_json::to_value(ReplayRequest::honest()).expect("encode request");
    request
        .as_object_mut()
        .expect("request object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    fs::write(
        &unknown_request,
        serde_json::to_vec(&request).expect("encode malformed request"),
    )
    .expect("write request");
    let unknown = run(&[
        "replay",
        "--request",
        as_str(&unknown_request),
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&unknown_bundle),
    ]);
    assert!(!unknown.status.success());
    assert!(!unknown_bundle.exists());

    let oversized_request = parent.join("oversized.json");
    let oversized_bundle = parent.join("oversized-bundle");
    fs::write(&oversized_request, vec![b' '; (1 << 20) + 1]).expect("write oversized request");
    let oversized = run(&[
        "replay",
        "--request",
        as_str(&oversized_request),
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&oversized_bundle),
    ]);
    assert!(!oversized.status.success());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("exceeds the 1 MiB limit"));
    assert!(!oversized_bundle.exists());

    let unsupported_request = parent.join("unsupported.json");
    let unsupported_bundle = parent.join("unsupported-bundle");
    let request = ReplayRequest::mutation(
        "unsupported-path",
        vec![MutationOperation::Truncate {
            path: BoundaryPath::new("fri.query_positions", vec![]),
            new_len: 0,
        }],
    );
    fs::write(
        &unsupported_request,
        serde_json::to_vec(&request).expect("encode unsupported request"),
    )
    .expect("write request");
    let unsupported = run(&[
        "replay",
        "--request",
        as_str(&unsupported_request),
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&unsupported_bundle),
    ]);
    assert!(!unsupported.status.success());
    let retained =
        read_verified_replay_bundle(&unsupported_bundle).expect("retained unsupported-path bundle");
    assert!(matches!(
        retained.report.termination,
        ProcessTermination::ExitFailure { code: Some(2) }
    ));
    assert!(retained.report.replay.is_none());

    fs::remove_dir_all(parent).expect("remove CLI test directory");
}

#[cfg(unix)]
#[test]
fn valid_failure_record_does_not_pass_the_cli_gate() {
    let request = ReplayRequest::honest();
    let parent = temp_parent("failure");
    let failure_worker = write_script(&parent, "exit.sh", b"#!/bin/sh\nexit 29\n");
    let report = run_isolated_replay(&failure_worker, &[], &request, Duration::from_secs(1))
        .expect("failure replay record");
    let bundle = parent.join("bundle");
    write_replay_bundle(&bundle, &request, &report).expect("write failure bundle");

    let verified = run(&[
        "verify",
        "--bundle",
        as_str(&bundle),
        "--worker",
        as_str(&failure_worker),
    ]);
    assert!(!verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stderr).contains("outcome is not expected"));
    fs::remove_dir_all(parent).expect("remove failure test directory");
}

#[cfg(unix)]
#[test]
fn bundle_verification_rejects_a_different_worker() {
    let parent = temp_parent("wrong-worker");
    let bundle = parent.join("honest");
    let honest_run = run(&[
        "honest",
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&bundle),
    ]);
    assert!(honest_run.status.success());

    let wrong_worker = write_script(&parent, "wrong.sh", b"#!/bin/sh\nexit 17\n");
    let verified = run(&[
        "verify",
        "--bundle",
        as_str(&bundle),
        "--worker",
        as_str(&wrong_worker),
    ]);
    assert!(!verified.status.success());
    assert!(
        String::from_utf8_lossy(&verified.stderr)
            .contains("does not match fresh execution with the supplied worker")
    );
    fs::remove_dir_all(parent).expect("remove wrong-worker test directory");
}
