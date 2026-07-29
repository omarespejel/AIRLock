use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use airlock_stwo::{ReplayRequest, run_isolated_replay, write_replay_bundle};

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

    for command in ["witness-honest", "witness-preserving", "witness-violating"] {
        let output = run(&[command]);
        assert!(output.status.success(), "{command}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("AIRLOCK_WITNESS_REPLAY_EXPECTED"),
            "{command}"
        );
    }
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
