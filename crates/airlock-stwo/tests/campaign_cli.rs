use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use airlock_boundary::WitnessVerdict;
use airlock_stwo::{
    CampaignManifest, HeldOutAdapter, StwoWitnessAdapter, write_held_out_replay,
    write_witness_replay,
};
use sha2::{Digest, Sha256};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const TEST_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHECKSUM_PATHS: [&str; 16] = [
    "campaign.json",
    "corrupt-oods-sample/SHA256SUMS",
    "corrupt-oods-sample/report.json",
    "corrupt-oods-sample/request.json",
    "corrupt-oods-sample-regression.rs",
    "coverage.yaml",
    "heldout-honest.json",
    "heldout-preserving.json",
    "heldout-violating.json",
    "honest/SHA256SUMS",
    "honest/report.json",
    "honest/request.json",
    "SUMMARY.md",
    "witness-honest.json",
    "witness-preserving.json",
    "witness-violating.json",
];

fn demo() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_airlock-stwo-demo"))
}

fn worker() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_airlock-stwo-worker"))
}

fn coverage() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/coverage.yaml")
}

fn temp_parent(label: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "airlock-campaign-{label}-{}-{counter}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("create campaign test directory");
    path
}

fn as_str(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(demo()).args(args).output().expect("run demo")
}

fn require_success(args: &[&str]) {
    let output = run(args);
    assert!(
        output.status.success(),
        "command failed: {args:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_sealed_campaign(parent: &Path) -> PathBuf {
    let root = parent.join("campaign");
    fs::create_dir(&root).expect("create campaign root");
    let honest = root.join("honest");
    let mutated = root.join("corrupt-oods-sample");
    let regression = root.join("corrupt-oods-sample-regression.rs");

    require_success(&[
        "honest",
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&honest),
    ]);
    require_success(&[
        "corrupt-sample",
        "--worker",
        as_str(&worker()),
        "--output",
        as_str(&mutated),
    ]);
    require_success(&[
        "generate-regression",
        "--bundle",
        as_str(&mutated),
        "--output",
        as_str(&regression),
    ]);
    for (command, output) in [
        ("witness-honest", root.join("witness-honest.json")),
        ("witness-preserving", root.join("witness-preserving.json")),
        ("witness-violating", root.join("witness-violating.json")),
    ] {
        require_success(&[command, "--output", as_str(&output)]);
    }
    for (command, output) in [
        ("held-out-honest", root.join("heldout-honest.json")),
        ("held-out-preserving", root.join("heldout-preserving.json")),
        ("held-out-violating", root.join("heldout-violating.json")),
    ] {
        require_success(&[command, "--output", as_str(&output)]);
    }
    require_success(&[
        "seal-campaign",
        "--root",
        as_str(&root),
        "--airlock-commit",
        TEST_COMMIT,
        "--coverage",
        as_str(&coverage()),
    ]);
    root
}

fn verify(root: &Path) -> std::process::Output {
    verify_with_worker(root, &worker())
}

fn verify_with_worker(root: &Path, replay_worker: &Path) -> std::process::Output {
    run(&[
        "verify-campaign",
        "--root",
        as_str(root),
        "--expected-airlock-commit",
        TEST_COMMIT,
        "--worker",
        as_str(replay_worker),
    ])
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create copied root");
    for entry in fs::read_dir(source).expect("list source") {
        let entry = entry.expect("source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("source type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy source file");
        }
    }
}

fn write_manifest(root: &Path, manifest: &CampaignManifest) {
    let mut bytes = serde_json::to_vec_pretty(manifest).expect("serialize campaign manifest");
    bytes.push(b'\n');
    fs::write(root.join("campaign.json"), bytes).expect("write changed campaign manifest");
    rewrite_top_checksums(root);
}

fn refresh_payload_record(root: &Path, manifest: &mut CampaignManifest, path: &str) {
    let bytes = fs::read(root.join(path)).expect("read changed payload");
    let record = manifest
        .payload_files
        .iter_mut()
        .find(|record| record.path == path)
        .expect("payload record");
    record.sha256 = format!("{:x}", Sha256::digest(&bytes));
    record.size_bytes = bytes.len() as u64;
}

fn rewrite_top_checksums(root: &Path) {
    let checksums = CHECKSUM_PATHS
        .iter()
        .map(|path| {
            let bytes = fs::read(root.join(path)).expect("read checksum payload");
            ((*path).to_owned(), format!("{:x}", Sha256::digest(bytes)))
        })
        .collect::<BTreeMap<_, _>>();
    let document = checksums
        .into_iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    fs::write(root.join("SHA256SUMS"), document).expect("rewrite top checksums");
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn text_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![];
    for entry in fs::read_dir(root).expect("list campaign text files") {
        let entry = entry.expect("campaign text entry");
        if entry.file_type().expect("campaign text type").is_dir() {
            files.extend(text_files(&entry.path()));
        } else {
            files.push(entry.path());
        }
    }
    files.sort();
    files
}

#[test]
fn sealed_campaign_is_deterministic_replays_and_contains_no_local_path() {
    let parent = temp_parent("baseline");
    let root = build_sealed_campaign(&parent);
    let second_parent = temp_parent("second-baseline");
    let second_root = build_sealed_campaign(&second_parent);
    let output = verify(&root);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("AIRLOCK_CAMPAIGN_REPLAY_MATCHED"));

    for path in ["campaign.json", "SHA256SUMS", "SUMMARY.md"] {
        assert_eq!(
            fs::read(root.join(path)).expect("first deterministic artifact"),
            fs::read(second_root.join(path)).expect("second deterministic artifact"),
            "{path}"
        );
    }
    for path in text_files(&root) {
        let text = fs::read_to_string(&path).expect("campaign artifact is text");
        assert!(
            !text.contains(as_str(&parent)),
            "local path leaked through {}",
            path.display()
        );
    }
    fs::remove_dir_all(parent).expect("remove campaign test directory");
    fs::remove_dir_all(second_parent).expect("remove second campaign test directory");
}

#[test]
fn campaign_rejects_tamper_missing_and_extra_entries() {
    let parent = temp_parent("inventory");
    let base = build_sealed_campaign(&parent);

    let tampered = parent.join("tampered");
    copy_tree(&base, &tampered);
    fs::write(tampered.join("SUMMARY.md"), b"changed\n").expect("tamper summary");
    let output = verify(&tampered);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("checksum mismatch for `SUMMARY.md`"));

    let missing = parent.join("missing");
    copy_tree(&base, &missing);
    fs::remove_file(missing.join("SUMMARY.md")).expect("remove summary");
    let output = verify(&missing);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("inventory is incomplete"));

    let extra = parent.join("extra");
    copy_tree(&base, &extra);
    fs::write(extra.join("unrequested.json"), b"{}\n").expect("write extra file");
    let output = verify(&extra);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unexpected campaign entry"));

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn campaign_rejects_self_consistently_rehashed_forbidden_external_content() {
    let parent = temp_parent("forbidden-external-content");
    let root = build_sealed_campaign(&parent);
    fs::write(
        root.join("SUMMARY.md"),
        b"# AIRLock Stwo Campaign\n\nGenerated by Claude under /Users/example.\n",
    )
    .expect("write forbidden summary");

    let mut manifest: CampaignManifest =
        serde_json::from_slice(&fs::read(root.join("campaign.json")).expect("read manifest"))
            .expect("parse manifest");
    refresh_payload_record(&root, &mut manifest, "SUMMARY.md");
    write_manifest(&root, &manifest);

    let output = verify(&root);
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(
        error.contains("contains forbidden local absolute path"),
        "{}",
        error
    );
    assert!(!error.contains("Claude"), "{error}");
    assert!(!error.contains("/Users/example"), "{error}");

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[cfg(unix)]
#[test]
fn campaign_rejects_mismatched_worker_before_execution() {
    use std::os::unix::fs::PermissionsExt;

    let parent = temp_parent("worker-substitution");
    let root = build_sealed_campaign(&parent);
    let sentinel = parent.join("sentinel-worker.sh");
    let marker = parent.join("worker-ran");
    assert!(!marker.to_string_lossy().contains('\''));
    fs::write(
        &sentinel,
        format!("#!/bin/sh\n: > '{}'\n", marker.display()),
    )
    .expect("write sentinel worker");
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o700))
        .expect("make sentinel worker executable");

    let output = verify_with_worker(&root, &sentinel);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("worker digest"));
    assert!(
        !marker.exists(),
        "mismatched worker executed before its digest was rejected"
    );

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn witness_artifact_writer_never_removes_an_existing_file() {
    let parent = temp_parent("existing-witness");
    let output = parent.join("witness-honest.json");
    fs::write(&output, b"keep me\n").expect("write existing witness artifact");

    let result = run(&["witness-honest", "--output", as_str(&output)]);
    assert!(!result.status.success());
    assert_eq!(
        fs::read(&output).expect("existing witness artifact remains"),
        b"keep me\n"
    );

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn held_out_artifact_writer_never_removes_an_existing_file() {
    let parent = temp_parent("existing-held-out");
    let output = parent.join("heldout-honest.json");
    fs::write(&output, b"keep me\n").expect("write existing held-out artifact");

    let result = run(&["held-out-honest", "--output", as_str(&output)]);
    assert!(!result.status.success());
    assert_eq!(
        fs::read(&output).expect("existing held-out artifact remains"),
        b"keep me\n"
    );

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn campaign_rejects_self_consistent_wrong_source_and_verdict() {
    let parent = temp_parent("semantic");
    let base = build_sealed_campaign(&parent);

    let wrong_source = parent.join("wrong-source");
    copy_tree(&base, &wrong_source);
    let mut manifest: CampaignManifest = serde_json::from_slice(
        &fs::read(wrong_source.join("campaign.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    manifest.stwo_source_id = "stwo@wrong-source".to_owned();
    write_manifest(&wrong_source, &manifest);
    let output = verify(&wrong_source);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unexpected Stwo source"));

    let wrong_airlock = run(&[
        "verify-campaign",
        "--root",
        as_str(&base),
        "--expected-airlock-commit",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--worker",
        as_str(&worker()),
    ]);
    assert!(!wrong_airlock.status.success());
    assert!(stderr(&wrong_airlock).contains("AIRLock commit mismatch"));

    let wrong_verdict = parent.join("wrong-verdict");
    copy_tree(&base, &wrong_verdict);
    let mut manifest: CampaignManifest = serde_json::from_slice(
        &fs::read(wrong_verdict.join("campaign.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    manifest.cases[0].expected_verdict = "COUNTEREXAMPLE".to_owned();
    write_manifest(&wrong_verdict, &manifest);
    let output = verify(&wrong_verdict);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("case inventory differs"));

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn campaign_rejects_a_self_consistently_rehashed_alternate_mutation_plan() {
    let parent = temp_parent("alternate-plan");
    let root = build_sealed_campaign(&parent);
    let adapter = StwoWitnessAdapter::new().expect("build witness adapter");
    let mut alternate_operations = adapter.increment_all_rows_operations();
    alternate_operations.reverse();
    let alternate = adapter
        .replay_mutation("constant-one-witness", alternate_operations)
        .expect("replay alternate preserving mutation");
    assert_eq!(
        alternate.report.verdict,
        WitnessVerdict::ConstraintPreservingAccepted
    );

    let artifact = root.join("witness-preserving.json");
    fs::remove_file(&artifact).expect("remove original preserving artifact");
    write_witness_replay(&artifact, &alternate).expect("write alternate preserving artifact");

    let mut manifest: CampaignManifest =
        serde_json::from_slice(&fs::read(root.join("campaign.json")).expect("read manifest"))
            .expect("parse manifest");
    refresh_payload_record(&root, &mut manifest, "witness-preserving.json");
    write_manifest(&root, &manifest);

    let output = verify(&root);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("differs from the frozen case contract"));

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn campaign_rejects_a_rehashed_semantically_equivalent_held_out_plan() {
    let parent = temp_parent("alternate-held-out-plan");
    let root = build_sealed_campaign(&parent);
    let adapter = HeldOutAdapter::new().expect("build held-out adapter");
    let mut alternate_operations = adapter
        .preserving_operations_at_row(0)
        .expect("in-range row");
    alternate_operations.reverse();
    let alternate = adapter
        .replay_mutation("wide-fibonacci-preserving", alternate_operations)
        .expect("replay alternate preserving mutation");
    assert_eq!(
        alternate.report.verdict,
        WitnessVerdict::ConstraintPreservingAccepted
    );

    let artifact = root.join("heldout-preserving.json");
    fs::remove_file(&artifact).expect("remove original held-out artifact");
    write_held_out_replay(&artifact, &alternate).expect("write alternate held-out artifact");

    let mut manifest: CampaignManifest =
        serde_json::from_slice(&fs::read(root.join("campaign.json")).expect("read manifest"))
            .expect("parse manifest");
    refresh_payload_record(&root, &mut manifest, "heldout-preserving.json");
    write_manifest(&root, &manifest);

    let output = verify(&root);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("differs from the frozen case contract"));

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}

#[test]
fn campaign_rejects_a_self_consistently_rehashed_coverage_overclaim() {
    let parent = temp_parent("coverage-overclaim");
    let root = build_sealed_campaign(&parent);
    let coverage_path = root.join("coverage.yaml");
    let original = fs::read_to_string(&coverage_path).expect("read coverage snapshot");
    let overclaim = original.replacen(
        "  - name: warp-streaming\n    status: UNSUPPORTED",
        "  - name: warp-streaming\n    status: COVERED",
        1,
    );
    assert_ne!(overclaim, original);
    fs::write(&coverage_path, overclaim).expect("write overclaimed coverage snapshot");

    let mut manifest: CampaignManifest =
        serde_json::from_slice(&fs::read(root.join("campaign.json")).expect("read manifest"))
            .expect("parse manifest");
    refresh_payload_record(&root, &mut manifest, "coverage.yaml");
    write_manifest(&root, &manifest);

    let output = verify(&root);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("differs from the canonical checked-in inventory"));

    fs::remove_dir_all(parent).expect("remove campaign test directory");
}
