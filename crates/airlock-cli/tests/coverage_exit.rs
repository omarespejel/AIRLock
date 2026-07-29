use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/coverage")
        .join(name)
}

#[test]
fn default_coverage_fails_when_any_listed_surface_is_incomplete() {
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["coverage", "--manifest"])
        .arg(fixture("incomplete.yaml"))
        .output()
        .expect("run airlock coverage");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("required surfaces are not all COVERED")
    );
}

#[test]
fn default_coverage_passes_when_every_listed_surface_is_covered() {
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["coverage", "--manifest"])
        .arg(fixture("all_covered.yaml"))
        .output()
        .expect("run airlock coverage");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn explicit_expected_surface_does_not_hide_an_incomplete_inventory() {
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["coverage", "--manifest"])
        .arg(fixture("incomplete.yaml"))
        .args(["--require", "component-a"])
        .output()
        .expect("run airlock coverage");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("required surfaces are not all COVERED")
    );
}

#[test]
fn explicit_missing_surface_fails_even_when_inventory_is_covered() {
    let output = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(["coverage", "--manifest"])
        .arg(fixture("all_covered.yaml"))
        .args(["--require", "component-c"])
        .output()
        .expect("run airlock coverage");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("component-c"));
}
