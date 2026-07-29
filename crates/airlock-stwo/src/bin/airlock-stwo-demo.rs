//! Fail-closed command-line demo for pinned Stwo verifier-boundary replay.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlock_boundary::{MutationOperation, ScalarMutation};
use airlock_stwo::{
    ReplayRequest, StwoBoundaryAdapter, generate_regression_source, read_verified_replay_bundle,
    run_isolated_replay, write_replay_bundle,
};
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(
    name = "airlock-stwo-demo",
    version,
    about = "Run and verify AIRLock's pinned Stwo boundary demo"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prove and verify the unmodified deterministic fixture.
    Honest(RunArgs),
    /// Corrupt one verifier-requested OODS sample and require typed rejection.
    CorruptSample(RunArgs),
    /// Verify a bundle and reproduce its expected replay with the pinned worker.
    Verify {
        /// Replay bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// Exact replay-worker executable. Defaults to a sibling binary.
        #[arg(long)]
        worker: Option<PathBuf>,
    },
    /// Generate a path-independent Rust regression from a verified bundle.
    GenerateRegression {
        /// Replay bundle directory.
        #[arg(long)]
        bundle: PathBuf,
        /// New Rust source file; existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Exact replay-worker executable. Defaults to a sibling binary.
    #[arg(long)]
    worker: Option<PathBuf>,
    /// New replay bundle directory; existing paths are never overwritten.
    #[arg(long)]
    output: PathBuf,
    /// Parent-owned worker deadline in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_seconds: u64,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Honest(args) => run_case(ReplayRequest::honest(), args),
        Command::CorruptSample(args) => {
            let adapter = StwoBoundaryAdapter::new().context("build pinned Stwo adapter")?;
            let request = ReplayRequest::mutation(
                "corrupt-oods-sample",
                vec![MutationOperation::ReplaceScalar {
                    path: adapter
                        .first_sampled_value_path()
                        .context("locate verifier-requested OODS sample")?,
                    value: ScalarMutation::Increment,
                }],
            );
            run_case(request, args)
        }
        Command::Verify { bundle, worker } => verify_expected_bundle(&bundle, worker),
        Command::GenerateRegression { bundle, output } => {
            let verified = read_verified_replay_bundle(&bundle)
                .with_context(|| format!("verify {}", bundle.display()))?;
            let replay = verified
                .report
                .replay
                .as_ref()
                .context("verified bundle has no completed replay")?;
            let source = generate_regression_source(&verified.request, replay.verdict)?;
            write_new(&output, source.as_bytes())?;
            println!(
                "{}",
                json!({
                    "status": "AIRLOCK_REGRESSION_WRITTEN",
                    "case_id": verified.report.case_id,
                    "output": output,
                })
            );
            Ok(())
        }
    }
}

fn run_case(request: ReplayRequest, args: RunArgs) -> Result<()> {
    let worker = args.worker.map_or_else(default_worker_path, Ok)?;
    let report = run_isolated_replay(
        &worker,
        &[],
        &request,
        Duration::from_secs(args.timeout_seconds),
    )
    .with_context(|| format!("run isolated replay with {}", worker.display()))?;
    let files = write_replay_bundle(&args.output, &request, &report)
        .with_context(|| format!("write {}", args.output.display()))?;
    let verified = read_verified_replay_bundle(&args.output)
        .with_context(|| format!("verify {}", args.output.display()))?;
    if !verified.report.is_expected() {
        bail!(
            "replay bundle is internally consistent but the outcome is not expected: {:?}",
            verified.report.termination
        );
    }
    let verdict = verified
        .report
        .replay
        .as_ref()
        .context("expected replay is absent")?
        .verdict;
    println!(
        "{}",
        json!({
            "status": "AIRLOCK_REPLAY_EXPECTED",
            "case_id": verified.report.case_id,
            "verdict": format!("{verdict:?}"),
            "bundle": args.output,
            "request_file_sha256": files.request_file_sha256,
            "report_file_sha256": files.report_file_sha256,
        })
    );
    Ok(())
}

fn verify_expected_bundle(bundle: &Path, worker: Option<PathBuf>) -> Result<()> {
    let verified = read_verified_replay_bundle(bundle)
        .with_context(|| format!("verify {}", bundle.display()))?;
    if !verified.report.is_expected() {
        bail!("bundle is internally consistent, but its replay outcome is not expected");
    }
    let worker = worker.map_or_else(default_worker_path, Ok)?;
    let replayed = run_isolated_replay(
        &worker,
        &verified.report.worker_args,
        &verified.request,
        Duration::from_millis(verified.report.timeout_ms),
    )
    .with_context(|| format!("replay bundle with {}", worker.display()))?;
    if replayed != verified.report {
        bail!("bundle record does not match fresh execution with the supplied worker");
    }
    let verdict = verified
        .report
        .replay
        .as_ref()
        .context("expected replay is absent")?
        .verdict;
    println!(
        "{}",
        json!({
            "status": "AIRLOCK_BUNDLE_REPLAY_MATCHED",
            "case_id": verified.report.case_id,
            "verdict": format!("{verdict:?}"),
            "request_file_sha256": verified.files.request_file_sha256,
            "report_file_sha256": verified.files.report_file_sha256,
        })
    );
    Ok(())
}

fn default_worker_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("locate demo executable")?;
    let name = format!("airlock-stwo-worker{}", std::env::consts::EXE_SUFFIX);
    Ok(executable.with_file_name(name))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", path.display()))
}
