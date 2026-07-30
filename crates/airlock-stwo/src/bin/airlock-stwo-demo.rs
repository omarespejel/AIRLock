//! Fail-closed command-line demo for pinned Stwo verifier-boundary replay.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use airlock_boundary::{MutationOperation, ScalarMutation};
use airlock_stwo::{
    HeldOutAdapter, ReplayRequest, StwoBoundaryAdapter, StwoWitnessAdapter,
    generate_regression_source, read_verified_replay_bundle, run_isolated_replay, seal_campaign,
    verify_campaign, write_held_out_replay, write_replay_bundle, write_witness_replay,
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
    /// Evaluate, prove, and verify the unmodified pre-commitment witness.
    WitnessHonest(WitnessArgs),
    /// Mutate every original-trace row while preserving the exported relation.
    WitnessPreserving(WitnessArgs),
    /// Mutate one original-trace row and require relation rejection.
    WitnessViolating(WitnessArgs),
    /// Prove and verify the unmodified upstream held-out witness.
    HeldOutHonest(WitnessArgs),
    /// Mutate the upstream held-out witness while preserving its relation.
    HeldOutPreserving(WitnessArgs),
    /// Mutate the upstream held-out witness and require relation rejection.
    HeldOutViolating(WitnessArgs),
    /// Seal the fixed campaign inventory with a source-bound manifest.
    SealCampaign {
        /// Existing campaign root containing only the executed payload files.
        #[arg(long)]
        root: PathBuf,
        /// Exact reviewed AIRLock Git commit.
        #[arg(long)]
        airlock_commit: String,
        /// Repository coverage manifest to snapshot.
        #[arg(long)]
        coverage: PathBuf,
    },
    /// Verify the sealed campaign and freshly replay every executable case.
    VerifyCampaign {
        /// Sealed campaign root.
        #[arg(long)]
        root: PathBuf,
        /// Caller-pinned AIRLock Git commit expected in the manifest.
        #[arg(long)]
        expected_airlock_commit: String,
        /// Exact replay-worker executable. Defaults to a sibling binary.
        #[arg(long)]
        worker: Option<PathBuf>,
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

#[derive(Debug, Args)]
struct WitnessArgs {
    /// New file receiving the complete typed replay; existing files are never overwritten.
    #[arg(long)]
    output: Option<PathBuf>,
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
        Command::WitnessHonest(args) => run_witness_case(WitnessDemoCase::Honest, args),
        Command::WitnessPreserving(args) => run_witness_case(WitnessDemoCase::Preserving, args),
        Command::WitnessViolating(args) => run_witness_case(WitnessDemoCase::Violating, args),
        Command::HeldOutHonest(args) => run_held_out_case(HeldOutDemoCase::Honest, args),
        Command::HeldOutPreserving(args) => run_held_out_case(HeldOutDemoCase::Preserving, args),
        Command::HeldOutViolating(args) => run_held_out_case(HeldOutDemoCase::Violating, args),
        Command::SealCampaign {
            root,
            airlock_commit,
            coverage,
        } => {
            let verified = seal_campaign(&root, &airlock_commit, &coverage)
                .with_context(|| format!("seal campaign {}", root.display()))?;
            println!(
                "{}",
                json!({
                    "status": "AIRLOCK_CAMPAIGN_SEALED",
                    "airlock_commit": verified.manifest.airlock_commit,
                    "manifest_sha256": verified.manifest_sha256,
                    "checksums_sha256": verified.checksums_sha256,
                })
            );
            Ok(())
        }
        Command::VerifyCampaign {
            root,
            expected_airlock_commit,
            worker,
        } => {
            let worker = worker.map_or_else(default_worker_path, Ok)?;
            let verified = verify_campaign(&root, &expected_airlock_commit, &worker)
                .with_context(|| format!("verify campaign {}", root.display()))?;
            println!(
                "{}",
                json!({
                    "status": "AIRLOCK_CAMPAIGN_REPLAY_MATCHED",
                    "airlock_commit": verified.manifest.airlock_commit,
                    "manifest_sha256": verified.manifest_sha256,
                    "checksums_sha256": verified.checksums_sha256,
                })
            );
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
enum WitnessDemoCase {
    Honest,
    Preserving,
    Violating,
}

#[derive(Clone, Copy)]
enum HeldOutDemoCase {
    Honest,
    Preserving,
    Violating,
}

fn run_witness_case(case: WitnessDemoCase, args: WitnessArgs) -> Result<()> {
    let adapter = StwoWitnessAdapter::new().context("build pinned witness adapter")?;
    let replay = match case {
        WitnessDemoCase::Honest => adapter.replay_honest(),
        WitnessDemoCase::Preserving => adapter.replay_mutation(
            "constant-one-witness",
            adapter.increment_all_rows_operations(),
        ),
        WitnessDemoCase::Violating => adapter.replay_mutation(
            "single-cell-violation",
            vec![adapter.increment_one_row_operation(0)?],
        ),
    }
    .context("run phase-bound witness replay")?;
    if !replay.report.verdict.is_expected() {
        bail!(
            "witness replay is internally consistent but produced unexpected verdict {:?}",
            replay.report.verdict
        );
    }
    let artifact_sha256 = args
        .output
        .as_ref()
        .map(|output| write_witness_replay(output, &replay))
        .transpose()
        .context("write complete witness replay")?;
    let mutation = replay.observation.mutation.as_ref();
    println!(
        "{}",
        json!({
            "status": "AIRLOCK_WITNESS_REPLAY_EXPECTED",
            "case_id": replay.report.case_id,
            "verdict": replay.report.verdict,
            "audit_ir_sha256": replay.observation.audit_ir_sha256,
            "seed_witness_sha256": mutation.map(|plan| &plan.seed_witness_sha256),
            "mutated_witness_sha256": mutation.map(|plan| &plan.mutated_witness_sha256),
            "audit_ir_constraints_hold": replay.observation.audit_ir_constraints_hold,
            "proof_generation": replay.observation.proof_generation,
            "verifier": replay.observation.verifier,
            "artifact_sha256": artifact_sha256,
        })
    );
    Ok(())
}

fn run_held_out_case(case: HeldOutDemoCase, args: WitnessArgs) -> Result<()> {
    let adapter = HeldOutAdapter::new().context("build upstream held-out adapter")?;
    let replay = match case {
        HeldOutDemoCase::Honest => adapter.replay_honest(),
        HeldOutDemoCase::Preserving => adapter.replay_preserving(),
        HeldOutDemoCase::Violating => adapter.replay_violating(),
    }
    .context("run held-out witness replay")?;
    if !replay.report.verdict.is_expected() {
        bail!(
            "held-out replay is internally consistent but produced unexpected verdict {:?}",
            replay.report.verdict
        );
    }
    let artifact_sha256 = args
        .output
        .as_ref()
        .map(|output| write_held_out_replay(output, &replay))
        .transpose()
        .context("write complete held-out replay")?;
    let mutation = replay.observation.mutation.as_ref();
    println!(
        "{}",
        json!({
            "status": "AIRLOCK_HELD_OUT_REPLAY_EXPECTED",
            "target": replay.contract.target,
            "case_id": replay.report.case_id,
            "verdict": replay.report.verdict,
            "requested_paths": replay.contract.requested.len(),
            "audit_ir_sha256": replay.observation.audit_ir_sha256,
            "seed_witness_sha256": mutation.map(|plan| &plan.seed_witness_sha256),
            "mutated_witness_sha256": mutation.map(|plan| &plan.mutated_witness_sha256),
            "audit_ir_constraints_hold": replay.observation.audit_ir_constraints_hold,
            "proof_generation": replay.observation.proof_generation,
            "verifier": replay.observation.verifier,
            "artifact_sha256": artifact_sha256,
        })
    );
    Ok(())
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
