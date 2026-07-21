//! AIRLock CLI — separate subcommands per assurance lane.

use std::fs;
use std::path::PathBuf;

use airlock_ir::{CoverageManifest, GateReport, IR_SCHEMA_VERSION};
use airlock_lint::{lint_manifest, LintOptions};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

const AIRLOCK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "airlock", version, about = "Adversarial soundness testing for Stwo AIRs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// AIR relation static gate over an AuditIR document.
    Air {
        /// Path to AuditIR JSON or YAML.
        #[arg(long)]
        manifest: PathBuf,
        /// Require semantic annotations on all columns.
        #[arg(long, default_value_t = false)]
        require_annotations: bool,
        /// Write GateReport JSON to this path.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Coverage manifest fail-closed check.
    Coverage {
        /// Path to coverage YAML/JSON.
        #[arg(long)]
        manifest: PathBuf,
        /// Required surface names (repeatable).
        #[arg(long = "require")]
        require: Vec<String>,
    },
    /// Protocol lane placeholder (not yet implemented).
    Protocol,
    /// Statement-binding lane placeholder.
    Statement,
    /// Evidence lane placeholder.
    Evidence,
    /// Print schema identity.
    Schema,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Air {
            manifest,
            require_annotations,
            report,
        } => cmd_air(manifest, require_annotations, report),
        Command::Coverage { manifest, require } => cmd_coverage(manifest, require),
        Command::Protocol => {
            bail!("protocol lane is OUT_OF_MODEL for AIRLock v0; see docs/SPEC.md")
        }
        Command::Statement => {
            bail!("statement-binding lane is not implemented in v0; see docs/SPEC.md")
        }
        Command::Evidence => {
            bail!("evidence lane is not implemented in v0; see docs/SPEC.md")
        }
        Command::Schema => {
            println!("schema={} version={} airlock={}", airlock_ir::IR_SCHEMA_ID, IR_SCHEMA_VERSION, AIRLOCK_VERSION);
            Ok(())
        }
    }
}

fn load_audit_manifest(path: &PathBuf) -> Result<airlock_ir::AuditManifest> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "yaml" || e == "yml")
    {
        Ok(serde_yaml::from_str(&text)?)
    } else {
        Ok(serde_json::from_str(&text)?)
    }
}

fn cmd_air(manifest: PathBuf, require_annotations: bool, report_path: Option<PathBuf>) -> Result<()> {
    let audit = load_audit_manifest(&manifest)?;
    let options = LintOptions {
        require_semantic_annotations: require_annotations,
    };
    let findings = lint_manifest(&audit, &options);
    let gate = GateReport::from_static_findings(AIRLOCK_VERSION, findings.clone());

    if let Some(path) = report_path {
        let json = serde_json::to_string_pretty(&gate)?;
        fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
    }

    println!(
        "airlock air: components={} findings={} verdict={:?} release={}",
        audit.components.len(),
        gate.findings.len(),
        gate.air_verdict,
        gate.overall_release_status
    );
    for finding in &gate.findings {
        println!(
            "  [{:?}] {:?} {}: {}",
            finding.severity,
            finding.code,
            finding.component.as_deref().unwrap_or("-"),
            finding.message
        );
    }

    if matches!(
        gate.air_verdict,
        airlock_ir::Verdict::StaticFail
            | airlock_ir::Verdict::ConfirmedSat
            | airlock_ir::Verdict::ProofConfirmedSat
            | airlock_ir::Verdict::CandidateSat
    ) {
        bail!("AIR static gate failed");
    }
    Ok(())
}

fn cmd_coverage(manifest: PathBuf, require: Vec<String>) -> Result<()> {
    let text = fs::read_to_string(&manifest)?;
    let coverage: CoverageManifest = if manifest
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e == "json")
    {
        serde_json::from_str(&text)?
    } else {
        serde_yaml::from_str(&text)?
    };

    let required: Vec<&str> = if require.is_empty() {
        coverage.surfaces.iter().map(|s| s.name.as_str()).collect()
    } else {
        require.iter().map(String::as_str).collect()
    };

    if let Err(missing) = coverage.require_listed(&required) {
        bail!("coverage manifest missing surfaces: {missing:?}");
    }

    for name in &required {
        let entry = coverage
            .surfaces
            .iter()
            .find(|s| s.name == *name)
            .expect("listed");
        println!("{} => {:?}", entry.name, entry.status);
    }

    let explicit: Vec<&str> = require.iter().map(String::as_str).collect();
    if !explicit.is_empty() && !coverage.all_required_covered(&explicit) {
        bail!("required surfaces are not all COVERED");
    }
    Ok(())
}
