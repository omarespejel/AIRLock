//! Result vocabulary for AIRLock analyses.

use serde::{Deserialize, Serialize};

/// Assurance lane identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLane {
    /// Local AIR / integer / lookup semantics.
    Air,
    /// Statement binding / registry / selected API.
    StatementBinding,
    /// Fiat–Shamir, FRI, composition.
    Protocol,
    /// Evidence / provenance / benchmarks.
    Evidence,
}

/// Severity for findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    /// Informational.
    Informational,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// Stable finding codes for static analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    /// Manifest schema identity or version is not the one this analyzer implements.
    InvalidSchemaIdentity,
    /// Manifest or component shape is inconsistent with the Stwo execution domain.
    InvalidManifestStructure,
    /// Column declarations are ambiguous, inconsistent, or do not cover expression reads.
    InvalidColumnContract,
    /// Preprocessed data, length, source, or content hash is inconsistent.
    InvalidPreprocessedContract,
    /// A declared row support is empty, duplicated, reversed, or outside the domain.
    InvalidRowSupport,
    /// An integer encoder declaration is malformed independently of its admitted bound.
    InvalidEncoderContract,
    /// Table multiplicity can be nonzero outside semantic support.
    TableMultiplicityOutsideSemanticSupport,
    /// Lookup key maps to multiple values on rows where multiplicity may be nonzero.
    NonfunctionalLookupKey,
    /// Admitted integer bound exceeds encoder capacity.
    AdmittedBoundExceedsEncoder,
    /// Field equality lacks an integer no-wrap obligation.
    MissingIntegerNowrapObligation,
    /// LogUp not finalized exactly once.
    LogupNotFinalized,
    /// Declared degree bound underreports computed degree.
    DeclaredDegreeUnderreport,
    /// Column lacks semantic annotation on a COVERED path.
    MissingSemanticAnnotation,
    /// Inverse without nonzero obligation.
    InverseWithoutNonzeroObligation,
    /// Formal parameter declarations do not close the exported expressions.
    InvalidParameterContract,
    /// Surface missing from coverage manifest.
    SurfaceNotListed,
    /// Other / custom.
    Other,
}

/// One analytical finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Code.
    pub code: FindingCode,
    /// Severity.
    pub severity: Severity,
    /// Component name when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    /// Human message.
    pub message: String,
    /// Related relation / column ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

/// Fine-grained verdict for a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Solver/model confirmed and replayed against Spec.
    ConfirmedSat,
    /// Model also yields an accepted Stwo proof.
    ProofConfirmedSat,
    /// Solver model incomplete / not yet replayed.
    CandidateSat,
    /// Degenerate challenge; report probability term.
    BadChallenge,
    /// Independently checked proof / Lean.
    UnsatChecked,
    /// Solver unsat for exact bounded model.
    UnsatSolver,
    /// Timeout / unsupported op.
    Unknown,
    /// Property outside this lane's model.
    OutOfModel,
    /// Static analysis pass with no findings of blocking severity.
    StaticPass,
    /// Static analysis found blocking issues.
    StaticFail,
}

/// Per-lane status for the aggregate report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneStatus {
    /// Lane.
    pub lane: AnalysisLane,
    /// Status label.
    pub status: String,
    /// Detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Machine-readable gate report (aggregatable by SparseProve reviewer packet).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Source commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    /// Stwo commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stwo_commit: Option<String>,
    /// AIRLock version.
    pub airlock_version: String,
    /// IR schema version.
    pub ir_schema: String,
    /// Findings.
    pub findings: Vec<Finding>,
    /// Overall static verdict for the AIR lane.
    pub air_verdict: Verdict,
    /// Other lanes (must not be collapsed into air_verdict).
    pub lanes: Vec<LaneStatus>,
    /// Release status: never green solely from AIR.
    pub overall_release_status: String,
}

impl GateReport {
    /// Build a blocked report from findings.
    ///
    /// `ir_schema` must be the analyzed manifest's `schema_version`, not necessarily
    /// the tool's current `IR_SCHEMA_VERSION`.
    pub fn from_static_findings(
        airlock_version: impl Into<String>,
        ir_schema: impl Into<String>,
        findings: Vec<Finding>,
    ) -> Self {
        let blocked = findings.iter().any(|f| f.severity >= Severity::High);
        let air_verdict = if blocked {
            Verdict::StaticFail
        } else if findings.is_empty() {
            Verdict::StaticPass
        } else {
            // Non-blocking findings still fail COVERED until discharged.
            Verdict::StaticFail
        };
        Self {
            source_commit: None,
            stwo_commit: None,
            airlock_version: airlock_version.into(),
            ir_schema: ir_schema.into(),
            findings,
            air_verdict,
            lanes: vec![
                LaneStatus {
                    lane: AnalysisLane::Air,
                    status: format!("{air_verdict:?}"),
                    detail: None,
                },
                LaneStatus {
                    lane: AnalysisLane::StatementBinding,
                    status: "NOT_RUN".into(),
                    detail: None,
                },
                LaneStatus {
                    lane: AnalysisLane::Protocol,
                    status: "UNINSTANTIATED".into(),
                    detail: None,
                },
                LaneStatus {
                    lane: AnalysisLane::Evidence,
                    status: "NOT_RUN".into(),
                    detail: None,
                },
            ],
            overall_release_status: "BLOCKED".into(),
        }
    }
}
