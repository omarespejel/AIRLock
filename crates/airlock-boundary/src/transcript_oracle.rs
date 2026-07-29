//! Generic Fiat--Shamir ordering and validation oracles.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::transcript::sha256_hex;
use crate::{
    AbsorbKind, AbsorptionRequirement, BoundaryPath, DomainSeparatorRequirement, DrawKind,
    DrawRequirement, PowRequirement, QueryShape, TranscriptContract, TranscriptContractError,
    TranscriptEvent, TranscriptSource, TranscriptStep, TranscriptTrace, ValidationOutcome,
    ValidationRule, ZeroPowNoncePolicy,
};

/// Blocking importance inside the modeled transcript lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TranscriptSeverity {
    /// High-confidence violation of a declared transcript invariant.
    High,
}

/// Stable transcript-lane finding codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TranscriptFindingCode {
    /// Transcript contract or trace is malformed or mismatched.
    InvalidTranscriptContract,
    /// Prover-controlled data was absorbed without a declared validation contract.
    UnmodeledProverTranscriptInput,
    /// Prover-controlled data was absorbed before required validation passed.
    ProverDataAbsorbedBeforeValidation,
    /// Prover-controlled data was used by another verifier operation before validation passed.
    ProverDataUsedBeforeValidation,
    /// Transcript contains an absorption outside the declared inventory.
    UnmodeledTranscriptAbsorption,
    /// A transcript absorption's path, source, or semantic kind differs from its contract.
    TranscriptAbsorptionContractMismatch,
    /// A transcript absorption occurred a different number of times than declared.
    TranscriptAbsorptionCardinalityMismatch,
    /// A transcript separator or proof-of-work event differs from its exact inventory.
    TranscriptEventInventoryMismatch,
    /// Ordered transcript events differ from the target's exact schedule.
    TranscriptScheduleMismatch,
    /// A challenge or query draw occurred before a required transcript event.
    MissingTranscriptPrerequisite,
    /// A challenge or query draw has no declared contract.
    UnmodeledTranscriptDraw,
    /// A required challenge or query draw was not observed.
    MissingTranscriptDraw,
    /// A contracted transcript draw occurred more than once.
    DuplicateTranscriptDraw,
    /// A zero-work nonce violates the target's explicit policy.
    ZeroPowNoncePolicyViolation,
    /// A proof-of-work event differs from its exact bits, path, or label contract.
    TranscriptPowContractMismatch,
    /// A declared proof-of-work verification failed.
    TranscriptPowVerificationFailed,
    /// A transcript nonce absorption is not the exact value accepted by proof-of-work validation.
    TranscriptPowNonceBindingMismatch,
    /// A query draw differs from the exact contracted count or domain.
    TranscriptDrawContractMismatch,
}

/// One transcript invariant finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptFinding {
    /// Stable finding identity.
    pub code: TranscriptFindingCode,
    /// Blocking importance inside the transcript lane.
    pub severity: TranscriptSeverity,
    /// Human-readable diagnostic.
    pub message: String,
    /// Stable paths or labels related to the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

type Finding = TranscriptFinding;
type FindingCode = TranscriptFindingCode;
type Severity = TranscriptSeverity;

/// Fail-closed result for one transcript trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TranscriptVerdict {
    /// Every modeled prerequisite was satisfied.
    Accepted,
    /// One or more transcript invariants produced a counterexample.
    Counterexample,
    /// Contract or trace was malformed, mismatched, or incomplete.
    Unsupported,
}

impl TranscriptVerdict {
    /// Whether the modeled transcript checks are conclusive and green.
    pub const fn is_green(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Report for one typed transcript trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptReport {
    /// Pinned target.
    pub target: String,
    /// Pinned source identity.
    pub upstream_commit: String,
    /// Execution identity.
    pub case_id: String,
    /// Canonical trace digest, absent only for malformed traces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_digest: Option<String>,
    /// Final verdict.
    pub verdict: TranscriptVerdict,
    /// Generic invariant findings.
    pub findings: Vec<TranscriptFinding>,
}

/// Evaluate an ordered transcript trace against its pinned contract.
pub fn evaluate_transcript(
    contract: &TranscriptContract,
    trace: &TranscriptTrace,
) -> TranscriptReport {
    if let Err(error) = validate_artifacts(contract, trace) {
        return report(
            trace,
            None,
            TranscriptVerdict::Unsupported,
            vec![finding(
                FindingCode::InvalidTranscriptContract,
                Severity::High,
                format!("invalid transcript artifact: {error}"),
                vec![],
            )],
        );
    }

    let trace_digest = match trace.digest() {
        Ok(digest) => Some(digest),
        Err(error) => {
            return report(
                trace,
                None,
                TranscriptVerdict::Unsupported,
                vec![finding(
                    FindingCode::InvalidTranscriptContract,
                    Severity::High,
                    format!("transcript trace could not be content addressed: {error}"),
                    vec![],
                )],
            );
        }
    };
    let requirements: BTreeMap<(DrawKind, String), &DrawRequirement> = contract
        .draws
        .iter()
        .map(|requirement| ((requirement.kind, requirement.label.clone()), requirement))
        .collect();
    let validation_requirements: BTreeMap<BoundaryPath, BTreeSet<ValidationRule>> = contract
        .path_validations
        .iter()
        .map(|requirement| {
            (
                requirement.path.clone(),
                requirement.rules.iter().cloned().collect(),
            )
        })
        .collect();
    let absorption_requirements: BTreeMap<String, &AbsorptionRequirement> = contract
        .absorptions
        .iter()
        .map(|requirement| (requirement.label.clone(), requirement))
        .collect();
    let separator_requirements: BTreeMap<String, &DomainSeparatorRequirement> = contract
        .domain_separators
        .iter()
        .map(|requirement| (requirement.label.clone(), requirement))
        .collect();
    let pow_requirements: BTreeMap<String, &PowRequirement> = contract
        .pow_verifications
        .iter()
        .map(|requirement| (requirement.label.clone(), requirement))
        .collect();
    let pow_by_absorption: BTreeMap<String, &PowRequirement> = contract
        .pow_verifications
        .iter()
        .filter_map(|requirement| {
            requirement
                .absorbed_as
                .as_ref()
                .map(|label| (label.clone(), requirement))
        })
        .collect();

    let mut passed_validations: BTreeMap<BoundaryPath, BTreeMap<ValidationRule, String>> =
        BTreeMap::new();
    let mut absorptions: BTreeMap<String, usize> = BTreeMap::new();
    let mut separators: BTreeMap<String, usize> = BTreeMap::new();
    let mut observed_draws = BTreeSet::new();
    let mut accepted_pow: BTreeMap<String, String> = BTreeMap::new();
    let mut pow_verifications: BTreeMap<String, usize> = BTreeMap::new();
    let observed_schedule: Vec<TranscriptStep> = trace.events.iter().map(event_step).collect();
    let mut findings = vec![];
    if observed_schedule != contract.schedule {
        let first_mismatch = contract
            .schedule
            .iter()
            .zip(&observed_schedule)
            .position(|(expected, observed)| expected != observed)
            .unwrap_or_else(|| contract.schedule.len().min(observed_schedule.len()));
        findings.push(finding(
            FindingCode::TranscriptScheduleMismatch,
            Severity::High,
            format!(
                "transcript event schedule differs at index {first_mismatch}: expected {} events, observed {}",
                contract.schedule.len(),
                observed_schedule.len()
            ),
            vec![first_mismatch.to_string()],
        ));
    }

    for (index, event) in trace.events.iter().enumerate() {
        match event {
            TranscriptEvent::DomainSeparator { label } => {
                if !separator_requirements.contains_key(label) {
                    findings.push(finding(
                        FindingCode::TranscriptEventInventoryMismatch,
                        Severity::High,
                        format!("event {index} uses unmodeled domain separator `{label}`"),
                        vec![label.clone()],
                    ));
                }
                *separators.entry(label.clone()).or_default() += 1;
            }
            TranscriptEvent::Validate {
                path,
                rule,
                value_digest,
                outcome,
            } => {
                let passed = passed_validations.entry(path.clone()).or_default();
                match outcome {
                    ValidationOutcome::Passed => {
                        passed.insert(rule.clone(), value_digest.clone());
                    }
                    ValidationOutcome::Failed => {
                        passed.remove(rule);
                    }
                }
            }
            TranscriptEvent::Absorb {
                label,
                path,
                source,
                kind,
                value_digest,
            } => {
                evaluate_absorption_contract(
                    index,
                    label,
                    path.as_ref(),
                    *source,
                    kind,
                    &absorption_requirements,
                    &mut findings,
                );
                if *source == TranscriptSource::ProverControlled
                    && let Some(path) = path
                {
                    evaluate_prover_absorption(
                        index,
                        label,
                        path,
                        &validation_requirements,
                        &passed_validations,
                        value_digest,
                        &mut findings,
                    );
                }
                if let Some(pow_requirement) = pow_by_absorption.get(label) {
                    evaluate_pow_nonce_absorption(
                        index,
                        label,
                        path.as_ref(),
                        value_digest,
                        pow_requirement,
                        &accepted_pow,
                        &mut findings,
                    );
                }
                *absorptions.entry(label.clone()).or_default() += 1;
            }
            TranscriptEvent::VerifyPow {
                label,
                bits,
                nonce_path,
                nonce_bytes,
                outcome,
            } => {
                *pow_verifications.entry(label.clone()).or_default() += 1;
                let nonce_digest = sha256_hex(nonce_bytes);
                if evaluate_pow_contract(
                    index,
                    label,
                    *bits,
                    nonce_path,
                    nonce_bytes.len(),
                    &nonce_digest,
                    nonce_bytes.iter().all(|byte| *byte == 0),
                    *outcome,
                    &pow_requirements,
                    &validation_requirements,
                    &passed_validations,
                    &mut findings,
                ) {
                    accepted_pow.insert(label.clone(), nonce_digest);
                }
            }
            TranscriptEvent::DrawChallenge { label, .. } => evaluate_draw(
                index,
                DrawKind::Challenge,
                label,
                &requirements,
                &absorption_requirements,
                &separator_requirements,
                &absorptions,
                &separators,
                &accepted_pow,
                None,
                &mut observed_draws,
                &mut findings,
            ),
            TranscriptEvent::DrawQueries {
                label,
                domain_size,
                positions,
                ..
            } => {
                evaluate_draw(
                    index,
                    DrawKind::Queries,
                    label,
                    &requirements,
                    &absorption_requirements,
                    &separator_requirements,
                    &absorptions,
                    &separators,
                    &accepted_pow,
                    Some(QueryShape {
                        count: positions.len(),
                        domain_size: *domain_size,
                    }),
                    &mut observed_draws,
                    &mut findings,
                );
            }
        }
    }

    for key in requirements.keys() {
        if !observed_draws.contains(key) {
            findings.push(finding(
                FindingCode::MissingTranscriptDraw,
                Severity::High,
                format!("required {:?} draw `{}` was not recorded", key.0, key.1),
                vec![key.1.clone()],
            ));
        }
    }

    for (label, requirement) in &absorption_requirements {
        let observed = absorptions.get(label).copied().unwrap_or_default();
        if observed != requirement.expected_count {
            findings.push(finding(
                FindingCode::TranscriptAbsorptionCardinalityMismatch,
                Severity::High,
                format!(
                    "absorption `{label}` occurred {observed} times; expected {}",
                    requirement.expected_count
                ),
                vec![label.clone()],
            ));
        }
    }
    for (label, requirement) in &separator_requirements {
        let observed = separators.get(label).copied().unwrap_or_default();
        if observed != requirement.expected_count {
            findings.push(finding(
                FindingCode::TranscriptEventInventoryMismatch,
                Severity::High,
                format!(
                    "domain separator `{label}` occurred {observed} times; expected {}",
                    requirement.expected_count
                ),
                vec![label.clone()],
            ));
        }
    }
    for label in pow_requirements.keys() {
        let observed = pow_verifications.get(label).copied().unwrap_or_default();
        if observed != 1 {
            findings.push(finding(
                FindingCode::TranscriptEventInventoryMismatch,
                Severity::High,
                format!(
                    "proof-of-work verification `{label}` occurred {observed} times; expected 1"
                ),
                vec![label.clone()],
            ));
        }
    }

    let verdict = if findings.is_empty() {
        TranscriptVerdict::Accepted
    } else {
        TranscriptVerdict::Counterexample
    };
    report(trace, trace_digest, verdict, findings)
}

fn evaluate_absorption_contract(
    index: usize,
    label: &str,
    path: Option<&BoundaryPath>,
    source: TranscriptSource,
    kind: &AbsorbKind,
    requirements: &BTreeMap<String, &AbsorptionRequirement>,
    findings: &mut Vec<Finding>,
) {
    let Some(requirement) = requirements.get(label) else {
        findings.push(finding(
            FindingCode::UnmodeledTranscriptAbsorption,
            Severity::High,
            format!("event {index} absorbs unmodeled value `{label}`"),
            vec![label.to_owned()],
        ));
        return;
    };
    if requirement.path.as_ref() != path
        || requirement.source != source
        || &requirement.kind != kind
    {
        findings.push(finding(
            FindingCode::TranscriptAbsorptionContractMismatch,
            Severity::High,
            format!("event {index} absorption `{label}` does not match its path, source, or kind"),
            vec![label.to_owned()],
        ));
    }
}

fn validate_artifacts(
    contract: &TranscriptContract,
    trace: &TranscriptTrace,
) -> Result<(), TranscriptContractError> {
    contract.validate()?;
    trace.validate()?;
    if contract.target != trace.target {
        return Err(TranscriptContractError::TargetMismatch {
            expected: contract.target.clone(),
            observed: trace.target.clone(),
        });
    }
    if contract.upstream_commit != trace.upstream_commit {
        return Err(TranscriptContractError::UpstreamCommitMismatch {
            expected: contract.upstream_commit.clone(),
            observed: trace.upstream_commit.clone(),
        });
    }
    Ok(())
}

fn event_step(event: &TranscriptEvent) -> TranscriptStep {
    match event {
        TranscriptEvent::DomainSeparator { label } => TranscriptStep::DomainSeparator {
            label: label.clone(),
        },
        TranscriptEvent::Validate { path, rule, .. } => TranscriptStep::Validate {
            path: path.clone(),
            rule: rule.clone(),
        },
        TranscriptEvent::Absorb { label, .. } => TranscriptStep::Absorb {
            label: label.clone(),
        },
        TranscriptEvent::VerifyPow { label, .. } => TranscriptStep::VerifyPow {
            label: label.clone(),
        },
        TranscriptEvent::DrawChallenge { label, .. } => TranscriptStep::DrawChallenge {
            label: label.clone(),
        },
        TranscriptEvent::DrawQueries { label, .. } => TranscriptStep::DrawQueries {
            label: label.clone(),
        },
    }
}

fn evaluate_prover_absorption(
    index: usize,
    label: &str,
    path: &BoundaryPath,
    requirements: &BTreeMap<BoundaryPath, BTreeSet<ValidationRule>>,
    passed: &BTreeMap<BoundaryPath, BTreeMap<ValidationRule, String>>,
    absorbed_digest: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(required) = requirements.get(path) else {
        findings.push(finding(
            FindingCode::UnmodeledProverTranscriptInput,
            Severity::High,
            format!(
                "event {index} absorbs prover-controlled `{label}` without a validation contract"
            ),
            vec![format_path(path), label.to_owned()],
        ));
        return;
    };
    let missing: Vec<String> = required
        .iter()
        .filter(|rule| {
            passed
                .get(path)
                .and_then(|rules| rules.get(*rule))
                .is_none_or(|validated_digest| validated_digest != absorbed_digest)
        })
        .map(|rule| format!("{rule:?}"))
        .collect();
    if !missing.is_empty() {
        findings.push(finding(
            FindingCode::ProverDataAbsorbedBeforeValidation,
            Severity::High,
            format!(
                "event {index} absorbs prover-controlled `{label}` before validations: {}",
                missing.join(", ")
            ),
            vec![format_path(path), label.to_owned()],
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_pow_contract(
    index: usize,
    label: &str,
    bits: u32,
    nonce_path: &BoundaryPath,
    nonce_byte_len: usize,
    nonce_digest: &str,
    nonce_is_zero: bool,
    outcome: ValidationOutcome,
    requirements: &BTreeMap<String, &PowRequirement>,
    validation_requirements: &BTreeMap<BoundaryPath, BTreeSet<ValidationRule>>,
    passed_validations: &BTreeMap<BoundaryPath, BTreeMap<ValidationRule, String>>,
    findings: &mut Vec<Finding>,
) -> bool {
    let Some(requirement) = requirements.get(label) else {
        findings.push(finding(
            FindingCode::TranscriptPowContractMismatch,
            Severity::High,
            format!("event {index} verifies unmodeled proof-of-work `{label}`"),
            vec![label.to_owned()],
        ));
        return false;
    };
    if bits != requirement.bits
        || nonce_path != &requirement.nonce_path
        || nonce_byte_len != requirement.nonce_byte_len
    {
        findings.push(finding(
            FindingCode::TranscriptPowContractMismatch,
            Severity::High,
            format!(
                "event {index} proof-of-work `{label}` differs from its bits, nonce path, or nonce length contract"
            ),
            vec![label.to_owned(), format_path(nonce_path)],
        ));
        return false;
    }
    if bits == 0 {
        let violation = match requirement.zero_nonce_policy {
            ZeroPowNoncePolicy::DisallowZeroPow => Some("zero-work profile is disallowed"),
            ZeroPowNoncePolicy::RequireZeroNonce if !nonce_is_zero => {
                Some("zero-work profile requires the canonical zero nonce")
            }
            ZeroPowNoncePolicy::RequireZeroNonce | ZeroPowNoncePolicy::AllowArbitraryNonce => None,
        };
        if let Some(message) = violation {
            findings.push(finding(
                FindingCode::ZeroPowNoncePolicyViolation,
                Severity::High,
                format!("event {index}: {message}"),
                vec![label.to_owned(), "pow_nonce".to_owned()],
            ));
            return false;
        }
    }
    let Some(required_rules) = validation_requirements.get(nonce_path) else {
        findings.push(finding(
            FindingCode::TranscriptPowContractMismatch,
            Severity::High,
            format!("event {index} proof-of-work `{label}` has no nonce validation contract"),
            vec![label.to_owned(), format_path(nonce_path)],
        ));
        return false;
    };
    let exact_value_was_validated = required_rules.iter().all(|rule| {
        passed_validations
            .get(nonce_path)
            .and_then(|rules| rules.get(rule))
            .is_some_and(|digest| digest == nonce_digest)
    });
    if !exact_value_was_validated {
        findings.push(finding(
            FindingCode::ProverDataUsedBeforeValidation,
            Severity::High,
            format!(
                "event {index} verifies proof-of-work `{label}` over a nonce that did not pass every declared validation"
            ),
            vec![label.to_owned(), format_path(nonce_path)],
        ));
        return false;
    }
    if outcome == ValidationOutcome::Failed {
        findings.push(finding(
            FindingCode::TranscriptPowVerificationFailed,
            Severity::High,
            format!("event {index} proof-of-work verification `{label}` failed"),
            vec![label.to_owned(), format_path(nonce_path)],
        ));
        return false;
    }
    true
}

fn evaluate_pow_nonce_absorption(
    index: usize,
    absorption_label: &str,
    path: Option<&BoundaryPath>,
    value_digest: &str,
    requirement: &PowRequirement,
    accepted_pow: &BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
) {
    let verified_digest = accepted_pow.get(&requirement.label);
    if path != Some(&requirement.nonce_path)
        || verified_digest.map(String::as_str) != Some(value_digest)
    {
        findings.push(finding(
            FindingCode::TranscriptPowNonceBindingMismatch,
            Severity::High,
            format!(
                "event {index} absorbs nonce `{absorption_label}` without a matching accepted proof-of-work value"
            ),
            vec![requirement.label.clone(), absorption_label.to_owned()],
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_draw(
    index: usize,
    kind: DrawKind,
    label: &str,
    requirements: &BTreeMap<(DrawKind, String), &DrawRequirement>,
    absorption_requirements: &BTreeMap<String, &AbsorptionRequirement>,
    separator_requirements: &BTreeMap<String, &DomainSeparatorRequirement>,
    absorptions: &BTreeMap<String, usize>,
    separators: &BTreeMap<String, usize>,
    accepted_pow: &BTreeMap<String, String>,
    observed_query_shape: Option<QueryShape>,
    observed_draws: &mut BTreeSet<(DrawKind, String)>,
    findings: &mut Vec<Finding>,
) {
    let key = (kind, label.to_owned());
    if !observed_draws.insert(key.clone()) {
        findings.push(finding(
            FindingCode::DuplicateTranscriptDraw,
            Severity::High,
            format!("event {index} repeats {:?} draw `{label}`", kind),
            vec![label.to_owned()],
        ));
    }

    let Some(requirement) = requirements.get(&key) else {
        findings.push(finding(
            FindingCode::UnmodeledTranscriptDraw,
            Severity::High,
            format!("event {index} performs unmodeled {:?} draw `{label}`", kind),
            vec![label.to_owned()],
        ));
        return;
    };

    let missing_absorptions: Vec<String> = requirement
        .required_absorptions
        .iter()
        .filter(|required| {
            let expected = absorption_requirements
                .get(*required)
                .map(|contract| contract.expected_count)
                .unwrap_or(usize::MAX);
            absorptions.get(*required).copied().unwrap_or_default() < expected
        })
        .cloned()
        .collect();
    if !missing_absorptions.is_empty() {
        findings.push(finding(
            FindingCode::MissingTranscriptPrerequisite,
            Severity::High,
            format!(
                "event {index} draws `{label}` before absorptions: {}",
                missing_absorptions.join(", ")
            ),
            missing_absorptions,
        ));
    }
    if let Some(separator) = &requirement.required_domain_separator {
        let expected = separator_requirements
            .get(separator)
            .map(|contract| contract.expected_count)
            .unwrap_or(usize::MAX);
        if separators.get(separator).copied().unwrap_or_default() < expected {
            findings.push(finding(
                FindingCode::MissingTranscriptPrerequisite,
                Severity::High,
                format!("event {index} draws `{label}` before separator `{separator}`"),
                vec![separator.clone(), label.to_owned()],
            ));
        }
    }
    if let Some(pow) = &requirement.required_pow
        && !accepted_pow.contains_key(pow)
    {
        findings.push(finding(
            FindingCode::MissingTranscriptPrerequisite,
            Severity::High,
            format!("event {index} draws `{label}` before accepted proof-of-work `{pow}`"),
            vec![pow.clone(), label.to_owned()],
        ));
    }
    if requirement.query_shape != observed_query_shape {
        findings.push(finding(
            FindingCode::TranscriptDrawContractMismatch,
            Severity::High,
            format!("event {index} draw `{label}` differs from its exact query-shape contract"),
            vec![label.to_owned()],
        ));
    }
}

fn report(
    trace: &TranscriptTrace,
    trace_digest: Option<String>,
    verdict: TranscriptVerdict,
    findings: Vec<Finding>,
) -> TranscriptReport {
    TranscriptReport {
        target: trace.target.clone(),
        upstream_commit: trace.upstream_commit.clone(),
        case_id: trace.case_id.clone(),
        trace_digest,
        verdict,
        findings,
    }
}

fn finding(
    code: FindingCode,
    severity: Severity,
    message: String,
    related: Vec<String>,
) -> Finding {
    Finding {
        code,
        severity,
        message,
        related,
    }
}

fn format_path(path: &BoundaryPath) -> String {
    let indices = path
        .indices
        .iter()
        .map(|index| format!("[{index}]"))
        .collect::<String>();
    format!("{}{indices}", path.field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AbsorbKind, DomainSeparatorRequirement, PathValidationRequirement, PowRequirement,
        QueryShape, TranscriptEvent, TranscriptInventory, TranscriptSource, TranscriptStep,
        ZeroPowNoncePolicy,
    };

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn proof_path() -> BoundaryPath {
        BoundaryPath::new("sampled_values", vec![1, 0])
    }

    fn contract(policy: ZeroPowNoncePolicy) -> TranscriptContract {
        TranscriptContract::new(
            "tiny-proof",
            "0123456789abcdef",
            TranscriptInventory {
                schedule: vec![
                    TranscriptStep::DomainSeparator {
                        label: "tiny-v1".to_owned(),
                    },
                    TranscriptStep::Validate {
                        path: proof_path(),
                        rule: ValidationRule::ExactShape,
                    },
                    TranscriptStep::Validate {
                        path: proof_path(),
                        rule: ValidationRule::CanonicalEncoding,
                    },
                    TranscriptStep::Absorb {
                        label: "fri_commitment".to_owned(),
                    },
                    TranscriptStep::Validate {
                        path: BoundaryPath::new("pow_nonce", vec![]),
                        rule: ValidationRule::CanonicalEncoding,
                    },
                    TranscriptStep::VerifyPow {
                        label: "fri_pow".to_owned(),
                    },
                    TranscriptStep::Absorb {
                        label: "pow_nonce".to_owned(),
                    },
                    TranscriptStep::DrawQueries {
                        label: "fri_queries".to_owned(),
                    },
                ],
                domain_separators: vec![DomainSeparatorRequirement {
                    label: "tiny-v1".to_owned(),
                    expected_count: 1,
                }],
                absorptions: vec![
                    AbsorptionRequirement {
                        label: "fri_commitment".to_owned(),
                        path: Some(proof_path()),
                        source: TranscriptSource::ProverControlled,
                        kind: AbsorbKind::Commitment,
                        expected_count: 1,
                    },
                    AbsorptionRequirement {
                        label: "pow_nonce".to_owned(),
                        path: Some(BoundaryPath::new("pow_nonce", vec![])),
                        source: TranscriptSource::ProverControlled,
                        kind: AbsorbKind::Nonce,
                        expected_count: 1,
                    },
                ],
                path_validations: vec![
                    PathValidationRequirement {
                        path: proof_path(),
                        rules: vec![
                            ValidationRule::ExactShape,
                            ValidationRule::CanonicalEncoding,
                        ],
                    },
                    PathValidationRequirement {
                        path: BoundaryPath::new("pow_nonce", vec![]),
                        rules: vec![ValidationRule::CanonicalEncoding],
                    },
                ],
                draws: vec![DrawRequirement {
                    kind: DrawKind::Queries,
                    label: "fri_queries".to_owned(),
                    required_absorptions: vec!["fri_commitment".to_owned(), "pow_nonce".to_owned()],
                    required_domain_separator: Some("tiny-v1".to_owned()),
                    required_pow: Some("fri_pow".to_owned()),
                    query_shape: Some(QueryShape {
                        count: 8,
                        domain_size: 1 << 16,
                    }),
                }],
                pow_verifications: vec![PowRequirement {
                    label: "fri_pow".to_owned(),
                    bits: if policy == ZeroPowNoncePolicy::DisallowZeroPow {
                        20
                    } else {
                        0
                    },
                    nonce_path: BoundaryPath::new("pow_nonce", vec![]),
                    nonce_byte_len: 8,
                    absorbed_as: Some("pow_nonce".to_owned()),
                    zero_nonce_policy: policy,
                }],
            },
        )
    }

    fn valid_trace(policy: ZeroPowNoncePolicy) -> TranscriptTrace {
        let nonce_bytes = if policy == ZeroPowNoncePolicy::AllowArbitraryNonce {
            vec![1, 0, 0, 0, 0, 0, 0, 0]
        } else {
            vec![0; 8]
        };
        let nonce_digest = sha256_hex(&nonce_bytes);
        TranscriptTrace {
            target: "tiny-proof".to_owned(),
            upstream_commit: "0123456789abcdef".to_owned(),
            case_id: "case-1".to_owned(),
            events: vec![
                TranscriptEvent::DomainSeparator {
                    label: "tiny-v1".to_owned(),
                },
                TranscriptEvent::Validate {
                    path: proof_path(),
                    rule: ValidationRule::ExactShape,
                    value_digest: DIGEST.to_owned(),
                    outcome: ValidationOutcome::Passed,
                },
                TranscriptEvent::Validate {
                    path: proof_path(),
                    rule: ValidationRule::CanonicalEncoding,
                    value_digest: DIGEST.to_owned(),
                    outcome: ValidationOutcome::Passed,
                },
                TranscriptEvent::Absorb {
                    label: "fri_commitment".to_owned(),
                    path: Some(proof_path()),
                    source: TranscriptSource::ProverControlled,
                    kind: AbsorbKind::Commitment,
                    value_digest: DIGEST.to_owned(),
                },
                TranscriptEvent::Validate {
                    path: BoundaryPath::new("pow_nonce", vec![]),
                    rule: ValidationRule::CanonicalEncoding,
                    value_digest: nonce_digest.clone(),
                    outcome: ValidationOutcome::Passed,
                },
                TranscriptEvent::VerifyPow {
                    label: "fri_pow".to_owned(),
                    bits: if policy == ZeroPowNoncePolicy::DisallowZeroPow {
                        20
                    } else {
                        0
                    },
                    nonce_path: BoundaryPath::new("pow_nonce", vec![]),
                    nonce_bytes,
                    outcome: ValidationOutcome::Passed,
                },
                TranscriptEvent::Absorb {
                    label: "pow_nonce".to_owned(),
                    path: Some(BoundaryPath::new("pow_nonce", vec![])),
                    source: TranscriptSource::ProverControlled,
                    kind: AbsorbKind::Nonce,
                    value_digest: nonce_digest,
                },
                TranscriptEvent::DrawQueries {
                    label: "fri_queries".to_owned(),
                    domain_size: 1 << 16,
                    positions: (0..8).collect(),
                },
            ],
        }
    }

    #[test]
    fn exact_validated_trace_is_green() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let report = evaluate_transcript(&contract(policy), &valid_trace(policy));
        assert_eq!(report.verdict, TranscriptVerdict::Accepted);
        assert!(report.verdict.is_green());
        assert!(report.trace_digest.is_some());
    }

    #[test]
    fn unreferenced_failed_pow_is_never_green() {
        let policy = ZeroPowNoncePolicy::DisallowZeroPow;
        let mut contract = contract(policy);
        contract.pow_verifications[0].absorbed_as = None;
        contract.draws[0].required_pow = None;
        let mut trace = valid_trace(policy);
        let TranscriptEvent::VerifyPow { outcome, .. } = &mut trace.events[5] else {
            panic!("fixture must contain its PoW event at index 5");
        };
        *outcome = ValidationOutcome::Failed;

        let report = evaluate_transcript(&contract, &trace);
        assert_eq!(report.verdict, TranscriptVerdict::Counterexample);
        assert!(report.findings.iter().any(|finding| {
            finding.code == TranscriptFindingCode::TranscriptPowVerificationFailed
        }));
    }

    #[test]
    fn absorption_before_validation_is_a_counterexample() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut trace = valid_trace(policy);
        trace.events.swap(2, 3);
        let report = evaluate_transcript(&contract(policy), &trace);
        assert_eq!(report.verdict, TranscriptVerdict::Counterexample);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptScheduleMismatch })
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::ProverDataAbsorbedBeforeValidation })
        );

        let mut different_value = valid_trace(policy);
        if let TranscriptEvent::Absorb { value_digest, .. } = &mut different_value.events[3] {
            *value_digest = "b".repeat(64);
        }
        let report = evaluate_transcript(&contract(policy), &different_value);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::ProverDataAbsorbedBeforeValidation })
        );
    }

    #[test]
    fn unmodeled_prover_input_never_goes_green() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut trace = valid_trace(policy);
        if let TranscriptEvent::Absorb { path, .. } = &mut trace.events[3] {
            *path = Some(BoundaryPath::new("another_field", vec![]));
        }
        let report = evaluate_transcript(&contract(policy), &trace);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::UnmodeledProverTranscriptInput })
        );
    }

    #[test]
    fn missing_commitment_separator_and_work_are_reported() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut trace = valid_trace(policy);
        trace.events = vec![trace.events.pop().expect("query event")];
        let report = evaluate_transcript(&contract(policy), &trace);
        let missing = report
            .findings
            .iter()
            .filter(|finding| finding.code == FindingCode::MissingTranscriptPrerequisite)
            .count();
        assert_eq!(missing, 3);
    }

    #[test]
    fn every_draw_must_be_modeled_and_observed_once() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut unmodeled = valid_trace(policy);
        if let TranscriptEvent::DrawQueries { label, .. } = &mut unmodeled.events[7] {
            *label = "another_draw".to_owned();
        }
        let report = evaluate_transcript(&contract(policy), &unmodeled);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnmodeledTranscriptDraw)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::MissingTranscriptDraw)
        );

        let mut duplicate = valid_trace(policy);
        duplicate.events.push(duplicate.events[7].clone());
        let report = evaluate_transcript(&contract(policy), &duplicate);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::DuplicateTranscriptDraw)
        );
    }

    #[test]
    fn absorption_inventory_is_exact() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut duplicate = valid_trace(policy);
        duplicate.events.insert(4, duplicate.events[3].clone());
        let report = evaluate_transcript(&contract(policy), &duplicate);
        assert!(report.findings.iter().any(|finding| {
            finding.code == FindingCode::TranscriptAbsorptionCardinalityMismatch
        }));

        let mut unmodeled = valid_trace(policy);
        if let TranscriptEvent::Absorb { label, .. } = &mut unmodeled.events[3] {
            *label = "unexpected_commitment".to_owned();
        }
        let report = evaluate_transcript(&contract(policy), &unmodeled);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnmodeledTranscriptAbsorption)
        );

        let mut wrong_kind = valid_trace(policy);
        if let TranscriptEvent::Absorb { kind, .. } = &mut wrong_kind.events[3] {
            *kind = AbsorbKind::Bytes;
        }
        let report = evaluate_transcript(&contract(policy), &wrong_kind);
        assert!(
            report.findings.iter().any(|finding| {
                finding.code == FindingCode::TranscriptAbsorptionContractMismatch
            })
        );
    }

    #[test]
    fn separator_and_pow_inventory_is_exact() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut extra_separator = valid_trace(policy);
        extra_separator.events.insert(
            1,
            TranscriptEvent::DomainSeparator {
                label: "tiny-v1".to_owned(),
            },
        );
        let report = evaluate_transcript(&contract(policy), &extra_separator);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptEventInventoryMismatch })
        );

        let mut extra_pow = valid_trace(policy);
        extra_pow.events.insert(6, extra_pow.events[5].clone());
        let report = evaluate_transcript(&contract(policy), &extra_pow);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptEventInventoryMismatch })
        );
    }

    #[test]
    fn vacuous_contract_is_unsupported() {
        let empty = TranscriptContract::new(
            "tiny-proof",
            "0123456789abcdef",
            TranscriptInventory {
                schedule: vec![],
                domain_separators: vec![],
                absorptions: vec![],
                path_validations: vec![],
                draws: vec![],
                pow_verifications: vec![],
            },
        );
        let report =
            evaluate_transcript(&empty, &valid_trace(ZeroPowNoncePolicy::RequireZeroNonce));
        assert_eq!(report.verdict, TranscriptVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            FindingCode::InvalidTranscriptContract
        );
    }

    #[test]
    fn zero_pow_behavior_requires_explicit_policy() {
        let mut trace = valid_trace(ZeroPowNoncePolicy::RequireZeroNonce);
        if let TranscriptEvent::VerifyPow { nonce_bytes, .. } = &mut trace.events[5] {
            nonce_bytes[0] = 1;
        }
        let report = evaluate_transcript(&contract(ZeroPowNoncePolicy::RequireZeroNonce), &trace);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::ZeroPowNoncePolicyViolation })
        );

        let allowed = evaluate_transcript(
            &contract(ZeroPowNoncePolicy::AllowArbitraryNonce),
            &valid_trace(ZeroPowNoncePolicy::AllowArbitraryNonce),
        );
        assert_eq!(allowed.verdict, TranscriptVerdict::Accepted);
    }

    #[test]
    fn query_shape_is_exact() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut trace = valid_trace(policy);
        if let TranscriptEvent::DrawQueries { positions, .. } = &mut trace.events[7] {
            positions.pop();
        }
        let report = evaluate_transcript(&contract(policy), &trace);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptDrawContractMismatch })
        );
    }

    #[test]
    fn pow_configuration_and_absorbed_nonce_are_bound() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut wrong_bits = valid_trace(policy);
        if let TranscriptEvent::VerifyPow { bits, .. } = &mut wrong_bits.events[5] {
            *bits = 1;
        }
        let report = evaluate_transcript(&contract(policy), &wrong_bits);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptPowContractMismatch })
        );

        let mut different_nonce = valid_trace(policy);
        if let TranscriptEvent::VerifyPow { nonce_bytes, .. } = &mut different_nonce.events[5] {
            nonce_bytes[0] = 1;
        }
        let report = evaluate_transcript(&contract(policy), &different_nonce);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.code == FindingCode::TranscriptPowNonceBindingMismatch })
        );
    }

    #[test]
    fn impossible_contract_schedule_is_unsupported() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut invalid = contract(policy);
        invalid.schedule.swap(5, 6);
        let report = evaluate_transcript(&invalid, &valid_trace(policy));
        assert_eq!(report.verdict, TranscriptVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            FindingCode::InvalidTranscriptContract
        );
    }

    #[test]
    fn mismatched_source_identity_is_unsupported() {
        let policy = ZeroPowNoncePolicy::RequireZeroNonce;
        let mut trace = valid_trace(policy);
        trace.upstream_commit = "wrong".to_owned();
        let report = evaluate_transcript(&contract(policy), &trace);
        assert_eq!(report.verdict, TranscriptVerdict::Unsupported);
        assert_eq!(
            report.findings[0].code,
            FindingCode::InvalidTranscriptContract
        );
    }
}
