//! Typed Fiat--Shamir transcript contracts and traces.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::BoundaryPath;

/// Stable schema identifier for transcript contracts.
pub const TRANSCRIPT_SCHEMA_ID: &str = "airlock.transcript-contract";

/// Serialized transcript-contract version.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1.0";

/// Source of data entering the Fiat--Shamir transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptSource {
    /// Supplied by the prover or read from the proof.
    ProverControlled,
    /// Derived by the verifier from already validated state.
    VerifierDerived,
    /// Public statement data.
    Public,
}

/// Semantic class of absorbed transcript data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AbsorbKind {
    /// Commitment root or digest.
    Commitment,
    /// Base- or extension-field elements.
    FieldElements,
    /// Arbitrary byte string.
    Bytes,
    /// Proof-of-work nonce.
    Nonce,
    /// Public statement input.
    PublicInput,
    /// Adapter-specific class with a stable nonempty label.
    Other(String),
}

/// Validation rule that can authorize transcript absorption.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ValidationRule {
    /// Nested proof shape and cardinality.
    ExactShape,
    /// Canonical serialization or field encoding.
    CanonicalEncoding,
    /// Membership in the expected field or domain.
    DomainMembership,
    /// Semantic role expected at this transcript position.
    SemanticRole,
    /// Adapter-specific validation with a stable nonempty label.
    Other(String),
}

/// Result of one verifier-side validation event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ValidationOutcome {
    /// Validation succeeded.
    Passed,
    /// Validation failed.
    Failed,
}

/// How a zero-work profile handles its nonce field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ZeroPowNoncePolicy {
    /// A zero-work profile is not permitted for this target.
    DisallowZeroPow,
    /// The nonce must use the canonical zero value when work is disabled.
    RequireZeroNonce,
    /// An arbitrary nonce is an explicit protocol choice, not an implicit default.
    AllowArbitraryNonce,
}

/// Transcript draw class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DrawKind {
    /// Fiat--Shamir scalar or extension-field challenge.
    Challenge,
    /// FRI or decommitment query positions.
    Queries,
}

/// Validations required before one prover-controlled proof path is absorbed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathValidationRequirement {
    /// Proof path whose value enters the transcript.
    pub path: BoundaryPath,
    /// Rules that must all pass before absorption.
    pub rules: Vec<ValidationRule>,
}

/// Exact contract for one labeled transcript absorption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsorptionRequirement {
    /// Stable absorption label.
    pub label: String,
    /// Proof path for proof-derived values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<BoundaryPath>,
    /// Source trust class.
    pub source: TranscriptSource,
    /// Semantic input class.
    pub kind: AbsorbKind,
    /// Exact number of times this labeled absorption must occur.
    pub expected_count: usize,
}

/// Exact count for one transcript domain separator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainSeparatorRequirement {
    /// Stable separator label.
    pub label: String,
    /// Exact number of times this separator must occur.
    pub expected_count: usize,
}

/// Preconditions for one named transcript draw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrawRequirement {
    /// Draw class.
    pub kind: DrawKind,
    /// Stable draw label.
    pub label: String,
    /// Absorption labels that must already have entered the transcript.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_absorptions: Vec<String>,
    /// Required domain separator, when the protocol declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_domain_separator: Option<String>,
    /// Named proof-of-work check that must have passed before this draw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_pow: Option<String>,
    /// Exact query shape. Required for query draws and forbidden for challenges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_shape: Option<QueryShape>,
}

/// Exact shape of a verifier query draw.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryShape {
    /// Number of query positions drawn.
    pub count: usize,
    /// Size of the queried domain.
    pub domain_size: usize,
}

/// Exact contract for one proof-of-work verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowRequirement {
    /// Stable verification label.
    pub label: String,
    /// Exact work parameter for this target.
    pub bits: u32,
    /// Proof path containing the nonce.
    pub nonce_path: BoundaryPath,
    /// Exact byte length of the nonce representation checked and absorbed.
    pub nonce_byte_len: usize,
    /// Transcript absorption that must use the exact verified nonce, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absorbed_as: Option<String>,
    /// Explicit behavior when `bits` is zero.
    pub zero_nonce_policy: ZeroPowNoncePolicy,
}

/// One exact position in the verifier's transcript schedule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptStep {
    /// Domain separator position.
    DomainSeparator {
        /// Contracted separator label.
        label: String,
    },
    /// Validation position.
    Validate {
        /// Contracted proof path.
        path: BoundaryPath,
        /// Contracted validation rule.
        rule: ValidationRule,
    },
    /// Absorption position.
    Absorb {
        /// Contracted absorption label.
        label: String,
    },
    /// Proof-of-work verification position.
    VerifyPow {
        /// Contracted proof-of-work label.
        label: String,
    },
    /// Challenge draw position.
    DrawChallenge {
        /// Contracted challenge label.
        label: String,
    },
    /// Query draw position.
    DrawQueries {
        /// Contracted query label.
        label: String,
    },
}

/// Complete expected event inventory for one transcript target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptInventory {
    /// Exact event order for the complete target transcript.
    pub schedule: Vec<TranscriptStep>,
    /// Complete inventory of transcript domain separators.
    pub domain_separators: Vec<DomainSeparatorRequirement>,
    /// Complete inventory of allowed transcript absorptions.
    pub absorptions: Vec<AbsorptionRequirement>,
    /// Validation requirements for prover-controlled transcript inputs.
    pub path_validations: Vec<PathValidationRequirement>,
    /// Requirements for every challenge and query draw.
    pub draws: Vec<DrawRequirement>,
    /// Complete inventory of proof-of-work verification events.
    pub pow_verifications: Vec<PowRequirement>,
}

/// Exact transcript policy for one pinned verifier target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptContract {
    /// Schema identity.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Stable target name.
    pub target: String,
    /// Exact source identifier or commit.
    pub upstream_commit: String,
    /// Exact event order for the complete target transcript.
    pub schedule: Vec<TranscriptStep>,
    /// Complete inventory of transcript domain separators.
    pub domain_separators: Vec<DomainSeparatorRequirement>,
    /// Complete inventory of allowed transcript absorptions.
    pub absorptions: Vec<AbsorptionRequirement>,
    /// Validation requirements for prover-controlled transcript inputs.
    pub path_validations: Vec<PathValidationRequirement>,
    /// Requirements for every challenge and query draw.
    pub draws: Vec<DrawRequirement>,
    /// Complete inventory of proof-of-work verification events.
    pub pow_verifications: Vec<PowRequirement>,
}

impl TranscriptContract {
    /// Construct a contract with the current schema identity.
    pub fn new(
        target: impl Into<String>,
        upstream_commit: impl Into<String>,
        inventory: TranscriptInventory,
    ) -> Self {
        Self {
            schema: TRANSCRIPT_SCHEMA_ID.to_owned(),
            schema_version: TRANSCRIPT_SCHEMA_VERSION.to_owned(),
            target: target.into(),
            upstream_commit: upstream_commit.into(),
            schedule: inventory.schedule,
            domain_separators: inventory.domain_separators,
            absorptions: inventory.absorptions,
            path_validations: inventory.path_validations,
            draws: inventory.draws,
            pow_verifications: inventory.pow_verifications,
        }
    }

    /// Validate the transcript contract before applying any oracle.
    pub fn validate(&self) -> Result<(), TranscriptContractError> {
        if self.schema != TRANSCRIPT_SCHEMA_ID || self.schema_version != TRANSCRIPT_SCHEMA_VERSION {
            return Err(TranscriptContractError::WrongSchema {
                schema: self.schema.clone(),
                version: self.schema_version.clone(),
            });
        }
        validate_identity(&self.target, &self.upstream_commit)?;
        if self.absorptions.is_empty() {
            return Err(TranscriptContractError::EmptyAbsorptionContract);
        }
        if self.draws.is_empty() {
            return Err(TranscriptContractError::EmptyDrawContract);
        }

        let mut separators = BTreeSet::new();
        for requirement in &self.domain_separators {
            validate_label(&requirement.label, "domain separator")?;
            if requirement.expected_count == 0 {
                return Err(TranscriptContractError::ZeroDomainSeparatorCount(
                    requirement.label.clone(),
                ));
            }
            if !separators.insert(requirement.label.clone()) {
                return Err(TranscriptContractError::DuplicateLabel {
                    kind: "domain separator",
                    label: requirement.label.clone(),
                });
            }
        }

        let mut paths = BTreeSet::new();
        for requirement in &self.path_validations {
            validate_path(&requirement.path)?;
            if !paths.insert(requirement.path.clone()) {
                return Err(TranscriptContractError::DuplicateValidationPath(
                    requirement.path.clone(),
                ));
            }
            if requirement.rules.is_empty() {
                return Err(TranscriptContractError::EmptyValidationRules(
                    requirement.path.clone(),
                ));
            }
            let mut rules = BTreeSet::new();
            for rule in &requirement.rules {
                validate_rule(rule)?;
                if !rules.insert(rule.clone()) {
                    return Err(TranscriptContractError::DuplicateValidationRule(
                        requirement.path.clone(),
                    ));
                }
            }
        }

        let mut absorptions = BTreeSet::new();
        for requirement in &self.absorptions {
            validate_label(&requirement.label, "absorption")?;
            if !absorptions.insert(requirement.label.clone()) {
                return Err(TranscriptContractError::DuplicateLabel {
                    kind: "absorption",
                    label: requirement.label.clone(),
                });
            }
            if requirement.expected_count == 0 {
                return Err(TranscriptContractError::ZeroAbsorptionCount(
                    requirement.label.clone(),
                ));
            }
            if let Some(path) = &requirement.path {
                validate_path(path)?;
            }
            if requirement.source == TranscriptSource::ProverControlled {
                let Some(path) = &requirement.path else {
                    return Err(TranscriptContractError::MissingProverPath(
                        requirement.label.clone(),
                    ));
                };
                if !paths.contains(path) {
                    return Err(TranscriptContractError::MissingPathValidation(path.clone()));
                }
            }
            if let AbsorbKind::Other(label) = &requirement.kind {
                validate_label(label, "absorption kind")?;
            }
        }
        for path in &paths {
            let used = self.absorptions.iter().any(|requirement| {
                requirement.source == TranscriptSource::ProverControlled
                    && requirement.path.as_ref() == Some(path)
            }) || self
                .pow_verifications
                .iter()
                .any(|requirement| &requirement.nonce_path == path);
            if !used {
                return Err(TranscriptContractError::UnusedPathValidation(path.clone()));
            }
        }

        let absorption_by_label: BTreeMap<&str, &AbsorptionRequirement> = self
            .absorptions
            .iter()
            .map(|requirement| (requirement.label.as_str(), requirement))
            .collect();
        let mut pow_labels = BTreeSet::new();
        let mut pow_absorptions = BTreeSet::new();
        for requirement in &self.pow_verifications {
            validate_label(&requirement.label, "proof-of-work")?;
            validate_path(&requirement.nonce_path)?;
            if requirement.nonce_byte_len == 0 || requirement.nonce_byte_len > 64 {
                return Err(TranscriptContractError::InvalidNonceLength(
                    requirement.nonce_byte_len,
                ));
            }
            if !paths.contains(&requirement.nonce_path) {
                return Err(TranscriptContractError::MissingPathValidation(
                    requirement.nonce_path.clone(),
                ));
            }
            if !pow_labels.insert(requirement.label.clone()) {
                return Err(TranscriptContractError::DuplicatePow(
                    requirement.label.clone(),
                ));
            }
            if requirement.bits > 0
                && requirement.zero_nonce_policy != ZeroPowNoncePolicy::DisallowZeroPow
            {
                return Err(TranscriptContractError::InvalidPowPolicy(
                    requirement.label.clone(),
                ));
            }
            if let Some(absorption_label) = &requirement.absorbed_as {
                if !pow_absorptions.insert(absorption_label.clone()) {
                    return Err(TranscriptContractError::DuplicatePowAbsorption(
                        absorption_label.clone(),
                    ));
                }
                let Some(absorption) = absorption_by_label.get(absorption_label.as_str()) else {
                    return Err(TranscriptContractError::UnknownAbsorption(
                        absorption_label.clone(),
                    ));
                };
                if absorption.source != TranscriptSource::ProverControlled
                    || absorption.kind != AbsorbKind::Nonce
                    || absorption.path.as_ref() != Some(&requirement.nonce_path)
                {
                    return Err(TranscriptContractError::InvalidPowAbsorption {
                        pow: requirement.label.clone(),
                        absorption: absorption_label.clone(),
                    });
                }
            }
        }

        let mut draws = BTreeSet::new();
        for requirement in &self.draws {
            validate_label(&requirement.label, "draw")?;
            if !draws.insert((requirement.kind, requirement.label.clone())) {
                return Err(TranscriptContractError::DuplicateDraw {
                    kind: requirement.kind,
                    label: requirement.label.clone(),
                });
            }
            if let Some(separator) = &requirement.required_domain_separator {
                validate_label(separator, "domain separator")?;
                if !separators.contains(separator) {
                    return Err(TranscriptContractError::UnknownDomainSeparator(
                        separator.clone(),
                    ));
                }
            }
            validate_unique_labels(&requirement.required_absorptions, "absorption")?;
            for label in &requirement.required_absorptions {
                if !absorptions.contains(label) {
                    return Err(TranscriptContractError::UnknownAbsorption(label.clone()));
                }
            }
            if let Some(pow) = &requirement.required_pow {
                validate_label(pow, "proof-of-work")?;
                if !pow_labels.contains(pow) {
                    return Err(TranscriptContractError::UnknownPow(pow.clone()));
                }
            }
            match (requirement.kind, requirement.query_shape) {
                (DrawKind::Queries, Some(shape))
                    if shape.count > 0
                        && shape.domain_size > 0
                        && shape.domain_size.is_power_of_two() => {}
                (DrawKind::Challenge, None) => {}
                _ => {
                    return Err(TranscriptContractError::InvalidDrawShape {
                        kind: requirement.kind,
                        label: requirement.label.clone(),
                    });
                }
            }
        }
        self.validate_schedule()?;
        Ok(())
    }

    fn validate_schedule(&self) -> Result<(), TranscriptContractError> {
        if self.schedule.is_empty() {
            return Err(TranscriptContractError::EmptySchedule);
        }
        let validation_rules: BTreeMap<BoundaryPath, BTreeSet<ValidationRule>> = self
            .path_validations
            .iter()
            .map(|requirement| {
                (
                    requirement.path.clone(),
                    requirement.rules.iter().cloned().collect::<BTreeSet<_>>(),
                )
            })
            .collect();
        let absorption_counts: BTreeMap<String, usize> = self
            .absorptions
            .iter()
            .map(|requirement| (requirement.label.clone(), requirement.expected_count))
            .collect();
        let separator_counts: BTreeMap<String, usize> = self
            .domain_separators
            .iter()
            .map(|requirement| (requirement.label.clone(), requirement.expected_count))
            .collect();
        let draw_keys: BTreeSet<(DrawKind, String)> = self
            .draws
            .iter()
            .map(|requirement| (requirement.kind, requirement.label.clone()))
            .collect();
        let pow_labels: BTreeSet<String> = self
            .pow_verifications
            .iter()
            .map(|requirement| requirement.label.clone())
            .collect();

        let mut observed_absorptions: BTreeMap<String, usize> = BTreeMap::new();
        let mut observed_separators: BTreeMap<String, usize> = BTreeMap::new();
        let mut observed_draws: BTreeMap<(DrawKind, String), usize> = BTreeMap::new();
        let mut observed_pow: BTreeMap<String, usize> = BTreeMap::new();
        let mut observed_validations: BTreeMap<(BoundaryPath, ValidationRule), usize> =
            BTreeMap::new();
        for step in &self.schedule {
            match step {
                TranscriptStep::DomainSeparator { label } => {
                    if !separator_counts.contains_key(label) {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    }
                    *observed_separators.entry(label.clone()).or_default() += 1;
                }
                TranscriptStep::Validate { path, rule } => {
                    let valid = validation_rules
                        .get(path)
                        .is_some_and(|rules| rules.contains(rule));
                    if !valid {
                        return Err(TranscriptContractError::InvalidScheduleReference(format!(
                            "{}:{rule:?}",
                            path.field
                        )));
                    }
                    *observed_validations
                        .entry((path.clone(), rule.clone()))
                        .or_default() += 1;
                }
                TranscriptStep::Absorb { label } => {
                    if !absorption_counts.contains_key(label) {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    }
                    *observed_absorptions.entry(label.clone()).or_default() += 1;
                }
                TranscriptStep::VerifyPow { label } => {
                    if !pow_labels.contains(label) {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    }
                    *observed_pow.entry(label.clone()).or_default() += 1;
                }
                TranscriptStep::DrawChallenge { label } => {
                    let key = (DrawKind::Challenge, label.clone());
                    if !draw_keys.contains(&key) {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    }
                    *observed_draws.entry(key).or_default() += 1;
                }
                TranscriptStep::DrawQueries { label } => {
                    let key = (DrawKind::Queries, label.clone());
                    if !draw_keys.contains(&key) {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    }
                    *observed_draws.entry(key).or_default() += 1;
                }
            }
        }

        let absorption_match = absorption_counts.iter().all(|(label, count)| {
            observed_absorptions.get(label).copied().unwrap_or_default() == *count
        });
        let separator_match = separator_counts.iter().all(|(label, count)| {
            observed_separators.get(label).copied().unwrap_or_default() == *count
        });
        let draws_match = draw_keys
            .iter()
            .all(|key| observed_draws.get(key).copied().unwrap_or_default() == 1);
        let pow_match = pow_labels
            .iter()
            .all(|label| observed_pow.get(label).copied().unwrap_or_default() == 1);
        let validation_match = validation_rules.iter().all(|(path, rules)| {
            rules.iter().all(|rule| {
                observed_validations
                    .get(&(path.clone(), rule.clone()))
                    .copied()
                    .unwrap_or_default()
                    == 1
            })
        });
        if !absorption_match || !separator_match || !draws_match || !pow_match || !validation_match
        {
            return Err(TranscriptContractError::ScheduleInventoryMismatch);
        }
        self.validate_schedule_order()
    }

    fn validate_schedule_order(&self) -> Result<(), TranscriptContractError> {
        let validations: BTreeMap<BoundaryPath, BTreeSet<ValidationRule>> = self
            .path_validations
            .iter()
            .map(|requirement| {
                (
                    requirement.path.clone(),
                    requirement.rules.iter().cloned().collect(),
                )
            })
            .collect();
        let absorptions: BTreeMap<String, &AbsorptionRequirement> = self
            .absorptions
            .iter()
            .map(|requirement| (requirement.label.clone(), requirement))
            .collect();
        let pow: BTreeMap<String, &PowRequirement> = self
            .pow_verifications
            .iter()
            .map(|requirement| (requirement.label.clone(), requirement))
            .collect();
        let pow_by_absorption: BTreeMap<String, &PowRequirement> = self
            .pow_verifications
            .iter()
            .filter_map(|requirement| {
                requirement
                    .absorbed_as
                    .as_ref()
                    .map(|label| (label.clone(), requirement))
            })
            .collect();
        let draws: BTreeMap<(DrawKind, String), &DrawRequirement> = self
            .draws
            .iter()
            .map(|requirement| ((requirement.kind, requirement.label.clone()), requirement))
            .collect();

        let mut seen_validations: BTreeMap<BoundaryPath, BTreeSet<ValidationRule>> =
            BTreeMap::new();
        let mut seen_absorptions: BTreeMap<String, usize> = BTreeMap::new();
        let mut seen_separators: BTreeMap<String, usize> = BTreeMap::new();
        let mut seen_pow = BTreeSet::new();
        for step in &self.schedule {
            match step {
                TranscriptStep::DomainSeparator { label } => {
                    *seen_separators.entry(label.clone()).or_default() += 1;
                }
                TranscriptStep::Validate { path, rule } => {
                    seen_validations
                        .entry(path.clone())
                        .or_default()
                        .insert(rule.clone());
                }
                TranscriptStep::VerifyPow { label } => {
                    let Some(requirement) = pow.get(label) else {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    };
                    if !has_required_validations(
                        &requirement.nonce_path,
                        &validations,
                        &seen_validations,
                    ) {
                        return Err(TranscriptContractError::InvalidScheduleOrder(label.clone()));
                    }
                    seen_pow.insert(label.clone());
                }
                TranscriptStep::Absorb { label } => {
                    let Some(requirement) = absorptions.get(label) else {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    };
                    if requirement.source == TranscriptSource::ProverControlled {
                        let Some(path) = requirement.path.as_ref() else {
                            return Err(TranscriptContractError::MissingProverPath(label.clone()));
                        };
                        if !has_required_validations(path, &validations, &seen_validations) {
                            return Err(TranscriptContractError::InvalidScheduleOrder(
                                label.clone(),
                            ));
                        }
                    }
                    if let Some(pow_requirement) = pow_by_absorption.get(label)
                        && !seen_pow.contains(&pow_requirement.label)
                    {
                        return Err(TranscriptContractError::InvalidScheduleOrder(label.clone()));
                    }
                    *seen_absorptions.entry(label.clone()).or_default() += 1;
                }
                TranscriptStep::DrawChallenge { label } | TranscriptStep::DrawQueries { label } => {
                    let kind = if matches!(step, TranscriptStep::DrawChallenge { .. }) {
                        DrawKind::Challenge
                    } else {
                        DrawKind::Queries
                    };
                    let Some(requirement) = draws.get(&(kind, label.clone())) else {
                        return Err(TranscriptContractError::InvalidScheduleReference(
                            label.clone(),
                        ));
                    };
                    let absorptions_ready = requirement.required_absorptions.iter().all(|label| {
                        absorptions.get(label).is_some_and(|absorption| {
                            seen_absorptions.get(label).copied().unwrap_or_default()
                                >= absorption.expected_count
                        })
                    });
                    let separator_ready = requirement
                        .required_domain_separator
                        .as_ref()
                        .is_none_or(|label| {
                            self.domain_separators
                                .iter()
                                .find(|separator| &separator.label == label)
                                .is_some_and(|separator| {
                                    seen_separators.get(label).copied().unwrap_or_default()
                                        >= separator.expected_count
                                })
                        });
                    let pow_ready = requirement
                        .required_pow
                        .as_ref()
                        .is_none_or(|label| seen_pow.contains(label));
                    if !absorptions_ready || !separator_ready || !pow_ready {
                        return Err(TranscriptContractError::InvalidScheduleOrder(label.clone()));
                    }
                }
            }
        }
        Ok(())
    }
}

fn has_required_validations(
    path: &BoundaryPath,
    required: &BTreeMap<BoundaryPath, BTreeSet<ValidationRule>>,
    seen: &BTreeMap<BoundaryPath, BTreeSet<ValidationRule>>,
) -> bool {
    let Some(required) = required.get(path) else {
        return false;
    };
    let seen = seen.get(path).cloned().unwrap_or_default();
    required.is_subset(&seen)
}

/// Recorder for one ordered verifier transcript execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptRecorder {
    trace: TranscriptTrace,
}

impl TranscriptRecorder {
    /// Start a recorder pinned to one exact target and source identity.
    pub fn new(
        target: impl Into<String>,
        upstream_commit: impl Into<String>,
        case_id: impl Into<String>,
    ) -> Result<Self, TranscriptContractError> {
        let trace = TranscriptTrace {
            target: target.into(),
            upstream_commit: upstream_commit.into(),
            case_id: case_id.into(),
            events: vec![],
        };
        validate_identity(&trace.target, &trace.upstream_commit)?;
        validate_label(&trace.case_id, "case")?;
        Ok(Self { trace })
    }

    /// Record one validated event without reordering earlier events.
    pub fn record(&mut self, event: TranscriptEvent) -> Result<(), TranscriptContractError> {
        event.validate()?;
        self.trace.events.push(event);
        Ok(())
    }

    /// Finish and validate the complete trace.
    pub fn finish(self) -> Result<TranscriptTrace, TranscriptContractError> {
        self.trace.validate()?;
        Ok(self.trace)
    }
}

/// One complete, ordered transcript execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptTrace {
    /// Target copied from the contract used by the recorder.
    pub target: String,
    /// Exact source identity exercised by the recorder.
    pub upstream_commit: String,
    /// Stable execution identity.
    pub case_id: String,
    /// Ordered transcript events.
    pub events: Vec<TranscriptEvent>,
}

impl TranscriptTrace {
    /// Validate recorder output independently of protocol invariants.
    pub fn validate(&self) -> Result<(), TranscriptContractError> {
        validate_identity(&self.target, &self.upstream_commit)?;
        validate_label(&self.case_id, "case")?;
        if self.events.is_empty() {
            return Err(TranscriptContractError::EmptyTrace);
        }
        for event in &self.events {
            event.validate()?;
        }
        Ok(())
    }

    /// SHA-256 digest of the canonical serialized trace.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        let serialized = serde_json::to_vec(self)?;
        Ok(hex_encode(&Sha256::digest(serialized)))
    }
}

/// Ordered verifier transcript event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptEvent {
    /// Enter a protocol-specific domain separator.
    DomainSeparator {
        /// Separator label or literal.
        label: String,
    },
    /// Validate one proof path before use.
    Validate {
        /// Proof path.
        path: BoundaryPath,
        /// Validation performed.
        rule: ValidationRule,
        /// SHA-256 digest of the exact value validated.
        value_digest: String,
        /// Validation result.
        outcome: ValidationOutcome,
    },
    /// Absorb one value into the transcript.
    Absorb {
        /// Stable event label.
        label: String,
        /// Proof path for proof-derived values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<BoundaryPath>,
        /// Source trust class.
        source: TranscriptSource,
        /// Semantic input class.
        kind: AbsorbKind,
        /// SHA-256 digest of the absorbed serialized value.
        value_digest: String,
    },
    /// Verify the proof-of-work field.
    VerifyPow {
        /// Stable verification label.
        label: String,
        /// Required work bits.
        bits: u32,
        /// Proof path containing the nonce.
        nonce_path: BoundaryPath,
        /// Exact canonical nonce bytes checked by the verifier.
        nonce_bytes: Vec<u8>,
        /// Verification result.
        outcome: ValidationOutcome,
    },
    /// Draw one Fiat--Shamir challenge.
    DrawChallenge {
        /// Stable challenge label.
        label: String,
        /// SHA-256 digest of the drawn value.
        value_digest: String,
    },
    /// Draw verifier query positions.
    DrawQueries {
        /// Stable draw label.
        label: String,
        /// Query domain size.
        domain_size: usize,
        /// Exact ordered query positions.
        positions: Vec<usize>,
    },
}

impl TranscriptEvent {
    fn validate(&self) -> Result<(), TranscriptContractError> {
        match self {
            Self::DomainSeparator { label } => validate_label(label, "domain separator"),
            Self::Validate {
                path,
                rule,
                value_digest,
                ..
            } => {
                validate_path(path)?;
                validate_rule(rule)?;
                validate_digest(value_digest)
            }
            Self::Absorb {
                label,
                path,
                source,
                kind,
                value_digest,
            } => {
                validate_label(label, "absorption")?;
                validate_digest(value_digest)?;
                if let Some(path) = path {
                    validate_path(path)?;
                }
                if *source == TranscriptSource::ProverControlled && path.is_none() {
                    return Err(TranscriptContractError::MissingProverPath(label.clone()));
                }
                if let AbsorbKind::Other(label) = kind {
                    validate_label(label, "absorption kind")?;
                }
                Ok(())
            }
            Self::VerifyPow {
                label,
                nonce_path,
                nonce_bytes,
                ..
            } => {
                validate_label(label, "proof-of-work")?;
                validate_path(nonce_path)?;
                if nonce_bytes.is_empty() || nonce_bytes.len() > 64 {
                    return Err(TranscriptContractError::InvalidNonceLength(
                        nonce_bytes.len(),
                    ));
                }
                Ok(())
            }
            Self::DrawChallenge {
                label,
                value_digest,
            } => {
                validate_label(label, "challenge")?;
                validate_digest(value_digest)
            }
            Self::DrawQueries {
                label,
                domain_size,
                positions,
            } => {
                validate_label(label, "query draw")?;
                if positions.is_empty()
                    || *domain_size == 0
                    || !domain_size.is_power_of_two()
                    || positions.iter().any(|position| *position >= *domain_size)
                {
                    return Err(TranscriptContractError::InvalidQueryDomain {
                        count: positions.len(),
                        domain_size: *domain_size,
                    });
                }
                Ok(())
            }
        }
    }
}

fn validate_identity(target: &str, upstream_commit: &str) -> Result<(), TranscriptContractError> {
    validate_label(target, "target")?;
    validate_label(upstream_commit, "upstream commit")
}

fn validate_path(path: &BoundaryPath) -> Result<(), TranscriptContractError> {
    validate_label(&path.field, "proof path")
}

fn validate_rule(rule: &ValidationRule) -> Result<(), TranscriptContractError> {
    if let ValidationRule::Other(label) = rule {
        validate_label(label, "validation rule")?;
    }
    Ok(())
}

fn validate_label(label: &str, kind: &'static str) -> Result<(), TranscriptContractError> {
    if label.trim().is_empty() {
        return Err(TranscriptContractError::EmptyLabel { kind });
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), TranscriptContractError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TranscriptContractError::InvalidDigest(digest.to_owned()));
    }
    Ok(())
}

fn validate_unique_labels(
    labels: &[String],
    kind: &'static str,
) -> Result<(), TranscriptContractError> {
    let mut seen = BTreeSet::new();
    for label in labels {
        validate_label(label, kind)?;
        if !seen.insert(label) {
            return Err(TranscriptContractError::DuplicateLabel {
                kind,
                label: label.clone(),
            });
        }
    }
    Ok(())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Malformed transcript artifacts cannot be treated as analyzed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum TranscriptContractError {
    /// Unknown schema identity or version.
    #[error("unexpected transcript schema `{schema}` version `{version}`")]
    WrongSchema {
        /// Supplied schema.
        schema: String,
        /// Supplied version.
        version: String,
    },
    /// Required label is empty.
    #[error("{kind} label must not be empty")]
    EmptyLabel {
        /// Label class.
        kind: &'static str,
    },
    /// One proof path has duplicate contract entries.
    #[error("duplicate validation requirement for {0:?}")]
    DuplicateValidationPath(BoundaryPath),
    /// One path declares no validation rule.
    #[error("validation requirement for {0:?} contains no rules")]
    EmptyValidationRules(BoundaryPath),
    /// One rule appears twice for a path.
    #[error("duplicate validation rule for {0:?}")]
    DuplicateValidationRule(BoundaryPath),
    /// One draw appears twice.
    #[error("duplicate {kind:?} draw contract `{label}`")]
    DuplicateDraw {
        /// Draw class.
        kind: DrawKind,
        /// Draw label.
        label: String,
    },
    /// One label appears twice where uniqueness is required.
    #[error("duplicate {kind} label `{label}`")]
    DuplicateLabel {
        /// Label class.
        kind: &'static str,
        /// Duplicate label.
        label: String,
    },
    /// Contract has no transcript inputs.
    #[error("transcript contract must declare at least one absorption")]
    EmptyAbsorptionContract,
    /// Contract has no challenge or query draw.
    #[error("transcript contract must declare at least one draw")]
    EmptyDrawContract,
    /// A domain separator count must be positive.
    #[error("domain separator `{0}` must have a positive expected count")]
    ZeroDomainSeparatorCount(String),
    /// An absorption count must be positive.
    #[error("absorption `{0}` must have a positive expected count")]
    ZeroAbsorptionCount(String),
    /// A prover-controlled absorption has no validation contract.
    #[error("prover-controlled path {0:?} has no validation requirement")]
    MissingPathValidation(BoundaryPath),
    /// A validation contract is not used by any prover-controlled absorption.
    #[error("validation requirement for {0:?} is not used by an absorption")]
    UnusedPathValidation(BoundaryPath),
    /// A draw names an absorption outside the contract inventory.
    #[error("draw requires unknown absorption `{0}`")]
    UnknownAbsorption(String),
    /// A draw names a domain separator outside the contract inventory.
    #[error("draw requires unknown domain separator `{0}`")]
    UnknownDomainSeparator(String),
    /// One proof-of-work label appears twice.
    #[error("duplicate proof-of-work contract `{0}`")]
    DuplicatePow(String),
    /// One nonce absorption cannot ambiguously bind multiple work checks.
    #[error("nonce absorption `{0}` is bound to multiple proof-of-work contracts")]
    DuplicatePowAbsorption(String),
    /// A draw names a proof-of-work check outside the contract inventory.
    #[error("draw requires unknown proof-of-work check `{0}`")]
    UnknownPow(String),
    /// Positive-work configurations cannot use a zero-work nonce policy.
    #[error("proof-of-work contract `{0}` uses a zero-work policy with nonzero bits")]
    InvalidPowPolicy(String),
    /// A named nonce absorption does not match the proof-of-work path and type.
    #[error("proof-of-work `{pow}` is not bound to nonce absorption `{absorption}`")]
    InvalidPowAbsorption {
        /// Proof-of-work label.
        pow: String,
        /// Absorption label.
        absorption: String,
    },
    /// Query draws require an exact shape; challenge draws must not have one.
    #[error("invalid shape contract for {kind:?} draw `{label}`")]
    InvalidDrawShape {
        /// Draw class.
        kind: DrawKind,
        /// Draw label.
        label: String,
    },
    /// Contract does not define an event sequence.
    #[error("transcript contract must declare a nonempty event schedule")]
    EmptySchedule,
    /// Event schedule names an undeclared contract element.
    #[error("transcript schedule references undeclared element `{0}`")]
    InvalidScheduleReference(String),
    /// Schedule multiplicities do not match the declared event inventory.
    #[error("transcript schedule multiplicities do not match the event inventory")]
    ScheduleInventoryMismatch,
    /// Schedule places an absorption or draw before its declared prerequisites.
    #[error("transcript schedule uses `{0}` before its declared prerequisites")]
    InvalidScheduleOrder(String),
    /// A prover-controlled absorption has no auditable proof path.
    #[error("prover-controlled absorption `{0}` has no proof path")]
    MissingProverPath(String),
    /// Trace has no events.
    #[error("transcript trace must contain at least one event")]
    EmptyTrace,
    /// Evidence digest is not canonical lowercase SHA-256 hex.
    #[error("invalid SHA-256 digest `{0}`")]
    InvalidDigest(String),
    /// Query shape is empty or not a power-of-two domain.
    #[error("invalid query shape: count={count}, domain_size={domain_size}")]
    InvalidQueryDomain {
        /// Number of positions.
        count: usize,
        /// Domain size.
        domain_size: usize,
    },
    /// Proof-of-work nonce bytes must have a bounded nonempty representation.
    #[error("invalid proof-of-work nonce byte length {0}")]
    InvalidNonceLength(usize),
    /// Trace target does not match the contract.
    #[error("trace target `{observed}` does not match contract target `{expected}`")]
    TargetMismatch {
        /// Contract target.
        expected: String,
        /// Trace target.
        observed: String,
    },
    /// Trace source does not match the contract.
    #[error("trace commit `{observed}` does not match contract commit `{expected}`")]
    UpstreamCommitMismatch {
        /// Contract source identity.
        expected: String,
        /// Trace source identity.
        observed: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn recorder_preserves_order_and_rejects_malformed_events() {
        let mut recorder =
            TranscriptRecorder::new("target", "commit", "case").expect("valid recorder");
        recorder
            .record(TranscriptEvent::DomainSeparator {
                label: "protocol".to_owned(),
            })
            .expect("record separator");
        let error = recorder
            .record(TranscriptEvent::DrawChallenge {
                label: "alpha".to_owned(),
                value_digest: "bad".to_owned(),
            })
            .expect_err("malformed event");
        assert!(matches!(error, TranscriptContractError::InvalidDigest(_)));
        recorder
            .record(TranscriptEvent::DrawChallenge {
                label: "alpha".to_owned(),
                value_digest: DIGEST.to_owned(),
            })
            .expect("record challenge");
        let trace = recorder.finish().expect("finish trace");
        assert!(matches!(
            trace.events.as_slice(),
            [
                TranscriptEvent::DomainSeparator { .. },
                TranscriptEvent::DrawChallenge { .. }
            ]
        ));
    }

    #[test]
    fn trace_digest_is_deterministic_and_sensitive_to_order() {
        let mut trace = TranscriptTrace {
            target: "target".to_owned(),
            upstream_commit: "commit".to_owned(),
            case_id: "case".to_owned(),
            events: vec![
                TranscriptEvent::DomainSeparator {
                    label: "protocol".to_owned(),
                },
                TranscriptEvent::DrawChallenge {
                    label: "alpha".to_owned(),
                    value_digest: DIGEST.to_owned(),
                },
            ],
        };
        trace.validate().expect("valid trace");
        let first = trace.digest().expect("digest trace");
        assert_eq!(first, trace.digest().expect("digest trace"));
        trace.events.swap(0, 1);
        assert_ne!(first, trace.digest().expect("digest reordered trace"));
    }

    #[test]
    fn noncanonical_digest_is_rejected() {
        let trace = TranscriptTrace {
            target: "target".to_owned(),
            upstream_commit: "commit".to_owned(),
            case_id: "case".to_owned(),
            events: vec![TranscriptEvent::DrawChallenge {
                label: "alpha".to_owned(),
                value_digest: "AA".repeat(32),
            }],
        };
        assert!(matches!(
            trace.validate(),
            Err(TranscriptContractError::InvalidDigest(_))
        ));
    }

    #[test]
    fn unknown_trace_fields_are_rejected() {
        let top_level = r#"{
            "target":"target",
            "upstream_commit":"commit",
            "case_id":"case",
            "events":[{"event":"domain_separator","label":"v1"}],
            "ignored":true
        }"#;
        let error = serde_json::from_str::<TranscriptTrace>(top_level).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));

        let nested = r#"{
            "target":"target",
            "upstream_commit":"commit",
            "case_id":"case",
            "events":[{"event":"domain_separator","label":"v1","ignored":true}]
        }"#;
        let error = serde_json::from_str::<TranscriptTrace>(nested).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn unknown_contract_fields_are_rejected() {
        let json = r#"{
            "schema":"airlock.transcript-contract",
            "schema_version":"0.1.0",
            "target":"target",
            "upstream_commit":"commit",
            "schedule":[],
            "domain_separators":[],
            "absorptions":[],
            "path_validations":[],
            "draws":[],
            "pow_verifications":[],
            "ignored":true
        }"#;
        let error = serde_json::from_str::<TranscriptContract>(json).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));
    }
}
