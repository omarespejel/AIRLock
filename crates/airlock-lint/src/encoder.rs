//! Encoder vs admitted-bound lints.

use std::collections::BTreeSet;

use airlock_ir::{
    ComponentManifest, Finding, FindingCode, IntegerEncoding, Severity, SignedEncoding,
};

const MAX_SINGLE_M31_ENCODING_BITS: u32 = 30;

/// Flag integer obligations whose abs_bound exceeds a biased-bits encoder capacity.
pub fn lint_encoder_bounds(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut names = BTreeSet::new();
    for obligation in &component.contract.integer_obligations {
        if obligation.name.trim().is_empty() || !names.insert(obligation.name.as_str()) {
            findings.push(encoder_contract_finding(
                component,
                obligation,
                "obligation names must be nonempty and unique".into(),
            ));
        }
        if let Some(finding) = check_obligation(component, obligation) {
            findings.push(finding);
        }
    }
    findings
}

fn check_obligation(
    component: &ComponentManifest,
    obligation: &IntegerEncoding,
) -> Option<Finding> {
    match obligation.encoding {
        SignedEncoding::BiasedBits { bias, bits } => {
            let Some(capacity) = biased_capacity(bits) else {
                return Some(encoder_contract_finding(
                    component,
                    obligation,
                    format!(
                        "biased encoder bit width {bits} is outside [1, {MAX_SINGLE_M31_ENCODING_BITS}]; wider encodings require an explicit limb decomposition"
                    ),
                ));
            };
            let Ok(bias) = u128::try_from(bias) else {
                return Some(encoder_contract_finding(
                    component,
                    obligation,
                    "biased encoder bias must be nonnegative".into(),
                ));
            };
            if bias > capacity {
                return Some(encoder_contract_finding(
                    component,
                    obligation,
                    format!("biased encoder bias {bias} exceeds code-space maximum {capacity}"),
                ));
            }
            // x + bias lies in [0, 2^bits), so a symmetric |x| bound is limited by
            // both the negative side (`bias`) and positive side (`capacity - bias`).
            let max_abs = bias.min(capacity - bias);
            if obligation.abs_bound > max_abs {
                return Some(Finding {
                    code: FindingCode::AdmittedBoundExceedsEncoder,
                    severity: Severity::High,
                    component: Some(component.name.clone()),
                    message: format!(
                        "integer obligation `{}` admits abs_bound {} but encoder bias {} with {} bits represents a symmetric range only through abs <= {}",
                        obligation.name, obligation.abs_bound, bias, bits, max_abs
                    ),
                    related: vec![obligation.name.clone()],
                });
            }
        }
        SignedEncoding::CenteredM31 => {
            let max_abs = u128::from(airlock_ir::M31_P / 2);
            if obligation.abs_bound > max_abs {
                return Some(Finding {
                    code: FindingCode::AdmittedBoundExceedsEncoder,
                    severity: Severity::High,
                    component: Some(component.name.clone()),
                    message: format!(
                        "integer obligation `{}` admits abs_bound {} exceeding centered-M31 unique range {}",
                        obligation.name, obligation.abs_bound, max_abs
                    ),
                    related: vec![obligation.name.clone()],
                });
            }
        }
    }
    None
}

fn biased_capacity(bits: u32) -> Option<u128> {
    if !(1..=MAX_SINGLE_M31_ENCODING_BITS).contains(&bits) {
        return None;
    }
    Some((1u128 << bits) - 1)
}

fn encoder_contract_finding(
    component: &ComponentManifest,
    obligation: &IntegerEncoding,
    message: String,
) -> Finding {
    Finding {
        code: FindingCode::InvalidEncoderContract,
        severity: Severity::High,
        component: Some(component.name.clone()),
        message: format!("integer obligation `{}`: {message}", obligation.name),
        related: vec![obligation.name.clone()],
    }
}
