//! Encoder vs admitted-bound lints.

use airlock_ir::{
    ComponentManifest, Finding, FindingCode, IntegerEncoding, Severity, SignedEncoding,
};

/// Flag integer obligations whose abs_bound exceeds a biased-bits encoder capacity.
pub fn lint_encoder_bounds(component: &ComponentManifest) -> Vec<Finding> {
    let mut findings = Vec::new();
    for obligation in &component.contract.integer_obligations {
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
        SignedEncoding::BiasedBits { bias: _, bits } => {
            // Encoded value in [0, 2^bits) ⇒ absolute magnitude before bias must fit.
            // For bias = 2^(bits-1), max abs is 2^(bits-1) - 1 for two's-style envelopes.
            let max_abs = (1u128 << (bits.saturating_sub(1))).saturating_sub(1);
            if obligation.abs_bound > max_abs {
                return Some(Finding {
                    code: FindingCode::AdmittedBoundExceedsEncoder,
                    severity: Severity::High,
                    component: Some(component.name.clone()),
                    message: format!(
                        "integer obligation `{}` admits abs_bound {} but encoder only represents abs <= {} ({}-bit biased)",
                        obligation.name, obligation.abs_bound, max_abs, bits
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
