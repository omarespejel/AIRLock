//! Observed transcript projection against the real pinned Stwo verifier.
//!
//! These cases run the unmodified pinned verifier. No defective mutant is
//! involved: a zero-work profile accepts any nonce by construction, so a
//! prover-chosen nonce reaches the channel immediately before the query draw
//! without changing a line of verifier code. The contract declares
//! `RequireZeroNonce`, and the oracle is expected to fire.

use airlock_boundary::{
    TranscriptFindingCode, TranscriptTrace, TranscriptVerdict, VerificationOutcome,
    evaluate_transcript,
};
use airlock_stwo::{QUERY_POW, observe_demo_transcript};

/// A conventional profile with real work required must satisfy the contract.
///
/// This is the direction that keeps the oracle honest: it must be possible to
/// pass, or firing proves nothing.
#[test]
fn conventional_pow_profile_satisfies_the_transcript_contract() {
    let run = observe_demo_transcript(10, None).expect("observed run");
    assert_eq!(run.outcome, VerificationOutcome::Accepted);

    let report = evaluate_transcript(&run.contract, &run.trace);
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "conventional profile must satisfy the contract: {:?}",
        report.findings
    );
}

/// A zero-work profile with the canonical zero nonce also satisfies it.
#[test]
fn zero_work_with_canonical_zero_nonce_is_accepted() {
    let run = observe_demo_transcript(0, Some(0)).expect("observed run");
    assert_eq!(run.outcome, VerificationOutcome::Accepted);

    let report = evaluate_transcript(&run.contract, &run.trace);
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "a canonical zero nonce is the defensible zero-work choice: {:?}",
        report.findings
    );
}

/// The demonstration: at zero work the real verifier accepts an arbitrary
/// prover-chosen nonce and absorbs it before drawing query positions, which the
/// contract refuses to treat as an implicit default.
#[test]
fn zero_work_arbitrary_nonce_makes_the_transcript_oracle_fire() {
    let run = observe_demo_transcript(0, Some(0xDEAD_BEEF_CAFE_F00D)).expect("observed run");

    // The unmodified verifier accepts. That is the point: this is not a mutant.
    assert_eq!(
        run.outcome,
        VerificationOutcome::Accepted,
        "a zero-work profile accepts any nonce, so verification must succeed"
    );

    let report = evaluate_transcript(&run.contract, &run.trace);
    assert_ne!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "an arbitrary nonce at zero work must not satisfy the contract"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| { finding.code == TranscriptFindingCode::ZeroPowNoncePolicyViolation }),
        "expected a zero-work nonce policy violation: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.related.iter().any(|item| item == QUERY_POW)),
        "the finding must name the proof-of-work event it came from: {:?}",
        report.findings
    );
}

/// The observed trace must come from reported events, so the nonce recorded as
/// verified must equal the nonce recorded as absorbed.
#[test]
fn observed_nonce_verification_and_absorption_agree() {
    let nonce: u64 = 0x0102_0304_0506_0708;
    let run = observe_demo_transcript(0, Some(nonce)).expect("observed run");

    let verified: Vec<Vec<u8>> = run
        .trace
        .events
        .iter()
        .filter_map(|event| match event {
            airlock_boundary::TranscriptEvent::VerifyPow { nonce_bytes, .. } => {
                Some(nonce_bytes.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        verified,
        vec![nonce.to_le_bytes().to_vec()],
        "the observed verification must carry the exact nonce checked"
    );
}

/// Print the firing report so the verdict class is visible, not merely asserted.
#[test]
fn firing_report_is_a_counterexample_not_unsupported() {
    let run = observe_demo_transcript(0, Some(0xDEAD_BEEF_CAFE_F00D)).expect("observed run");
    let report = evaluate_transcript(&run.contract, &run.trace);
    println!("verdict: {:?}", report.verdict);
    for finding in &report.findings {
        println!("  {:?}: {}", finding.code, finding.message);
    }
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Counterexample,
        "the oracle must report a counterexample, not a malformed-artifact verdict"
    );
}

/// An unobserved run must not read as a pass.
///
/// If the sink is never installed the trace is empty. Evaluating an empty trace
/// against the contract must not be silently green, or forgetting to wire the
/// sink would turn absent observation into passing evidence.
#[test]
fn an_empty_trace_is_never_accepted() {
    let run = observe_demo_transcript(10, None).expect("observed run");
    let empty = TranscriptTrace {
        events: vec![],
        ..run.trace.clone()
    };

    let report = evaluate_transcript(&run.contract, &empty);
    assert_ne!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "an unobserved transcript must not satisfy the contract: {:?}",
        report.findings
    );
}
