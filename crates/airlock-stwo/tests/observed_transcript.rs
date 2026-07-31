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
use airlock_stwo::{QUERY_POW, demo_transcript_contract, observe_demo_transcript};

/// Query count of the pinned demo profile (`FriConfig::new(0, 1, 3, 1)`).
const DEMO_QUERY_COUNT: usize = 3;
/// Lifted query domain of the pinned demo profile: trace log size plus blowup.
const DEMO_QUERY_DOMAIN_SIZE: usize = 1 << 5;

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
/// If the sink is never installed the trace is empty. The refusal happens at the
/// artifact layer rather than in the schedule comparison -- `TranscriptTrace`
/// rejects an empty event list outright, so the verdict is `Unsupported`. Pin the
/// class, not just the negation, so a later relaxation of that schema shows up
/// here instead of silently moving the check somewhere weaker.
#[test]
fn an_empty_trace_is_unsupported_not_accepted() {
    let run = observe_demo_transcript(10, None).expect("observed run");
    let empty = TranscriptTrace {
        events: vec![],
        ..run.trace.clone()
    };

    let report = evaluate_transcript(&run.contract, &empty);
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Unsupported,
        "an empty trace must be refused as a malformed artifact: {:?}",
        report.findings
    );
    assert!(!report.verdict.is_green(), "Unsupported must not be green");
}

/// Partial observation must not read as a pass either.
///
/// The realistic regression is not an absent sink but a dropped hook: a future
/// patch edit that stops reporting one site. Removing the query draw must fail
/// closed rather than leave a shorter trace that happens to satisfy a prefix.
#[test]
fn a_trace_missing_its_query_draw_is_not_accepted() {
    let run = observe_demo_transcript(10, None).expect("observed run");
    let truncated = TranscriptTrace {
        events: run
            .trace
            .events
            .iter()
            .filter(|event| !matches!(event, airlock_boundary::TranscriptEvent::DrawQueries { .. }))
            .cloned()
            .collect(),
        ..run.trace.clone()
    };
    assert_eq!(
        truncated.events.len(),
        run.trace.events.len() - 1,
        "the fixture must actually drop one event"
    );

    let report = evaluate_transcript(&run.contract, &truncated);
    assert_ne!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "a dropped observation must not satisfy the contract: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == TranscriptFindingCode::MissingTranscriptDraw),
        "expected the missing draw to be named: {:?}",
        report.findings
    );
}

/// The contract must be able to disagree with the run.
///
/// Every other case here builds the contract from the same config that produced
/// the trace, so the declared proof-of-work bits can never differ from the
/// observed bits. That makes the `bits` equality check untested by construction.
/// Evaluate a trace observed at zero work against a contract declaring ten bits.
#[test]
fn a_contract_declaring_different_pow_bits_fires() {
    let observed_at_zero = observe_demo_transcript(0, Some(0)).expect("observed run");
    let declares_ten = demo_transcript_contract(10, DEMO_QUERY_COUNT, DEMO_QUERY_DOMAIN_SIZE);

    let report = evaluate_transcript(&declares_ten, &observed_at_zero.trace);
    assert_ne!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "a run at zero work must not satisfy a ten-bit contract: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == TranscriptFindingCode::TranscriptPowContractMismatch),
        "expected a proof-of-work contract mismatch: {:?}",
        report.findings
    );
}

/// A contract declaring the wrong query shape must fire.
///
/// Same gap as the bits case: `query_count` and `domain_size` are otherwise taken
/// from the config that produced the run.
#[test]
fn a_contract_declaring_the_wrong_query_shape_fires() {
    let run = observe_demo_transcript(10, None).expect("observed run");
    let wrong_shape = demo_transcript_contract(10, DEMO_QUERY_COUNT + 1, DEMO_QUERY_DOMAIN_SIZE);

    let report = evaluate_transcript(&wrong_shape, &run.trace);
    assert_ne!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "an overstated query count must not be satisfied: {:?}",
        report.findings
    );
}
