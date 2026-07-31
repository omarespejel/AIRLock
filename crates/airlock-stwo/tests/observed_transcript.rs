//! Observed transcript projection against the real pinned Stwo verifier.
//!
//! These cases run the unmodified pinned verifier. No defective mutant is
//! involved: a zero-work profile accepts any nonce by construction, so a
//! prover-chosen nonce reaches the channel immediately before the query draw
//! without changing a line of verifier code. The contract declares
//! `RequireZeroNonce`, and the oracle is expected to fire.

use airlock_boundary::{
    AbsorbKind, TranscriptEvent, TranscriptFindingCode, TranscriptTrace, TranscriptVerdict,
    VerificationOutcome, evaluate_transcript,
};
use airlock_stwo::{QUERY_POW, demo_transcript_contract, observe_demo_transcript};
use sha2::{Digest, Sha256};

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

/// The observed proof-of-work event must carry the exact nonce checked.
///
/// This pins the `VerifyPow` side only. The binding between what was verified and
/// what was absorbed is a separate property, exercised in the two cases below.
#[test]
fn observed_pow_event_carries_the_exact_nonce() {
    let nonce: u64 = 0x0102_0304_0506_0708;
    let run = observe_demo_transcript(0, Some(nonce)).expect("observed run");

    let verified: Vec<Vec<u8>> = run
        .trace
        .events
        .iter()
        .filter_map(|event| match event {
            TranscriptEvent::VerifyPow { nonce_bytes, .. } => Some(nonce_bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        verified,
        vec![nonce.to_le_bytes().to_vec()],
        "the observed verification must carry the exact nonce checked"
    );
}

/// The absorbed nonce must be the one that passed verification.
///
/// The repair direction: on an honest run the absorption digest equals the digest
/// of the verified nonce bytes, so the binding holds and the oracle accepts.
#[test]
fn absorbed_nonce_is_bound_to_the_verified_nonce() {
    let run = observe_demo_transcript(0, Some(0)).expect("observed run");

    let verified = pow_nonce_bytes(&run.trace).expect("one pow event");
    let absorbed = absorbed_nonce_digest(&run.trace).expect("one nonce absorption");
    assert_eq!(
        absorbed,
        sha256_hex(&verified),
        "the absorbed digest must be the digest of the verified nonce"
    );

    let report = evaluate_transcript(&run.contract, &run.trace);
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Accepted,
        "a bound nonce must satisfy the contract: {:?}",
        report.findings
    );
}

/// The vulnerable direction: a verifier that absorbs a different value than the
/// one it verified must be caught.
///
/// Proof-of-work acceptance alone is not enough -- if the absorbed bytes may
/// differ from the verified bytes, the work does not constrain the transcript the
/// draw is derived from. Both traces here are real observations; only the
/// absorption digest is swapped, so the proof-of-work event still reports an
/// accepted canonical zero nonce and the binding check is the sole failure.
#[test]
fn an_absorbed_nonce_that_differs_from_the_verified_one_fires() {
    let bound = observe_demo_transcript(0, Some(0)).expect("observed run");
    let other = observe_demo_transcript(0, Some(0xA5A5_A5A5_A5A5_A5A5)).expect("observed run");

    let foreign_digest = absorbed_nonce_digest(&other.trace).expect("one nonce absorption");
    assert_ne!(
        foreign_digest,
        absorbed_nonce_digest(&bound.trace).expect("one nonce absorption"),
        "the substituted digest must actually differ"
    );

    let mut events = bound.trace.events.clone();
    let absorption = events
        .iter_mut()
        .find_map(|event| match event {
            TranscriptEvent::Absorb {
                kind: AbsorbKind::Nonce,
                value_digest,
                ..
            } => Some(value_digest),
            _ => None,
        })
        .expect("one nonce absorption");
    *absorption = foreign_digest;
    let unbound = TranscriptTrace {
        events,
        ..bound.trace.clone()
    };

    let report = evaluate_transcript(&bound.contract, &unbound);
    assert_eq!(
        report.verdict,
        TranscriptVerdict::Counterexample,
        "an unbound nonce absorption must be a counterexample: {:?}",
        report.findings
    );
    assert!(
        report.findings.iter().any(|finding| finding.code
            == TranscriptFindingCode::TranscriptPowNonceBindingMismatch),
        "expected the nonce binding mismatch to be named: {:?}",
        report.findings
    );
}

/// Exact nonce bytes from the single observed proof-of-work event.
fn pow_nonce_bytes(trace: &TranscriptTrace) -> Option<Vec<u8>> {
    let mut found = trace.events.iter().filter_map(|event| match event {
        TranscriptEvent::VerifyPow { nonce_bytes, .. } => Some(nonce_bytes.clone()),
        _ => None,
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// Digest from the single observed nonce absorption.
fn absorbed_nonce_digest(trace: &TranscriptTrace) -> Option<String> {
    let mut found = trace.events.iter().filter_map(|event| match event {
        TranscriptEvent::Absorb {
            kind: AbsorbKind::Nonce,
            value_digest,
            ..
        } => Some(value_digest.clone()),
        _ => None,
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
            .filter(|event| !matches!(event, TranscriptEvent::DrawQueries { .. }))
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
