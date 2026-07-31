//! Observed transcript projection for the pinned Stwo demo target.
//!
//! The checked consumption patch made sample reads observable. This module does
//! the same for the transcript, and the distinction it preserves is the point: a
//! recorded trace is built only from events the patched verifier reports, never
//! reconstructed from the proof and config. Reconstruction would let AIRLock
//! assert a transcript rather than observe one.
//!
//! The projection is deliberately narrow: the nonce read, the proof-of-work
//! verification over it, the absorption that follows, and the query draw that
//! depends on it. FRI-internal folding challenges, statement absorption, and
//! commitment absorptions are not reported by the patch and are therefore absent
//! from both the contract and the trace.
//!
//! Sampled values are also out of the projection, for a reason worth recording.
//! The oracle requires that prover-controlled data pass its declared validations
//! *before* it enters the transcript, and the pinned verifier absorbs the
//! flattened sampled values with no prior check: their shape is only reconciled
//! against the sampled points much later, by `zip_eq`. Modeling that absorption
//! would therefore force a `ProverDataUsedBeforeValidation` finding. That finding
//! would be unsound as stated -- the prover already controls those field element
//! values, so ordering the shape check earlier removes no grinding freedom -- so
//! the projection excludes it rather than manufacture it.
//!
//! The contract is exact over the projection, not over the whole Fiat-Shamir
//! transcript, and `docs/coverage.yaml` says so.

use std::cell::RefCell;
use std::rc::Rc;

use airlock_boundary::{
    AbsorbKind, AbsorptionRequirement, BoundaryPath, DrawKind, DrawRequirement,
    PathValidationRequirement, PowRequirement, QueryShape, TranscriptContract, TranscriptEvent,
    TranscriptInventory, TranscriptRecorder, TranscriptSource, TranscriptStep, TranscriptTrace,
    ValidationOutcome, ValidationRule, VerificationOutcome, ZeroPowNoncePolicy,
};
use sha2::{Digest, Sha256};
use stwo::core::pcs::{PcsConfig, TranscriptSink};

use crate::adapter::{capture_verifier, verify_framework_observed_transcript};
use crate::fixture::{DEMO_LOG_ROWS, build_demo_fixture_with_config};
use crate::{STWO_DEMO_TARGET, STWO_SOURCE_ID};

/// Label for the query proof-of-work verification.
pub const QUERY_POW: &str = "query_pow";
/// Label for the nonce absorption that follows proof-of-work verification.
pub const QUERY_POW_NONCE_ABSORPTION: &str = "query_pow_nonce";
/// Label for the FRI query-position draw.
pub const FRI_QUERY_POSITIONS_DRAW: &str = "fri_query_positions";

/// Byte length of the canonical nonce representation the verifier absorbs.
const NONCE_BYTE_LEN: usize = 8;

fn digest_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Collects the transcript events the patched Stwo verifier reports.
#[derive(Clone, Default)]
pub(crate) struct ObservedTranscript {
    events: Rc<RefCell<Vec<TranscriptEvent>>>,
}

impl ObservedTranscript {
    /// Build a trace from the observed events.
    pub(crate) fn trace(&self, case_id: &str) -> Result<TranscriptTrace, TranscriptObserveError> {
        let mut recorder = TranscriptRecorder::new(
            STWO_DEMO_TARGET.to_owned(),
            STWO_SOURCE_ID.to_owned(),
            case_id.to_owned(),
        )
        .map_err(|error| TranscriptObserveError::Record(error.to_string()))?;
        for event in self.events.borrow().iter() {
            recorder
                .record(event.clone())
                .map_err(|error| TranscriptObserveError::Record(error.to_string()))?;
        }
        recorder
            .finish()
            .map_err(|error| TranscriptObserveError::Record(error.to_string()))
    }
}

impl TranscriptSink for ObservedTranscript {
    fn record_nonce_encoding(&mut self, label: &str, nonce: u64) {
        // The patch passes the proof field name here, so the label is the path.
        self.events.borrow_mut().push(TranscriptEvent::Validate {
            path: BoundaryPath::new(label, vec![]),
            rule: ValidationRule::CanonicalEncoding,
            value_digest: digest_bytes(&nonce.to_le_bytes()),
            outcome: ValidationOutcome::Passed,
        });
    }

    fn record_pow_verification(&mut self, label: &str, bits: u32, nonce: u64, accepted: bool) {
        self.events.borrow_mut().push(TranscriptEvent::VerifyPow {
            label: label.to_owned(),
            bits,
            nonce_path: BoundaryPath::new("proof_of_work", vec![]),
            nonce_bytes: nonce.to_le_bytes().to_vec(),
            outcome: if accepted {
                ValidationOutcome::Passed
            } else {
                ValidationOutcome::Failed
            },
        });
    }

    fn record_nonce_absorption(&mut self, label: &str, nonce: u64) {
        self.events.borrow_mut().push(TranscriptEvent::Absorb {
            label: label.to_owned(),
            path: Some(BoundaryPath::new("proof_of_work", vec![])),
            source: TranscriptSource::ProverControlled,
            kind: AbsorbKind::Nonce,
            value_digest: digest_bytes(&nonce.to_le_bytes()),
        });
    }

    fn record_query_draw(&mut self, label: &str, domain_size: usize, positions: &[usize]) {
        self.events.borrow_mut().push(TranscriptEvent::DrawQueries {
            label: label.to_owned(),
            domain_size,
            positions: positions.to_vec(),
        });
    }
}

/// Exact transcript contract for the observed projection of the demo target.
///
/// The contract states expectations independently of any run; the oracle
/// compares them against an observed trace. `query_domain_size` is therefore a
/// caller-supplied claim, not a copy of what the verifier reported.
///
/// The zero-work policy is the substantive clause. At `pow_bits > 0` the profile
/// must not degrade to zero work at all. At `pow_bits == 0` the only defensible
/// nonce is the canonical zero: a verifier that accepts and absorbs an arbitrary
/// nonce at zero work hands the prover a free parameter over the query draw that
/// follows, so the contract refuses to treat that as an implicit default.
pub fn demo_transcript_contract(
    pow_bits: u32,
    query_count: usize,
    query_domain_size: usize,
) -> TranscriptContract {
    TranscriptContract::new(
        STWO_DEMO_TARGET.to_owned(),
        STWO_SOURCE_ID.to_owned(),
        TranscriptInventory {
            schedule: vec![
                TranscriptStep::Validate {
                    path: BoundaryPath::new("proof_of_work", vec![]),
                    rule: ValidationRule::CanonicalEncoding,
                },
                TranscriptStep::VerifyPow {
                    label: QUERY_POW.to_owned(),
                },
                TranscriptStep::Absorb {
                    label: QUERY_POW_NONCE_ABSORPTION.to_owned(),
                },
                TranscriptStep::DrawQueries {
                    label: FRI_QUERY_POSITIONS_DRAW.to_owned(),
                },
            ],
            domain_separators: vec![],
            absorptions: vec![AbsorptionRequirement {
                label: QUERY_POW_NONCE_ABSORPTION.to_owned(),
                path: Some(BoundaryPath::new("proof_of_work", vec![])),
                source: TranscriptSource::ProverControlled,
                kind: AbsorbKind::Nonce,
                expected_count: 1,
            }],
            path_validations: vec![PathValidationRequirement {
                path: BoundaryPath::new("proof_of_work", vec![]),
                rules: vec![ValidationRule::CanonicalEncoding],
            }],
            draws: vec![DrawRequirement {
                kind: DrawKind::Queries,
                label: FRI_QUERY_POSITIONS_DRAW.to_owned(),
                required_absorptions: vec![QUERY_POW_NONCE_ABSORPTION.to_owned()],
                required_domain_separator: None,
                required_pow: Some(QUERY_POW.to_owned()),
                query_shape: Some(QueryShape {
                    count: query_count,
                    domain_size: query_domain_size,
                }),
            }],
            pow_verifications: vec![PowRequirement {
                label: QUERY_POW.to_owned(),
                bits: pow_bits,
                nonce_path: BoundaryPath::new("proof_of_work", vec![]),
                nonce_byte_len: NONCE_BYTE_LEN,
                absorbed_as: Some(QUERY_POW_NONCE_ABSORPTION.to_owned()),
                zero_nonce_policy: if pow_bits > 0 {
                    // A profile that requires real work must not silently degrade
                    // to zero work; the contract states that as a hard rule.
                    ZeroPowNoncePolicy::DisallowZeroPow
                } else {
                    ZeroPowNoncePolicy::RequireZeroNonce
                },
            }],
        },
    )
}

/// Verify the demo proof under `pow_bits`, observing the transcript projection.
///
/// `nonce_override` replaces the proof's nonce before verification. A zero-work
/// profile accepts any nonce, so this is how a prover-chosen nonce reaches the
/// channel without modifying the verifier.
pub fn observe_demo_transcript(
    pow_bits: u32,
    nonce_override: Option<u64>,
) -> Result<ObservedTranscriptRun, TranscriptObserveError> {
    let config = PcsConfig {
        pow_bits,
        ..PcsConfig::default()
    };
    let mut fixture = build_demo_fixture_with_config(&[0; 1 << DEMO_LOG_ROWS], config)
        .map_err(|error| TranscriptObserveError::Fixture(error.to_string()))?;
    if let Some(nonce) = nonce_override {
        fixture.proof.0.proof_of_work = nonce;
    }

    let observed = ObservedTranscript::default();
    let outcome = capture_verifier(|| {
        verify_framework_observed_transcript(
            &fixture.component,
            fixture.config,
            fixture.proof.clone(),
            observed.clone(),
        )
    });

    // The query draw indexes the lifted evaluation domain, whose log size is the
    // trace log size plus the FRI blowup factor. Deriving the expected size from
    // the configuration rather than from the reported event keeps the contract an
    // independent claim.
    let query_domain_log_size = DEMO_LOG_ROWS + config.fri_config.log_blowup_factor;
    let query_count = fixture.config.fri_config.n_queries;
    let trace = observed.trace("observed-transcript")?;
    Ok(ObservedTranscriptRun {
        contract: demo_transcript_contract(pow_bits, query_count, 1 << query_domain_log_size),
        trace,
        outcome,
    })
}

/// One observed transcript run and the contract it must satisfy.
#[derive(Clone, Debug)]
pub struct ObservedTranscriptRun {
    /// Exact contract for the observed projection.
    pub contract: TranscriptContract,
    /// Trace built only from reported events.
    pub trace: TranscriptTrace,
    /// Outcome of the real verifier on this proof.
    pub outcome: VerificationOutcome,
}

/// Transcript observation failures.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TranscriptObserveError {
    /// A recorded event violated the trace schema.
    #[error("transcript record rejected: {0}")]
    Record(String),
    /// The deterministic fixture could not be built.
    #[error("transcript fixture build failed: {0}")]
    Fixture(String),
}
