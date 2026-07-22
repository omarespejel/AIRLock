//! Unit tests for expression helpers and hashing.

use airlock_ir::{
    AuditManifest, BaseExpr, ComponentManifest, CoverageStatus, IR_SCHEMA_ID, IR_SCHEMA_VERSION,
    M31_P, SemanticContract, hash_u32_values,
};

#[test]
fn m31_prime_is_correct() {
    assert_eq!(M31_P, (1 << 31) - 1);
}

#[test]
fn schema_identity_stable() {
    assert_eq!(IR_SCHEMA_ID, "airlock.audit-ir");
    assert_eq!(IR_SCHEMA_VERSION, "0.2.0");
}

#[test]
fn base_expr_helpers() {
    assert_eq!(
        BaseExpr::param("alpha"),
        BaseExpr::Param {
            name: "alpha".into()
        }
    );
    assert_eq!(
        BaseExpr::column("c0"),
        BaseExpr::Column {
            id: "c0".into(),
            offset: 0
        }
    );
}

#[test]
fn coverage_status_green_only_covered() {
    assert!(CoverageStatus::Covered.is_green());
    assert!(!CoverageStatus::Unsupported.is_green());
    assert!(!CoverageStatus::Quarantined.is_green());
    assert!(!CoverageStatus::Unknown.is_green());
}

#[test]
fn empty_manifest_hashes_deterministically() {
    let a = AuditManifest::new(
        "0.1.0",
        vec![ComponentManifest {
            name: "empty".into(),
            log_size: 0,
            domain_size: 1,
            columns: vec![],
            constraints: vec![],
            relations: vec![],
            preprocessed: vec![],
            declared_max_constraint_log_degree_bound: None,
            contract: SemanticContract::default(),
            logup_finalized: true,
        }],
    );
    let h1 = airlock_ir::hash_manifest(&a).unwrap();
    let h2 = airlock_ir::hash_manifest(&a).unwrap();
    assert_eq!(h1.0, h2.0);
    assert_ne!(hash_u32_values(&[1]), hash_u32_values(&[2]));
}
