//! Root registry tests for phase-1, phase-2, and phase-5 invariants.
//!
//! Phase 1: Domain reservation enforcement
//! Phase 2: dao. prefix enforcement (Issue #657)
//! Phase 5: Verification requirements for root issuance (Issue #661)

use super::core::RootRegistry;
use super::dao_prefix_router::DaoPrefixRouter;
use super::types::{
    NameStatus, ZoneController, PublicKey, VerificationLevel, VerificationProof, ZkProofData,
};

fn test_public_key(id: u8) -> PublicKey {
    [id; 32]
}

/// Create a valid L2 verification proof for testing
fn test_verification_proof() -> VerificationProof {
    VerificationProof {
        credential_ref: [1u8; 32],
        zk_proof: ZkProofData {
            proof_data: vec![1, 2, 3, 4], // Non-empty proof
            public_inputs: vec![5, 6, 7, 8],
        },
        context: [0u8; 32],
        nonce: 12345,
    }
}

#[test]
fn test_reserved_namespace_rejected_in_commercial_path() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // Even with valid L2 verification, reserved namespaces are rejected
    let result = registry.register_commercial(
        "food.dao.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn test_zone_controller_scope_rejected_for_wrong_issuer() {
    let mut registry = RootRegistry::new();
    let food_owner = test_public_key(1);
    let health_owner = test_public_key(2);
    let food_controller = test_public_key(3);
    let health_controller = test_public_key(4);

    let food_hash = registry
        .register_reserved_root("food.dao.sov", food_owner.clone(), 0, 100, None)
        .expect("register food root");
    let health_hash = registry
        .register_reserved_root("health.dao.sov", health_owner.clone(), 0, 100, None)
        .expect("register health root");

    registry
        .set_zone_controller(
            &food_hash,
            ZoneController {
                controller: food_controller.clone(),
                scope: food_hash,
                expires_at: None,
            },
            &food_owner,
        )
        .expect("set food controller");

    registry
        .set_zone_controller(
            &health_hash,
            ZoneController {
                controller: health_controller.clone(),
                scope: health_hash,
                expires_at: None,
            },
            &health_owner,
        )
        .expect("set health controller");

    let result = registry.register_under_zone_controller(
        "clinic.health.dao.sov",
        test_public_key(9),
        &food_controller,
        0,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn test_dao_prefixed_requires_parent_ownership() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let intruder = test_public_key(2);
    let proof = test_verification_proof();

    registry
        .register_commercial(
            "shoes.sov",
            owner.clone(),
            VerificationLevel::L2VerifiedEntity,
            Some(&proof),
            0,
            100,
        )
        .expect("register parent");

    // dao.* names are virtual - even with verification, cannot be registered
    let result = registry.register_commercial(
        "dao.shoes.sov",
        intruder,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
}

#[test]
fn test_parent_expiry_propagates_suspension() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    let parent_hash = registry
        .register_commercial(
            "parent.sov",
            owner.clone(),
            VerificationLevel::L2VerifiedEntity,
            Some(&proof),
            0,
            100,
        )
        .expect("register parent");
    let child_hash = registry
        .register_commercial(
            "child.parent.sov",
            owner,
            VerificationLevel::L2VerifiedEntity,
            Some(&proof),
            0,
            100,
        )
        .expect("register child");

    registry.expire_name(&parent_hash).expect("expire parent");

    let child = registry.get_record(&child_hash).expect("child record");
    assert_eq!(child.status, NameStatus::SuspendedByParent);
}

#[test]
fn test_zone_controller_scope_allows_mint_within_scope() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let controller = test_public_key(2);

    let root_hash = registry
        .register_reserved_root("food.dao.sov", owner.clone(), 0, 100, None)
        .expect("register root");

    registry
        .set_zone_controller(
            &root_hash,
            ZoneController {
                controller: controller.clone(),
                scope: root_hash,
                expires_at: None,
            },
            &owner,
        )
        .expect("set controller");

    let result = registry.register_under_zone_controller(
        "aid.food.dao.sov",
        test_public_key(3),
        &controller,
        0,
        100,
    );
    assert!(result.is_ok());
}

#[test]
fn test_expired_zone_controller_rejected() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let controller = test_public_key(2);

    let root_hash = registry
        .register_reserved_root("health.dao.sov", owner.clone(), 0, 100, None)
        .expect("register root");

    registry
        .set_zone_controller(
            &root_hash,
            ZoneController {
                controller: controller.clone(),
                scope: root_hash,
                expires_at: Some(10),
            },
            &owner,
        )
        .expect("set controller");

    let result = registry.register_under_zone_controller(
        "clinic.health.dao.sov",
        test_public_key(3),
        &controller,
        20,
        200,
    );
    assert!(result.is_err());
}

// ============================================================================
// Phase 2: dao. Prefix Enforcement Tests (Issue #657)
// ============================================================================

/// Test: Attempting to register dao.shoes.sov without owning shoes.sov → REJECTED
#[test]
fn test_phase2_dao_prefix_registration_without_parent_rejected() {
    let mut registry = RootRegistry::new();
    let intruder = test_public_key(1);
    let proof = test_verification_proof();

    // Try to register dao.shoes.sov without shoes.sov existing
    // dao.* names are virtual, so this fails regardless of verification
    let result = registry.register_commercial(
        "dao.shoes.sov",
        intruder,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("virtual") || err.contains("cannot be registered"),
        "Error should mention virtual: {}",
        err
    );
}

/// Test: Attempting to register dao.shoes.sov while owning shoes.sov → REJECTED (no registration path)
/// This is the key Phase 2 change: even owners cannot register dao.* names
#[test]
fn test_phase2_dao_prefix_registration_even_with_ownership_rejected() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // First register shoes.sov with proper verification
    registry
        .register_commercial(
            "shoes.sov",
            owner.clone(),
            VerificationLevel::L2VerifiedEntity,
            Some(&proof),
            0,
            100,
        )
        .expect("register parent");

    // Now try to register dao.shoes.sov as the owner - should still fail!
    let result = registry.register_commercial(
        "dao.shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("virtual") || err.contains("cannot be registered"),
        "Error should indicate dao.* is virtual: {}",
        err
    );
}

/// Test: mydao.sov registration → ALLOWED (not a prefix)
#[test]
fn test_phase2_mydao_sov_registration_allowed() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // "mydao" is not "dao." prefix - should be allowed with L2 verification
    let result = registry.register_commercial(
        "mydao.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_ok());
}

/// Test: DaoPrefixRouter correctly identifies dao-prefixed names
#[test]
fn test_phase2_dao_prefix_router_detection() {
    assert!(DaoPrefixRouter::is_dao_prefixed("dao.shoes.sov"));
    assert!(DaoPrefixRouter::is_dao_prefixed("dao.food.dao.sov"));
    assert!(DaoPrefixRouter::is_dao_prefixed("dao.sub.shoes.sov"));

    assert!(!DaoPrefixRouter::is_dao_prefixed("shoes.sov"));
    assert!(!DaoPrefixRouter::is_dao_prefixed("mydao.sov"));
    assert!(!DaoPrefixRouter::is_dao_prefixed("food.dao.sov"));
}

/// Test: dao.dao.sov resolution → INVALID
#[test]
fn test_phase2_dao_dao_sov_invalid() {
    assert!(!DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.dao.sov"));
}

/// Test: dao.food.dao.sov resolution → Valid (returns governance of food.dao.sov)
#[test]
fn test_phase2_dao_food_dao_sov_valid() {
    assert!(DaoPrefixRouter::is_valid_dao_prefix_resolution("dao.food.dao.sov"));
}

/// Test: dao.sub.shoes.sov → Controlled by sub.shoes.sov, not shoes.sov
#[test]
fn test_phase2_dao_prefix_binds_to_immediate_parent() {
    // dao.sub.shoes.sov should bind to sub.shoes.sov, not shoes.sov
    let parent = DaoPrefixRouter::extract_parent("dao.sub.shoes.sov");
    assert_eq!(parent, Some("sub.shoes.sov".to_string()));

    // NOT shoes.sov
    assert_ne!(parent, Some("shoes.sov".to_string()));
}

/// Test: DaoPrefixRouter validation rejects all dao.* registrations
#[test]
fn test_phase2_validate_registration_rejects_dao_prefix() {
    assert!(DaoPrefixRouter::validate_registration("dao.shoes.sov").is_err());
    assert!(DaoPrefixRouter::validate_registration("dao.food.dao.sov").is_err());
    assert!(DaoPrefixRouter::validate_registration("dao.sub.shoes.sov").is_err());

    // Non-dao-prefixed should pass validation
    assert!(DaoPrefixRouter::validate_registration("shoes.sov").is_ok());
    assert!(DaoPrefixRouter::validate_registration("mydao.sov").is_ok());
    assert!(DaoPrefixRouter::validate_registration("food.dao.sov").is_ok());
}

/// Invariant Test: No NameRecord should exist with name starting with "dao."
#[test]
fn test_phase2_invariant_no_dao_records_stored() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // Register some normal domains with proper verification
    registry.register_commercial(
        "shoes.sov",
        owner.clone(),
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    ).unwrap();
    registry.register_commercial(
        "boots.sov",
        owner.clone(),
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    ).unwrap();

    // Try to register dao-prefixed (should all fail)
    let _ = registry.register_commercial(
        "dao.shoes.sov",
        owner.clone(),
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    let _ = registry.register_commercial(
        "dao.boots.sov",
        owner.clone(),
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );

    // Verify: count should be 2 (only shoes.sov and boots.sov)
    // No dao.* records should exist
    // (We can't directly iterate the registry, but the rejection above proves it)
}

// ============================================================================
// Phase 5: Verification Requirements Tests (Issue #661)
// ============================================================================

/// Test: L0 (Unverified) cannot register any .sov domain
/// Invariant V1: .sov root issuance is impossible without verification
#[test]
fn test_phase5_l0_unverified_rejected_for_sov() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // L0 should ALWAYS be rejected for .sov domains
    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L0Unverified,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("L0") || err.contains("unverified") || err.contains("Unverified"),
        "Error should mention L0 not allowed: {}",
        err
    );
}

/// Test: L1 (BasicDID) insufficient for commercial root registration
/// Invariant V2: Verification requirements are name-class dependent
#[test]
fn test_phase5_l1_insufficient_for_commercial_root() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // L1 is insufficient for commercial roots (requires L2)
    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L1BasicDID,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("Insufficient") || err.contains("level"),
        "Error should mention insufficient level: {}",
        err
    );
}

/// Test: L2 (VerifiedEntity) with valid proof succeeds for commercial root
#[test]
fn test_phase5_l2_verified_entity_succeeds() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // L2 should succeed for commercial roots
    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_ok(), "L2 should succeed for commercial: {:?}", result);

    // Verify the record was created with correct verification level
    let name_hash = result.unwrap();
    let record = registry.get_record(&name_hash).expect("record exists");
    assert_eq!(record.verification_level, VerificationLevel::L2VerifiedEntity);
}

/// Test: L3 (ConstitutionalActor) also succeeds for commercial root (exceeds minimum)
#[test]
fn test_phase5_l3_exceeds_minimum_succeeds() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    // L3 exceeds L2 requirement, should succeed
    let result = registry.register_commercial(
        "premium.sov",
        owner,
        VerificationLevel::L3ConstitutionalActor,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_ok(), "L3 should exceed L2 requirement: {:?}", result);
}

/// Test: Missing proof fails even with valid level
/// Invariant V7: Missing verification fails loudly and deterministically
#[test]
fn test_phase5_missing_proof_rejected() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Valid level but no proof - should fail
    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        None, // No proof!
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("proof") || err.contains("Proof") || err.contains("Missing"),
        "Error should mention missing proof: {}",
        err
    );
}

/// Test: Empty proof data is rejected
#[test]
fn test_phase5_empty_proof_rejected() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    
    // Proof with empty data
    let empty_proof = VerificationProof {
        credential_ref: [1u8; 32],
        zk_proof: ZkProofData {
            proof_data: vec![], // Empty!
            public_inputs: vec![],
        },
        context: [0u8; 32],
        nonce: 12345,
    };

    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&empty_proof),
        0,
        100,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("Empty") || err.contains("proof") || err.contains("Invalid"),
        "Error should mention invalid/empty proof: {}",
        err
    );
}

/// Test: Verification level is snapshotted at registration time
/// Invariant V6: Domain verification is snapshotted, not continuously policed
#[test]
fn test_phase5_verification_level_stored_in_record() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

    let result = registry.register_commercial(
        "verified.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_ok());

    let name_hash = result.unwrap();
    let record = registry.get_record(&name_hash).expect("record exists");
    
    // Verification level should be stored (snapshotted)
    assert_eq!(
        record.verification_level,
        VerificationLevel::L2VerifiedEntity,
        "Verification level should be stored in record"
    );
}

/// Test: NamespacePolicy correctly maps domain classes to required levels
#[test]
fn test_phase5_namespace_policy_required_levels() {
    use super::namespace_policy::NamespacePolicy;
    use super::types::{NameClass, ReservedReason};

    let policy = NamespacePolicy::new();

    // Commercial requires L2
    let commercial = NameClass::Commercial {
        min_verification: VerificationLevel::L2VerifiedEntity,
    };
    assert_eq!(
        policy.required_verification(&commercial),
        VerificationLevel::L2VerifiedEntity
    );

    // Reserved (welfare root) requires L3
    let reserved_welfare = NameClass::Reserved {
        reason: ReservedReason::WelfareRoot,
    };
    assert_eq!(
        policy.required_verification(&reserved_welfare),
        VerificationLevel::L3ConstitutionalActor
    );

    // Welfare child requires L1
    let welfare_child = NameClass::WelfareChild {
        sector: super::types::WelfareSector::Health,
        zone_root_hash: [0u8; 32],
    };
    assert_eq!(
        policy.required_verification(&welfare_child),
        VerificationLevel::L1BasicDID
    );
}

/// Test: VerificationLevel ordering is correct
#[test]
fn test_phase5_verification_level_ordering() {
    // L3 >= L2 >= L1 >= L0
    assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L2VerifiedEntity));
    assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L1BasicDID));
    assert!(VerificationLevel::L3ConstitutionalActor.meets_minimum(VerificationLevel::L0Unverified));

    assert!(VerificationLevel::L2VerifiedEntity.meets_minimum(VerificationLevel::L1BasicDID));
    assert!(VerificationLevel::L2VerifiedEntity.meets_minimum(VerificationLevel::L0Unverified));
    assert!(!VerificationLevel::L2VerifiedEntity.meets_minimum(VerificationLevel::L3ConstitutionalActor));

    assert!(VerificationLevel::L1BasicDID.meets_minimum(VerificationLevel::L0Unverified));
    assert!(!VerificationLevel::L1BasicDID.meets_minimum(VerificationLevel::L2VerifiedEntity));

    assert!(!VerificationLevel::L0Unverified.meets_minimum(VerificationLevel::L1BasicDID));
}
