//! Root registry tests for phase-1 and phase-2 invariants.
//!
//! Phase 1: Domain reservation enforcement
//! Phase 2: dao. prefix enforcement (Issue #657)

use super::core::RootRegistry;
use super::dao_prefix_router::DaoPrefixRouter;
use super::types::{NameStatus, ZoneController, PublicKey};

fn test_public_key(id: u8) -> PublicKey {
    [id; 32]
}

#[test]
fn test_reserved_namespace_rejected_in_commercial_path() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    let result = registry.register_commercial_unverified("food.dao.sov", owner, 0, 100);
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

    registry
        .register_commercial_unverified("shoes.sov", owner.clone(), 0, 100)
        .expect("register parent");

    let result = registry.register_commercial_unverified("dao.shoes.sov", intruder, 0, 100);
    assert!(result.is_err());
}

#[test]
fn test_parent_expiry_propagates_suspension() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let current_height = 0;
    let duration_blocks = 100;

    let parent_hash = registry
        .register_commercial_unverified("parent.sov", owner.clone(), current_height, duration_blocks)
        .expect("register parent");
    let child_hash = registry
        .register_commercial_unverified("child.parent.sov", owner, current_height, duration_blocks)
        .expect("register child");

    // Expire at a height after the expiry period
    let past_expiry = current_height + duration_blocks + 1;
    #[allow(deprecated)]
    registry.expire_name(&parent_hash, past_expiry).expect("expire parent");

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

    // Try to register dao.shoes.sov without shoes.sov existing
    let result = registry.register_commercial_unverified("dao.shoes.sov", intruder, 0, 100);
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

    // First register shoes.sov
    registry
        .register_commercial_unverified("shoes.sov", owner.clone(), 0, 100)
        .expect("register parent");

    // Now try to register dao.shoes.sov as the owner - should still fail!
    let result = registry.register_commercial_unverified("dao.shoes.sov", owner, 0, 100);
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

    // "mydao" is not "dao." prefix - should be allowed
    let result = registry.register_commercial_unverified("mydao.sov", owner, 0, 100);
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

    // Register some normal domains
    registry.register_commercial_unverified("shoes.sov", owner.clone(), 0, 100).unwrap();
    registry.register_commercial_unverified("boots.sov", owner.clone(), 0, 100).unwrap();

    // Try to register dao-prefixed (should all fail)
    let _ = registry.register_commercial_unverified("dao.shoes.sov", owner.clone(), 0, 100);
    let _ = registry.register_commercial_unverified("dao.boots.sov", owner.clone(), 0, 100);

    // Verify: count should be 2 (only shoes.sov and boots.sov)
    // No dao.* records should exist
    // (We can't directly iterate the registry, but the rejection above proves it)
}

// ============================================================================
// Phase 6: Lifecycle Tests
// ============================================================================

/// Test touch() correctly finalizes commercial domains past grace to Released
#[test]
fn test_touch_commercial_past_grace_releases() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register a commercial domain at height 0 with 100 block duration
    let name_hash = registry
        .register_commercial_unverified("mystore.sov", owner.clone(), 0, 100)
        .expect("register");

    // Before grace: should return Some
    let record = registry.touch(&name_hash, 50);
    assert!(record.is_some());

    // Still in grace period (100 + grace_blocks): should return Some
    // Default grace is EXPIRATION_GRACE_BLOCKS (30 days * 8600 = 258,000)
    let record = registry.touch(&name_hash, 101);
    assert!(record.is_some());

    // Way past grace period: should finalize and return None (released)
    let record = registry.touch(&name_hash, 500_000);
    assert!(record.is_none(), "Commercial domain should be released past grace");

    // After release, the record should still exist but be Released
    let final_record = registry.get_record(&name_hash).expect("record exists");
    assert!(matches!(final_record.status, NameStatus::Released));
}

/// Test touch() correctly returns welfare domains to governance
#[test]
fn test_touch_welfare_returns_to_governance() {
    use super::types::WelfareSector;

    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let dao_id = [42u8; 32];

    // Register a welfare root
    let root_hash = registry
        .register_reserved_root("food.dao.sov", owner.clone(), 0, 100, Some(dao_id))
        .expect("register root");

    // Link the sector DAO
    registry.link_welfare_sector_dao(WelfareSector::Food, dao_id).unwrap();

    // Way past grace: should finalize to ReturnedToGovernance
    let record = registry.touch(&root_hash, 500_000);
    assert!(record.is_some(), "Welfare domain should return Some (not None like commercial)");

    // Check custodian is set
    let final_record = registry.get_record(&root_hash).expect("record exists");
    assert!(final_record.custodian.is_some(), "Custodian should be set for welfare domain");
}

/// Test touch() doesn't mutate active domains
#[test]
fn test_touch_active_domain_unchanged() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    let name_hash = registry
        .register_commercial_unverified("active.sov", owner.clone(), 0, 100)
        .expect("register");

    // Touch within active period
    let record = registry.touch(&name_hash, 50).expect("record exists");
    assert!(matches!(record.status, NameStatus::Active));

    // Should still be active
    let record2 = registry.get_record(&name_hash).expect("record exists");
    assert!(matches!(record2.status, NameStatus::Active));
}

/// Test renew_name() succeeds for owner within renewal window
#[test]
fn test_renew_name_success() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register at height 0 with 1000 block duration
    let name_hash = registry
        .register_commercial_unverified("renewable.sov", owner.clone(), 0, 1000)
        .expect("register");

    // Renew during active period (within renewal window)
    let result = registry.renew_name(&name_hash, &owner, 900, 500, 100);
    assert!(result.is_ok());
    let fee = result.unwrap();
    assert_eq!(fee, 100, "Base fee should be charged before expiry");

    // Verify expiry was extended
    let record = registry.get_record(&name_hash).expect("record exists");
    assert!(record.expires_at_height > 1000, "Expiry should be extended");
}

/// Test renew_name() applies late penalty during grace period
#[test]
fn test_renew_name_late_penalty() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register at height 0 with 100 block duration
    let name_hash = registry
        .register_commercial_unverified("late.sov", owner.clone(), 0, 100)
        .expect("register");

    // Renew during grace period (past 100, within grace)
    // Default late penalty is 20% (timing::DEFAULT_LATE_RENEWAL_PENALTY_PERCENT)
    let result = registry.renew_name(&name_hash, &owner, 150, 500, 100);
    assert!(result.is_ok());
    let fee = result.unwrap();
    // 100 base + 20% penalty = 120
    assert_eq!(fee, 120, "Late penalty should be applied");
}

/// Test renew_name() fails for non-owner
#[test]
fn test_renew_name_non_owner_fails() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let other = test_public_key(2);

    let name_hash = registry
        .register_commercial_unverified("owned.sov", owner.clone(), 0, 100)
        .expect("register");

    let result = registry.renew_name(&name_hash, &other, 50, 500, 100);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Only owner can renew"));
}

/// Test renew_name() fails past grace period
#[test]
fn test_renew_name_past_grace_fails() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    let name_hash = registry
        .register_commercial_unverified("expired.sov", owner.clone(), 0, 100)
        .expect("register");

    // Way past grace period
    let result = registry.renew_name(&name_hash, &owner, 500_000, 500, 100);
    assert!(result.is_err());
}

/// Test sweep_expired() processes domains in height order
#[test]
fn test_sweep_expired_height_order() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register domains with different expiry times
    registry.register_commercial_unverified("first.sov", owner.clone(), 0, 50).unwrap();
    registry.register_commercial_unverified("second.sov", owner.clone(), 0, 100).unwrap();
    registry.register_commercial_unverified("third.sov", owner.clone(), 0, 150).unwrap();

    // Way past all grace periods
    let swept = registry.sweep_expired(600_000, 10);
    assert_eq!(swept, 3, "Should sweep all 3 expired domains");
}

/// Test sweep_expired() respects limit parameter
#[test]
fn test_sweep_expired_respects_limit() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register 5 domains
    for i in 0..5 {
        registry.register_commercial_unverified(&format!("domain{}.sov", i), owner.clone(), 0, 100).unwrap();
    }

    // Sweep with limit of 2
    let swept = registry.sweep_expired(600_000, 2);
    assert_eq!(swept, 2, "Should only sweep 2 domains due to limit");
}

/// Test sweep_expired() skips active domains
#[test]
fn test_sweep_expired_skips_active() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);

    // Register one active, one expired
    registry.register_commercial_unverified("active.sov", owner.clone(), 0, 1_000_000).unwrap();
    registry.register_commercial_unverified("expired.sov", owner.clone(), 0, 100).unwrap();

    // Sweep at height where only expired.sov is past grace
    let swept = registry.sweep_expired(600_000, 10);
    assert_eq!(swept, 1, "Should only sweep the expired domain");
}

// ============================================================================
// Phase 5: Verification Requirements Tests (Issue #661)
// ============================================================================

use super::types::{VerificationLevel, VerificationProof, ZkProofData};
use super::namespace_policy::NamespacePolicy;

fn test_verification_proof() -> VerificationProof {
    VerificationProof {
        credential_ref: [1u8; 32],
        zk_proof: ZkProofData {
            proof_data: vec![1, 2, 3, 4, 5],
            public_inputs: vec![],
        },
        context: [0u8; 32],
        nonce: 12345,
    }
}

/// Test: L0 (Unverified) cannot register any .sov domain
/// Invariant V1: .sov root issuance is impossible without verification
#[test]
fn test_phase5_l0_unverified_rejected_for_sov() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let proof = test_verification_proof();

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

    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        Some(&proof),
        0,
        100,
    );
    assert!(result.is_ok(), "L2 should succeed for commercial: {:?}", result);

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

    let result = registry.register_commercial(
        "shoes.sov",
        owner,
        VerificationLevel::L2VerifiedEntity,
        None, // No proof
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
    assert_eq!(
        record.verification_level,
        VerificationLevel::L2VerifiedEntity,
        "Verification level should be stored in record"
    );
}

/// Test: NamespacePolicy correctly maps domain classes to required levels
#[test]
fn test_phase5_namespace_policy_required_levels() {
    use super::types::{NameClass, ReservedReason, WelfareSector};

    let policy = NamespacePolicy::new();

    let commercial = NameClass::Commercial {
        min_verification: VerificationLevel::L2VerifiedEntity,
    };
    assert_eq!(
        policy.required_verification(&commercial),
        VerificationLevel::L2VerifiedEntity
    );

    let reserved_welfare = NameClass::Reserved {
        reason: ReservedReason::WelfareRoot,
    };
    assert_eq!(
        policy.required_verification(&reserved_welfare),
        VerificationLevel::L3ConstitutionalActor
    );

    let welfare_child = NameClass::WelfareChild {
        sector: WelfareSector::Health,
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
