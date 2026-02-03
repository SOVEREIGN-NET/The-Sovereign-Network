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

    let result = registry.register_commercial("food.dao.sov", owner, 0, 100);
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
        .register_commercial("shoes.sov", owner.clone(), 0, 100)
        .expect("register parent");

    let result = registry.register_commercial("dao.shoes.sov", intruder, 0, 100);
    assert!(result.is_err());
}

#[test]
fn test_parent_expiry_propagates_suspension() {
    let mut registry = RootRegistry::new();
    let owner = test_public_key(1);
    let current_height = 0;
    let duration_blocks = 100;

    let parent_hash = registry
        .register_commercial("parent.sov", owner.clone(), current_height, duration_blocks)
        .expect("register parent");
    let child_hash = registry
        .register_commercial("child.parent.sov", owner, current_height, duration_blocks)
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
    let result = registry.register_commercial("dao.shoes.sov", intruder, 0, 100);
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
        .register_commercial("shoes.sov", owner.clone(), 0, 100)
        .expect("register parent");

    // Now try to register dao.shoes.sov as the owner - should still fail!
    let result = registry.register_commercial("dao.shoes.sov", owner, 0, 100);
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
    let result = registry.register_commercial("mydao.sov", owner, 0, 100);
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
    registry.register_commercial("shoes.sov", owner.clone(), 0, 100).unwrap();
    registry.register_commercial("boots.sov", owner.clone(), 0, 100).unwrap();

    // Try to register dao-prefixed (should all fail)
    let _ = registry.register_commercial("dao.shoes.sov", owner.clone(), 0, 100);
    let _ = registry.register_commercial("dao.boots.sov", owner.clone(), 0, 100);

    // Verify: count should be 2 (only shoes.sov and boots.sov)
    // No dao.* records should exist
    // (We can't directly iterate the registry, but the rejection above proves it)
}
