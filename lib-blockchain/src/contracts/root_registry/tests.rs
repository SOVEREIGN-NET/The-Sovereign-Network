//! Root registry tests for phase-1 invariants.

use super::core::RootRegistry;
use super::types::{NameStatus, ZoneController};
use crate::integration::crypto_integration::PublicKey;

fn test_public_key(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 1312])
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

    let parent_hash = registry
        .register_commercial("parent.sov", owner.clone(), 0, 100)
        .expect("register parent");
    let child_hash = registry
        .register_commercial("child.parent.sov", owner, 0, 100)
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
