//! Tests for validator management functionality

use anyhow::Result;
use lib_consensus::validators::ValidatorStats;
use lib_consensus::{SlashType, ValidatorManager, ValidatorStatus};
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

#[test]
fn test_validator_manager_initialization() {
    let manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let stats = manager.get_validator_stats();
    assert_eq!(stats.total_validators, 0);
    assert_eq!(stats.active_validators, 0);
    assert_eq!(stats.total_stake, 0);
    assert_eq!(stats.total_storage, 0);
    assert_eq!(stats.total_voting_power, 0);
}

#[test]
fn test_validator_registration_success() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("alice");
    let stake = 2000 * 1_000_000;
    let storage = 200 * 1024 * 1024 * 1024;
    let consensus_key = vec![1u8; 32];
    let commission_rate = 5;

    let result = manager.register_validator(
        identity.clone(),
        stake,
        storage,
        consensus_key,
        commission_rate,
    );

    assert!(result.is_ok());

    let validator = manager.get_validator(&identity);
    assert!(validator.is_some());
    assert_eq!(validator.unwrap().stake, stake);
    assert_eq!(validator.unwrap().storage_provided, storage);
    assert_eq!(validator.unwrap().commission_rate, commission_rate);

    let stats = manager.get_validator_stats();
    assert_eq!(stats.total_validators, 1);
    assert_eq!(stats.active_validators, 1);
    assert_eq!(stats.total_stake, stake);

    Ok(())
}

#[test]
fn test_validator_registration_insufficient_stake() {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("bob");
    let insufficient_stake = 500 * 1_000_000; // Below minimum
    let storage = 200 * 1024 * 1024 * 1024;
    let consensus_key = vec![2u8; 32];
    let commission_rate = 5;

    let result = manager.register_validator(
        identity,
        insufficient_stake,
        storage,
        consensus_key,
        commission_rate,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Insufficient stake"));
}

#[test]
fn test_validator_registration_insufficient_storage() {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("charlie");
    let stake = 2000 * 1_000_000;
    let insufficient_storage = 50 * 1024 * 1024 * 1024; // Below minimum
    let consensus_key = vec![3u8; 32];
    let commission_rate = 5;

    let result = manager.register_validator(
        identity,
        stake,
        insufficient_storage,
        consensus_key,
        commission_rate,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Insufficient storage"));
}

#[test]
fn test_duplicate_validator_registration() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("alice");
    let stake = 2000 * 1_000_000;
    let storage = 200 * 1024 * 1024 * 1024;
    let consensus_key = vec![1u8; 32];
    let commission_rate = 5;

    // First registration should succeed
    let result1 = manager.register_validator(
        identity.clone(),
        stake,
        storage,
        consensus_key.clone(),
        commission_rate,
    );
    assert!(result1.is_ok());

    // Second registration with same identity should fail
    let result2 =
        manager.register_validator(identity, stake, storage, consensus_key, commission_rate);
    assert!(result2.is_err());
    assert!(result2
        .unwrap_err()
        .to_string()
        .contains("already registered"));

    Ok(())
}

#[test]
fn test_maximum_validator_limit() -> Result<()> {
    let mut manager = ValidatorManager::new(2, 1000 * 1_000_000);

    // Register up to the limit
    for i in 1..=2 {
        let identity = create_test_identity(&format!("validator_{}", i));
        let result = manager.register_validator(
            identity,
            1000 * 1_000_000,
            100 * 1024 * 1024 * 1024,
            vec![i as u8; 32],
            5,
        );
        assert!(result.is_ok());
    }

    // Try to register one more (should fail)
    let identity = create_test_identity("extra_validator");
    let result = manager.register_validator(
        identity,
        1000 * 1_000_000,
        100 * 1024 * 1024 * 1024,
        vec![99u8; 32],
        5,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Maximum validator limit"));

    Ok(())
}

#[test]
fn test_validator_removal() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("alice");
    let stake = 2000 * 1_000_000;
    let storage = 200 * 1024 * 1024 * 1024;

    // Register validator
    manager.register_validator(identity.clone(), stake, storage, vec![1u8; 32], 5)?;

    assert_eq!(manager.get_validator_stats().total_validators, 1);

    // Remove validator
    let result = manager.remove_validator(&identity);
    assert!(result.is_ok());

    assert_eq!(manager.get_validator_stats().total_validators, 0);
    assert!(manager.get_validator(&identity).is_none());

    Ok(())
}

#[test]
fn test_remove_nonexistent_validator() {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("nonexistent");
    let result = manager.remove_validator(&identity);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Validator not found"));
}

#[test]
fn test_proposer_selection() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    // Register multiple validators
    let validators = vec!["alice", "bob", "charlie"];
    for (i, name) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        manager.register_validator(
            identity,
            1000 * 1_000_000,
            100 * 1024 * 1024 * 1024,
            vec![(i + 1) as u8; 32],
            5,
        )?;
    }

    // Test proposer selection for different heights/rounds
    let proposer1 = manager.select_proposer(1, 0);
    let proposer2 = manager.select_proposer(2, 0);
    let proposer3 = manager.select_proposer(1, 1);

    assert!(proposer1.is_some());
    assert!(proposer2.is_some());
    assert!(proposer3.is_some());

    // Selection should be deterministic
    let proposer1_again = manager.select_proposer(1, 0);
    assert_eq!(
        proposer1.unwrap().identity,
        proposer1_again.unwrap().identity
    );

    Ok(())
}

#[test]
fn test_proposer_selection_no_validators() {
    let manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let proposer = manager.select_proposer(1, 0);
    assert!(proposer.is_none());
}

#[test]
fn test_slashing_double_sign() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("alice");
    let initial_stake = 2000 * 1_000_000;

    manager.register_validator(
        identity.clone(),
        initial_stake,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;

    let initial_voting_power = manager.get_validator(&identity).unwrap().voting_power;

    // Slash for double signing (5%)
    let slashed_amount = manager.slash_validator(&identity, SlashType::DoubleSign, 5)?;

    let validator = manager.get_validator(&identity).unwrap();
    assert_eq!(slashed_amount, initial_stake * 5 / 100);
    assert_eq!(validator.stake, initial_stake - slashed_amount);
    assert!(validator.voting_power < initial_voting_power);
    // For 5% slashing, validator remains Active (not severe enough for jailing)
    assert_eq!(validator.status, ValidatorStatus::Active);

    Ok(())
}

#[test]
fn test_slashing_liveness() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("bob");
    let initial_stake = 3000 * 1_000_000;

    manager.register_validator(
        identity.clone(),
        initial_stake,
        300 * 1024 * 1024 * 1024,
        vec![2u8; 32],
        5,
    )?;

    // Slash for liveness violation (1%)
    let slashed_amount = manager.slash_validator(&identity, SlashType::Liveness, 1)?;

    let validator = manager.get_validator(&identity).unwrap();
    assert_eq!(slashed_amount, initial_stake * 1 / 100);
    assert_eq!(validator.stake, initial_stake - slashed_amount);

    Ok(())
}

#[test]
fn test_slash_nonexistent_validator() {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("nonexistent");
    let result = manager.slash_validator(&identity, SlashType::DoubleSign, 5);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Validator not found"));
}

#[test]
fn test_byzantine_threshold_calculation() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    // Register validators with equal stakes
    let validators = vec!["alice", "bob", "charlie"];
    for (i, name) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        manager.register_validator(
            identity,
            1000 * 1_000_000,
            100 * 1024 * 1024 * 1024,
            vec![(i + 1) as u8; 32],
            5,
        )?;
    }

    let total_voting_power = manager.get_total_voting_power();
    let byzantine_threshold = manager.get_byzantine_threshold();

    // Byzantine threshold should be > 2/3 of total voting power
    let expected_threshold = (total_voting_power * 2) / 3 + 1;
    assert_eq!(byzantine_threshold, expected_threshold);

    // Test threshold checking
    assert!(manager.meets_byzantine_threshold(byzantine_threshold));
    assert!(!manager.meets_byzantine_threshold(byzantine_threshold - 1));

    Ok(())
}

#[test]
fn test_sufficient_validators_check() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    // Initially no validators
    assert!(!manager.has_sufficient_validators());

    // Add validators one by one
    for i in 1..=4 {
        let identity = create_test_identity(&format!("validator_{}", i));
        manager.register_validator(
            identity,
            1000 * 1_000_000,
            100 * 1024 * 1024 * 1024,
            vec![i as u8; 32],
            5,
        )?;

        if i >= 4 {
            assert!(manager.has_sufficient_validators());
        } else {
            assert!(!manager.has_sufficient_validators());
        }
    }

    Ok(())
}

#[test]
fn test_validator_activity_update() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let identity = create_test_identity("alice");
    manager.register_validator(
        identity.clone(),
        1000 * 1_000_000,
        100 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;

    let initial_activity = manager.get_validator(&identity).unwrap().last_activity;

    // Update activity
    manager.update_validator_activity(&identity);

    let updated_activity = manager.get_validator(&identity).unwrap().last_activity;
    assert!(updated_activity >= initial_activity);

    Ok(())
}

#[test]
fn test_validator_stats_calculation() -> Result<()> {
    let mut manager = ValidatorManager::new(10, 1000 * 1_000_000);

    let validators = vec![
        ("alice", 1000 * 1_000_000, 100 * 1024 * 1024 * 1024),
        ("bob", 2000 * 1_000_000, 200 * 1024 * 1024 * 1024),
        ("charlie", 3000 * 1_000_000, 300 * 1024 * 1024 * 1024),
    ];

    let mut total_stake = 0;
    let mut total_storage = 0;

    for (i, (name, stake, storage)) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        manager.register_validator(identity, *stake, *storage, vec![(i + 1) as u8; 32], 5)?;
        total_stake += stake;
        total_storage += storage;
    }

    let stats = manager.get_validator_stats();
    assert_eq!(stats.total_validators, 3);
    assert_eq!(stats.active_validators, 3);
    assert_eq!(stats.total_stake, total_stake);
    assert_eq!(stats.total_storage, total_storage);
    assert!(stats.total_voting_power > 0);

    Ok(())
}
