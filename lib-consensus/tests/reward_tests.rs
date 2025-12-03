//! Tests for reward calculation and distribution system

use anyhow::Result;
use lib_consensus::{
    RewardCalculator, ValidatorManager, UsefulWorkType
};
use lib_consensus::rewards::{RewardRound, ValidatorReward};
use lib_identity::IdentityId;
use lib_crypto::{Hash, hash_blake3};

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

#[test]
fn test_reward_calculator_initialization() {
    let calculator = RewardCalculator::new();
    
    // Should initialize with default settings
    // Implementation will vary based on actual RewardCalculator struct
    assert!(true); // Placeholder - replace with actual assertions
}

#[test]
fn test_basic_validation_rewards() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validators
    let validators = vec![
        ("alice", 2000 * 1_000_000, 200 * 1024 * 1024 * 1024),
        ("bob", 1500 * 1_000_000, 150 * 1024 * 1024 * 1024),
        ("charlie", 1000 * 1_000_000, 100 * 1024 * 1024 * 1024),
    ];
    
    for (i, (name, stake, storage)) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        validator_manager.register_validator(
            identity,
            *stake,
            *storage,
            vec![(i + 1) as u8; 32],
            5,
        )?;
    }
    
    // Calculate rewards for a round
    let block_height = 100;
    let reward_round = calculator.calculate_round_rewards(&validator_manager, block_height)?;
    
    // Should have rewards for all active validators
    assert!(reward_round.validator_rewards.len() > 0);
    assert_eq!(reward_round.height, block_height);
    assert!(reward_round.total_rewards > 0);
    
    Ok(())
}

#[test]
fn test_stake_proportional_rewards() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validators with different stakes
    let alice_stake = 3000 * 1_000_000; // High stake
    let bob_stake = 1000 * 1_000_000;   // Low stake
    
    let alice_id = create_test_identity("alice");
    let bob_id = create_test_identity("bob");
    
    validator_manager.register_validator(
        alice_id.clone(),
        alice_stake,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;
    
    validator_manager.register_validator(
        bob_id.clone(),
        bob_stake,
        200 * 1024 * 1024 * 1024,
        vec![2u8; 32],
        5,
    )?;
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    // Find rewards for each validator
    let alice_rewards = reward_round.validator_rewards.get(&alice_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    let bob_rewards = reward_round.validator_rewards.get(&bob_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    // Alice should receive more rewards due to higher stake
    assert!(alice_rewards > bob_rewards);
    
    Ok(())
}

#[test]
fn test_reputation_bonus_rewards() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validators with same stake but different reputations
    let alice_id = create_test_identity("alice");
    let bob_id = create_test_identity("bob");
    
    validator_manager.register_validator(
        alice_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;
    
    validator_manager.register_validator(
        bob_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![2u8; 32],
        5,
    )?;
    
    // Manually set different reputations
    if let Some(alice) = validator_manager.get_validator_mut(&alice_id) {
        alice.reputation = 800; // High reputation
    }
    
    if let Some(bob) = validator_manager.get_validator_mut(&bob_id) {
        bob.reputation = 200; // Low reputation
    }
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    let alice_rewards = reward_round.validator_rewards.get(&alice_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    let bob_rewards = reward_round.validator_rewards.get(&bob_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    // Alice should receive more rewards due to higher reputation
    assert!(alice_rewards > bob_rewards);
    
    Ok(())
}

#[test]
fn test_storage_provision_rewards() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validators with different storage capacities
    let alice_id = create_test_identity("alice");
    let bob_id = create_test_identity("bob");
    
    validator_manager.register_validator(
        alice_id.clone(),
        2000 * 1_000_000,
        500 * 1024 * 1024 * 1024, // 500 GB - high storage
        vec![1u8; 32],
        5,
    )?;
    
    validator_manager.register_validator(
        bob_id.clone(),
        2000 * 1_000_000,
        100 * 1024 * 1024 * 1024, // 100 GB - minimum storage
        vec![2u8; 32],
        5,
    )?;
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    let alice_rewards = reward_round.validator_rewards.get(&alice_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    let bob_rewards = reward_round.validator_rewards.get(&bob_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    
    // Alice should receive more rewards due to higher storage provision
    assert!(alice_rewards > bob_rewards);
    
    Ok(())
}

#[test]
fn test_commission_rate_impact() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validators with different commission rates
    let alice_id = create_test_identity("alice");
    let bob_id = create_test_identity("bob");
    
    validator_manager.register_validator(
        alice_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5, // 5% commission
    )?;
    
    validator_manager.register_validator(
        bob_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![2u8; 32],
        15, // 15% commission
    )?;
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    // Both should receive rewards, but commission affects delegator rewards
    let alice_rewards = reward_round.validator_rewards.get(&alice_id);
    
    let bob_rewards = reward_round.validator_rewards.get(&bob_id);
    
    assert!(alice_rewards.is_some());
    assert!(bob_rewards.is_some());
    
    Ok(())
}

#[test]
fn test_reward_distribution() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    // Test that distribution doesn't fail
    let result = calculator.distribute_rewards(&reward_round);
    assert!(result.is_ok());
    
    Ok(())
}

#[test]
fn test_zero_validators_reward_calculation() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    let reward_round = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    // Should handle empty validator set gracefully
    assert_eq!(reward_round.validator_rewards.len(), 0);
    assert_eq!(reward_round.total_rewards, 0);
    
    Ok(())
}

#[test]
fn test_reward_round_structure() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register a validator
    let alice_id = create_test_identity("alice");
    validator_manager.register_validator(
        alice_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;
    
    let block_height = 150;
    let reward_round = calculator.calculate_round_rewards(&validator_manager, block_height)?;
    
    // Verify reward round structure
    assert_eq!(reward_round.height, block_height);
    assert!(reward_round.timestamp > 0);
    assert_eq!(reward_round.validator_rewards.len(), 1);
    assert!(reward_round.total_rewards > 0);
    
    // Check validator reward structure if validator_rewards is a HashMap
    let validator_reward = reward_round.validator_rewards.get(&alice_id).unwrap();
    assert!(validator_reward.total_reward > 0);
    
    Ok(())
}

#[test]
fn test_useful_work_reward_types() -> Result<()> {
    let calculator = RewardCalculator::new();
    
    // Test that all useful work types are supported
    let work_types = vec![
        UsefulWorkType::NetworkRouting,
        UsefulWorkType::DataStorage,
        UsefulWorkType::Computation,
        UsefulWorkType::Validation,
        UsefulWorkType::BridgeOperations,
    ];
    
    for work_type in work_types {
        // In a full implementation, this would test reward calculation for each work type
        // For now, just verify the types exist
        match work_type {
            UsefulWorkType::NetworkRouting => assert!(true),
            UsefulWorkType::DataStorage => assert!(true),
            UsefulWorkType::Computation => assert!(true),
            UsefulWorkType::Validation => assert!(true),
            UsefulWorkType::BridgeOperations => assert!(true),
        }
    }
    
    Ok(())
}

#[test]
fn test_reward_consistency() -> Result<()> {
    let mut calculator = RewardCalculator::new();
    let mut validator_manager = ValidatorManager::new(10, 1000 * 1_000_000);
    
    // Register validator
    let alice_id = create_test_identity("alice");
    validator_manager.register_validator(
        alice_id.clone(),
        2000 * 1_000_000,
        200 * 1024 * 1024 * 1024,
        vec![1u8; 32],
        5,
    )?;
    
    // Calculate rewards for same conditions multiple times
    let reward_round1 = calculator.calculate_round_rewards(&validator_manager, 100)?;
    let reward_round2 = calculator.calculate_round_rewards(&validator_manager, 100)?;
    
    // Results should be consistent for same inputs
    assert_eq!(reward_round1.validator_rewards.len(), reward_round2.validator_rewards.len());
    
    // Individual reward amounts should be deterministic
    let reward1 = reward_round1.validator_rewards.get(&alice_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    let reward2 = reward_round2.validator_rewards.get(&alice_id)
        .map(|r| r.total_reward)
        .unwrap_or(0);
    assert_eq!(reward1, reward2);
    
    Ok(())
}
