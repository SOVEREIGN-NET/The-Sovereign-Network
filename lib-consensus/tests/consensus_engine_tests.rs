//! Integration tests for the main consensus engine

use anyhow::Result;
use lib_consensus::{ConsensusConfig, ConsensusEngine, ConsensusError, ConsensusType, NoOpBroadcaster};
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::sync::Arc;

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

/// Helper function to create test consensus config
fn create_test_config() -> ConsensusConfig {
    ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000,           // 1000 ZHTP
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
        max_validators: 10,
        block_time: 1, // Fast for testing
        epoch_length_blocks: 100,
        propose_timeout: 100,
        prevote_timeout: 50,
        precommit_timeout: 50,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: true, // Enable development mode for tests
    }
}

#[tokio::test]
async fn test_consensus_engine_initialization() -> Result<()> {
    let config = create_test_config();
    let consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    assert_eq!(consensus_engine.current_round().height, 0);
    assert_eq!(consensus_engine.current_round().round, 0);
    assert_eq!(
        consensus_engine
            .validator_manager()
            .get_validator_stats()
            .total_validators,
        0
    );

    Ok(())
}

#[tokio::test]
async fn test_validator_registration_success() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    let identity = create_test_identity("alice");
    let stake = 2000 * 1_000_000; // 2000 ZHTP
    let storage = 200 * 1024 * 1024 * 1024; // 200 GB
    let consensus_key = vec![1u8; 32];
    let commission_rate = 5;

    let result = consensus_engine
        .register_validator(
            identity.clone(),
            stake,
            storage,
            consensus_key,
            commission_rate,
            true, // Genesis validator
        )
        .await;

    assert!(result.is_ok());

    let validator = consensus_engine
        .validator_manager()
        .get_validator(&identity);
    assert!(validator.is_some());
    assert_eq!(validator.unwrap().stake, stake);
    assert_eq!(validator.unwrap().storage_provided, storage);

    Ok(())
}

#[tokio::test]
async fn test_validator_registration_insufficient_stake() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    let identity = create_test_identity("bob");
    let insufficient_stake = 500 * 1_000_000; // 500 ZHTP (below minimum)
    let storage = 200 * 1024 * 1024 * 1024;
    let consensus_key = vec![2u8; 32];
    let commission_rate = 5;

    let result = consensus_engine
        .register_validator(
            identity,
            insufficient_stake,
            storage,
            consensus_key,
            commission_rate,
            false,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ConsensusError::ValidatorError(msg) => {
            assert!(msg.contains("Insufficient stake"));
        }
        _ => panic!("Expected ValidatorError for insufficient stake"),
    }

    Ok(())
}

#[tokio::test]
async fn test_validator_registration_insufficient_storage() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    let identity = create_test_identity("charlie");
    let stake = 2000 * 1_000_000;
    let insufficient_storage = 50 * 1024 * 1024 * 1024; // 50 GB (below minimum)
    let consensus_key = vec![3u8; 32];
    let commission_rate = 5;

    let result = consensus_engine
        .register_validator(
            identity,
            stake,
            insufficient_storage,
            consensus_key,
            commission_rate,
            false,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ConsensusError::ValidatorError(msg) => {
            assert!(msg.contains("Insufficient storage"));
        }
        _ => panic!("Expected ValidatorError for insufficient storage"),
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_validator_registration() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    let validators = vec![
        ("alice", 2000 * 1_000_000, 200 * 1024 * 1024 * 1024),
        ("bob", 1500 * 1_000_000, 150 * 1024 * 1024 * 1024),
        ("charlie", 1000 * 1_000_000, 100 * 1024 * 1024 * 1024),
    ];

    for (i, (name, stake, storage)) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        let consensus_key = vec![(i + 1) as u8; 32];
        let commission_rate = 5;

        let result = consensus_engine
            .register_validator(
                identity,
                *stake,
                *storage,
                consensus_key,
                commission_rate,
                i == 0, // First is genesis
            )
            .await;

        assert!(result.is_ok());
    }

    let stats = consensus_engine.validator_manager().get_validator_stats();
    assert_eq!(stats.total_validators, 3);
    assert_eq!(stats.active_validators, 3);
    assert!(stats.total_stake > 0);

    Ok(())
}

#[tokio::test]
async fn test_proposer_selection() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    // Register multiple validators
    let validators = vec!["alice", "bob", "charlie"];
    for (i, name) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        let consensus_key = vec![(i + 1) as u8; 32];

        consensus_engine
            .register_validator(
                identity,
                2000 * 1_000_000,
                200 * 1024 * 1024 * 1024,
                consensus_key,
                5,
                i == 0,
            )
            .await?;
    }

    // Test proposer selection for different heights/rounds
    let proposer1 = consensus_engine.validator_manager().select_proposer(1, 0);
    let proposer2 = consensus_engine.validator_manager().select_proposer(2, 0);
    let proposer3 = consensus_engine.validator_manager().select_proposer(1, 1);

    assert!(proposer1.is_some());
    assert!(proposer2.is_some());
    assert!(proposer3.is_some());

    // Different heights should potentially select different proposers
    // (though with 3 validators, some may repeat)

    Ok(())
}

#[tokio::test]
async fn test_byzantine_threshold_calculation() -> Result<()> {
    let config = create_test_config();
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    // Register validators with different stakes
    let validators = vec![
        ("alice", 1000 * 1_000_000),
        ("bob", 2000 * 1_000_000),
        ("charlie", 3000 * 1_000_000),
    ];

    for (i, (name, stake)) in validators.iter().enumerate() {
        let identity = create_test_identity(name);
        let consensus_key = vec![(i + 1) as u8; 32];

        consensus_engine
            .register_validator(
                identity,
                *stake,
                200 * 1024 * 1024 * 1024,
                consensus_key,
                5,
                i == 0,
            )
            .await?;
    }

    let total_voting_power = consensus_engine
        .validator_manager()
        .get_total_voting_power();
    let byzantine_threshold = consensus_engine
        .validator_manager()
        .get_byzantine_threshold();

    // Byzantine threshold should be > 2/3 of total voting power
    let expected_threshold = (total_voting_power * 2) / 3 + 1;
    assert_eq!(byzantine_threshold, expected_threshold);

    // Test threshold checking
    assert!(consensus_engine
        .validator_manager()
        .meets_byzantine_threshold(byzantine_threshold));
    assert!(!consensus_engine
        .validator_manager()
        .meets_byzantine_threshold(byzantine_threshold - 1));

    Ok(())
}

#[tokio::test]
async fn test_insufficient_validators_for_consensus() -> Result<()> {
    let mut config = create_test_config();
    config.development_mode = false; // Disable development mode to test BFT requirements
    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    // Register only one validator (insufficient for BFT)
    let identity = create_test_identity("alice");
    consensus_engine
        .register_validator(
            identity,
            2000 * 1_000_000,
            200 * 1024 * 1024 * 1024,
            vec![1u8; 32],
            5,
            true,
        )
        .await?;

    // Should not have sufficient validators for consensus
    assert!(!consensus_engine
        .validator_manager()
        .has_sufficient_validators());

    // Add more validators
    for i in 2..=4 {
        let identity = create_test_identity(&format!("validator_{}", i));
        consensus_engine
            .register_validator(
                identity,
                1000 * 1_000_000,
                100 * 1024 * 1024 * 1024,
                vec![i as u8; 32],
                5,
                false,
            )
            .await?;
    }

    // Now should have sufficient validators
    assert!(consensus_engine
        .validator_manager()
        .has_sufficient_validators());

    Ok(())
}

#[tokio::test]
async fn test_consensus_round_initialization() -> Result<()> {
    let config = create_test_config();
    let consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    let current_round = consensus_engine.current_round();

    // Initial round should be at height 0, round 0
    assert_eq!(current_round.height, 0);
    assert_eq!(current_round.round, 0);
    assert!(current_round.proposer.is_none());
    assert!(current_round.proposals.is_empty());
    assert!(current_round.votes.is_empty());
    assert!(!current_round.timed_out);
    assert!(current_round.locked_proposal.is_none());
    assert!(current_round.valid_proposal.is_none());

    Ok(())
}

#[tokio::test]
async fn test_maximum_validator_limit() -> Result<()> {
    let mut config = create_test_config();
    config.max_validators = 2; // Set low limit for testing

    let mut consensus_engine = ConsensusEngine::new(config, Arc::new(NoOpBroadcaster))?;

    // Register up to the limit
    for i in 1..=2 {
        let identity = create_test_identity(&format!("validator_{}", i));
        let result = consensus_engine
            .register_validator(
                identity,
                1000 * 1_000_000,
                100 * 1024 * 1024 * 1024,
                vec![i as u8; 32],
                5,
                i == 1,
            )
            .await;
        assert!(result.is_ok());
    }

    // Try to register one more (should fail)
    let identity = create_test_identity("extra_validator");
    let result = consensus_engine
        .register_validator(
            identity,
            1000 * 1_000_000,
            100 * 1024 * 1024 * 1024,
            vec![99u8; 32],
            5,
            false,
        )
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ConsensusError::ValidatorError(msg) => {
            assert!(msg.contains("Maximum validator limit"));
        }
        _ => panic!("Expected ValidatorError for maximum limit"),
    }

    Ok(())
}
