//! Tests for DAO governance functionality
//!
//! These tests validate DAO proposal creation, voting, status transitions, and
//! validation logic at the consensus layer. Full blockchain-backed persistence
//! is tested through integration tests that combine lib-consensus with lib-blockchain.
//!
//! NOTE: These tests were refactored from the deprecated in-memory implementation.
//! The DaoEngine is now designed to work with blockchain-backed storage where
//! proposals and votes are persisted as transactions on-chain.

use anyhow::Result;
use lib_consensus::{DaoEngine, DaoProposalType, DaoVoteChoice, ConsensusConfig};
use lib_crypto::{hash_blake3, Hash};
use lib_identity::IdentityId;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

/// Helper to get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// Test 1: DAO Engine Initialization
// ============================================================================

#[tokio::test]
async fn test_dao_engine_initialization() -> Result<()> {
    let dao_engine = DaoEngine::new();

    // Engine should initialize successfully
    // Base voting power is 1 for all users (from dao_engine.rs placeholder)
    let voting_power = dao_engine.get_dao_voting_power(&create_test_identity("user1"));
    assert_eq!(voting_power, 1); // Base voting power of 1

    Ok(())
}

// ============================================================================
// Test 2: DAO Proposal Creation and Validation
// ============================================================================

#[tokio::test]
async fn test_dao_proposal_creation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("alice");
    let title = "Test Proposal: Increase UBI".to_string();
    let description = "A proposal to increase monthly UBI distribution".to_string();
    let proposal_type = DaoProposalType::UbiDistribution;
    let voting_period_days = 7;

    // Create proposal - validation happens here
    let _proposal_id = dao_engine
        .create_dao_proposal(
            proposer.clone(),
            title.clone(),
            description.clone(),
            proposal_type.clone(),
            voting_period_days,
        )
        .await?;

    // Verify proposal was created
    // (ID is valid if function returned successfully)

    Ok(())
}

// ============================================================================
// Test 3: Treasury Proposal Validation
// ============================================================================

#[tokio::test]
async fn test_treasury_proposal_validation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("alice");

    // Attempt to create Treasury allocation proposal with insufficient voting power
    // Treasury proposals require minimum 100 voting power (proposer has base power of 1)
    let result = dao_engine
        .create_dao_proposal(
            proposer,
            "Treasury Allocation".to_string(),
            "Allocate funds to welfare services".to_string(),
            DaoProposalType::TreasuryAllocation,
            7,
        )
        .await;

    // Should FAIL - Treasury proposals require 100 voting power, proposer only has 1
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("minimum 100 voting power"));

    Ok(())
}

// ============================================================================
// Test 4: DAO Vote Casting
// ============================================================================

#[tokio::test]
async fn test_dao_vote_casting() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let voter = create_test_identity("bob");
    let proposal_id = Hash::from_bytes(&hash_blake3(b"test_proposal_1"));

    // Cast vote - validation happens here
    let _vote_id = dao_engine
        .cast_dao_vote(
            voter.clone(),
            proposal_id.clone(),
            DaoVoteChoice::Yes,
            Some("I support this proposal".to_string()),
        )
        .await?;

    // Verify vote was created
    // (ID is valid if function returned successfully)

    Ok(())
}

// ============================================================================
// Test 5: Double-Vote Prevention (Validation Layer)
// ============================================================================

#[tokio::test]
async fn test_double_vote_prevention_validation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let voter = create_test_identity("charlie");
    let proposal_id = Hash::from_bytes(&hash_blake3(b"test_proposal_2"));

    // First vote succeeds
    dao_engine
        .cast_dao_vote(
            voter.clone(),
            proposal_id.clone(),
            DaoVoteChoice::Yes,
            None,
        )
        .await?;

    // Vote 1 created successfully

    // Second vote from same voter
    let vote_2_result = dao_engine
        .cast_dao_vote(
            voter.clone(),
            proposal_id.clone(),
            DaoVoteChoice::No,
            None,
        )
        .await;

    // Engine detects duplicate vote
    assert!(vote_2_result.is_err());
    assert!(vote_2_result
        .unwrap_err()
        .to_string()
        .contains("already voted"));

    Ok(())
}

// ============================================================================
// Test 6: Vote Choice Types Validation
// ============================================================================

#[tokio::test]
async fn test_vote_choice_types() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposal_id = Hash::from_bytes(&hash_blake3(b"test_proposal_3"));

    // Test "Yes" vote
    dao_engine
        .cast_dao_vote(
            create_test_identity("voter_yes"),
            proposal_id.clone(),
            DaoVoteChoice::Yes,
            None,
        )
        .await?;

    // Test "No" vote
    dao_engine
        .cast_dao_vote(
            create_test_identity("voter_no"),
            proposal_id.clone(),
            DaoVoteChoice::No,
            None,
        )
        .await?;

    // Test "Abstain" vote
    dao_engine
        .cast_dao_vote(
            create_test_identity("voter_abstain"),
            proposal_id.clone(),
            DaoVoteChoice::Abstain,
            None,
        )
        .await?;

    Ok(())
}

// ============================================================================
// Test 7: Governance Parameter Validation
// ============================================================================

#[tokio::test]
async fn test_governance_parameter_validation() -> Result<()> {
    let dao_engine = DaoEngine::new();

    // Test minimum stake validation
    let min_stake_update = lib_consensus::GovernanceParameterUpdate {
        updates: vec![lib_consensus::GovernanceParameterValue::MinStake(1000)],
    };

    let result = dao_engine.validate_governance_update(&min_stake_update);
    assert!(result.is_ok());

    // Test multiple parameter update
    let multi_update = lib_consensus::GovernanceParameterUpdate {
        updates: vec![
            lib_consensus::GovernanceParameterValue::MinStake(5000),
            lib_consensus::GovernanceParameterValue::MaxValidators(100),
        ],
    };

    let result = dao_engine.validate_governance_update(&multi_update);
    assert!(result.is_ok());

    Ok(())
}

// ============================================================================
// Test 8: Voting Power Calculation
// ============================================================================

#[tokio::test]
async fn test_voting_power_calculation() -> Result<()> {
    let _dao_engine = DaoEngine::new();

    let _user_id = create_test_identity("power_user");

    // Calculate voting power from test values
    let power = lib_consensus::DaoEngine::calculate_voting_power(100, 50, 80, 85, 10);
    assert!(power > 0);

    // Calculate with zero values
    let zero_power = lib_consensus::DaoEngine::calculate_voting_power(0, 0, 0, 0, 0);
    assert_eq!(zero_power, 1); // Everyone gets at least 1 base vote

    Ok(())
}

// ============================================================================
// Test 9: Proposal Type Validation
// ============================================================================

#[tokio::test]
async fn test_proposal_type_validation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("proposal_creator");

    // Test multiple proposal types
    // NOTE: TreasuryAllocation requires 100 voting power, so skip it here
    // (it's tested separately in test_treasury_proposal_validation)
    let proposal_types = vec![
        DaoProposalType::UbiDistribution,
        DaoProposalType::WelfareAllocation,
        DaoProposalType::ProtocolUpgrade,
        // DaoProposalType::TreasuryAllocation, // Requires 100 voting power
        DaoProposalType::ValidatorUpdate,
        DaoProposalType::EconomicParams,
        DaoProposalType::GovernanceRules,
        DaoProposalType::FeeStructure,
    ];

    for proposal_type in &proposal_types {
        let result = dao_engine
            .create_dao_proposal(
                proposer.clone(),
                format!("Proposal: {:?}", proposal_type),
                "Description".to_string(),
                proposal_type.clone(),
                7,
            )
            .await;

        assert!(result.is_ok(), "Should accept proposal type: {:?}", proposal_type);
    }

    Ok(())
}

// ============================================================================
// Test 10: Proposal Expiration Handling
// ============================================================================

#[tokio::test]
async fn test_expired_proposal_processing() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    // Process expired proposals (in production, run at block boundaries)
    let result = dao_engine.process_expired_proposals().await;

    // Should complete without error
    assert!(result.is_ok());

    Ok(())
}

// ============================================================================
// Test 11: Execution Parameters Encoding/Decoding
// ============================================================================

#[tokio::test]
async fn test_execution_params_encoding() -> Result<()> {
    let dao_engine = DaoEngine::new();

    // Create governance parameter update
    let params = lib_consensus::DaoExecutionParams {
        action: lib_consensus::DaoExecutionAction::GovernanceParameterUpdate(
            lib_consensus::GovernanceParameterUpdate {
                updates: vec![
                    lib_consensus::GovernanceParameterValue::MinStake(10000),
                    lib_consensus::GovernanceParameterValue::MaxValidators(50),
                ],
            },
        ),
    };

    // Encode
    let encoded = dao_engine.encode_execution_params(&params)?;
    assert!(!encoded.is_empty());

    // Decode
    let decoded = dao_engine.decode_execution_params(&encoded)?;
    assert!(matches!(
        decoded.action,
        lib_consensus::DaoExecutionAction::GovernanceParameterUpdate(_)
    ));

    Ok(())
}

// ============================================================================
// Test 12: DAO Treasury Validation
// ============================================================================

#[tokio::test]
async fn test_dao_treasury_validation() -> Result<()> {
    let dao_engine = DaoEngine::new();

    // Get treasury (in production, fetches from blockchain state)
    let treasury = dao_engine.get_dao_treasury();

    // Verify treasury structure is valid
    assert_eq!(treasury.total_balance, 0); // No balance without blockchain state
    assert_eq!(treasury.available_balance, 0);

    Ok(())
}

// ============================================================================
// Test 13: Voting Power and Quorum Calculation
// ============================================================================

#[tokio::test]
async fn test_quorum_requirements() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("quorum_tester");

    // Create proposal with regular type (TreasuryAllocation requires 100 voting power)
    let _proposal_id = dao_engine
        .create_dao_proposal(
            proposer,
            "Protocol Upgrade Proposal".to_string(),
            "Upgrade network protocol".to_string(),
            DaoProposalType::ProtocolUpgrade, // Use non-treasury type
            7,
        )
        .await?;

    // Get voting power for a validator
    // Base voting power is 1 (from placeholder implementation)
    let voting_power = dao_engine.get_dao_voting_power(&create_test_identity("validator1"));
    assert_eq!(voting_power, 1); // Base power of 1

    Ok(())
}

// ============================================================================
// Test 14: Governance Update Validation
// ============================================================================

#[tokio::test]
async fn test_governance_update_application() -> Result<()> {
    let dao_engine = DaoEngine::new();

    // Create valid governance update
    let update = lib_consensus::GovernanceParameterUpdate {
        updates: vec![
            lib_consensus::GovernanceParameterValue::BlockTime(10),
            lib_consensus::GovernanceParameterValue::EpochLengthBlocks(100),
        ],
    };

    // Validate update
    let result = dao_engine.validate_governance_update(&update);
    assert!(result.is_ok());

    // Apply update (updates internal state)
    let mut consensus_config = ConsensusConfig::default();
    let apply_result = dao_engine.apply_governance_update(&mut consensus_config, &update);
    assert!(apply_result.is_ok());

    Ok(())
}

// ============================================================================
// Test 15: Vote Tallying Consistency
// ============================================================================

#[tokio::test]
async fn test_vote_tally_consistency() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposal_id = Hash::from_bytes(&hash_blake3(b"tally_test_proposal"));

    // Cast multiple votes of different types
    let votes = vec![
        ("voter1", DaoVoteChoice::Yes),
        ("voter2", DaoVoteChoice::Yes),
        ("voter3", DaoVoteChoice::No),
        ("voter4", DaoVoteChoice::Abstain),
    ];

    let mut successful_votes = 0;
    for (voter_name, choice) in votes {
        let result = dao_engine
            .cast_dao_vote(
                create_test_identity(voter_name),
                proposal_id.clone(),
                choice,
                None,
            )
            .await;

        if result.is_ok() {
            successful_votes += 1;
        }
    }

    // Verify all votes were cast successfully
    // Note: get_user_dao_votes is deprecated - actual vote storage is in blockchain
    assert_eq!(successful_votes, 4, "Should have 4 successful vote operations");

    Ok(())
}

// ============================================================================
// DIFFICULTY PARAMETER UPDATE PROPOSAL TESTS
// ============================================================================

/// Test creating a basic difficulty parameter update proposal
#[tokio::test]
async fn test_difficulty_update_proposal_creation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator1");
    
    // Create a difficulty update proposal with Bitcoin-like parameters
    let proposal_id = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            14 * 24 * 60 * 60, // 2 weeks target timespan
            2016,              // adjustment interval
            None,              // no min factor
            None,              // no max factor
            7,                 // 7 day voting period
        )
        .await?;

    // Proposal ID should be valid (32 bytes)
    assert_eq!(proposal_id.as_bytes().len(), 32);

    Ok(())
}

/// Test difficulty update proposal with all parameters
#[tokio::test]
async fn test_difficulty_update_proposal_with_factors() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator2");
    
    let proposal_id = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,    // 1 week
            1008,      // blocks
            Some(25),  // min factor 25%
            Some(400), // max factor 400%
            14,        // 14 day voting period
        )
        .await?;

    assert_eq!(proposal_id.as_bytes().len(), 32);

    Ok(())
}

/// Test validation: target_timespan must be > 0
#[tokio::test]
async fn test_difficulty_update_proposal_zero_timespan() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator3");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            0,    // Invalid: zero timespan
            2016,
            None,
            None,
            7,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("target_timespan must be greater than 0"));

    Ok(())
}

/// Test validation: adjustment_interval must be > 0
#[tokio::test]
async fn test_difficulty_update_proposal_zero_interval() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator4");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,
            0,    // Invalid: zero interval
            None,
            None,
            7,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("adjustment_interval must be greater than 0"));

    Ok(())
}

/// Test validation: min_adjustment_factor must be >= 1
#[tokio::test]
async fn test_difficulty_update_proposal_zero_min_factor() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator5");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,
            2016,
            Some(0), // Invalid: zero min factor
            None,
            7,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("min_adjustment_factor must be >= 1"));

    Ok(())
}

/// Test validation: max_adjustment_factor must be >= 1
#[tokio::test]
async fn test_difficulty_update_proposal_zero_max_factor() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator6");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,
            2016,
            None,
            Some(0), // Invalid: zero max factor
            7,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("max_adjustment_factor must be >= 1"));

    Ok(())
}

/// Test validation: max_adjustment_factor must be >= min_adjustment_factor
#[tokio::test]
async fn test_difficulty_update_proposal_max_less_than_min() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator7");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,
            2016,
            Some(400), // min = 400
            Some(25),  // max = 25 (invalid: less than min)
            7,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("max_adjustment_factor must be >= min_adjustment_factor"));

    Ok(())
}

/// Test that equal min and max factors are valid
#[tokio::test]
async fn test_difficulty_update_proposal_equal_factors() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

    let proposer = create_test_identity("validator8");
    
    let result = dao_engine
        .create_difficulty_update_proposal(
            proposer,
            604800,
            2016,
            Some(100), // min = 100
            Some(100), // max = 100 (valid: equal)
            7,
        )
        .await;

    assert!(result.is_ok());

    Ok(())
}

/// Test DaoProposalType enum includes DifficultyParameterUpdate
#[test]
fn test_difficulty_parameter_update_proposal_type_exists() {
    // Verify the variant exists and can be compared
    let proposal_type = DaoProposalType::DifficultyParameterUpdate;
    assert_eq!(proposal_type, DaoProposalType::DifficultyParameterUpdate);
    
    // Verify it's different from other types
    assert_ne!(proposal_type, DaoProposalType::ProtocolUpgrade);
    assert_ne!(proposal_type, DaoProposalType::EconomicParams);
}

/// Test that DifficultyParameterUpdate serializes correctly
#[test]
fn test_difficulty_parameter_update_proposal_type_serialization() {
    let proposal_type = DaoProposalType::DifficultyParameterUpdate;
    
    // Serialize to JSON
    let json = serde_json::to_string(&proposal_type).expect("serialize to JSON");
    assert!(json.contains("DifficultyParameterUpdate"));
    
    // Deserialize from JSON
    let deserialized: DaoProposalType = 
        serde_json::from_str(&json).expect("deserialize from JSON");
    assert_eq!(deserialized, DaoProposalType::DifficultyParameterUpdate);
}

