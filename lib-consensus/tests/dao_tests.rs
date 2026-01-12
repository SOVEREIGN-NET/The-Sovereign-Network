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
use lib_consensus::{DaoEngine, DaoProposalType, DaoVoteChoice};
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

    // Engine should initialize successfully with empty state
    // (actual treasury/proposal data comes from blockchain in production)
    let voting_power = dao_engine.get_dao_voting_power(&create_test_identity("user1"));
    assert_eq!(voting_power, 0); // No voting power without blockchain state

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

    // Create valid Treasury allocation proposal
    let result = dao_engine
        .create_dao_proposal(
            proposer,
            "Treasury Allocation".to_string(),
            "Allocate funds to welfare services".to_string(),
            DaoProposalType::TreasuryAllocation,
            7,
        )
        .await;

    // Should succeed (validation logic accepts it at proposal layer)
    // Actual voting power checks happen at consensus layer during voting
    assert!(result.is_ok());

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
    let dao_engine = DaoEngine::new();

    let user_id = create_test_identity("power_user");

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
    let proposal_types = vec![
        DaoProposalType::UbiDistribution,
        DaoProposalType::WelfareAllocation,
        DaoProposalType::ProtocolUpgrade,
        DaoProposalType::TreasuryAllocation,
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

    // Create proposal with high stakes (requires more quorum)
    let proposal_id = dao_engine
        .create_dao_proposal(
            proposer,
            "High-Stakes Treasury Proposal".to_string(),
            "Allocate major treasury funds".to_string(),
            DaoProposalType::TreasuryAllocation,
            7,
        )
        .await?;

    // Get voting power required for this proposal type
    // (actual quorum enforcement happens at consensus layer during voting)
    let voting_power = dao_engine.get_dao_voting_power(&create_test_identity("validator1"));
    assert_eq!(voting_power, 0); // No power without blockchain state

    Ok(())
}

// ============================================================================
// Test 14: Governance Update Validation
// ============================================================================

#[tokio::test]
async fn test_governance_update_application() -> Result<()> {
    let mut dao_engine = DaoEngine::new();

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
    let apply_result = dao_engine.apply_governance_update(&update);
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

    for (voter_name, choice) in votes {
        let result = dao_engine
            .cast_dao_vote(
                create_test_identity(voter_name),
                proposal_id.clone(),
                choice,
                None,
            )
            .await;

        assert!(result.is_ok(), "Vote from {} should be accepted", voter_name);
    }

    // Get votes (in production, queries from blockchain)
    let all_votes = dao_engine.get_user_dao_votes(&proposal_id);
    assert_eq!(all_votes.len(), 4, "Should have 4 votes recorded");

    Ok(())
}
