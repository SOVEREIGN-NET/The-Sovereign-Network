//! Tests for DAO governance functionality
//!
//! NOTE: These tests are currently IGNORED and need refactoring.
//!
//! PROBLEM: DaoEngine was refactored to be blockchain-backed. The old in-memory
//! methods (get_dao_treasury, get_dao_proposals, get_dao_proposal_by_id) are now
//! deprecated and return empty data. They expect data to come from blockchain state.
//!
//! REQUIRED REFACTORING:
//! - Replace DaoEngine-only tests with full blockchain integration tests
//! - Test flow should be: create proposal → add to blockchain → query from blockchain
//! - Use lib_blockchain::Blockchain instance instead of standalone DaoEngine
//! - Test real DAO transaction types (DaoProposal, DaoVote, DaoExecution)
//!
//! TRACKING: Issue #XXX - Refactor DAO tests for blockchain-backed architecture

use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use lib_consensus::{
    DaoEngine, DaoProposalType, DaoVoteChoice, DaoProposalStatus
};
use lib_identity::IdentityId;
use lib_crypto::{Hash, hash_blake3};

/// Helper function to create test identity
fn create_test_identity(name: &str) -> IdentityId {
    Hash::from_bytes(&hash_blake3(name.as_bytes()))
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_dao_engine_initialization() {
    let dao_engine = DaoEngine::new();
    
    let treasury = dao_engine.get_dao_treasury();
    assert!(treasury.total_balance > 0); // Should have bootstrap funds
    assert!(treasury.available_balance > 0);
    
    let proposals = dao_engine.get_dao_proposals();
    assert_eq!(proposals.len(), 0); // Should start with no proposals
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_dao_proposal_creation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let proposer = create_test_identity("alice");
    let title = "Test Proposal".to_string();
    let description = "A test proposal for governance".to_string();
    let proposal_type = DaoProposalType::ProtocolUpgrade;
    let voting_period = 7;
    
    let proposal_id = dao_engine.create_dao_proposal(
        proposer.clone(),
        title.clone(),
        description.clone(),
        proposal_type.clone(),
        voting_period,
    ).await?;
    
    let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id);
    assert!(proposal.is_some());
    
    let proposal = proposal.unwrap();
    assert_eq!(proposal.title, title);
    assert_eq!(proposal.description, description);
    assert_eq!(proposal.proposer, proposer);
    assert_eq!(proposal.proposal_type, proposal_type);
    assert_eq!(proposal.status, DaoProposalStatus::Active);
    assert!(proposal.voting_end_time > proposal.voting_start_time);
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_treasury_proposal_validation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let proposer = create_test_identity("low_power_user");
    
    // Should fail for treasury proposals with insufficient voting power
    let result = dao_engine.create_dao_proposal(
        proposer,
        "Treasury Spending".to_string(),
        "Spend treasury funds".to_string(),
        DaoProposalType::TreasuryAllocation,
        7,
    ).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("minimum 100 voting power"));
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_dao_vote_casting() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    // Create a proposal
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Test Proposal".to_string(),
        "A test proposal".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    // Cast a vote
    let voter = create_test_identity("bob");
    let vote_choice = DaoVoteChoice::Yes;
    let justification = Some("I support this proposal".to_string());
    
    let vote_id = dao_engine.cast_dao_vote(
        voter.clone(),
        proposal_id.clone(),
        vote_choice.clone(),
        justification,
    ).await?;
    
    // Check that vote was recorded
    let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();
    assert_eq!(proposal.vote_tally.yes_votes, 1);
    assert_eq!(proposal.vote_tally.total_votes, 1);
    assert!(proposal.vote_tally.weighted_yes > 0);
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_duplicate_voting_prevention() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    // Create a proposal
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Test Proposal".to_string(),
        "A test proposal".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    let voter = create_test_identity("bob");
    
    // Cast first vote (should succeed)
    let result1 = dao_engine.cast_dao_vote(
        voter.clone(),
        proposal_id.clone(),
        DaoVoteChoice::Yes,
        None,
    ).await;
    assert!(result1.is_ok());
    
    // Cast second vote (should fail)
    let result2 = dao_engine.cast_dao_vote(
        voter,
        proposal_id,
        DaoVoteChoice::No,
        None,
    ).await;
    assert!(result2.is_err());
    assert!(result2.unwrap_err().to_string().contains("already voted"));
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_voting_on_nonexistent_proposal() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let voter = create_test_identity("alice");
    let fake_proposal_id = Hash::from_bytes(&hash_blake3(b"fake_proposal"));
    
    let result = dao_engine.cast_dao_vote(
        voter,
        fake_proposal_id,
        DaoVoteChoice::Yes,
        None,
    ).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Proposal not found"));
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_vote_tally_calculation() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    // Create a proposal
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Vote Tally Test".to_string(),
        "Testing vote tallying".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    // Cast multiple votes
    let voters = vec![
        ("bob", DaoVoteChoice::Yes),
        ("charlie", DaoVoteChoice::Yes),
        ("dave", DaoVoteChoice::No),
        ("eve", DaoVoteChoice::Abstain),
    ];
    
    for (name, choice) in voters {
        let voter = create_test_identity(name);
        dao_engine.cast_dao_vote(
            voter,
            proposal_id.clone(),
            choice,
            None,
        ).await?;
    }
    
    let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();
    assert_eq!(proposal.vote_tally.yes_votes, 2);
    assert_eq!(proposal.vote_tally.no_votes, 1);
    assert_eq!(proposal.vote_tally.abstain_votes, 1);
    assert_eq!(proposal.vote_tally.total_votes, 4);
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_dao_voting_power() {
    let dao_engine = DaoEngine::new();
    
    let user = create_test_identity("alice");
    let voting_power = dao_engine.get_dao_voting_power(&user);
    
    // All users should have at least 1 voting power
    assert!(voting_power >= 1);
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_treasury_state() {
    let dao_engine = DaoEngine::new();
    
    let treasury = dao_engine.get_dao_treasury();
    
    // Treasury should be initialized with bootstrap funds
    assert!(treasury.total_balance > 0);
    assert!(treasury.available_balance > 0);
    assert!(treasury.reserved_funds > 0);
    assert!(!treasury.transaction_history.is_empty()); // Bootstrap transaction
    
    // Debug the treasury state
    println!("Treasury Debug:");
    println!("  Total Balance: {}", treasury.total_balance);
    println!("  Available Balance: {}", treasury.available_balance);
    println!("  Allocated Funds: {}", treasury.allocated_funds);
    println!("  Reserved Funds: {}", treasury.reserved_funds);
    println!("  Sum: {}", treasury.available_balance + treasury.allocated_funds + treasury.reserved_funds);
    
    // For now, just verify that total_balance is not less than the individual components
    assert!(treasury.total_balance >= treasury.available_balance);
    assert!(treasury.total_balance >= treasury.allocated_funds);
    assert!(treasury.total_balance >= treasury.reserved_funds);
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_proposal_quorum_requirements() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let proposer = create_test_identity("alice");
    
    // Test different proposal types have different quorum requirements
    let treasury_proposal = dao_engine.create_dao_proposal(
        proposer.clone(),
        "Treasury Test".to_string(),
        "Testing treasury quorum. amount: 1000".to_string(),
        DaoProposalType::TreasuryAllocation,
        7,
    ).await;
    
    // Treasury proposals should have higher quorum requirements
    if let Ok(proposal_id) = treasury_proposal {
        let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();
        assert!(proposal.quorum_required >= 20); // At least 20% for treasury
    }
    
    let protocol_proposal = dao_engine.create_dao_proposal(
        proposer,
        "Protocol Test".to_string(),
        "Testing protocol quorum".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    let proposal = dao_engine.get_dao_proposal_by_id(&protocol_proposal).unwrap();
    assert!(proposal.quorum_required >= 20); // Protocol changes need high quorum
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_expired_proposal_processing() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    // Create a proposal with very short voting period for testing
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Quick Proposal".to_string(),
        "A proposal that expires quickly".to_string(),
        DaoProposalType::ProtocolUpgrade,
        0, // Very short voting period
    ).await?;
    
    // Manually set the voting end time to past
    let _ = dao_engine.get_dao_proposals(); // Deprecated path retained for compatibility
    
    // Process expired proposals
    let result = dao_engine.process_expired_proposals().await;
    assert!(result.is_ok());
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_vote_choice_types() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Vote Types Test".to_string(),
        "Testing different vote types".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    // Test all vote choice types
    let vote_choices = vec![
        ("voter1", DaoVoteChoice::Yes),
        ("voter2", DaoVoteChoice::No),
        ("voter3", DaoVoteChoice::Abstain),
    ];
    
    for (name, choice) in vote_choices {
        let voter = create_test_identity(name);
        let result = dao_engine.cast_dao_vote(
            voter,
            proposal_id.clone(),
            choice,
            Some(format!("Vote from {}", name)),
        ).await;
        assert!(result.is_ok());
    }
    
    let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();
    assert_eq!(proposal.vote_tally.yes_votes, 1);
    assert_eq!(proposal.vote_tally.no_votes, 1);
    assert_eq!(proposal.vote_tally.abstain_votes, 1);
    assert_eq!(proposal.vote_tally.total_votes, 3);
    
    Ok(())
}

#[tokio::test]
#[ignore = "DEPRECATED: DaoEngine refactored to blockchain-backed - test needs rewrite with Blockchain instance"]
async fn test_proposal_status_transitions() -> Result<()> {
    let mut dao_engine = DaoEngine::new();
    
    let proposer = create_test_identity("alice");
    let proposal_id = dao_engine.create_dao_proposal(
        proposer,
        "Status Test".to_string(),
        "Testing proposal status transitions".to_string(),
        DaoProposalType::ProtocolUpgrade,
        7,
    ).await?;
    
    // Initially should be Active
    let proposal = dao_engine.get_dao_proposal_by_id(&proposal_id).unwrap();
    assert_eq!(proposal.status, DaoProposalStatus::Active);
    
    // After processing (if conditions are met), status should change
    // This would require more complex setup to test different end states
    
    Ok(())
}
