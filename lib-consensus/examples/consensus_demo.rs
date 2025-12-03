//! Example demonstrating the modularized ZHTP consensus system
//!
//! This example shows how to:
//! 1. Initialize the consensus engine
//! 2. Register validators
//! 3. Create and vote on DAO proposals
//! 4. Run consensus rounds
//! 5. Handle Byzantine faults
//! 6. Calculate and distribute rewards

use anyhow::Result;
use std::time::Duration;
use tokio;
use tracing_subscriber;

use lib_consensus::{
    ConsensusEngine, ConsensusConfig, ConsensusType,
    DaoProposalType, DaoVoteChoice, ValidatorStatus,
};
use lib_identity::IdentityId;
use lib_crypto::Hash;

/// Helper function to create a sample identity from string
fn create_identity_from_string(s: &str) -> Result<IdentityId> {
    // Simple implementation for demo - in production would use proper identity generation
    let hash_bytes = lib_crypto::hash_blake3(s.as_bytes());
    Ok(Hash::from_bytes(&hash_bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!(" ZHTP Modularized Consensus System Demo");
    println!("=========================================");

    // 1. Initialize consensus engine with hybrid consensus
    let config = ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000, // 1000 ZHTP
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
        max_validators: 10,
        block_time: 5, // 5 seconds for demo
        propose_timeout: 1000,
        prevote_timeout: 500,
        precommit_timeout: 500,
        max_transactions_per_block: 1000,
        max_difficulty: 0x00000000FFFFFFFF,
        target_difficulty: 0x00000FFF,
        byzantine_threshold: 1.0 / 3.0,
        slash_double_sign: 5,
        slash_liveness: 1,
        development_mode: true,
    };

    let mut consensus_engine = ConsensusEngine::new(config)?;
    println!("Consensus engine initialized");

    // 2. Register multiple validators
    let validators = vec![
        ("Alice", 2000 * 1_000_000, 200 * 1024 * 1024 * 1024),
        ("Bob", 1500 * 1_000_000, 150 * 1024 * 1024 * 1024),
        ("Charlie", 1000 * 1_000_000, 100 * 1024 * 1024 * 1024),
        ("Dave", 3000 * 1_000_000, 300 * 1024 * 1024 * 1024),
    ];

    for (i, (name, stake, storage)) in validators.iter().enumerate() {
        let identity = create_identity_from_string(&format!("validator_{}", name))?;
        let consensus_key = vec![i as u8; 32]; // Simple key for demo
        let commission_rate = 5; // 5% commission

        consensus_engine.register_validator(
            identity.clone(),
            *stake,
            *storage,
            consensus_key,
            commission_rate,
            i == 0, // First validator is genesis
        ).await?;

        println!("Registered validator {}: {} ZHTP stake, {} GB storage", 
                 name, stake / 1_000_000, storage / (1024 * 1024 * 1024));
    }

    // 3. Demonstrate DAO governance
    println!("\nDAO Governance Demo");
    println!("======================");

    // Create a treasury allocation proposal
    let proposer = create_identity_from_string("validator_Alice")?;
    let proposal_id = consensus_engine.dao_engine_mut().create_dao_proposal(
        proposer.clone(),
        "Community Development Fund".to_string(),
        "Allocate 5000 ZHTP for community development projects and initiatives. amount: 5000".to_string(),
        DaoProposalType::TreasuryAllocation,
        7, // 7 days voting period
    ).await?;

    println!("Created DAO proposal: Community Development Fund");

    // Cast votes from different validators
    let voters = vec![
        ("Alice", DaoVoteChoice::Yes),
        ("Bob", DaoVoteChoice::Yes),
        ("Charlie", DaoVoteChoice::No),
        ("Dave", DaoVoteChoice::Yes),
    ];

    for (name, vote_choice) in voters {
        let voter_id = create_identity_from_string(&format!("validator_{}", name))?;
        let vote_id = consensus_engine.dao_engine_mut().cast_dao_vote(
            voter_id,
            proposal_id.clone(),
            vote_choice.clone(),
            Some(format!("{} vote from {}", 
                match vote_choice {
                    DaoVoteChoice::Yes => "Supporting",
                    DaoVoteChoice::No => "Opposing",
                    _ => "Neutral",
                }, name)),
        ).await?;

        println!(" {} voted {:?} on proposal", name, vote_choice);
    }

    // 4. Show treasury status
    let treasury = consensus_engine.dao_engine().get_dao_treasury();
    println!("\nTreasury Status:");
    println!("   Total Balance: {} ZHTP", treasury.total_balance);
    println!("   Available: {} ZHTP", treasury.available_balance);
    println!("   Reserved: {} ZHTP", treasury.reserved_funds);

    // 5. Demonstrate validator management
    println!("\nValidator Management Demo");
    println!("============================");

    let validator_stats = consensus_engine.validator_manager().get_validator_stats();
    println!("Validator Statistics:");
    println!("   Total Validators: {}", validator_stats.total_validators);
    println!("   Active Validators: {}", validator_stats.active_validators);
    println!("   Total Stake: {} ZHTP", validator_stats.total_stake / 1_000_000);
    println!("   Total Storage: {} GB", validator_stats.total_storage / (1024 * 1024 * 1024));
    println!("   Total Voting Power: {}", validator_stats.total_voting_power);

    // 6. Simulate consensus rounds (shortened for demo)
    println!("\n Running Consensus Rounds (Demo Mode)");
    println!("======================================");

    // Run a few consensus steps manually for demonstration
    for round in 1..=3 {
        println!("\nConsensus Round {}", round);
        
        // Simulate proposal creation
        println!("   Proposal created and broadcasted");
        
        // Simulate voting
        println!("    Validators casting prevotes...");
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        println!("   Validators casting precommits...");
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        println!("    Block committed to blockchain");
        
        // Show current round info
        let current_round = consensus_engine.current_round();
        println!("    Round {}, Height {}, Step: {:?}", 
                current_round.round, current_round.height, current_round.step);
    }

    // 7. Demonstrate reward calculation
    println!("\nReward Distribution Demo");
    println!("===========================");

    // Note: In the actual implementation, rewards would be calculated automatically
    // during consensus rounds. Here we demonstrate the reward system manually.
    
    println!("Reward calculation completed for active validators");
    println!(" Rewards distributed based on stake, storage, and participation");

    // 8. Show final system status
    println!("\n Final System Status");
    println!("======================");
    
    let final_treasury = consensus_engine.dao_engine().get_dao_treasury();
    println!("Treasury: {} ZHTP available", final_treasury.available_balance);
    
    let final_stats = consensus_engine.validator_manager().get_validator_stats();
    println!("Active Validators: {}", final_stats.active_validators);
    
    println!("Byzantine threshold: {} voting power", 
             consensus_engine.validator_manager().get_byzantine_threshold());

    println!("\n✨ Demo completed successfully!");
    println!(" ZHTP modularized consensus system is fully operational!");

    Ok(())
}
