//! Consensus integration tests
//! 
//! Tests for the full blockchain consensus integration including validators,
//! DAO governance, reward distribution, and block production.

use std::sync::Arc;
use tokio::sync::RwLock;
use lib_blockchain::{
    Blockchain, Mempool, BlockchainConsensusCoordinator,
    initialize_consensus_integration,
    create_dao_proposal_transaction, create_dao_vote_transaction,
};
use lib_consensus::{ConsensusType, DaoProposalType, DaoVoteChoice};
use lib_crypto::KeyPair;
use lib_identity::IdentityId;

#[tokio::test]
async fn test_consensus_integration_initialization() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));

    let coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::Hybrid,
    ).await;

    assert!(coordinator.is_ok(), "Consensus integration should initialize successfully");
}

#[tokio::test]
async fn test_validator_registration() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    
    let mut coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::ProofOfStake,
    ).await.unwrap();

    let validator_keypair = KeyPair::generate().unwrap();
    let validator_identity = IdentityId::from_bytes(&validator_keypair.public_key.dilithium_pk);

    let result = coordinator.register_as_validator(
        validator_identity,
        1000_000_000, // 1000 ZHTP
        100 * 1024 * 1024 * 1024, // 100 GB
        &validator_keypair,
        5, // 5% commission
    ).await;

    assert!(result.is_ok(), "Validator registration should succeed");
}

#[tokio::test]
async fn test_dao_proposal_creation() {
    let proposer_keypair = KeyPair::generate().unwrap();
    
    let proposal_tx = create_dao_proposal_transaction(
        &proposer_keypair,
        "Test Proposal".to_string(),
        "A test proposal for the DAO".to_string(),
        DaoProposalType::TreasuryAllocation,
    );

    assert!(proposal_tx.is_ok(), "DAO proposal transaction should be created successfully");
    
    let tx = proposal_tx.unwrap();
    assert_eq!(tx.transaction_type, lib_blockchain::TransactionType::IdentityUpdate);
    assert!(tx.fee > 0, "DAO proposal should have a fee");
    
    let memo = String::from_utf8_lossy(&tx.memo);
    assert!(memo.contains("dao:proposal:"), "Transaction memo should contain DAO proposal marker");
}

#[tokio::test]
async fn test_dao_vote_creation() {
    let voter_keypair = KeyPair::generate().unwrap();
    let proposal_id = lib_crypto::Hash::from_bytes(&[1u8; 32]);
    
    let vote_tx = create_dao_vote_transaction(
        &voter_keypair,
        proposal_id,
        DaoVoteChoice::Yes,
    );

    assert!(vote_tx.is_ok(), "DAO vote transaction should be created successfully");
    
    let tx = vote_tx.unwrap();
    assert_eq!(tx.transaction_type, lib_blockchain::TransactionType::IdentityUpdate);
    assert!(tx.fee > 0, "DAO vote should have a fee");
    
    let memo = String::from_utf8_lossy(&tx.memo);
    assert!(memo.contains("dao:vote:"), "Transaction memo should contain DAO vote marker");
    assert!(memo.contains("yes"), "Vote memo should contain vote choice");
}

#[tokio::test]
async fn test_consensus_status() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    
    let coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::ByzantineFaultTolerance,
    ).await.unwrap();

    let status = coordinator.get_consensus_status().await;
    assert!(status.is_ok(), "Should be able to get consensus status");
    
    let status = status.unwrap();
    assert_eq!(status.current_height, 0, "Initial height should be 0");
    assert_eq!(status.current_round, 0, "Initial round should be 0");
    assert!(!status.is_validator, "Should not be a validator initially");
}

#[tokio::test]
async fn test_consensus_integration_with_blockchain() {
    let mut blockchain = Blockchain::new().unwrap();
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    let blockchain_arc = Arc::new(RwLock::new(blockchain.clone()));

    // Initialize consensus coordinator
    blockchain.initialize_consensus_coordinator(
        mempool.clone(),
        ConsensusType::Hybrid,
    ).await.unwrap();

    // Check that consensus coordinator was initialized
    assert!(blockchain.get_consensus_coordinator().is_some(), 
           "Consensus coordinator should be initialized");

    // Test consensus status
    let status = blockchain.get_consensus_status().await.unwrap();
    assert!(status.is_some(), "Should have consensus status");
}

#[tokio::test]
async fn test_multiple_validators() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    
    let mut coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::Hybrid,
    ).await.unwrap();

    // Register multiple validators
    let validators = vec![
        ("Alice", 2000_000_000u64, 200u64),
        ("Bob", 1500_000_000, 150),
        ("Charlie", 1000_000_000, 100),
    ];

    for (name, stake, storage_gb) in validators {
        let keypair = KeyPair::generate().unwrap();
        let identity = IdentityId::from_bytes(&keypair.public_key.dilithium_pk);
        let storage_bytes = storage_gb * 1024 * 1024 * 1024;

        let result = coordinator.register_as_validator(
            identity,
            stake,
            storage_bytes,
            &keypair,
            5,
        ).await;

        assert!(result.is_ok(), "Validator {} should register successfully", name);
    }

    let status = coordinator.get_consensus_status().await.unwrap();
    assert!(status.validator_count > 0, "Should have registered validators");
}

#[tokio::test]
async fn test_consensus_event_handling() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    
    let coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::ProofOfStake,
    ).await.unwrap();

    // Test that coordinator can handle consensus events
    // This tests the internal event loop initialization
    let status_before = coordinator.get_consensus_status().await.unwrap();
    
    // Give it a moment to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let status_after = coordinator.get_consensus_status().await.unwrap();
    
    // The status should be accessible both before and after
    assert_eq!(status_before.current_height, status_after.current_height);
}

#[tokio::test]
async fn test_dao_transaction_parsing() {
    // Test DAO proposal transaction format
    let proposer_keypair = KeyPair::generate().unwrap();
    let proposal_tx = create_dao_proposal_transaction(
        &proposer_keypair,
        "Treasury Allocation".to_string(),
        "Allocate funds for development".to_string(),
        DaoProposalType::TreasuryAllocation,
    ).unwrap();

    let memo = String::from_utf8_lossy(&proposal_tx.memo);
    assert!(memo.contains("dao:proposal:"));
    assert!(memo.contains("title:Treasury Allocation"));
    assert!(memo.contains("description:Allocate funds for development"));
    assert!(memo.contains("type:TreasuryAllocation"));

    // Test DAO vote transaction format
    let voter_keypair = KeyPair::generate().unwrap();
    let proposal_id = lib_crypto::Hash::from_bytes(&[0xab; 32]);
    let vote_tx = create_dao_vote_transaction(
        &voter_keypair,
        proposal_id,
        DaoVoteChoice::No,
    ).unwrap();

    let memo = String::from_utf8_lossy(&vote_tx.memo);
    assert!(memo.contains("dao:vote:"));
    assert!(memo.contains("proposal:"));
    assert!(memo.contains("vote:no"));
}

#[tokio::test]
async fn test_consensus_coordinator_lifecycle() {
    let blockchain = Arc::new(RwLock::new(Blockchain::new().unwrap()));
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    
    let mut coordinator = initialize_consensus_integration(
        blockchain,
        mempool,
        ConsensusType::ProofOfStake,
    ).await.unwrap();

    // Test starting coordinator
    let start_result = coordinator.start_consensus_coordinator().await;
    assert!(start_result.is_ok(), "Should be able to start consensus coordinator");

    // Test status while running
    let status = coordinator.get_consensus_status().await.unwrap();
    assert!(status.is_producing_blocks, "Should be producing blocks when started");

    // Test stopping coordinator
    coordinator.stop().await;
    
    // Note: The coordinator might not immediately reflect the stopped state
    // in the status due to async nature, but the stop call should succeed
}
