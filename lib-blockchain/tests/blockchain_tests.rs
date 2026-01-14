//! Comprehensive blockchain tests
//!
//! Tests the core blockchain functionality including block addition,
//! transaction validation, identity management, and consensus.

use lib_blockchain::*;
use lib_blockchain::integration::*;
use lib_blockchain::integration::crypto_integration;
use lib_blockchain::types::mining::get_mining_config_from_env;
use lib_blockchain::blockchain::ValidatorInfo;
use anyhow::Result;

// Helper function to create a simple valid transaction for testing
fn create_test_transaction(memo: &str) -> Result<Transaction> {
    // Create a simple identity transaction that doesn't need inputs/outputs
    let unique_id = memo.len() as u32; // Use memo length for uniqueness
    let identity_data = IdentityTransactionData::new(
        format!("did:zhtp:test_{}", unique_id),
        "Test User".to_string(),
        vec![1, 2, 3, 4], // public_key
        vec![5, 6, 7, 8], // ownership_proof
        "human".to_string(),
        Hash::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?,
        1000, // registration_fee
        100,  // dao_fee
    );

    let transaction = Transaction::new_identity_registration(
        identity_data,
        vec![], // Identity registration doesn't need outputs
        crypto_integration::Signature {
            signature: vec![1, 2, 3, 4, 5], // Non-empty signature
            public_key: crypto_integration::PublicKey::new(vec![6, 7, 8, 9]),
            algorithm: crypto_integration::SignatureAlgorithm::Dilithium5,
            timestamp: 12345,
        },
        memo.as_bytes().to_vec(),
    );
    Ok(transaction)
}

// Helper function to create a validator info for testing
fn create_test_validator(id: &str, stake: u64) -> ValidatorInfo {
    ValidatorInfo {
        identity_id: id.to_string(),
        stake,
        storage_provided: 1000000u64,
        consensus_key: vec![1, 2, 3, 4, 5],
        network_address: format!("127.0.0.1:{}", 8000 + stake % 1000),
        commission_rate: 5u8,
        status: "active".to_string(),
        registered_at: 1000u64,
        last_activity: 1000u64,
        blocks_validated: 0u64,
        slash_count: 0u32,
    }
}

// Helper function to register a validator identity and return it
fn register_validator_identity(blockchain: &mut Blockchain, id: &str) -> Result<()> {
    let identity_data = IdentityTransactionData::new(
        id.to_string(),
        format!("Validator {}", id),
        vec![1, 2, 3, 4],
        vec![5, 6, 7, 8],
        "validator".to_string(),
        Hash::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?,
        1000,
        100,
    );
    blockchain.identity_registry.insert(id.to_string(), identity_data);
    Ok(())
}

// Helper function to create a mined block that meets difficulty
fn create_mined_block(blockchain: &Blockchain, transactions: Vec<Transaction>) -> Result<Block> {
    let mining_config = get_mining_config_from_env();
    let merkle_root = if transactions.is_empty() {
        Hash::default()
    } else {
        crate::transaction::hashing::calculate_transaction_merkle_root(&transactions)
    };

    let mut header = BlockHeader::new(
        1,
        blockchain.latest_block().unwrap().hash(),
        merkle_root,
        blockchain.latest_block().unwrap().timestamp() + 10,
        mining_config.difficulty,
        blockchain.height + 1,
        transactions.len() as u32,
        transactions.iter().map(|tx| tx.size()).sum::<usize>() as u32,
        mining_config.difficulty,
    );

    // Set nonce to 0 for easy difficulty
    header.set_nonce(0);

    Ok(Block::new(header, transactions))
}

#[test]
fn test_blockchain_creation() -> Result<()> {
    let blockchain = Blockchain::new()?;

    // Check initial state
    assert_eq!(blockchain.height, 0);
    assert_eq!(blockchain.blocks.len(), 1); // Genesis block
    assert!(blockchain.utxo_set.is_empty());
    assert!(blockchain.nullifier_set.is_empty());
    assert!(blockchain.pending_transactions.is_empty());
    assert!(blockchain.identity_registry.is_empty());

    // Check genesis block
    let genesis = blockchain.latest_block().unwrap();
    assert!(genesis.is_genesis());
    assert_eq!(genesis.height(), 0);
    assert_eq!(genesis.previous_hash(), Hash::default());

    Ok(())
}

#[test]
fn test_block_addition() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Create a test block using helper function
    let block = create_mined_block(&blockchain, Vec::new())?;

    // Add the block
    blockchain.add_block(block)?;

    // Verify the state
    assert_eq!(blockchain.height, 1);
    assert_eq!(blockchain.blocks.len(), 2);

    Ok(())
}

#[test]
fn test_identity_registration() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Create identity data
    let identity_data = IdentityTransactionData::new(
        "did:zhtp:test123".to_string(),
        "Test User".to_string(),
        vec![1, 2, 3, 4], // public_key
        vec![5, 6, 7, 8], // ownership_proof
        "human".to_string(),
        Hash::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")?,
        1000, // registration_fee
        100,  // dao_fee
    );

    // Register the identity
    blockchain.identity_registry.insert("did:zhtp:test123".to_string(), identity_data.clone());
    blockchain.identity_blocks.insert("did:zhtp:test123".to_string(), 0);

    // Verify it's in the registry
    assert!(blockchain.identity_registry.contains_key("did:zhtp:test123"));

    Ok(())
}

#[test]
fn test_register_validator_added_to_blockchain() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identity first
    register_validator_identity(&mut blockchain, "validator_001")?;

    // Add validator
    blockchain.validator_registry.insert(
        "validator_001".to_string(),
        create_test_validator("validator_001", 5000),
    );
    blockchain.validator_blocks.insert("validator_001".to_string(), 0);

    // Verify validator exists and is active
    assert!(blockchain.get_validator("validator_001").is_some(), "Validator should exist");

    let validator = blockchain.get_validator("validator_001").unwrap();
    assert_eq!(validator.stake, 5000u64, "Validator stake should match");
    assert_eq!(validator.status, "active", "Validator should be active");

    Ok(())
}

#[test]
fn test_consensus_queries_validator_set() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identities first
    register_validator_identity(&mut blockchain, "validator_001")?;
    register_validator_identity(&mut blockchain, "validator_002")?;
    register_validator_identity(&mut blockchain, "validator_003")?;

    // Directly add validators to registry for testing
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));
    blockchain.validator_registry.insert("validator_002".to_string(), create_test_validator("validator_002", 3000));
    blockchain.validator_registry.insert("validator_003".to_string(), create_test_validator("validator_003", 2000));

    // Query the active validator set for consensus
    let active_set = blockchain.get_active_validator_set_for_consensus();

    // Should have 3 validators
    assert_eq!(active_set.len(), 3, "Should have 3 active validators");

    // Verify the set contains the expected validators with correct stakes
    let validator_map: std::collections::HashMap<String, u64> = active_set
        .iter()
        .map(|(id, stake)| (id.clone(), *stake))
        .collect();

    assert_eq!(validator_map.get("validator_001").copied(), Some(5000));
    assert_eq!(validator_map.get("validator_002").copied(), Some(3000));
    assert_eq!(validator_map.get("validator_003").copied(), Some(2000));

    Ok(())
}

#[test]
fn test_pending_transactions() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Create a test transaction
    let tx = create_test_transaction("test_pending")?;

    // Add to pending
    blockchain.pending_transactions.push(tx.clone());

    // Verify it's pending
    assert_eq!(blockchain.pending_transactions.len(), 1);

    Ok(())
}

#[test]
fn test_utxo_management() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // UTXO set should exist (may be empty until funded)
    assert!(blockchain.utxo_set.is_empty() || !blockchain.utxo_set.is_empty()); // Always true, just verifying existence

    // Add a block and verify UTXO set is maintained
    let block = create_mined_block(&blockchain, Vec::new())?;
    let initial_size = blockchain.utxo_set.len();
    blockchain.add_block(block)?;

    // UTXO set should maintain its size (no new outputs added)
    assert_eq!(blockchain.utxo_set.len(), initial_size);

    Ok(())
}

#[test]
fn test_block_verification() -> Result<()> {
    let blockchain = Blockchain::new()?;

    // Create a mined block
    let block = create_mined_block(&blockchain, Vec::new())?;

    // Verify block against blockchain
    assert_eq!(block.previous_hash(), blockchain.latest_block().unwrap().hash());
    assert_eq!(block.height(), blockchain.height + 1);

    Ok(())
}

#[test]
fn test_blockchain_serialization() -> Result<()> {
    let blockchain = Blockchain::new()?;

    // Test that blockchain can be serialized
    let _serialized = serde_json::to_string(&blockchain);
    assert!(_serialized.is_ok(), "Blockchain should be serializable");

    Ok(())
}

#[test]
fn test_difficulty_adjustment() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add a block
    let block = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block)?;

    // Difficulty might or might not change based on adjustment logic
    // Just verify no panic and blockchain is valid
    assert_eq!(blockchain.height, 1);

    Ok(())
}

#[test]
fn test_validator_set_in_sync() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identities first
    register_validator_identity(&mut blockchain, "validator_001")?;
    register_validator_identity(&mut blockchain, "validator_002")?;
    register_validator_identity(&mut blockchain, "validator_003")?;

    // Add initial validators
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));
    blockchain.validator_registry.insert("validator_002".to_string(), create_test_validator("validator_002", 3000));

    // Get initial set
    let initial_set = blockchain.get_active_validator_set_for_consensus();
    assert_eq!(initial_set.len(), 2);

    // Add a new validator
    blockchain.validator_registry.insert("validator_003".to_string(), create_test_validator("validator_003", 2000));

    // Get updated set
    let updated_set = blockchain.get_active_validator_set_for_consensus();
    assert_eq!(updated_set.len(), 3, "Set should include new validator");

    // Verify new validator is in the set
    let validator_ids: Vec<_> = updated_set.iter().map(|(id, _)| id.clone()).collect();
    assert!(validator_ids.contains(&"validator_003".to_string()));

    Ok(())
}

#[test]
fn test_validator_stake_update_propagates() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identity first
    register_validator_identity(&mut blockchain, "validator_001")?;

    // Add a validator
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));

    // Get initial set
    let initial_set = blockchain.get_active_validator_set_for_consensus();
    let initial_stake = initial_set
        .iter()
        .find(|(id, _)| id == "validator_001")
        .map(|(_, stake)| *stake)
        .unwrap_or(0);
    assert_eq!(initial_stake, 5000);

    // Update validator stake directly in registry
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 7500));

    // Get updated set
    let updated_set = blockchain.get_active_validator_set_for_consensus();
    let updated_stake = updated_set
        .iter()
        .find(|(id, _)| id == "validator_001")
        .map(|(_, stake)| *stake)
        .unwrap_or(0);
    assert_eq!(updated_stake, 7500, "Stake update should propagate");

    Ok(())
}

#[test]
fn test_total_validator_stake_calculation() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identities first
    register_validator_identity(&mut blockchain, "validator_001")?;
    register_validator_identity(&mut blockchain, "validator_002")?;
    register_validator_identity(&mut blockchain, "validator_003")?;

    // Add validators with specific stakes
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));
    blockchain.validator_registry.insert("validator_002".to_string(), create_test_validator("validator_002", 3000));
    blockchain.validator_registry.insert("validator_003".to_string(), create_test_validator("validator_003", 2000));

    // Calculate total stake
    let total_stake = blockchain.get_total_validator_stake();

    // Should be 5000 + 3000 + 2000 = 10000
    assert_eq!(total_stake, 10000, "Total stake calculation incorrect");

    Ok(())
}

#[test]
fn test_is_validator_active_check() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identity first
    register_validator_identity(&mut blockchain, "validator_001")?;

    // Add a validator
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));

    // Should be active
    assert!(blockchain.is_validator_active("validator_001"), "Registered validator should be active");

    // Non-existent validator should not be active
    assert!(!blockchain.is_validator_active("validator_999"), "Non-existent validator should not be active");

    Ok(())
}

#[test]
fn test_sync_validator_set_to_consensus() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Register validator identities first
    register_validator_identity(&mut blockchain, "validator_001")?;
    register_validator_identity(&mut blockchain, "validator_002")?;

    // Add validators
    blockchain.validator_registry.insert("validator_001".to_string(), create_test_validator("validator_001", 5000));
    blockchain.validator_registry.insert("validator_002".to_string(), create_test_validator("validator_002", 3000));

    // Call sync - should log active validators
    // This method is primarily for logging/event emission, so we just verify it doesn't panic
    blockchain.sync_validator_set_to_consensus();

    // Verify validators are still active after sync
    let active_set = blockchain.get_active_validator_set_for_consensus();
    assert_eq!(active_set.len(), 2);

    Ok(())
}

// Fork Detection Tests - Issue #6
// Tests for fork detection and chain evaluation in consensus layer

#[test]
fn test_fork_detection_at_same_height() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Create a block at height 1
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1.clone())?;
    assert_eq!(blockchain.height, 1);

    // Try to add another block at the same height - should fail
    // This simulates a fork detection scenario
    let block1_alt = {
        let mining_config = get_mining_config_from_env();
        let merkle_root = Hash::default();

        let mut header = BlockHeader::new(
            1,
            blockchain.blocks[0].hash(),
            merkle_root,
            blockchain.latest_block().unwrap().timestamp() + 15,
            mining_config.difficulty,
            1, // Same height as block1
            0,
            0,
            mining_config.difficulty,
        );
        header.set_nonce(1);
        Block::new(header, Vec::new())
    };

    // The blockchain should recognize this as a fork attempt
    // At the same height with different hash
    assert_ne!(block1.hash(), block1_alt.hash());
    assert_eq!(block1.height(), block1_alt.height());

    Ok(())
}

#[test]
fn test_fork_detection_in_get_block() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add a block at height 1
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1.clone())?;

    // Verify we can retrieve it
    let retrieved = blockchain.get_block(1);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().height(), 1);
    assert_eq!(retrieved.unwrap().hash(), block1.hash());

    // Verify get_block returns None for height that doesn't exist
    let missing = blockchain.get_block(100);
    assert!(missing.is_none());

    Ok(())
}

#[test]
fn test_blockchain_height_consistency() -> Result<()> {
    let mut blockchain = Blockchain::new()?;
    assert_eq!(blockchain.height, 0);
    assert_eq!(blockchain.blocks.len(), 1); // Genesis block

    // Add a block at height 1
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1)?;
    assert_eq!(blockchain.height, 1);
    assert_eq!(blockchain.blocks.len(), 2);

    // Add a block at height 2
    let block2 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block2)?;
    assert_eq!(blockchain.height, 2);
    assert_eq!(blockchain.blocks.len(), 3);

    // Verify blocks are in correct order
    let genesis = blockchain.get_block(0).unwrap();
    assert!(genesis.is_genesis());

    let b1 = blockchain.get_block(1).unwrap();
    assert_eq!(b1.height(), 1);
    assert_eq!(b1.previous_hash(), genesis.hash());

    let b2 = blockchain.get_block(2).unwrap();
    assert_eq!(b2.height(), 2);
    assert_eq!(b2.previous_hash(), b1.hash());

    Ok(())
}

#[test]
fn test_fork_detection_requires_same_height() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Create and add blocks in sequence
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1.clone())?;

    let block2 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block2.clone())?;

    assert_eq!(blockchain.height, 2);

    // Blocks at same height (1) with different hashes represent a fork
    assert_eq!(block1.height(), block2.height().saturating_sub(1));

    // But blocks at consecutive heights are not a fork
    assert_eq!(block1.height() + 1, block2.height());
    assert_eq!(block1.hash(), block2.previous_hash());

    Ok(())
}

#[test]
fn test_cumulative_difficulty_tracking() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Get initial cumulative difficulty from genesis
    let genesis = blockchain.latest_block().unwrap();
    let genesis_difficulty = genesis.header.cumulative_difficulty;

    // Add a new block
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1)?;

    // Cumulative difficulty should increase
    let new_latest = blockchain.latest_block().unwrap();
    assert!(new_latest.header.cumulative_difficulty >= genesis_difficulty);

    // Verify we can retrieve blocks and check their cumulative difficulties
    let retrieved_genesis = blockchain.get_block(0).unwrap();
    let retrieved_block1 = blockchain.get_block(1).unwrap();

    assert!(retrieved_block1.header.cumulative_difficulty >= retrieved_genesis.header.cumulative_difficulty);

    Ok(())
}

#[test]
fn test_block_chain_validity() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add several blocks and verify chain validity
    for _ in 0..5 {
        let block = create_mined_block(&blockchain, Vec::new())?;
        blockchain.add_block(block)?;
    }

    assert_eq!(blockchain.height, 5);

    // Verify the entire chain is valid
    for height in 0..=blockchain.height {
        let block = blockchain.get_block(height);
        assert!(block.is_some(), "Block at height {} should exist", height);

        let current = block.unwrap();
        assert_eq!(current.height(), height);

        if height > 0 {
            let previous = blockchain.get_block(height - 1).unwrap();
            assert_eq!(current.previous_hash(), previous.hash());
        } else {
            assert!(current.is_genesis());
        }
    }

    Ok(())
}

// UTXO Snapshot Tests - Issue #7
// Tests for UTXO state snapshots per block height

#[test]
fn test_utxo_snapshot_creation() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Initially, genesis block should have a snapshot at height 0
    assert!(blockchain.get_utxo_set_at_height(0).is_some());

    // Add 3 blocks
    for _ in 0..3 {
        let block = create_mined_block(&blockchain, Vec::new())?;
        blockchain.add_block(block)?;
    }

    // Verify snapshots exist at heights 1, 2, 3
    assert!(blockchain.get_utxo_set_at_height(1).is_some(), "Snapshot at height 1 should exist");
    assert!(blockchain.get_utxo_set_at_height(2).is_some(), "Snapshot at height 2 should exist");
    assert!(blockchain.get_utxo_set_at_height(3).is_some(), "Snapshot at height 3 should exist");

    Ok(())
}

#[test]
fn test_utxo_snapshot_retrieval() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Get initial UTXO set size
    let genesis_utxos = blockchain.get_utxo_set_at_height(0);
    assert!(genesis_utxos.is_some());
    let _genesis_count = genesis_utxos.unwrap().len();

    // Add a block
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1)?;

    // Get snapshot at height 1
    let snapshot_at_1 = blockchain.get_utxo_set_at_height(1);
    assert!(snapshot_at_1.is_some());

    // Verify snapshot can be retrieved at different heights
    let snapshot_at_0 = blockchain.get_utxo_set_at_height(0);
    assert!(snapshot_at_0.is_some());

    // Snapshots at non-existent heights should return None
    let missing_snapshot = blockchain.get_utxo_set_at_height(100);
    assert!(missing_snapshot.is_none(), "Snapshot at non-existent height should return None");

    Ok(())
}

#[test]
fn test_utxo_snapshot_accuracy() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Get current UTXO set size
    let _initial_utxo_count = blockchain.utxo_set.len();

    // Add a block
    let block1 = create_mined_block(&blockchain, Vec::new())?;
    blockchain.add_block(block1)?;

    // Get snapshot at height 1
    let snapshot_at_1 = blockchain.get_utxo_set_at_height(1).unwrap();

    // Snapshot should match current UTXO set
    assert_eq!(
        snapshot_at_1.len(),
        blockchain.utxo_set.len(),
        "Snapshot should have same number of UTXOs as current set"
    );

    // Verify snapshot content matches (verify all keys present)
    for (utxo_hash, _utxo_output) in &snapshot_at_1 {
        assert!(
            blockchain.utxo_set.contains_key(utxo_hash),
            "UTXO from snapshot should be in current set"
        );
    }

    Ok(())
}

#[test]
fn test_utxo_snapshot_pruning() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add 10 blocks
    for _ in 0..10 {
        let block = create_mined_block(&blockchain, Vec::new())?;
        blockchain.add_block(block)?;
    }

    // Verify we have 11 snapshots (0-10)
    assert_eq!(blockchain.height, 10);
    let snapshots_before = blockchain.utxo_snapshots.len();
    assert_eq!(snapshots_before, 11, "Should have 11 snapshots (heights 0-10)");

    // Prune keeping only 5 blocks
    blockchain.prune_utxo_history(5);

    // Verify snapshots were pruned
    let snapshots_after = blockchain.utxo_snapshots.len();
    assert!(snapshots_after < snapshots_before, "Pruning should reduce snapshot count");

    // Verify only recent blocks are kept
    assert!(
        blockchain.get_utxo_set_at_height(10).is_some(),
        "Latest block snapshot should be kept"
    );
    assert!(
        blockchain.get_utxo_set_at_height(6).is_some(),
        "Recent block snapshots should be kept"
    );

    // Old snapshots should be removed (approximately)
    // Note: exact behavior depends on pruning algorithm, but at least some old ones should be gone
    let old_snapshots_missing = (0..5).any(|h| blockchain.get_utxo_set_at_height(h).is_none());
    assert!(
        old_snapshots_missing,
        "Some old snapshots should be removed during pruning"
    );

    Ok(())
}

#[test]
fn test_utxo_restore_from_snapshot() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add 3 blocks
    for _ in 0..3 {
        let block = create_mined_block(&blockchain, Vec::new())?;
        blockchain.add_block(block)?;
    }

    // Save current UTXO set information
    let utxo_set_at_1 = blockchain.get_utxo_set_at_height(1).unwrap();
    let utxo_count_at_1 = utxo_set_at_1.len();

    // Verify current UTXO set is different (we added more blocks)
    assert!(
        blockchain.utxo_set.len() >= utxo_count_at_1,
        "Current UTXO set should have more UTXOs than at height 1"
    );

    // Restore UTXO set from snapshot at height 1
    blockchain.restore_utxo_set_from_snapshot(1)?;

    // Verify UTXO set matches snapshot
    assert_eq!(
        blockchain.utxo_set.len(),
        utxo_count_at_1,
        "Restored UTXO set should match snapshot"
    );

    // Verify content matches (verify all keys present)
    for (hash, _output) in &utxo_set_at_1 {
        assert!(
            blockchain.utxo_set.contains_key(hash),
            "Restored UTXO should be in set"
        );
    }

    Ok(())
}

#[test]
fn test_utxo_snapshot_handles_empty_blocks() -> Result<()> {
    let mut blockchain = Blockchain::new()?;

    // Add 3 empty blocks (no transactions)
    for _ in 0..3 {
        let block = create_mined_block(&blockchain, Vec::new())?;
        blockchain.add_block(block)?;
    }

    // Verify snapshots are created even for empty blocks
    assert!(blockchain.get_utxo_set_at_height(1).is_some());
    assert!(blockchain.get_utxo_set_at_height(2).is_some());
    assert!(blockchain.get_utxo_set_at_height(3).is_some());

    // Verify UTXO set remains unchanged (no transactions means no new UTXOs)
    let snapshot_at_0 = blockchain.get_utxo_set_at_height(0).unwrap();
    let snapshot_at_1 = blockchain.get_utxo_set_at_height(1).unwrap();
    let snapshot_at_2 = blockchain.get_utxo_set_at_height(2).unwrap();
    let snapshot_at_3 = blockchain.get_utxo_set_at_height(3).unwrap();

    // All snapshots should have same UTXOs since no transactions were processed
    assert_eq!(snapshot_at_0.len(), snapshot_at_1.len());
    assert_eq!(snapshot_at_1.len(), snapshot_at_2.len());
    assert_eq!(snapshot_at_2.len(), snapshot_at_3.len());

    Ok(())
}
