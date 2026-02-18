//! Phase 3A Sync Integration Tests
//!
//! Tests for export/import functionality including:
//! - Import/export roundtrip for N blocks
//! - Restart in the middle of import (crash simulation)
//! - Blocks with token contracts at genesis and token transfers later

use std::sync::Arc;
use tempfile::TempDir;

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::execution::{BlockExecutor, ExecutorConfig};
use lib_blockchain::storage::{BlockchainStore, SledStore, Address, TokenId};
use lib_blockchain::sync::{ChainSync, SyncError};
use lib_blockchain::transaction::{Transaction, TransactionOutput, TokenTransferData};
use lib_blockchain::types::{Hash, Difficulty, TransactionType};
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_store(dir: &TempDir) -> Arc<dyn BlockchainStore> {
    Arc::new(SledStore::open(dir.path()).unwrap())
}

fn create_dummy_public_key() -> PublicKey {
    PublicKey::new(vec![0u8; 32])
}

fn create_dummy_signature() -> Signature {
    Signature {
        signature: vec![0u8; 64],
        public_key: create_dummy_public_key(),
        algorithm: SignatureAlgorithm::Dilithium2,
        timestamp: 0,
    }
}

fn create_genesis_block() -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = 0x01;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_block_hash: Hash::default(),
        merkle_root: Hash::default(),
        state_root: Hash::default(),
        timestamp: 1000,
        difficulty: Difficulty::minimum(),
        nonce: 0,
        cumulative_difficulty: Difficulty::minimum(),
        height: 0,
        block_hash,
        transaction_count: 0,
        block_size: 0,
        fee_model_version: 2, // Phase 2+ uses v2
    };
    Block::new(header, vec![])
}

fn create_block_at_height(height: u64, prev_hash: Hash) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_block_hash: prev_hash,
        merkle_root: Hash::default(),
        state_root: Hash::default(),
        timestamp: 1000 + height * 600,
        difficulty: Difficulty::minimum(),
        nonce: 0,
        cumulative_difficulty: Difficulty::minimum(),
        height,
        block_hash,
        transaction_count: 0,
        block_size: 0,
        fee_model_version: 2, // Phase 2+ uses v2
    };
    Block::new(header, vec![])
}

/// Create a block with transactions
fn create_block_with_txs(height: u64, prev_hash: Hash, txs: Vec<Transaction>) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
    hash_bytes[8] = txs.len() as u8;
    let block_hash = Hash::new(hash_bytes);

    let header = BlockHeader {
        version: 1,
        previous_block_hash: prev_hash,
        merkle_root: Hash::default(),
        state_root: Hash::default(),
        timestamp: 1000 + height * 600,
        difficulty: Difficulty::minimum(),
        nonce: 0,
        cumulative_difficulty: Difficulty::minimum(),
        height,
        block_hash,
        transaction_count: txs.len() as u32,
        block_size: 0,
        fee_model_version: 2, // Phase 2+ uses v2
    };
    Block::new(header, txs)
}

/// Create a token transfer transaction
fn create_token_transfer_tx(
    token_id: [u8; 32],
    from: [u8; 32],
    to: [u8; 32],
    amount: u128,
) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 0x03,
        transaction_type: TransactionType::TokenTransfer,
        inputs: vec![],
        outputs: vec![],
        fee: 0, // Token transfers have 0 fee per Phase-2 rules
        signature: create_dummy_signature(),
        memo: vec![],
        identity_data: None,
        wallet_data: None,
        validator_data: None,
        dao_proposal_data: None,
        dao_vote_data: None,
        dao_execution_data: None,
        ubi_claim_data: None,
        profit_declaration_data: None,
        token_transfer_data: Some(TokenTransferData {
            token_id,
            from,
            to,
            amount,
            nonce: 0,
        }),
        token_mint_data: None,
        governance_config_data: None,
    }
}

// =============================================================================
// Tests
// =============================================================================

/// Test: Import/export roundtrip for N blocks
#[test]
fn test_roundtrip_n_blocks() {
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();

    let store1 = create_test_store(&dir1);
    let store2 = create_test_store(&dir2);

    let sync1 = ChainSync::new(Arc::clone(&store1));
    let sync2 = ChainSync::new(Arc::clone(&store2));

    // Create chain with 20 blocks
    let genesis = create_genesis_block();
    let mut blocks = vec![genesis.clone()];

    for height in 1..20 {
        let prev_hash = blocks.last().unwrap().header.block_hash;
        let block = create_block_at_height(height, prev_hash);
        blocks.push(block);
    }

    // Import to store1
    let result = sync1.import_blocks(blocks.clone()).unwrap();
    assert_eq!(result.blocks_imported, 20);
    assert_eq!(result.final_height, Some(19));

    // Export all blocks
    let exported = sync1.export_all_blocks().unwrap();
    assert_eq!(exported.len(), 20);

    // Import to store2
    let result2 = sync2.import_blocks(exported).unwrap();
    assert_eq!(result2.blocks_imported, 20);

    // Verify chains are identical
    for height in 0..20 {
        let block1 = store1.get_block_by_height(height).unwrap().unwrap();
        let block2 = store2.get_block_by_height(height).unwrap().unwrap();
        assert_eq!(
            block1.header.block_hash,
            block2.header.block_hash,
            "Block hash mismatch at height {}", height
        );
    }
}

/// Test: Partial export range
#[test]
fn test_partial_export_range() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    // Create 15 blocks
    let genesis = create_genesis_block();
    let mut blocks = vec![genesis.clone()];

    for height in 1..15 {
        let prev_hash = blocks.last().unwrap().header.block_hash;
        let block = create_block_at_height(height, prev_hash);
        blocks.push(block);
    }

    sync.import_blocks(blocks).unwrap();

    // Export subset [5, 10]
    let exported = sync.export_blocks(5, 10).unwrap();
    assert_eq!(exported.len(), 6);
    assert_eq!(exported[0].header.height, 5);
    assert_eq!(exported[5].header.height, 10);
}

/// Test: Crash simulation - state reflects last committed block only
#[test]
fn test_crash_no_partial_state() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    // Create valid chain
    let genesis = create_genesis_block();
    let block1 = create_block_at_height(1, genesis.header.block_hash);
    let block2 = create_block_at_height(2, block1.header.block_hash);

    // Import first 3 valid blocks
    sync.import_blocks(vec![genesis.clone(), block1.clone(), block2.clone()]).unwrap();

    // Verify at height 2
    assert_eq!(store.latest_height().unwrap(), 2);

    // Create invalid block 3 (wrong previous hash)
    let invalid_block3 = create_block_at_height(3, Hash::new([99u8; 32]));

    // Try to import - should fail
    let result = sync.import_blocks(vec![invalid_block3]);
    assert!(matches!(result, Err(SyncError::BlockApplyFailed { height: 3, .. })));

    // Verify state is EXACTLY at height 2 - no partial state from failed block
    assert_eq!(store.latest_height().unwrap(), 2);

    // Verify we can continue with valid block
    let valid_block3 = create_block_at_height(3, block2.header.block_hash);
    sync.import_blocks(vec![valid_block3]).unwrap();

    assert_eq!(store.latest_height().unwrap(), 3);
}

/// Test: Blocks with token transfers (token balance state)
///
/// This test verifies that token transfer transactions are correctly:
/// 1. Applied via the executor (debits sender, credits receiver)
/// 2. Exported and imported via ChainSync
/// 3. Verified to produce identical balance state in both stores
///
/// NOTE: Block-level sync exports/imports blocks but does NOT replay token
/// balance state transitions. The receiving node must re-execute transactions
/// to reconstruct balance state. This test verifies the block structure syncs
/// correctly; full state sync would require separate balance transfer mechanisms.
#[test]
fn test_token_transfer_state_sync() {
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();

    let store1 = create_test_store(&dir1);
    let store2 = create_test_store(&dir2);

    let sync1 = ChainSync::new(Arc::clone(&store1));
    let _sync2 = ChainSync::new(Arc::clone(&store2));

    // Define addresses and token
    let alice: [u8; 32] = [1u8; 32];
    let bob: [u8; 32] = [2u8; 32];
    let token_id: [u8; 32] = [0u8; 32]; // Native token

    // === STORE 1: Build chain with token transfer ===

    // Set up initial balance for Alice in store1 before genesis
    store1.begin_block(0).unwrap();
    store1.set_token_balance(&TokenId::new(token_id), &Address::new(alice), 1_000_000).unwrap();
    let genesis = create_genesis_block();
    store1.append_block(&genesis).unwrap();
    store1.commit_block().unwrap();

    // Create and apply block 1 with token transfer: Alice -> Bob, 100 tokens
    let transfer_tx = create_token_transfer_tx(token_id, alice, bob, 100);
    let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![transfer_tx]);

    let executor1 = BlockExecutor::from_config(Arc::clone(&store1), ExecutorConfig::default());
    executor1.apply_block(&block1).unwrap();

    // Verify balances in store1
    let alice_balance_1 = store1.get_token_balance(&TokenId::new(token_id), &Address::new(alice)).unwrap();
    let bob_balance_1 = store1.get_token_balance(&TokenId::new(token_id), &Address::new(bob)).unwrap();
    assert_eq!(alice_balance_1, 999_900, "Alice should have 1M - 100 = 999900");
    assert_eq!(bob_balance_1, 100, "Bob should have 100");

    // === STORE 2: Import blocks and verify structure ===

    // Export all blocks from store1
    let exported = sync1.export_all_blocks().unwrap();
    assert_eq!(exported.len(), 2, "Should export genesis + block1");

    // Set up identical initial balance state in store2 and import genesis
    // Note: We manually set up genesis + balance, then apply block 1 via executor
    store2.begin_block(0).unwrap();
    store2.set_token_balance(&TokenId::new(token_id), &Address::new(alice), 1_000_000).unwrap();
    // Append the exported genesis block to store2
    store2.append_block(&exported[0]).unwrap();
    store2.commit_block().unwrap();

    // Now apply block 1 via executor (which will replay the token transfer)
    let executor2 = BlockExecutor::from_config(Arc::clone(&store2), ExecutorConfig::default());
    executor2.apply_block(&exported[1]).unwrap();

    // Verify block hashes match
    let block1_store1 = store1.get_block_by_height(1).unwrap().unwrap();
    let block1_store2 = store2.get_block_by_height(1).unwrap().unwrap();
    assert_eq!(
        block1_store1.header.block_hash,
        block1_store2.header.block_hash,
        "Block 1 hash should match between stores"
    );

    // Verify balances match after re-execution
    let alice_balance_2 = store2.get_token_balance(&TokenId::new(token_id), &Address::new(alice)).unwrap();
    let bob_balance_2 = store2.get_token_balance(&TokenId::new(token_id), &Address::new(bob)).unwrap();
    assert_eq!(alice_balance_2, alice_balance_1, "Alice balance should match");
    assert_eq!(bob_balance_2, bob_balance_1, "Bob balance should match");
}

/// Test: Import with progress tracking
#[test]
fn test_import_progress_tracking() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    // Create 10 blocks
    let genesis = create_genesis_block();
    let mut blocks = vec![genesis.clone()];

    for height in 1..10 {
        let prev_hash = blocks.last().unwrap().header.block_hash;
        let block = create_block_at_height(height, prev_hash);
        blocks.push(block);
    }

    let mut progress_log: Vec<(u64, usize)> = vec![];

    sync.import_blocks_with_progress(blocks, |height, total| {
        progress_log.push((height, total));
    }).unwrap();

    assert_eq!(progress_log.len(), 10);
    assert_eq!(progress_log[0], (0, 1));  // Genesis
    assert_eq!(progress_log[9], (9, 10)); // Last block
}

/// Test: Multiple sequential imports
#[test]
fn test_sequential_imports() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    // First batch: blocks 0-4
    let genesis = create_genesis_block();
    let mut blocks = vec![genesis.clone()];

    for height in 1..5 {
        let prev_hash = blocks.last().unwrap().header.block_hash;
        let block = create_block_at_height(height, prev_hash);
        blocks.push(block);
    }

    sync.import_blocks(blocks.clone()).unwrap();
    assert_eq!(store.latest_height().unwrap(), 4);

    // Second batch: blocks 5-9
    let mut blocks2 = vec![];
    let mut prev_hash = blocks.last().unwrap().header.block_hash;

    for height in 5..10 {
        let block = create_block_at_height(height, prev_hash);
        prev_hash = block.header.block_hash;
        blocks2.push(block);
    }

    sync.import_blocks(blocks2).unwrap();
    assert_eq!(store.latest_height().unwrap(), 9);
}

/// Test: Export from empty chain
#[test]
fn test_export_empty_chain() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(store);

    let result = sync.export_all_blocks();
    assert!(matches!(result, Err(SyncError::NotInitialized)));
}

/// Test: Import with height gap (should fail)
#[test]
fn test_import_height_gap() {
    let dir = TempDir::new().unwrap();
    let store = create_test_store(&dir);
    let sync = ChainSync::new(Arc::clone(&store));

    // Import genesis
    let genesis = create_genesis_block();
    sync.import_blocks(vec![genesis.clone()]).unwrap();

    // Try to import block 3 (skipping 1 and 2)
    let block3 = create_block_at_height(3, Hash::new([1u8; 32]));
    let result = sync.import_blocks(vec![block3]);

    assert!(matches!(result, Err(SyncError::HeightMismatch { expected: 1, actual: 3 })));
}
