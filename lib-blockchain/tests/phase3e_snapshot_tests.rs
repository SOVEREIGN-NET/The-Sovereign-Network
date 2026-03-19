//! Phase 3E Snapshot Integration Tests
//!
//! Tests for snapshot and fast sync functionality including:
//! - Snapshot + restore yields identical balances and UTXOs
//! - Restore then import more blocks works
//! - Snapshot integrity verification
//! - Multiple snapshots and cleanup

use std::sync::Arc;
use tempfile::TempDir;

use lib_blockchain::block::{Block, BlockHeader};
use lib_blockchain::execution::{BlockExecutor, ExecutorConfig};
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::storage::{
    AccountState, Address, BlockchainStore, OutPoint, SledStore, TokenId, TxHash, Utxo, WalletState,
};
use lib_blockchain::sync::{ChainSync, SnapshotId, SnapshotManager};
use lib_blockchain::transaction::{TokenTransferData, Transaction};
use lib_blockchain::types::{Difficulty, Hash, TransactionType};

// =============================================================================
// Test Helpers
// =============================================================================

fn create_test_store(dir: &TempDir) -> Arc<SledStore> {
    Arc::new(SledStore::open(dir.path()).ok_or("Automatic Remediation")?)
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
        fee_model_version: 2,
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
        fee_model_version: 2,
    };
    Block::new(header, vec![])
}

// =============================================================================
// Tests
// =============================================================================

/// Test: Snapshot and restore preserves complete state
#[test]
fn test_snapshot_restore_complete_state() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    // Create chain with multiple blocks
    let genesis = create_genesis_block();
    let block1 = create_block_at_height(1, genesis.header.block_hash);
    let block2 = create_block_at_height(2, block1.header.block_hash);
    let block3 = create_block_at_height(3, block2.header.block_hash);

    // Set up state
    let alice = Address::new([1u8; 32]);
    let bob = Address::new([2u8; 32]);
    let charlie = Address::new([3u8; 32]);
    let token = TokenId::NATIVE;

    let outpoint1 = OutPoint::new(TxHash::new([0xaa; 32]), 0);
    let utxo1 = Utxo::native(10_000, alice, 0);

    let outpoint2 = OutPoint::new(TxHash::new([0xbb; 32]), 1);
    let utxo2 = Utxo::native(20_000, bob, 1);

    let outpoint3 = OutPoint::new(TxHash::new([0xcc; 32]), 2);
    let utxo3 = Utxo::native(30_000, charlie, 2);

    // Apply genesis with initial state
    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.put_utxo(&outpoint1, &utxo1).ok_or("Automatic Remediation")?;
    store.set_token_balance(&token, &alice, 10_000).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    // Apply block 1
    store.begin_block(1).ok_or("Automatic Remediation")?;
    store.append_block(&block1).ok_or("Automatic Remediation")?;
    store.put_utxo(&outpoint2, &utxo2).ok_or("Automatic Remediation")?;
    store.set_token_balance(&token, &bob, 20_000).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    // Apply block 2
    store.begin_block(2).ok_or("Automatic Remediation")?;
    store.append_block(&block2).ok_or("Automatic Remediation")?;
    store.put_utxo(&outpoint3, &utxo3).ok_or("Automatic Remediation")?;
    store.set_token_balance(&token, &charlie, 30_000).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    // Apply block 3
    store.begin_block(3).ok_or("Automatic Remediation")?;
    store.append_block(&block3).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    // Take snapshot at height 3
    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(3).ok_or("Automatic Remediation")?;

    // Record state before restore
    let alice_balance_before = store.get_token_balance(&token, &alice).ok_or("Automatic Remediation")?;
    let bob_balance_before = store.get_token_balance(&token, &bob).ok_or("Automatic Remediation")?;
    let charlie_balance_before = store.get_token_balance(&token, &charlie).ok_or("Automatic Remediation")?;

    // Clear all state
    store.blocks_by_height().clear().ok_or("Automatic Remediation")?;
    store.blocks_by_hash().clear().ok_or("Automatic Remediation")?;
    store.utxos().clear().ok_or("Automatic Remediation")?;
    store.token_balances().clear().ok_or("Automatic Remediation")?;
    store.meta().clear().ok_or("Automatic Remediation")?;

    // Verify state is cleared
    assert!(store.get_utxo(&outpoint1).ok_or("Automatic Remediation")?.is_none());
    assert_eq!(store.get_token_balance(&token, &alice).ok_or("Automatic Remediation")?, 0);

    // Restore from snapshot
    manager.restore(&snapshot_id).ok_or("Automatic Remediation")?;

    // Verify all state is restored
    assert_eq!(store.latest_height().ok_or("Automatic Remediation")?, 3);

    // Verify balances
    assert_eq!(
        store.get_token_balance(&token, &alice).ok_or("Automatic Remediation")?,
        alice_balance_before
    );
    assert_eq!(
        store.get_token_balance(&token, &bob).ok_or("Automatic Remediation")?,
        bob_balance_before
    );
    assert_eq!(
        store.get_token_balance(&token, &charlie).ok_or("Automatic Remediation")?,
        charlie_balance_before
    );

    // Verify UTXOs
    let restored_utxo1 = store.get_utxo(&outpoint1).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
    assert_eq!(restored_utxo1.amount, 10_000);
    assert_eq!(restored_utxo1.owner, alice);

    let restored_utxo2 = store.get_utxo(&outpoint2).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
    assert_eq!(restored_utxo2.amount, 20_000);

    let restored_utxo3 = store.get_utxo(&outpoint3).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
    assert_eq!(restored_utxo3.amount, 30_000);

    // Verify all blocks
    for height in 0..=3 {
        assert!(store.get_block_by_height(height).ok_or("Automatic Remediation")?.is_some());
    }
}

/// Test: Restore from snapshot then continue with more blocks
#[test]
fn test_restore_then_continue_chain() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    // Build initial chain to height 5
    let genesis = create_genesis_block();
    let mut prev_hash = genesis.header.block_hash;

    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    for height in 1..=5 {
        let block = create_block_at_height(height, prev_hash);
        prev_hash = block.header.block_hash;
        store.begin_block(height).ok_or("Automatic Remediation")?;
        store.append_block(&block).ok_or("Automatic Remediation")?;
        store.commit_block().ok_or("Automatic Remediation")?;
    }

    // Take snapshot at height 5
    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(5).ok_or("Automatic Remediation")?;

    // Clear and restore
    store.blocks_by_height().clear().ok_or("Automatic Remediation")?;
    store.blocks_by_hash().clear().ok_or("Automatic Remediation")?;
    store.meta().clear().ok_or("Automatic Remediation")?;

    manager.restore(&snapshot_id).ok_or("Automatic Remediation")?;
    assert_eq!(store.latest_height().ok_or("Automatic Remediation")?, 5);

    // Get block 5's hash to continue from
    let block5 = store.get_block_by_height(5).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
    prev_hash = block5.header.block_hash;

    // Add more blocks (6-10)
    for height in 6..=10 {
        let block = create_block_at_height(height, prev_hash);
        prev_hash = block.header.block_hash;
        store.begin_block(height).ok_or("Automatic Remediation")?;
        store.append_block(&block).ok_or("Automatic Remediation")?;
        store.commit_block().ok_or("Automatic Remediation")?;
    }

    // Verify complete chain
    assert_eq!(store.latest_height().ok_or("Automatic Remediation")?, 10);

    for height in 0..=10 {
        let block = store.get_block_by_height(height).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
        assert_eq!(block.header.height, height);
    }
}

/// Test: Snapshot at intermediate height preserves only state up to that point
#[test]
fn test_snapshot_at_intermediate_height() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    // Create chain with 10 blocks
    let genesis = create_genesis_block();
    let mut prev_hash = genesis.header.block_hash;

    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    for height in 1..=10 {
        let block = create_block_at_height(height, prev_hash);
        prev_hash = block.header.block_hash;
        store.begin_block(height).ok_or("Automatic Remediation")?;
        store.append_block(&block).ok_or("Automatic Remediation")?;
        store.commit_block().ok_or("Automatic Remediation")?;
    }

    // Take snapshot at height 5 (middle)
    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(5).ok_or("Automatic Remediation")?;

    // Verify snapshot info
    let info = manager.get_snapshot_info(&snapshot_id).ok_or("Automatic Remediation")?;
    assert_eq!(info.height, 5);

    // Clear and restore
    store.blocks_by_height().clear().ok_or("Automatic Remediation")?;
    store.blocks_by_hash().clear().ok_or("Automatic Remediation")?;
    store.meta().clear().ok_or("Automatic Remediation")?;

    manager.restore(&snapshot_id).ok_or("Automatic Remediation")?;

    // Should only have blocks 0-5
    assert_eq!(store.latest_height().ok_or("Automatic Remediation")?, 5);

    for height in 0..=5 {
        assert!(store.get_block_by_height(height).ok_or("Automatic Remediation")?.is_some());
    }

    // Blocks 6-10 should not exist
    for height in 6..=10 {
        assert!(store.get_block_by_height(height).ok_or("Automatic Remediation")?.is_none());
    }
}

/// Test: Snapshot state hash integrity check
#[test]
fn test_snapshot_integrity_verification() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    let genesis = create_genesis_block();
    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(0).ok_or("Automatic Remediation")?;

    // Get snapshot info
    let info = manager.get_snapshot_info(&snapshot_id).ok_or("Automatic Remediation")?;

    // State hash should be non-zero
    assert_ne!(info.state_hash, [0u8; 32]);

    // Create another snapshot - same state should produce same hash
    // (determinism test)
    let snapshot_id2 = manager.snapshot_at(0).ok_or("Automatic Remediation")?;
    let info2 = manager.get_snapshot_info(&snapshot_id2).ok_or("Automatic Remediation")?;

    assert_eq!(info.state_hash, info2.state_hash);
}

/// Test: Multiple snapshots management
#[test]
fn test_multiple_snapshots() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    // Build chain
    let genesis = create_genesis_block();
    let block1 = create_block_at_height(1, genesis.header.block_hash);
    let block2 = create_block_at_height(2, block1.header.block_hash);
    let block3 = create_block_at_height(3, block2.header.block_hash);

    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    store.begin_block(1).ok_or("Automatic Remediation")?;
    store.append_block(&block1).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    store.begin_block(2).ok_or("Automatic Remediation")?;
    store.append_block(&block2).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    store.begin_block(3).ok_or("Automatic Remediation")?;
    store.append_block(&block3).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;

    // Create snapshots at different heights
    let id_h1 = manager.snapshot_at(1).ok_or("Automatic Remediation")?;
    let id_h2 = manager.snapshot_at(2).ok_or("Automatic Remediation")?;
    let id_h3 = manager.snapshot_at(3).ok_or("Automatic Remediation")?;

    // List should have 3 snapshots
    let list = manager.list_snapshots().ok_or("Automatic Remediation")?;
    assert_eq!(list.len(), 3);

    // Sorted by height descending
    assert_eq!(list[0].height, 3);
    assert_eq!(list[1].height, 2);
    assert_eq!(list[2].height, 1);

    // Delete one
    manager.delete_snapshot(&id_h2).ok_or("Automatic Remediation")?;

    let list = manager.list_snapshots().ok_or("Automatic Remediation")?;
    assert_eq!(list.len(), 2);

    // Can still restore from remaining snapshots
    store.blocks_by_height().clear().ok_or("Automatic Remediation")?;
    store.blocks_by_hash().clear().ok_or("Automatic Remediation")?;
    store.meta().clear().ok_or("Automatic Remediation")?;

    manager.restore(&id_h3).ok_or("Automatic Remediation")?;
    assert_eq!(store.latest_height().ok_or("Automatic Remediation")?, 3);
}

/// Test: Restore with account state
#[test]
fn test_snapshot_restore_account_state() {
    let dir = TempDir::new().ok_or("Automatic Remediation")?;
    let store = create_test_store(&dir);
    let snapshot_dir = dir.path().join("snapshots");

    let genesis = create_genesis_block();

    let alice = Address::new([1u8; 32]);
    let alice_account = AccountState::new(alice).with_wallet(WalletState::new(42));

    store.begin_block(0).ok_or("Automatic Remediation")?;
    store.append_block(&genesis).ok_or("Automatic Remediation")?;
    store.put_account(&alice, &alice_account).ok_or("Automatic Remediation")?;
    store.commit_block().ok_or("Automatic Remediation")?;

    let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(0).ok_or("Automatic Remediation")?;

    // Clear and restore
    store.blocks_by_height().clear().ok_or("Automatic Remediation")?;
    store.blocks_by_hash().clear().ok_or("Automatic Remediation")?;
    store.accounts().clear().ok_or("Automatic Remediation")?;
    store.meta().clear().ok_or("Automatic Remediation")?;

    manager.restore(&snapshot_id).ok_or("Automatic Remediation")?;

    // Verify account state
    let restored_account = store.get_account(&alice).ok_or("Automatic Remediation")?.ok_or("Automatic Remediation")?;
    assert_eq!(restored_account.wallet.ok_or("Automatic Remediation")?.nonce, 42);
}

/// Test: Snapshot with sync roundtrip
#[test]
fn test_snapshot_with_chain_sync_roundtrip() {
    let dir1 = TempDir::new().ok_or("Automatic Remediation")?;
    let dir2 = TempDir::new().ok_or("Automatic Remediation")?;
    let snapshot_dir = dir1.path().join("snapshots");

    let store1 = create_test_store(&dir1);
    let store2 = create_test_store(&dir2);

    // Build chain in store1
    let sync1 = ChainSync::new(Arc::clone(&store1) as Arc<dyn BlockchainStore>);

    let genesis = create_genesis_block();
    let mut blocks = vec![genesis.clone()];

    for height in 1..10 {
        let prev_hash = blocks.last().ok_or("Automatic Remediation")?.header.block_hash;
        let block = create_block_at_height(height, prev_hash);
        blocks.push(block);
    }

    sync1.import_blocks(blocks.clone()).ok_or("Automatic Remediation")?;

    // Add some state
    store1.begin_block(10).ok_or("Automatic Remediation")?;
    let block10 = create_block_at_height(
        10,
        store1
            .get_block_by_height(9)
            .ok_or("Automatic Remediation")?
            .ok_or("Automatic Remediation")?
            .header
            .block_hash,
    );
    store1.append_block(&block10).ok_or("Automatic Remediation")?;
    store1
        .set_token_balance(&TokenId::NATIVE, &Address::new([1u8; 32]), 999_999)
        .ok_or("Automatic Remediation")?;
    store1.commit_block().ok_or("Automatic Remediation")?;

    // Take snapshot
    let manager = SnapshotManager::new(Arc::clone(&store1), &snapshot_dir).ok_or("Automatic Remediation")?;
    let snapshot_id = manager.snapshot_at(10).ok_or("Automatic Remediation")?;

    // Export all blocks from store1
    let exported = sync1.export_all_blocks().ok_or("Automatic Remediation")?;
    assert_eq!(exported.len(), 11);

    // Import to store2 via ChainSync
    let sync2 = ChainSync::new(Arc::clone(&store2) as Arc<dyn BlockchainStore>);
    sync2.import_blocks(exported).ok_or("Automatic Remediation")?;

    // Both should be at height 10
    assert_eq!(store1.latest_height().ok_or("Automatic Remediation")?, 10);
    assert_eq!(store2.latest_height().ok_or("Automatic Remediation")?, 10);

    // Hashes should match
    let hash1 = store1
        .get_block_by_height(10)
        .ok_or("Automatic Remediation")?
        .ok_or("Automatic Remediation")?
        .header
        .block_hash;
    let hash2 = store2
        .get_block_by_height(10)
        .ok_or("Automatic Remediation")?
        .ok_or("Automatic Remediation")?
        .header
        .block_hash;
    assert_eq!(hash1, hash2);
}
