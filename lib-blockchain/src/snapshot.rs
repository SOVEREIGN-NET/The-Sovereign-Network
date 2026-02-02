//! Snapshot & Sync (Consensus-Critical)
//!
//! This module provides snapshot capture and restore functionality for
//! fast sync without requiring full block replay.
//!
//! # Design Principles
//!
//! 1. **Complete state capture**: Snapshots include all consensus-critical state
//! 2. **Integrity verification**: State hash ensures snapshot validity
//! 3. **Deterministic**: Same state always produces same snapshot hash
//! 4. **Clean resume**: After restore, block execution continues cleanly
//!
//! # Restore Guarantees
//!
//! After `restore()` completes successfully:
//! - Height is set to snapshot height
//! - All storage trees are populated
//! - Block execution can resume at height + 1

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::block::Block;
use crate::storage::{
    Address, BlockchainStore, BlockHash, OutPoint, SledStore, StorageError,
    TokenId, TxHash, Utxo,
};
use crate::types::hash::blake3_hash;
use crate::types::Hash;

use lib_types::BlockHeight;

// =============================================================================
// SNAPSHOT ERRORS
// =============================================================================

/// Errors that can occur during snapshot operations
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Serialization failed
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// State hash mismatch during restore
    #[error("State hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Height not found in chain
    #[error("Height not found: {0}")]
    HeightNotFound(BlockHeight),

    /// Chain not initialized
    #[error("Chain not initialized")]
    NotInitialized,

    /// Invalid snapshot version
    #[error("Invalid snapshot version: {0}")]
    InvalidVersion(u32),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

// =============================================================================
// SNAPSHOT STRUCTURE
// =============================================================================

/// Complete blockchain state snapshot
///
/// Contains all data necessary to restore a node to a specific height
/// without replaying blocks from genesis.
///
/// # Invariants
///
/// - `state_hash` MUST match `compute_state_hash()` after construction
/// - `height` MUST match the latest block's height
/// - `block_hash` MUST match the latest block's hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot format version (currently 1)
    pub version: u32,

    /// Block height at which snapshot was taken
    pub height: BlockHeight,

    /// Block hash at this height
    pub block_hash: [u8; 32],

    /// Computed state hash for integrity verification
    pub state_hash: [u8; 32],

    /// Timestamp when snapshot was created (Unix seconds)
    pub created_at: u64,

    /// All blocks up to and including this height
    pub blocks: Vec<BlockEntry>,

    /// All unspent transaction outputs
    pub utxos: Vec<UtxoEntry>,

    /// All token balances
    pub token_balances: Vec<TokenBalanceEntry>,

    /// All account states
    pub accounts: Vec<AccountEntry>,
}

/// A block entry in the snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// Block height
    pub height: BlockHeight,
    /// Serialized block data
    pub data: Vec<u8>,
}

/// A UTXO entry in the snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Output index
    pub index: u32,
    /// Serialized UTXO data
    pub data: Vec<u8>,
}

/// A token balance entry in the snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalanceEntry {
    /// Token ID
    pub token: [u8; 32],
    /// Address
    pub address: [u8; 32],
    /// Balance amount (u128 stored as 16 bytes)
    pub balance: u128,
}

/// An account entry in the snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    /// Account address
    pub address: [u8; 32],
    /// Serialized account state
    pub data: Vec<u8>,
}

impl Snapshot {
    /// Current snapshot format version
    pub const VERSION: u32 = 1;

    /// Create a new empty snapshot
    pub fn new(height: BlockHeight, block_hash: [u8; 32]) -> Self {
        Self {
            version: Self::VERSION,
            height,
            block_hash,
            state_hash: [0u8; 32],
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            blocks: Vec::new(),
            utxos: Vec::new(),
            token_balances: Vec::new(),
            accounts: Vec::new(),
        }
    }

    /// Compute the state hash from all snapshot data
    ///
    /// The hash covers:
    /// - Height and block hash
    /// - All blocks (sorted by height)
    /// - All UTXOs (sorted by outpoint)
    /// - All token balances (sorted by token+address)
    /// - All accounts (sorted by address)
    pub fn compute_state_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();

        // Hash height and block hash
        data.extend_from_slice(&self.height.to_be_bytes());
        data.extend_from_slice(&self.block_hash);

        // Hash all blocks (assumed sorted by height)
        for block in &self.blocks {
            data.extend_from_slice(&block.height.to_be_bytes());
            data.extend_from_slice(&block.data);
        }

        // Hash all UTXOs (sort by tx_hash then index for determinism)
        let mut utxos_sorted = self.utxos.clone();
        utxos_sorted.sort_by(|a, b| {
            (&a.tx_hash, a.index).cmp(&(&b.tx_hash, b.index))
        });
        for utxo in &utxos_sorted {
            data.extend_from_slice(&utxo.tx_hash);
            data.extend_from_slice(&utxo.index.to_be_bytes());
            data.extend_from_slice(&utxo.data);
        }

        // Hash all token balances (sort by token+address)
        let mut balances_sorted = self.token_balances.clone();
        balances_sorted.sort_by(|a, b| {
            (&a.token, &a.address).cmp(&(&b.token, &b.address))
        });
        for bal in &balances_sorted {
            data.extend_from_slice(&bal.token);
            data.extend_from_slice(&bal.address);
            data.extend_from_slice(&bal.balance.to_be_bytes());
        }

        // Hash all accounts (sort by address)
        let mut accounts_sorted = self.accounts.clone();
        accounts_sorted.sort_by(|a, b| a.address.cmp(&b.address));
        for acct in &accounts_sorted {
            data.extend_from_slice(&acct.address);
            data.extend_from_slice(&acct.data);
        }

        blake3_hash(&data).as_array()
    }

    /// Verify the state hash matches computed hash
    pub fn verify_state_hash(&self) -> bool {
        self.state_hash == self.compute_state_hash()
    }

    /// Finalize the snapshot by computing and setting the state hash
    pub fn finalize(&mut self) {
        self.state_hash = self.compute_state_hash();
    }
}

// =============================================================================
// SNAPSHOT FUNCTIONS
// =============================================================================

/// Create a snapshot from the current store state
///
/// Captures all blocks, UTXOs, token balances, and accounts at the
/// current chain tip.
///
/// # Arguments
///
/// * `store` - The blockchain store to snapshot
///
/// # Returns
///
/// A complete `Snapshot` with state_hash computed
///
/// # Errors
///
/// Returns error if:
/// - Store is not initialized (no genesis)
/// - Data serialization fails
pub fn snapshot(store: &SledStore) -> SnapshotResult<Snapshot> {
    // Get current height
    let height = store.latest_height().map_err(|e| match e {
        StorageError::NotInitialized => SnapshotError::NotInitialized,
        other => SnapshotError::Storage(other),
    })?;

    // Get block at current height for block hash
    let tip_block = store
        .get_block_by_height(height)?
        .ok_or(SnapshotError::HeightNotFound(height))?;
    let block_hash = tip_block.header.block_hash.as_array();

    let mut snap = Snapshot::new(height, block_hash);

    // Collect all blocks
    snap.blocks = collect_blocks(store, height)?;

    // Collect all UTXOs
    snap.utxos = collect_utxos(store)?;

    // Collect all token balances
    snap.token_balances = collect_token_balances(store)?;

    // Collect all accounts
    snap.accounts = collect_accounts(store)?;

    // Finalize with state hash
    snap.finalize();

    Ok(snap)
}

/// Restore store state from a snapshot
///
/// # Restore Guarantees
///
/// After successful restore:
/// 1. Height is set to snapshot height
/// 2. All trees are populated with snapshot data
/// 3. Block execution can resume cleanly at height + 1
///
/// # Arguments
///
/// * `store` - The blockchain store to restore into
/// * `snap` - The snapshot to restore from
///
/// # Errors
///
/// Returns error if:
/// - Snapshot state hash doesn't verify
/// - Snapshot version is unsupported
/// - Database operations fail
///
/// # Atomicity
///
/// Restore attempts to be atomic. If any step fails, the store may be
/// left in an inconsistent state and should be re-initialized from scratch.
pub fn restore(store: &SledStore, snap: Snapshot) -> SnapshotResult<()> {
    // Verify version
    if snap.version != Snapshot::VERSION {
        return Err(SnapshotError::InvalidVersion(snap.version));
    }

    // Verify state hash
    if !snap.verify_state_hash() {
        return Err(SnapshotError::HashMismatch {
            expected: hex::encode(snap.state_hash),
            actual: hex::encode(snap.compute_state_hash()),
        });
    }

    // Clear all existing data
    clear_all_trees(store)?;

    // Restore blocks
    restore_blocks(store, &snap.blocks)?;

    // Restore UTXOs
    restore_utxos(store, &snap.utxos)?;

    // Restore token balances
    restore_token_balances(store, &snap.token_balances)?;

    // Restore accounts
    restore_accounts(store, &snap.accounts)?;

    // Set the latest height
    let meta = store.meta();
    meta.insert("latest_height", &snap.height.to_be_bytes())
        .map_err(|e| SnapshotError::Database(e.to_string()))?;

    // Flush to ensure durability
    store.flush()?;

    Ok(())
}

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

fn collect_blocks(store: &SledStore, up_to_height: BlockHeight) -> SnapshotResult<Vec<BlockEntry>> {
    let mut blocks = Vec::new();

    for height in 0..=up_to_height {
        if let Some(block) = store.get_block_by_height(height)? {
            let data = bincode::serialize(&block)
                .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
            blocks.push(BlockEntry { height, data });
        }
    }

    Ok(blocks)
}

fn collect_utxos(store: &SledStore) -> SnapshotResult<Vec<UtxoEntry>> {
    let mut utxos = Vec::new();
    let utxo_tree = store.utxos();

    for entry in utxo_tree.iter() {
        let (key, value) = entry.map_err(|e| SnapshotError::Database(e.to_string()))?;

        // Key format: tx_hash (32 bytes) + index (4 bytes)
        if key.len() >= 36 {
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&key[..32]);
            let index = u32::from_be_bytes([key[32], key[33], key[34], key[35]]);

            utxos.push(UtxoEntry {
                tx_hash,
                index,
                data: value.to_vec(),
            });
        }
    }

    Ok(utxos)
}

fn collect_token_balances(store: &SledStore) -> SnapshotResult<Vec<TokenBalanceEntry>> {
    let mut balances = Vec::new();
    let balance_tree = store.token_balances();

    for entry in balance_tree.iter() {
        let (key, value) = entry.map_err(|e| SnapshotError::Database(e.to_string()))?;

        // Key format: token_id (32 bytes) + address (32 bytes)
        if key.len() >= 64 {
            let mut token = [0u8; 32];
            token.copy_from_slice(&key[..32]);
            let mut address = [0u8; 32];
            address.copy_from_slice(&key[32..64]);

            // Value is u128 balance (16 bytes)
            if value.len() >= 16 {
                let balance = u128::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                    value[4], value[5], value[6], value[7],
                    value[8], value[9], value[10], value[11],
                    value[12], value[13], value[14], value[15],
                ]);

                balances.push(TokenBalanceEntry {
                    token,
                    address,
                    balance,
                });
            }
        }
    }

    Ok(balances)
}

fn collect_accounts(store: &SledStore) -> SnapshotResult<Vec<AccountEntry>> {
    let mut accounts = Vec::new();
    let account_tree = store.accounts();

    for entry in account_tree.iter() {
        let (key, value) = entry.map_err(|e| SnapshotError::Database(e.to_string()))?;

        // Key format: address (32 bytes)
        if key.len() >= 32 {
            let mut address = [0u8; 32];
            address.copy_from_slice(&key[..32]);

            accounts.push(AccountEntry {
                address,
                data: value.to_vec(),
            });
        }
    }

    Ok(accounts)
}

fn clear_all_trees(store: &SledStore) -> SnapshotResult<()> {
    store.blocks_by_height().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;
    store.blocks_by_hash().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;
    store.utxos().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;
    store.accounts().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;
    store.token_balances().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;
    store.meta().clear()
        .map_err(|e| SnapshotError::Database(e.to_string()))?;

    Ok(())
}

fn restore_blocks(store: &SledStore, blocks: &[BlockEntry]) -> SnapshotResult<()> {
    let blocks_by_height = store.blocks_by_height();
    let blocks_by_hash = store.blocks_by_hash();

    for entry in blocks {
        // Deserialize to get hash
        let block: Block = bincode::deserialize(&entry.data)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
        let hash = block.header.block_hash.as_array();

        // Store by height (height -> hash)
        let height_key = entry.height.to_be_bytes();
        blocks_by_height.insert(&height_key, hash.as_ref())
            .map_err(|e| SnapshotError::Database(e.to_string()))?;

        // Store by hash (hash -> block data)
        blocks_by_hash.insert(hash.as_ref(), entry.data.as_slice())
            .map_err(|e| SnapshotError::Database(e.to_string()))?;
    }

    Ok(())
}

fn restore_utxos(store: &SledStore, utxos: &[UtxoEntry]) -> SnapshotResult<()> {
    let utxo_tree = store.utxos();

    for entry in utxos {
        // Reconstruct key: tx_hash + index
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(&entry.tx_hash);
        key.extend_from_slice(&entry.index.to_be_bytes());

        utxo_tree.insert(key.as_slice(), entry.data.as_slice())
            .map_err(|e| SnapshotError::Database(e.to_string()))?;
    }

    Ok(())
}

fn restore_token_balances(store: &SledStore, balances: &[TokenBalanceEntry]) -> SnapshotResult<()> {
    let balance_tree = store.token_balances();

    for entry in balances {
        // Reconstruct key: token + address
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(&entry.token);
        key.extend_from_slice(&entry.address);

        // Value is u128 balance (16 bytes)
        let value = entry.balance.to_be_bytes();

        balance_tree.insert(key.as_slice(), &value)
            .map_err(|e| SnapshotError::Database(e.to_string()))?;
    }

    Ok(())
}

fn restore_accounts(store: &SledStore, accounts: &[AccountEntry]) -> SnapshotResult<()> {
    let account_tree = store.accounts();

    for entry in accounts {
        account_tree.insert(&entry.address, entry.data.as_slice())
            .map_err(|e| SnapshotError::Database(e.to_string()))?;
    }

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::storage::BlockchainStore;
    use crate::types::{Hash, Difficulty};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_store() -> (TempDir, Arc<SledStore>) {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(SledStore::open(dir.path()).unwrap());
        (dir, store)
    }

    fn create_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01;
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            timestamp: 1000,
            difficulty: Difficulty::default(),
            nonce: 0,
            height: 0,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
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
            timestamp: 1000 + height * 600,
            difficulty: Difficulty::default(),
            nonce: 0,
            height,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2,
        };
        Block::new(header, vec![])
    }

    #[test]
    fn test_snapshot_empty_chain_fails() {
        let (_dir, store) = create_test_store();
        let result = snapshot(&store);
        assert!(matches!(result, Err(SnapshotError::NotInitialized)));
    }

    #[test]
    fn test_snapshot_and_restore_basic() {
        let (_dir, store) = create_test_store();

        // Create a chain with 3 blocks
        let genesis = create_genesis_block();
        let block1 = create_block_at_height(1, genesis.header.block_hash);
        let block2 = create_block_at_height(2, block1.header.block_hash);

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();

        store.begin_block(2).unwrap();
        store.append_block(&block2).unwrap();
        store.commit_block().unwrap();

        // Take snapshot
        let snap = snapshot(&store).unwrap();

        assert_eq!(snap.height, 2);
        assert_eq!(snap.block_hash, block2.header.block_hash.as_array());
        assert_eq!(snap.blocks.len(), 3);
        assert!(snap.verify_state_hash());

        // Clear store and restore
        clear_all_trees(&store).unwrap();

        // Verify store is empty
        assert!(store.get_block_by_height(0).unwrap().is_none());

        // Restore from snapshot
        restore(&store, snap).unwrap();

        // Verify restoration
        assert_eq!(store.latest_height().unwrap(), 2);

        let restored_genesis = store.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(restored_genesis.header.block_hash, genesis.header.block_hash);

        let restored_block1 = store.get_block_by_height(1).unwrap().unwrap();
        assert_eq!(restored_block1.header.block_hash, block1.header.block_hash);

        let restored_block2 = store.get_block_by_height(2).unwrap().unwrap();
        assert_eq!(restored_block2.header.block_hash, block2.header.block_hash);
    }

    #[test]
    fn test_snapshot_with_balances() {
        let (_dir, store) = create_test_store();

        let genesis = create_genesis_block();
        let alice = Address::new([1u8; 32]);
        let bob = Address::new([2u8; 32]);
        let token = TokenId::NATIVE;

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.set_token_balance(&token, &alice, 1000).unwrap();
        store.set_token_balance(&token, &bob, 2000).unwrap();
        store.commit_block().unwrap();

        // Take snapshot
        let snap = snapshot(&store).unwrap();
        assert_eq!(snap.token_balances.len(), 2);

        // Clear and restore
        clear_all_trees(&store).unwrap();
        restore(&store, snap).unwrap();

        // Verify balances restored
        assert_eq!(store.get_token_balance(&token, &alice).unwrap(), 1000);
        assert_eq!(store.get_token_balance(&token, &bob).unwrap(), 2000);
    }

    #[test]
    fn test_snapshot_with_utxos() {
        let (_dir, store) = create_test_store();

        let genesis = create_genesis_block();
        let alice = Address::new([1u8; 32]);
        let outpoint = OutPoint::new(TxHash::new([0xaa; 32]), 0);
        let utxo = Utxo::native(5000, alice, 0);

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.put_utxo(&outpoint, &utxo).unwrap();
        store.commit_block().unwrap();

        // Take snapshot
        let snap = snapshot(&store).unwrap();
        assert_eq!(snap.utxos.len(), 1);

        // Clear and restore
        clear_all_trees(&store).unwrap();
        restore(&store, snap).unwrap();

        // Verify UTXO restored
        let restored = store.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(restored.amount, 5000);
        assert_eq!(restored.owner, alice);
    }

    #[test]
    fn test_restore_then_add_blocks() {
        let (_dir, store) = create_test_store();

        // Create initial chain
        let genesis = create_genesis_block();
        let block1 = create_block_at_height(1, genesis.header.block_hash);

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();

        // Take snapshot
        let snap = snapshot(&store).unwrap();

        // Clear and restore
        clear_all_trees(&store).unwrap();
        restore(&store, snap).unwrap();

        // Add more blocks after restore
        let block2 = create_block_at_height(2, block1.header.block_hash);
        let block3 = create_block_at_height(3, block2.header.block_hash);

        store.begin_block(2).unwrap();
        store.append_block(&block2).unwrap();
        store.commit_block().unwrap();

        store.begin_block(3).unwrap();
        store.append_block(&block3).unwrap();
        store.commit_block().unwrap();

        // Verify final state
        assert_eq!(store.latest_height().unwrap(), 3);
        assert!(store.get_block_by_height(0).unwrap().is_some());
        assert!(store.get_block_by_height(1).unwrap().is_some());
        assert!(store.get_block_by_height(2).unwrap().is_some());
        assert!(store.get_block_by_height(3).unwrap().is_some());
    }

    #[test]
    fn test_snapshot_state_hash_integrity() {
        let (_dir, store) = create_test_store();

        let genesis = create_genesis_block();

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        let snap = snapshot(&store).unwrap();

        // State hash should be non-zero and verify
        assert_ne!(snap.state_hash, [0u8; 32]);
        assert!(snap.verify_state_hash());

        // Tampered snapshot should fail verification
        let mut tampered = snap.clone();
        tampered.height = 999;
        assert!(!tampered.verify_state_hash());
    }

    #[test]
    fn test_restore_invalid_hash_fails() {
        let (_dir, store) = create_test_store();

        // Create a snapshot with invalid state hash
        let mut snap = Snapshot::new(0, [0u8; 32]);
        snap.state_hash = [0xff; 32]; // Wrong hash

        let result = restore(&store, snap);
        assert!(matches!(result, Err(SnapshotError::HashMismatch { .. })));
    }

    #[test]
    fn test_restore_invalid_version_fails() {
        let (_dir, store) = create_test_store();

        let mut snap = Snapshot::new(0, [0u8; 32]);
        snap.version = 999; // Invalid version
        snap.finalize();

        let result = restore(&store, snap);
        assert!(matches!(result, Err(SnapshotError::InvalidVersion(999))));
    }

    #[test]
    fn test_snapshot_deterministic_hash() {
        let (_dir, store) = create_test_store();

        let genesis = create_genesis_block();

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        // Take two snapshots
        let snap1 = snapshot(&store).unwrap();
        let snap2 = snapshot(&store).unwrap();

        // State hashes should be identical
        assert_eq!(snap1.state_hash, snap2.state_hash);
    }
}
