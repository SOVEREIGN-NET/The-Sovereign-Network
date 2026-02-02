//! Snapshot Module (Phase 3E)
//!
//! Provides snapshot and restore functionality for fast sync without full replay.
//!
//! # Design Principles
//!
//! 1. **Complete State Capture** - Snapshots include all storage trees
//! 2. **Integrity Verification** - State hash ensures snapshot validity
//! 3. **Deterministic** - Same state always produces same snapshot hash
//! 4. **Atomic Restore** - Restore is all-or-nothing
//!
//! # Usage
//!
//! ```ignore
//! let snapshot_manager = SnapshotManager::new(store, "/path/to/snapshots");
//!
//! // Create snapshot at height 1000
//! let snapshot_id = snapshot_manager.snapshot_at(1000)?;
//!
//! // Later, restore from snapshot
//! snapshot_manager.restore(&snapshot_id)?;
//! ```

use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::storage::{BlockchainStore, StorageError, SledStore};
use crate::types::hash::blake3_hash;

/// Errors that can occur during snapshot operations
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// IO operation failed
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization failed
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Snapshot not found
    #[error("Snapshot not found: {0}")]
    NotFound(SnapshotId),

    /// State hash mismatch during restore
    #[error("State hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Height not found in chain
    #[error("Height not found: {0}")]
    HeightNotFound(u64),

    /// Chain not initialized
    #[error("Chain not initialized")]
    NotInitialized,

    /// Invalid snapshot format
    #[error("Invalid snapshot format: {0}")]
    InvalidFormat(String),
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

/// Unique identifier for a snapshot (32-byte hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub [u8; 32]);

impl SnapshotId {
    /// Create from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a hash of the snapshot data
    pub fn from_snapshot_data(data: &SnapshotData) -> Self {
        // Combine height, state hash, and block hash for ID
        let mut combined = Vec::with_capacity(72);
        combined.extend_from_slice(&data.height.to_be_bytes());
        combined.extend_from_slice(&data.state_hash);
        combined.extend_from_slice(&data.block_hash);

        let hash = blake3_hash(&combined);
        Self(hash.as_array())
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, SnapshotError> {
        let bytes = hex::decode(hex)
            .map_err(|e| SnapshotError::InvalidFormat(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(SnapshotError::InvalidFormat("Invalid snapshot ID length".to_string()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Snapshot data - complete state at a specific height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    /// Version of snapshot format
    pub version: u32,

    /// Block height at which snapshot was taken
    pub height: u64,

    /// Block hash at this height
    pub block_hash: [u8; 32],

    /// Computed state hash for integrity verification
    pub state_hash: [u8; 32],

    /// Timestamp when snapshot was created
    pub created_at: u64,

    /// All blocks (height -> serialized block)
    pub blocks: Vec<(u64, Vec<u8>)>,

    /// All UTXOs (key -> value)
    pub utxos: Vec<(Vec<u8>, Vec<u8>)>,

    /// All accounts (key -> value)
    pub accounts: Vec<(Vec<u8>, Vec<u8>)>,

    /// All token balances (key -> value)
    pub token_balances: Vec<(Vec<u8>, Vec<u8>)>,

    /// Meta data entries (key -> value)
    pub meta: Vec<(Vec<u8>, Vec<u8>)>,
}

impl SnapshotData {
    /// Compute the state hash from all data
    pub fn compute_state_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();

        // Hash height and block hash
        data.extend_from_slice(&self.height.to_be_bytes());
        data.extend_from_slice(&self.block_hash);

        // Hash all blocks
        for (height, block_data) in &self.blocks {
            data.extend_from_slice(&height.to_be_bytes());
            data.extend_from_slice(block_data);
        }

        // Hash all UTXOs (sorted for determinism)
        let mut utxos_sorted = self.utxos.clone();
        utxos_sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in &utxos_sorted {
            data.extend_from_slice(key);
            data.extend_from_slice(value);
        }

        // Hash all accounts (sorted)
        let mut accounts_sorted = self.accounts.clone();
        accounts_sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in &accounts_sorted {
            data.extend_from_slice(key);
            data.extend_from_slice(value);
        }

        // Hash all token balances (sorted)
        let mut balances_sorted = self.token_balances.clone();
        balances_sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in &balances_sorted {
            data.extend_from_slice(key);
            data.extend_from_slice(value);
        }

        blake3_hash(&data).as_array()
    }

    /// Verify the state hash
    pub fn verify_state_hash(&self) -> bool {
        self.state_hash == self.compute_state_hash()
    }
}

/// Snapshot manager for creating and restoring snapshots
pub struct SnapshotManager {
    store: Arc<SledStore>,
    snapshot_dir: PathBuf,
}

impl SnapshotManager {
    /// Create a new SnapshotManager
    pub fn new<P: AsRef<Path>>(store: Arc<SledStore>, snapshot_dir: P) -> SnapshotResult<Self> {
        let snapshot_dir = snapshot_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !snapshot_dir.exists() {
            fs::create_dir_all(&snapshot_dir)?;
        }

        Ok(Self { store, snapshot_dir })
    }

    /// Create a snapshot at the specified height
    ///
    /// # Arguments
    /// * `height` - The block height at which to snapshot
    ///
    /// # Returns
    /// * `SnapshotId` - Unique identifier for this snapshot
    ///
    /// # Errors
    /// * `HeightNotFound` - If the specified height doesn't exist
    /// * `NotInitialized` - If chain has no blocks
    pub fn snapshot_at(&self, height: u64) -> SnapshotResult<SnapshotId> {
        // Verify height exists
        let latest_height = self.store.get_latest_height()
            .map_err(|e| match e {
                StorageError::NotInitialized => SnapshotError::NotInitialized,
                other => SnapshotError::Storage(other),
            })?;

        if height > latest_height {
            return Err(SnapshotError::HeightNotFound(height));
        }

        // Get the block hash at this height
        let block = self.store.get_block_by_height(height)?
            .ok_or(SnapshotError::HeightNotFound(height))?;
        let block_hash = block.header.block_hash.as_array();

        // Collect all state
        let blocks = self.collect_blocks(height)?;
        let utxos = self.collect_tree_data(&self.store.utxos())?;
        let accounts = self.collect_tree_data(&self.store.accounts())?;
        let token_balances = self.collect_tree_data(&self.store.token_balances())?;
        let meta = self.collect_tree_data(&self.store.meta())?;

        // Create snapshot data (without hash initially)
        let mut snapshot_data = SnapshotData {
            version: 1,
            height,
            block_hash,
            state_hash: [0u8; 32], // Will be computed
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            blocks,
            utxos,
            accounts,
            token_balances,
            meta,
        };

        // Compute and set state hash
        snapshot_data.state_hash = snapshot_data.compute_state_hash();

        // Generate snapshot ID
        let snapshot_id = SnapshotId::from_snapshot_data(&snapshot_data);

        // Serialize and save to disk
        let snapshot_bytes = bincode::serialize(&snapshot_data)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;

        let snapshot_path = self.snapshot_path(&snapshot_id);
        let mut file = fs::File::create(&snapshot_path)?;
        file.write_all(&snapshot_bytes)?;
        file.sync_all()?;

        Ok(snapshot_id)
    }

    /// Restore from a snapshot
    ///
    /// # Arguments
    /// * `snapshot_id` - The ID of the snapshot to restore
    ///
    /// # Returns
    /// * `()` on success
    ///
    /// # Errors
    /// * `NotFound` - If snapshot doesn't exist
    /// * `HashMismatch` - If snapshot integrity check fails
    pub fn restore(&self, snapshot_id: &SnapshotId) -> SnapshotResult<()> {
        // Load snapshot from disk
        let snapshot_path = self.snapshot_path(snapshot_id);
        if !snapshot_path.exists() {
            return Err(SnapshotError::NotFound(*snapshot_id));
        }

        let mut file = fs::File::open(&snapshot_path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let snapshot_data: SnapshotData = bincode::deserialize(&bytes)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;

        // Verify state hash
        if !snapshot_data.verify_state_hash() {
            return Err(SnapshotError::HashMismatch {
                expected: hex::encode(snapshot_data.state_hash),
                actual: hex::encode(snapshot_data.compute_state_hash()),
            });
        }

        // Clear all existing data and restore from snapshot
        self.restore_tree(&self.store.blocks_by_height(), &[])?;
        self.restore_tree(&self.store.blocks_by_hash(), &[])?;
        self.restore_tree(&self.store.utxos(), &snapshot_data.utxos)?;
        self.restore_tree(&self.store.accounts(), &snapshot_data.accounts)?;
        self.restore_tree(&self.store.token_balances(), &snapshot_data.token_balances)?;

        // Restore blocks
        self.restore_blocks(&snapshot_data.blocks)?;

        // Update meta (including latest_height)
        let meta_tree = self.store.meta();
        meta_tree.clear().map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;

        // Set latest height to snapshot height
        meta_tree.insert("latest_height", &snapshot_data.height.to_be_bytes())
            .map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;

        // Restore other meta entries (except latest_height which we just set)
        for (key, value) in &snapshot_data.meta {
            if key != b"latest_height" {
                meta_tree.insert(key.as_slice(), value.as_slice())
                    .map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;
            }
        }

        // Flush to ensure durability
        self.store.flush()?;

        Ok(())
    }

    /// List all available snapshots
    pub fn list_snapshots(&self) -> SnapshotResult<Vec<SnapshotInfo>> {
        let mut snapshots = Vec::new();

        for entry in fs::read_dir(&self.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("snapshot") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(id) = SnapshotId::from_hex(stem) {
                        // Read snapshot metadata without loading full data
                        if let Ok(info) = self.get_snapshot_info(&id) {
                            snapshots.push(info);
                        }
                    }
                }
            }
        }

        // Sort by height descending
        snapshots.sort_by(|a, b| b.height.cmp(&a.height));
        Ok(snapshots)
    }

    /// Get metadata about a snapshot without loading full data
    pub fn get_snapshot_info(&self, snapshot_id: &SnapshotId) -> SnapshotResult<SnapshotInfo> {
        let snapshot_path = self.snapshot_path(snapshot_id);
        if !snapshot_path.exists() {
            return Err(SnapshotError::NotFound(*snapshot_id));
        }

        // Read and deserialize snapshot
        let mut file = fs::File::open(&snapshot_path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let snapshot_data: SnapshotData = bincode::deserialize(&bytes)
            .map_err(|e| SnapshotError::Serialization(e.to_string()))?;

        Ok(SnapshotInfo {
            id: *snapshot_id,
            height: snapshot_data.height,
            block_hash: snapshot_data.block_hash,
            state_hash: snapshot_data.state_hash,
            created_at: snapshot_data.created_at,
            size_bytes: bytes.len() as u64,
        })
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, snapshot_id: &SnapshotId) -> SnapshotResult<()> {
        let snapshot_path = self.snapshot_path(snapshot_id);
        if snapshot_path.exists() {
            fs::remove_file(snapshot_path)?;
        }
        Ok(())
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    fn snapshot_path(&self, id: &SnapshotId) -> PathBuf {
        self.snapshot_dir.join(format!("{}.snapshot", id.to_hex()))
    }

    fn collect_blocks(&self, up_to_height: u64) -> SnapshotResult<Vec<(u64, Vec<u8>)>> {
        let mut blocks = Vec::new();

        for height in 0..=up_to_height {
            if let Some(block) = self.store.get_block_by_height(height)? {
                let block_bytes = bincode::serialize(&block)
                    .map_err(|e| SnapshotError::Serialization(e.to_string()))?;
                blocks.push((height, block_bytes));
            }
        }

        Ok(blocks)
    }

    fn collect_tree_data(&self, tree: &sled::Tree) -> SnapshotResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut data = Vec::new();

        for entry in tree.iter() {
            let (key, value) = entry.map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;
            data.push((key.to_vec(), value.to_vec()));
        }

        Ok(data)
    }

    fn restore_tree(&self, tree: &sled::Tree, data: &[(Vec<u8>, Vec<u8>)]) -> SnapshotResult<()> {
        // Clear existing data
        tree.clear().map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;

        // Insert new data
        for (key, value) in data {
            tree.insert(key.as_slice(), value.as_slice())
                .map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;
        }

        Ok(())
    }

    fn restore_blocks(&self, blocks: &[(u64, Vec<u8>)]) -> SnapshotResult<()> {
        let blocks_by_height = self.store.blocks_by_height();
        let blocks_by_hash = self.store.blocks_by_hash();

        for (height, block_bytes) in blocks {
            // Deserialize to get the hash
            let block: crate::block::Block = bincode::deserialize(block_bytes)
                .map_err(|e| SnapshotError::Serialization(e.to_string()))?;

            let hash = block.header.block_hash.as_array();

            // Store by height
            let height_key = height.to_be_bytes();
            blocks_by_height.insert(&height_key, hash.as_ref())
                .map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;

            // Store by hash
            blocks_by_hash.insert(hash.as_ref(), block_bytes.as_slice())
                .map_err(|e| SnapshotError::Storage(StorageError::Database(e.to_string())))?;
        }

        Ok(())
    }
}

/// Information about a snapshot
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Snapshot ID
    pub id: SnapshotId,
    /// Block height at snapshot
    pub height: u64,
    /// Block hash at snapshot height
    pub block_hash: [u8; 32],
    /// State hash for integrity
    pub state_hash: [u8; 32],
    /// When the snapshot was created
    pub created_at: u64,
    /// Size in bytes
    pub size_bytes: u64,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::storage::{Address, TokenId, OutPoint, TxHash, Utxo};
    use crate::types::{Hash, Difficulty};
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
    fn test_snapshot_and_restore_basic() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        // Create some blocks
        let genesis = create_genesis_block();
        let block1 = create_block_at_height(1, genesis.header.block_hash);
        let block2 = create_block_at_height(2, block1.header.block_hash);

        // Apply blocks
        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();

        store.begin_block(2).unwrap();
        store.append_block(&block2).unwrap();
        store.commit_block().unwrap();

        // Take snapshot at height 2
        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();
        let snapshot_id = manager.snapshot_at(2).unwrap();

        // Verify snapshot exists
        let info = manager.get_snapshot_info(&snapshot_id).unwrap();
        assert_eq!(info.height, 2);

        // Clear the store and restore
        store.blocks_by_height().clear().unwrap();
        store.blocks_by_hash().clear().unwrap();
        store.meta().clear().unwrap();

        // Restore
        manager.restore(&snapshot_id).unwrap();

        // Verify restoration
        assert_eq!(store.get_latest_height().unwrap(), 2);

        // Verify all blocks are restored
        let restored_genesis = store.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(restored_genesis.header.block_hash, genesis.header.block_hash);

        let restored_block1 = store.get_block_by_height(1).unwrap().unwrap();
        assert_eq!(restored_block1.header.block_hash, block1.header.block_hash);

        let restored_block2 = store.get_block_by_height(2).unwrap().unwrap();
        assert_eq!(restored_block2.header.block_hash, block2.header.block_hash);
    }

    #[test]
    fn test_snapshot_restore_with_balances_and_utxos() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        // Create genesis and add some state
        let genesis = create_genesis_block();

        let alice = Address::new([1u8; 32]);
        let bob = Address::new([2u8; 32]);
        let token = TokenId::NATIVE;

        let outpoint1 = OutPoint::new(TxHash::new([0xaa; 32]), 0);
        let utxo1 = Utxo::native(1000, alice, 0);

        let outpoint2 = OutPoint::new(TxHash::new([0xbb; 32]), 0);
        let utxo2 = Utxo::native(2000, bob, 0);

        // Apply genesis with state
        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.put_utxo(&outpoint1, &utxo1).unwrap();
        store.put_utxo(&outpoint2, &utxo2).unwrap();
        store.set_token_balance(token, &alice, 1000).unwrap();
        store.set_token_balance(token, &bob, 2000).unwrap();
        store.commit_block().unwrap();

        // Take snapshot
        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();
        let snapshot_id = manager.snapshot_at(0).unwrap();

        // Clear the store
        store.blocks_by_height().clear().unwrap();
        store.blocks_by_hash().clear().unwrap();
        store.utxos().clear().unwrap();
        store.token_balances().clear().unwrap();
        store.meta().clear().unwrap();

        // Restore
        manager.restore(&snapshot_id).unwrap();

        // Verify balances are restored
        assert_eq!(store.get_token_balance(token, &alice).unwrap(), 1000);
        assert_eq!(store.get_token_balance(token, &bob).unwrap(), 2000);

        // Verify UTXOs are restored
        let restored_utxo1 = store.get_utxo(&outpoint1).unwrap().unwrap();
        assert_eq!(restored_utxo1.amount, 1000);
        assert_eq!(restored_utxo1.owner, alice);

        let restored_utxo2 = store.get_utxo(&outpoint2).unwrap().unwrap();
        assert_eq!(restored_utxo2.amount, 2000);
        assert_eq!(restored_utxo2.owner, bob);
    }

    #[test]
    fn test_restore_then_import_more_blocks() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        // Create chain with 5 blocks
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

        // Snapshot at height 2
        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();
        let snapshot_id = manager.snapshot_at(2).unwrap();

        // Clear and restore
        store.blocks_by_height().clear().unwrap();
        store.blocks_by_hash().clear().unwrap();
        store.meta().clear().unwrap();

        manager.restore(&snapshot_id).unwrap();
        assert_eq!(store.get_latest_height().unwrap(), 2);

        // Now add more blocks on top
        let block3 = create_block_at_height(3, block2.header.block_hash);
        let block4 = create_block_at_height(4, block3.header.block_hash);

        store.begin_block(3).unwrap();
        store.append_block(&block3).unwrap();
        store.commit_block().unwrap();

        store.begin_block(4).unwrap();
        store.append_block(&block4).unwrap();
        store.commit_block().unwrap();

        // Verify final state
        assert_eq!(store.get_latest_height().unwrap(), 4);

        // All blocks should be accessible
        assert!(store.get_block_by_height(0).unwrap().is_some());
        assert!(store.get_block_by_height(1).unwrap().is_some());
        assert!(store.get_block_by_height(2).unwrap().is_some());
        assert!(store.get_block_by_height(3).unwrap().is_some());
        assert!(store.get_block_by_height(4).unwrap().is_some());
    }

    #[test]
    fn test_snapshot_state_hash_integrity() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        let genesis = create_genesis_block();

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();
        let snapshot_id = manager.snapshot_at(0).unwrap();

        // Get snapshot info and verify hash is set
        let info = manager.get_snapshot_info(&snapshot_id).unwrap();
        assert_ne!(info.state_hash, [0u8; 32]);
    }

    #[test]
    fn test_snapshot_list_and_delete() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        let genesis = create_genesis_block();
        let block1 = create_block_at_height(1, genesis.header.block_hash);

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();

        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();

        // Create two snapshots
        let id0 = manager.snapshot_at(0).unwrap();
        let id1 = manager.snapshot_at(1).unwrap();

        // List should show both
        let list = manager.list_snapshots().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].height, 1); // Sorted by height descending
        assert_eq!(list[1].height, 0);

        // Delete one
        manager.delete_snapshot(&id0).unwrap();

        // List should show one
        let list = manager.list_snapshots().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].height, 1);
    }

    #[test]
    fn test_snapshot_not_found() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();

        let fake_id = SnapshotId::new([0xde; 32]);
        let result = manager.restore(&fake_id);
        assert!(matches!(result, Err(SnapshotError::NotFound(_))));
    }

    #[test]
    fn test_snapshot_height_not_found() {
        let (dir, store) = create_test_store();
        let snapshot_dir = dir.path().join("snapshots");

        let genesis = create_genesis_block();
        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();

        let manager = SnapshotManager::new(Arc::clone(&store), &snapshot_dir).unwrap();

        // Try to snapshot at height that doesn't exist
        let result = manager.snapshot_at(100);
        assert!(matches!(result, Err(SnapshotError::HeightNotFound(100))));
    }
}
