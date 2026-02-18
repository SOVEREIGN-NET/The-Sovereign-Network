//! Block Synchronization Module (Phase 3A/3E)
//!
//! Provides deterministic export/import for chain sync without genesis regeneration
//! and without full memory loads.
//!
//! # Design Principles
//!
//! 1. **Import uses executor by default** - Standard imports go through `BlockExecutor::apply_block`
//! 2. **Canonical fallback for Contract/DAO txs** - Imports containing `Contract*`/`Dao*`
//!    transactions replay via canonical `Blockchain` runtime path
//! 3. **No direct state writes** - Import never writes directly to store
//! 4. **Atomic failure** - If any block fails, stop immediately; state reflects last committed block
//! 5. **Deterministic** - Same blocks always produce same state
//!
//! # Phase 3E: Snapshot and Fast Sync
//!
//! The snapshot module provides fast sync via state snapshots:
//! - `Snapshot::snapshot_at(height)` - Capture complete state at a height
//! - `Snapshot::restore(snapshot_id)` - Restore state from a snapshot
//!
//! ```ignore
//! // Export blocks from an existing chain
//! let blocks = chain_sync.export_blocks(0, 100)?;
//!
//! // Import blocks to a fresh store
//! chain_sync.import_blocks(blocks)?;
//!
//! // Or use snapshots for fast sync
//! let snapshot_id = snapshot_manager.snapshot_at(1000)?;
//! snapshot_manager.restore(&snapshot_id)?;
//! ```

pub mod snapshot;

pub use snapshot::{
    SnapshotError, SnapshotId, SnapshotInfo, SnapshotManager, SnapshotResult,
};

use std::sync::Arc;
use thiserror::Error;

use crate::block::Block;
use crate::execution::{BlockExecutor, ExecutorConfig, BlockApplyError};
use crate::storage::{BlockchainStore, StorageError};
use crate::types::TransactionType;

/// Errors that can occur during sync operations
#[derive(Debug, Error)]
pub enum SyncError {
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Block application failed
    #[error("Block apply failed at height {height}: {error}")]
    BlockApplyFailed {
        height: u64,
        error: BlockApplyError,
    },

    /// Invalid height range
    #[error("Invalid height range: from={from}, to={to}")]
    InvalidRange { from: u64, to: u64 },

    /// Block not found at expected height
    #[error("Block not found at height {0}")]
    BlockNotFound(u64),

    /// Chain not initialized (no genesis)
    #[error("Chain not initialized - no genesis block")]
    NotInitialized,

    /// Import height mismatch
    #[error("Import height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },

    /// Runtime import path failed
    #[error("Runtime import failed: {0}")]
    RuntimeImportFailed(String),
}

pub type SyncResult<T> = Result<T, SyncError>;

/// Chain synchronization handler
///
/// Provides export/import functionality for deterministic chain sync.
pub struct ChainSync {
    store: Arc<dyn BlockchainStore>,
    executor_config: ExecutorConfig,
}

impl ChainSync {
    /// Create a new ChainSync with the given store
    pub fn new(store: Arc<dyn BlockchainStore>) -> Self {
        Self {
            store,
            executor_config: ExecutorConfig::default(),
        }
    }

    /// Create with custom executor config
    pub fn with_config(store: Arc<dyn BlockchainStore>, config: ExecutorConfig) -> Self {
        Self {
            store,
            executor_config: config,
        }
    }

    /// Create with custom protocol params
    pub fn with_protocol_params(store: Arc<dyn BlockchainStore>, protocol_params: crate::protocol::ProtocolParams) -> Self {
        let mut config = ExecutorConfig::default();
        config.protocol_params = protocol_params;
        Self {
            store,
            executor_config: config,
        }
    }

    /// Get reference to the underlying store
    pub fn store(&self) -> &Arc<dyn BlockchainStore> {
        &self.store
    }

    // =========================================================================
    // Export API
    // =========================================================================

    /// Export blocks in a height range (inclusive).
    ///
    /// # Arguments
    /// * `from_height` - Starting block height (inclusive)
    /// * `to_height` - Ending block height (inclusive)
    ///
    /// # Returns
    /// Vector of blocks in order from `from_height` to `to_height`.
    ///
    /// # Errors
    /// - `InvalidRange` if from > to
    /// - `BlockNotFound` if any block in the range doesn't exist
    /// - `Storage` for underlying storage errors
    pub fn export_blocks(&self, from_height: u64, to_height: u64) -> SyncResult<Vec<Block>> {
        // Validate range
        if from_height > to_height {
            return Err(SyncError::InvalidRange {
                from: from_height,
                to: to_height,
            });
        }

        let mut blocks = Vec::with_capacity((to_height - from_height + 1) as usize);

        for height in from_height..=to_height {
            let block = self.store
                .get_block_by_height(height)?
                .ok_or(SyncError::BlockNotFound(height))?;
            blocks.push(block);
        }

        Ok(blocks)
    }

    /// Export all blocks from genesis to tip.
    ///
    /// # Returns
    /// Vector of all blocks in the chain.
    ///
    /// # Errors
    /// - `NotInitialized` if chain has no blocks
    /// - `Storage` for underlying storage errors
    pub fn export_all_blocks(&self) -> SyncResult<Vec<Block>> {
        let latest_height = self.store
            .latest_height()
            .map_err(|e| match e {
                StorageError::NotInitialized => SyncError::NotInitialized,
                other => SyncError::Storage(other),
            })?;

        self.export_blocks(0, latest_height)
    }

    // =========================================================================
    // Import API
    // =========================================================================

    /// Import blocks by replaying them through the executor.
    ///
    /// # Arguments
    /// * `blocks` - Blocks to import, must be in ascending height order
    ///
    /// # Rules
    /// 1. Default path: each block is applied through `BlockExecutor::apply_block`
    /// 2. Batches containing `Contract*`/`Dao*` tx variants replay through canonical
    ///    `Blockchain` runtime path for consensus parity
    /// 3. No direct state writes occur - all state changes go through executor/runtime
    /// 4. If ANY block fails: stop immediately, return error
    /// 5. On error, state reflects the last successfully committed block only
    ///
    /// # Errors
    /// - `HeightMismatch` if blocks are not in correct sequence
    /// - `BlockApplyFailed` if any block fails to apply
    /// - `Storage` for underlying storage errors
    pub fn import_blocks(&self, blocks: Vec<Block>) -> SyncResult<ImportResult> {
        if blocks.is_empty() {
            return Ok(ImportResult {
                blocks_imported: 0,
                final_height: None,
            });
        }

        if Self::requires_canonical_runtime_import(&blocks) {
            return self.import_blocks_via_canonical_runtime(blocks, None);
        }

        let executor = BlockExecutor::from_config(Arc::clone(&self.store), self.executor_config.clone());

        // Determine expected starting height
        let expected_start = match self.store.latest_height() {
            Ok(h) => h + 1,
            Err(StorageError::NotInitialized) => 0,
            Err(e) => return Err(SyncError::Storage(e)),
        };

        // Validate first block height
        let first_block_height = blocks[0].header.height;
        if first_block_height != expected_start {
            return Err(SyncError::HeightMismatch {
                expected: expected_start,
                actual: first_block_height,
            });
        }

        let mut imported_count = 0;
        let mut last_height = None;

        for block in blocks {
            let height = block.header.height;

            // Apply block through executor
            // This handles: prechecks, begin_block, apply txs, append_block, commit_block
            // On error: automatic rollback, state unchanged from before begin_block
            executor.apply_block(&block).map_err(|e| SyncError::BlockApplyFailed {
                height,
                error: e,
            })?;

            imported_count += 1;
            last_height = Some(height);
        }

        Ok(ImportResult {
            blocks_imported: imported_count,
            final_height: last_height,
        })
    }

    /// Import blocks with progress callback.
    ///
    /// Same as `import_blocks` but calls the callback after each successful block.
    pub fn import_blocks_with_progress<F>(
        &self,
        blocks: Vec<Block>,
        mut on_progress: F,
    ) -> SyncResult<ImportResult>
    where
        F: FnMut(u64, usize), // (height, total_imported)
    {
        if blocks.is_empty() {
            return Ok(ImportResult {
                blocks_imported: 0,
                final_height: None,
            });
        }

        if Self::requires_canonical_runtime_import(&blocks) {
            return self.import_blocks_via_canonical_runtime(blocks, Some(&mut on_progress));
        }

        let executor = BlockExecutor::from_config(Arc::clone(&self.store), self.executor_config.clone());

        // Determine expected starting height
        let expected_start = match self.store.latest_height() {
            Ok(h) => h + 1,
            Err(StorageError::NotInitialized) => 0,
            Err(e) => return Err(SyncError::Storage(e)),
        };

        // Validate first block height
        let first_block_height = blocks[0].header.height;
        if first_block_height != expected_start {
            return Err(SyncError::HeightMismatch {
                expected: expected_start,
                actual: first_block_height,
            });
        }

        let mut imported_count = 0;
        let mut last_height = None;

        for block in blocks {
            let height = block.header.height;

            executor.apply_block(&block).map_err(|e| SyncError::BlockApplyFailed {
                height,
                error: e,
            })?;

            imported_count += 1;
            last_height = Some(height);
            on_progress(height, imported_count);
        }

        Ok(ImportResult {
            blocks_imported: imported_count,
            final_height: last_height,
        })
    }

    /// Contract/DAO variants currently execute through canonical `Blockchain` flow,
    /// not `BlockExecutor`'s phase-2 transaction applicator.
    fn requires_canonical_runtime_import(blocks: &[Block]) -> bool {
        blocks.iter().any(Self::block_needs_canonical_runtime)
    }

    fn import_blocks_via_canonical_runtime(
        &self,
        blocks: Vec<Block>,
        mut on_progress: Option<&mut dyn FnMut(u64, usize)>,
    ) -> SyncResult<ImportResult> {
        let expected_start = match self.store.latest_height() {
            Ok(h) => h + 1,
            Err(StorageError::NotInitialized) => 0,
            Err(e) => return Err(SyncError::Storage(e)),
        };

        let first_block_height = blocks[0].header.height;
        if first_block_height != expected_start {
            return Err(SyncError::HeightMismatch {
                expected: expected_start,
                actual: first_block_height,
            });
        }

        let mut imported_count = 0usize;
        let mut last_height = None;
        let mut remaining_blocks = blocks;

        if expected_start == 0 {
            let split_index = remaining_blocks
                .iter()
                .position(|block| Self::block_needs_canonical_runtime(block))
                .unwrap_or(remaining_blocks.len());

            if split_index > 0 {
                let prefix: Vec<Block> = remaining_blocks.drain(..split_index).collect();
                let executor = BlockExecutor::from_config(
                    Arc::clone(&self.store),
                    self.executor_config.clone(),
                );

                for block in prefix {
                    let height = block.header.height;
                    executor.apply_block(&block).map_err(|e| SyncError::BlockApplyFailed {
                        height,
                        error: e,
                    })?;
                    imported_count += 1;
                    last_height = Some(height);
                    if let Some(progress) = on_progress.as_mut() {
                        progress(height, imported_count);
                    }
                }
            }
        }

        if remaining_blocks.is_empty() {
            return Ok(ImportResult {
                blocks_imported: imported_count,
                final_height: last_height,
            });
        }

        let canonical = self.run_canonical_import(remaining_blocks)?;
        if let Some(progress) = on_progress.as_mut() {
            for (offset, height) in canonical.heights.iter().enumerate() {
                progress(*height, imported_count + offset + 1);
            }
        }

        Ok(ImportResult {
            blocks_imported: imported_count + canonical.blocks_imported,
            final_height: canonical.final_height.or(last_height),
        })
    }

    fn block_needs_canonical_runtime(block: &Block) -> bool {
        block.transactions.iter().any(|tx| {
            matches!(
                tx.transaction_type,
                TransactionType::ContractDeployment
                    | TransactionType::ContractExecution
                    | TransactionType::DaoProposal
                    | TransactionType::DaoVote
                    | TransactionType::DaoExecution
            )
        })
    }

    fn run_canonical_import(&self, blocks: Vec<Block>) -> SyncResult<CanonicalImportResult> {
        if tokio::runtime::Handle::try_current().is_ok() {
            let store = Arc::clone(&self.store);
            std::thread::spawn(move || run_canonical_import_inner(store, blocks))
                .join()
                .map_err(|_| SyncError::RuntimeImportFailed("canonical import thread panicked".to_string()))?
        } else {
            run_canonical_import_inner(Arc::clone(&self.store), blocks)
        }
    }
}

#[derive(Debug, Clone)]
struct CanonicalImportResult {
    blocks_imported: usize,
    final_height: Option<u64>,
    heights: Vec<u64>,
}

fn run_canonical_import_inner(
    store: Arc<dyn BlockchainStore>,
    blocks: Vec<Block>,
) -> SyncResult<CanonicalImportResult> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| SyncError::RuntimeImportFailed(format!("failed to create runtime: {}", e)))?;

    rt.block_on(async move {
        let mut blockchain = crate::blockchain::Blockchain::load_from_store(Arc::clone(&store))
            .map_err(|e| SyncError::RuntimeImportFailed(format!("failed to load chain from store: {}", e)))?
            .ok_or_else(|| {
                SyncError::RuntimeImportFailed(
                    "canonical runtime import requires initialized chain state".to_string(),
                )
            })?;

        let mut heights = Vec::with_capacity(blocks.len());
        for block in blocks {
            let height = block.header.height;
            blockchain
                .add_block_from_network(block)
                .await
                .map_err(|e| SyncError::BlockApplyFailed {
                    height,
                    error: BlockApplyError::ValidationFailed(format!(
                        "canonical runtime import failed: {}",
                        e
                    )),
                })?;

            let persisted_height = store.latest_height().map_err(SyncError::Storage)?;
            if persisted_height < height {
                return Err(SyncError::BlockApplyFailed {
                    height,
                    error: BlockApplyError::ValidationFailed(format!(
                        "block at height {} was applied in runtime but not persisted to store (latest persisted height: {})",
                        height, persisted_height
                    )),
                });
            }
            heights.push(height);
        }

        Ok(CanonicalImportResult {
            blocks_imported: heights.len(),
            final_height: heights.last().copied(),
            heights,
        })
    })
}

/// Result of a successful import operation
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Number of blocks successfully imported
    pub blocks_imported: usize,
    /// Height of the last imported block (None if no blocks imported)
    pub final_height: Option<u64>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::storage::SledStore;
    use crate::transaction::Transaction;
    use crate::types::{Hash, Difficulty, TransactionType};
    use tempfile::TempDir;

    fn create_test_store() -> (TempDir, Arc<dyn BlockchainStore>) {
        let dir = TempDir::new().unwrap();
        let store: Arc<dyn BlockchainStore> = Arc::new(SledStore::open(dir.path()).unwrap());
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
            state_root: Hash::default(),
            timestamp: 1000,
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
            timestamp: 1000 + height,
            height,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, vec![])
    }

    fn create_test_tx(transaction_type: TransactionType) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![1u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: 0,
            },
            memo: vec![],
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            token_mint_data: None,
            governance_config_data: None,
        }
    }

    #[test]
    fn test_export_import_roundtrip() {
        // Create source chain with N blocks
        let (_dir1, store1) = create_test_store();
        let sync1 = ChainSync::new(Arc::clone(&store1));

        // Build 5 blocks
        let genesis = create_genesis_block();
        let mut blocks = vec![genesis.clone()];

        for height in 1..5 {
            let prev_hash = blocks.last().unwrap().header.block_hash;
            let block = create_block_at_height(height, prev_hash);
            blocks.push(block);
        }

        // Import blocks to source store
        let result = sync1.import_blocks(blocks.clone()).unwrap();
        assert_eq!(result.blocks_imported, 5);
        assert_eq!(result.final_height, Some(4));

        // Export all blocks
        let exported = sync1.export_all_blocks().unwrap();
        assert_eq!(exported.len(), 5);

        // Create destination chain and import
        let (_dir2, store2) = create_test_store();
        let sync2 = ChainSync::new(Arc::clone(&store2));

        let result2 = sync2.import_blocks(exported).unwrap();
        assert_eq!(result2.blocks_imported, 5);
        assert_eq!(result2.final_height, Some(4));

        // Verify chains match
        let latest1 = store1.latest_height().unwrap();
        let latest2 = store2.latest_height().unwrap();
        assert_eq!(latest1, latest2);

        for height in 0..=4 {
            let block1 = store1.get_block_by_height(height).unwrap().unwrap();
            let block2 = store2.get_block_by_height(height).unwrap().unwrap();
            assert_eq!(block1.header.block_hash, block2.header.block_hash);
        }
    }

    #[test]
    fn test_export_range() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(Arc::clone(&store));

        // Build 10 blocks
        let genesis = create_genesis_block();
        let mut blocks = vec![genesis.clone()];

        for height in 1..10 {
            let prev_hash = blocks.last().unwrap().header.block_hash;
            let block = create_block_at_height(height, prev_hash);
            blocks.push(block);
        }

        sync.import_blocks(blocks).unwrap();

        // Export subset
        let exported = sync.export_blocks(3, 7).unwrap();
        assert_eq!(exported.len(), 5);
        assert_eq!(exported[0].header.height, 3);
        assert_eq!(exported[4].header.height, 7);
    }

    #[test]
    fn test_invalid_range() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(store);

        let result = sync.export_blocks(10, 5);
        assert!(matches!(result, Err(SyncError::InvalidRange { .. })));
    }

    #[test]
    fn test_import_stops_on_error() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(Arc::clone(&store));

        // Create valid genesis
        let genesis = create_genesis_block();

        // Create block 1 with wrong previous hash (should fail)
        let mut bad_block = create_block_at_height(1, Hash::new([99u8; 32]));

        // Try to import - genesis should succeed, block 1 should fail
        let result = sync.import_blocks(vec![genesis.clone()]);
        assert!(result.is_ok());

        let result = sync.import_blocks(vec![bad_block]);
        assert!(matches!(result, Err(SyncError::BlockApplyFailed { height: 1, .. })));

        // Verify state reflects only genesis
        let latest = store.latest_height().unwrap();
        assert_eq!(latest, 0);
    }

    #[test]
    fn test_import_height_mismatch() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(Arc::clone(&store));

        // Import genesis first
        let genesis = create_genesis_block();
        sync.import_blocks(vec![genesis.clone()]).unwrap();

        // Try to import block 3 (skipping blocks 1 and 2)
        let block3 = create_block_at_height(3, Hash::new([1u8; 32]));

        let result = sync.import_blocks(vec![block3]);
        assert!(matches!(result, Err(SyncError::HeightMismatch { expected: 1, actual: 3 })));
    }

    #[test]
    fn test_empty_import() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(store);

        let result = sync.import_blocks(vec![]).unwrap();
        assert_eq!(result.blocks_imported, 0);
        assert_eq!(result.final_height, None);
    }

    #[test]
    fn test_requires_canonical_runtime_import_detection() {
        let normal_block = create_block_at_height(0, Hash::default());
        let canonical_header = create_block_at_height(1, normal_block.header.block_hash).header;
        let canonical_block = Block::new(
            canonical_header,
            vec![create_test_tx(TransactionType::ContractExecution)],
        );

        assert!(!ChainSync::requires_canonical_runtime_import(&[normal_block.clone()]));
        assert!(ChainSync::requires_canonical_runtime_import(&[normal_block, canonical_block]));
    }

    #[test]
    fn test_crash_simulation_no_partial_state() {
        // This test simulates what happens if we "crash" mid-import
        // Since each block is atomic, state should only reflect committed blocks

        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(Arc::clone(&store));

        // Create valid chain
        let genesis = create_genesis_block();
        let block1 = create_block_at_height(1, genesis.header.block_hash);

        // Create invalid block 2 (will fail)
        let invalid_block2 = create_block_at_height(2, Hash::new([99u8; 32])); // Wrong prev hash

        // Import first two valid blocks
        sync.import_blocks(vec![genesis.clone(), block1.clone()]).unwrap();

        // Verify state at height 1
        let height_before = store.latest_height().unwrap();
        assert_eq!(height_before, 1);

        // Try to import invalid block - should fail
        let result = sync.import_blocks(vec![invalid_block2]);
        assert!(result.is_err());

        // Verify state is EXACTLY at height 1 (no partial state from failed block)
        let height_after = store.latest_height().unwrap();
        assert_eq!(height_after, 1);

        // Can still continue with valid block
        let valid_block2 = create_block_at_height(2, block1.header.block_hash);
        sync.import_blocks(vec![valid_block2]).unwrap();

        let final_height = store.latest_height().unwrap();
        assert_eq!(final_height, 2);
    }

    #[test]
    fn test_progress_callback() {
        let (_dir, store) = create_test_store();
        let sync = ChainSync::new(Arc::clone(&store));

        // Build 5 blocks
        let genesis = create_genesis_block();
        let mut blocks = vec![genesis.clone()];

        for height in 1..5 {
            let prev_hash = blocks.last().unwrap().header.block_hash;
            let block = create_block_at_height(height, prev_hash);
            blocks.push(block);
        }

        let mut progress_calls = vec![];

        sync.import_blocks_with_progress(blocks, |height, count| {
            progress_calls.push((height, count));
        }).unwrap();

        assert_eq!(progress_calls.len(), 5);
        assert_eq!(progress_calls[0], (0, 1));
        assert_eq!(progress_calls[4], (4, 5));
    }
}
