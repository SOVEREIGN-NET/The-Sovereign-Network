//! Sled-based BlockchainStore Implementation
//!
//! This is the ONLY storage backend in Phase 1.
//! Do not rely on sled-specific features beyond basic KV + transactions.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use sled::{Db, Tree, Batch};

use crate::block::Block;
use super::{
    keys, AccountState, Address, Amount, BlockchainStore, BlockHash, BlockHeight,
    OutPoint, StorageError, StorageResult, TokenId, Utxo,
};
use crate::contracts::TokenContract;

// =============================================================================
// TREE NAMES (FIXED - DO NOT CHANGE)
// =============================================================================
// These names are protocol. Changing them breaks migrations.
// =============================================================================

const TREE_BLOCKS_BY_HEIGHT: &str = "blocks_by_height";
const TREE_BLOCKS_BY_HASH: &str = "blocks_by_hash";
const TREE_UTXOS: &str = "utxos";
const TREE_ACCOUNTS: &str = "accounts";
const TREE_TOKEN_BALANCES: &str = "token_balances";
const TREE_TOKEN_CONTRACTS: &str = "token_contracts";
const TREE_META: &str = "meta";

/// Sled-based implementation of BlockchainStore
pub struct SledStore {
    db: Db,

    // Trees (opened once, reused)
    blocks_by_height: Tree,
    blocks_by_hash: Tree,
    utxos: Tree,
    accounts: Tree,
    token_balances: Tree,
    token_contracts: Tree,
    meta: Tree,

    // Transaction state
    tx_active: AtomicBool,
    tx_height: AtomicU64,
    tx_batch: Mutex<Option<PendingBatch>>,
}

/// Buffered changes for atomic commit
struct PendingBatch {
    blocks_by_height: Batch,
    blocks_by_hash: Batch,
    utxos: Batch,
    accounts: Batch,
    token_balances: Batch,
    token_contracts: Batch,
    meta: Batch,
    block_data: Option<(u64, BlockHash, Vec<u8>)>, // (height, hash, serialized block)
}

impl PendingBatch {
    fn new() -> Self {
        Self {
            blocks_by_height: Batch::default(),
            blocks_by_hash: Batch::default(),
            utxos: Batch::default(),
            accounts: Batch::default(),
            token_balances: Batch::default(),
            token_contracts: Batch::default(),
            meta: Batch::default(),
            block_data: None,
        }
    }
}

impl std::fmt::Debug for SledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SledStore")
            .field("tx_active", &self.tx_active.load(Ordering::SeqCst))
            .field("tx_height", &self.tx_height.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl SledStore {
    /// Open or create a SledStore at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let db = sled::open(path).map_err(|e| StorageError::Database(e.to_string()))?;

        let blocks_by_height = db
            .open_tree(TREE_BLOCKS_BY_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let blocks_by_hash = db
            .open_tree(TREE_BLOCKS_BY_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxos = db
            .open_tree(TREE_UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let accounts = db
            .open_tree(TREE_ACCOUNTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_balances = db
            .open_tree(TREE_TOKEN_BALANCES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_contracts = db
            .open_tree(TREE_TOKEN_CONTRACTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let meta = db
            .open_tree(TREE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            blocks_by_height,
            blocks_by_hash,
            utxos,
            accounts,
            token_balances,
            token_contracts,
            meta,
            tx_active: AtomicBool::new(false),
            tx_height: AtomicU64::new(0),
            tx_batch: Mutex::new(None),
        })
    }

    /// Open a temporary in-memory store (for testing)
    #[cfg(test)]
    pub fn open_temporary() -> StorageResult<Self> {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let blocks_by_height = db
            .open_tree(TREE_BLOCKS_BY_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let blocks_by_hash = db
            .open_tree(TREE_BLOCKS_BY_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxos = db
            .open_tree(TREE_UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let accounts = db
            .open_tree(TREE_ACCOUNTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_balances = db
            .open_tree(TREE_TOKEN_BALANCES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_contracts = db
            .open_tree(TREE_TOKEN_CONTRACTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let meta = db
            .open_tree(TREE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            blocks_by_height,
            blocks_by_hash,
            utxos,
            accounts,
            token_balances,
            token_contracts,
            meta,
            tx_active: AtomicBool::new(false),
            tx_height: AtomicU64::new(0),
            tx_batch: Mutex::new(None),
        })
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> StorageResult<()> {
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    // =========================================================================
    // Tree Accessors (for snapshot module)
    // =========================================================================

    /// Get direct access to blocks_by_height tree (for snapshots)
    pub fn blocks_by_height(&self) -> &Tree {
        &self.blocks_by_height
    }

    /// Get direct access to blocks_by_hash tree (for snapshots)
    pub fn blocks_by_hash(&self) -> &Tree {
        &self.blocks_by_hash
    }

    /// Get direct access to utxos tree (for snapshots)
    pub fn utxos(&self) -> &Tree {
        &self.utxos
    }

    /// Get direct access to accounts tree (for snapshots)
    pub fn accounts(&self) -> &Tree {
        &self.accounts
    }

    /// Get direct access to token_balances tree (for snapshots)
    pub fn token_balances(&self) -> &Tree {
        &self.token_balances
    }

    /// Get direct access to token_contracts tree (for snapshots)
    pub fn token_contracts(&self) -> &Tree {
        &self.token_contracts
    }

    /// Get direct access to meta tree (for snapshots)
    pub fn meta(&self) -> &Tree {
        &self.meta
    }

    /// Check if a transaction is active
    fn require_transaction(&self) -> StorageResult<()> {
        if !self.tx_active.load(Ordering::SeqCst) {
            return Err(StorageError::NoActiveTransaction);
        }
        Ok(())
    }

    /// Helper to serialize a value
    fn serialize<T: serde::Serialize>(value: &T) -> StorageResult<Vec<u8>> {
        bincode::serialize(value).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Helper to deserialize a value
    fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
        bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Get the current latest height, or None if chain is empty
    fn get_latest_height_internal(&self) -> StorageResult<Option<u64>> {
        match self.meta.get(keys::meta::LATEST_HEIGHT) {
            Ok(Some(bytes)) => {
                if bytes.len() != 8 {
                    return Err(StorageError::CorruptedData(
                        "Invalid latest_height length".to_string(),
                    ));
                }
                let height = u64::from_be_bytes(bytes.as_ref().try_into().unwrap());
                Ok(Some(height))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }
}

impl BlockchainStore for SledStore {
    // =========================================================================
    // Block Operations
    // =========================================================================

    fn append_block(&self, block: &Block) -> StorageResult<()> {
        self.require_transaction()?;

        let height = block.header.height;
        let expected_height = self.tx_height.load(Ordering::SeqCst);

        if height != expected_height {
            return Err(StorageError::InvalidBlockHeight {
                expected: expected_height,
                actual: height,
            });
        }

        // Compute block hash
        let hash_bytes: [u8; 32] = block.header.block_hash.as_array();
        let block_hash = BlockHash::new(hash_bytes);

        // Serialize block
        let block_bytes = Self::serialize(block)?;

        // Store in batch
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.block_data = Some((height, block_hash, block_bytes));
        }

        Ok(())
    }

    fn get_block_by_height(&self, h: BlockHeight) -> StorageResult<Option<Block>> {
        // Get block hash from height index
        let height_key = keys::block_height_key(h);
        let hash_bytes = match self.blocks_by_height.get(height_key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };

        // Get block data from hash index
        match self.blocks_by_hash.get(hash_bytes.as_ref()) {
            Ok(Some(block_bytes)) => {
                let block: Block = Self::deserialize(&block_bytes)?;
                Ok(Some(block))
            }
            Ok(None) => Err(StorageError::CorruptedData(format!(
                "Block hash exists at height {} but block data missing",
                h
            ))),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<Block>> {
        let hash_key = keys::block_hash_key(hash);
        match self.blocks_by_hash.get(hash_key) {
            Ok(Some(block_bytes)) => {
                let block: Block = Self::deserialize(&block_bytes)?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn latest_height(&self) -> StorageResult<BlockHeight> {
        self.get_latest_height_internal()?
            .ok_or(StorageError::NotInitialized)
    }

    // =========================================================================
    // UTXO Operations
    // =========================================================================

    fn get_utxo(&self, op: &OutPoint) -> StorageResult<Option<Utxo>> {
        let key = keys::utxo_key(op);
        match self.utxos.get(key) {
            Ok(Some(bytes)) => {
                let utxo: Utxo = Self::deserialize(&bytes)?;
                Ok(Some(utxo))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_utxo(&self, op: &OutPoint, u: &Utxo) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::utxo_key(op);
        let value = Self::serialize(u)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.utxos.insert(key.as_ref(), value);
        }

        Ok(())
    }

    fn delete_utxo(&self, op: &OutPoint) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::utxo_key(op);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.utxos.remove(key.as_ref());
        }

        Ok(())
    }

    // =========================================================================
    // Token Contract Operations
    // =========================================================================

    fn get_token_contract(&self, id: &TokenId) -> StorageResult<Option<TokenContract>> {
        let key = keys::token_contract_key(id);
        match self.token_contracts.get(key) {
            Ok(Some(bytes)) => {
                let contract: TokenContract = Self::deserialize(&bytes)?;
                Ok(Some(contract))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_token_contract(&self, c: &TokenContract) -> StorageResult<()> {
        self.require_transaction()?;

        let token_id = TokenId::new(c.token_id);
        let key = keys::token_contract_key(&token_id);
        let value = Self::serialize(c)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.token_contracts.insert(key.as_ref(), value);
        }

        Ok(())
    }

    // =========================================================================
    // Account Operations
    // =========================================================================

    fn get_account(&self, addr: &Address) -> StorageResult<Option<AccountState>> {
        let key = keys::account_key(addr);
        match self.accounts.get(key) {
            Ok(Some(bytes)) => {
                let account: AccountState = Self::deserialize(&bytes)?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_account(&self, addr: &Address, acct: &AccountState) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::account_key(addr);
        let value = Self::serialize(acct)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.accounts.insert(key.as_ref(), value);
        }

        Ok(())
    }

    // =========================================================================
    // Token Balance Operations
    // =========================================================================

    fn get_token_balance(&self, t: &TokenId, a: &Address) -> StorageResult<Amount> {
        let key = keys::token_balance_key(t, a);
        match self.token_balances.get(key) {
            Ok(Some(bytes)) => {
                if bytes.len() != 16 {
                    return Err(StorageError::CorruptedData(
                        "Invalid balance length".to_string(),
                    ));
                }
                let balance = u128::from_be_bytes(bytes.as_ref().try_into().unwrap());
                Ok(balance)
            }
            Ok(None) => Ok(0), // No balance = 0
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn set_token_balance(&self, t: &TokenId, a: &Address, v: Amount) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::token_balance_key(t, a);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            if v == 0 {
                // Optionally delete zero balances to save space
                batch.token_balances.remove(key.as_ref());
            } else {
                batch.token_balances.insert(key.as_ref(), &v.to_be_bytes());
            }
        }

        Ok(())
    }

    // =========================================================================
    // Transaction Control
    // =========================================================================

    fn begin_block(&self, height: BlockHeight) -> StorageResult<()> {
        // Check if transaction already active
        if self.tx_active.swap(true, Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }

        // Validate height
        let expected = match self.get_latest_height_internal()? {
            Some(h) => h + 1,
            None => 0, // Genesis case
        };

        if height != expected {
            self.tx_active.store(false, Ordering::SeqCst);
            return Err(StorageError::InvalidBlockHeight {
                expected,
                actual: height,
            });
        }

        // Initialize batch
        self.tx_height.store(height, Ordering::SeqCst);
        let mut batch_guard = self.tx_batch.lock().unwrap();
        *batch_guard = Some(PendingBatch::new());

        Ok(())
    }

    fn commit_block(&self) -> StorageResult<()> {
        self.require_transaction()?;

        let height = self.tx_height.load(Ordering::SeqCst);

        // Take the batch
        let batch = {
            let mut batch_guard = self.tx_batch.lock().unwrap();
            batch_guard.take().ok_or(StorageError::NoActiveTransaction)?
        };

        // Apply all batches
        // Note: sled doesn't have true multi-tree transactions, but batches
        // are applied atomically per-tree. For full atomicity, we'd need
        // a different approach, but this is acceptable for Phase 1.

        // Apply block data first (if present)
        if let Some((block_height, block_hash, block_bytes)) = batch.block_data {
            let height_key = keys::block_height_key(block_height);
            let hash_key = keys::block_hash_key(&block_hash);

            self.blocks_by_height
                .insert(height_key, block_hash.as_bytes().as_ref())
                .map_err(|e| StorageError::Database(e.to_string()))?;

            self.blocks_by_hash
                .insert(hash_key, block_bytes)
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }

        // Apply other batches
        self.utxos
            .apply_batch(batch.utxos)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.accounts
            .apply_batch(batch.accounts)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.token_balances
            .apply_batch(batch.token_balances)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.token_contracts
            .apply_batch(batch.token_contracts)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Update latest height
        self.meta
            .insert(keys::meta::LATEST_HEIGHT, &height.to_be_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Flush to ensure durability
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Clear transaction state
        self.tx_active.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn rollback_block(&self) -> StorageResult<()> {
        self.require_transaction()?;

        // Simply drop the batch
        let mut batch_guard = self.tx_batch.lock().unwrap();
        *batch_guard = None;

        // Clear transaction state
        self.tx_active.store(false, Ordering::SeqCst);

        Ok(())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{TxHash, WalletState};
    use crate::block::{Block, BlockHeader};
    use crate::types::{Hash, Difficulty};

    fn create_test_block(height: u64, prev_hash: Hash) -> Block {
        // Create a unique block hash based on height
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: prev_hash,
            merkle_root: Hash::default(),
            timestamp: 1000 + height,
            difficulty: Difficulty::default(),
            nonce: 0,
            height,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, vec![])
    }

    #[test]
    fn test_store_open_temporary() {
        let store = SledStore::open_temporary().unwrap();
        assert!(store.get_latest_height_internal().unwrap().is_none());
    }

    #[test]
    fn test_begin_block_genesis() {
        let store = SledStore::open_temporary().unwrap();

        // Begin genesis block
        store.begin_block(0).unwrap();
        store.rollback_block().unwrap();

        // Should be able to begin again after rollback
        store.begin_block(0).unwrap();
    }

    #[test]
    fn test_begin_block_wrong_height() {
        let store = SledStore::open_temporary().unwrap();

        // Trying to begin at height 1 without genesis should fail
        let result = store.begin_block(1);
        assert!(matches!(result, Err(StorageError::InvalidBlockHeight { .. })));
    }

    #[test]
    fn test_append_and_get_block() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());
        let block_hash = BlockHash::new(block.header.block_hash.as_array());

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.commit_block().unwrap();

        // Get by height
        let retrieved = store.get_block_by_height(0).unwrap().unwrap();
        assert_eq!(retrieved.header.height, 0);

        // Get by hash
        let retrieved = store.get_block_by_hash(&block_hash).unwrap().unwrap();
        assert_eq!(retrieved.header.height, 0);

        // Get latest height
        assert_eq!(store.latest_height().unwrap(), 0);
    }

    #[test]
    fn test_utxo_operations() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let outpoint = OutPoint::new(TxHash([0xab; 32]), 0);
        let utxo = Utxo::native(1000, Address([0xcd; 32]), 0);

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_utxo(&outpoint, &utxo).unwrap();
        store.commit_block().unwrap();

        // Get UTXO
        let retrieved = store.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved.amount, 1000);

        // Delete UTXO
        let block1 = create_test_block(1, block.header.block_hash);
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.delete_utxo(&outpoint).unwrap();
        store.commit_block().unwrap();

        // Should be gone
        assert!(store.get_utxo(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_account_operations() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let addr = Address([0xef; 32]);
        let account = AccountState::new(addr).with_wallet(WalletState::new(5));

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_account(&addr, &account).unwrap();
        store.commit_block().unwrap();

        // Get account
        let retrieved = store.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.wallet.unwrap().nonce, 5);
    }

    #[test]
    fn test_token_balance_operations() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let token = TokenId([0x11; 32]);
        let addr = Address([0x22; 32]);

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.set_token_balance(&token, &addr, 999_999).unwrap();
        store.commit_block().unwrap();

        // Get balance
        assert_eq!(store.get_token_balance(&token, &addr).unwrap(), 999_999);

        // Non-existent balance should be 0
        let other_addr = Address([0x33; 32]);
        assert_eq!(store.get_token_balance(&token, &other_addr).unwrap(), 0);
    }

    #[test]
    fn test_rollback_discards_changes() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let outpoint = OutPoint::new(TxHash([0x44; 32]), 0);
        let utxo = Utxo::native(500, Address([0x55; 32]), 0);

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_utxo(&outpoint, &utxo).unwrap();
        store.rollback_block().unwrap();

        // UTXO should not exist
        assert!(store.get_utxo(&outpoint).unwrap().is_none());

        // Chain should still be empty
        assert!(store.get_latest_height_internal().unwrap().is_none());
    }

    #[test]
    fn test_transaction_already_active() {
        let store = SledStore::open_temporary().unwrap();

        store.begin_block(0).unwrap();
        let result = store.begin_block(0);

        assert!(matches!(result, Err(StorageError::TransactionAlreadyActive)));
    }

    #[test]
    fn test_no_active_transaction() {
        let store = SledStore::open_temporary().unwrap();

        let outpoint = OutPoint::new(TxHash([0; 32]), 0);
        let utxo = Utxo::native(100, Address::ZERO, 0);

        // All write operations should fail without transaction
        assert!(matches!(
            store.put_utxo(&outpoint, &utxo),
            Err(StorageError::NoActiveTransaction)
        ));
        assert!(matches!(
            store.delete_utxo(&outpoint),
            Err(StorageError::NoActiveTransaction)
        ));
        assert!(matches!(
            store.put_account(&Address::ZERO, &AccountState::new(Address::ZERO)),
            Err(StorageError::NoActiveTransaction)
        ));
        assert!(matches!(
            store.set_token_balance(&TokenId::NATIVE, &Address::ZERO, 0),
            Err(StorageError::NoActiveTransaction)
        ));
    }

    #[test]
    fn test_multiple_blocks() {
        let store = SledStore::open_temporary().unwrap();

        let block0 = create_test_block(0, Hash::default());
        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store.commit_block().unwrap();

        let block1 = create_test_block(1, block0.header.block_hash);
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();

        let block2 = create_test_block(2, block1.header.block_hash);
        store.begin_block(2).unwrap();
        store.append_block(&block2).unwrap();
        store.commit_block().unwrap();

        assert_eq!(store.latest_height().unwrap(), 2);
        assert!(store.get_block_by_height(0).unwrap().is_some());
        assert!(store.get_block_by_height(1).unwrap().is_some());
        assert!(store.get_block_by_height(2).unwrap().is_some());
        assert!(store.get_block_by_height(3).unwrap().is_none());
    }
}
