//! Sled-based BlockchainStore Implementation
//!
//! This is the ONLY storage backend in Phase 1.
//! Do not rely on sled-specific features beyond basic KV + transactions.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use sled::{Batch, Db, IVec, Tree};

use super::{
    keys, AccountState, Address, Amount, BlockHash, BlockHeight, BlockchainStore,
    IdentityConsensus, IdentityMetadata, OutPoint, StorageError, StorageResult, TokenId,
    TokenStateSnapshot, Utxo,
};
use crate::block::Block;
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
const TREE_TOKEN_NONCES: &str = "token_nonces"; // Token transfer nonces for replay protection
const TREE_TOKEN_CONTRACTS: &str = "token_contracts";
const TREE_TOKEN_SUPPLY: &str = "token_supply"; // Total supply tracking
const TREE_CONTRACT_CODE: &str = "contract_code"; // WASM contract code
const TREE_CONTRACT_STORAGE: &str = "contract_storage"; // Contract key-value storage
const TREE_IDENTITIES: &str = "identities"; // Consensus state (participates in state hash)
const TREE_IDENTITY_METADATA: &str = "identity_meta"; // Non-consensus (for DID resolution)
const TREE_IDENTITY_BY_OWNER: &str = "identity_owner"; // Index: owner → did_hash
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
    token_nonces: Tree, // Nonce for token transfers (replay protection)
    token_contracts: Tree,
    token_supply: Tree,      // Total supply tracking for deflationary tokens
    contract_code: Tree,     // WASM contract code storage
    contract_storage: Tree,  // Contract key-value storage
    identities: Tree,        // Consensus: did_hash → IdentityConsensus
    identity_metadata: Tree, // Non-consensus: did_hash → IdentityMetadata
    identity_by_owner: Tree, // Index: owner_addr → did_hash
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
    token_nonces: Batch, // Nonce for token transfers
    token_contracts: Batch,
    token_supply: Batch,     // Total supply tracking
    contract_code: Batch,    // Contract code storage
    contract_storage: Batch, // Contract key-value storage
    identities: Batch,
    identity_metadata: Batch,
    identity_by_owner: Batch,
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
            token_nonces: Batch::default(),
            token_contracts: Batch::default(),
            token_supply: Batch::default(),
            contract_code: Batch::default(),
            contract_storage: Batch::default(),
            identities: Batch::default(),
            identity_metadata: Batch::default(),
            identity_by_owner: Batch::default(),
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
        let identities = db
            .open_tree(TREE_IDENTITIES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let identity_metadata = db
            .open_tree(TREE_IDENTITY_METADATA)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let identity_by_owner = db
            .open_tree(TREE_IDENTITY_BY_OWNER)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let meta = db
            .open_tree(TREE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_nonces = db
            .open_tree(TREE_TOKEN_NONCES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_supply = db
            .open_tree(TREE_TOKEN_SUPPLY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let contract_code = db
            .open_tree(TREE_CONTRACT_CODE)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let contract_storage = db
            .open_tree(TREE_CONTRACT_STORAGE)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            blocks_by_height,
            blocks_by_hash,
            utxos,
            accounts,
            token_balances,
            token_nonces,
            token_contracts,
            token_supply,
            contract_code,
            contract_storage,
            identities,
            identity_metadata,
            identity_by_owner,
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
        let identities = db
            .open_tree(TREE_IDENTITIES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let identity_metadata = db
            .open_tree(TREE_IDENTITY_METADATA)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let identity_by_owner = db
            .open_tree(TREE_IDENTITY_BY_OWNER)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let meta = db
            .open_tree(TREE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_nonces = db
            .open_tree(TREE_TOKEN_NONCES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let token_supply = db
            .open_tree(TREE_TOKEN_SUPPLY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let contract_code = db
            .open_tree(TREE_CONTRACT_CODE)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let contract_storage = db
            .open_tree(TREE_CONTRACT_STORAGE)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            blocks_by_height,
            blocks_by_hash,
            utxos,
            accounts,
            token_balances,
            token_nonces,
            token_contracts,
            token_supply,
            contract_code,
            contract_storage,
            identities,
            identity_metadata,
            identity_by_owner,
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

    /// Get direct access to underlying sled database
    ///
    /// Used by snapshot module to access trees not yet in SledStore
    /// (e.g., identities tree added by DID team in Phase 0)
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Get direct access to identities tree (for snapshots)
    pub fn identities(&self) -> &Tree {
        &self.identities
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

    fn iter_token_contracts(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = (TokenId, TokenContract)> + '_>> {
        use crate::contracts::TokenContract;

        let mut results = Vec::new();
        for result in self.token_contracts.iter() {
            match result {
                Ok((key, value)) => {
                    let token_id_arr: [u8; 32] = match key.as_ref().try_into() {
                        Ok(arr) => arr,
                        Err(_) => continue,
                    };
                    let token_id = TokenId::new(token_id_arr);
                    let contract: TokenContract = Self::deserialize(&value)?;
                    results.push((token_id, contract));
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }

        Ok(Box::new(results.into_iter()))
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

    fn get_token_supply(&self, token: &TokenId) -> StorageResult<Option<u64>> {
        let key = keys::token_supply_key(token);
        match self.token_supply.get(key) {
            Ok(Some(bytes)) => {
                let supply = u64::from_le_bytes(bytes.as_ref().try_into().map_err(|_| {
                    StorageError::Serialization("Failed to deserialize supply".into())
                })?);
                Ok(Some(supply))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_token_supply(&self, token: &TokenId, supply: u64) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::token_supply_key(token);
        let value = supply.to_le_bytes();

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.token_supply.insert(key.as_ref(), value.as_ref());
        }

        Ok(())
    }

    // =========================================================================
    // Smart Contract Storage (Phase 4)
    // =========================================================================

    fn get_contract_code(&self, contract_id: &[u8; 32]) -> StorageResult<Option<Vec<u8>>> {
        match self.contract_code.get(contract_id) {
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_contract_code(&self, contract_id: &[u8; 32], code: &[u8]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.contract_code.insert(contract_id, code);
        }

        Ok(())
    }

    fn get_contract_storage(
        &self,
        contract_id: &[u8; 32],
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        let mut composite_key = Vec::with_capacity(32 + key.len());
        composite_key.extend_from_slice(contract_id);
        composite_key.extend_from_slice(key);

        match self.contract_storage.get(&composite_key) {
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_contract_storage(
        &self,
        contract_id: &[u8; 32],
        key: &[u8],
        value: &[u8],
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let mut composite_key = Vec::with_capacity(32 + key.len());
        composite_key.extend_from_slice(contract_id);
        composite_key.extend_from_slice(key);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch
                .contract_storage
                .insert(IVec::from(composite_key), value);
        }

        Ok(())
    }

    fn delete_contract_storage(&self, contract_id: &[u8; 32], key: &[u8]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut composite_key = Vec::with_capacity(32 + key.len());
        composite_key.extend_from_slice(contract_id);
        composite_key.extend_from_slice(key);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.contract_storage.remove(IVec::from(composite_key));
        }

        Ok(())
    }

    fn get_token_state_snapshot(&self) -> StorageResult<Option<TokenStateSnapshot>> {
        match self.meta.get(keys::meta::TOKEN_STATE_SNAPSHOT) {
            Ok(Some(bytes)) => {
                let snapshot: TokenStateSnapshot = Self::deserialize(&bytes)?;
                Ok(Some(snapshot))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_token_state_snapshot(&self, snapshot: &TokenStateSnapshot) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(snapshot)?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.meta.insert(keys::meta::TOKEN_STATE_SNAPSHOT, value);
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
    // Token Transfer Nonce Operations (Replay Protection)
    // =========================================================================

    fn get_token_nonce(&self, token_id: &TokenId, sender: &Address) -> StorageResult<u64> {
        let key = keys::token_nonce_key(token_id, sender);
        match self.token_nonces.get(key.as_ref()) {
            Ok(Some(bytes)) => {
                if bytes.len() != 8 {
                    return Err(StorageError::CorruptedData(
                        "Invalid nonce length".to_string(),
                    ));
                }
                let nonce = u64::from_be_bytes(bytes.as_ref().try_into().unwrap());
                Ok(nonce)
            }
            Ok(None) => Ok(0), // No nonce = first transfer
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn set_token_nonce(
        &self,
        token_id: &TokenId,
        sender: &Address,
        nonce: u64,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::token_nonce_key(token_id, sender);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            if nonce == 0 {
                // Delete zero nonces to save space
                batch.token_nonces.remove(key.as_ref());
            } else {
                batch
                    .token_nonces
                    .insert(key.as_ref(), &nonce.to_be_bytes());
            }
        }

        Ok(())
    }

    // =========================================================================
    // Identity Consensus Operations (fixed-size keys only)
    // =========================================================================

    fn get_identity(&self, did_hash: &[u8; 32]) -> StorageResult<Option<IdentityConsensus>> {
        match self.identities.get(did_hash) {
            Ok(Some(bytes)) => {
                let identity: IdentityConsensus = Self::deserialize(&bytes)?;
                Ok(Some(identity))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_identity(&self, did_hash: &[u8; 32], identity: &IdentityConsensus) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(identity)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.identities.insert(did_hash.as_ref(), value);
        }

        Ok(())
    }

    fn delete_identity(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.identities.remove(did_hash.as_ref());
        }

        Ok(())
    }

    fn get_identity_by_owner(&self, addr: &Address) -> StorageResult<Option<[u8; 32]>> {
        let key = keys::identity_by_owner_key(addr);
        match self.identity_by_owner.get(key) {
            Ok(Some(bytes)) => {
                if bytes.len() != 32 {
                    return Err(StorageError::CorruptedData(
                        "Invalid did_hash length in identity_by_owner index".to_string(),
                    ));
                }
                let mut did_hash = [0u8; 32];
                did_hash.copy_from_slice(&bytes);
                Ok(Some(did_hash))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_identity_owner_index(&self, addr: &Address, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::identity_by_owner_key(addr);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch
                .identity_by_owner
                .insert(key.as_ref(), did_hash.as_ref());
        }

        Ok(())
    }

    fn delete_identity_owner_index(&self, addr: &Address) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::identity_by_owner_key(addr);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.identity_by_owner.remove(key.as_ref());
        }

        Ok(())
    }

    // =========================================================================
    // Identity Metadata Operations (non-consensus)
    // =========================================================================

    fn get_identity_metadata(
        &self,
        did_hash: &[u8; 32],
    ) -> StorageResult<Option<IdentityMetadata>> {
        match self.identity_metadata.get(did_hash) {
            Ok(Some(bytes)) => {
                let metadata: IdentityMetadata = Self::deserialize(&bytes)?;
                Ok(Some(metadata))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_identity_metadata(
        &self,
        did_hash: &[u8; 32],
        metadata: &IdentityMetadata,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(metadata)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.identity_metadata.insert(did_hash.as_ref(), value);
        }

        Ok(())
    }

    fn delete_identity_metadata(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.identity_metadata.remove(did_hash.as_ref());
        }

        Ok(())
    }

    fn get_identities_at_height(&self, height: u64) -> StorageResult<Vec<[u8; 32]>> {
        // Scan all identities and filter by registration height
        // Returns did_hashes, not full identity data
        let mut results = Vec::new();
        for result in self.identities.iter() {
            match result {
                Ok((key, value)) => {
                    let identity: IdentityConsensus = Self::deserialize(&value)?;
                    if identity.registered_at_height == height {
                        if key.len() == 32 {
                            let mut did_hash = [0u8; 32];
                            did_hash.copy_from_slice(&key);
                            results.push(did_hash);
                        }
                    }
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(results)
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
            batch_guard
                .take()
                .ok_or(StorageError::NoActiveTransaction)?
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

        self.identities
            .apply_batch(batch.identities)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.identity_metadata
            .apply_batch(batch.identity_metadata)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.identity_by_owner
            .apply_batch(batch.identity_by_owner)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.meta
            .apply_batch(batch.meta)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.contract_code
            .apply_batch(batch.contract_code)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        self.contract_storage
            .apply_batch(batch.contract_storage)
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
    use super::super::{TxHash, WalletState};
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::types::{Difficulty, Hash};

    fn create_test_block(height: u64, prev_hash: Hash) -> Block {
        // Create a unique block hash based on height
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: prev_hash,
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            timestamp: 1000 + height,
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
        assert!(matches!(
            result,
            Err(StorageError::InvalidBlockHeight { .. })
        ));
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

        assert!(matches!(
            result,
            Err(StorageError::TransactionAlreadyActive)
        ));
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

    // =========================================================================
    // Identity Tests (Consensus-Compliant Fixed-Size Types)
    // =========================================================================

    /// Helper to hash a DID string (simulates did_to_hash from mod.rs)
    fn hash_did(did: &str) -> [u8; 32] {
        blake3::hash(did.as_bytes()).into()
    }

    #[test]
    fn test_identity_consensus_operations() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let did = "did:zhtp:test123abc";
        let did_hash = hash_did(did);
        let owner = Address([0xaa; 32]);

        let identity = IdentityConsensus {
            did_hash,
            owner,
            public_key_hash: [0x01; 32],
            did_document_hash: [0x02; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 1,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &identity).unwrap();
        store.commit_block().unwrap();

        // Get identity by DID hash
        let retrieved = store.get_identity(&did_hash).unwrap().unwrap();
        assert_eq!(retrieved.did_hash, did_hash);
        assert_eq!(retrieved.owner, owner);
        assert_eq!(retrieved.identity_type, IdentityType::Human);

        // Non-existent identity should return None
        let nonexistent_hash = hash_did("did:zhtp:nonexistent");
        assert!(store.get_identity(&nonexistent_hash).unwrap().is_none());
    }

    #[test]
    fn test_identity_metadata_operations() {
        use super::super::{IdentityConsensus, IdentityMetadata, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let did = "did:zhtp:metadata_test";
        let did_hash = hash_did(did);
        let owner = Address([0xbb; 32]);

        let consensus = IdentityConsensus {
            did_hash,
            owner,
            public_key_hash: [0x03; 32],
            did_document_hash: [0x04; 32],
            seed_commitment: None,
            identity_type: IdentityType::Organization,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 2000,
            dao_fee: 200,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        let metadata = IdentityMetadata {
            did: did.to_string(),
            display_name: "Test Organization".to_string(),
            public_key: vec![0x05; 64],
            ownership_proof: vec![0x06; 128],
            controlled_nodes: vec![],
            owned_wallets: vec!["wallet-1".to_string()],
            attributes: vec![],
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &consensus).unwrap();
        store.put_identity_metadata(&did_hash, &metadata).unwrap();
        store.commit_block().unwrap();

        // Get consensus state (participates in state hash)
        let retrieved_consensus = store.get_identity(&did_hash).unwrap().unwrap();
        assert_eq!(
            retrieved_consensus.identity_type,
            IdentityType::Organization
        );

        // Get metadata (for DID resolution, non-consensus)
        let retrieved_metadata = store.get_identity_metadata(&did_hash).unwrap().unwrap();
        assert_eq!(retrieved_metadata.did, did);
        assert_eq!(retrieved_metadata.display_name, "Test Organization");
        assert_eq!(retrieved_metadata.owned_wallets, vec!["wallet-1"]);
    }

    #[test]
    fn test_identity_owner_index() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let did = "did:zhtp:owner_index_test";
        let did_hash = hash_did(did);
        let owner = Address([0xcc; 32]);

        let identity = IdentityConsensus {
            did_hash,
            owner,
            public_key_hash: [0x07; 32],
            did_document_hash: [0x08; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &identity).unwrap();
        store.put_identity_owner_index(&owner, &did_hash).unwrap();
        store.commit_block().unwrap();

        // Lookup by owner
        let found_did_hash = store.get_identity_by_owner(&owner).unwrap().unwrap();
        assert_eq!(found_did_hash, did_hash);

        // Non-existent owner should return None
        let other_owner = Address([0xdd; 32]);
        assert!(store.get_identity_by_owner(&other_owner).unwrap().is_none());
    }

    #[test]
    fn test_identity_with_seed_commitment() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let did = "did:zhtp:recovery_test";
        let did_hash = hash_did(did);
        let seed_commitment = [0xab; 32];

        let identity = IdentityConsensus {
            did_hash,
            owner: Address([0xee; 32]),
            public_key_hash: [0x09; 32],
            did_document_hash: [0x0a; 32],
            seed_commitment: Some(seed_commitment),
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &identity).unwrap();
        store.commit_block().unwrap();

        // Verify seed commitment persisted
        let retrieved = store.get_identity(&did_hash).unwrap().unwrap();
        assert_eq!(retrieved.seed_commitment, Some(seed_commitment));
        assert!(retrieved.verify_seed_commitment(&seed_commitment));
        assert!(!retrieved.verify_seed_commitment(&[0xcd; 32]));
    }

    #[test]
    fn test_identity_delete() {
        use super::super::{IdentityConsensus, IdentityMetadata, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block0 = create_test_block(0, Hash::default());
        let block1 = create_test_block(1, block0.header.block_hash);

        let did = "did:zhtp:to_be_deleted";
        let did_hash = hash_did(did);
        let owner = Address([0xff; 32]);

        let consensus = IdentityConsensus {
            did_hash,
            owner,
            public_key_hash: [0x0b; 32],
            did_document_hash: [0x0c; 32],
            seed_commitment: None,
            identity_type: IdentityType::Device,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 500,
            dao_fee: 50,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        let metadata = IdentityMetadata {
            did: did.to_string(),
            display_name: "Delete Me".to_string(),
            public_key: vec![0x0d; 64],
            ownership_proof: vec![],
            controlled_nodes: vec![],
            owned_wallets: vec![],
            attributes: vec![],
        };

        // Create identity
        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store.put_identity(&did_hash, &consensus).unwrap();
        store.put_identity_metadata(&did_hash, &metadata).unwrap();
        store.put_identity_owner_index(&owner, &did_hash).unwrap();
        store.commit_block().unwrap();

        assert!(store.get_identity(&did_hash).unwrap().is_some());
        assert!(store.get_identity_metadata(&did_hash).unwrap().is_some());
        assert!(store.get_identity_by_owner(&owner).unwrap().is_some());

        // Delete identity (all trees)
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.delete_identity(&did_hash).unwrap();
        store.delete_identity_metadata(&did_hash).unwrap();
        store.delete_identity_owner_index(&owner).unwrap();
        store.commit_block().unwrap();

        assert!(store.get_identity(&did_hash).unwrap().is_none());
        assert!(store.get_identity_metadata(&did_hash).unwrap().is_none());
        assert!(store.get_identity_by_owner(&owner).unwrap().is_none());
    }

    #[test]
    fn test_identity_rollback() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());

        let did = "did:zhtp:rollback_test";
        let did_hash = hash_did(did);

        let identity = IdentityConsensus {
            did_hash,
            owner: Address([0x11; 32]),
            public_key_hash: [0x0e; 32],
            did_document_hash: [0x0f; 32],
            seed_commitment: None,
            identity_type: IdentityType::Agent,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &identity).unwrap();
        store.rollback_block().unwrap();

        // Identity should not exist after rollback
        assert!(store.get_identity(&did_hash).unwrap().is_none());
    }

    #[test]
    fn test_get_identities_at_height() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block0 = create_test_block(0, Hash::default());
        let block1 = create_test_block(1, block0.header.block_hash);

        // Create two identities at height 0
        let did1 = "did:zhtp:height0_a";
        let did_hash1 = hash_did(did1);
        let id1 = IdentityConsensus {
            did_hash: did_hash1,
            owner: Address([0x21; 32]),
            public_key_hash: [0x10; 32],
            did_document_hash: [0x11; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        let did2 = "did:zhtp:height0_b";
        let did_hash2 = hash_did(did2);
        let id2 = IdentityConsensus {
            did_hash: did_hash2,
            owner: Address([0x22; 32]),
            public_key_hash: [0x12; 32],
            did_document_hash: [0x13; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store.put_identity(&did_hash1, &id1).unwrap();
        store.put_identity(&did_hash2, &id2).unwrap();
        store.commit_block().unwrap();

        // Create one identity at height 1
        let did3 = "did:zhtp:height1";
        let did_hash3 = hash_did(did3);
        let id3 = IdentityConsensus {
            did_hash: did_hash3,
            owner: Address([0x23; 32]),
            public_key_hash: [0x14; 32],
            did_document_hash: [0x15; 32],
            seed_commitment: None,
            identity_type: IdentityType::Organization,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1700000000,
            registered_at_height: 1,
            registration_fee: 2000,
            dao_fee: 200,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.put_identity(&did_hash3, &id3).unwrap();
        store.commit_block().unwrap();

        // Query by height - returns did_hashes, not full identity
        let height0_hashes = store.get_identities_at_height(0).unwrap();
        assert_eq!(height0_hashes.len(), 2);
        assert!(height0_hashes.contains(&did_hash1));
        assert!(height0_hashes.contains(&did_hash2));

        let height1_hashes = store.get_identities_at_height(1).unwrap();
        assert_eq!(height1_hashes.len(), 1);
        assert_eq!(height1_hashes[0], did_hash3);

        let height2_hashes = store.get_identities_at_height(2).unwrap();
        assert!(height2_hashes.is_empty());
    }
}
