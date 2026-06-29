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
    TokenStateSnapshot, Utxo, UtxoMerkleProof, WalletProjectionRecord,
};
use crate::block::Block;
use crate::contracts::TokenContract;
use crate::transaction::Transaction;
use crate::types::Hash;

// =============================================================================
// TREE NAMES (FIXED - DO NOT CHANGE)
// =============================================================================
// These names are protocol. Changing them breaks migrations.
// =============================================================================

const TREE_BLOCKS_BY_HEIGHT: &str = "blocks_by_height";
const TREE_BLOCKS_BY_HASH: &str = "blocks_by_hash";
const TREE_UTXOS: &str = "utxos";
const TREE_NULLIFIERS: &str = "nullifiers";
const TREE_UTXO_MERKLE_LEAVES: &str = "utxo_merkle_leaves";
const TREE_UTXO_MERKLE_INDEX: &str = "utxo_merkle_index";
const TREE_UTXO_MERKLE_META: &str = "utxo_merkle_meta";
const TREE_UTXO_MERKLE_NODES: &str = "utxo_merkle_nodes";
const TREE_ACCOUNTS: &str = "accounts";
const TREE_TOKEN_BALANCES: &str = "token_balances";
const TREE_TOKEN_NONCES: &str = "token_nonces"; // Token transfer nonces for replay protection
const TREE_TOKEN_CONTRACTS: &str = "token_contracts";
const TREE_TOKEN_SUPPLY: &str = "token_supply"; // Total supply tracking
const TREE_WALLETS: &str = "wallets"; // Rebuildable wallet projection: wallet_id -> WalletProjectionRecord
const TREE_CONTRACT_CODE: &str = "contract_code"; // WASM contract code
const TREE_CONTRACT_STORAGE: &str = "contract_storage"; // Contract key-value storage
const TREE_IDENTITIES: &str = "identities"; // Consensus state (participates in state hash)
const TREE_IDENTITY_METADATA: &str = "identity_meta"; // Non-consensus (for DID resolution)
const TREE_IDENTITY_BY_OWNER: &str = "identity_owner"; // Index: owner → did_hash
const TREE_VALIDATORS: &str = "validators"; // #56: did_hash → StoredValidatorRecord (consensus+metadata split)
const TREE_BONDING_CURVES: &str = "bonding_curves"; // Bonding curve tokens
const TREE_BONDING_CURVE_SYMBOLS: &str = "bonding_curve_symbols"; // Index: symbol → token_id
const TREE_CBE_ACCOUNTS: &str = "cbe_accounts"; // Canonical CBE account states (#1926)
const TREE_PENDING_TRANSACTIONS: &str = "pending_transactions"; // Non-consensus restart recovery
const TREE_QUORUM_PROOFS: &str = "quorum_proofs"; // BFT quorum proofs by height
const TREE_DAO_STAKES: &str = "dao_stakes"; // SOV stakes to sector DAOs: dao_key_id||staker → DaoStakeRecord
const TREE_OBSERVER_REGISTRY: &str = "observer_registry"; // Observer admission records: did_hash → ObserverAdmissionRecord
const TREE_META: &str = "meta";
const TREE_WAL: &str = "wal_block_commit"; // Write-ahead log for crash-safe block commits
const TREE_FORK_POINTS: &str = "fork_points"; // Fork audit log — direct durable writes
const TREE_RECEIPTS: &str = "receipts"; // Transaction receipts — direct writes, tx_hash → receipt
const TREE_PROJECTION_HOT_STATE_META: &str = "projection_hot_state_meta";
const TREE_PROJECTION_VALIDATORS: &str = "projection_validators";
const TREE_PROJECTION_GATEWAYS: &str = "projection_gateways";
const TREE_PROJECTION_DOMAINS: &str = "projection_domains";
const TREE_PROJECTION_CREDENTIALS: &str = "projection_credentials";
const TREE_PROJECTION_DID_USERNAMES: &str = "projection_did_usernames";
const TREE_PROJECTION_EMPLOYMENT: &str = "projection_employment";
const TREE_PROJECTION_DAO_REGISTRY: &str = "projection_dao_registry";
const TREE_PROJECTION_POUW_MINTS: &str = "projection_pouw_mints";
const TREE_PROJECTION_CONTRACT_BLOCKS: &str = "projection_contract_blocks";

/// The single key under which an in-progress block commit's post-image is
/// staged in the `wal` tree. Only one block commits at a time, so one key
/// suffices: present ⇒ a commit may be incomplete, absent ⇒ no commit pending.
const WAL_PENDING_KEY: &[u8] = b"pending_block_commit";

/// Upper bound on a serialized WAL record. A block-commit post-image is
/// realistically well under a few MiB; this cap exists purely so a corrupted
/// or maliciously crafted `wal` tree entry cannot drive an unbounded
/// allocation when `recover_pending_commit` runs at startup. The same limit
/// is applied on the write side so the two stay symmetric.
const MAX_WAL_RECORD_BYTES: u64 = 256 * 1024 * 1024;

/// Sled-based implementation of BlockchainStore
pub struct SledStore {
    db: Db,

    // Trees (opened once, reused)
    blocks_by_height: Tree,
    blocks_by_hash: Tree,
    utxos: Tree,
    nullifiers: Tree,
    accounts: Tree,
    wallets: Tree,
    token_balances: Tree,
    token_nonces: Tree, // Nonce for token transfers (replay protection)
    token_contracts: Tree,
    token_supply: Tree,          // Total supply tracking for deflationary tokens
    contract_code: Tree,         // WASM contract code storage
    contract_storage: Tree,      // Contract key-value storage
    identities: Tree,            // Consensus: did_hash → IdentityConsensus
    identity_metadata: Tree,     // Non-consensus: did_hash → IdentityMetadata
    identity_by_owner: Tree,     // Index: owner_addr → did_hash
    validators: Tree,            // #56: did_hash → StoredValidatorRecord (consensus+metadata split)
    bonding_curves: Tree,        // Bonding curve tokens: token_id → BondingCurveToken
    bonding_curve_symbols: Tree, // Index: symbol → token_id
    cbe_accounts: Tree,          // Canonical CBE account states: key_id → BondingCurveAccountState
    pending_transactions: Tree,  // Non-consensus mempool recovery state
    quorum_proofs: Tree,         // BFT quorum proofs by height
    dao_stakes: Tree,            // SOV stakes: dao_key_id (32) || staker (32) → DaoStakeRecord
    observer_registry: Tree,     // Observer admission: did_hash (32) → ObserverAdmissionRecord
    utxo_merkle_leaves: Tree,    // leaf_index (u64 BE) → [u8; 32] leaf hash
    utxo_merkle_index: Tree,     // outpoint (36 bytes) → leaf_index (u64 BE)
    utxo_merkle_meta: Tree,      // metadata: next_leaf_index, current_root
    utxo_merkle_nodes: Tree,     // level (u32 BE) || node_index (u64 BE) → [u8; 32]
    meta: Tree,
    wal: Tree,                   // Write-ahead log: durable block-commit post-image
    fork_points: Tree,           // Fork audit log: direct durable writes (non-batched)
    receipts: Tree,              // Transaction receipts: tx_hash → TransactionReceipt
    projection_hot_state_meta: Tree,
    projection_validators: Tree,
    projection_gateways: Tree,
    projection_domains: Tree,
    projection_credentials: Tree,
    projection_did_usernames: Tree,
    projection_employment: Tree,
    projection_dao_registry: Tree,
    projection_pouw_mints: Tree,
    projection_contract_blocks: Tree,

    // Transaction state
    tx_active: AtomicBool,
    tx_height: AtomicU64,
    tx_utxo_merkle_next_index: AtomicU64,
    tx_batch: Mutex<Option<PendingBatch>>,
}

/// One tree's worth of buffered key writes (insert-with-value, or remove).
///
/// Mirrors the `insert`/`remove` surface of sled's `Batch` so existing call
/// sites are unchanged — but unlike sled's opaque `Batch`, the operations can
/// be inspected and serialized. That is what makes the write-ahead log
/// possible: the post-image can be staged durably before it is applied.
#[derive(Default)]
struct TreeBatch {
    /// `(key, Some(value) = insert | None = remove)`, in insertion order.
    ops: Vec<(IVec, Option<IVec>)>,
}

impl TreeBatch {
    fn insert<K: Into<IVec>, V: Into<IVec>>(&mut self, key: K, value: V) {
        self.ops.push((key.into(), Some(value.into())));
    }

    fn remove<K: Into<IVec>>(&mut self, key: K) {
        self.ops.push((key.into(), None));
    }

    fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Serializable post-image: `(key, op)` pairs as owned byte vectors.
    fn to_post_image(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.ops
            .iter()
            .map(|(k, v)| (k.to_vec(), v.as_ref().map(|val| val.to_vec())))
            .collect()
    }
}

/// Apply a serialized post-image of `(key, op)` pairs to a sled `Tree` as one
/// atomic per-tree batch. Re-applying the same post-image is idempotent (blind
/// key→value writes), which is what makes WAL roll-forward recovery safe.
fn apply_tree_post_image(tree: &Tree, ops: &[(Vec<u8>, Option<Vec<u8>>)]) -> StorageResult<()> {
    let mut batch = Batch::default();
    for (key, value) in ops {
        match value {
            Some(val) => batch.insert(key.as_slice(), val.as_slice()),
            None => batch.remove(key.as_slice()),
        }
    }
    tree.apply_batch(batch)
        .map_err(|e| StorageError::Database(e.to_string()))
}

/// Durable write-ahead record of a block commit's full post-image.
///
/// Written atomically to the `wal` tree (and flushed) *before* any per-tree
/// batch is applied. sled commits each tree's batch atomically but provides no
/// atomicity *across* trees, so a crash mid-commit can leave a block partially
/// applied. If that happens, `recover_pending_commit` re-applies this record on
/// the next open: replaying the recorded key→value post-image is idempotent, so
/// rolling forward always reaches the fully-committed state. Recovery never
/// re-executes transactions — that would not be idempotent.
#[derive(serde::Serialize, serde::Deserialize)]
struct WalRecord {
    /// Height of the block being committed.
    height: u64,
    /// Hash of the block being committed (diagnostic / cross-check).
    block_hash: [u8; 32],
    /// Per-tree post-image: `(tree_name, [(key, Some(value) | None)])`.
    trees: Vec<(String, Vec<(Vec<u8>, Option<Vec<u8>>)>)>,
}

/// Buffered changes for one atomic commit.
///
/// Per-tree write batches are keyed by tree name in a single map, so adding a
/// storage tree needs no new struct field, no `new()` initializer, and no
/// `to_wal_record` line — the WAL path iterates the map generically.
struct PendingBatch {
    /// Tree name → buffered key writes. Only touched trees get an entry.
    trees: std::collections::BTreeMap<&'static str, TreeBatch>,
    /// Hash of the block staged via `append_block` (recorded in the WAL).
    block_hash: Option<[u8; 32]>,
    /// In-transaction cache of outpoints → leaf_index for the current block.
    utxo_merkle_indexed: std::collections::HashMap<[u8; 36], u64>,
    /// In-transaction cache of Merkle internal nodes for path updates.
    utxo_merkle_nodes_cache: std::collections::HashMap<[u8; 12], [u8; 32]>,
}

impl PendingBatch {
    fn new() -> Self {
        Self {
            trees: std::collections::BTreeMap::new(),
            block_hash: None,
            utxo_merkle_indexed: std::collections::HashMap::new(),
            utxo_merkle_nodes_cache: std::collections::HashMap::new(),
        }
    }

    /// Buffer for tree `name`, created empty on first use. `name` must be one
    /// of the canonical `TREE_*` constants (`tree_by_name` maps it back).
    fn tree(&mut self, name: &'static str) -> &mut TreeBatch {
        self.trees.entry(name).or_default()
    }

    /// Write-through read for staged operations.
    ///
    /// Returns:
    ///   `Some(Some(value))` — the key was inserted into `tree` during this
    ///                          block; return the staged value.
    ///   `Some(None)`        — the key was removed during this block; return
    ///                          "absent" (caller treats as default).
    ///   `None`              — the key was not touched in this block; caller
    ///                          should fall through to committed sled state.
    ///
    /// Scans the per-tree ops in REVERSE so the most-recent write wins, since
    /// repeated set_*/clear_* within a block append to `ops`. Required by the
    /// state-unification facade contract — a `get_*` issued by
    /// `process_*_transactions` or `finish_block_processing` after a staged
    /// write must observe that write, otherwise mid-block reads silently see
    /// pre-block state. (CR #2658 issue #2.)
    fn tree_lookup(&self, name: &'static str, key: &[u8]) -> Option<Option<IVec>> {
        let batch = self.trees.get(name)?;
        for (k, v) in batch.ops.iter().rev() {
            if k.as_ref() == key {
                return Some(v.clone());
            }
        }
        None
    }

    /// Build the durable WAL record for committing block `height`.
    /// Empty per-tree batches are omitted to keep the record compact.
    fn to_wal_record(&self, height: u64) -> WalRecord {
        let trees = self
            .trees
            .iter()
            .filter(|(_, b)| !b.is_empty())
            .map(|(name, b)| (name.to_string(), b.to_post_image()))
            .collect();
        WalRecord {
            height,
            block_hash: self.block_hash.unwrap_or([0u8; 32]),
            trees,
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
        Self::from_db(db)
    }

    /// Open a temporary in-memory store (for testing)
    #[cfg(test)]
    pub fn open_temporary() -> StorageResult<Self> {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Self::from_db(db)
    }

    /// Initialize a SledStore from an already-opened sled database.
    ///
    /// Single source of truth for tree names and struct initialization.
    /// Both `open` and `open_temporary` delegate here so a new tree added
    /// in one place is automatically present in both.
    fn from_db(db: sled::Db) -> StorageResult<Self> {
        let blocks_by_height = db
            .open_tree(TREE_BLOCKS_BY_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let blocks_by_hash = db
            .open_tree(TREE_BLOCKS_BY_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxos = db
            .open_tree(TREE_UTXOS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let nullifiers = db
            .open_tree(TREE_NULLIFIERS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let accounts = db
            .open_tree(TREE_ACCOUNTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let wallets = db
            .open_tree(TREE_WALLETS)
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
        let validators = db
            .open_tree(TREE_VALIDATORS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let bonding_curves = db
            .open_tree(TREE_BONDING_CURVES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let bonding_curve_symbols = db
            .open_tree(TREE_BONDING_CURVE_SYMBOLS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let cbe_accounts = db
            .open_tree(TREE_CBE_ACCOUNTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let pending_transactions = db
            .open_tree(TREE_PENDING_TRANSACTIONS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let quorum_proofs = db
            .open_tree(TREE_QUORUM_PROOFS)
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
        let dao_stakes = db
            .open_tree(TREE_DAO_STAKES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let observer_registry = db
            .open_tree(TREE_OBSERVER_REGISTRY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxo_merkle_leaves = db
            .open_tree(TREE_UTXO_MERKLE_LEAVES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxo_merkle_index = db
            .open_tree(TREE_UTXO_MERKLE_INDEX)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxo_merkle_meta = db
            .open_tree(TREE_UTXO_MERKLE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let utxo_merkle_nodes = db
            .open_tree(TREE_UTXO_MERKLE_NODES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let wal = db
            .open_tree(TREE_WAL)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let fork_points = db
            .open_tree(TREE_FORK_POINTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let receipts = db
            .open_tree(TREE_RECEIPTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_hot_state_meta = db
            .open_tree(TREE_PROJECTION_HOT_STATE_META)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_validators = db
            .open_tree(TREE_PROJECTION_VALIDATORS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_gateways = db
            .open_tree(TREE_PROJECTION_GATEWAYS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_domains = db
            .open_tree(TREE_PROJECTION_DOMAINS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_credentials = db
            .open_tree(TREE_PROJECTION_CREDENTIALS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_did_usernames = db
            .open_tree(TREE_PROJECTION_DID_USERNAMES)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_employment = db
            .open_tree(TREE_PROJECTION_EMPLOYMENT)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_dao_registry = db
            .open_tree(TREE_PROJECTION_DAO_REGISTRY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_pouw_mints = db
            .open_tree(TREE_PROJECTION_POUW_MINTS)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let projection_contract_blocks = db
            .open_tree(TREE_PROJECTION_CONTRACT_BLOCKS)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let store = Self {
            db,
            blocks_by_height,
            blocks_by_hash,
            utxos,
            nullifiers,
            accounts,
            wallets,
            token_balances,
            token_nonces,
            token_contracts,
            token_supply,
            contract_code,
            contract_storage,
            identities,
            identity_metadata,
            validators,
            identity_by_owner,
            bonding_curves,
            bonding_curve_symbols,
            cbe_accounts,
            pending_transactions,
            quorum_proofs,
            dao_stakes,
            observer_registry,
            utxo_merkle_leaves,
            utxo_merkle_index,
            utxo_merkle_meta,
            utxo_merkle_nodes,
            meta,
            wal,
            fork_points,
            receipts,
            projection_hot_state_meta,
            projection_validators,
            projection_gateways,
            projection_domains,
            projection_credentials,
            projection_did_usernames,
            projection_employment,
            projection_dao_registry,
            projection_pouw_mints,
            projection_contract_blocks,
            tx_active: AtomicBool::new(false),
            tx_height: AtomicU64::new(0),
            tx_utxo_merkle_next_index: AtomicU64::new(0),
            tx_batch: Mutex::new(None),
        };

        // Crash recovery: roll forward any block commit that was interrupted
        // before it could clear its write-ahead marker. Safe to run on every
        // open — a no-op when no commit is pending.
        store.recover_pending_commit()?;

        // CR PR #2679: brand-new stores (identity_metadata tree empty AND no
        // schema version key) get marked at the current version so the next
        // replay-based boot doesn't trigger a needless clear+rewrite migration.
        // An absent version key with NON-empty metadata still reads as v1 (the
        // legitimate legacy pre-versioning case) and is migrated as designed.
        let needs_init_marker = matches!(
            store.meta.get(keys::meta::IDENTITY_METADATA_SCHEMA_VERSION),
            Ok(None)
        ) && store.identity_metadata.is_empty();
        if needs_init_marker {
            store
                .meta
                .insert(
                    keys::meta::IDENTITY_METADATA_SCHEMA_VERSION,
                    &super::IDENTITY_METADATA_SCHEMA_VERSION.to_be_bytes(),
                )
                .map_err(|e| StorageError::Database(e.to_string()))?;
            store
                .meta
                .flush()
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }

        Ok(store)
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

    /// Get direct access to wallets projection tree.
    pub fn wallets(&self) -> &Tree {
        &self.wallets
    }

    /// Load a wallet projection entry by wallet id.
    pub fn get_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
    ) -> StorageResult<Option<WalletProjectionRecord>> {
        match self.wallets.get(wallet_id) {
            Ok(Some(bytes)) => {
                let record: WalletProjectionRecord = Self::deserialize(&bytes)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    /// Persist a wallet projection entry inside an active block transaction.
    pub fn put_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
        record: &WalletProjectionRecord,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(record)?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_WALLETS).insert(wallet_id.as_ref(), value);
        }

        Ok(())
    }

    /// Delete a wallet projection entry inside an active block transaction.
    pub fn delete_wallet_projection(&self, wallet_id: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_WALLETS).remove(wallet_id.as_ref());
        }

        Ok(())
    }

    /// Count wallet projection entries.
    pub fn count_wallet_projections(&self) -> StorageResult<usize> {
        Ok(self.wallets.len())
    }

    /// Iterate all wallet projection entries.
    pub fn iter_wallet_projections(&self) -> StorageResult<Vec<([u8; 32], WalletProjectionRecord)>> {
        let mut entries = Vec::new();
        for item in self.wallets.iter() {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.len() != 32 {
                return Err(StorageError::CorruptedData(
                    "Invalid wallet projection key length".to_string(),
                ));
            }
            let mut wallet_id = [0u8; 32];
            wallet_id.copy_from_slice(key.as_ref());
            let record: WalletProjectionRecord = Self::deserialize(&value)?;
            entries.push((wallet_id, record));
        }
        Ok(entries)
    }

    /// Replace the wallet projection tree outside block execution.
    ///
    /// This is used only for startup recovery of the rebuildable projection.
    pub fn replace_wallet_projections(
        &self,
        records: &[([u8; 32], WalletProjectionRecord)],
    ) -> StorageResult<()> {
        let mut batch = Batch::default();
        self.wallets.clear().map_err(|e| StorageError::Database(e.to_string()))?;
        for (wallet_id, record) in records {
            let value = Self::serialize(record)?;
            batch.insert(wallet_id.as_ref(), value);
        }
        self.wallets
            .apply_batch(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
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

    /// Build a 12-byte key for a Merkle internal node: `level (u32 BE) || node_index (u64 BE)`.
    fn merkle_node_key(level: u32, index: u64) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..4].copy_from_slice(&level.to_be_bytes());
        key[4..].copy_from_slice(&index.to_be_bytes());
        key
    }

    /// Precomputed zero hashes for each Merkle level.
    /// `zero_hashes[level]` is the hash of a zero-filled subtree at that height.
    fn merkle_zero_hashes() -> &'static Vec<[u8; 32]> {
        use std::sync::OnceLock;
        static ZERO_HASHES: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
        ZERO_HASHES.get_or_init(|| {
            let mut zh = vec![[0u8; 32]];
            for _ in 1..=lib_proofs::transaction::circuit::MERKLE_DEPTH {
                let last = *zh.last().unwrap();
                zh.push(lib_proofs::transaction::circuit::real::hash_pair_u8(last, last));
            }
            zh
        })
    }

    /// Read a Merkle node from the in-flight batch cache or the committed tree.
    fn get_merkle_node(
        &self,
        batch: &PendingBatch,
        level: u32,
        index: u64,
    ) -> StorageResult<[u8; 32]> {
        let key = Self::merkle_node_key(level, index);
        if let Some(&hash) = batch.utxo_merkle_nodes_cache.get(&key) {
            return Ok(hash);
        }
        match self.utxo_merkle_nodes.get(key) {
            Ok(Some(bytes)) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            }
            Ok(_) => Ok(Self::merkle_zero_hashes()[level as usize]),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    /// Update the Merkle path from `leaf_index` up to the root using `leaf_hash`.
    fn update_merkle_path(
        &self,
        leaf_index: u64,
        leaf_hash: [u8; 32],
    ) -> StorageResult<()> {
        let mut batch_guard = self.tx_batch.lock().unwrap();
        let batch = batch_guard.as_mut().ok_or(StorageError::NoActiveTransaction)?;

        let mut current_hash = leaf_hash;
        let mut current_index = leaf_index;

        for level in 0..lib_proofs::transaction::circuit::MERKLE_DEPTH as u32 {
            let key = Self::merkle_node_key(level, current_index);
            batch.utxo_merkle_nodes_cache.insert(key, current_hash);
            batch.tree(TREE_UTXO_MERKLE_NODES).insert(key.as_ref(), current_hash.as_ref());

            let sibling_index = current_index ^ 1;
            let sibling_hash = self.get_merkle_node(batch, level, sibling_index)?;

            current_hash = if current_index % 2 == 0 {
                lib_proofs::transaction::circuit::real::hash_pair_u8(current_hash, sibling_hash)
            } else {
                lib_proofs::transaction::circuit::real::hash_pair_u8(sibling_hash, current_hash)
            };
            current_index /= 2;
        }

        let depth = lib_proofs::transaction::circuit::MERKLE_DEPTH as u32;
        let root_key = Self::merkle_node_key(depth, 0);
        batch.utxo_merkle_nodes_cache.insert(root_key, current_hash);
        batch.tree(TREE_UTXO_MERKLE_NODES).insert(root_key.as_ref(), current_hash.as_ref());
        batch.tree(TREE_UTXO_MERKLE_META).insert(
            keys::meta::UTXO_MERKLE_ROOT,
            current_hash.as_ref(),
        );

        Ok(())
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

    /// Serialize a WAL record with an explicit byte limit.
    ///
    /// The limit is applied symmetrically with [`Self::deserialize_wal`]; both
    /// use `bincode::DefaultOptions` (whose encoding differs from the bare
    /// `bincode::serialize`), so WAL records MUST round-trip exclusively
    /// through this pair.
    fn serialize_wal<T: serde::Serialize>(value: &T) -> StorageResult<Vec<u8>> {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_limit(MAX_WAL_RECORD_BYTES)
            .serialize(value)
            .map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Deserialize a WAL record, refusing anything that would read past
    /// [`MAX_WAL_RECORD_BYTES`].
    ///
    /// `recover_pending_commit` runs this at startup against `wal` tree
    /// contents that are not yet trusted: a corrupted entry could otherwise
    /// encode enormous length prefixes and drive bincode into an unbounded
    /// allocation. The explicit `bytes.len()` guard rejects an oversized
    /// record outright; the `with_limit` config bounds allocation driven by
    /// internal length prefixes within an otherwise small record.
    fn deserialize_wal<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
        use bincode::Options;
        if bytes.len() as u64 > MAX_WAL_RECORD_BYTES {
            return Err(StorageError::CorruptedData(format!(
                "WAL record is {} bytes, exceeds the {}-byte maximum — refusing to deserialize",
                bytes.len(),
                MAX_WAL_RECORD_BYTES,
            )));
        }
        bincode::DefaultOptions::new()
            .with_limit(MAX_WAL_RECORD_BYTES)
            .deserialize(bytes)
            .map_err(|e| StorageError::Serialization(e.to_string()))
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

    fn nullifier_checkpoint_value(height: BlockHeight, block_hash: &BlockHash) -> [u8; 40] {
        let mut value = [0u8; 40];
        value[..8].copy_from_slice(&height.to_be_bytes());
        value[8..].copy_from_slice(block_hash.as_bytes());
        value
    }

    fn nullifier_index_is_current_internal(
        &self,
        height: BlockHeight,
        block_hash: &BlockHash,
    ) -> StorageResult<bool> {
        let expected = Self::nullifier_checkpoint_value(height, block_hash);
        match self.meta.get(keys::meta::NULLIFIER_INDEX_CHECKPOINT) {
            Ok(Some(bytes)) => Ok(bytes.as_ref() == expected),
            Ok(None) => Ok(false),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    /// Map a canonical `TREE_*` name back to its live tree handle.
    ///
    /// Used to replay a WAL post-image onto the correct trees. Only the trees
    /// that participate in a block commit are listed.
    fn tree_by_name(&self, name: &str) -> Option<&Tree> {
        Some(match name {
            TREE_BLOCKS_BY_HEIGHT => &self.blocks_by_height,
            TREE_BLOCKS_BY_HASH => &self.blocks_by_hash,
            TREE_UTXOS => &self.utxos,
            TREE_NULLIFIERS => &self.nullifiers,
            TREE_ACCOUNTS => &self.accounts,
            TREE_WALLETS => &self.wallets,
            TREE_TOKEN_BALANCES => &self.token_balances,
            TREE_TOKEN_NONCES => &self.token_nonces,
            TREE_TOKEN_CONTRACTS => &self.token_contracts,
            TREE_TOKEN_SUPPLY => &self.token_supply,
            TREE_CONTRACT_CODE => &self.contract_code,
            TREE_CONTRACT_STORAGE => &self.contract_storage,
            TREE_IDENTITIES => &self.identities,
            TREE_IDENTITY_METADATA => &self.identity_metadata,
            TREE_IDENTITY_BY_OWNER => &self.identity_by_owner,
            TREE_VALIDATORS => &self.validators,
            TREE_BONDING_CURVES => &self.bonding_curves,
            TREE_BONDING_CURVE_SYMBOLS => &self.bonding_curve_symbols,
            TREE_CBE_ACCOUNTS => &self.cbe_accounts,
            TREE_DAO_STAKES => &self.dao_stakes,
            TREE_OBSERVER_REGISTRY => &self.observer_registry,
            TREE_UTXO_MERKLE_LEAVES => &self.utxo_merkle_leaves,
            TREE_UTXO_MERKLE_INDEX => &self.utxo_merkle_index,
            TREE_UTXO_MERKLE_META => &self.utxo_merkle_meta,
            TREE_UTXO_MERKLE_NODES => &self.utxo_merkle_nodes,
            TREE_META => &self.meta,
            TREE_PROJECTION_HOT_STATE_META => &self.projection_hot_state_meta,
            TREE_PROJECTION_VALIDATORS => &self.projection_validators,
            TREE_PROJECTION_GATEWAYS => &self.projection_gateways,
            TREE_PROJECTION_DOMAINS => &self.projection_domains,
            TREE_PROJECTION_CREDENTIALS => &self.projection_credentials,
            TREE_PROJECTION_DID_USERNAMES => &self.projection_did_usernames,
            TREE_PROJECTION_EMPLOYMENT => &self.projection_employment,
            TREE_PROJECTION_DAO_REGISTRY => &self.projection_dao_registry,
            TREE_PROJECTION_POUW_MINTS => &self.projection_pouw_mints,
            TREE_PROJECTION_CONTRACT_BLOCKS => &self.projection_contract_blocks,
            _ => return None,
        })
    }

    /// Apply a WAL post-image: every recorded tree's key writes, then
    /// `latest_height`, then flush for durability.
    ///
    /// Each tree's batch is atomic; the WAL record guarantees the whole set is
    /// re-applied together after a crash. This is idempotent — re-applying an
    /// already-committed record rewrites identical bytes — which is what makes
    /// roll-forward recovery safe. Shared by `commit_block` and
    /// `recover_pending_commit`.
    fn apply_post_image(&self, record: &WalRecord) -> StorageResult<()> {
        for (tree_name, ops) in &record.trees {
            let tree = self.tree_by_name(tree_name).ok_or_else(|| {
                StorageError::CorruptedData(format!(
                    "WAL record references unknown tree '{}'",
                    tree_name
                ))
            })?;
            apply_tree_post_image(tree, ops)?;
        }

        // `latest_height` is the logical commit point. Written from the WAL's
        // authoritative height so a normal commit and a recovered commit agree.
        self.meta
            .insert(keys::meta::LATEST_HEIGHT, &record.height.to_be_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Durability point: the block's state is on disk once this returns Ok.
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    /// On open, complete any block commit interrupted before it could clear its
    /// WAL marker.
    ///
    /// Re-applies the recorded post-image (idempotent) and removes the marker.
    /// A no-op when no commit is pending. Recovery rolls *forward* from the
    /// recorded post-image — it never re-executes transactions, which would not
    /// be idempotent.
    fn recover_pending_commit(&self) -> StorageResult<()> {
        let staged = self
            .wal
            .get(WAL_PENDING_KEY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        let Some(bytes) = staged else {
            return Ok(());
        };

        let record: WalRecord = Self::deserialize_wal(&bytes)?;
        tracing::warn!(
            "SledStore: interrupted block commit detected at height {} (hash {}); \
             rolling forward from the write-ahead log",
            record.height,
            hex::encode(record.block_hash),
        );

        self.apply_post_image(&record)?;

        self.wal
            .remove(WAL_PENDING_KEY)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        tracing::info!(
            "SledStore: write-ahead recovery complete — block {} is fully committed",
            record.height,
        );
        Ok(())
    }

    /// Test-only: run a block commit but stop partway, leaving the WAL marker
    /// in place — simulating the process dying mid-commit.
    ///
    /// Stages the WAL record (as `commit_block` does), then applies only the
    /// first `stop_after_trees` per-tree batches and, optionally, the
    /// `latest_height` write. The WAL marker is intentionally NOT cleared, so a
    /// subsequent `open()` exercises `recover_pending_commit`. Returns the total
    /// number of per-tree batches in the staged record.
    #[cfg(test)]
    fn debug_interrupt_commit(
        &self,
        stop_after_trees: usize,
        write_latest_height: bool,
    ) -> StorageResult<usize> {
        self.require_transaction()?;
        let height = self.tx_height.load(Ordering::SeqCst);
        let batch = {
            let mut batch_guard = self.tx_batch.lock().unwrap();
            batch_guard
                .take()
                .ok_or(StorageError::NoActiveTransaction)?
        };
        let record = batch.to_wal_record(height);
        let total_trees = record.trees.len();

        // Step 1 of commit_block: durably stage the WAL record.
        self.wal
            .insert(WAL_PENDING_KEY, Self::serialize_wal(&record)?)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Step 2, interrupted: apply only a prefix of the per-tree batches.
        for (tree_name, ops) in record.trees.iter().take(stop_after_trees) {
            let tree = self.tree_by_name(tree_name).expect("known tree");
            apply_tree_post_image(tree, ops)?;
        }
        if write_latest_height {
            self.meta
                .insert(keys::meta::LATEST_HEIGHT, &height.to_be_bytes())
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // The WAL marker is deliberately left in place — recovery must heal it.
        self.tx_active.store(false, Ordering::SeqCst);
        Ok(total_trees)
    }

    /// TEST-ONLY: insert raw bytes into the `identity_metadata` tree without
    /// going through `Self::serialize`. Used by the schema-migration
    /// safety-property test (CR PR #2679) to plant an old-shaped / corrupt
    /// blob and verify the migration succeeds without ever decoding it.
    /// (`pub(crate)` + `#[cfg(test)]` so production paths cannot reach it.)
    #[cfg(test)]
    pub(crate) fn put_identity_metadata_raw_bytes(
        &self,
        did_hash: &[u8; 32],
        bytes: &[u8],
    ) -> StorageResult<()> {
        self.identity_metadata
            .insert(did_hash.as_ref(), bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.identity_metadata
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
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

        // Stage block index writes in the batch alongside all other state writes.
        // This ensures block index entries commit at the same point as utxos/accounts/etc.
        // rather than ahead of them via direct Tree::insert.
        let height_key = keys::block_height_key(height);
        let hash_key = *keys::block_hash_key(&block_hash);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            // TreeBatch::insert mirrors sled Batch::insert (Into<IVec> for K and V),
            // so fixed-size arrays are converted to slices.
            batch
                .tree(TREE_BLOCKS_BY_HEIGHT)
                .insert(height_key.as_ref(), block_hash.as_bytes().as_ref());
            batch.tree(TREE_BLOCKS_BY_HASH).insert(hash_key.as_ref(), block_bytes);
            for tx in &block.transactions {
                for input in &tx.inputs {
                    batch
                        .tree(TREE_NULLIFIERS)
                        .insert(input.nullifier.as_bytes(), &[1u8][..]);
                }
            }
            let nullifier_index_was_current = if height == 0 {
                true
            } else {
                let previous_hash = BlockHash::new(block.header.previous_hash);
                self.nullifier_index_is_current_internal(height - 1, &previous_hash)?
            };
            if nullifier_index_was_current {
                let checkpoint = Self::nullifier_checkpoint_value(height, &block_hash);
                batch
                    .tree(TREE_META)
                    .insert(keys::meta::NULLIFIER_INDEX_CHECKPOINT, checkpoint.as_ref());
            }
            // Record the block hash for the write-ahead commit record.
            batch.block_hash = Some(hash_bytes);
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
            batch.tree(TREE_UTXOS).insert(key.as_ref(), value);
        }

        Ok(())
    }

    fn delete_utxo(&self, op: &OutPoint) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::utxo_key(op);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_UTXOS).remove(key.as_ref());
        }

        Ok(())
    }

    fn iter_utxos(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(OutPoint, Utxo)>> + '_>> {
        // Wrap the sled iterator directly so rows yield one at a time —
        // hydrate paths can stream into projection tables without ever
        // holding the whole UTXO set in memory. Per-row decode errors
        // bubble up as `StorageResult` items.
        let iter = self.utxos.iter().map(|result| {
            let (key, value) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            let outpoint = keys::parse_utxo_key(key.as_ref()).ok_or_else(|| {
                StorageError::CorruptedData(format!(
                    "Invalid UTXO key length: {}",
                    key.len()
                ))
            })?;
            let utxo: Utxo = Self::deserialize(&value)?;
            Ok((outpoint, utxo))
        });
        Ok(Box::new(iter))
    }

    fn is_nullifier_used(&self, nullifier: &Hash) -> StorageResult<bool> {
        let key = nullifier.as_bytes();
        {
            let batch_guard = self.tx_batch.lock().unwrap();
            if let Some(batch) = batch_guard.as_ref() {
                if let Some(staged) = batch.tree_lookup(TREE_NULLIFIERS, key) {
                    return Ok(staged.is_some());
                }
            }
        }

        self.nullifiers
            .contains_key(key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn put_nullifier(&self, nullifier: &Hash) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch
                .tree(TREE_NULLIFIERS)
                .insert(nullifier.as_bytes(), &[1u8][..]);
        }

        Ok(())
    }

    fn iter_nullifiers(&self) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Hash>> + '_>> {
        let iter = self.nullifiers.iter().map(|result| {
            let (key, _) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.len() != 32 {
                return Err(StorageError::CorruptedData(format!(
                    "Invalid nullifier key length: {}",
                    key.len()
                )));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(key.as_ref());
            Ok(Hash::new(bytes))
        });
        Ok(Box::new(iter))
    }

    fn backfill_nullifiers(&self, nullifiers: &[Hash]) -> StorageResult<()> {
        // Must only be called during startup migrations, before block processing begins.
        if self.tx_active.load(Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }
        if nullifiers.is_empty() {
            return Ok(());
        }

        let mut batch = Batch::default();
        for nullifier in nullifiers {
            batch.insert(nullifier.as_bytes(), &[1u8][..]);
        }
        self.nullifiers
            .apply_batch(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.nullifiers
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn nullifier_index_is_current(
        &self,
        height: BlockHeight,
        block_hash: &BlockHash,
    ) -> StorageResult<bool> {
        self.nullifier_index_is_current_internal(height, block_hash)
    }

    fn mark_nullifier_index_current(
        &self,
        height: BlockHeight,
        block_hash: &BlockHash,
    ) -> StorageResult<()> {
        if self.tx_active.load(Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }

        let checkpoint = Self::nullifier_checkpoint_value(height, block_hash);
        self.meta
            .insert(keys::meta::NULLIFIER_INDEX_CHECKPOINT, checkpoint.as_ref())
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.meta
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    // =========================================================================
    // UTXO Merkle Tree Operations
    // =========================================================================

    fn put_utxo_merkle_leaf(&self, op: &OutPoint, leaf: [u8; 32]) -> StorageResult<u64> {
        self.require_transaction()?;

        let op_key = keys::utxo_key(op);
        let mut batch_guard = self.tx_batch.lock().unwrap();
        let batch = batch_guard.as_mut().ok_or(StorageError::NoActiveTransaction)?;

        // Ensure outpoint is not already indexed in this block or committed state.
        if batch.utxo_merkle_indexed.contains_key(&op_key) {
            return Err(StorageError::CorruptedData(
                "UTXO already has a Merkle leaf in the current block".to_string(),
            ));
        }
        if self.utxo_merkle_index.get(op_key.as_ref()).map(|v| v.is_some()).unwrap_or(false) {
            return Err(StorageError::CorruptedData(
                "UTXO already has a committed Merkle leaf".to_string(),
            ));
        }

        let next_index = self.tx_utxo_merkle_next_index.fetch_add(1, Ordering::SeqCst);
        let index_bytes = next_index.to_be_bytes();

        batch.tree(TREE_UTXO_MERKLE_LEAVES).insert(index_bytes.as_ref(), &leaf[..]);
        batch.tree(TREE_UTXO_MERKLE_INDEX).insert(op_key.as_ref(), index_bytes.as_ref());
        batch.tree(TREE_UTXO_MERKLE_META).insert(
            keys::meta::UTXO_MERKLE_NEXT_INDEX,
            (next_index + 1).to_be_bytes().as_ref(),
        );
        batch.utxo_merkle_indexed.insert(op_key, next_index);
        drop(batch_guard);

        self.update_merkle_path(next_index, leaf)?;
        Ok(next_index)
    }

    fn delete_utxo_merkle_leaf(&self, op: &OutPoint) -> StorageResult<()> {
        self.require_transaction()?;

        let op_key = keys::utxo_key(op);
        let mut batch_guard = self.tx_batch.lock().unwrap();
        let batch = batch_guard.as_mut().ok_or(StorageError::NoActiveTransaction)?;

        // If the outpoint was inserted in the current block, use the cached index.
        let index_bytes = if let Some(&idx) = batch.utxo_merkle_indexed.get(&op_key) {
            batch.utxo_merkle_indexed.remove(&op_key);
            Some(idx.to_be_bytes().to_vec())
        } else {
            self.utxo_merkle_index
                .get(op_key.as_ref())
                .ok()
                .flatten()
                .map(|v| v.to_vec())
        };

        if let Some(bytes) = index_bytes {
            batch.tree(TREE_UTXO_MERKLE_LEAVES).insert(bytes.as_slice(), &[0u8; 32][..]);
            batch.tree(TREE_UTXO_MERKLE_INDEX).remove(op_key.as_ref());
            let idx = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            drop(batch_guard);
            self.update_merkle_path(idx, [0u8; 32])?;
        }

        Ok(())
    }

    fn get_utxo_merkle_root(&self) -> StorageResult<Option<[u8; 32]>> {
        let depth = lib_proofs::transaction::circuit::MERKLE_DEPTH as u32;
        let root_key = Self::merkle_node_key(depth, 0);

        // Check active batch cache first
        {
            let batch_guard = self.tx_batch.lock().unwrap();
            if let Some(batch) = batch_guard.as_ref() {
                if let Some(&hash) = batch.utxo_merkle_nodes_cache.get(&root_key) {
                    return Ok(Some(hash));
                }
            }
        }

        // Fall back to committed tree
        match self.utxo_merkle_nodes.get(root_key) {
            Ok(Some(bytes)) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn get_utxo_merkle_proof(&self, op: &OutPoint) -> StorageResult<Option<UtxoMerkleProof>> {
        let leaf_index = match self.get_utxo_merkle_leaf_index(op)? {
            Some(idx) => idx,
            None => return Ok(None),
        };

        #[cfg(feature = "real-proofs")]
        {
            let mut siblings = Vec::with_capacity(lib_proofs::transaction::circuit::MERKLE_DEPTH);
            let mut current_index = leaf_index;
            let zero_hashes = Self::merkle_zero_hashes();

            let batch_guard = self.tx_batch.lock().unwrap();
            let batch_ref = batch_guard.as_ref();

            for level in 0..lib_proofs::transaction::circuit::MERKLE_DEPTH as u32 {
                let sibling_index = current_index ^ 1;
                let sibling_key = Self::merkle_node_key(level, sibling_index);
                let sibling_hash = if let Some(hash) = batch_ref.and_then(|b| b.utxo_merkle_nodes_cache.get(&sibling_key)) {
                    *hash
                } else {
                    match self.utxo_merkle_nodes.get(sibling_key) {
                        Ok(Some(bytes)) if bytes.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            arr
                        }
                        Ok(_) => zero_hashes[level as usize],
                        Err(e) => return Err(StorageError::Database(e.to_string())),
                    }
                };
                siblings.push(sibling_hash);
                current_index /= 2;
            }

            let depth = lib_proofs::transaction::circuit::MERKLE_DEPTH as u32;
            let root_key = Self::merkle_node_key(depth, 0);
            let root = if let Some(hash) = batch_ref.and_then(|b| b.utxo_merkle_nodes_cache.get(&root_key)) {
                *hash
            } else {
                match self.utxo_merkle_nodes.get(root_key) {
                    Ok(Some(bytes)) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    Ok(_) => zero_hashes[lib_proofs::transaction::circuit::MERKLE_DEPTH],
                    Err(e) => return Err(StorageError::Database(e.to_string())),
                }
            };

            Ok(Some(UtxoMerkleProof {
                leaf_index,
                siblings,
                root,
            }))
        }

        #[cfg(not(feature = "real-proofs"))]
        {
            Ok(None)
        }
    }

    fn get_utxo_merkle_leaf_index(&self, op: &OutPoint) -> StorageResult<Option<u64>> {
        let op_key = keys::utxo_key(op);
        let bytes = match self.utxo_merkle_index.get(op_key.as_ref()) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(StorageError::Database(e.to_string())),
        };
        if bytes.len() >= 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            Ok(Some(u64::from_be_bytes(arr)))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // Token Contract Operations
    // =========================================================================

    fn get_token_contract(&self, id: &TokenId) -> StorageResult<Option<TokenContract>> {
        let key = keys::token_contract_key(id);

        // Write-through read (CR #2658): staged puts are visible within the open block
        // batch so genesis bootstrap and multi-step applies observe their own writes.
        {
            let batch_guard = self.tx_batch.lock().unwrap();
            if let Some(ref batch) = *batch_guard {
                if let Some(staged) = batch.tree_lookup(TREE_TOKEN_CONTRACTS, key.as_ref()) {
                    return match staged {
                        Some(bytes) => {
                            let contract: TokenContract = Self::deserialize(&bytes)?;
                            Ok(Some(contract))
                        }
                        None => Ok(None),
                    };
                }
            }
        }

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
            batch.tree(TREE_TOKEN_CONTRACTS).insert(key.as_ref(), value);
        }

        Ok(())
    }

    fn get_token_supply(&self, token: &TokenId) -> StorageResult<Option<u128>> {
        let key = keys::token_supply_key(token);
        match self.token_supply.get(key) {
            Ok(Some(bytes)) => {
                // Support both legacy 8-byte (u64) and new 16-byte (u128) encodings
                let supply = if bytes.len() == 8 {
                    let val = u64::from_le_bytes(bytes.as_ref().try_into().map_err(|_| {
                        StorageError::Serialization("Failed to deserialize supply (u64)".into())
                    })?);
                    val as u128
                } else {
                    u128::from_le_bytes(bytes.as_ref().try_into().map_err(|_| {
                        StorageError::Serialization("Failed to deserialize supply (u128)".into())
                    })?)
                };
                Ok(Some(supply))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_token_supply(&self, token: &TokenId, supply: u128) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::token_supply_key(token);
        let value = supply.to_le_bytes();

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_TOKEN_SUPPLY).insert(key.as_ref(), value.as_ref());
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
            batch.tree(TREE_CONTRACT_CODE).insert(contract_id, code);
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
                .tree(TREE_CONTRACT_STORAGE)
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
            batch.tree(TREE_CONTRACT_STORAGE).remove(IVec::from(composite_key));
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
            batch.tree(TREE_META).insert(keys::meta::TOKEN_STATE_SNAPSHOT, value);
        }

        Ok(())
    }

    fn get_oracle_state(&self) -> StorageResult<Option<crate::oracle::OracleState>> {
        match self.meta.get(keys::meta::ORACLE_STATE) {
            Ok(Some(bytes)) => {
                let state: crate::oracle::OracleState = Self::deserialize(&bytes)?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn save_oracle_state(&self, state: &crate::oracle::OracleState) -> StorageResult<()> {
        // Direct write to meta tree — no active block transaction required.
        // Oracle bootstrap happens outside of block processing.
        let value = Self::serialize(state)?;
        self.meta
            .insert(keys::meta::ORACLE_STATE, value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn put_pending_transaction(&self, tx: &Transaction) -> StorageResult<()> {
        let key = tx.hash();
        let value = Self::serialize(tx)?;
        self.pending_transactions
            .insert(key.as_bytes(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn delete_pending_transaction(&self, tx_hash: &[u8; 32]) -> StorageResult<()> {
        self.pending_transactions
            .remove(tx_hash)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn iter_pending_transactions(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = Transaction> + '_>> {
        let mut results = Vec::new();
        for result in self.pending_transactions.iter() {
            match result {
                Ok((_key, value)) => {
                    let tx: Transaction = Self::deserialize(&value)?;
                    results.push(tx);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }

        Ok(Box::new(results.into_iter()))
    }

    fn get_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
    ) -> StorageResult<Option<WalletProjectionRecord>> {
        SledStore::get_wallet_projection(self, wallet_id)
    }

    fn put_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
        record: &WalletProjectionRecord,
    ) -> StorageResult<()> {
        SledStore::put_wallet_projection(self, wallet_id, record)
    }

    fn delete_wallet_projection(&self, wallet_id: &[u8; 32]) -> StorageResult<()> {
        SledStore::delete_wallet_projection(self, wallet_id)
    }

    fn count_wallet_projections(&self) -> StorageResult<usize> {
        SledStore::count_wallet_projections(self)
    }

    fn iter_wallet_projections(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = ([u8; 32], WalletProjectionRecord)> + '_>> {
        let entries = SledStore::iter_wallet_projections(self)?;
        Ok(Box::new(entries.into_iter()))
    }

    fn replace_wallet_projections(
        &self,
        records: &[([u8; 32], WalletProjectionRecord)],
    ) -> StorageResult<()> {
        SledStore::replace_wallet_projections(self, records)
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
            batch.tree(TREE_ACCOUNTS).insert(key.as_ref(), value);
        }

        Ok(())
    }

    // =========================================================================
    // Token Balance Operations
    // =========================================================================

    fn get_token_balance(&self, t: &TokenId, a: &Address) -> StorageResult<Amount> {
        let key = keys::token_balance_key(t, a);

        // Write-through read: if a `set_token_balance` for this key is staged
        // in the open block's batch, it has not yet flushed to
        // `self.token_balances` but IS the value any subsequent reader within
        // the same block should observe. Without this lookup, a balance
        // updated earlier in `apply_transaction` would still appear as the
        // pre-block value to `process_*_transactions` later in the same block
        // — silently authorising a double-spend (CR #2658 issue #2).
        {
            let batch_guard = self.tx_batch.lock().unwrap();
            if let Some(ref batch) = *batch_guard {
                if let Some(staged) = batch.tree_lookup(TREE_TOKEN_BALANCES, key.as_ref()) {
                    return match staged {
                        Some(bytes) => {
                            if bytes.len() != 16 {
                                return Err(StorageError::CorruptedData(
                                    "Invalid balance length in staged batch".to_string(),
                                ));
                            }
                            Ok(u128::from_be_bytes(bytes.as_ref().try_into().unwrap()))
                        }
                        // Staged remove → balance was cleared this block.
                        None => Ok(0),
                    };
                }
            }
        }

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

    fn count_token_holders(&self, token_id: &TokenId) -> StorageResult<usize> {
        let prefix = keys::token_balances_prefix(token_id);
        let mut count = 0usize;
        for result in self.token_balances.scan_prefix(&prefix) {
            let (_, value) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            if value.len() == 16 {
                let balance = u128::from_be_bytes(value.as_ref().try_into().unwrap());
                if balance > 0 {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    fn set_token_balance(&self, t: &TokenId, a: &Address, v: Amount) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::token_balance_key(t, a);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            if v == 0 {
                // Optionally delete zero balances to save space
                batch.tree(TREE_TOKEN_BALANCES).remove(key.as_ref());
            } else {
                batch.tree(TREE_TOKEN_BALANCES).insert(key.as_ref(), &v.to_be_bytes());
            }
        }

        Ok(())
    }

    fn backfill_token_balances_from_contract(
        &self,
        token_id: &TokenId,
        entries: &[([u8; 32], u128)],
    ) -> StorageResult<usize> {
        // Must only be called during startup, before block processing begins.
        if self.tx_active.load(Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }
        let mut batch = sled::Batch::default();
        let mut written = 0usize;
        for (addr_bytes, balance) in entries {
            if *balance == 0 {
                continue;
            }
            let addr = Address::new(*addr_bytes);
            let key = keys::token_balance_key(token_id, &addr);
            // Only backfill entries missing from the tree (idempotent)
            match self.token_balances.get(&key) {
                Ok(Some(_)) => {} // Already populated, skip
                Ok(None) => {
                    batch.insert(key.as_ref(), &balance.to_be_bytes());
                    written += 1;
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        if written > 0 {
            self.token_balances
                .apply_batch(batch)
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }
        Ok(written)
    }

    fn force_set_token_balances(
        &self,
        entries: &[(TokenId, Address, u128)],
    ) -> StorageResult<usize> {
        // Must only be called during startup migrations, before block processing begins.
        if self.tx_active.load(Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }
        let mut batch = sled::Batch::default();
        for (token_id, addr, balance) in entries {
            let key = keys::token_balance_key(token_id, addr);
            if *balance == 0 {
                batch.remove(key.as_ref());
            } else {
                batch.insert(key.as_ref(), &balance.to_be_bytes());
            }
        }
        self.token_balances
            .apply_batch(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(entries.len())
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
                batch.tree(TREE_TOKEN_NONCES).remove(key.as_ref());
            } else {
                batch
                    .tree(TREE_TOKEN_NONCES)
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

    fn iter_identities(&self) -> StorageResult<Box<dyn Iterator<Item = IdentityConsensus> + '_>> {
        // Materialize under one pass so a deserialize error surfaces here rather
        // than mid-iteration in the caller. Mirrors iter_token_contracts.
        let mut results = Vec::new();
        for entry in self.identities.iter() {
            match entry {
                Ok((key, value)) => {
                    let identity: IdentityConsensus = Self::deserialize(&value)?;
                    // The tree key IS the did_hash (see put_identity). Validate the
                    // deserialized record's embedded did_hash matches its key so a
                    // corrupted/mismatched value cannot feed callers (and the
                    // divergence detector) a wrong did_hash silently.
                    let key_hash: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                        StorageError::CorruptedData(format!(
                            "identities tree key is not 32 bytes (len={})",
                            key.len()
                        ))
                    })?;
                    if key_hash != identity.did_hash {
                        return Err(StorageError::CorruptedData(format!(
                            "identity did_hash {} does not match tree key {}",
                            hex::encode(identity.did_hash),
                            hex::encode(key_hash)
                        )));
                    }
                    results.push(identity);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(Box::new(results.into_iter()))
    }

    fn iter_identity_metadata(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = IdentityMetadata> + '_>> {
        // Materialize in one pass so a deserialize error surfaces here. Mirrors
        // iter_identities; the tree is keyed by did_hash = did_to_hash(did).
        let mut results = Vec::new();
        for entry in self.identity_metadata.iter() {
            match entry {
                Ok((key, value)) => {
                    let metadata: IdentityMetadata = Self::deserialize(&value)?;
                    // Validate the record's DID hashes back to its tree key, so a
                    // corrupted/mismatched value cannot feed callers a wrong DID.
                    if crate::storage::did_to_hash(&metadata.did).as_ref() != key.as_ref() {
                        return Err(StorageError::CorruptedData(format!(
                            "identity_metadata did {} does not hash to its tree key {}",
                            metadata.did,
                            hex::encode(key.as_ref())
                        )));
                    }
                    results.push(metadata);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(Box::new(results.into_iter()))
    }

    fn count_identities(&self) -> StorageResult<usize> {
        // sled::Tree::len is an O(n) walk but avoids deserializing every record,
        // so it is the cheapest authoritative count available.
        Ok(self.identities.len())
    }

    fn iter_identities_with_metadata(
        &self,
    ) -> StorageResult<
        Box<
            dyn Iterator<
                    Item = StorageResult<(
                        [u8; 32],
                        IdentityConsensus,
                        Option<IdentityMetadata>,
                    )>,
                > + '_,
        >,
    > {
        // Streams rows lazily so the hydrate path can process the
        // identity set (~thousands+ at mainnet scale) without
        // materialising it. The metadata lookup is intentionally
        // per-row: identity_metadata is a separate sled tree and there
        // is no efficient co-iteration primitive — the cost is one
        // point-lookup per identity. If this ever shows up in profiling
        // we can switch to scanning both trees in lock-step using
        // sled's sorted-key ordering.
        let metadata_tree = self.identity_metadata.clone();
        let iter = self.identities.iter().map(move |result| {
            let (key, value) = result.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.len() != 32 {
                return Err(StorageError::CorruptedData(format!(
                    "Invalid identity key length: {}",
                    key.len()
                )));
            }
            let mut did_hash = [0u8; 32];
            did_hash.copy_from_slice(&key);
            let consensus: IdentityConsensus = Self::deserialize(&value)?;
            let metadata = match metadata_tree.get(did_hash) {
                Ok(Some(bytes)) => Some(Self::deserialize(&bytes)?),
                Ok(None) => None,
                Err(e) => return Err(StorageError::Database(e.to_string())),
            };
            Ok((did_hash, consensus, metadata))
        });
        Ok(Box::new(iter))
    }

    fn put_identity(&self, did_hash: &[u8; 32], identity: &IdentityConsensus) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(identity)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_IDENTITIES).insert(did_hash.as_ref(), value);
        }

        Ok(())
    }

    fn delete_identity(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_IDENTITIES).remove(did_hash.as_ref());
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
                .tree(TREE_IDENTITY_BY_OWNER)
                .insert(key.as_ref(), did_hash.as_ref());
        }

        Ok(())
    }

    fn delete_identity_owner_index(&self, addr: &Address) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::identity_by_owner_key(addr);

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_IDENTITY_BY_OWNER).remove(key.as_ref());
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
            batch.tree(TREE_IDENTITY_METADATA).insert(did_hash.as_ref(), value);
        }

        Ok(())
    }

    fn delete_identity_metadata(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_IDENTITY_METADATA).remove(did_hash.as_ref());
        }

        Ok(())
    }

    fn put_identity_direct(
        &self,
        did_hash: &[u8; 32],
        identity: &IdentityConsensus,
    ) -> StorageResult<()> {
        let value = Self::serialize(identity)?;
        self.identities
            .insert(did_hash.as_ref(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.identities
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn put_identity_metadata_direct(
        &self,
        did_hash: &[u8; 32],
        metadata: &IdentityMetadata,
    ) -> StorageResult<()> {
        let value = Self::serialize(metadata)?;
        self.identity_metadata
            .insert(did_hash.as_ref(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.identity_metadata
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// Bulk insert + single flush (CR PR #2679 — used by the schema-v2
    /// regenerate-from-blocks migration to amortise the fsync cost; the
    /// per-record `put_identity_metadata_direct` flushed every call,
    /// making upgrades O(n) in fsync count).
    fn put_identity_metadata_batch(
        &self,
        records: &[([u8; 32], IdentityMetadata)],
    ) -> StorageResult<usize> {
        let mut written = 0usize;
        for (did_hash, metadata) in records {
            let value = Self::serialize(metadata)?;
            self.identity_metadata
                .insert(did_hash.as_ref(), value)
                .map_err(|e| StorageError::Database(e.to_string()))?;
            written += 1;
        }
        self.identity_metadata
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(written)
    }

    fn identity_metadata_schema_version(&self) -> StorageResult<u32> {
        // Absent key => version 1 (pre-kyber records written before #58).
        match self.meta.get(keys::meta::IDENTITY_METADATA_SCHEMA_VERSION) {
            Ok(Some(bytes)) => {
                let arr: [u8; 4] = bytes.as_ref().try_into().map_err(|_| {
                    StorageError::Database(
                        "identity_metadata_schema_version: malformed u32".to_string(),
                    )
                })?;
                Ok(u32::from_be_bytes(arr))
            }
            Ok(None) => Ok(1),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn set_identity_metadata_schema_version(&self, version: u32) -> StorageResult<()> {
        self.meta
            .insert(
                keys::meta::IDENTITY_METADATA_SCHEMA_VERSION,
                &version.to_be_bytes(),
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.meta
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn clear_identity_metadata(&self) -> StorageResult<()> {
        self.identity_metadata
            .clear()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.identity_metadata
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    // ---- Durable validator records (#56), keyed by did_to_hash(identity_id) ----

    fn get_validator_record(
        &self,
        did_hash: &[u8; 32],
    ) -> StorageResult<Option<crate::storage::StoredValidatorRecord>> {
        match self.validators.get(did_hash) {
            Ok(Some(bytes)) => Ok(Some(Self::deserialize(&bytes)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn iter_validator_records(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = crate::storage::StoredValidatorRecord> + '_>> {
        // Materialize in one pass so a deserialize error surfaces here (mirrors
        // iter_identity_metadata). Each record's identity_id must hash back to its
        // tree key, so a corrupted/mismatched value cannot feed a wrong validator.
        let mut results = Vec::new();
        for entry in self.validators.iter() {
            match entry {
                Ok((key, value)) => {
                    let record: crate::storage::StoredValidatorRecord =
                        Self::deserialize(&value)?;
                    if crate::storage::did_to_hash(&record.consensus.identity_id).as_ref()
                        != key.as_ref()
                    {
                        return Err(StorageError::CorruptedData(format!(
                            "validator record id {} does not hash to its tree key {}",
                            record.consensus.identity_id,
                            hex::encode(key.as_ref())
                        )));
                    }
                    results.push(record);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(Box::new(results.into_iter()))
    }

    fn put_validator_record(
        &self,
        did_hash: &[u8; 32],
        record: &crate::storage::StoredValidatorRecord,
    ) -> StorageResult<()> {
        self.require_transaction()?;
        let value = Self::serialize(record)?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_VALIDATORS).insert(did_hash.as_ref(), value);
        }
        Ok(())
    }

    fn delete_validator_record(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        self.require_transaction()?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_VALIDATORS).remove(did_hash.as_ref());
        }
        Ok(())
    }

    fn count_validator_records(&self) -> StorageResult<usize> {
        Ok(self.validators.len())
    }

    fn put_validator_record_direct(
        &self,
        did_hash: &[u8; 32],
        record: &crate::storage::StoredValidatorRecord,
    ) -> StorageResult<()> {
        let value = Self::serialize(record)?;
        self.validators
            .insert(did_hash.as_ref(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.validators
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    /// Bulk insert + single flush (#56 — used by the regenerate-from-blocks
    /// migration to amortise fsync cost, mirroring put_identity_metadata_batch).
    fn put_validator_record_batch(
        &self,
        records: &[([u8; 32], crate::storage::StoredValidatorRecord)],
    ) -> StorageResult<usize> {
        let mut written = 0usize;
        for (did_hash, record) in records {
            let value = Self::serialize(record)?;
            self.validators
                .insert(did_hash.as_ref(), value)
                .map_err(|e| StorageError::Database(e.to_string()))?;
            written += 1;
        }
        self.validators
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(written)
    }

    fn validator_record_schema_version(&self) -> StorageResult<u32> {
        // Absent key => version 0 (no durable validators yet → migrate to v1).
        match self.meta.get(keys::meta::VALIDATOR_RECORD_SCHEMA_VERSION) {
            Ok(Some(bytes)) => {
                let arr: [u8; 4] = bytes.as_ref().try_into().map_err(|_| {
                    StorageError::Database(
                        "validator_record_schema_version: malformed u32".to_string(),
                    )
                })?;
                Ok(u32::from_be_bytes(arr))
            }
            Ok(None) => Ok(0),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn set_validator_record_schema_version(&self, version: u32) -> StorageResult<()> {
        self.meta
            .insert(
                keys::meta::VALIDATOR_RECORD_SCHEMA_VERSION,
                &version.to_be_bytes(),
            )
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.meta
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn clear_validator_records(&self) -> StorageResult<()> {
        self.validators
            .clear()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.validators
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
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
        let next_index = match self.utxo_merkle_meta.get(keys::meta::UTXO_MERKLE_NEXT_INDEX) {
            Ok(Some(bytes)) if bytes.len() >= 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                u64::from_be_bytes(arr)
            }
            _ => 0,
        };
        self.tx_utxo_merkle_next_index.store(next_index, Ordering::SeqCst);
        let mut batch_guard = self.tx_batch.lock().unwrap();
        *batch_guard = Some(PendingBatch::new());

        Ok(())
    }

    fn commit_block(&self) -> StorageResult<()> {
        self.require_transaction()?;

        let height = self.tx_height.load(Ordering::SeqCst);

        // Drop guard: always clear tx_active when this function returns, whether
        // Ok or Err. Without this, any apply_batch failure permanently deadlocks
        // the node — begin_block would return TransactionAlreadyActive forever.
        struct TxGuard<'a>(&'a AtomicBool);
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = TxGuard(&self.tx_active);

        // Take the batch.
        let batch = {
            let mut batch_guard = self.tx_batch.lock().unwrap();
            batch_guard
                .take()
                .ok_or(StorageError::NoActiveTransaction)?
        };

        // sled commits each tree's batch atomically but gives NO atomicity
        // across trees, so applying the ~24 per-tree batches directly can leave
        // a block half-committed after a crash. A write-ahead log closes that
        // gap:
        //
        //   1. Stage the full post-image (every tree's key writes plus the
        //      height/hash) into the `wal` tree as a single atomic record, and
        //      flush — the commit is now durably recoverable.
        //   2. Apply the per-tree batches and `latest_height`.
        //   3. Clear the WAL marker.
        //
        // A crash between (1) and (3) is healed on the next open by
        // `recover_pending_commit`, which idempotently re-applies the
        // post-image. A crash before (1) finishes leaves nothing applied. Block
        // state is therefore never left partially committed.
        let record = batch.to_wal_record(height);

        let record_bytes = Self::serialize_wal(&record)?;
        self.wal
            .insert(WAL_PENDING_KEY, record_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // The WAL record is durable: apply the post-image. If this is
        // interrupted, the next open rolls it forward from that record.
        self.apply_post_image(&record)?;

        // Commit complete — drop the WAL marker. Deliberately not flushed: a
        // stale marker surviving a crash here only triggers an idempotent
        // re-apply on the next open, which is harmless.
        self.wal
            .remove(WAL_PENDING_KEY)
            .map_err(|e| StorageError::Database(e.to_string()))?;

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

    fn begin_metadata_write(&self) -> StorageResult<()> {
        if self.tx_active.swap(true, Ordering::SeqCst) {
            return Err(StorageError::TransactionAlreadyActive);
        }
        // tx_height is intentionally not set — commit_metadata_write will not update latest_height.
        let mut batch_guard = self.tx_batch.lock().unwrap();
        *batch_guard = Some(PendingBatch::new());
        Ok(())
    }

    fn commit_metadata_write(&self) -> StorageResult<()> {
        self.require_transaction()?;

        // Same drop guard as commit_block — always clear tx_active on exit.
        struct TxGuard<'a>(&'a AtomicBool);
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _guard = TxGuard(&self.tx_active);

        let batch = {
            let mut batch_guard = self.tx_batch.lock().unwrap();
            batch_guard
                .take()
                .ok_or(StorageError::NoActiveTransaction)?
        };

        // Apply whatever index trees were staged (identities/metadata/owner/
        // accounts) — no block data, no latest_height update. This path is not
        // WAL-protected: it writes rebuildable identity indexes, not
        // block-commit consensus state.
        for (name, tree_batch) in &batch.trees {
            let tree = self.tree_by_name(name).ok_or_else(|| {
                StorageError::CorruptedData(format!(
                    "metadata write staged unknown tree '{}'",
                    name
                ))
            })?;
            apply_tree_post_image(tree, &tree_batch.to_post_image())?;
        }

        // Flush to ensure identity writes are durable before the next block commit.
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    // =========================================================================
    // Generic Table Access (BST-101)
    // =========================================================================

    fn get_raw(&self, tree: &'static str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let t = self.tree_by_name(tree).ok_or_else(|| {
            StorageError::Database(format!("unknown table keyspace '{}'", tree))
        })?;
        match t.get(key) {
            Ok(Some(v)) => Ok(Some(v.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn stage_raw(
        &self,
        tree: &'static str,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> StorageResult<()> {
        self.require_transaction()?;
        if self.tree_by_name(tree).is_none() {
            return Err(StorageError::Database(format!(
                "unknown table keyspace '{}'",
                tree
            )));
        }
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            match value {
                Some(v) => batch.tree(tree).insert(key, v),
                None => batch.tree(tree).remove(key),
            }
        }
        Ok(())
    }

    fn iter_raw(
        &self,
        tree: &'static str,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>> {
        let t = self.tree_by_name(tree).ok_or_else(|| {
            StorageError::Database(format!("unknown table keyspace '{}'", tree))
        })?;
        Ok(Box::new(t.iter().map(|r| {
            r.map(|(k, v)| (k.to_vec(), v.to_vec()))
                .map_err(|e| StorageError::Database(e.to_string()))
        })))
    }

    // =========================================================================
    // Fork audit log (BST-203) — direct durable writes
    // =========================================================================

    fn put_fork_point(
        &self,
        height: u64,
        fork_point: &crate::fork_recovery::ForkPoint,
    ) -> StorageResult<()> {
        let value = Self::serialize(fork_point)?;
        self.fork_points
            .insert(height.to_be_bytes(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        // Audit record — flush so a crash right after a reorg keeps it.
        self.db
            .flush()
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn iter_fork_points(&self) -> StorageResult<Vec<crate::fork_recovery::ForkPoint>> {
        // sled iterates keys in order; keys are big-endian heights, so the
        // result is already ascending by height.
        let mut out = Vec::new();
        for item in self.fork_points.iter() {
            let (_, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            out.push(Self::deserialize(&value)?);
        }
        Ok(out)
    }

    fn put_receipt(&self, receipt: &crate::receipts::TransactionReceipt) -> StorageResult<()> {
        let value = Self::serialize(receipt)?;
        self.receipts
            .insert(receipt.tx_hash.as_array(), value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn get_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> StorageResult<Option<crate::receipts::TransactionReceipt>> {
        match self.receipts.get(tx_hash) {
            Ok(Some(value)) => Ok(Some(Self::deserialize(&value)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    // =========================================================================
    // Bonding Curve Operations
    // =========================================================================

    fn get_bonding_curve_token(
        &self,
        token_id: &TokenId,
    ) -> StorageResult<Option<crate::contracts::bonding_curve::BondingCurveToken>> {
        match self.bonding_curves.get(token_id.as_ref()) {
            Ok(Some(bytes)) => {
                let token: crate::contracts::bonding_curve::BondingCurveToken =
                    Self::deserialize(&bytes)?;
                Ok(Some(token))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_bonding_curve_token(
        &self,
        token_id: &TokenId,
        token: &crate::contracts::bonding_curve::BondingCurveToken,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let key = token_id.as_ref();
        let value = Self::serialize(token)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_BONDING_CURVES).insert(key, value);
        }

        Ok(())
    }

    fn delete_bonding_curve_token(&self, token_id: &TokenId) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_BONDING_CURVES).remove(token_id.as_ref());
        }

        Ok(())
    }

    fn iter_bonding_curve_tokens(
        &self,
    ) -> StorageResult<
        Box<
            dyn Iterator<Item = (TokenId, crate::contracts::bonding_curve::BondingCurveToken)> + '_,
        >,
    > {
        let iter = self.bonding_curves.iter().filter_map(|item| {
            let (k, v) = item.ok()?;
            let token_id_bytes: [u8; 32] = match k.as_ref().try_into() {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(
                        "iter_bonding_curve_tokens: corrupt key (len={}), skipping entry",
                        k.len()
                    );
                    return None;
                }
            };
            match Self::deserialize(&v) {
                Ok(token) => Some((TokenId(token_id_bytes), token)),
                Err(e) => {
                    tracing::warn!(
                        "iter_bonding_curve_tokens: failed to deserialize token {:?}: {}",
                        token_id_bytes,
                        e
                    );
                    None
                }
            }
        });

        Ok(Box::new(iter))
    }

    fn get_bonding_curve_by_symbol(&self, symbol: &str) -> StorageResult<Option<TokenId>> {
        match self.bonding_curve_symbols.get(symbol.as_bytes()) {
            Ok(Some(bytes)) => {
                if bytes.len() == 32 {
                    let mut token_id = [0u8; 32];
                    token_id.copy_from_slice(&bytes);
                    Ok(Some(TokenId(token_id)))
                } else {
                    Err(StorageError::CorruptedData(
                        "Invalid token_id length in symbol index".to_string(),
                    ))
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_bonding_curve_symbol_index(
        &self,
        symbol: &str,
        token_id: &TokenId,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch
                .tree(TREE_BONDING_CURVE_SYMBOLS)
                .insert(symbol.as_bytes(), token_id.as_ref());
        }

        Ok(())
    }

    fn delete_bonding_curve_symbol_index(&self, symbol: &str) -> StorageResult<()> {
        self.require_transaction()?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_BONDING_CURVE_SYMBOLS).remove(symbol.as_bytes());
        }

        Ok(())
    }

    // =========================================================================
    // Canonical CBE Curve State (#1926)
    // =========================================================================

    fn get_cbe_economic_state(&self) -> StorageResult<lib_types::BondingCurveEconomicState> {
        match self.meta.get(keys::meta::CBE_ECONOMIC_STATE) {
            Ok(Some(bytes)) => {
                let state: lib_types::BondingCurveEconomicState = Self::deserialize(&bytes)?;
                Ok(state)
            }
            Ok(None) => Ok(lib_types::BondingCurveEconomicState::default()),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_cbe_economic_state(
        &self,
        state: &lib_types::BondingCurveEconomicState,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let value = Self::serialize(state)?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_META).insert(keys::meta::CBE_ECONOMIC_STATE, value);
        }

        Ok(())
    }

    fn get_cbe_account_state(
        &self,
        key_id: &[u8; 32],
    ) -> StorageResult<Option<lib_types::BondingCurveAccountState>> {
        let key = keys::cbe_account_key(key_id);
        match self.cbe_accounts.get(key) {
            Ok(Some(bytes)) => {
                let state: lib_types::BondingCurveAccountState = Self::deserialize(&bytes)?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_cbe_account_state(
        &self,
        key_id: &[u8; 32],
        state: &lib_types::BondingCurveAccountState,
    ) -> StorageResult<()> {
        self.require_transaction()?;

        let key = keys::cbe_account_key(key_id);
        let value = Self::serialize(state)?;

        let mut batch_guard = self.tx_batch.lock().unwrap();
        if let Some(ref mut batch) = *batch_guard {
            batch.tree(TREE_CBE_ACCOUNTS).insert(key.as_ref(), value);
        }

        Ok(())
    }


    fn put_quorum_proof(
        &self,
        height: u64,
        proof: &lib_types::consensus::BftQuorumProof,
    ) -> StorageResult<()> {
        let key = height.to_be_bytes();
        let value = Self::serialize(proof)?;
        self.quorum_proofs
            .insert(key, value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    fn get_quorum_proof(
        &self,
        height: u64,
    ) -> StorageResult<Option<lib_types::consensus::BftQuorumProof>> {
        let key = height.to_be_bytes();
        match self.quorum_proofs.get(key) {
            Ok(Some(bytes)) => {
                let proof: lib_types::consensus::BftQuorumProof = Self::deserialize(&bytes)?;
                Ok(Some(proof))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    // =========================================================================
    // DAO Stake Operations
    // =========================================================================

    fn get_dao_stake(
        &self,
        sector_dao_key_id: &[u8; 32],
        staker: &[u8; 32],
    ) -> StorageResult<Option<super::DaoStakeRecord>> {
        let key = keys::dao_stake_key(sector_dao_key_id, staker);
        match self.dao_stakes.get(key) {
            Ok(Some(bytes)) => {
                let record: super::DaoStakeRecord = Self::deserialize(&bytes)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_dao_stake(&self, record: &super::DaoStakeRecord) -> StorageResult<()> {
        self.require_transaction()?;
        let key = keys::dao_stake_key(&record.sector_dao_key_id, &record.staker);
        let value = Self::serialize(record)?;
        let mut batch_guard = self.tx_batch.lock().unwrap();
        let batch = batch_guard.as_mut().ok_or(StorageError::NoActiveTransaction)?;
        batch.tree(TREE_DAO_STAKES).insert(key.as_ref(), value);
        Ok(())
    }

    fn delete_dao_stake(
        &self,
        sector_dao_key_id: &[u8; 32],
        staker: &[u8; 32],
    ) -> StorageResult<()> {
        self.require_transaction()?;
        let key = keys::dao_stake_key(sector_dao_key_id, staker);
        let mut batch_guard = self.tx_batch.lock().unwrap();
        let batch = batch_guard.as_mut().ok_or(StorageError::NoActiveTransaction)?;
        batch.tree(TREE_DAO_STAKES).remove(key.as_ref());
        Ok(())
    }

    fn iter_dao_stakes_for_dao(
        &self,
        sector_dao_key_id: &[u8; 32],
    ) -> StorageResult<Vec<super::DaoStakeRecord>> {
        let prefix = sector_dao_key_id.as_slice();
        let mut records = Vec::new();
        for result in self.dao_stakes.scan_prefix(prefix) {
            match result {
                Ok((_key, bytes)) => {
                    let record: super::DaoStakeRecord = Self::deserialize(&bytes)?;
                    records.push(record);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(records)
    }

    // =========================================================================
    // Observer Admission (observer-admission-3)
    // =========================================================================

    fn get_observer_record(
        &self,
        did_hash: &[u8; 32],
    ) -> StorageResult<Option<lib_types::ObserverAdmissionRecord>> {
        match self.observer_registry.get(did_hash) {
            Ok(Some(bytes)) => {
                let record: lib_types::ObserverAdmissionRecord = Self::deserialize(&bytes)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn put_observer_record(
        &self,
        did_hash: &[u8; 32],
        record: &lib_types::ObserverAdmissionRecord,
    ) -> StorageResult<()> {
        let bytes = Self::serialize(record)?;
        let mut guard = self.tx_batch.lock().map_err(|e| {
            StorageError::Database(format!("lock poisoned in put_observer_record: {e}"))
        })?;
        if let Some(batch) = guard.as_mut() {
            batch.tree(TREE_OBSERVER_REGISTRY).insert(did_hash.as_slice(), bytes);
            Ok(())
        } else {
            Err(StorageError::Database(
                "put_observer_record called outside begin_block/commit_block".to_owned(),
            ))
        }
    }

    fn delete_observer_record(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        let mut guard = self.tx_batch.lock().map_err(|e| {
            StorageError::Database(format!("lock poisoned in delete_observer_record: {e}"))
        })?;
        if let Some(batch) = guard.as_mut() {
            batch.tree(TREE_OBSERVER_REGISTRY).remove(did_hash.as_slice());
            Ok(())
        } else {
            Err(StorageError::Database(
                "delete_observer_record called outside begin_block/commit_block".to_owned(),
            ))
        }
    }

    fn iter_observer_records(&self) -> StorageResult<Vec<lib_types::ObserverAdmissionRecord>> {
        let mut records = Vec::new();
        for result in self.observer_registry.iter() {
            match result {
                Ok((_key, bytes)) => {
                    let record: lib_types::ObserverAdmissionRecord = Self::deserialize(&bytes)?;
                    records.push(record);
                }
                Err(e) => return Err(StorageError::Database(e.to_string())),
            }
        }
        Ok(records)
    }

    fn get_observer_policy(
        &self,
    ) -> StorageResult<Option<lib_types::ObserverAdmissionPolicy>> {
        match self.meta.get(keys::meta::OBSERVER_POLICY) {
            Ok(Some(bytes)) => {
                let policy: lib_types::ObserverAdmissionPolicy = Self::deserialize(&bytes)?;
                Ok(Some(policy))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
    }

    fn save_observer_policy(
        &self,
        policy: &lib_types::ObserverAdmissionPolicy,
    ) -> StorageResult<()> {
        // Direct write to meta tree — like save_oracle_state, this is a
        // metadata write that does not require an active block transaction.
        let value = Self::serialize(policy)?;
        self.meta
            .insert(keys::meta::OBSERVER_POLICY, value)
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::super::{TxHash, WalletProjectionRecord, WalletState};
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::projections::{
        HotStateProjectionMeta, HotStateProjectionMetaTable, ValidatorProjectionRecord,
        ValidatorProjectionTable, HOT_STATE_PROJECTION_VERSION,
    };
    use crate::storage::table::TableAccess;
    use crate::transaction::{TransactionInput, TransactionPayload, WalletTransactionData};
    use crate::types::{Hash, TransactionType};

    fn create_test_block(height: u64, prev_hash: Hash) -> Block {
        create_test_block_with_transactions(height, prev_hash, vec![])
    }

    fn create_test_block_with_transactions(
        height: u64,
        prev_hash: Hash,
        transactions: Vec<Transaction>,
    ) -> Block {
        // Create a unique block hash based on height
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_hash: prev_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1000 + height,
            height,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
        };
        Block::new(header, transactions)
    }

    fn transaction_with_nullifier(nullifier: Hash) -> Transaction {
        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::Transfer,
            inputs: vec![TransactionInput {
                previous_output: Hash::new([0x11; 32]),
                output_index: 0,
                nullifier,
                zk_proof: crate::integration::zk_integration::ZkTransactionProof::default(),
            }],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: vec![],
                public_key: PublicKey::new([0u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: Vec::new(),
            payload: TransactionPayload::None,
        }
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
    fn test_hot_state_projection_tables_commit_atomically() {
        let store = SledStore::open_temporary().unwrap();
        let block0 = create_test_block(0, Hash::default());
        let validator = crate::blockchain::ValidatorInfo {
            identity_id: "did:sovn:test-validator".to_string(),
            stake: 100,
            storage_provided: 64,
            consensus_key: [7u8; 2592],
            networking_key: vec![1, 2, 3],
            rewards_key: vec![4, 5, 6],
            network_address: "127.0.0.1:7000".to_string(),
            commission_rate: 50,
            status: "active".to_string(),
            registered_at: 0,
            last_activity: 0,
            blocks_validated: 0,
            slash_count: 0,
            admission_source: crate::blockchain::ADMISSION_SOURCE_ONCHAIN_GOVERNANCE.to_string(),
            governance_proposal_id: None,
            oracle_key_id: None,
        };
        let meta = HotStateProjectionMeta {
            version: HOT_STATE_PROJECTION_VERSION,
            height: 0,
            block_hash: block0.hash().as_array(),
            completed_at_unix: 1,
            validators: 1,
            gateways: 0,
            domains: 0,
            credentials: 0,
            employment_contracts: 0,
            dao_entries: 0,
            pouw_mints: 0,
            contract_blocks: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store
            .stage::<ValidatorProjectionTable>(
                validator.identity_id.as_str(),
                &ValidatorProjectionRecord {
                    info: validator.clone(),
                    committed_at_height: 0,
                },
            )
            .unwrap();
        store
            .stage::<HotStateProjectionMetaTable>("hot_state", &meta)
            .unwrap();
        store.commit_block().unwrap();

        let loaded = store
            .get::<ValidatorProjectionTable>(validator.identity_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.info.identity_id, validator.identity_id);
        assert_eq!(loaded.committed_at_height, 0);

        let loaded_meta = store
            .get::<HotStateProjectionMetaTable>("hot_state")
            .unwrap()
            .unwrap();
        assert!(loaded_meta.is_current_for(0, block0.hash().as_array()));
    }

    #[test]
    fn test_wallet_projection_operations() {
        let store = SledStore::open_temporary().unwrap();
        let block0 = create_test_block(0, Hash::default());
        let wallet_id = [0xabu8; 32];
        let record = WalletProjectionRecord {
            wallet_data: WalletTransactionData {
                wallet_id: Hash::new(wallet_id),
                wallet_type: "Primary".to_string(),
                wallet_name: "Projection Wallet".to_string(),
                alias: Some("wallet-proj".to_string()),
                public_key: vec![0x11; 32],
                owner_identity_id: Some(Hash::new([0x22; 32])),
                seed_commitment: Hash::new([0x33; 32]),
                created_at: 1234,
                registration_fee: 10,
                capabilities: 7,
                initial_balance: 42,
            },
            committed_at_height: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store.put_wallet_projection(&wallet_id, &record).unwrap();
        store.commit_block().unwrap();

        let loaded = store.get_wallet_projection(&wallet_id).unwrap().unwrap();
        assert_eq!(loaded, record);

        let entries = store.iter_wallet_projections().unwrap();
        assert_eq!(entries, vec![(wallet_id, record.clone())]);

        let block1 = create_test_block(1, block0.header.block_hash);
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.delete_wallet_projection(&wallet_id).unwrap();
        store.commit_block().unwrap();

        assert!(store.get_wallet_projection(&wallet_id).unwrap().is_none());
        assert!(store.iter_wallet_projections().unwrap().is_empty());

        store
            .replace_wallet_projections(&[(wallet_id, record.clone())])
            .unwrap();
        assert_eq!(store.get_wallet_projection(&wallet_id).unwrap(), Some(record));
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
        let utxo = Utxo::native(100, Address::zero(), 0);

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
            store.put_account(&Address::zero(), &AccountState::new(Address::zero())),
            Err(StorageError::NoActiveTransaction)
        ));
        assert!(matches!(
            store.set_token_balance(&TokenId::NATIVE, &Address::zero(), 0),
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

    #[test]
    fn test_pending_transaction_recovery_storage() {
        let store = SledStore::open_temporary().unwrap();

        let tx = crate::transaction::Transaction::new_wallet_registration(
            crate::transaction::WalletTransactionData {
                wallet_id: Hash::new([0x11; 32]),
                wallet_type: "primary".to_string(),
                wallet_name: "Recovery Wallet".to_string(),
                alias: None,
                public_key: vec![0x22; 32],
                owner_identity_id: Some(Hash::new([0x33; 32])),
                seed_commitment: Hash::new([0x44; 32]),
                created_at: 1_700_000_000,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 25,
            },
            vec![],
            Signature {
                signature: vec![0x55; 32],
                public_key: PublicKey::new([0x22; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 1_700_000_000,
            },
            b"pending wallet".to_vec(),
        );

        store.put_pending_transaction(&tx).unwrap();
        let restored: Vec<_> = store.iter_pending_transactions().unwrap().collect();
        assert_eq!(restored.len(), 1, "pending transaction should be persisted");
        assert_eq!(restored[0].hash(), tx.hash(), "restored tx hash must match");

        let tx_hash: [u8; 32] = tx.hash().as_bytes().try_into().unwrap();
        store.delete_pending_transaction(&tx_hash).unwrap();
        let after_delete: Vec<_> = store.iter_pending_transactions().unwrap().collect();
        assert!(
            after_delete.is_empty(),
            "pending transaction should be removed from recovery storage"
        );
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
            owned_wallets: vec!["wallet-1".to_string()],
            ..Default::default()
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
            ..Default::default()
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

    #[test]
    #[cfg(feature = "real-proofs")]
    fn test_utxo_merkle_tree_persistence() {
        let store = SledStore::open_temporary().unwrap();

        let outpoint1 = OutPoint::new(TxHash::new([1u8; 32]), 0);
        let outpoint2 = OutPoint::new(TxHash::new([2u8; 32]), 0);
        let leaf1 = [10u8; 32];
        let leaf2 = [20u8; 32];

        // 1. Insert two leaves in block 1
        store.begin_block(0).unwrap();
        let idx1 = store.put_utxo_merkle_leaf(&outpoint1, leaf1).unwrap();
        let idx2 = store.put_utxo_merkle_leaf(&outpoint2, leaf2).unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        store.commit_block().unwrap();

        // 2. Root should be available after commit
        let root1 = store.get_utxo_merkle_root().unwrap();
        assert!(root1.is_some(), "Merkle root should be set after commit");

        // 3. Proofs should be queryable
        let proof1 = store.get_utxo_merkle_proof(&outpoint1).unwrap().expect("proof1");
        assert_eq!(proof1.leaf_index, 0);
        assert_eq!(proof1.root, root1.unwrap());

        let proof2 = store.get_utxo_merkle_proof(&outpoint2).unwrap().expect("proof2");
        assert_eq!(proof2.leaf_index, 1);
        assert_eq!(proof2.root, root1.unwrap());

        // 4. Delete leaf1 in block 2
        store.begin_block(1).unwrap();
        store.delete_utxo_merkle_leaf(&outpoint1).unwrap();
        store.commit_block().unwrap();

        // 5. outpoint1 should no longer have a proof
        assert!(store.get_utxo_merkle_proof(&outpoint1).unwrap().is_none());

        // 6. outpoint2 should still have a proof, but the root changed because leaf1 is now zero
        let proof2_after = store.get_utxo_merkle_proof(&outpoint2).unwrap().expect("proof2_after");
        assert_eq!(proof2_after.leaf_index, 1);
        let root2 = store.get_utxo_merkle_root().unwrap().expect("root2");
        assert_ne!(root2, root1.unwrap(), "Root should change after deletion");
    }

    #[test]
    fn test_utxo_merkle_tree_no_real_proofs() {
        let store = SledStore::open_temporary().unwrap();
        let outpoint = OutPoint::new(TxHash::new([1u8; 32]), 0);
        let leaf = [10u8; 32];

        store.begin_block(0).unwrap();
        let idx = store.put_utxo_merkle_leaf(&outpoint, leaf).unwrap();
        assert_eq!(idx, 0);
        store.commit_block().unwrap();

        // Without real-proofs, root is still updated (empty) and proof returns None
        let root = store.get_utxo_merkle_root().unwrap();
        #[cfg(not(feature = "real-proofs"))]
        assert!(root.is_none() || root == Some([0u8; 32]));

        let proof = store.get_utxo_merkle_proof(&outpoint).unwrap();
        #[cfg(not(feature = "real-proofs"))]
        assert!(proof.is_none());
    }

    // =========================================================================
    // Write-ahead log crash-recovery tests
    // =========================================================================

    /// A block commit interrupted at *any* point — before any tree batch,
    /// after each tree batch, and before/after the `latest_height` write —
    /// must be rolled forward to a fully-committed block on the next open.
    #[test]
    fn test_wal_recovers_interrupted_block_commit() {
        use tempfile::TempDir;

        // Run one interruption scenario end-to-end and return the total
        // number of per-tree batches in block 1's staged WAL record, so the
        // caller can iterate exactly the data-dependent set of boundaries
        // rather than a hard-coded range.
        let run_scenario = |stop_after: usize, write_latest_height: bool| -> usize {
            let dir = TempDir::new().unwrap();
            let scenario =
                format!("stop_after={stop_after}, write_latest_height={write_latest_height}");

            let block0 = create_test_block(0, Hash::default());
            let block1 = create_test_block(1, block0.header.block_hash);
            let addr = Address([0x42; 32]);
            let account = AccountState::new(addr).with_wallet(WalletState::new(7));
            let outpoint = OutPoint::new(TxHash([0x99; 32]), 0);
            let utxo = Utxo::native(555, addr, 1);

            // --- session 1: commit genesis cleanly, then interrupt block 1 ---
            let total = {
                let store = SledStore::open(dir.path()).unwrap();

                store.begin_block(0).unwrap();
                store.append_block(&block0).unwrap();
                store.commit_block().unwrap();

                // Stage block 1 across several trees, then interrupt the
                // commit partway with the WAL marker still in place.
                store.begin_block(1).unwrap();
                store.append_block(&block1).unwrap();
                store.put_account(&addr, &account).unwrap();
                store.put_utxo(&outpoint, &utxo).unwrap();
                let total = store
                    .debug_interrupt_commit(stop_after, write_latest_height)
                    .unwrap();
                assert!(total >= 4, "block 1 should touch several trees ({scenario})");

                assert!(
                    store.wal.get(WAL_PENDING_KEY).unwrap().is_some(),
                    "interrupted commit must leave a WAL marker ({scenario})"
                );
                total
            }; // store dropped — simulates the process dying mid-commit

            // --- session 2: reopening MUST roll the commit forward ---
            {
                let store = SledStore::open(dir.path()).unwrap();

                assert_eq!(
                    store.latest_height().unwrap(),
                    1,
                    "recovery must finish block 1 ({scenario})"
                );
                let block = store.get_block_by_height(1).unwrap();
                assert!(block.is_some(), "block 1 must be present after recovery ({scenario})");
                assert_eq!(block.unwrap().header.height, 1);

                let recovered_account = store
                    .get_account(&addr)
                    .unwrap()
                    .unwrap_or_else(|| panic!("account missing after recovery ({scenario})"));
                assert_eq!(recovered_account.wallet.unwrap().nonce, 7, "{scenario}");

                let recovered_utxo = store
                    .get_utxo(&outpoint)
                    .unwrap()
                    .unwrap_or_else(|| panic!("utxo missing after recovery ({scenario})"));
                assert_eq!(recovered_utxo.amount, 555, "{scenario}");

                assert!(
                    store.wal.get(WAL_PENDING_KEY).unwrap().is_none(),
                    "WAL marker must be cleared once recovery completes ({scenario})"
                );
            }

            // --- session 3: a second reopen is a clean no-op ---
            {
                let store = SledStore::open(dir.path()).unwrap();
                assert_eq!(store.latest_height().unwrap(), 1, "{scenario}");
                assert!(
                    store.wal.get(WAL_PENDING_KEY).unwrap().is_none(),
                    "no recovery should be pending on a clean reopen ({scenario})"
                );
            }

            total
        };

        // Probe once to learn how many per-tree batches block 1 actually
        // produces, then exercise EVERY interruption boundary: `stop_after`
        // 0 → interrupted before any tree, `total` → after all of them.
        // Deriving the bound from the data keeps every tree boundary covered
        // even as the set of trees a commit touches changes.
        let total_trees = run_scenario(0, false);
        for stop_after in 0..=total_trees {
            for write_latest_height in [false, true] {
                let total = run_scenario(stop_after, write_latest_height);
                assert_eq!(
                    total, total_trees,
                    "per-tree batch count must be deterministic across scenarios"
                );
            }
        }
    }

    /// A commit that runs to completion leaves no WAL marker, and reopening
    /// such a store performs no recovery.
    #[test]
    fn test_clean_commit_leaves_no_wal_marker() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let block0 = create_test_block(0, Hash::default());

        {
            let store = SledStore::open(dir.path()).unwrap();
            store.begin_block(0).unwrap();
            store.append_block(&block0).unwrap();
            store.commit_block().unwrap();
            assert!(
                store.wal.get(WAL_PENDING_KEY).unwrap().is_none(),
                "a completed commit must leave no WAL marker"
            );
        }

        // Reopen: recovery is a no-op and state is intact.
        let store = SledStore::open(dir.path()).unwrap();
        assert_eq!(store.latest_height().unwrap(), 0);
        assert!(store.get_block_by_height(0).unwrap().is_some());
        assert!(store.wal.get(WAL_PENDING_KEY).unwrap().is_none());
    }

    // =========================================================================
    // Generic Table abstraction (BST-101)
    // =========================================================================

    /// A `Table` declared purely for the round-trip test, backed by the (empty
    /// in a fresh store) `dao_stakes` keyspace.
    struct TableProbe;
    impl crate::storage::Table for TableProbe {
        const NAME: &'static str = TREE_DAO_STAKES;
        const VERSION: u32 = 1;
        type Key = [u8; 8];
        type Value = u64;
        fn encode_key(key: &[u8; 8]) -> Vec<u8> {
            key.to_vec()
        }
    }

    /// One `impl Table` yields typed `get` / `stage` / `stage_delete` / `iter`
    /// with no bespoke store methods — staged writes land atomically with the
    /// block commit, exactly like every other tree.
    #[test]
    fn test_generic_table_round_trip() {
        use crate::storage::TableAccess;

        let store = SledStore::open_temporary().unwrap();
        let block0 = create_test_block(0, Hash::default());

        store.begin_block(0).unwrap();
        store.append_block(&block0).unwrap();
        store.stage::<TableProbe>(&1u64.to_be_bytes(), &111u64).unwrap();
        store.stage::<TableProbe>(&2u64.to_be_bytes(), &222u64).unwrap();
        // Staged writes are not visible until the block commits.
        assert_eq!(store.get::<TableProbe>(&1u64.to_be_bytes()).unwrap(), None);
        store.commit_block().unwrap();

        assert_eq!(store.get::<TableProbe>(&1u64.to_be_bytes()).unwrap(), Some(111));
        assert_eq!(store.get::<TableProbe>(&2u64.to_be_bytes()).unwrap(), Some(222));
        assert_eq!(store.get::<TableProbe>(&9u64.to_be_bytes()).unwrap(), None);

        let mut all = store.iter::<TableProbe>().unwrap();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1, 111);
        assert_eq!(all[1].1, 222);

        // stage_delete also lands with the block commit.
        let block1 = create_test_block(1, block0.header.block_hash);
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.stage_delete::<TableProbe>(&1u64.to_be_bytes()).unwrap();
        store.commit_block().unwrap();
        assert_eq!(store.get::<TableProbe>(&1u64.to_be_bytes()).unwrap(), None);
        assert_eq!(store.get::<TableProbe>(&2u64.to_be_bytes()).unwrap(), Some(222));
    }

    /// Generic table writes outside `begin_block` are rejected, like every
    /// other staged write.
    #[test]
    fn test_generic_table_stage_requires_transaction() {
        use crate::storage::TableAccess;
        let store = SledStore::open_temporary().unwrap();
        assert!(matches!(
            store.stage::<TableProbe>(&1u64.to_be_bytes(), &1u64),
            Err(StorageError::NoActiveTransaction)
        ));
    }

    /// Fork points are written directly (no `begin_block`) — reorgs are not
    /// block commits — are returned ascending by height, and survive a reopen.
    #[test]
    fn test_fork_point_direct_durable_write() {
        use crate::fork_recovery::{ForkPoint, ForkResolution};
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let mk = |h: u64| {
            ForkPoint::new(
                h,
                1_000 + h,
                Hash::new([h as u8; 32]),
                Hash::new([(h + 100) as u8; 32]),
                ForkResolution::SwitchedToFork,
            )
        };
        {
            let store = SledStore::open(dir.path()).unwrap();
            // No begin_block: a reorg has no open block transaction.
            store.put_fork_point(7, &mk(7)).unwrap();
            store.put_fork_point(3, &mk(3)).unwrap();

            let all = store.iter_fork_points().unwrap();
            assert_eq!(all.len(), 2);
            assert_eq!(all[0].height, 3, "ascending by height");
            assert_eq!(all[1].height, 7);
        }
        // Durable across reopen.
        let store = SledStore::open(dir.path()).unwrap();
        assert_eq!(store.iter_fork_points().unwrap().len(), 2);
    }

    /// Receipts are written directly (created after the block commits), keyed
    /// by tx hash, survive a reopen, and report finality derived from height.
    #[test]
    fn test_receipt_direct_durable_write() {
        use crate::receipts::TransactionReceipt;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let tx_hash = Hash::new([7u8; 32]);
        let receipt = TransactionReceipt::new(tx_hash, Hash::new([1u8; 32]), 42, 3, 100, 12345);
        {
            let store = SledStore::open(dir.path()).unwrap();
            store.put_receipt(&receipt).unwrap();

            let got = store.get_receipt(&tx_hash.as_array()).unwrap().unwrap();
            assert_eq!(got.block_height, 42);
            assert_eq!(got.tx_index, 3);
            // Finality is derived from current height, not stored.
            assert!(!got.is_finalized(50)); // 8 confirmations
            assert!(got.is_finalized(54)); // 12 confirmations
            assert!(store.get_receipt(&[0u8; 32]).unwrap().is_none());
        }
        // Durable across reopen.
        let store = SledStore::open(dir.path()).unwrap();
        assert!(store.get_receipt(&tx_hash.as_array()).unwrap().is_some());
    }

    // =========================================================================
    // Hot-state iterator tests (added in PR #2692 — lazy + Result)
    // =========================================================================

    #[test]
    fn test_iter_utxos_returns_committed_unspent_outputs() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());
        let outpoint = OutPoint::new(TxHash([0x44; 32]), 7);
        let utxo = Utxo::native(42u128, Address([0x55; 32]), 0);

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_utxo(&outpoint, &utxo).unwrap();
        store.commit_block().unwrap();

        let entries: Vec<_> = store
            .iter_utxos()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, outpoint);
        assert_eq!(entries[0].1.amount, 42);
    }

    #[test]
    fn test_iter_utxos_empty_store_yields_nothing() {
        let store = SledStore::open_temporary().unwrap();
        let entries: Vec<_> = store
            .iter_utxos()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_iter_utxos_returns_all_entries() {
        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());
        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        for i in 0..5u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            let outpoint = OutPoint::new(TxHash(hash), i as u32);
            let utxo = Utxo::native(100u128 + i as u128, Address([i; 32]), 0);
            store.put_utxo(&outpoint, &utxo).unwrap();
        }
        store.commit_block().unwrap();

        let entries: Vec<_> = store
            .iter_utxos()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_block_append_commits_nullifiers_atomically() {
        let store = SledStore::open_temporary().unwrap();
        let nullifier = Hash::new([0x91; 32]);
        let block = create_test_block_with_transactions(
            0,
            Hash::default(),
            vec![transaction_with_nullifier(nullifier)],
        );

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        assert!(
            store.is_nullifier_used(&nullifier).unwrap(),
            "mid-block reads must see staged nullifiers"
        );
        store.commit_block().unwrap();

        assert!(store.is_nullifier_used(&nullifier).unwrap());
        let entries: Vec<_> = store
            .iter_nullifiers()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries, vec![nullifier]);
    }

    #[test]
    fn test_uncommitted_nullifier_does_not_leak_after_rollback() {
        let store = SledStore::open_temporary().unwrap();
        let nullifier = Hash::new([0x92; 32]);
        let block = create_test_block_with_transactions(
            0,
            Hash::default(),
            vec![transaction_with_nullifier(nullifier)],
        );

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.rollback_block().unwrap();

        assert!(!store.is_nullifier_used(&nullifier).unwrap());
        let entries: Vec<_> = store
            .iter_nullifiers()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_nullifier_backfill_is_durable_without_block_transaction() {
        let dir = tempfile::TempDir::new().unwrap();
        let nullifier = Hash::new([0x93; 32]);

        {
            let store = SledStore::open(dir.path()).unwrap();
            store.backfill_nullifiers(&[nullifier]).unwrap();
            assert!(store.is_nullifier_used(&nullifier).unwrap());
        }

        let store = SledStore::open(dir.path()).unwrap();
        assert!(store.is_nullifier_used(&nullifier).unwrap());
        let entries: Vec<_> = store
            .iter_nullifiers()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries, vec![nullifier]);
    }

    #[test]
    fn test_nullifier_backfill_rejects_active_block_transaction() {
        let store = SledStore::open_temporary().unwrap();
        store.begin_block(0).unwrap();

        assert!(matches!(
            store.backfill_nullifiers(&[Hash::new([0x94; 32])]),
            Err(StorageError::TransactionAlreadyActive)
        ));

        store.rollback_block().unwrap();
    }

    #[test]
    fn test_nullifier_checkpoint_tracks_only_complete_contiguous_index() {
        let store = SledStore::open_temporary().unwrap();
        let genesis = create_test_block_with_transactions(
            0,
            Hash::default(),
            vec![transaction_with_nullifier(Hash::new([0x95; 32]))],
        );
        let genesis_hash = BlockHash::new(genesis.header.block_hash.as_array());

        store.begin_block(0).unwrap();
        store.append_block(&genesis).unwrap();
        store.commit_block().unwrap();
        assert!(store.nullifier_index_is_current(0, &genesis_hash).unwrap());

        let block1 = create_test_block_with_transactions(
            1,
            genesis.header.block_hash,
            vec![transaction_with_nullifier(Hash::new([0x96; 32]))],
        );
        let block1_hash = BlockHash::new(block1.header.block_hash.as_array());
        store.begin_block(1).unwrap();
        store.append_block(&block1).unwrap();
        store.commit_block().unwrap();
        assert!(store.nullifier_index_is_current(1, &block1_hash).unwrap());
    }

    #[test]
    fn test_iter_identities_with_metadata_returns_consensus_and_metadata() {
        use super::super::{IdentityConsensus, IdentityMetadata, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());
        let did_hash = [0x88; 32];
        let consensus = IdentityConsensus {
            did_hash,
            owner: Address([0x99; 32]),
            public_key_hash: [0xaa; 32],
            did_document_hash: [0xbb; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 1,
            registered_at_height: 0,
            registration_fee: 1000,
            dao_fee: 100,
            controlled_node_count: 0,
            owned_wallet_count: 1,
            attribute_count: 0,
        };
        let metadata = IdentityMetadata {
            did: "did:sovn:test-identity".to_string(),
            display_name: "Test Identity".to_string(),
            public_key: vec![1, 2, 3],
            kyber_public_key: vec![],
            ownership_proof: vec![4, 5, 6],
            controlled_nodes: vec![],
            owned_wallets: vec!["wallet-1".to_string()],
            attributes: vec![],
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &consensus).unwrap();
        store.put_identity_metadata(&did_hash, &metadata).unwrap();
        store.commit_block().unwrap();

        let entries: Vec<_> = store
            .iter_identities_with_metadata()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, did_hash);
        assert_eq!(entries[0].1.owner, consensus.owner);
        assert_eq!(entries[0].2.as_ref().unwrap().did, metadata.did);
    }

    /// Edge case: an identity may exist in the consensus tree without
    /// a corresponding metadata row (legacy / partial-write recovery
    /// scenarios). Must yield `Option<_> = None` for metadata in that
    /// case rather than erroring.
    #[test]
    fn test_iter_identities_with_metadata_handles_missing_metadata() {
        use super::super::{IdentityConsensus, IdentityStatus, IdentityType};

        let store = SledStore::open_temporary().unwrap();
        let block = create_test_block(0, Hash::default());
        let did_hash = [0x77; 32];
        let consensus = IdentityConsensus {
            did_hash,
            owner: Address([0x66; 32]),
            public_key_hash: [0x55; 32],
            did_document_hash: [0x44; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 1,
            created_at: 0,
            registered_at_height: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        };

        store.begin_block(0).unwrap();
        store.append_block(&block).unwrap();
        store.put_identity(&did_hash, &consensus).unwrap();
        // Intentionally NO put_identity_metadata.
        store.commit_block().unwrap();

        let entries: Vec<_> = store
            .iter_identities_with_metadata()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, did_hash);
        assert!(
            entries[0].2.is_none(),
            "identity without metadata must yield Option::None, not error"
        );
    }

    #[test]
    fn test_iter_identities_with_metadata_empty_store_yields_nothing() {
        let store = SledStore::open_temporary().unwrap();
        let entries: Vec<_> = store
            .iter_identities_with_metadata()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(entries.is_empty());
    }
}
