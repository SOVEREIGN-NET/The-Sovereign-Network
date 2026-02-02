//! Blockchain Storage Layer
//!
//! This module defines the storage contract for the ZHTP blockchain.
//! All persistence operations MUST go through the `BlockchainStore` trait.
//!
//! # Data Model Invariants
//!
//! These invariants are NON-NEGOTIABLE. Any PR violating them is rejected.
//!
//! 1. **Blocks are append-only** - Once written, blocks are never modified or deleted.
//!    The only valid block operation after genesis is `append_block`.
//!
//! 2. **State is fully derivable from blocks** - Given the genesis state and all blocks,
//!    the current state can be reconstructed deterministically. No "magic" state.
//!
//! 3. **State writes only occur inside begin_block → commit_block** - All state mutations
//!    (UTXOs, accounts, balances) must happen within an atomic block transaction.
//!
//! 4. **No state mutation outside block execution** - Consensus, validation, and query
//!    code may only READ state. Writes are exclusively during block application.
//!
//! 5. **Rollback must restore exact pre-block state** - If `rollback_block` is called,
//!    the state MUST be identical to before `begin_block` was called.
//!
//! # Design Principles
//!
//! - Consensus code MUST NOT know which database backend is used
//! - No `save_to_file`, `load_from_file`, or `serialize(Blockchain)` anywhere
//! - Key encoding is protocol - see `keys.rs`
//! - Types are canonical - no ad-hoc types cross the storage boundary

pub mod keys;
pub mod sled_store;

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export the store implementation
pub use sled_store::SledStore;

// =============================================================================
// CANONICAL TYPES
// =============================================================================
// These types are the ONLY types that cross the storage boundary.
// They are protocol-level concepts, not implementation artifacts.
// =============================================================================

/// 32-byte block hash - uniquely identifies a block
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for BlockHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// 32-byte transaction hash - uniquely identifies a transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Reference to a specific output within a transaction
///
/// This is the canonical way to identify a UTXO. Never use tx hash alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Transaction containing this output
    pub tx: TxHash,
    /// Index of the output within the transaction (0-based)
    pub index: u32,
}

impl OutPoint {
    pub fn new(tx: TxHash, index: u32) -> Self {
        Self { tx, index }
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.tx, self.index)
    }
}

/// 32-byte address - identifies an account
///
/// Addresses are derived from public keys but are NOT public keys.
/// The derivation is: Address = hash(public_key)[0..32]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// 32-byte token identifier - uniquely identifies a token contract
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    /// Native ZHTP token (all zeros)
    pub const NATIVE: Self = Self([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn is_native(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl From<[u8; 32]> for TokenId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for TokenId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_native() {
            write!(f, "NATIVE")
        } else {
            write!(f, "{}", hex::encode(self.0))
        }
    }
}

// =============================================================================
// UTXO TYPE
// =============================================================================

/// Unspent Transaction Output
///
/// Represents spendable value at an OutPoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Amount in smallest unit (satoshi-equivalent)
    pub amount: u64,
    /// Owner's address (who can spend this)
    pub owner: Address,
    /// Token type (NATIVE for ZHTP, or custom token ID)
    pub token: TokenId,
    /// Block height when this UTXO was created
    pub created_at_height: u64,
    /// Optional lock script or conditions
    pub script: Option<Vec<u8>>,
}

impl Utxo {
    pub fn new(amount: u64, owner: Address, token: TokenId, created_at_height: u64) -> Self {
        Self {
            amount,
            owner,
            token,
            created_at_height,
            script: None,
        }
    }

    pub fn native(amount: u64, owner: Address, created_at_height: u64) -> Self {
        Self::new(amount, owner, TokenId::NATIVE, created_at_height)
    }
}

// =============================================================================
// ACCOUNT STATE
// =============================================================================
// Composite account state with typed sub-records.
// One address can play multiple roles. Roles evolve independently.
// =============================================================================

/// Complete account state at an address
///
/// This is a composite structure - an address may have any combination of:
/// - Wallet state (balance tracking, nonce)
/// - Identity state (DID, attributes)
/// - Validator state (stake, status)
///
/// These are stored together but evolve independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    /// The address this state belongs to
    pub address: Address,
    /// Wallet-related state (if this address has wallet functionality)
    pub wallet: Option<WalletState>,
    /// Identity-related state (if this address has a DID)
    pub identity: Option<IdentityState>,
    /// Validator-related state (if this address is a validator)
    pub validator: Option<ValidatorState>,
}

impl AccountState {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            wallet: None,
            identity: None,
            validator: None,
        }
    }

    pub fn with_wallet(mut self, wallet: WalletState) -> Self {
        self.wallet = Some(wallet);
        self
    }

    pub fn with_identity(mut self, identity: IdentityState) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn with_validator(mut self, validator: ValidatorState) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Returns true if this account has any state
    pub fn is_empty(&self) -> bool {
        self.wallet.is_none() && self.identity.is_none() && self.validator.is_none()
    }
}

/// Wallet state - transaction counting and metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletState {
    /// Transaction nonce (increments with each outgoing tx)
    pub nonce: u64,
    /// Wallet metadata
    pub metadata: WalletMetadata,
}

impl WalletState {
    pub fn new(nonce: u64) -> Self {
        Self {
            nonce,
            metadata: WalletMetadata::default(),
        }
    }
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Wallet metadata - optional descriptive information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WalletMetadata {
    /// Human-readable label
    pub label: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Wallet type (e.g., "standard", "multisig", "contract")
    pub wallet_type: Option<String>,
}

/// Identity state - DID and verifiable attributes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityState {
    /// Decentralized Identifier (DID)
    pub did: String,
    /// Verifiable attributes/claims
    pub attributes: Vec<IdentityAttribute>,
    /// Identity status
    pub status: IdentityStatus,
    /// Registration timestamp
    pub registered_at: u64,
}

impl IdentityState {
    pub fn new(did: String, registered_at: u64) -> Self {
        Self {
            did,
            attributes: Vec::new(),
            status: IdentityStatus::Active,
            registered_at,
        }
    }
}

/// A single identity attribute/claim
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAttribute {
    /// Attribute name (e.g., "email", "citizenship")
    pub name: String,
    /// Attribute value (may be hashed for privacy)
    pub value: Vec<u8>,
    /// Issuer of this attribute
    pub issuer: Option<Address>,
    /// Expiration timestamp (0 = never)
    pub expires_at: u64,
}

/// Identity status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IdentityStatus {
    #[default]
    Active,
    Suspended,
    Revoked,
}

/// Validator state - staking and consensus participation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorState {
    /// Total staked amount
    pub stake: u128,
    /// Validator status
    pub status: ValidatorStatus,
    /// Commission rate (basis points, 100 = 1%)
    pub commission_rate: u16,
    /// Block height when validator registered
    pub registered_at_height: u64,
    /// Number of blocks proposed
    pub blocks_proposed: u64,
    /// Number of blocks missed
    pub blocks_missed: u64,
}

impl ValidatorState {
    pub fn new(stake: u128, registered_at_height: u64) -> Self {
        Self {
            stake,
            status: ValidatorStatus::Pending,
            commission_rate: 0,
            registered_at_height,
            blocks_proposed: 0,
            blocks_missed: 0,
        }
    }
}

/// Validator status in consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ValidatorStatus {
    #[default]
    Pending,
    Active,
    Jailed,
    Unbonding,
    Inactive,
}

// =============================================================================
// STORAGE ERROR
// =============================================================================

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Block not found at height {0}")]
    BlockNotFoundByHeight(u64),

    #[error("Block not found with hash {0}")]
    BlockNotFoundByHash(BlockHash),

    #[error("UTXO not found: {0}")]
    UtxoNotFound(OutPoint),

    #[error("Account not found: {0}")]
    AccountNotFound(Address),

    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidBlockHeight { expected: u64, actual: u64 },

    #[error("No active block transaction")]
    NoActiveTransaction,

    #[error("Block transaction already active")]
    TransactionAlreadyActive,

    #[error("Corrupted data: {0}")]
    CorruptedData(String),

    #[error("Storage not initialized")]
    NotInitialized,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type StorageResult<T> = Result<T, StorageError>;

// =============================================================================
// BLOCKCHAIN STORE TRAIT
// =============================================================================
// This is the ONLY interface between consensus code and persistence.
// Consensus code MUST NOT know whether sled, RocksDB, or files are used.
// =============================================================================

/// The canonical storage interface for blockchain persistence.
///
/// # Contract
///
/// All implementations MUST guarantee:
/// - Atomicity: Changes within begin_block/commit_block are all-or-nothing
/// - Durability: After commit_block returns, data survives crashes
/// - Isolation: Reads see consistent state (no partial block updates)
///
/// # Usage Pattern
///
/// ```ignore
/// store.begin_block(height)?;
/// // ... apply all state changes ...
/// store.append_block(&block)?;
/// store.commit_block()?;
/// // If anything fails, call rollback_block() instead
/// ```
pub trait BlockchainStore: Send + Sync + fmt::Debug {
    // =========================================================================
    // Block History (Immutable)
    // =========================================================================
    // Blocks are append-only. Once written, they are never modified.
    // =========================================================================

    /// Append a new block to the chain.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Block height MUST equal latest_height + 1 (or 0 for genesis)
    /// - Block hash MUST be unique
    fn append_block(&self, block: &crate::block::Block) -> StorageResult<()>;

    /// Get a block by its height.
    ///
    /// Returns None if no block exists at that height.
    fn get_block_by_height(&self, height: u64) -> StorageResult<Option<crate::block::Block>>;

    /// Get a block by its hash.
    ///
    /// Returns None if no block with that hash exists.
    fn get_block_by_hash(&self, hash: &BlockHash) -> StorageResult<Option<crate::block::Block>>;

    /// Get the height of the latest block.
    ///
    /// Returns 0 if only genesis exists, or the height of the tip.
    /// Returns error if chain is empty (no genesis).
    fn get_latest_height(&self) -> StorageResult<u64>;

    /// Get just the block hash at a given height (without full deserialization).
    ///
    /// This is an optimization for previous-hash validation to avoid
    /// deserializing the entire block when only the hash is needed.
    ///
    /// Default implementation falls back to get_block_by_height.
    fn get_block_hash_by_height(&self, height: u64) -> StorageResult<Option<BlockHash>> {
        Ok(self.get_block_by_height(height)?
            .map(|b| BlockHash::new(b.header.block_hash.as_array())))
    }

    // =========================================================================
    // UTXO State (Mutable)
    // =========================================================================
    // UTXOs track spendable outputs. They are created and destroyed atomically
    // during block execution.
    // =========================================================================

    /// Get a UTXO by its outpoint.
    ///
    /// Returns None if the UTXO doesn't exist or has been spent.
    fn get_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>>;

    /// Create or update a UTXO.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> StorageResult<()>;

    /// Delete a UTXO (mark as spent).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Deleting non-existent UTXO is a no-op (idempotent)
    fn delete_utxo(&self, outpoint: &OutPoint) -> StorageResult<()>;

    // =========================================================================
    // Account State (Mutable)
    // =========================================================================
    // Accounts track identity, wallet, and validator state for addresses.
    // =========================================================================

    /// Get account state for an address.
    ///
    /// Returns None if no account exists at that address.
    fn get_account(&self, addr: &Address) -> StorageResult<Option<AccountState>>;

    /// Create or update account state.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_account(&self, addr: &Address, acct: &AccountState) -> StorageResult<()>;

    // =========================================================================
    // Token Balances (Mutable, Hot Path)
    // =========================================================================
    // Token balances are separate from contract metadata for performance.
    // This is the hot path - updated on every transfer.
    // =========================================================================

    /// Get token balance for an address.
    ///
    /// Returns 0 if no balance exists (not an error).
    fn get_token_balance(&self, token: TokenId, addr: &Address) -> StorageResult<u128>;

    /// Set token balance for an address.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Setting balance to 0 may delete the entry (implementation detail)
    fn set_token_balance(&self, token: TokenId, addr: &Address, balance: u128) -> StorageResult<()>;

    // =========================================================================
    // Token Contracts (Phase 2)
    // =========================================================================
    // Token contracts store the full token metadata, supply policy, and
    // economic configuration. This is the authoritative source for token rules.
    // =========================================================================

    /// Get a token contract by its ID.
    ///
    /// Returns None if no contract exists for that token.
    fn get_token_contract(&self, token: &TokenId) -> StorageResult<Option<Vec<u8>>> {
        // Default implementation returns None (not implemented)
        Ok(None)
    }

    /// Store a token contract.
    ///
    /// The contract is serialized to bytes by the caller.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_token_contract(&self, token: &TokenId, contract: &[u8]) -> StorageResult<()> {
        // Default implementation is a no-op
        Ok(())
    }

    // =========================================================================
    // Atomicity Control
    // =========================================================================
    // All state mutations MUST occur within begin_block/commit_block.
    // This ensures atomic application of block state changes.
    // =========================================================================

    /// Begin a block transaction.
    ///
    /// All subsequent state mutations are buffered until commit_block or
    /// discarded on rollback_block.
    ///
    /// # Requirements
    /// - Height MUST be latest_height + 1 (or 0 for genesis)
    /// - MUST NOT be called if a transaction is already active
    fn begin_block(&self, height: u64) -> StorageResult<()>;

    /// Commit all buffered changes from the current block transaction.
    ///
    /// After this returns successfully, all changes are durable.
    ///
    /// # Requirements
    /// - MUST have an active transaction from begin_block
    fn commit_block(&self) -> StorageResult<()>;

    /// Discard all buffered changes from the current block transaction.
    ///
    /// After this returns, state is identical to before begin_block was called.
    ///
    /// # Requirements
    /// - MUST have an active transaction from begin_block
    fn rollback_block(&self) -> StorageResult<()>;
}
