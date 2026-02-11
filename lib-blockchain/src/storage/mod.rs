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
//!
//! # CONSENSUS CORE RULE
//!
//! **No String identifiers in consensus state. Ever.**
//!
//! All identifiers (DIDs, token names, etc.) must be represented as fixed-size
//! byte arrays ([u8; 32]) in consensus-critical data structures. Human-readable
//! strings are metadata, not consensus state.

pub mod keys;
pub mod sled_store;

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export the store implementation
pub use sled_store::SledStore;

// Import canonical type aliases from lib-types
// These are the authoritative definitions for consensus-critical values
pub use lib_types::primitives::{BlockHeight, Amount, Bps};

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
    /// Native SOV token (all zeros)
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

/// Identity state - reference to identity in AccountState
/// CONSENSUS CORE SPEC: Fixed-size only, no String fields
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityState {
    /// Blake3 hash of DID string - reference to identities tree
    pub did_hash: [u8; 32],
    /// Identity status (cached from IdentityConsensus)
    pub status: IdentityStatus,
    /// Registration timestamp
    pub registered_at: u64,
}

impl IdentityState {
    pub fn new(did_hash: [u8; 32], registered_at: u64) -> Self {
        Self {
            did_hash,
            status: IdentityStatus::Active,
            registered_at,
        }
    }

    /// Create from a DID string by hashing it
    pub fn from_did(did: &str, registered_at: u64) -> Self {
        Self::new(blake3::hash(did.as_bytes()).into(), registered_at)
    }
}

/// A single identity attribute/claim - FIXED-SIZE
/// CONSENSUS CORE SPEC: No String fields in consensus state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAttribute {
    /// Blake3 hash of attribute name
    pub name_hash: [u8; 32],
    /// Attribute value (may be hashed for privacy)
    pub value: Vec<u8>,
    /// Issuer of this attribute
    pub issuer: Option<Address>,
    /// Expiration timestamp (0 = never)
    pub expires_at: u64,
}

impl IdentityAttribute {
    /// Create from a name string by hashing it
    pub fn new(name: &str, value: Vec<u8>, issuer: Option<Address>, expires_at: u64) -> Self {
        Self {
            name_hash: blake3::hash(name.as_bytes()).into(),
            value,
            issuer,
            expires_at,
        }
    }
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
// IDENTITY CONSENSUS STATE (Fixed-Size Only)
// =============================================================================
// CONSENSUS CORE SPEC: No String identifiers in consensus state. Ever.
//
// This structure is stored in the `identities` tree and participates in
// state hash computation. All fields MUST be fixed-size.
// =============================================================================

/// Identity type enum - NO STRINGS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum IdentityType {
    #[default]
    Human = 0,
    Organization = 1,
    Device = 2,
    Agent = 3,
}

impl IdentityType {
    /// Convert from string (for migration from legacy data)
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "human" => Self::Human,
            "organization" | "org" => Self::Organization,
            "device" => Self::Device,
            "agent" => Self::Agent,
            _ => Self::Human, // Default to human
        }
    }

    /// Get the string representation (for display only, not storage)
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Organization => "organization",
            Self::Device => "device",
            Self::Agent => "agent",
        }
    }
}

/// Identity consensus state - ALL FIELDS FIXED-SIZE
///
/// This is what goes in the `identities` tree and participates in state hash.
/// Human-readable data (strings) is stored separately in IdentityMetadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityConsensus {
    /// Blake3 hash of DID string - primary identifier
    pub did_hash: [u8; 32],
    /// Owner address (derived from public key)
    pub owner: Address,
    /// Blake3 hash of public key (full key in metadata)
    pub public_key_hash: [u8; 32],
    /// Blake3 hash of DID document
    pub did_document_hash: [u8; 32],
    /// Seed commitment for recovery verification
    /// Blake3(seed || "ZHTP_SEED_COMMITMENT_V2")
    pub seed_commitment: Option<[u8; 32]>,
    /// Identity type as enum (not string)
    pub identity_type: IdentityType,
    /// Identity status
    pub status: IdentityStatus,
    /// Identity version (1=legacy, 2=with seed commitment)
    pub version: u32,
    /// Creation timestamp (unix seconds)
    pub created_at: u64,
    /// Registration block height
    pub registered_at_height: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// DAO fee contribution
    pub dao_fee: u64,
    /// Number of controlled nodes (actual IDs in metadata)
    pub controlled_node_count: u32,
    /// Number of owned wallets (actual IDs in metadata)
    pub owned_wallet_count: u32,
    /// Number of attributes (actual data in metadata)
    pub attribute_count: u32,
}

impl IdentityConsensus {
    /// Create a new identity consensus state
    pub fn new(
        did_hash: [u8; 32],
        owner: Address,
        public_key: &[u8],
        identity_type: IdentityType,
    ) -> Self {
        Self {
            did_hash,
            owner,
            public_key_hash: blake3::hash(public_key).into(),
            did_document_hash: [0u8; 32],
            seed_commitment: None,
            identity_type,
            status: IdentityStatus::Active,
            version: 2,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            registered_at_height: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        }
    }

    /// Check if this identity has a seed commitment for recovery
    pub fn has_seed_commitment(&self) -> bool {
        self.seed_commitment.is_some()
    }

    /// Verify a seed commitment matches this identity's stored commitment
    pub fn verify_seed_commitment(&self, commitment: &[u8; 32]) -> bool {
        self.seed_commitment.as_ref() == Some(commitment)
    }

    /// Check if this identity needs migration to V2 format
    pub fn needs_migration(&self) -> bool {
        self.version < 2 || self.seed_commitment.is_none()
    }

    /// Set seed commitment and upgrade to V2
    pub fn set_seed_commitment(&mut self, commitment: [u8; 32]) {
        self.seed_commitment = Some(commitment);
        self.version = 2;
    }
}

impl Default for IdentityConsensus {
    fn default() -> Self {
        Self {
            did_hash: [0u8; 32],
            owner: Address::ZERO,
            public_key_hash: [0u8; 32],
            did_document_hash: [0u8; 32],
            seed_commitment: None,
            identity_type: IdentityType::Human,
            status: IdentityStatus::Active,
            version: 2,
            created_at: 0,
            registered_at_height: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_node_count: 0,
            owned_wallet_count: 0,
            attribute_count: 0,
        }
    }
}

// =============================================================================
// IDENTITY METADATA (Non-Consensus, Strings Allowed)
// =============================================================================
// This structure is stored in the `identity_metadata` tree for DID resolution
// and display purposes. It does NOT participate in consensus state hash.
// =============================================================================

/// Identity metadata - for resolution and display
///
/// Stored in separate `identity_metadata` tree, NOT part of consensus state hash.
/// This allows human-readable strings without violating consensus requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMetadata {
    /// The actual DID string (for resolution)
    pub did: String,
    /// Human-readable display name
    pub display_name: String,
    /// Full public key bytes
    pub public_key: Vec<u8>,
    /// Full ownership proof
    pub ownership_proof: Vec<u8>,
    /// Node IDs controlled by this identity
    pub controlled_nodes: Vec<String>,
    /// Wallet IDs owned by this identity
    pub owned_wallets: Vec<String>,
    /// Full attribute data with names
    pub attributes: Vec<IdentityAttributeFull>,
}

impl IdentityMetadata {
    pub fn new(did: String, display_name: String, public_key: Vec<u8>) -> Self {
        Self {
            did,
            display_name,
            public_key,
            ownership_proof: Vec::new(),
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
            attributes: Vec::new(),
        }
    }
}

impl Default for IdentityMetadata {
    fn default() -> Self {
        Self {
            did: String::new(),
            display_name: String::new(),
            public_key: Vec::new(),
            ownership_proof: Vec::new(),
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
            attributes: Vec::new(),
        }
    }
}

/// Full attribute with string data (metadata only, non-consensus)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAttributeFull {
    /// Attribute name (e.g., "email", "citizenship")
    pub name: String,
    /// Attribute value
    pub value: Vec<u8>,
    /// Issuer of this attribute
    pub issuer: Option<Address>,
    /// Expiration timestamp (0 = never)
    pub expires_at: u64,
}

// =============================================================================
// HELPER: Hash a DID string for storage key
// =============================================================================

/// Hash a DID string to get the fixed-size storage key
///
/// Callers MUST use this before any identity storage operation.
/// The DID string itself is stored in IdentityMetadata for resolution.
#[inline]
pub fn did_to_hash(did: &str) -> [u8; 32] {
    blake3::hash(did.as_bytes()).into()
}

/// Derive an address from a public key (first 32 bytes of hash)
#[inline]
pub fn derive_address_from_public_key(public_key: &[u8]) -> Address {
    Address::new(*blake3::hash(public_key).as_bytes())
}

// =============================================================================
// LEGACY CONVERSION
// =============================================================================

/// Convert legacy IdentityTransactionData to consensus + metadata pair
pub fn convert_legacy_identity(
    legacy: &crate::transaction::IdentityTransactionData,
) -> (IdentityConsensus, IdentityMetadata) {
    let did_hash = did_to_hash(&legacy.did);
    let owner = derive_address_from_public_key(&legacy.public_key);

    let consensus = IdentityConsensus {
        did_hash,
        owner,
        public_key_hash: blake3::hash(&legacy.public_key).into(),
        did_document_hash: legacy.did_document_hash.into(),
        seed_commitment: None, // Legacy identities don't have this
        identity_type: IdentityType::from_str(&legacy.identity_type),
        status: IdentityStatus::Active,
        version: 1, // Mark as legacy
        created_at: legacy.created_at,
        registered_at_height: 0, // Unknown for legacy
        registration_fee: legacy.registration_fee,
        dao_fee: legacy.dao_fee,
        controlled_node_count: legacy.controlled_nodes.len() as u32,
        owned_wallet_count: legacy.owned_wallets.len() as u32,
        attribute_count: 0,
    };

    let metadata = IdentityMetadata {
        did: legacy.did.clone(),
        display_name: legacy.display_name.clone(),
        public_key: legacy.public_key.clone(),
        ownership_proof: legacy.ownership_proof.clone(),
        controlled_nodes: legacy.controlled_nodes.clone(),
        owned_wallets: legacy.owned_wallets.clone(),
        attributes: Vec::new(),
    };

    (consensus, metadata)
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

    #[error("Identity not found: {}", hex::encode(.0))]
    IdentityNotFound([u8; 32]),

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
/// # Invariant
///
/// **No consensus logic reads or writes state outside this trait.**
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
    fn get_block_by_height(&self, h: BlockHeight) -> StorageResult<Option<crate::block::Block>>;

    /// Get a block by its hash.
    ///
    /// Returns None if no block with that hash exists.
    fn get_block_by_hash(&self, h: &BlockHash) -> StorageResult<Option<crate::block::Block>>;

    /// Get the height of the latest block.
    ///
    /// Returns 0 if only genesis exists, or the height of the tip.
    /// Returns error if chain is empty (no genesis).
    fn latest_height(&self) -> StorageResult<BlockHeight>;

    /// Get just the block hash at a given height (without full deserialization).
    ///
    /// This is an optimization for previous-hash validation to avoid
    /// deserializing the entire block when only the hash is needed.
    ///
    /// Default implementation falls back to get_block_by_height.
    fn get_block_hash_by_height(&self, h: BlockHeight) -> StorageResult<Option<BlockHash>> {
        Ok(self.get_block_by_height(h)?
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
    fn get_utxo(&self, op: &OutPoint) -> StorageResult<Option<Utxo>>;

    /// Create or update a UTXO.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_utxo(&self, op: &OutPoint, u: &Utxo) -> StorageResult<()>;

    /// Delete a UTXO (mark as spent).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Deleting non-existent UTXO is a no-op (idempotent)
    fn delete_utxo(&self, op: &OutPoint) -> StorageResult<()>;

    // =========================================================================
    // Token Contracts
    // =========================================================================
    // Token contracts store the full token metadata, supply policy, and
    // economic configuration. This is the authoritative source for token rules.
    // =========================================================================

    /// Get a token contract by its ID.
    ///
    /// Returns None if no contract exists for that token.
    fn get_token_contract(&self, id: &TokenId) -> StorageResult<Option<crate::contracts::TokenContract>>;

    /// Store a token contract.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_token_contract(&self, c: &crate::contracts::TokenContract) -> StorageResult<()>;

    // =========================================================================
    // Token Balances (Hot Path)
    // =========================================================================
    // Token balances are separate from contract metadata for performance.
    // This is the hot path - updated on every transfer.
    // =========================================================================

    /// Get token balance for an address.
    ///
    /// Returns 0 if no balance exists (not an error).
    fn get_token_balance(&self, t: &TokenId, a: &Address) -> StorageResult<Amount>;

    /// Set token balance for an address.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Setting balance to 0 may delete the entry (implementation detail)
    fn set_token_balance(&self, t: &TokenId, a: &Address, v: Amount) -> StorageResult<()>;

    // =========================================================================
    // Identity Consensus State (Phase 0 - DID Recovery)
    // =========================================================================
    // CONSENSUS CORE SPEC: All keys are [u8; 32], no String parameters.
    //
    // Two-layer storage:
    // - identities tree: did_hash → IdentityConsensus (participates in state hash)
    // - identity_metadata tree: did_hash → IdentityMetadata (non-consensus, for resolution)
    // =========================================================================

    /// Get identity consensus state by DID hash.
    ///
    /// Returns None if no identity exists with that DID hash.
    /// Use `did_to_hash()` to convert a DID string to hash.
    fn get_identity(&self, did_hash: &[u8; 32]) -> StorageResult<Option<IdentityConsensus>>;

    /// Store identity consensus state.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_identity(&self, did_hash: &[u8; 32], identity: &IdentityConsensus) -> StorageResult<()>;

    /// Delete an identity (revocation).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Deleting non-existent identity is a no-op (idempotent)
    fn delete_identity(&self, did_hash: &[u8; 32]) -> StorageResult<()>;

    /// Get DID hash by owner address (secondary index).
    ///
    /// Returns the DID hash for the identity owned by this address.
    /// Use get_identity() with the returned hash to get full consensus state.
    fn get_identity_by_owner(&self, addr: &Address) -> StorageResult<Option<[u8; 32]>> {
        // Default implementation returns None (requires secondary index)
        let _ = addr;
        Ok(None)
    }

    /// Store owner → did_hash index entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_identity_owner_index(&self, addr: &Address, did_hash: &[u8; 32]) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = (addr, did_hash);
        Ok(())
    }

    /// Delete owner → did_hash index entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_identity_owner_index(&self, addr: &Address) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = addr;
        Ok(())
    }

    // =========================================================================
    // Identity Metadata (Non-Consensus, for DID Resolution)
    // =========================================================================

    /// Get identity metadata by DID hash.
    ///
    /// This is for DID resolution and display, NOT consensus.
    fn get_identity_metadata(&self, did_hash: &[u8; 32]) -> StorageResult<Option<IdentityMetadata>> {
        // Default implementation returns None
        let _ = did_hash;
        Ok(None)
    }

    /// Store identity metadata.
    ///
    /// This is for DID resolution and display, NOT consensus.
    fn put_identity_metadata(&self, did_hash: &[u8; 32], metadata: &IdentityMetadata) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = (did_hash, metadata);
        Ok(())
    }

    /// Delete identity metadata.
    fn delete_identity_metadata(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = did_hash;
        Ok(())
    }

    /// List identity DID hashes registered at a specific block height.
    ///
    /// Useful for syncing and auditing identity registrations.
    fn get_identities_at_height(&self, height: u64) -> StorageResult<Vec<[u8; 32]>> {
        // Default implementation returns empty (requires height index)
        let _ = height;
        Ok(Vec::new())
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
    fn begin_block(&self, height: BlockHeight) -> StorageResult<()>;

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

    // =========================================================================
    // Account State (Legacy - Migrating to typed sub-stores)
    // =========================================================================
    // NOTE: Account state methods are being phased out in favor of typed
    // accessors. New code should use get_token_balance/set_token_balance
    // for balances, and future typed methods for identity/validator state.
    // =========================================================================

    /// Get account state for an address.
    ///
    /// Returns None if no account exists at that address.
    ///
    /// DEPRECATED: Use typed accessors (get_token_balance, etc.) instead.
    fn get_account(&self, addr: &Address) -> StorageResult<Option<AccountState>>;

    /// Create or update account state.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    ///
    /// DEPRECATED: Use typed accessors (set_token_balance, etc.) instead.
    fn put_account(&self, addr: &Address, acct: &AccountState) -> StorageResult<()>;
}
