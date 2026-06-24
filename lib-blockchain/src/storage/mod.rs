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
pub mod table;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// Re-export the store implementation
pub use sled_store::SledStore;
pub use table::{Table, TableAccess};

// Import ALL canonical types from lib-types
// These are the authoritative definitions for consensus-critical types
pub use lib_types::primitives::{
    Address, Amount, BlockHash, BlockHeight, Bps, OutPoint, TokenId, TxHash, Utxo, UtxoMerkleProof,
};
use crate::types::Hash;

// =============================================================================
// EXTENSION TRAITS FOR CANONICAL TYPES
// =============================================================================
// These traits add storage-specific methods to canonical types from lib-types.
// The trait implementations (Display, AsRef, From) are in lib-types.
// =============================================================================

/// Extension trait adding storage-specific methods to BlockHash
pub trait BlockHashExt {
    /// Zero hash (used for genesis parent)
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl BlockHashExt for BlockHash {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to TxHash
pub trait TxHashExt {
    /// Zero hash
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl TxHashExt for TxHash {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to Address
pub trait AddressExt {
    /// Zero address
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl AddressExt for Address {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to TokenId
pub trait TokenIdExt {
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl TokenIdExt for TokenId {
    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
// UTXO TYPE (canonical definitions live in lib_types::primitives; re-exported above)
// =============================================================================

/// Consensus snapshot for token subsystem state.
///
/// This is persisted atomically within the block transaction boundary and loaded
/// on restart to guarantee deterministic token state reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenStateSnapshot {
    /// Full token contract state map (metadata + balances + supply).
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    /// Replay-protection nonces keyed by (token_id, sender_address).
    pub token_nonces: HashMap<([u8; 32], [u8; 32]), u64>,
}

/// Rebuildable wallet projection entry persisted in the dedicated wallets tree.
///
/// Schema:
/// - key: raw 32-byte wallet_id
/// - value: bincode-serialized `WalletProjectionRecord`
///
/// This is an indexed projection of committed wallet-registration state. It is
/// not authoritative consensus state and is safe to rebuild from canonical block
/// replay when required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletProjectionRecord {
    /// Canonical committed wallet data mirrored from block execution.
    pub wallet_data: crate::transaction::WalletTransactionData,
    /// Block height where this wallet registration committed.
    pub committed_at_height: u64,
}

/// Persistent record for a SOV stake to a sector DAO wallet.
///
/// Keyed in the `dao_stakes` sled tree as `sector_dao_key_id (32) || staker (32)`.
/// An existing record is replaced when the staker re-stakes to the same DAO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaoStakeRecord {
    /// Staker's key_id (32 bytes)
    pub staker: [u8; 32],
    /// Target DAO's key_id (32 bytes)
    pub sector_dao_key_id: [u8; 32],
    /// Locked SOV amount (in nSOV)
    pub amount: u128,
    /// Block height when the stake was last updated
    pub staked_at_height: u64,
    /// Absolute block height when the lock expires (staked_at_height + lock_blocks)
    pub locked_until: u64,
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
// DURABLE VALIDATOR RECORD (state-unification #56)
// =============================================================================
// The in-memory `ValidatorInfo` (blockchain layer) is split into two STORAGE
// types with the consensus/metadata boundary enforced by the type system, so
// durable storage never inherits consensus semantics by accident. Conversion
// to/from `ValidatorInfo` lives in the blockchain layer (`blockchain/validators`)
// — storage deliberately knows nothing about `ValidatorInfo`.
//
// Classification rule (per-field verified against real reads, #56): a field is
// CONSENSUS only if it affects block validity, validator-set membership,
// signatures, voting power, or replay determinism. Everything else is METADATA.
// =============================================================================

/// Schema version for the durable validator record set (`validators` tree).
///
/// v1 = first sled persistence of validator state (#56). Existing chains have no
/// durable validator record (validators lived only in the in-memory
/// `validator_registry`), so the version-gated regenerate-from-blocks migration
/// (`Blockchain::migrate_validator_records_schema`) backfills the whole tree from
/// replayed blocks. Like `identity_metadata`, the validator record set is fully
/// rebuildable from blocks, so the migration never decodes an old-shaped blob —
/// safe under bincode's positional (non-self-describing) encoding.
pub const VALIDATOR_RECORD_SCHEMA_VERSION: u32 = 1;

/// Consensus-affecting validator fields (#56).
///
/// STRICT boundary: a field belongs here ONLY if it has a verified consensus
/// read. Every field below does:
/// - `consensus_key` verifies BFT/validator signatures (`transaction::validation`),
/// - `stake` + `storage_provided` are the inputs to `calculate_voting_power`,
/// - `status` gates active-set membership (`get_active_validators`),
/// - `oracle_key_id` derives oracle-committee membership (attestation validity).
///
/// Do NOT add a field here without a real consensus read — accidental coupling
/// is exactly the divergence class #2645 exists to eliminate. Non-consensus
/// fields (transport/rewards keys, commission, timestamps, stats, provenance)
/// live in [`ValidatorMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorConsensusRecord {
    /// Validator identity ID (DID string) — the validator-set key.
    pub identity_id: String,
    /// Dilithium5 consensus public key — verifies BFT consensus signatures.
    #[serde(with = "serde_arrays")]
    pub consensus_key: [u8; 2592],
    /// Staked amount in micro-SOV — voting-power input.
    pub stake: u64,
    /// Storage provided in bytes — voting-power input (logarithmic storage bonus).
    pub storage_provided: u64,
    /// Active-set membership status: "active" | "inactive" | "jailed" | "slashed".
    /// Kept as the in-memory string verbatim (lossless) rather than remapped to
    /// the narrower `ValidatorStatus` enum (which has no `Slashed` variant), to
    /// avoid a silent misclassification at the storage boundary.
    pub status: String,
    /// Oracle committee attestation key id (oracle-attestation validity).
    pub oracle_key_id: Option<[u8; 32]>,
}

/// Non-consensus validator fields — ops / routing / display / provenance (#56).
///
/// A SEPARATE type from [`ValidatorConsensusRecord`] so a change here can never
/// become consensus-coupled by accident. None of these have a consensus read
/// (verified #56): `rewards_key`/`networking_key` are checked only for
/// key-separation at admission (from the tx, never re-derived from storage);
/// `commission_rate`/`registered_at` have no block-validity read; the rest are
/// liveness/throughput stats or provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ValidatorMetadata {
    /// Ed25519 / X25519 transport identity key (QUIC TLS, DHT node id).
    pub networking_key: Vec<u8>,
    /// Rewards wallet public key (reward destination; not read in state mutation).
    pub rewards_key: Vec<u8>,
    /// Network address for validator communication (host:port).
    pub network_address: String,
    /// Commission rate percentage (0-100).
    pub commission_rate: u8,
    /// Block height when the validator was registered.
    pub registered_at: u64,
    /// Last activity height/timestamp (liveness stat).
    pub last_activity: u64,
    /// Total blocks validated (throughput stat).
    pub blocks_validated: u64,
    /// Slash count (inert for validators today; only gateways threshold it).
    pub slash_count: u32,
    /// Provenance: validator admission path.
    pub admission_source: String,
    /// Provenance: governance proposal id authorizing this validator, if any.
    pub governance_proposal_id: Option<String>,
}

/// Durable validator record — the consensus/metadata split with the boundary in
/// the type system (#56). Persisted to the `validators` tree keyed by
/// `did_to_hash(identity_id)`. Convert to/from the in-memory `ValidatorInfo`
/// ONLY at the storage boundary (`blockchain/validators`), never store
/// `ValidatorInfo` directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredValidatorRecord {
    pub consensus: ValidatorConsensusRecord,
    pub metadata: ValidatorMetadata,
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

/// Current schema version of the `identity_metadata` tree.
///
/// - v1: original shape (no `kyber_public_key`).
/// - v2: adds `kyber_public_key` (#58).
///
/// On startup, a store whose persisted version is below this triggers the
/// regenerate-from-blocks migration (see
/// `Blockchain::migrate_identity_metadata_schema`). Because `identity_metadata`
/// is non-consensus and fully derivable from blocks, the migration rebuilds the
/// whole tree rather than reading any old-shaped blob — keeping it safe under
/// bincode's positional (non-self-describing) encoding.
pub const IDENTITY_METADATA_SCHEMA_VERSION: u32 = 2;

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
    /// Full Dilithium public key bytes
    pub public_key: Vec<u8>,
    /// Full Kyber (KEM) public key bytes — for encrypted-session setup and
    /// DID resolution (#58). Added in identity_metadata schema v2; existing
    /// records are regenerated from blocks by the version-gated migration
    /// (see `Blockchain::migrate_identity_metadata_schema`), so this is NOT
    /// read out of pre-v2 bincode blobs.
    pub kyber_public_key: Vec<u8>,
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
            kyber_public_key: Vec::new(),
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
            kyber_public_key: Vec::new(),
            ownership_proof: Vec::new(),
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
            attributes: Vec::new(),
        }
    }
}

/// Access-controlled view of identity metadata.
///
/// This is the only metadata shape that may be returned across trust
/// boundaries. Sensitive fields are wrapped in `Option` so that unauthorized
/// callers receive `None` instead of the actual data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMetadataView {
    pub did: String,
    pub display_name: String,
    pub public_key: Option<Vec<u8>>,
    pub controlled_nodes: Option<Vec<String>>,
    pub owned_wallets: Option<Vec<String>>,
    pub attributes: Option<Vec<IdentityAttributeFull>>,
}

impl IdentityMetadataView {
    /// Build a public-scoped view (minimal exposure).
    pub fn public(did: String, display_name: String) -> Self {
        Self {
            did,
            display_name,
            public_key: None,
            controlled_nodes: None,
            owned_wallets: None,
            attributes: None,
        }
    }

    /// Build a full view from raw metadata (owner, admin, council, self).
    pub fn from_metadata(metadata: &IdentityMetadata) -> Self {
        Self {
            did: metadata.did.clone(),
            display_name: metadata.display_name.clone(),
            public_key: Some(metadata.public_key.clone()),
            controlled_nodes: Some(metadata.controlled_nodes.clone()),
            owned_wallets: Some(metadata.owned_wallets.clone()),
            attributes: Some(metadata.attributes.clone()),
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
        kyber_public_key: legacy.kyber_public_key.clone(),
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
        Ok(self
            .get_block_by_height(h)?
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

    /// Iterate all currently unspent UTXOs.
    ///
    /// Yields lazily so callers don't materialise the entire UTXO set in
    /// RAM — at mainnet scale this set is unbounded. Each `Item` is a
    /// `StorageResult` so per-row decode failures surface to the caller
    /// without aborting the rest of the scan.
    fn iter_utxos(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(OutPoint, Utxo)>> + '_>> {
        Err(StorageError::Database(
            "UTXO iteration not supported by this store".to_string(),
        ))
    }

    // =========================================================================
    // Nullifier State (Mutable)
    // =========================================================================
    // Nullifiers are replay-protection markers for spent inputs. They are
    // consensus-critical and must be committed atomically with the block that
    // consumes them.
    // =========================================================================

    /// Return true if a nullifier has already been committed.
    fn is_nullifier_used(&self, nullifier: &Hash) -> StorageResult<bool> {
        let _ = nullifier;
        Err(StorageError::Database(
            "Nullifier lookups are not supported by this store".to_string(),
        ))
    }

    /// Mark a nullifier as spent.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_nullifier(&self, nullifier: &Hash) -> StorageResult<()> {
        let _ = nullifier;
        Err(StorageError::Database(
            "Nullifier writes are not supported by this store".to_string(),
        ))
    }

    /// Iterate all committed nullifiers.
    fn iter_nullifiers(&self) -> StorageResult<Box<dyn Iterator<Item = StorageResult<Hash>> + '_>> {
        Err(StorageError::Database(
            "Nullifier iteration is not supported by this store".to_string(),
        ))
    }

    /// Idempotently backfill nullifiers outside a block transaction.
    ///
    /// Used only during startup migrations from historical blocks. Normal block
    /// execution must use `put_nullifier` inside begin_block/commit_block.
    fn backfill_nullifiers(&self, nullifiers: &[Hash]) -> StorageResult<()> {
        let _ = nullifiers;
        Err(StorageError::Database(
            "Nullifier backfill is not supported by this store".to_string(),
        ))
    }

    /// Return true when the durable nullifier index is complete for this tip.
    fn nullifier_index_is_current(
        &self,
        height: BlockHeight,
        block_hash: &BlockHash,
    ) -> StorageResult<bool> {
        let _ = (height, block_hash);
        Ok(false)
    }

    /// Mark the durable nullifier index complete for this tip.
    fn mark_nullifier_index_current(
        &self,
        height: BlockHeight,
        block_hash: &BlockHash,
    ) -> StorageResult<()> {
        let _ = (height, block_hash);
        Err(StorageError::Database(
            "Nullifier checkpoint writes are not supported by this store".to_string(),
        ))
    }

    // =========================================================================
    // UTXO Merkle Tree (Mutable)
    // =========================================================================
    // Persistent Poseidon Merkle tree of unspent outputs. Wallets query this
    // to obtain inclusion proofs for real ZK transaction proofs.
    // =========================================================================

    /// Insert a UTXO leaf commitment into the Merkle tree.
    ///
    /// Returns the assigned `leaf_index` for the outpoint.
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_utxo_merkle_leaf(&self, op: &OutPoint, leaf: [u8; 32]) -> StorageResult<u64>;

    /// Remove a UTXO from the Merkle tree (sets its leaf to the zero hash).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_utxo_merkle_leaf(&self, op: &OutPoint) -> StorageResult<()>;

    /// Get the current UTXO Merkle root.
    fn get_utxo_merkle_root(&self) -> StorageResult<Option<[u8; 32]>>;

    /// Get the Merkle inclusion proof for a given outpoint.
    ///
    /// Returns `None` if the outpoint is not tracked in the Merkle tree.
    fn get_utxo_merkle_proof(&self, op: &OutPoint) -> StorageResult<Option<UtxoMerkleProof>>;

    /// Get the leaf index assigned to an outpoint.
    fn get_utxo_merkle_leaf_index(&self, op: &OutPoint) -> StorageResult<Option<u64>>;

    // =========================================================================
    // Token Contracts
    // =========================================================================
    // Token contracts store the full token metadata, supply policy, and
    // economic configuration. This is the authoritative source for token rules.
    // =========================================================================

    /// Get a token contract by its ID.
    ///
    /// Returns None if no contract exists for that token.
    fn get_token_contract(
        &self,
        id: &TokenId,
    ) -> StorageResult<Option<crate::contracts::TokenContract>>;

    /// Iterate over all token contracts.
    ///
    /// Returns an iterator of (TokenId, TokenContract) pairs.
    fn iter_token_contracts(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = (TokenId, crate::contracts::TokenContract)> + '_>>;

    /// Store a token contract.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_token_contract(&self, c: &crate::contracts::TokenContract) -> StorageResult<()>;

    /// Get token total supply.
    ///
    /// Returns None if no supply is tracked (token not initialized with supply).
    fn get_token_supply(&self, token: &TokenId) -> StorageResult<Option<u128>>;

    /// Set token total supply.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_token_supply(&self, token: &TokenId, supply: u128) -> StorageResult<()>;

    /// Get the latest persisted token subsystem snapshot.
    fn get_token_state_snapshot(&self) -> StorageResult<Option<TokenStateSnapshot>>;

    /// Persist the full token subsystem snapshot.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_token_state_snapshot(&self, snapshot: &TokenStateSnapshot) -> StorageResult<()>;

    // =========================================================================
    // Oracle State Persistence
    // =========================================================================

    /// Get the persisted oracle state (committee, config, signing pubkeys).
    ///
    /// Returns `None` if no oracle state has been persisted yet.
    /// Default no-op: implementations that don't support oracle state return None.
    fn get_oracle_state(&self) -> StorageResult<Option<crate::oracle::OracleState>> {
        Ok(None)
    }

    /// Persist oracle state directly (not inside a block transaction).
    ///
    /// This is intentionally a direct write (no `begin_block`/`commit_block` required)
    /// because oracle committee bootstrap happens outside of block processing.
    /// Default no-op for implementations that don't support oracle state.
    fn save_oracle_state(&self, _state: &crate::oracle::OracleState) -> StorageResult<()> {
        Ok(())
    }

    // =========================================================================
    // Pending Transactions (Non-Consensus Recovery State)
    // =========================================================================

    /// Persist a pending transaction for restart recovery.
    ///
    /// This is intentionally outside the block transaction boundary because the
    /// mempool is not consensus state. Implementations should make the write
    /// durable before returning so queued registrations survive restart.
    fn put_pending_transaction(&self, tx: &crate::transaction::Transaction) -> StorageResult<()>;

    /// Remove a pending transaction from recovery storage.
    fn delete_pending_transaction(&self, tx_hash: &[u8; 32]) -> StorageResult<()>;

    /// Iterate over all persisted pending transactions.
    fn iter_pending_transactions(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = crate::transaction::Transaction> + '_>>;

    // =========================================================================
    // Wallet Projection (Non-Authoritative, Rebuildable)
    // =========================================================================

    /// Load a wallet projection entry by wallet id.
    fn get_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
    ) -> StorageResult<Option<WalletProjectionRecord>>;

    /// Persist a wallet projection entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
        record: &WalletProjectionRecord,
    ) -> StorageResult<()>;

    /// Delete a wallet projection entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_wallet_projection(&self, wallet_id: &[u8; 32]) -> StorageResult<()>;

    /// Count wallet projection entries (authoritative sled cardinality).
    fn count_wallet_projections(&self) -> StorageResult<usize> {
        Ok(self.iter_wallet_projections()?.count())
    }

    /// Iterate all wallet projection entries.
    fn iter_wallet_projections(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = ([u8; 32], WalletProjectionRecord)> + '_>>;

    /// Replace the full wallet projection tree outside block execution.
    ///
    /// This is reserved for startup recovery of the non-authoritative wallet
    /// projection from canonical replay. It must not be used to mutate
    /// consensus-authoritative state.
    fn replace_wallet_projections(
        &self,
        records: &[([u8; 32], WalletProjectionRecord)],
    ) -> StorageResult<()>;

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

    /// Count non-zero balance holders for a token (sled `token_balances` tree).
    ///
    /// SledStore implements via prefix scan. Other backends must override or
    /// callers receive an explicit error — never a silent `Ok(0)`.
    fn count_token_holders(&self, _token_id: &TokenId) -> StorageResult<usize> {
        Err(StorageError::Database(
            "count_token_holders not implemented for this BlockchainStore backend".to_string(),
        ))
    }

    /// Set token balance for an address.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    /// - Setting balance to 0 may delete the entry (implementation detail)
    fn set_token_balance(&self, t: &TokenId, a: &Address, v: Amount) -> StorageResult<()>;

    /// Backfill token balances from a legacy TokenContract into the token_balances store.
    ///
    /// Used as a one-time migration when upgrading from a node that stored SOV balances
    /// only in the TokenContract blob (legacy path) to a node that uses the token_balances
    /// Sled tree (executor path). Entries are keyed by raw 32-byte address (wallet_id).
    ///
    /// Only writes entries where the token_balances tree has no existing entry for the
    /// (token_id, address) pair. This is idempotent.
    ///
    /// Returns the number of entries written (0 if already up-to-date).
    fn backfill_token_balances_from_contract(
        &self,
        _token_id: &TokenId,
        _entries: &[([u8; 32], u128)],
    ) -> StorageResult<usize> {
        Ok(0) // Default no-op
    }

    /// Directly overwrite token balances for startup migration/repair only.
    ///
    /// Unlike `set_token_balance`, this does NOT require an active block transaction.
    /// Use ONLY in startup migrations (e.g., correcting backfill inflation), never
    /// during block execution.
    ///
    /// SledStore implements this path. Other backends must override or callers
    /// receive an explicit error — never a silent `Ok(0)` no-write.
    fn force_set_token_balances(
        &self,
        _entries: &[(TokenId, Address, u128)],
    ) -> StorageResult<usize> {
        Err(StorageError::Database(
            "force_set_token_balances not implemented for this BlockchainStore backend"
                .to_string(),
        ))
    }

    // =========================================================================
    // Token Transfer Nonces (Replay Protection)
    // =========================================================================
    // Nonces prevent replay attacks on token transfers.
    // Key: (token_id, sender_address) -> nonce
    // =========================================================================

    /// Get the nonce for a token transfer from a specific sender.
    ///
    /// Returns 0 if no nonce exists (first transfer).
    fn get_token_nonce(&self, token_id: &TokenId, sender: &Address) -> StorageResult<u64>;

    /// Set the nonce for a token transfer.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn set_token_nonce(
        &self,
        token_id: &TokenId,
        sender: &Address,
        nonce: u64,
    ) -> StorageResult<()>;

    /// Increment the nonce for a token transfer after successful execution.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn increment_token_nonce(&self, token_id: &TokenId, sender: &Address) -> StorageResult<u64> {
        let current = self.get_token_nonce(token_id, sender)?;
        let new_nonce = current + 1;
        self.set_token_nonce(token_id, sender, new_nonce)?;
        Ok(new_nonce)
    }

    // =========================================================================
    // Smart Contract Storage (Phase 4)
    // =========================================================================

    /// Get contract code by ID.
    ///
    /// Returns None if no contract exists at that ID.
    fn get_contract_code(&self, contract_id: &[u8; 32]) -> StorageResult<Option<Vec<u8>>>;

    /// Store contract code.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_contract_code(&self, contract_id: &[u8; 32], code: &[u8]) -> StorageResult<()>;

    /// Get contract storage value.
    ///
    /// Returns None if no value exists at that key.
    fn get_contract_storage(
        &self,
        contract_id: &[u8; 32],
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>>;

    /// Set contract storage value.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_contract_storage(
        &self,
        contract_id: &[u8; 32],
        key: &[u8],
        value: &[u8],
    ) -> StorageResult<()>;

    /// Delete contract storage value.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_contract_storage(&self, contract_id: &[u8; 32], key: &[u8]) -> StorageResult<()>;

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

    /// Iterate over every persisted identity (consensus projection).
    ///
    /// Returns the authoritative, complete set of `IdentityConsensus` records.
    /// Unlike the in-memory `Blockchain::identity_registry` — a non-durable
    /// shadow that can be empty or partial on a store-backed node after restart
    /// or window pruning — this reflects what consensus actually committed.
    ///
    /// Intentionally has NO default implementation: a backend that silently
    /// returned an empty iterator would make callers report zero identities
    /// (the same class of consensus footgun the #2639 migration exists to
    /// eliminate), so every backend MUST provide a real scan.
    fn iter_identities(&self) -> StorageResult<Box<dyn Iterator<Item = IdentityConsensus> + '_>>;

    /// Count persisted identities (authoritative).
    ///
    /// No default for the same reason as [`iter_identities`]: an empty/zero
    /// default would silently misreport the validator/citizen population.
    fn count_identities(&self) -> StorageResult<usize>;

    /// Iterate identity consensus records joined with their optional
    /// `IdentityMetadata`.
    ///
    /// Distinct from [`iter_identities`] which returns the bare consensus
    /// row. This variant pairs each consensus record with its metadata
    /// (display name, did string, controlled nodes, etc.) and is the
    /// surface the startup hydrate path uses to rebuild
    /// `identity_registry` from sled.
    ///
    /// Yields lazily so the entire identity set never lives in RAM at
    /// once. Each `Item` is a `StorageResult` so per-row decode failures
    /// surface to the caller without aborting the rest of the scan.
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
        Err(StorageError::Database(
            "identity-with-metadata iteration not supported by this store".to_string(),
        ))
    }

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
    fn get_identity_metadata(
        &self,
        did_hash: &[u8; 32],
    ) -> StorageResult<Option<IdentityMetadata>> {
        // Default implementation returns None
        let _ = did_hash;
        Ok(None)
    }

    /// Iterate every persisted identity metadata record (#2639).
    ///
    /// Returns the durable `IdentityMetadata` set (display_name, public_key,
    /// controlled_nodes, owned_wallets, attributes). Required (no default),
    /// unlike the point-lookup `get_identity_metadata`: a silent empty default
    /// for an ITERATOR would make metadata scans — e.g. resolving a DID by
    /// public key for a council-membership check during transaction validation —
    /// drop the whole set, the consensus footgun #2645 exists to eliminate.
    fn iter_identity_metadata(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = IdentityMetadata> + '_>>;

    /// Store identity metadata.
    ///
    /// This is for DID resolution and display, NOT consensus.
    fn put_identity_metadata(
        &self,
        did_hash: &[u8; 32],
        metadata: &IdentityMetadata,
    ) -> StorageResult<()> {
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

    /// Read the persisted `identity_metadata` schema version.
    ///
    /// Drives the version-gated regenerate-from-blocks migration (#58).
    /// The default returns [`IDENTITY_METADATA_SCHEMA_VERSION`] so backends with
    /// no persisted metadata (mocks, in-memory) are treated as already current
    /// and never trigger a rebuild. Sled overrides this to read the meta key,
    /// defaulting to `1` when the key is absent (pre-kyber records).
    fn identity_metadata_schema_version(&self) -> StorageResult<u32> {
        Ok(IDENTITY_METADATA_SCHEMA_VERSION)
    }

    /// Persist the `identity_metadata` schema version. Default is a no-op.
    fn set_identity_metadata_schema_version(&self, version: u32) -> StorageResult<()> {
        let _ = version;
        Ok(())
    }

    /// Remove every record from the `identity_metadata` tree.
    ///
    /// Used by the schema migration to drop stale pre-kyber blobs before
    /// regenerating the tree from blocks. Default is a no-op (metadata is
    /// non-consensus and rebuildable, so clearing a backend without one is safe).
    fn clear_identity_metadata(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Write an identity consensus entry directly, bypassing the block-tx batch.
    ///
    /// Used for one-off bootstrap writes (genesis backfill) that must happen
    /// outside of a normal begin_block/commit_block cycle. Idempotent.
    fn put_identity_direct(
        &self,
        did_hash: &[u8; 32],
        identity: &IdentityConsensus,
    ) -> StorageResult<()> {
        // Default falls back to the batched API; implementations that need
        // non-tx writes override this.
        let _ = (did_hash, identity);
        Err(StorageError::Database(
            "put_identity_direct not supported by this backend".to_string(),
        ))
    }

    /// Write identity metadata directly, bypassing the block-tx batch.
    fn put_identity_metadata_direct(
        &self,
        did_hash: &[u8; 32],
        metadata: &IdentityMetadata,
    ) -> StorageResult<()> {
        let _ = (did_hash, metadata);
        Err(StorageError::Database(
            "put_identity_metadata_direct not supported by this backend".to_string(),
        ))
    }

    /// Bulk-write identity metadata, with a SINGLE flush at the end (CR PR #2679).
    ///
    /// Used by the schema-v2 regenerate-from-blocks migration where calling
    /// `put_identity_metadata_direct` per record makes upgrade time O(n) in
    /// fsync calls. Implementations should batch the inserts and flush once.
    /// Default falls back to the per-record direct write so backends that
    /// haven't specialised this still function (just at the old cost).
    fn put_identity_metadata_batch(
        &self,
        records: &[([u8; 32], IdentityMetadata)],
    ) -> StorageResult<usize> {
        let mut written = 0usize;
        for (did_hash, metadata) in records {
            self.put_identity_metadata_direct(did_hash, metadata)?;
            written += 1;
        }
        Ok(written)
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
    // Durable validator records (state-unification #56)
    // =========================================================================
    // The `validators` tree stores `StoredValidatorRecord` (consensus+metadata
    // split) keyed by `did_to_hash(identity_id)`. Point reads/writes default to
    // no-op/None so non-sled backends (mocks) compile unchanged; the ITERATOR is
    // required (see `iter_validator_records`).
    // =========================================================================

    /// Point-lookup a durable validator record by DID hash (#56).
    fn get_validator_record(
        &self,
        did_hash: &[u8; 32],
    ) -> StorageResult<Option<StoredValidatorRecord>> {
        let _ = did_hash;
        Ok(None)
    }

    /// Iterate every persisted validator record (#56).
    ///
    /// Required (no default), mirroring `iter_identity_metadata`: a silent empty
    /// default for an ITERATOR would make a validator-set scan — e.g. rebuilding
    /// the active set or resolving a validator by consensus key — drop the whole
    /// set, the consensus footgun #2645 exists to eliminate.
    fn iter_validator_records(
        &self,
    ) -> StorageResult<Box<dyn Iterator<Item = StoredValidatorRecord> + '_>>;

    /// Store a validator record within the open block tx batch. Default no-op.
    fn put_validator_record(
        &self,
        did_hash: &[u8; 32],
        record: &StoredValidatorRecord,
    ) -> StorageResult<()> {
        let _ = (did_hash, record);
        Ok(())
    }

    /// Delete a validator record. Default no-op.
    fn delete_validator_record(&self, did_hash: &[u8; 32]) -> StorageResult<()> {
        let _ = did_hash;
        Ok(())
    }

    /// Count durable validator records. Default 0.
    fn count_validator_records(&self) -> StorageResult<usize> {
        Ok(0)
    }

    /// Read the persisted `validators` schema version.
    ///
    /// Drives the version-gated regenerate-from-blocks migration (#56). The
    /// default returns [`VALIDATOR_RECORD_SCHEMA_VERSION`] so backends with no
    /// persisted validators (mocks) are treated as already current and never
    /// trigger a rebuild. Sled overrides this to read the meta key, defaulting to
    /// `0` when the key is absent (no durable validators yet → migrate to v1).
    fn validator_record_schema_version(&self) -> StorageResult<u32> {
        Ok(VALIDATOR_RECORD_SCHEMA_VERSION)
    }

    /// Persist the `validators` schema version. Default no-op.
    fn set_validator_record_schema_version(&self, version: u32) -> StorageResult<()> {
        let _ = version;
        Ok(())
    }

    /// Remove every record from the `validators` tree.
    ///
    /// Used by the schema migration to drop stale records before regenerating
    /// from blocks. Default no-op (records are rebuildable, so clearing a backend
    /// without one is safe).
    fn clear_validator_records(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Write a validator record directly, bypassing the block-tx batch.
    ///
    /// Used by the regenerate-from-blocks migration (outside begin/commit_block).
    fn put_validator_record_direct(
        &self,
        did_hash: &[u8; 32],
        record: &StoredValidatorRecord,
    ) -> StorageResult<()> {
        let _ = (did_hash, record);
        Err(StorageError::Database(
            "put_validator_record_direct not supported by this backend".to_string(),
        ))
    }

    /// Bulk-write validator records with a SINGLE flush at the end (#56).
    ///
    /// Mirrors `put_identity_metadata_batch`: the migration would otherwise pay
    /// O(n) fsyncs via per-record direct writes. Default falls back to the
    /// per-record direct write so unspecialised backends still function.
    fn put_validator_record_batch(
        &self,
        records: &[([u8; 32], StoredValidatorRecord)],
    ) -> StorageResult<usize> {
        let mut written = 0usize;
        for (did_hash, record) in records {
            self.put_validator_record_direct(did_hash, record)?;
            written += 1;
        }
        Ok(written)
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

    /// Open a write batch for supplementary metadata (identity/wallet/entity index data)
    /// produced by the legacy processing path when BlockExecutor is active.
    ///
    /// Unlike `begin_block`, does NOT validate or advance `latest_height`. Safe to call
    /// immediately after the executor's `commit_block` for the same block height.
    fn begin_metadata_write(&self) -> StorageResult<()>;

    /// Commit a metadata-only batch opened with `begin_metadata_write`.
    /// Applies identity/wallet index writes without updating `latest_height`.
    fn commit_metadata_write(&self) -> StorageResult<()>;

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

    // =========================================================================
    // Bonding Curve Storage (SOV Tokenomics)
    // =========================================================================
    // Bonding curve tokens are stored separately from regular tokens.
    // Each token has a lifecycle: Curve -> Graduated -> AMM
    // =========================================================================

    /// Get a bonding curve token by its ID.
    ///
    /// Returns None if no bonding curve token exists with that ID.
    fn get_bonding_curve_token(
        &self,
        token_id: &TokenId,
    ) -> StorageResult<Option<crate::contracts::bonding_curve::BondingCurveToken>>;

    /// Store a bonding curve token.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_bonding_curve_token(
        &self,
        token_id: &TokenId,
        token: &crate::contracts::bonding_curve::BondingCurveToken,
    ) -> StorageResult<()>;

    /// Delete a bonding curve token.
    ///
    /// Called when token graduates to AMM (migrated to AMM pool).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_bonding_curve_token(&self, token_id: &TokenId) -> StorageResult<()>;

    /// Iterate over all bonding curve tokens.
    ///
    /// Returns an iterator of (TokenId, BondingCurveToken) pairs.
    fn iter_bonding_curve_tokens(
        &self,
    ) -> StorageResult<
        Box<
            dyn Iterator<Item = (TokenId, crate::contracts::bonding_curve::BondingCurveToken)> + '_,
        >,
    >;

    /// Get bonding curve token ID by symbol (secondary index).
    ///
    /// Returns the token ID for the token with this symbol.
    fn get_bonding_curve_by_symbol(&self, symbol: &str) -> StorageResult<Option<TokenId>> {
        // Default implementation returns None (requires secondary index)
        let _ = symbol;
        Ok(None)
    }

    /// Store symbol → token_id index entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_bonding_curve_symbol_index(
        &self,
        symbol: &str,
        token_id: &TokenId,
    ) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = (symbol, token_id);
        Ok(())
    }

    /// Delete symbol → token_id index entry.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_bonding_curve_symbol_index(&self, symbol: &str) -> StorageResult<()> {
        // Default implementation is a no-op
        let _ = symbol;
        Ok(())
    }

    // =========================================================================
    // Canonical CBE Curve State (#1926)
    // =========================================================================
    // Single global EconomicState + per-sender AccountState.
    // These are the authoritative persistence records for the canonical CBE
    // curve execution lane.  All other curve state (BondingCurveToken, etc.)
    // is legacy and must not be used as the source of truth for canonical
    // curve economics.
    // =========================================================================

    /// Load the global canonical CBE economic state.
    ///
    /// Returns a zero-initialised default when no state has been persisted yet
    /// (first transaction on a fresh chain).
    fn get_cbe_economic_state(&self) -> StorageResult<lib_types::BondingCurveEconomicState>;

    /// Persist the global canonical CBE economic state.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_cbe_economic_state(
        &self,
        state: &lib_types::BondingCurveEconomicState,
    ) -> StorageResult<()>;

    /// Load the CBE account state for `key_id`.
    ///
    /// Returns `None` if no account exists yet (new participant with zero
    /// balances and nonce = 0).
    fn get_cbe_account_state(
        &self,
        key_id: &[u8; 32],
    ) -> StorageResult<Option<lib_types::BondingCurveAccountState>>;

    /// Persist the CBE account state for `key_id`.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_cbe_account_state(
        &self,
        key_id: &[u8; 32],
        state: &lib_types::BondingCurveAccountState,
    ) -> StorageResult<()>;


    // =========================================================================
    // BFT Quorum Proof Operations (default no-ops for non-sled backends)
    // =========================================================================

    /// Store a BFT quorum proof for a given block height.
    fn put_quorum_proof(
        &self,
        _height: u64,
        _proof: &lib_types::consensus::BftQuorumProof,
    ) -> StorageResult<()> {
        Ok(())
    }

    /// Retrieve the BFT quorum proof for a given block height.
    fn get_quorum_proof(
        &self,
        _height: u64,
    ) -> StorageResult<Option<lib_types::consensus::BftQuorumProof>> {
        Ok(None)
    }

    // =========================================================================
    // DAO Stake Operations (default no-ops for non-sled backends)
    // =========================================================================

    /// Retrieve the stake record for `(sector_dao_key_id, staker)`, if any.
    fn get_dao_stake(
        &self,
        _sector_dao_key_id: &[u8; 32],
        _staker: &[u8; 32],
    ) -> StorageResult<Option<DaoStakeRecord>> {
        Ok(None)
    }

    /// Persist (upsert) a DAO stake record within the current block transaction.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_dao_stake(&self, _record: &DaoStakeRecord) -> StorageResult<()> {
        Ok(())
    }

    /// Delete a DAO stake record within the current block transaction.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_dao_stake(
        &self,
        _sector_dao_key_id: &[u8; 32],
        _staker: &[u8; 32],
    ) -> StorageResult<()> {
        Ok(())
    }

    /// Iterate all stake records for a given DAO wallet.
    fn iter_dao_stakes_for_dao(
        &self,
        _sector_dao_key_id: &[u8; 32],
    ) -> StorageResult<Vec<DaoStakeRecord>> {
        Ok(vec![])
    }

    // =========================================================================
    // Observer Admission Operations (default no-ops for non-sled backends)
    // =========================================================================

    /// Retrieve an observer admission record by node DID hash.
    ///
    /// `did_hash` is `blake3(observer_node_did_string)`.
    fn get_observer_record(
        &self,
        _did_hash: &[u8; 32],
    ) -> StorageResult<Option<lib_types::ObserverAdmissionRecord>> {
        Ok(None)
    }

    /// Persist (upsert) an observer admission record within the current block transaction.
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn put_observer_record(
        &self,
        _did_hash: &[u8; 32],
        _record: &lib_types::ObserverAdmissionRecord,
    ) -> StorageResult<()> {
        Ok(())
    }

    /// Delete an observer admission record within the current block transaction.
    ///
    /// Used when a record is superseded (currently unused, reserved for future purge).
    ///
    /// # Requirements
    /// - MUST be called within begin_block/commit_block
    fn delete_observer_record(&self, _did_hash: &[u8; 32]) -> StorageResult<()> {
        Ok(())
    }

    /// Iterate every observer admission record currently in the registry.
    ///
    /// Used by read endpoints (admission-6) and policy/quota evaluation (admission-4)
    /// that need to enumerate the canonical set of admitted observers.
    fn iter_observer_records(&self) -> StorageResult<Vec<lib_types::ObserverAdmissionRecord>> {
        Ok(vec![])
    }

    /// Iterate every observer admission record sponsored by the given user DID hash.
    ///
    /// `sponsor_did_hash` is `blake3(sponsoring_user_did_string)`. Implementations
    /// MAY use a secondary index; the default implementation filters via
    /// `iter_observer_records`.
    fn iter_observer_records_for_sponsor(
        &self,
        sponsor_did_hash: &[u8; 32],
    ) -> StorageResult<Vec<lib_types::ObserverAdmissionRecord>> {
        let all = self.iter_observer_records()?;
        Ok(all
            .into_iter()
            .filter(|r| {
                let h = crate::storage::did_to_hash(&r.sponsor.sponsoring_user_did);
                &h == sponsor_did_hash
            })
            .collect())
    }

    /// Retrieve the canonical observer admission policy.
    ///
    /// Returns `None` if no policy has been seeded yet (callers should treat
    /// this as "genesis not yet bootstrapped" and fall back to
    /// `crate::observer::default_policy()`).
    fn get_observer_policy(
        &self,
    ) -> StorageResult<Option<lib_types::ObserverAdmissionPolicy>> {
        Ok(None)
    }

    /// Persist the canonical observer admission policy.
    ///
    /// This is a metadata write — like `save_oracle_state`, it does not
    /// require an active block transaction. Governance/genesis bootstrap
    /// calls it directly.
    fn save_observer_policy(
        &self,
        _policy: &lib_types::ObserverAdmissionPolicy,
    ) -> StorageResult<()> {
        Ok(())
    }

    // =========================================================================
    // Generic Table Access (blockchain-state-tiering epic, BST-101)
    // =========================================================================
    // Object-safe byte-level primitives. The typed, generic API is layered on
    // top by the `TableAccess` extension trait — see `storage::table`. A
    // dataset declares one `impl Table` instead of a bespoke get/put/delete/
    // iter method quadruple.
    //
    // Default impls error: a store that has not opted into generic table
    // access does not support it. `SledStore` overrides all three.
    // =========================================================================

    /// Read a raw value from keyspace `tree`.
    fn get_raw(&self, _tree: &'static str, _key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        Err(StorageError::Database(
            "generic table access not supported by this store".to_string(),
        ))
    }

    /// Stage a raw write (`Some` = insert, `None` = delete) into keyspace
    /// `tree`. MUST be called within `begin_block`/`commit_block`.
    fn stage_raw(
        &self,
        _tree: &'static str,
        _key: &[u8],
        _value: Option<&[u8]>,
    ) -> StorageResult<()> {
        Err(StorageError::Database(
            "generic table access not supported by this store".to_string(),
        ))
    }

    /// Iterate every `(key, value)` pair in keyspace `tree`.
    #[allow(clippy::type_complexity)]
    fn iter_raw(
        &self,
        _tree: &'static str,
    ) -> StorageResult<Box<dyn Iterator<Item = StorageResult<(Vec<u8>, Vec<u8>)>> + '_>> {
        Err(StorageError::Database(
            "generic table access not supported by this store".to_string(),
        ))
    }

    // =========================================================================
    // Fork audit log (BST-203)
    // =========================================================================
    // Fork points are recorded during reorgs, which are NOT block commits —
    // there is no open block transaction. So they use direct durable writes,
    // not the block batch. Audit data, not consensus state.

    /// Durably record a fork point, keyed by height.
    fn put_fork_point(
        &self,
        _height: u64,
        _fork_point: &crate::fork_recovery::ForkPoint,
    ) -> StorageResult<()> {
        Err(StorageError::Database(
            "fork point persistence not supported by this store".to_string(),
        ))
    }

    /// All recorded fork points, ascending by height.
    fn iter_fork_points(&self) -> StorageResult<Vec<crate::fork_recovery::ForkPoint>> {
        Ok(Vec::new())
    }

    // =========================================================================
    // Transaction receipts (BST-201) — direct durable writes
    // =========================================================================
    // Receipts are created after the block transaction has committed, so they
    // use direct writes, not the block batch. They are rebuildable from blocks,
    // so per-receipt fsync is not required — sled flushes on its own cadence.

    /// Store a transaction receipt, keyed by transaction hash.
    fn put_receipt(&self, _receipt: &crate::receipts::TransactionReceipt) -> StorageResult<()> {
        Err(StorageError::Database(
            "receipt persistence not supported by this store".to_string(),
        ))
    }

    /// Fetch a transaction receipt by transaction hash.
    fn get_receipt(
        &self,
        _tx_hash: &[u8; 32],
    ) -> StorageResult<Option<crate::receipts::TransactionReceipt>> {
        Ok(None)
    }
}
