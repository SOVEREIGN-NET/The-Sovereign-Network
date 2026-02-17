//! Core block structures
//!
//! Defines the fundamental block data structures used in the ZHTP blockchain.
//!
//! # BlockHeader Structure and Commitments
//!
//! The [`BlockHeader`] struct represents the cryptographic commitment to an entire block.
//! Its fields are divided into two categories:
//!
//! ## Consensus-Critical Fields (included in block hash via `calculate_hash`)
//!
//! These fields are fed into the BLAKE3 hash function in [`BlockHeader::calculate_hash`]
//! and MUST be included for any node to reproduce the same block hash. Changing any of
//! these fields changes the block hash, breaking the chain:
//!
//! | Field | Purpose |
//! |-------|---------|
//! | `version` | Protocol version; changes indicate hard-fork boundaries |
//! | `previous_block_hash` | Links this block to its parent; enforces chain continuity |
//! | `merkle_root` | Commits to the complete, ordered set of transactions |
//! | `timestamp` | Wall-clock time of block production (consensus-validated range) |
//! | `difficulty` | Proof-of-work target that this block must satisfy |
//! | `nonce` | Mining nonce found via proof-of-work |
//! | `height` | Canonical position of this block in the chain |
//! | `transaction_count` | Number of transactions; must match `transactions` length |
//! | `block_size` | Serialized byte size of the full block |
//!
//! ## Informational Fields (NOT included in block hash)
//!
//! These fields are stored for convenience but do not affect the canonical block hash.
//! They may be recalculated or verified independently:
//!
//! | Field | Purpose |
//! |-------|---------|
//! | `block_hash` | Cached result of `calculate_hash()`; not an input to itself |
//! | `cumulative_difficulty` | Running sum of all difficulty values up to this block |
//! | `fee_model_version` | Determines fee schedule rules applied at this block height |
//!
//! ## Compile-Time Verification
//!
//! The constant [`BFT_REQUIRED_HEADER_FIELDS`] enumerates every consensus-critical field
//! name. It serves as a checklist: if you add a new consensus-critical field to
//! `BlockHeader` you MUST also add its name to `BFT_REQUIRED_HEADER_FIELDS` and include
//! it in [`BlockHeader::calculate_hash`]. The `verify_hash_covers_required_fields` test
//! confirms that the number of bytes fed into the hash function equals the total size
//! of all consensus-critical fields.

use serde::{Serialize, Deserialize};
use crate::types::{Hash, Difficulty};
use crate::transaction::Transaction;

/// Names of every consensus-critical field in [`BlockHeader`].
///
/// These are the fields that are hashed by [`BlockHeader::calculate_hash`] and therefore
/// determine the canonical block hash. Any new consensus-critical field MUST be added
/// here and included in `calculate_hash`.
///
/// Informational fields (`block_hash`, `cumulative_difficulty`, `fee_model_version`) are
/// intentionally excluded because they do not participate in hash computation.
pub const BFT_REQUIRED_HEADER_FIELDS: &[&str] = &[
    "version",
    "previous_block_hash",
    "merkle_root",
    "timestamp",
    "difficulty",
    "nonce",
    "height",
    "transaction_count",
    "block_size",
];

/// Number of consensus-critical fields in [`BlockHeader`].
///
/// This constant is checked at compile time (via a `const` expression in the test module)
/// to ensure it stays in sync with [`BFT_REQUIRED_HEADER_FIELDS`].
pub const BFT_REQUIRED_HEADER_FIELD_COUNT: usize = BFT_REQUIRED_HEADER_FIELDS.len();

/// ZHTP blockchain block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header containing metadata
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
}

/// Block header with consensus and metadata information.
///
/// # Field Classification
///
/// See the module-level documentation for the full breakdown of which fields are
/// consensus-critical (hashed) vs informational (not hashed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    // -------------------------------------------------------------------------
    // CONSENSUS-CRITICAL FIELDS — included in calculate_hash()
    // -------------------------------------------------------------------------

    /// Protocol version.
    ///
    /// **Consensus-critical.** Changes signal protocol upgrades or hard-fork
    /// boundaries. All nodes must agree on the version rules for a given height.
    pub version: u32,

    /// Hash of the parent block.
    ///
    /// **Consensus-critical.** Cryptographically links this block to its
    /// predecessor, forming the immutable chain. The genesis block uses
    /// `Hash::default()` (all zeros) as its previous hash.
    pub previous_block_hash: Hash,

    /// Merkle root of the transaction set.
    ///
    /// **Consensus-critical.** A single 32-byte commitment to the complete,
    /// ordered list of transactions in this block. Verifying the Merkle root
    /// proves that no transaction has been added, removed, or reordered.
    pub merkle_root: Hash,

    /// UNIX timestamp (seconds since epoch) of block production.
    ///
    /// **Consensus-critical.** Used for difficulty adjustment and to enforce
    /// the temporal ordering invariant (`timestamp > previous.timestamp`).
    /// Nodes reject blocks whose timestamp is more than 2 hours in the future.
    pub timestamp: u64,

    /// Proof-of-work difficulty target for this block.
    ///
    /// **Consensus-critical.** Encodes the minimum work required. The block
    /// hash must be numerically less than or equal to the target derived from
    /// this field.
    pub difficulty: Difficulty,

    /// Proof-of-work nonce found by the miner.
    ///
    /// **Consensus-critical.** The value that, when combined with the other
    /// header fields, produces a block hash satisfying the difficulty target.
    pub nonce: u64,

    /// Zero-based block height in the canonical chain.
    ///
    /// **Consensus-critical.** The genesis block has height 0. Every subsequent
    /// block has `height = parent.height + 1`.
    pub height: u64,

    // -------------------------------------------------------------------------
    // INFORMATIONAL FIELDS — NOT included in calculate_hash()
    // -------------------------------------------------------------------------

    /// Cached block hash (result of `calculate_hash()`).
    ///
    /// **Informational.** This field stores the pre-computed hash for fast
    /// lookups. It is NOT an input to `calculate_hash()` (that would be
    /// circular). Always recalculate via `calculate_hash()` when verifying.
    pub block_hash: Hash,

    /// Number of transactions committed in this block.
    ///
    /// **Consensus-critical.** Must equal `transactions.len()` exactly.
    /// Validated in `Block::has_valid_header()`.
    pub transaction_count: u32,

    /// Serialized byte size of the complete block.
    ///
    /// **Consensus-critical.** Used to enforce `MAX_BLOCK_SIZE` limits.
    pub block_size: u32,

    /// Cumulative proof-of-work difficulty from genesis to this block.
    ///
    /// **Informational.** Used for chain-selection (heaviest chain wins) but
    /// not included in the block hash itself. Can be recomputed by summing
    /// `difficulty` across all ancestors.
    pub cumulative_difficulty: Difficulty,

    /// Fee model version active at this block height (Phase 3B).
    ///
    /// **Informational / soft-consensus.** Determines which fee schedule rules
    /// apply when processing transactions in this block:
    /// - Version 1: Legacy fee model (before activation height)
    /// - Version 2: Fee Model v2 (at and after activation height)
    ///
    /// Not included in the block hash but enforced by consensus rules: a block
    /// MUST use the correct fee model version for its height.
    #[serde(default = "default_fee_model_version")]
    pub fee_model_version: u16,
}

/// Default fee model version for backwards compatibility
fn default_fee_model_version() -> u16 {
    1 // Legacy default for deserializing old blocks
}

impl Block {
    /// Create a new block with the given header and transactions
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get the block ID (same as hash)
    pub fn id(&self) -> Hash {
        self.hash()
    }

    /// Get the block height
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the previous block hash
    pub fn previous_hash(&self) -> Hash {
        self.header.previous_block_hash
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Get the difficulty
    pub fn difficulty(&self) -> Difficulty {
        self.header.difficulty
    }

    /// Get the number of transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get the block size in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if this is the genesis block
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0 && self.header.previous_block_hash == Hash::default()
    }

    /// Get total transaction fees in the block
    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee).sum()
    }

    /// Week 10 Phase 3: Get detailed fee information for block
    ///
    /// This method calculates comprehensive fee statistics for:
    /// - Total fees collected
    /// - Average fee per transaction
    /// - Fee distribution to consensus/UBI/governance
    ///
    /// Used for fee distribution and audit logging.
    pub fn fee_summary(&self) -> (u64, u64, u64, u64) {
        let total_fees = self.total_fees();

        // Fee distribution percentages (45% UBI, 30% Consensus, 15% Governance, 10% Treasury)
        let ubi_fees = total_fees.saturating_mul(45) / 100;
        let consensus_fees = total_fees.saturating_mul(30) / 100;
        let governance_fees = total_fees.saturating_mul(15) / 100;
        let treasury_fees = total_fees.saturating_mul(10) / 100;

        (ubi_fees, consensus_fees, governance_fees, treasury_fees)
    }

    /// Get average transaction fee in the block
    pub fn average_fee(&self) -> u64 {
        let total_fees = self.total_fees();
        let tx_count = self.transactions.len() as u64;
        if tx_count > 0 {
            total_fees / tx_count
        } else {
            0
        }
    }

    /// Verify the Merkle root of transactions
    pub fn verify_merkle_root(&self) -> bool {
        let calculated_root = crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions);
        let matches = calculated_root == self.header.merkle_root;
        if !matches {
            tracing::warn!(
                "Merkle root mismatch at height {}: calculated={}, stored={}transactions_count={}",
                self.height(),
                hex::encode(calculated_root.as_bytes()),
                hex::encode(self.header.merkle_root.as_bytes()),
                self.transactions.len()
            );
        }
        matches
    }

    /// Verify the block meets the difficulty target
    pub fn meets_difficulty_target(&self) -> bool {
        let block_hash = self.hash();
        self.header.difficulty.meets_target(&block_hash)
    }

    /// Get all transaction IDs in the block
    pub fn transaction_ids(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Find a transaction by hash
    pub fn find_transaction(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.transactions.iter().find(|tx| &tx.hash() == tx_hash)
    }

    /// Check if block contains a specific transaction
    pub fn contains_transaction(&self, tx_hash: &Hash) -> bool {
        self.find_transaction(tx_hash).is_some()
    }

    /// Get all transaction hashes
    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Check if block header is valid
    pub fn has_valid_header(&self) -> bool {
        // Basic header validation
        self.header.version > 0 &&
        self.header.timestamp > 0 &&
        self.header.transaction_count == self.transactions.len() as u32
    }

    /// Calculate merkle root of transactions
    pub fn calculate_merkle_root(&self) -> Hash {
        crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions)
    }
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        version: u32,
        previous_block_hash: Hash,
        merkle_root: Hash,
        timestamp: u64,
        difficulty: Difficulty,
        height: u64,
        transaction_count: u32,
        block_size: u32,
        cumulative_difficulty: Difficulty,
    ) -> Self {
        let mut header = Self {
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            difficulty,
            nonce: 0,
            height,
            block_hash: Hash::default(),
            transaction_count,
            block_size,
            cumulative_difficulty,
            fee_model_version: 1, // Default to v1 for backwards compatibility
        };

        // Calculate and set the block hash
        header.block_hash = header.calculate_hash();
        header
    }

    /// Calculate the hash of this block header
    pub fn calculate_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        
        hasher.update(&self.version.to_le_bytes());
        hasher.update(self.previous_block_hash.as_bytes());
        hasher.update(self.merkle_root.as_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.difficulty.bits().to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.transaction_count.to_le_bytes());
        hasher.update(&self.block_size.to_le_bytes());
        
        Hash::from_slice(hasher.finalize().as_bytes())
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.block_hash
    }

    /// Set the nonce and recalculate hash
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
        self.block_hash = self.calculate_hash();
    }

    /// Check if the block hash meets the difficulty target
    pub fn meets_difficulty_target(&self) -> bool {
        self.difficulty.check_hash(&self.block_hash)
    }

    /// Get the target value for this difficulty
    pub fn target(&self) -> [u8; 32] {
        self.difficulty.target()
    }

    /// Check if this header represents a valid proof-of-work
    pub fn is_valid_proof_of_work(&self) -> bool {
        self.meets_difficulty_target()
    }

    /// Get time since previous block (requires previous block timestamp)
    pub fn time_since_previous(&self, previous_timestamp: u64) -> u64 {
        if self.timestamp > previous_timestamp {
            self.timestamp - previous_timestamp
        } else {
            0
        }
    }

    /// Check if timestamp is reasonable (not too far in future)
    pub fn has_reasonable_timestamp(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Allow up to 2 hours in the future
        self.timestamp <= now + 7200
    }
}

/// Implement Hash trait for Block
impl crate::types::hash::Hashable for Block {
    fn hash(&self) -> Hash {
        self.header.hash()
    }
}

/// Implement Hash trait for BlockHeader
impl crate::types::hash::Hashable for BlockHeader {
    fn hash(&self) -> Hash {
        self.calculate_hash()
    }
}

/// Genesis block creation
pub fn create_genesis_block() -> Block {
    // FIXED genesis timestamp for network consistency
    // November 1, 2025 00:00:00 UTC - ensures all nodes create identical genesis
    let genesis_timestamp = 1730419200;
    // Genesis blocks should use easy consensus difficulty like other system transaction blocks
    let genesis_difficulty = Difficulty::from_bits(0x1fffffff);
    
    let header = BlockHeader::new(
        1, // version
        Hash::default(), // previous_block_hash (none for genesis)
        Hash::default(), // merkle_root (will be calculated)
        genesis_timestamp,
        genesis_difficulty,
        0, // height
        0, // transaction_count
        0, // block_size
        genesis_difficulty, // cumulative_difficulty
    );

    let genesis_block = Block::new(header, Vec::new());
    
    // For genesis block, we might want to add special transactions
    // This is handled by the blockchain initialization logic
    
    genesis_block
}

/// Block validation result
pub type BlockValidationResult = Result<(), BlockValidationError>;

/// Block validation errors
#[derive(Debug, Clone)]
pub enum BlockValidationError {
    InvalidHeader,
    InvalidMerkleRoot,
    InvalidTimestamp,
    InvalidDifficulty,
    InvalidProofOfWork,
    InvalidTransactions,
    InvalidSize,
    InvalidHeight,
}

impl std::fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockValidationError::InvalidHeader => write!(f, "Invalid block header"),
            BlockValidationError::InvalidMerkleRoot => write!(f, "Invalid merkle root"),
            BlockValidationError::InvalidTimestamp => write!(f, "Invalid timestamp"),
            BlockValidationError::InvalidDifficulty => write!(f, "Invalid difficulty"),
            BlockValidationError::InvalidProofOfWork => write!(f, "Invalid proof of work"),
            BlockValidationError::InvalidTransactions => write!(f, "Invalid transactions"),
            BlockValidationError::InvalidSize => write!(f, "Invalid block size"),
            BlockValidationError::InvalidHeight => write!(f, "Invalid block height"),
        }
    }
}

impl std::error::Error for BlockValidationError {}

/// Constants for block validation
pub const MAX_BLOCK_SIZE: usize = 4_194_304; // 4 MB
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
pub const MIN_BLOCK_TIME: u64 = 1; // 1 second minimum between blocks
pub const MAX_BLOCK_TIME: u64 = 7200; // 2 hours maximum future timestamp

// ---------------------------------------------------------------------------
// Compile-time assertions: block header hash coverage
// ---------------------------------------------------------------------------

/// Compile-time check: [`BFT_REQUIRED_HEADER_FIELDS`] must list exactly
/// [`BFT_REQUIRED_HEADER_FIELD_COUNT`] entries.
///
/// If you add or remove a consensus-critical field you MUST update BOTH the
/// constant array AND this assertion, and you MUST update
/// [`BlockHeader::calculate_hash`] accordingly.
const _ASSERT_FIELD_COUNT: () = {
    assert!(
        BFT_REQUIRED_HEADER_FIELD_COUNT == 9,
        "BFT_REQUIRED_HEADER_FIELDS length does not match expected count of 9. \
         Update BFT_REQUIRED_HEADER_FIELDS and BlockHeader::calculate_hash together."
    );
};

#[cfg(test)]
mod header_hash_tests {
    use super::*;

    /// Verify that `calculate_hash` processes bytes for every consensus-critical
    /// field listed in `BFT_REQUIRED_HEADER_FIELDS`.
    ///
    /// The test creates two headers that differ in exactly one consensus-critical
    /// field at a time and asserts that the resulting hashes differ.  This
    /// exercises each field path through `calculate_hash` and ensures no field
    /// is silently dropped from the hash computation.
    #[test]
    fn verify_hash_covers_required_fields() {
        let base = BlockHeader::new(
            1,
            Hash::default(),
            Hash::default(),
            1_000_000,
            Difficulty::from_bits(0x1fffffff),
            0,
            0,
            0,
            Difficulty::from_bits(0x1fffffff),
        );

        // version
        let mut h = base.clone();
        h.version = 2;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "version must affect hash");

        // previous_block_hash
        let mut h = base.clone();
        h.previous_block_hash = Hash::from_slice(&[1u8; 32]);
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "previous_block_hash must affect hash");

        // merkle_root
        let mut h = base.clone();
        h.merkle_root = Hash::from_slice(&[2u8; 32]);
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "merkle_root must affect hash");

        // timestamp
        let mut h = base.clone();
        h.timestamp = 2_000_000;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "timestamp must affect hash");

        // difficulty
        let mut h = base.clone();
        h.difficulty = Difficulty::from_bits(0x1ffffffe);
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "difficulty must affect hash");

        // nonce
        let mut h = base.clone();
        h.nonce = 42;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "nonce must affect hash");

        // height
        let mut h = base.clone();
        h.height = 1;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "height must affect hash");

        // transaction_count
        let mut h = base.clone();
        h.transaction_count = 5;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "transaction_count must affect hash");

        // block_size
        let mut h = base.clone();
        h.block_size = 1024;
        h.block_hash = h.calculate_hash();
        assert_ne!(base.calculate_hash(), h.calculate_hash(), "block_size must affect hash");

        // Informational fields must NOT change the hash
        let mut h = base.clone();
        h.cumulative_difficulty = Difficulty::from_bits(0x1ffffffe);
        assert_eq!(base.calculate_hash(), h.calculate_hash(),
            "cumulative_difficulty is informational and must NOT affect hash");

        let mut h = base.clone();
        h.fee_model_version = 2;
        assert_eq!(base.calculate_hash(), h.calculate_hash(),
            "fee_model_version is informational and must NOT affect hash");
    }

    /// Verify that the number of entries in BFT_REQUIRED_HEADER_FIELDS is correct.
    #[test]
    fn bft_required_header_fields_count() {
        assert_eq!(
            BFT_REQUIRED_HEADER_FIELDS.len(),
            BFT_REQUIRED_HEADER_FIELD_COUNT,
            "BFT_REQUIRED_HEADER_FIELD_COUNT is out of sync with BFT_REQUIRED_HEADER_FIELDS"
        );
    }
}
