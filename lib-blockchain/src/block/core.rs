//! Core block structures
//!
//! Defines the fundamental block data structures used in the ZHTP blockchain.
//!
//! # State Root Commitment
//!
//! Every committed block carries a `state_root` in its [`BlockHeader`].  The
//! `state_root` is a single 32-byte BLAKE3 hash that cryptographically commits
//! to the **complete world state** after executing all transactions in the block.
//! The world state is UTXO-based (see [`crate::blockchain::STATE_MODEL`]) and
//! consists of four components:
//!
//! 1. **UTXO set** — all unspent transaction outputs after this block
//! 2. **Identity registry** — all on-chain DID records after this block
//! 3. **Wallet registry** — all on-chain wallet descriptors after this block
//! 4. **Contract state** — execution state of all deployed smart contracts after this block
//!
//! ## Invariant
//!
//! A block is considered *committed* (finalized by BFT consensus) only when its
//! `state_root` is non-zero.  A zero `state_root` (`Hash::default()`) indicates
//! that the block has not yet been executed or that the state transition failed.
//! The function [`assert_state_root_set`] can be called to enforce this invariant
//! in production code paths.

use serde::{Serialize, Deserialize};
use crate::types::{Hash, Difficulty};
use crate::transaction::Transaction;

/// Assert that the `state_root` of a committed block is non-zero.
///
/// Call this after executing every block that has been finalized by BFT consensus.
/// Panics in debug builds; emits a `tracing::error!` in release builds so that
/// production nodes surface the violation without crashing.
///
/// # Panics
///
/// Panics (debug) or logs an error (release) if `state_root == Hash::default()`.
#[inline]
pub fn assert_state_root_set(height: u64, state_root: &Hash) {
    if *state_root == Hash::default() {
        let msg = format!(
            "INVARIANT VIOLATION: committed block at height {} has a zero state_root. \
             state_root must be set for every committed block.",
            height
        );
        #[cfg(debug_assertions)]
        panic!("{}", msg);
        #[cfg(not(debug_assertions))]
        tracing::error!("{}", msg);
    }
}

/// ZHTP blockchain block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header containing metadata
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
}

/// Block header with consensus and metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version
    pub version: u32,
    /// Hash of the previous block
    pub previous_block_hash: Hash,
    /// Merkle root of all transactions in this block
    pub merkle_root: Hash,
    /// Block creation timestamp
    pub timestamp: u64,
    /// Current difficulty target
    pub difficulty: Difficulty,
    /// Mining nonce for proof-of-work
    pub nonce: u64,
    /// Block height in the chain
    pub height: u64,
    /// Hash of the block (calculated)
    pub block_hash: Hash,
    /// Number of transactions in the block
    pub transaction_count: u32,
    /// Total size of the block in bytes
    pub block_size: u32,
    /// Cumulative difficulty from genesis
    pub cumulative_difficulty: Difficulty,
    /// Fee model version for this block (Phase 3B)
    ///
    /// - Version 1: Legacy fee model (before activation height)
    /// - Version 2: Fee Model v2 (at and after activation height)
    ///
    /// This field is consensus-critical. A block MUST use the correct
    /// fee model version for its height per the activation rules.
    #[serde(default = "default_fee_model_version")]
    pub fee_model_version: u16,

    /// Cryptographic commitment to the full world state after this block.
    ///
    /// The `state_root` is a BLAKE3 hash over the Merkle roots of all four
    /// state components (see module-level documentation):
    ///
    /// 1. UTXO set root
    /// 2. Identity registry root
    /// 3. Wallet registry root
    /// 4. Contract state root
    ///
    /// **Invariant**: For every *committed* block (finalized by BFT), `state_root`
    /// MUST be non-zero.  A zero `state_root` (`Hash::default()`) is only valid
    /// for the genesis block before state initialization, or for blocks that are
    /// still in-flight (not yet executed).
    ///
    /// Use [`assert_state_root_set`] to enforce this invariant at commit time.
    #[serde(default)]
    pub state_root: Hash,
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
            state_root: Hash::default(), // Set via set_state_root() after execution
        };

        // Calculate and set the block hash
        header.block_hash = header.calculate_hash();
        header
    }

    /// Set the state root after block execution and verify it is non-zero.
    ///
    /// This method MUST be called after executing all transactions in the block
    /// and before the block is finalized by BFT consensus.  The `state_root`
    /// commits to the full UTXO+identity+wallet+contract world state.
    ///
    /// # Panics (debug) / Logs error (release)
    ///
    /// Panics in debug builds (or logs an error in release builds) if the
    /// provided `state_root` is `Hash::default()` (all zeros), which would
    /// indicate a failed or incomplete state transition.
    pub fn set_state_root(&mut self, state_root: Hash) {
        assert_state_root_set(self.height, &state_root);
        self.state_root = state_root;
        // Recompute the block hash after updating the state root so that
        // block_hash always reflects the finalized header contents.
        self.block_hash = self.calculate_hash();
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

#[cfg(test)]
mod state_root_tests {
    use super::*;

    /// Verify that a freshly constructed BlockHeader has a zero state_root.
    /// This reflects the invariant that state_root is set only after execution.
    #[test]
    fn new_block_header_has_zero_state_root() {
        let header = BlockHeader::new(
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
        assert_eq!(
            header.state_root,
            Hash::default(),
            "Newly created BlockHeader must have zero state_root until set_state_root() is called"
        );
    }

    /// Verify that set_state_root stores a non-zero root correctly.
    #[test]
    fn set_state_root_stores_value() {
        let mut header = BlockHeader::new(
            1,
            Hash::default(),
            Hash::default(),
            1_000_000,
            Difficulty::from_bits(0x1fffffff),
            1, // height > 0 so genesis exemption does not apply
            0,
            0,
            Difficulty::from_bits(0x1fffffff),
        );
        let expected = Hash::from_slice(&[0xab; 32]);
        header.set_state_root(expected);
        assert_eq!(header.state_root, expected);
    }

    /// Verify that assert_state_root_set panics in debug mode for the zero hash.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "INVARIANT VIOLATION")]
    fn assert_state_root_set_panics_on_zero_hash() {
        assert_state_root_set(5, &Hash::default());
    }

    /// Verify that assert_state_root_set does NOT panic for a non-zero hash.
    #[test]
    fn assert_state_root_set_ok_for_nonzero_hash() {
        // Should not panic
        assert_state_root_set(5, &Hash::from_slice(&[1u8; 32]));
    }
}
