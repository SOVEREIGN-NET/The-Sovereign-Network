//! Core block structures
//!
//! Defines the fundamental block data structures used in the ZHTP blockchain.

use serde::{Serialize, Deserialize};
use crate::types::Hash;
use crate::transaction::Transaction;

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
    /// Block height in the chain
    pub height: u64,
    /// Hash of the block (calculated)
    pub block_hash: Hash,
    /// Number of transactions in the block
    pub transaction_count: u32,
    /// Total size of the block in bytes
    pub block_size: u32,
    /// Fee model version for this block (Phase 3B)
    ///
    /// - Version 1: Legacy fee model (before activation height)
    /// - Version 2: Fee Model v2 (at and after activation height)
    ///
    /// This field is consensus-critical. A block MUST use the correct
    /// fee model version for its height per the activation rules.
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
        height: u64,
        transaction_count: u32,
        block_size: u32,
    ) -> Self {
        let mut header = Self {
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            height,
            block_hash: Hash::default(),
            transaction_count,
            block_size,
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
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.transaction_count.to_le_bytes());
        hasher.update(&self.block_size.to_le_bytes());

        Hash::from_slice(hasher.finalize().as_bytes())
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.block_hash
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

    let header = BlockHeader::new(
        1, // version
        Hash::default(), // previous_block_hash (none for genesis)
        Hash::default(), // merkle_root (will be calculated)
        genesis_timestamp,
        0, // height
        0, // transaction_count
        0, // block_size
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
