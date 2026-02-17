//! Core block structures
//!
//! Defines the fundamental block data structures used in the ZHTP blockchain.

use serde::{Serialize, Deserialize};
use crate::types::{Hash, Difficulty};
use crate::transaction::Transaction;

// ============================================================================
// GENESIS_INVARIANTS
// ============================================================================
//
// The genesis block is the immutable foundation of the ZHTP blockchain. Every
// node MUST produce an identical genesis block; any divergence constitutes a
// network split. The following invariants are enforced at construction time
// and must hold for all time:
//
// 1. INITIAL VALIDATOR SET
//    The genesis block implicitly defines the initial validator set through
//    the network's social-consensus launch parameters. All BFT consensus
//    rounds after block 0 are validated against this set. The validator set
//    is recorded in the genesis state root (see invariant 3).
//
// 2. INITIAL UTXO ALLOCATIONS
//    Any pre-mine, treasury seed, or founding-allocation UTXOs are committed
//    in the genesis merkle root. The merkle root of an empty transaction list
//    is the zero hash, meaning a clean-slate genesis carries no pre-allocated
//    funds. Any non-empty allocation MUST be explicitly documented here.
//
// 3. GENESIS STATE ROOT COMMITMENT
//    The genesis block header contains a `merkle_root` field that commits to
//    the complete initial state: UTXOs, identity records, and validator
//    registrations. Verifiers MUST check that the merkle root matches the
//    independently-derived initial state before trusting any subsequent block.
//
// 4. PROTOCOL VERSION
//    The `version` field in the genesis header pins the protocol version in
//    effect at chain launch. All nodes MUST reject genesis blocks whose
//    version does not equal `GENESIS_PROTOCOL_VERSION`. Protocol upgrades are
//    signalled at higher block heights via the `fee_model_version` and future
//    upgrade-signalling fields; the genesis version never changes.
//
// 5. FIXED TIMESTAMP
//    The genesis timestamp is hardcoded to a well-known UTC instant so that
//    every node independently reconstructs the same block hash. Dynamic
//    timestamps are FORBIDDEN for the genesis block.
//
// 6. ZERO PREVIOUS HASH
//    The `previous_block_hash` of the genesis block MUST be the zero hash
//    (all bytes 0x00). Any block claiming height 0 with a non-zero previous
//    hash is invalid and MUST be rejected.
//
// See `assert_genesis_invariants` below for the runtime enforcement of these
// properties.
// ============================================================================

/// Protocol version pinned in the genesis block.
///
/// This constant is consensus-critical: nodes MUST reject any genesis block
/// whose `version` field differs from this value.
pub const GENESIS_PROTOCOL_VERSION: u32 = 1;

/// Assert that a block satisfies all genesis invariants.
///
/// This function MUST be called immediately after `create_genesis_block`
/// returns and also during chain validation whenever a block at height 0 is
/// encountered (e.g. during chain import or bootstrap).
///
/// # Panics
///
/// Panics in debug builds if any invariant is violated. In release builds the
/// assertions are elided; callers should additionally use
/// `verify_genesis_invariants` for non-panicking validation in production.
pub fn assert_genesis_invariants(block: &Block) {
    // Invariant 6: zero previous hash
    assert_eq!(
        block.header.previous_block_hash,
        Hash::default(),
        "GENESIS INVARIANT VIOLATED: previous_block_hash must be the zero hash"
    );

    // Invariant derived from invariant 6: height must be 0
    assert_eq!(
        block.header.height, 0,
        "GENESIS INVARIANT VIOLATED: genesis block height must be 0"
    );

    // Invariant 5: fixed timestamp
    assert_eq!(
        block.header.timestamp, GENESIS_FIXED_TIMESTAMP,
        "GENESIS INVARIANT VIOLATED: genesis timestamp must be the fixed launch timestamp"
    );

    // Invariant 4: protocol version
    assert_eq!(
        block.header.version, GENESIS_PROTOCOL_VERSION,
        "GENESIS INVARIANT VIOLATED: genesis block version must equal GENESIS_PROTOCOL_VERSION"
    );

    // Invariant 3: merkle root must be consistent with transaction list
    let expected_merkle = crate::transaction::hashing::calculate_transaction_merkle_root(
        &block.transactions,
    );
    assert_eq!(
        block.header.merkle_root, expected_merkle,
        "GENESIS INVARIANT VIOLATED: merkle_root does not match the genesis transaction list"
    );

    // Invariant 2: for a clean-slate genesis the merkle root is the zero hash
    // (no pre-allocated UTXOs). If pre-mine UTXOs are ever added, this assert
    // must be updated to reflect the known non-zero commitment.
    assert_eq!(
        block.transactions.len(), 0,
        "GENESIS INVARIANT VIOLATED: genesis block must contain no pre-mine transactions \
         unless explicitly documented and the merkle root updated accordingly"
    );
}

/// Non-panicking version of `assert_genesis_invariants`.
///
/// Returns `Ok(())` when all invariants hold, or an `Err` describing the
/// first violated invariant. Use this in production validation paths where
/// a panic is undesirable.
pub fn verify_genesis_invariants(block: &Block) -> Result<(), String> {
    if block.header.previous_block_hash != Hash::default() {
        return Err("previous_block_hash must be the zero hash".to_string());
    }
    if block.header.height != 0 {
        return Err("genesis block height must be 0".to_string());
    }
    if block.header.timestamp != GENESIS_FIXED_TIMESTAMP {
        return Err(format!(
            "genesis timestamp must be {} (got {})",
            GENESIS_FIXED_TIMESTAMP, block.header.timestamp
        ));
    }
    if block.header.version != GENESIS_PROTOCOL_VERSION {
        return Err(format!(
            "genesis block version must be {} (got {})",
            GENESIS_PROTOCOL_VERSION, block.header.version
        ));
    }
    let expected_merkle =
        crate::transaction::hashing::calculate_transaction_merkle_root(&block.transactions);
    if block.header.merkle_root != expected_merkle {
        return Err("merkle_root does not match the genesis transaction list".to_string());
    }
    Ok(())
}

/// Fixed UTC timestamp for the genesis block.
///
/// Aliased to `crate::GENESIS_TIMESTAMP` so that both names always refer to
/// the same value. Any change to the genesis timestamp must be made in
/// `lib-blockchain/src/lib.rs` and will be reflected here automatically.
pub const GENESIS_FIXED_TIMESTAMP: u64 = crate::GENESIS_TIMESTAMP;

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
///
/// # Genesis Contents
///
/// The genesis block produced by this function satisfies all `GENESIS_INVARIANTS`:
///
/// - **Initial validator set**: Defined by social consensus at network launch and
///   recorded implicitly through the zero-hash state root (clean slate). Validators
///   register themselves in block 1 and onwards via `ValidatorTransactionData`.
///
/// - **Initial UTXO allocations**: None. The genesis block carries an empty
///   transaction list and a zero-hash merkle root, signifying no pre-mine. Any
///   future allocation MUST be added as explicit genesis transactions AND the
///   merkle root commitment here must be updated accordingly.
///
/// - **Genesis state root commitment**: The `merkle_root` field in the returned
///   header commits to the initial state. For a clean-slate genesis this is the
///   zero hash (empty transaction list). Verifiers must independently derive this
///   commitment and reject any genesis block whose merkle root does not match.
///
/// - **Protocol version**: Pinned to `GENESIS_PROTOCOL_VERSION` (currently 1).
///   All nodes must reject genesis blocks with a differing version field.
///
/// # Invariant Checking
///
/// `assert_genesis_invariants` is called before returning so that any regression
/// that breaks the deterministic genesis construction is caught at the call site
/// in debug builds. Use `verify_genesis_invariants` for non-panicking checks in
/// production validation paths.
pub fn create_genesis_block() -> Block {
    // Use the module-level constant so there is a single source of truth.
    let genesis_timestamp = GENESIS_FIXED_TIMESTAMP;
    // Genesis blocks should use easy consensus difficulty like other system transaction blocks
    let genesis_difficulty = Difficulty::from_bits(0x1fffffff);

    // Compute the merkle root of the (empty) genesis transaction list so that
    // the state root commitment is always consistent with the actual contents.
    let genesis_transactions: Vec<crate::transaction::Transaction> = Vec::new();
    let genesis_merkle_root =
        crate::transaction::hashing::calculate_transaction_merkle_root(&genesis_transactions);

    let header = BlockHeader::new(
        GENESIS_PROTOCOL_VERSION,  // version — pinned, consensus-critical
        Hash::default(),           // previous_block_hash (none for genesis)
        genesis_merkle_root,       // merkle_root — state root commitment
        genesis_timestamp,
        genesis_difficulty,
        0,                         // height
        0,                         // transaction_count
        0,                         // block_size
        genesis_difficulty,        // cumulative_difficulty
    );

    let genesis_block = Block::new(header, genesis_transactions);

    // Enforce all genesis invariants before returning.  Any violation here
    // indicates a programming error and must be fixed before deployment.
    assert_genesis_invariants(&genesis_block);

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
