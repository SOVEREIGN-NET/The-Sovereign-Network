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
//! | `version` | Protocol version metadata; not part of the canonical header hash |
//! | `previous_hash` | Links this block to its parent; enforces chain continuity |
//! | `data_helix_root` | Commits to the complete, ordered set of transactions |
//! | `verification_helix_root` | Commits to verification artifacts (zero until Sprint 6) |
//! | `state_root` | Commits to the complete world state after executing this block |
//! | `bft_quorum_root` | Commits to the finalized quorum attestations |
//! | `timestamp` | Wall-clock time of block production (consensus-validated range) |
//! | `height` | Canonical position of this block in the chain |
//!
//! ## Informational Fields (NOT included in block hash)
//!
//! These fields are stored for convenience but do not affect the canonical block hash.
//! They may be recalculated or verified independently:
//!
//! | Field | Purpose |
//! |-------|---------|
//! | `block_hash` | Cached result of `calculate_hash()`; not an input to itself |
//! | `version` | Protocol version metadata and upgrade signalling |
//!
//! ## State Root Commitment
//!
//! The `state_root` is a single 32-byte BLAKE3 hash that cryptographically commits
//! to the **complete world state** after executing all transactions in the block.
//! The world state is UTXO-based (see [`crate::blockchain::STATE_MODEL`]) and
//! consists of four components plus the canonical bonding-curve placeholders:
//!
//! 1. **UTXO set** — all unspent transaction outputs after this block
//! 2. **Identity registry** — all on-chain DID records after this block
//! 3. **Wallet registry** — all on-chain wallet descriptors after this block
//! 4. **Contract state** — execution state of all deployed smart contracts after this block
//! 5. **Bonding curve state placeholders** — five zero-filled `u128` values until Sprint 4

use crate::transaction::Transaction;
use crate::types::{Difficulty, Hash};
use serde::{Deserialize, Serialize};

// ============================================================================
// GENESIS TRUST MODEL
// ============================================================================
//
// The genesis block is the singular root of trust for the entire ZHTP
// blockchain. Unlike every subsequent block — which is verified by BFT
// consensus and cryptographic proofs — the genesis block cannot be
// self-referentially verified: there is no prior state against which to
// check it. Its legitimacy therefore rests on *social consensus* among
// the founding participants.
//
// ## Trust Model: "social-consensus"
//
// `GENESIS_TRUST_MODEL = "social-consensus"` captures this explicitly:
//
//   - The genesis block parameters (hash, timestamp, validator set, initial
//     allocations, protocol version) are published out-of-band — in
//     documentation, announcements, and open-source code — before the
//     network launches.
//
//   - Any node operator who chooses to join the network implicitly accepts
//     these published parameters. This acceptance IS the social consensus.
//
//   - There is NO cryptographic proof that the genesis block is "correct"
//     in an absolute sense. Correctness is defined by community agreement.
//
// ## Initial Validator Set as Root of Trust
//
// The initial validator set is embedded in (or derived from) the genesis
// block. It forms the *cryptographic* root of trust for all subsequent
// consensus rounds:
//
//   - BFT quorum certificates for blocks 1, 2, … are verified against the
//     public keys of the initial validators.
//   - Validator set changes after genesis are themselves subject to BFT
//     approval, so the chain of cryptographic trust traces back to the
//     genesis validator set.
//   - Compromising the initial validator set would allow forging all
//     subsequent blocks; therefore the genesis validator set must be
//     chosen with the highest care and published via multiple independent
//     channels before launch.
//
// ## Subsequent Blocks: BFT Verification
//
// From block 1 onwards, every block MUST carry a valid BFT quorum
// certificate (QC) signed by at least 2/3+1 of the current voting stake.
// The QC is verified algorithmically — no social trust is required. This
// is the boundary between social-consensus trust (genesis only) and
// cryptographic trust (all other blocks).
//
// ## Implications for Node Operators
//
//   1. When bootstrapping a new node, ALWAYS verify the genesis block hash
//      against the canonical value published in the project documentation
//      and source code. A mismatch means the node is on a different (and
//      potentially adversarial) chain.
//
//   2. The genesis block MUST NOT be downloaded from peers. It MUST be
//      constructed locally from hardcoded parameters so that peer nodes
//      cannot substitute a forged genesis.
//
//   3. If the community ever decides to hard-fork, the new genesis hash
//      must be agreed upon and published via the same social-consensus
//      process described here. There is no in-protocol mechanism for
//      replacing the genesis trust anchor.
//
// See `GENESIS_TRUST_MODEL` constant and `assert_genesis_trust_model`
// function below for the programmatic expression of these assumptions.
// ============================================================================

/// Genesis trust model identifier.
///
/// The value `"social-consensus"` captures that the genesis block is trusted
/// by agreement among network participants rather than by cryptographic proof.
/// This constant is intentionally a `&str` so it can appear in logs, config
/// comparisons, and error messages without additional dependencies.
///
/// All software that constructs or validates the genesis block SHOULD assert
/// that this value equals `"social-consensus"` to make the trust assumption
/// explicit and visible in code review.
pub const GENESIS_TRUST_MODEL: &str = "social-consensus";

/// Assert that the genesis trust model constant has its expected value.
///
/// Call this during node initialisation or in tests to make the trust
/// assumption visible and to catch any accidental modification.
///
/// # Panics
///
/// Panics if `GENESIS_TRUST_MODEL` has been changed from `"social-consensus"`.
pub fn assert_genesis_trust_model() {
    assert_eq!(
        GENESIS_TRUST_MODEL, "social-consensus",
        "GENESIS TRUST MODEL VIOLATED: GENESIS_TRUST_MODEL must be \
         \"social-consensus\" — the genesis block is trusted by community \
         agreement, not by cryptographic proof"
    );
}

// ============================================================================
// GENESIS VALIDATOR SNAPSHOT (BFT-G, Issue #1001)
// ============================================================================

/// Canonical description of the genesis validator snapshot.
///
/// The genesis block defines the initial validator set and state commitments
/// for the entire network.  All nodes MUST verify these values at startup to
/// ensure they share the same trust root.
///
/// # Invariants
///
/// - `height` MUST be `0`.
/// - `validator_count` MUST be `> 0`.
/// - `state_commitment` is the BLAKE3 hash of the initial world state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisValidatorSnapshot {
    /// Block height — always 0 for genesis.
    pub height: u64,
    /// Number of validators at genesis.
    pub validator_count: usize,
    /// BLAKE3 commitment to the initial state (UTXO + identity + wallet).
    pub state_commitment: [u8; 32],
}

impl GenesisValidatorSnapshot {
    /// Creates a snapshot, panicking if invariants are violated.
    pub fn new(height: u64, validator_count: usize, state_commitment: [u8; 32]) -> Self {
        assert_eq!(height, 0, "genesis snapshot height must be 0, got {height}");
        assert!(
            validator_count > 0,
            "genesis must have at least one validator"
        );
        Self {
            height,
            validator_count,
            state_commitment,
        }
    }
}

/// Validates a genesis block against an explicit validator snapshot.
///
/// Returns `Ok(())` if all genesis invariants hold, or `Err` on the first failure.
pub fn validate_genesis_snapshot(
    block: &Block,
    snapshot: &GenesisValidatorSnapshot,
) -> Result<(), String> {
    if block.header.height != 0 {
        return Err(format!(
            "genesis block height must be 0, got {}",
            block.header.height
        ));
    }
    if snapshot.validator_count == 0 {
        return Err("genesis validator snapshot must contain at least one validator".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod genesis_snapshot_tests {
    use super::*;

    #[test]
    fn test_validate_genesis_snapshot_ok() {
        let block = create_genesis_block();
        let snapshot = GenesisValidatorSnapshot::new(0, 4, [0u8; 32]);
        assert!(validate_genesis_snapshot(&block, &snapshot).is_ok());
    }

    #[test]
    fn test_validate_genesis_snapshot_rejects_nonzero_height() {
        let mut block = create_genesis_block();
        block.header.height = 1;
        let snapshot = GenesisValidatorSnapshot::new(0, 1, [0u8; 32]);
        assert!(validate_genesis_snapshot(&block, &snapshot).is_err());
    }
}

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

/// Block header with consensus and metadata information.
///
/// # Field Classification
///
/// See the module-level documentation for the full breakdown of which fields are
/// consensus-critical (hashed) vs informational (not hashed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version.
    ///
    /// Informational metadata. The canonical Sprint 2 block hash no longer
    /// commits to version bytes.
    #[serde(default = "default_block_version")]
    pub version: u32,

    /// Hash of the parent block.
    #[serde(alias = "previous_block_hash")]
    pub previous_hash: [u8; 32],

    /// Root of the ordered block data helix (currently the transaction Merkle root).
    #[serde(alias = "merkle_root")]
    pub data_helix_root: [u8; 32],

    /// UNIX timestamp (seconds since epoch) of block production.
    pub timestamp: u64,

    /// Zero-based block height in the canonical chain.
    pub height: u64,

    /// Root of the verification helix. Zero until Sprint 6.
    #[serde(default)]
    pub verification_helix_root: [u8; 32],

    /// Cryptographic commitment to the full world state after this block.
    #[serde(default)]
    pub state_root: [u8; 32],

    /// BLAKE3 root over the finalized BFT quorum attestations.
    #[serde(default)]
    pub bft_quorum_root: [u8; 32],

    /// Cached block hash (result of `calculate_hash()`).
    pub block_hash: Hash,
}

fn default_block_version() -> u32 {
    1
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
        Hash::new(self.header.previous_hash)
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Legacy PoW difficulty is retired. Returns the minimum sentinel.
    pub fn difficulty(&self) -> Difficulty {
        Difficulty::minimum()
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
        self.header.height == 0 && self.header.previous_hash == [0u8; 32]
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
        let calculated_root =
            crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions);
        let matches = calculated_root.as_array() == self.header.data_helix_root;
        if !matches {
            tracing::warn!(
                "Merkle root mismatch at height {}: calculated={}, stored={}transactions_count={}",
                self.height(),
                hex::encode(calculated_root.as_bytes()),
                hex::encode(self.header.data_helix_root),
                self.transactions.len()
            );
        }
        matches
    }

    /// Legacy PoW validation is retired in Sprint 2.
    pub fn meets_difficulty_target(&self) -> bool {
        true
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
        self.header.version > 0 && self.header.timestamp > 0
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
        previous_hash: Hash,
        data_helix_root: Hash,
        timestamp: u64,
        height: u64,
    ) -> Self {
        let mut header = Self {
            version,
            previous_hash: previous_hash.as_array(),
            data_helix_root: data_helix_root.as_array(),
            timestamp,
            height,
            verification_helix_root: [0u8; 32],
            state_root: [0u8; 32],
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        };

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
        self.state_root = state_root.as_array();
        self.block_hash = self.calculate_hash();
    }

    /// Update the verification helix root and recompute the cached block hash.
    pub fn set_verification_helix_root(&mut self, root: [u8; 32]) {
        self.verification_helix_root = root;
        self.block_hash = self.calculate_hash();
    }

    /// Update the BFT quorum root and recompute the cached block hash.
    pub fn set_bft_quorum_root(&mut self, root: [u8; 32]) {
        self.bft_quorum_root = root;
        self.block_hash = self.calculate_hash();
    }

    /// Calculate the hash of this block header
    pub fn calculate_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.previous_hash);
        hasher.update(&self.data_helix_root);
        hasher.update(&self.verification_helix_root);
        hasher.update(&self.state_root);
        hasher.update(&self.bft_quorum_root);

        Hash::from_slice(hasher.finalize().as_bytes())
    }

    /// Get the block hash
    pub fn hash(&self) -> Hash {
        self.block_hash
    }

    /// Legacy PoW verification is retired in Sprint 2.
    pub fn meets_difficulty_target(&self) -> bool {
        true
    }

    /// Legacy PoW target access is retired in Sprint 2.
    pub fn target(&self) -> [u8; 32] {
        [0u8; 32]
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

    /// Check if timestamp is reasonable (relative to previous block)
    ///
    /// REMOVED: Wall-clock validation (nondeterministic)
    /// Block timestamps are validated relative to previous blocks during consensus,
    /// not against wall-clock time. This ensures deterministic validation across all nodes.
    pub fn has_reasonable_timestamp(&self) -> bool {
        // Block timestamp validation is now handled in consensus validation
        // where previous block timestamps are available for comparison
        self.timestamp > 0
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
    // Test-only genesis timestamp (2024-11-01T00:00:00Z = 1730419200).
    // NOTE: This function is used by unit tests only. Production genesis is built
    // via GenesisConfig::build_block0() which reads the timestamp from genesis.toml
    // (currently "2025-11-01T00:00:00Z" = 1761955200).
    let genesis_timestamp = 1730419200u64;
    let header = BlockHeader::new(
        1,               // version
        Hash::default(), // previous_hash (none for genesis)
        Hash::default(), // data_helix_root (will be calculated)
        genesis_timestamp,
        0,                  // height
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
            0,
        );

        // version
        let mut h = base.clone();
        h.version = 2;
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "version must affect hash"
        );

        // previous_hash
        let mut h = base.clone();
        h.previous_hash = [1u8; 32];
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "previous_hash must affect hash"
        );

        // data_helix_root
        let mut h = base.clone();
        h.data_helix_root = [2u8; 32];
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "data_helix_root must affect hash"
        );

        // timestamp
        let mut h = base.clone();
        h.timestamp = 2_000_000;
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "timestamp must affect hash"
        );

        // verification_helix_root
        let mut h = base.clone();
        h.verification_helix_root = [3u8; 32];
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "verification_helix_root must affect hash"
        );

        // state_root
        let mut h = base.clone();
        h.state_root = [4u8; 32];
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "state_root must affect hash"
        );

        // height
        let mut h = base.clone();
        h.height = 1;
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "height must affect hash"
        );

        // bft_quorum_root
        let mut h = base.clone();
        h.bft_quorum_root = [5u8; 32];
        h.block_hash = h.calculate_hash();
        assert_ne!(
            base.calculate_hash(),
            h.calculate_hash(),
            "bft_quorum_root must affect hash"
        );

        // block_hash itself must NOT affect hash calculation (it is the output, not an input)
        let mut h = base.clone();
        h.block_hash = Hash::from_slice(&[3u8; 32]);
        assert_eq!(
            base.calculate_hash(),
            h.calculate_hash(),
            "block_hash is the output and must NOT affect hash calculation"
        );
    }

}

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
            0,
        );
        assert_eq!(
            header.state_root,
            [0u8; 32],
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
            1, // height > 0 so genesis exemption does not apply
        );
        let expected = Hash::from_slice(&[0xab; 32]);
        header.set_state_root(expected);
        assert_eq!(header.state_root, expected.as_array());
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
