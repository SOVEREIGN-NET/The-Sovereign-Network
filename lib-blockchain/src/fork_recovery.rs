//! Fork Detection and Recovery Mechanism
//!
//! # BFT Mode: Fork-Choice is Forbidden
//!
//! **INVARIANT**: In Byzantine Fault Tolerant (BFT) consensus, fork-choice logic is
//! **completely forbidden and must never be invoked**.
//!
//! ## Why Forks Cannot Exist in BFT
//!
//! BFT consensus (specifically the Tendermint-style protocol used here) provides
//! *immediate finality*: once 2/3+1 validators have committed a block at height H,
//! that decision is irreversible. There is no scenario in which a competing block
//! at the same height can ever be valid, regardless of its length, difficulty, or
//! timestamp.
//!
//! This is fundamentally different from Nakamoto (Proof-of-Work) consensus:
//! - **PoW**: Forks are possible; resolved by longest-chain / most-work rule.
//! - **BFT**: Forks are impossible by construction (assuming < 1/3 Byzantine validators).
//!   A fork in BFT implies a safety violation and is treated as evidence of Byzantine
//!   behavior, not as a normal network condition to be resolved.
//!
//! ## What This Means for This Module
//!
//! - `ForkDetector::evaluate_chains` — **FORBIDDEN**. Calling this function is a
//!   programming error and will panic with `unreachable!`. Fork-choice must never
//!   be invoked in BFT mode.
//! - `ForkDetector::detect_fork` — Retained for **diagnostic and evidence purposes only**.
//!   If a fork is detected, it is logged as Byzantine evidence, not resolved via
//!   chain selection. The detection result should be forwarded to the equivocation
//!   evidence handler.
//! - `Blockchain::reorg_to_fork` — **FORBIDDEN**. Chain reorganization cannot occur
//!   in BFT mode. Calling this function is a programming error and will panic.
//!
//! ## Historical Note
//!
//! This module was originally written for a hybrid PoW/BFT consensus mode.
//! The fork-choice logic (`evaluate_chains`) was gutted in issue #936 when the
//! system transitioned to pure BFT mode. In issue #968, explicit `unreachable!`
//! guards were added to all fork-choice entry points to make this constraint
//! statically enforced at runtime.

use serde::{Serialize, Deserialize};
use crate::types::Hash;
use crate::block::Block;

/// Fork point record - tracks when the chain diverged
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkPoint {
    /// Block height where fork occurred
    pub height: u64,
    /// Timestamp when fork was detected
    pub detected_at: u64,
    /// Hash of original block on our chain
    pub original_block_hash: Hash,
    /// Hash of competing block from fork
    pub forked_block_hash: Hash,
    /// Which chain we resolved to
    pub resolution: ForkResolution,
}

/// How the fork was resolved
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkResolution {
    /// Kept original chain (forked chain was invalid/shorter)
    KeptOriginal,
    /// Switched to forked chain (longer or better)
    SwitchedToFork,
}

impl ForkPoint {
    /// Create a new fork point record
    pub fn new(
        height: u64,
        detected_at: u64,
        original_hash: Hash,
        forked_hash: Hash,
        resolution: ForkResolution,
    ) -> Self {
        Self {
            height,
            detected_at,
            original_block_hash: original_hash,
            forked_block_hash: forked_hash,
            resolution,
        }
    }
}

/// Fork detector for identifying chain divergences
pub struct ForkDetector;

impl ForkDetector {
    /// Detect if a new block creates a fork
    pub fn detect_fork(
        existing_block: &Block,
        new_block: &Block,
    ) -> Option<ForkDetection> {
        // Both blocks at same height but different hashes = fork detected
        if existing_block.header.height == new_block.header.height
            && existing_block.header.block_hash != new_block.header.block_hash
        {
            return Some(ForkDetection {
                height: existing_block.header.height,
                existing_hash: existing_block.header.block_hash,
                new_hash: new_block.header.block_hash,
            });
        }
        None
    }

    /// Evaluate two chains and return which is canonical.
    ///
    /// # FORBIDDEN IN BFT MODE
    ///
    /// **This function must never be called in BFT consensus mode.**
    ///
    /// Fork-choice logic (selecting between competing chains) is fundamentally
    /// incompatible with BFT consensus. In BFT, once a block is committed at
    /// height H with 2/3+1 validator agreement, it is final and irreversible.
    /// No competing chain can ever be canonical at that height.
    ///
    /// Invoking this function is a programming error. It will panic unconditionally
    /// with `unreachable!` to surface the bug immediately at the call site.
    ///
    /// If you believe you need fork-choice logic, reconsider your design:
    /// - If you received a competing block, it is Byzantine evidence — report it.
    /// - If you are syncing a new node, use the canonical committed chain, not fork selection.
    /// - If you are implementing PoW mode, this function was valid in the hybrid era (pre-#936).
    ///   In BFT-only mode it is permanently disabled.
    ///
    /// See module-level documentation for full rationale.
    #[allow(unused_variables)]
    pub fn evaluate_chains(
        our_chain: &[Block],
        candidate_chain: &[Block],
    ) -> ChainEvaluation {
        unreachable!(
            "BFT INVARIANT VIOLATED: ForkDetector::evaluate_chains was called. \
             Fork-choice is forbidden in BFT consensus mode. \
             In BFT, committed blocks are final and irreversible — there is no competing \
             chain to evaluate. If a fork was detected, it must be treated as Byzantine \
             evidence, not resolved via chain selection. \
             See lib-blockchain/src/fork_recovery.rs module documentation for details."
        );
    }
}

/// Result of fork detection
#[derive(Debug, Clone)]
pub struct ForkDetection {
    /// Height where blocks diverge
    pub height: u64,
    /// Hash of our existing block
    pub existing_hash: Hash,
    /// Hash of competing block
    pub new_hash: Hash,
}

/// Result of chain evaluation
#[derive(Debug, Clone)]
pub enum ChainEvaluation {
    /// Keep our current chain as canonical
    KeepOurChain {
        our_work: u128,
        candidate_work: u128,
        reason: String,
    },
    /// Switch to candidate chain as canonical
    SwitchToCandidate {
        our_work: u128,
        candidate_work: u128,
        reason: String,
    },
}

/// Configuration for fork recovery behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkRecoveryConfig {
    /// Maximum blocks to reorg (prevents deep reorganizations)
    pub max_reorg_depth: u64,
    /// Minimum confirmations before block cannot be reorged
    pub min_finality_depth: u64,
    /// Track all forks for audit purposes
    pub track_fork_history: bool,
}

impl Default for ForkRecoveryConfig {
    fn default() -> Self {
        Self {
            max_reorg_depth: 1000, // 1000-block max reorg
            min_finality_depth: 12, // 12-block finality minimum
            track_fork_history: true,
        }
    }
}

// Helper function to calculate total work (from highest cumulative difficulty)
#[allow(dead_code)]
fn calculate_total_work(chain: &[Block]) -> u128 {
    chain
        .iter()
        .last()
        .map(|b| b.header.cumulative_difficulty.bits() as u128)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::types::Difficulty;

    fn create_test_block(height: u64, previous_hash: Hash, work_bits: u32, identifier: u64) -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[..8].copy_from_slice(&height.to_le_bytes());
        hash_bytes[8..16].copy_from_slice(&identifier.to_le_bytes());

        Block {
            header: BlockHeader {
                version: 1,
                previous_block_hash: previous_hash,
                merkle_root: Hash::default(),
                timestamp: height * 1000, // Deterministic timestamps
                difficulty: Difficulty::from_bits(1),
                nonce: identifier,
                height,
                block_hash: Hash::new(hash_bytes),
                transaction_count: 0,
                block_size: 0,
                cumulative_difficulty: Difficulty::from_bits(work_bits),
                fee_model_version: 2, // Phase 2+ uses v2
            },
            transactions: vec![],
        }
    }

    #[test]
    fn test_fork_detection_at_same_height() {
        let block_a = create_test_block(100, Hash::default(), 100, 1);
        let block_b = create_test_block(100, Hash::default(), 100, 2);

        let fork = ForkDetector::detect_fork(&block_a, &block_b);
        assert!(fork.is_some());
    }

    #[test]
    fn test_no_fork_at_different_heights() {
        let block_a = create_test_block(100, Hash::default(), 100, 1);
        let block_b = create_test_block(101, Hash::default(), 101, 1);

        let fork = ForkDetector::detect_fork(&block_a, &block_b);
        assert!(fork.is_none());
    }

    /// Verify that evaluate_chains panics unconditionally.
    ///
    /// In BFT mode, fork-choice is forbidden. Calling evaluate_chains is a
    /// programming error. These tests confirm the function panics immediately,
    /// which is the intended behavior after issue #968.
    #[test]
    #[should_panic(expected = "BFT INVARIANT VIOLATED")]
    fn test_evaluate_chains_is_forbidden_longer_chain() {
        let chain_a = vec![
            create_test_block(1, Hash::default(), 1, 1),
            create_test_block(2, Hash::default(), 2, 2),
            create_test_block(3, Hash::default(), 3, 3),
        ];

        let chain_b = vec![
            create_test_block(1, Hash::default(), 1, 1),
            create_test_block(2, Hash::default(), 2, 2),
        ];

        // This must panic — fork-choice is forbidden in BFT mode.
        let _ = ForkDetector::evaluate_chains(&chain_a, &chain_b);
    }

    #[test]
    #[should_panic(expected = "BFT INVARIANT VIOLATED")]
    fn test_evaluate_chains_is_forbidden_more_work() {
        let chain_a = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 200, 2),
        ];

        let chain_b = vec![
            create_test_block(1, Hash::default(), 1000, 1),
            create_test_block(2, Hash::default(), 2000, 2),
        ];

        // This must panic — fork-choice is forbidden in BFT mode.
        let _ = ForkDetector::evaluate_chains(&chain_a, &chain_b);
    }

    #[test]
    #[should_panic(expected = "BFT INVARIANT VIOLATED")]
    fn test_evaluate_chains_is_forbidden_timestamp_tiebreak() {
        let mut chain_a = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 100, 2),
        ];

        let mut chain_b = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 100, 2),
        ];

        chain_a[1].header.timestamp = 1000;
        chain_b[1].header.timestamp = 2000;

        // This must panic — fork-choice is forbidden in BFT mode.
        let _ = ForkDetector::evaluate_chains(&chain_a, &chain_b);
    }
}
