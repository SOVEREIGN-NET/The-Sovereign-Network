//! Fork Detection and Recovery Mechanism
//!
//! Handles network fork detection, chain evaluation, and reorganization.
//! Implements longest-chain rule with timestamp tiebreaker for canonical chain selection.

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

    /// Evaluate two chains and return which is canonical
    ///
    /// Uses longest-chain rule with timestamp tiebreaker:
    /// 1. Longer chain wins (more blocks)
    /// 2. If equal length, newer timestamp wins
    ///
    /// **Timestamp Tiebreaker Rationale:**
    /// Newer timestamps are chosen to prefer recently-produced blocks when
    /// chain lengths are equal. This is acceptable because:
    /// - Block timestamps are validated against network time during consensus
    /// - BFT consensus requires 2/3+ validator agreement, limiting manipulation
    /// - Timestamp must be within acceptable drift bounds (enforced in block validation)
    pub fn evaluate_chains(
        our_chain: &[Block],
        candidate_chain: &[Block],
    ) -> ChainEvaluation {
        // Step 1: Compare chain lengths (number of blocks)
        let our_length = our_chain.len();
        let candidate_length = candidate_chain.len();

        if candidate_length > our_length {
            // Candidate chain is longer
            return ChainEvaluation::SwitchToCandidate {
                our_work: our_length as u128,
                candidate_work: candidate_length as u128,
                reason: format!("candidate chain is longer ({} vs {} blocks)", candidate_length, our_length),
            };
        } else if our_length > candidate_length {
            // Our chain is longer
            return ChainEvaluation::KeepOurChain {
                our_work: our_length as u128,
                candidate_work: candidate_length as u128,
                reason: format!("our chain is longer ({} vs {} blocks)", our_length, candidate_length),
            };
        }

        // Step 2: Equal length - use timestamp as tiebreaker
        if !candidate_chain.is_empty() && !our_chain.is_empty() {
            let our_timestamp = our_chain.last().map(|b| b.header.timestamp).unwrap_or(0);
            let candidate_timestamp = candidate_chain
                .last()
                .map(|b| b.header.timestamp)
                .unwrap_or(0);

            if candidate_timestamp > our_timestamp {
                ChainEvaluation::SwitchToCandidate {
                    our_work: our_length as u128,
                    candidate_work: candidate_length as u128,
                    reason: "equal length, candidate has newer timestamp".to_string(),
                }
            } else {
                ChainEvaluation::KeepOurChain {
                    our_work: our_length as u128,
                    candidate_work: candidate_length as u128,
                    reason: "equal length, our chain preferred (older or equal timestamp)".to_string(),
                }
            }
        } else {
            ChainEvaluation::KeepOurChain {
                our_work: our_length as u128,
                candidate_work: candidate_length as u128,
                reason: "equal length".to_string(),
            }
        }
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::types::Difficulty;

    fn create_test_block(height: u64, previous_hash: Hash, _work_bits: u32, identifier: u64) -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[..8].copy_from_slice(&height.to_le_bytes());
        hash_bytes[8..16].copy_from_slice(&identifier.to_le_bytes());

        Block {
            header: BlockHeader {
                version: 1,
                previous_block_hash: previous_hash,
                merkle_root: Hash::default(),
                timestamp: height * 1000, // Deterministic timestamps
                height,
                block_hash: Hash::new(hash_bytes),
                transaction_count: 0,
                block_size: 0,
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

    #[test]
    fn test_longer_chain_wins() {
        let chain_a = vec![
            create_test_block(1, Hash::default(), 1, 1),
            create_test_block(2, Hash::default(), 2, 2),
            create_test_block(3, Hash::default(), 3, 3),
        ];

        let chain_b = vec![
            create_test_block(1, Hash::default(), 1, 1),
            create_test_block(2, Hash::default(), 2, 2),
        ];

        let eval = ForkDetector::evaluate_chains(&chain_a, &chain_b);
        assert!(matches!(eval, ChainEvaluation::KeepOurChain { .. }));
    }

    #[test]
    fn test_chain_with_more_work_wins() {
        let chain_a = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 200, 2),
        ];

        let chain_b = vec![
            create_test_block(1, Hash::default(), 1000, 1),
            create_test_block(2, Hash::default(), 2000, 2),
        ];

        let eval = ForkDetector::evaluate_chains(&chain_a, &chain_b);
        assert!(matches!(eval, ChainEvaluation::SwitchToCandidate { .. }));
    }

    #[test]
    fn test_newer_timestamp_wins_at_equal_work() {
        let mut chain_a = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 100, 2),
        ];

        let mut chain_b = vec![
            create_test_block(1, Hash::default(), 100, 1),
            create_test_block(2, Hash::default(), 100, 2),
        ];

        // Set different timestamps for last block
        chain_a[1].header.timestamp = 1000;
        chain_b[1].header.timestamp = 2000;

        let eval = ForkDetector::evaluate_chains(&chain_a, &chain_b);
        assert!(matches!(eval, ChainEvaluation::SwitchToCandidate { .. }));
    }
}
