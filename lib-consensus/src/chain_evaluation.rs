//! Chain Evaluation and Selection Rules
//!
//! DEPRECATED: Nakamoto-style chain scoring logic removed (Issue #937).
//! Sync now targets the highest committed BFT height (Issue #950).
//! This module is kept for backward compatibility of public types only.

use serde::{Deserialize, Serialize};

/// Result of comparing two blockchain chains
#[derive(Debug, Clone, PartialEq)]
pub enum ChainDecision {
    /// Keep the local chain (it is at least as far ahead in committed BFT height)
    KeepLocal,
    /// Adopt the imported chain (it has a higher committed BFT height)
    AdoptImported,
    /// Local chain is stronger - use as merge base, import content from remote
    AdoptLocal,
    /// Chains are compatible and can be merged (similar height)
    Merge,
    /// Import shorter chain's unique content into longer chain
    MergeContentOnly,
    /// Chains conflict and manual resolution needed
    Conflict,
    /// Chains are incompatible and cannot be merged safely
    Reject,
}

/// Result of chain merge operation
#[derive(Debug, Clone, PartialEq)]
pub enum ChainMergeResult {
    /// Local chain was kept
    LocalKept,
    /// Imported chain was adopted
    ImportedAdopted,
    /// Chains were successfully merged
    Merged,
    /// Unique content from imported chain was merged into local
    ContentMerged,
    /// Merge failed due to conflicts
    Failed(String),
}

/// Simplified blockchain data for evaluation
///
/// Retained for backward compatibility. The `total_work` field and
/// scoring-related fields are no longer used for sync decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSummary {
    pub height: u64,
    pub total_work: u128,
    pub total_transactions: u64,
    pub total_identities: u64,
    pub total_utxos: u64,
    pub total_contracts: u64,
    pub genesis_timestamp: u64,
    pub latest_timestamp: u64,
    pub genesis_hash: String,
    /// Number of active validators backing this chain
    pub validator_count: u64,
    /// Total stake/reputation of validators
    pub total_validator_stake: u128,
    /// Hash of the validator set (for compatibility checking)
    pub validator_set_hash: String,
    /// Number of bridge nodes connecting to other networks
    pub bridge_node_count: u64,
    /// Expected network throughput (TPS)
    pub expected_tps: u64,
    /// Network size (total nodes)
    pub network_size: u64,
}

/// Chain evaluation engine
///
/// All Nakamoto-style chain scoring has been removed (Issue #937 / #950).
/// Sync now targets the highest committed BFT height; see
/// `Blockchain::evaluate_and_merge_chain` for the authoritative logic.
pub struct ChainEvaluator;

impl ChainEvaluator {
    /// Compare two chains and decide which should be adopted.
    ///
    /// DEPRECATED (Issue #937 / #950): This function always returns
    /// `KeepLocal`. The real sync decision is made in
    /// `Blockchain::evaluate_and_merge_chain` based on committed BFT height,
    /// not on chain scoring.
    #[deprecated(
        since = "2.0.0",
        note = "Chain evaluation removed - use highest committed BFT height instead (Issue #950)"
    )]
    pub fn evaluate_chains(_local: &ChainSummary, _imported: &ChainSummary) -> ChainDecision {
        // BFT consensus provides finality; the sync target is always the peer
        // with the highest committed block height. No Nakamoto-style scoring.
        ChainDecision::KeepLocal
    }

    /// Validate that chain summaries are compatible for merging.
    ///
    /// DEPRECATED (Issue #937 / #950): Always returns false. BFT consensus
    /// does not use chain merging.
    #[deprecated(
        since = "2.0.0",
        note = "Chain merging removed - BFT consensus only (Issue #950)"
    )]
    pub fn can_merge_chains(_local: &ChainSummary, _imported: &ChainSummary) -> bool {
        false
    }

    /// Create a chain summary from blockchain data.
    ///
    /// Retained for callers that still populate `ChainSummary` for
    /// informational / monitoring purposes.
    pub fn create_chain_summary(
        height: u64,
        total_work: u128,
        blocks: &[impl AsRef<[u8]>],
        utxo_count: u64,
        identity_count: u64,
        contract_count: u64,
        genesis_timestamp: u64,
        latest_timestamp: u64,
        genesis_hash: String,
        validator_count: u64,
        total_validator_stake: u128,
        validator_set_hash: String,
        bridge_node_count: u64,
        expected_tps: u64,
        network_size: u64,
    ) -> ChainSummary {
        // Count transactions across all blocks (simplified)
        let total_transactions = blocks.len() as u64;

        ChainSummary {
            height,
            total_work,
            total_transactions,
            total_identities: identity_count,
            total_utxos: utxo_count,
            total_contracts: contract_count,
            genesis_timestamp,
            latest_timestamp,
            genesis_hash,
            validator_count,
            total_validator_stake,
            validator_set_hash,
            bridge_node_count,
            expected_tps,
            network_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_chain(height: u64, work: u128, identities: u64, transactions: u64) -> ChainSummary {
        ChainSummary {
            height,
            total_work: work,
            total_transactions: transactions,
            total_identities: identities,
            total_utxos: 100,
            total_contracts: 5,
            genesis_timestamp: 1640995200,
            latest_timestamp: 1640995200 + 3600,
            genesis_hash: "test_genesis".to_string(),
            validator_count: 5,
            total_validator_stake: 10000,
            validator_set_hash: "test_validators".to_string(),
            bridge_node_count: 8,
            expected_tps: 1000,
            network_size: 50,
        }
    }

    /// Verify that evaluate_chains always returns KeepLocal (BFT-only mode).
    /// Sync decisions are made by Blockchain::evaluate_and_merge_chain based on
    /// committed BFT height, not by this function.
    #[test]
    #[allow(deprecated)]
    fn test_evaluate_chains_always_keep_local() {
        // Even if the imported chain is "longer" or "higher work", evaluate_chains
        // returns KeepLocal because BFT height comparison is done elsewhere.
        let local = create_test_chain(3, 500, 5, 20);
        let imported_taller = create_test_chain(10, 9999, 100, 500);

        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported_taller),
            ChainDecision::KeepLocal,
            "evaluate_chains must always return KeepLocal (Issue #950)"
        );

        // Symmetric: imported shorter than local
        let imported_shorter = create_test_chain(1, 10, 1, 2);
        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported_shorter),
            ChainDecision::KeepLocal,
            "evaluate_chains must always return KeepLocal (Issue #950)"
        );
    }

    /// Verify that can_merge_chains always returns false (BFT-only mode).
    #[test]
    #[allow(deprecated)]
    fn test_can_merge_chains_always_false() {
        let local = create_test_chain(5, 1000, 10, 50);
        let imported = create_test_chain(5, 1000, 10, 50);
        assert!(
            !ChainEvaluator::can_merge_chains(&local, &imported),
            "can_merge_chains must always return false (Issue #950)"
        );
    }

    /// Verify create_chain_summary still works for informational use.
    #[test]
    fn test_create_chain_summary() {
        let blocks: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let summary = ChainEvaluator::create_chain_summary(
            10,
            5000,
            &blocks,
            50,
            20,
            3,
            1640995200,
            1640998800,
            "genesis_hash".to_string(),
            5,
            10000,
            "validator_set".to_string(),
            2,
            100,
            30,
        );
        assert_eq!(summary.height, 10);
        assert_eq!(summary.total_work, 5000);
        assert_eq!(summary.total_transactions, 2); // blocks.len()
        assert_eq!(summary.total_identities, 20);
        assert_eq!(summary.total_utxos, 50);
        assert_eq!(summary.total_contracts, 3);
        assert_eq!(summary.validator_count, 5);
    }
}
