//! Chain Evaluation and Selection Rules
//! 
//! Implements consensus rules for deciding which blockchain chain to adopt
//! when multiple chains are available (e.g., during mesh network synchronization)

use serde::{Deserialize, Serialize};
use tracing::info;

/// Result of comparing two blockchain chains
#[derive(Debug, Clone, PartialEq)]
pub enum ChainDecision {
    /// Keep the local chain (it's better)
    KeepLocal,
    /// Adopt the imported chain (it's better)
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

/// Chain evaluation engine implementing consensus rules
pub struct ChainEvaluator;

impl ChainEvaluator {
    /// Compare two chains and decide which should be adopted
    pub fn evaluate_chains(local: &ChainSummary, imported: &ChainSummary) -> ChainDecision {
        // Rule 0: Special case - if local chain is genesis-only (height 0-1) with minimal activity,
        // adopt the imported chain regardless of genesis hash mismatch.
        // This handles the case where a node just started and created its own genesis,
        // then discovered a peer with an existing network.
        if Self::is_genesis_only_chain(local) && !Self::is_genesis_only_chain(imported) {
            // Local is empty, imported has real activity - adopt imported
            return ChainDecision::AdoptImported;
        }
        
        // Rule 0b: CRITICAL - Different genesis hashes means different network origins
        // Use score-based evaluation to determine which chain should be the merge base
        // This prevents a 1000-validator network from being absorbed by a 5-validator network
        if local.genesis_hash != imported.genesis_hash {
            info!(" Genesis hash mismatch detected during evaluation");
            info!("   Local genesis:    {}", local.genesis_hash);
            info!("   Imported genesis: {}", imported.genesis_hash);
            info!("   Local network: {} validators, {} identities, height {}", 
                  local.validator_count, local.total_identities, local.height);
            info!("   Imported network: {} validators, {} identities, height {}", 
                  imported.validator_count, imported.total_identities, imported.height);
            
            // Evaluate which chain should be the merge base
            return Self::evaluate_genesis_mismatch(local, imported);
        }
        
        // Rule 1: Genesis hash must match (same network)
        if local.genesis_hash != imported.genesis_hash {
            // Different genesis hashes - check if we should still adopt
            if Self::should_adopt_despite_genesis_mismatch(local, imported) {
                return ChainDecision::AdoptImported;
            }
            return ChainDecision::Conflict;
        }

        // Rule 2: Check if chains can be merged (similar height, compatible content)
        if Self::can_merge_chains(local, imported) {
            return ChainDecision::Merge;
        }

        // Rule 3: Longest chain wins (most blocks)
        // BUT preserve unique content from shorter chain
        if imported.height > local.height {
            return ChainDecision::AdoptImported;
        } else if local.height > imported.height {
            // Check if imported chain has unique content worth preserving
            if Self::has_unique_content(local, imported) {
                return ChainDecision::MergeContentOnly;
            }
            return ChainDecision::KeepLocal;
        }

        // Rule 4: If same height, most cumulative work wins
        if imported.total_work > local.total_work {
            return ChainDecision::AdoptImported;
        } else if local.total_work > imported.total_work {
            return ChainDecision::KeepLocal;
        }

        // Rule 5: Tiebreaker - Point-based scoring system
        let local_score = Self::calculate_chain_score(local);
        let imported_score = Self::calculate_chain_score(imported);

        if imported_score > local_score {
            ChainDecision::AdoptImported
        } else if local_score > imported_score {
            ChainDecision::KeepLocal
        } else {
            // Rule 6: Final tiebreaker - earliest genesis timestamp wins
            if imported.genesis_timestamp < local.genesis_timestamp {
                ChainDecision::AdoptImported
            } else {
                ChainDecision::KeepLocal
            }
        }
    }

    /// Calculate point-based score for tiebreaking
    fn calculate_chain_score(chain: &ChainSummary) -> u64 {
        let mut score = 0u64;

        // Points for network activity
        score += chain.total_transactions * 10;     // 10 points per transaction
        score += chain.total_identities * 100;     // 100 points per identity
        score += chain.total_utxos * 5;           // 5 points per UTXO
        score += chain.total_contracts * 50;      // 50 points per contract

        // Bonus for chain age (older = more established)
        let chain_age = chain.latest_timestamp.saturating_sub(chain.genesis_timestamp);
        score += chain_age / 3600; // 1 point per hour of chain history

        score
    }

    /// Validate that chain summaries are compatible for merging
    /// Requires sufficient validator overlap for secure merging
    pub fn can_merge_chains(local: &ChainSummary, imported: &ChainSummary) -> bool {
        // Must be same network
        if local.genesis_hash != imported.genesis_hash {
            return false;
        }
        
        // CRITICAL: Validator requirements for secure merging
        if !Self::has_sufficient_validator_overlap(local, imported) {
            return false; // Insufficient validators - potential security risk
        }
        
        // Case 1: Identical content (same hashes) - NO MERGE NEEDED
        if Self::chains_have_identical_content(local, imported) {
            return false; // Same content = no merge needed, just keep local
        }
        
        // Case 2: Identical height and work but different content (parallel mining)
        if local.height == imported.height && local.total_work == imported.total_work {
            // Check if they have complementary content (different transactions/identities/contracts)
            let has_different_content = 
                local.total_transactions != imported.total_transactions ||
                local.total_identities != imported.total_identities ||
                local.total_contracts != imported.total_contracts ||
                local.total_utxos != imported.total_utxos;
            
            if has_different_content {
                return true; // Merge complementary content
            }
        }
        
        // Case 3: Height difference of 1 (one chain is slightly ahead)
        if local.height.abs_diff(imported.height) == 1 {
            return true; // Can merge by adding missing block
        }
        
        // Case 4: Same height, similar work (within 10% difference)
        if local.height == imported.height {
            let work_diff_ratio = if local.total_work > imported.total_work {
                (local.total_work - imported.total_work) as f64 / local.total_work as f64
            } else {
                (imported.total_work - local.total_work) as f64 / imported.total_work as f64
            };
            
            if work_diff_ratio <= 0.1 { // Within 10% work difference
                return true; // Likely compatible parallel chains
            }
        }
        
        false
    }

    /// Check if two chains have sufficient validator overlap for secure merging
    /// Allows smaller meshes to merge more easily for security benefits
    /// CRITICAL: Prevents split-brain consensus failures with BFT bridge node requirements
    fn has_sufficient_validator_overlap(local: &ChainSummary, imported: &ChainSummary) -> bool {
        const MIN_VALIDATORS_FOR_STRICT_RULES: u64 = 7; // Threshold for strict validator rules
        const SMALL_MESH_MAX_VALIDATORS: u64 = 5; // Small meshes can merge easily
        const MIN_VALIDATOR_OVERLAP_RATIO: f64 = 0.67; // 67% validator overlap for large meshes
        const SMALL_MESH_OVERLAP_RATIO: f64 = 0.33; // 33% overlap for small meshes
        
        let local_count = local.validator_count;
        let imported_count = imported.validator_count;
        
        // CRITICAL CHECK: Ensure BFT bridge node requirements are met
        // This prevents the split-brain problem identified in the analysis
        if !Self::validate_bft_bridge_requirements(local, imported) {
            return false; // Insufficient bridge nodes - split-brain risk
        }
        
        // Rule 1: If either chain has very few validators, allow easier merging
        // Small meshes NEED to merge for security
        if local_count <= SMALL_MESH_MAX_VALIDATORS || imported_count <= SMALL_MESH_MAX_VALIDATORS {
            // Even single-validator meshes can merge (they desperately need security)
            if local_count == 0 || imported_count == 0 {
                return true; // Solo nodes should join any network
            }
            
            // Small meshes use relaxed overlap requirements
            let required_overlap = SMALL_MESH_OVERLAP_RATIO;
            return Self::check_validator_overlap(local, imported, required_overlap);
        }
        
        // Rule 2: Both chains have sufficient validators for strict rules
        if local_count >= MIN_VALIDATORS_FOR_STRICT_RULES && imported_count >= MIN_VALIDATORS_FOR_STRICT_RULES {
            // Large meshes require strong validator overlap for security
            return Self::check_validator_overlap(local, imported, MIN_VALIDATOR_OVERLAP_RATIO);
        }
        
        // Rule 3: Mixed case - one small, one large mesh
        // Allow small mesh to join large mesh with medium requirements
        let required_overlap = (MIN_VALIDATOR_OVERLAP_RATIO + SMALL_MESH_OVERLAP_RATIO) / 2.0; // ~50%
        Self::check_validator_overlap(local, imported, required_overlap)
    }
    
    /// CRITICAL: Validate Byzantine Fault Tolerant bridge node requirements
    /// Handles asymmetric joining: small nodes can join large networks easily
    /// Only requires RECEIVING network to have adequate bridge infrastructure
    fn validate_bft_bridge_requirements(local: &ChainSummary, imported: &ChainSummary) -> bool {
        const SOLO_NODE_MAX_SIZE: u64 = 5; // Solo/small nodes don't need bridge requirements
        const SMALL_NETWORK_MAX_SIZE: u64 = 50; // Small networks have relaxed requirements
        
        // Determine which network is larger (the "receiving" network)
        let (smaller_network, larger_network) = if local.network_size <= imported.network_size {
            (local, imported)
        } else {
            (imported, local)
        };
        
        // Case 1: Solo node or tiny mesh joining any network
        // Solo nodes ARE their own infrastructure - no requirements needed!
        if smaller_network.network_size <= SOLO_NODE_MAX_SIZE {
            // Solo nodes can join ANY network without ANY infrastructure requirements
            // The solo node IS the infrastructure they're bringing to the network
            return true; // Solo nodes can always join - they bring themselves as infrastructure
        }
        
        // Case 2: Small network joining larger network
        if smaller_network.network_size <= SMALL_NETWORK_MAX_SIZE {
            // Small network has relaxed requirements (only needs basic connectivity)
            let min_nodes_for_small = 1; // Just needs 1 bridge to connect
            let min_nodes_for_large = Self::calculate_minimum_bft_bridge_nodes(
                larger_network.network_size + smaller_network.network_size,
                larger_network.expected_tps + smaller_network.expected_tps
            );
            
            return smaller_network.bridge_node_count >= min_nodes_for_small &&
                   larger_network.bridge_node_count >= min_nodes_for_large;
        }
        
        // Case 3: Two large networks merging (original strict requirements)
        let combined_network_size = local.network_size + imported.network_size;
        let combined_expected_tps = local.expected_tps + imported.expected_tps;
        let min_bft_nodes = Self::calculate_minimum_bft_bridge_nodes(combined_network_size, combined_expected_tps);
        
        // Both large networks must meet full BFT requirements
        local.bridge_node_count >= min_bft_nodes && imported.bridge_node_count >= min_bft_nodes
    }
    
    /// Calculate minimum bridge nodes using BFT formula: N >= 3F + 1
    /// Also considers throughput requirements to prevent bottlenecks
    fn calculate_minimum_bft_bridge_nodes(network_size: u64, expected_tps: u64) -> u64 {
        // Constants based on analysis
        const NODE_TPS_CAPACITY: u64 = 2500; // TPS per bridge node
        const MIN_FAULT_TOLERANCE: u64 = 2; // Tolerate 2 malicious/failed nodes
        
        // Rule A: BFT Security Requirement - N >= 3F + 1
        let min_security_nodes = 3 * MIN_FAULT_TOLERANCE + 1; // = 7 nodes
        
        // Rule B: Throughput Requirement - prevent bottlenecks
        let min_throughput_nodes = if expected_tps > 0 {
            (expected_tps + NODE_TPS_CAPACITY - 1) / NODE_TPS_CAPACITY // Ceiling division
        } else {
            1
        };
        
        // Rule C: Network Size Scaling - larger networks need more bridge nodes
        let min_scale_nodes = if network_size > 100 {
            ((network_size as f64).sqrt().ceil() as u64).max(4) // Square root scaling with ceiling, minimum 4
        } else {
            3 // Small networks need at least 3 for quorum
        };
        
        // Take the maximum of all requirements
        let min_nodes = min_security_nodes.max(min_throughput_nodes).max(min_scale_nodes);
        
        // Absolute minimum is 3 (prevents 2-node split-brain)
        min_nodes.max(3)
    }

    /// Helper function to check actual validator overlap ratio
    fn check_validator_overlap(local: &ChainSummary, imported: &ChainSummary, required_ratio: f64) -> bool {
        // Same validator set hash = automatic approval
        if local.validator_set_hash == imported.validator_set_hash {
            return true; // Same validator set = 100% overlap
        }
        
        // Estimate overlap based on stake similarity (simplified)
        // In full implementation, would check actual validator intersection
        let stake_ratio = if local.total_validator_stake > imported.total_validator_stake {
            if local.total_validator_stake == 0 {
                1.0 // Avoid division by zero
            } else {
                imported.total_validator_stake as f64 / local.total_validator_stake as f64
            }
        } else {
            if imported.total_validator_stake == 0 {
                1.0 // Avoid division by zero
            } else {
                local.total_validator_stake as f64 / imported.total_validator_stake as f64
            }
        };
        
        stake_ratio >= required_ratio
    }

    /// Detect if chains have identical content (same hashes)
    /// When content is identical, merging is unnecessary
    fn chains_have_identical_content(local: &ChainSummary, imported: &ChainSummary) -> bool {
        // If all metrics are identical, content is likely identical
        local.height == imported.height &&
        local.total_work == imported.total_work &&
        local.total_transactions == imported.total_transactions &&
        local.total_identities == imported.total_identities &&
        local.total_utxos == imported.total_utxos &&
        local.total_contracts == imported.total_contracts &&
        local.genesis_timestamp == imported.genesis_timestamp
        // Note: In full implementation, would compare actual content hashes
    }

    /// Check if imported chain has unique content worth preserving
    /// Used when local chain is longer but imported has valuable data
    fn has_unique_content(local: &ChainSummary, imported: &ChainSummary) -> bool {
        // If imported chain has any unique identities, wallets, contracts, or UTXOs
        // that might not exist in the longer local chain, return true
        
        // Heuristic: If imported has content but much smaller numbers than local,
        // it might still have unique identities/contracts not in local chain
        if imported.total_identities > 0 || 
           imported.total_contracts > 0 || 
           imported.total_utxos > 0 ||
           imported.total_transactions > 0 {
            return true; // Has content that should be checked
        }
        
        false // No unique content
    }

    /// Create chain summary from blockchain data
    pub fn create_chain_summary(
        height: u64,
        total_work: u128,
        blocks: &[impl AsRef<[u8]>], // Block data for analysis
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
        // Count transactions across all blocks
        let total_transactions = blocks.len() as u64; // Simplified - would parse actual tx count

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
    
    /// Check if a chain is essentially genesis-only (no real activity)
    /// This detects chains that were just created and haven't processed any real transactions
    fn is_genesis_only_chain(chain: &ChainSummary) -> bool {
        // A genesis-only chain has:
        // 1. Height of 0 or 1 (just genesis block, maybe one system tx block)
        // 2. Minimal identities (0-1, just the bootstrap validator)
        // 3. Minimal transactions (1-2, just genesis funding)
        // Note: We DON'T check age because genesis timestamps may be 0 or very low
        //       The structural checks (height, identities, txs) are sufficient
        
        let height_check = chain.height <= 1;
        let identity_check = chain.total_identities <= 1;
        let tx_check = chain.total_transactions <= 2;
        
        info!("    Genesis-only check: height={} (<=1? {}), identities={} (<=1? {}), txs={} (<=2? {})",
              chain.height, height_check, chain.total_identities, identity_check, 
              chain.total_transactions, tx_check);
        
        height_check && identity_check && tx_check
    }
    
    /// Evaluate which chain should be the merge base when genesis hashes differ
    /// Uses score-based system to select the stronger, more established network
    /// This prevents security downgrades (e.g., 1000 validators absorbed by 5 validators)
    fn evaluate_genesis_mismatch(local: &ChainSummary, imported: &ChainSummary) -> ChainDecision {
        info!("⚖️  Evaluating genesis mismatch - determining merge base");
        
        // 1. Calculate weighted scores for each chain (security + economic activity)
        let local_score = Self::calculate_merge_score(local);
        let imported_score = Self::calculate_merge_score(imported);
        
        info!("   Local merge score:    {} points", local_score);
        info!("   Imported merge score: {} points", imported_score);
        
        // 2. Safety check - ensure networks are compatible enough to merge
        if !Self::are_networks_compatible(local, imported) {
            info!(" Networks are incompatible - merge rejected for safety");
            return ChainDecision::Reject;
        }
        
        // 3. Select the stronger chain as the merge base
        // The weaker chain's unique content (identities, validators, UTXOs) will be
        // imported into the stronger chain to preserve all user data
        if imported_score > local_score {
            info!(" Imported chain is stronger - will be used as merge base");
            info!("   → Local identities and validators will be preserved");
            ChainDecision::AdoptImported
        } else if local_score > imported_score {
            info!(" Local chain is stronger - will be used as merge base");
            info!("   → Imported identities and validators will be preserved");
            ChainDecision::AdoptLocal
        } else {
            // Exact tie - use genesis timestamp as tiebreaker (older = more established)
            info!("⚖️  Exact tie - using genesis timestamp tiebreaker");
            if imported.genesis_timestamp < local.genesis_timestamp {
                info!(" Imported chain is older - will be used as merge base");
                ChainDecision::AdoptImported
            } else if local.genesis_timestamp < imported.genesis_timestamp {
                info!(" Local chain is older - will be used as merge base");
                ChainDecision::AdoptLocal
            } else {
                // Extremely rare: same score AND same genesis timestamp
                // Use genesis hash comparison as final deterministic tiebreaker
                info!("  Perfect tie - using genesis hash comparison");
                if imported.genesis_hash < local.genesis_hash {
                    ChainDecision::AdoptImported
                } else {
                    ChainDecision::AdoptLocal
                }
            }
        }
    }
    
    /// Calculate merge score based on security and economic activity
    /// Prioritizes: Validators > Identities > Transactions > Work
    /// This ensures established, secure networks are preferred as merge bases
    fn calculate_merge_score(chain: &ChainSummary) -> u64 {
        // Weights prioritize security (validators) over everything else
        let validator_score = chain.validator_count * 100;        // 1 validator = 100 points
        let identity_score = chain.total_identities * 10;         // 1 identity = 10 points  
        let transaction_score = chain.total_transactions;         // 1 transaction = 1 point
        let work_score = (chain.total_work / 100_000) as u64;    // Total work (scaled down)
        let stake_score = (chain.total_validator_stake / 1000) as u64; // Validator stake weight
        
        let total_score = validator_score 
            + identity_score 
            + transaction_score 
            + work_score
            + stake_score;
        
        info!("   Score breakdown: validators={}, identities={}, txs={}, work={}, stake={} → total={}",
              validator_score, identity_score, transaction_score, work_score, stake_score, total_score);
        
        total_score
    }
    
    /// Check if two networks are compatible enough to merge safely
    /// Prevents merging chains that are too different in size or age
    fn are_networks_compatible(local: &ChainSummary, imported: &ChainSummary) -> bool {
        // Both are genesis-only chains - always compatible (just started)
        if Self::is_genesis_only_chain(local) && Self::is_genesis_only_chain(imported) {
            return true;
        }
        
        // One is genesis-only - always compatible (new node joining network)
        if Self::is_genesis_only_chain(local) || Self::is_genesis_only_chain(imported) {
            return true;
        }
        
        // Both are established networks - apply compatibility checks
        
        // Check 1: Neither network can be TOO small (minimum viable network)
        // A network with < 3 validators is vulnerable and shouldn't dictate merge direction
        let min_validators_for_merge = 3;
        if local.validator_count < min_validators_for_merge 
            && imported.validator_count < min_validators_for_merge {
            info!("     Both networks have < {} validators - allowing merge", min_validators_for_merge);
            return true; // Both are small, allow merge
        }
        
        // Check 2: Age difference shouldn't be extreme (prevents ancient chain from dominating)
        // Allow up to 1 year age difference (365 days * 24 hours * 3600 seconds)
        let max_age_difference_seconds = 365 * 24 * 3600;
        let age_difference = if local.genesis_timestamp > imported.genesis_timestamp {
            local.genesis_timestamp - imported.genesis_timestamp
        } else {
            imported.genesis_timestamp - local.genesis_timestamp
        };
        
        if age_difference > max_age_difference_seconds {
            info!("     Age difference too large: {} days (max 365 days)", 
                  age_difference / (24 * 3600));
            return false; // Too different in age
        }
        
        // Check 3: Size disparity shouldn't be extreme (prevents tiny chain from absorbing huge one)
        // Calculate size ratio (always > 1.0)
        let size_ratio = if local.total_identities > imported.total_identities {
            local.total_identities as f64 / imported.total_identities.max(1) as f64
        } else {
            imported.total_identities as f64 / local.total_identities.max(1) as f64
        };
        
        // Allow up to 100:1 size ratio (larger network can be up to 100x bigger)
        let max_size_ratio = 100.0;
        if size_ratio > max_size_ratio {
            info!("     Size disparity too large: {:.1}:1 ratio (max {}:1)", 
                  size_ratio, max_size_ratio);
            return false; // One network is way too big compared to the other
        }
        
        info!("    Networks are compatible: age_diff={}d, size_ratio={:.1}:1", 
              age_difference / (24 * 3600), size_ratio);
        
        true // Networks are compatible
    }
    
    /// Decide if we should adopt imported chain despite genesis hash mismatch
    /// This handles the case where a new node created its own genesis, then discovered
    /// an existing network with real activity
    /// DEPRECATED: Replaced by evaluate_genesis_mismatch() which uses score-based selection
    fn should_adopt_despite_genesis_mismatch(local: &ChainSummary, imported: &ChainSummary) -> bool {
        // Case 1: Local is genesis-only, imported has real activity
        if Self::is_genesis_only_chain(local) && !Self::is_genesis_only_chain(imported) {
            return true;
        }
        
        // Case 2: Both are genesis-only, adopt the older one (earlier genesis timestamp)
        if Self::is_genesis_only_chain(local) && Self::is_genesis_only_chain(imported) {
            return imported.genesis_timestamp < local.genesis_timestamp;
        }
        
        // Case 3: Local has minimal activity (< 5 identities, < 10 transactions)
        // but imported has significant activity
        if local.height <= 5 
            && local.total_identities < 5 
            && local.total_transactions < 10
            && imported.height > local.height * 2  // Imported is significantly longer
            && imported.total_identities > 5 
        {
            return true;
        }
        
        // Otherwise, respect genesis hash mismatch - they're different networks
        false
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
            genesis_timestamp: 1640995200, // Jan 1, 2022
            latest_timestamp: 1640995200 + 3600,
            genesis_hash: "test_genesis".to_string(),
            validator_count: 5, // Default test validator count
            total_validator_stake: 10000, // Default test stake
            validator_set_hash: "test_validators".to_string(),
            bridge_node_count: 8, // Default BFT-safe bridge node count
            expected_tps: 1000, // Default expected throughput
            network_size: 50, // Default network size
        }
    }

    #[test]
    fn test_longest_chain_wins() {
        let local = create_test_chain(5, 1000, 10, 50);
        let imported = create_test_chain(7, 1000, 10, 50);

        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported),
            ChainDecision::AdoptImported
        );
    }

    #[test]
    fn test_most_work_wins() {
        let local = create_test_chain(5, 1000, 10, 50);
        let imported = create_test_chain(5, 2000, 10, 50);

        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported),
            ChainDecision::AdoptImported
        );
    }

    #[test]
    fn test_point_based_tiebreaker() {
        let mut local = create_test_chain(5, 1000, 5, 20);     // Lower score
        let mut imported = create_test_chain(5, 1000, 10, 40); // Higher score
        
        // Make them incompatible for merging by having different validator sets
        // and make sure they don't pass the validator overlap requirements
        local.validator_set_hash = "validators_local".to_string();
        imported.validator_set_hash = "validators_imported".to_string();
        local.validator_count = 3;
        imported.validator_count = 3;
        local.bridge_node_count = 1; // Insufficient bridge nodes for BFT requirements
        imported.bridge_node_count = 1; // This will fail the BFT validation

        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported),
            ChainDecision::AdoptImported
        );
    }

    #[test]
    fn test_different_genesis_mismatch() {
        let mut local = create_test_chain(5, 1000, 10, 50);
        let mut imported = create_test_chain(7, 2000, 15, 60);

        local.genesis_hash = "genesis_a".to_string();
        imported.genesis_hash = "genesis_b".to_string();

        // With genesis mismatch, the system evaluates which network is stronger
        // and adopts that as the merge base. Imported chain has higher metrics.
        assert_eq!(
            ChainEvaluator::evaluate_chains(&local, &imported),
            ChainDecision::AdoptImported
        );
    }

    #[test]
    fn test_small_mesh_can_merge_easily() {
        // Small meshes should be able to merge with relaxed requirements
        let mut small_local = create_test_chain(3, 1000, 5, 20);
        let mut small_imported = create_test_chain(3, 1000, 8, 25);
        
        small_local.validator_count = 2; // Small mesh
        small_imported.validator_count = 3; // Small mesh
        small_local.total_validator_stake = 1000;
        small_imported.total_validator_stake = 500; // Only 50% stake ratio
        
        // Should allow merge despite low stake ratio (small meshes need security)
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&small_local, &small_imported));
    }

    #[test]
    fn test_solo_node_can_join_any_network_basic() {
        // Solo nodes (0-1 validators) should be able to join any network
        let mut solo_node = create_test_chain(1, 100, 1, 5);
        let mut network = create_test_chain(5, 2000, 20, 100);
        
        solo_node.validator_count = 1; // Solo node
        network.validator_count = 10; // Established network
        
        // Solo node should be able to join established network
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&solo_node, &network));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&network, &solo_node));
    }

    #[test]
    fn test_large_meshes_need_strong_overlap() {
        // Large meshes should require strong validator overlap
        let mut large_local = create_test_chain(10, 5000, 50, 200);
        let mut large_imported = create_test_chain(10, 5000, 60, 250);
        
        large_local.validator_count = 10; // Large mesh
        large_imported.validator_count = 12; // Large mesh
        large_local.total_validator_stake = 10000;
        large_imported.total_validator_stake = 5000; // Only 50% stake ratio
        
        // Different validator sets to test stake-based overlap
        large_local.validator_set_hash = "local_validators".to_string();
        large_imported.validator_set_hash = "imported_validators".to_string();
        
        // Should reject merge due to insufficient overlap (50% < 67% required)
        assert!(!ChainEvaluator::has_sufficient_validator_overlap(&large_local, &large_imported));
    }

    #[test]
    fn test_mixed_mesh_sizes_medium_requirements() {
        // One small, one large mesh should use medium requirements (~50%)
        let mut small_mesh = create_test_chain(3, 1000, 10, 30);
        let mut large_mesh = create_test_chain(8, 4000, 40, 150);
        
        small_mesh.validator_count = 3; // Small mesh
        large_mesh.validator_count = 15; // Large mesh
        small_mesh.total_validator_stake = 2000;
        large_mesh.total_validator_stake = 4000; // 50% stake ratio
        
        // Should allow merge with medium requirements (~50% overlap)
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&small_mesh, &large_mesh));
    }

    #[test]
    fn test_bft_bridge_node_requirements() {
        // Test the critical BFT bridge node validation for large network merges
        
        // Case 1: Two large networks with insufficient bridge nodes (split-brain risk)
        let mut network_a = create_test_chain(10, 5000, 50, 200);
        let mut network_b = create_test_chain(10, 5000, 60, 250);
        
        network_a.network_size = 100; // Large network
        network_b.network_size = 100; // Large network
        network_a.expected_tps = 10000;
        network_b.expected_tps = 10000;
        network_a.bridge_node_count = 2; // DANGEROUS: Only 2 nodes - split-brain risk!
        network_b.bridge_node_count = 2;
        
        // Should reject merge due to insufficient bridge nodes for large networks
        assert!(!ChainEvaluator::validate_bft_bridge_requirements(&network_a, &network_b));
    }

    #[test]  
    fn test_bft_bridge_node_minimum_requirements() {
        // Test minimum BFT requirements calculation
        
        // Small network: 50 nodes, 1000 TPS
        let min_nodes_small = ChainEvaluator::calculate_minimum_bft_bridge_nodes(50, 1000);
        assert_eq!(min_nodes_small, 7); // BFT minimum: 3*2+1 = 7
        
        // Large network: 200 nodes, 20000 TPS  
        let min_nodes_large = ChainEvaluator::calculate_minimum_bft_bridge_nodes(200, 20000);
        assert_eq!(min_nodes_large, 15); // max(7 BFT, 8 throughput, 15 scale) = 15
        
        // Massive network: 1000 nodes, 50000 TPS
        let min_nodes_massive = ChainEvaluator::calculate_minimum_bft_bridge_nodes(1000, 50000);
        assert_eq!(min_nodes_massive, 32); // max(7 BFT, 20 throughput, 32 scale) = 32
    }

    #[test]
    fn test_sufficient_bridge_nodes_allows_merge() {
        // Test that sufficient bridge nodes allow secure merging
        let mut secure_network_a = create_test_chain(15, 8000, 80, 300);
        let mut secure_network_b = create_test_chain(15, 8000, 90, 350);
        
        secure_network_a.network_size = 150;
        secure_network_b.network_size = 150;
        secure_network_a.expected_tps = 15000;
        secure_network_b.expected_tps = 15000;
        secure_network_a.bridge_node_count = 20; // Sufficient for BFT + throughput (needs 18)
        secure_network_b.bridge_node_count = 20;
        
        // Should allow merge with sufficient bridge nodes
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&secure_network_a, &secure_network_b));
    }

    #[test]
    fn test_throughput_bottleneck_prevention() {
        // Test that high TPS requirements increase minimum bridge nodes
        let mut high_tps_network = create_test_chain(10, 3000, 30, 100);
        let mut normal_network = create_test_chain(10, 3000, 30, 100);
        
        high_tps_network.network_size = 80;
        normal_network.network_size = 80;
        high_tps_network.expected_tps = 25000; // Very high TPS requirement
        normal_network.expected_tps = 25000;
        high_tps_network.bridge_node_count = 5; // Insufficient for throughput
        normal_network.bridge_node_count = 5;
        
        // Should reject due to throughput bottleneck risk
        assert!(!ChainEvaluator::validate_bft_bridge_requirements(&high_tps_network, &normal_network));
        
        // Increase bridge nodes to handle throughput
        high_tps_network.bridge_node_count = 22; // Sufficient for 50k TPS combined (50000/2500 = 20, need 22 for safety)
        normal_network.bridge_node_count = 22;
        
        // Should now allow merge
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&high_tps_network, &normal_network));
    }

    #[test]
    fn test_prevents_split_brain_attack() {
        // Simulate the exact scenario from the analysis:
        // Two 100-node networks trying to merge with only 2 bridge nodes
        let mut cluster_a = create_test_chain(20, 10000, 100, 500);
        let mut cluster_b = create_test_chain(20, 10000, 100, 500);
        
        cluster_a.network_size = 100;
        cluster_b.network_size = 100;
        cluster_a.expected_tps = 10000;
        cluster_b.expected_tps = 10000;
        cluster_a.bridge_node_count = 2; // CRITICAL FLAW: Only 2 bridge nodes!
        cluster_b.bridge_node_count = 2;
        cluster_a.validator_count = 15; // Both have sufficient validators
        cluster_b.validator_count = 15;
        cluster_a.total_validator_stake = 20000; // Different stake amounts to simulate low overlap
        cluster_b.total_validator_stake = 5000;  // Much lower stake = insufficient overlap
        
        // Make validator sets different to test BFT requirements
        cluster_a.validator_set_hash = "cluster_a_validators".to_string();
        cluster_b.validator_set_hash = "cluster_b_validators".to_string();
        
        // Should prevent merge despite good validator overlap due to split-brain risk
        assert!(!ChainEvaluator::has_sufficient_validator_overlap(&cluster_a, &cluster_b));
        
        // Fix by adding sufficient bridge nodes and better stake overlap
        cluster_a.bridge_node_count = 16; // Sufficient BFT + throughput (needs 15 minimum)
        cluster_b.bridge_node_count = 16;
        cluster_b.total_validator_stake = 15000; // Better stake overlap (75% ratio)
        
        // Should now allow secure merge
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&cluster_a, &cluster_b));
    }

    #[test]
    fn test_solo_node_joining_established_network() {
        // FIXED: Solo nodes ARE their own infrastructure - can join anyone!
        let mut solo_node = create_test_chain(1, 100, 1, 5);
        let mut established_network = create_test_chain(15, 5000, 100, 300);
        
        solo_node.network_size = 1; // Solo node
        solo_node.bridge_node_count = 0; // Solo node has NO bridge infrastructure!
        solo_node.validator_count = 1;
        
        established_network.network_size = 200; // Large established network
        established_network.bridge_node_count = 2; // Even inadequate infrastructure
        established_network.validator_count = 20;
        
        // Solo node should be able to join ANY network regardless of infrastructure
        // The solo node IS the infrastructure they're contributing
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_node, &established_network));
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&established_network, &solo_node));
    }

    #[test]
    fn test_small_network_joining_large_network() {
        // Small networks only need basic connectivity (1 bridge node)
        let mut small_network = create_test_chain(3, 500, 10, 30);
        let mut large_network = create_test_chain(20, 8000, 150, 500);
        
        small_network.network_size = 25; // Small community
        small_network.bridge_node_count = 1; // Just needs basic connectivity
        small_network.validator_count = 5;
        
        large_network.network_size = 300; // Large established network
        large_network.bridge_node_count = 20; // Adequate for combined network (needs 19)
        large_network.validator_count = 30;
        
        // Small network can join large network with minimal bridge requirements
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&small_network, &large_network));
    }

    #[test]
    fn test_solo_nodes_merging_together() {
        // Two solo nodes merging should have no bridge requirements
        let mut solo_a = create_test_chain(1, 50, 1, 2);
        let mut solo_b = create_test_chain(1, 60, 1, 3);
        
        solo_a.network_size = 1;
        solo_a.bridge_node_count = 0; // No bridge infrastructure
        solo_b.network_size = 1;
        solo_b.bridge_node_count = 0; // No bridge infrastructure
        
        // Two solo nodes can merge without bridge requirements
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_a, &solo_b));
    }

    #[test]
    fn test_solo_node_can_join_any_network() {
        // Solo nodes can join any network regardless of that network's infrastructure
        let mut solo_node = create_test_chain(1, 100, 1, 5);
        let mut any_network = create_test_chain(10, 3000, 80, 200);
        
        solo_node.network_size = 1;
        solo_node.bridge_node_count = 0; // Solo node (no requirements)
        
        any_network.network_size = 150; // Large network
        any_network.bridge_node_count = 1; // Even minimal infrastructure
        any_network.expected_tps = 15000; // High throughput needs
        
        // Should ALWAYS allow solo nodes to join - they ARE infrastructure
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_node, &any_network));
        
        // Even if the network has zero infrastructure, solo can still join
        any_network.bridge_node_count = 0;
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_node, &any_network));
    }

    // ============================================================================
    // COMPREHENSIVE NETWORK JOINING SCENARIO TESTS
    // ============================================================================

    #[test]
    fn test_scenario_1_solo_to_solo_merging() {
        // Two solo nodes meeting and merging
        let mut alice = create_test_chain(1, 50, 1, 2);
        let mut bob = create_test_chain(1, 60, 1, 3);
        
        alice.network_size = 1;
        alice.bridge_node_count = 0;
        alice.validator_count = 1;
        
        bob.network_size = 1;
        bob.bridge_node_count = 0;
        bob.validator_count = 1;
        
        // Two solo nodes can always merge
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&alice, &bob));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&alice, &bob));
        
        println!(" Solo-to-Solo: Alice + Bob can merge");
    }

    #[test]
    fn test_scenario_2_solo_to_tiny_mesh() {
        // Solo node joining a tiny mesh (2-5 nodes)
        let mut solo_charlie = create_test_chain(1, 100, 1, 5);
        let mut tiny_mesh = create_test_chain(3, 500, 8, 25);
        
        solo_charlie.network_size = 1;
        solo_charlie.bridge_node_count = 0;
        solo_charlie.validator_count = 1;
        
        tiny_mesh.network_size = 4; // Tiny mesh (4 people)
        tiny_mesh.bridge_node_count = 0; // Tiny mesh also has no bridge infrastructure
        tiny_mesh.validator_count = 3;
        
        // Solo can join tiny mesh
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_charlie, &tiny_mesh));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&solo_charlie, &tiny_mesh));
        
        println!(" Solo-to-Tiny: Charlie can join 4-person mesh");
    }

    #[test]
    fn test_scenario_3_solo_to_small_network() {
        // Solo node joining a small network (6-50 nodes)
        let mut solo_dave = create_test_chain(1, 200, 1, 8);
        let mut small_community = create_test_chain(8, 2000, 40, 150);
        
        solo_dave.network_size = 1;
        solo_dave.bridge_node_count = 0;
        solo_dave.validator_count = 1;
        
        small_community.network_size = 25; // Small community
        small_community.bridge_node_count = 2; // Has some infrastructure
        small_community.validator_count = 8;
        
        // Solo can join small network
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_dave, &small_community));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&solo_dave, &small_community));
        
        println!(" Solo-to-Small: Dave can join 25-node community");
    }

    #[test]
    fn test_scenario_4_solo_to_large_enterprise() {
        // Solo node joining a large enterprise network (100+ nodes)
        let mut solo_eve = create_test_chain(1, 150, 1, 6);
        let mut enterprise = create_test_chain(20, 10000, 200, 800);
        
        solo_eve.network_size = 1;
        solo_eve.bridge_node_count = 0;
        solo_eve.validator_count = 1;
        
        enterprise.network_size = 500; // Large enterprise
        enterprise.bridge_node_count = 25; // Proper enterprise infrastructure
        enterprise.validator_count = 50;
        enterprise.expected_tps = 50000;
        
        // Solo can join large enterprise
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&solo_eve, &enterprise));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&solo_eve, &enterprise));
        
        println!(" Solo-to-Enterprise: Eve can join 500-node enterprise");
    }

    #[test]
    fn test_scenario_5_small_to_small_merging() {
        // Two small networks merging together
        let mut startup_a = create_test_chain(5, 1500, 20, 75);
        let mut startup_b = create_test_chain(6, 1800, 25, 90);
        
        startup_a.network_size = 15; // Small startup
        startup_a.bridge_node_count = 1;
        startup_a.validator_count = 4;
        
        startup_b.network_size = 20; // Small startup
        startup_b.bridge_node_count = 8; // Needs to handle combined network (minimum 7)
        startup_b.validator_count = 5;
        
        // Small networks should be able to merge easily
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&startup_a, &startup_b));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&startup_a, &startup_b));
        
        println!(" Small-to-Small: 15-node + 20-node startups can merge");
    }

    #[test]
    fn test_scenario_6_small_to_large_joining() {
        // Small network joining a large network
        let mut small_business = create_test_chain(4, 800, 15, 50);
        let mut large_corp = create_test_chain(25, 12000, 300, 1000);
        
        small_business.network_size = 12; // Small business
        small_business.bridge_node_count = 1; // Minimal connectivity
        small_business.validator_count = 3;
        
        large_corp.network_size = 300; // Large corporation
        large_corp.bridge_node_count = 18; // Adequate infrastructure
        large_corp.validator_count = 30;
        large_corp.expected_tps = 30000;
        
        // Small business should be able to join large corp
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&small_business, &large_corp));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&small_business, &large_corp));
        
        println!(" Small-to-Large: 12-node business can join 300-node corp");
    }

    #[test]
    fn test_scenario_7_small_network_inadequate_bridge() {
        // Small network with inadequate bridge infrastructure trying to join
        let mut inadequate_small = create_test_chain(3, 600, 12, 40);
        let mut large_network = create_test_chain(15, 8000, 150, 600);
        
        inadequate_small.network_size = 8; // Small network
        inadequate_small.bridge_node_count = 0; // NO bridge infrastructure!
        inadequate_small.validator_count = 2;
        
        large_network.network_size = 200; // Large network
        large_network.bridge_node_count = 15; // Adequate infrastructure
        large_network.validator_count = 25;
        
        // Should fail - small network needs at least 1 bridge
        assert!(!ChainEvaluator::validate_bft_bridge_requirements(&inadequate_small, &large_network));
        
        println!(" Small-to-Large BLOCKED: 8-node network needs 1 bridge minimum");
    }

    #[test]
    fn test_scenario_8_large_to_large_successful_merge() {
        // Two large networks with adequate infrastructure merging
        let mut tech_giant_a = create_test_chain(30, 20000, 500, 2000);
        let mut tech_giant_b = create_test_chain(35, 25000, 600, 2500);
        
        tech_giant_a.network_size = 400; // Large tech company
        tech_giant_a.bridge_node_count = 40; // Needs 36 for combined 90k TPS throughput
        tech_giant_a.validator_count = 40;
        tech_giant_a.expected_tps = 40000;
        
        tech_giant_b.network_size = 500; // Large tech company
        tech_giant_b.bridge_node_count = 40; // Needs 36 for combined network
        tech_giant_b.validator_count = 50;
        tech_giant_b.expected_tps = 50000;
        
        // Both have adequate infrastructure for merger
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&tech_giant_a, &tech_giant_b));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&tech_giant_a, &tech_giant_b));
        
        println!(" Large-to-Large: 400-node + 500-node tech giants can merge");
    }

    #[test]
    fn test_scenario_9_large_to_large_inadequate_infrastructure() {
        // Two large networks with inadequate bridge infrastructure
        let mut corp_a = create_test_chain(25, 15000, 400, 1500);
        let mut corp_b = create_test_chain(28, 18000, 450, 1800);
        
        corp_a.network_size = 300; // Large corporation
        corp_a.bridge_node_count = 5; // INADEQUATE! Needs √300 ≈ 17
        corp_a.validator_count = 30;
        corp_a.expected_tps = 30000;
        
        corp_b.network_size = 350; // Large corporation
        corp_b.bridge_node_count = 4; // INADEQUATE! Needs √350 ≈ 19
        corp_b.validator_count = 35;
        corp_b.expected_tps = 35000;
        
        // Should fail - both lack adequate bridge infrastructure
        assert!(!ChainEvaluator::validate_bft_bridge_requirements(&corp_a, &corp_b));
        
        println!(" Large-to-Large BLOCKED: Both corps need more bridge infrastructure");
    }

    #[test]
    fn test_scenario_10_massive_network_requirements() {
        // Testing massive enterprise networks (1000+ nodes)
        let mut mega_corp_a = create_test_chain(50, 100000, 2000, 8000);
        let mut mega_corp_b = create_test_chain(55, 120000, 2500, 10000);
        
        mega_corp_a.network_size = 1000; // Massive enterprise
        mega_corp_a.bridge_node_count = 90; // Needs 88 for combined 220k TPS throughput
        mega_corp_a.validator_count = 100;
        mega_corp_a.expected_tps = 100000;
        
        mega_corp_b.network_size = 1200; // Massive enterprise
        mega_corp_b.bridge_node_count = 90; // Needs 88 for combined network
        mega_corp_b.validator_count = 120;
        mega_corp_b.expected_tps = 120000;
        
        // Massive networks should be able to merge with proper infrastructure
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&mega_corp_a, &mega_corp_b));
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&mega_corp_a, &mega_corp_b));
        
        println!(" Massive-to-Massive: 1000-node + 1200-node mega-corps can merge");
    }

    #[test]
    fn test_scenario_11_throughput_bottleneck_edge_case() {
        // Network with extremely high TPS requirements
        let mut high_freq_network = create_test_chain(15, 5000, 100, 500);
        let mut normal_network = create_test_chain(20, 8000, 150, 600);
        
        high_freq_network.network_size = 100; // Medium size
        high_freq_network.bridge_node_count = 8; // Adequate for size but not TPS
        high_freq_network.validator_count = 15;
        high_freq_network.expected_tps = 50000; // EXTREMELY HIGH TPS! Needs 20 bridges
        
        normal_network.network_size = 120; // Medium size
        normal_network.bridge_node_count = 25; // More than adequate
        normal_network.validator_count = 18;
        normal_network.expected_tps = 10000;
        
        // Should fail due to throughput bottleneck in high-freq network
        assert!(!ChainEvaluator::validate_bft_bridge_requirements(&high_freq_network, &normal_network));
        
        // Fix the throughput issue
        high_freq_network.bridge_node_count = 25; // Now adequate for 50k TPS
        assert!(ChainEvaluator::validate_bft_bridge_requirements(&high_freq_network, &normal_network));
        
        println!(" Throughput Edge Case: High-TPS network needs adequate bridges");
    }

    #[test]
    fn test_scenario_12_validator_overlap_edge_cases() {
        // Testing validator overlap requirements at boundaries
        let mut network_a = create_test_chain(12, 3000, 80, 300);
        let mut network_b = create_test_chain(15, 4000, 100, 400);
        
        // Case A: Small mesh validators (≤5) - should use 33% overlap
        network_a.network_size = 30;
        network_a.bridge_node_count = 10; // Needs 9 for combined network
        network_a.validator_count = 4; // Small validator count
        network_a.total_validator_stake = 8000;
        network_a.validator_set_hash = "network_a_validators".to_string();
        
        network_b.network_size = 40;
        network_b.bridge_node_count = 10; // Needs 9 for combined network
        network_b.validator_count = 5; // Small validator count
        network_b.total_validator_stake = 5000; // 62.5% stake ratio - should pass 33% requirement
        network_b.validator_set_hash = "network_b_validators".to_string();
        
        assert!(ChainEvaluator::has_sufficient_validator_overlap(&network_a, &network_b));
        
        // Case B: Large mesh validators (≥7) - should use 67% overlap
        network_a.validator_count = 10; // Large validator count
        network_b.validator_count = 12; // Large validator count
        // Same stake ratio (62.5%) - should fail 67% requirement
        
        assert!(!ChainEvaluator::has_sufficient_validator_overlap(&network_a, &network_b));
        
        println!(" Validator Overlap: Small meshes easier, large meshes stricter");
    }
}