//! Consensus primitives for the Sovereign Network.
//!
//! Pure data types for consensus. Complex types with crypto dependencies
//! remain in lib-consensus and are migrated incrementally.

use serde::{Deserialize, Serialize};

// =============================================================================
// PHASE 1: Simple Enums (no external dependencies)
// =============================================================================

/// Consensus mechanism types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusType {
    /// Proof of Stake consensus
    ProofOfStake,
    /// Proof of Storage consensus
    ProofOfStorage,
    /// Proof of Useful Work consensus
    ProofOfUsefulWork,
    /// Byzantine Fault Tolerance
    #[serde(alias = "Hybrid")]
    ByzantineFaultTolerance,
}

/// Types of useful work that can be performed for consensus rewards
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UsefulWorkType {
    /// Network packet routing and mesh forwarding
    NetworkRouting,
    /// Data storage and retrieval services
    DataStorage,
    /// Computational processing for other nodes
    Computation,
    /// Network validation and consensus participation
    Validation,
    /// Cross-chain bridge operations
    BridgeOperations,
}

/// Validator status in the consensus network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorStatus {
    /// Active validator participating in consensus
    Active,
    /// Inactive validator (not participating)
    Inactive,
    /// Slashed validator (penalized)
    Slashed,
    /// Jailed validator (temporarily suspended)
    Jailed,
}

/// Vote types for consensus
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VoteType {
    /// Pre-vote for a proposal
    PreVote = 1,
    /// Pre-commit for a proposal
    PreCommit = 2,
    /// Final commit vote
    Commit = 3,
    /// Vote against a proposal
    Against = 4,
}

/// Consensus step in the BFT protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
pub enum ConsensusStep {
    /// Propose step - validator proposes a block
    Propose,
    /// Prevote step - validators vote on proposals
    PreVote,
    /// Precommit step - validators commit to a proposal
    PreCommit,
    /// Commit step - finalize the block
    Commit,
    /// New round initialization
    NewRound,
}

/// Types of slashing events
#[derive(Debug, Clone, PartialEq)]
pub enum SlashType {
    /// Double signing (signing multiple blocks at same height)
    DoubleSign,
    /// Liveness violation (not participating in consensus)
    Liveness,
    /// Invalid proposal
    InvalidProposal,
    /// Invalid vote
    InvalidVote,
}

// =============================================================================
// PHASE 2: Simple Structs (minimal external dependencies)
// =============================================================================

/// Consensus configuration
///
/// # Validator count bounds
///
/// `max_validators` is the governance-adjustable upper bound on the active
/// validator set. Its valid range at runtime is:
///
/// - **Minimum**: `MIN_VALIDATORS` (= 4) — the BFT safety floor
/// - **Maximum**: `MAX_VALIDATORS_HARD_CAP` (= 256) — the protocol ceiling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Type of consensus mechanism
    pub consensus_type: ConsensusType,
    /// Minimum stake required to be a validator (in micro-SOV)
    pub min_stake: u64,
    /// Minimum storage required to be a validator (in bytes)
    pub min_storage: u64,
    /// Governance-adjustable upper bound on the active validator set
    pub max_validators: u32,
    /// Target block time in seconds
    pub block_time: u64,
    /// Epoch length in blocks for validator set updates
    pub epoch_length_blocks: u64,
    /// Proposal timeout in milliseconds
    pub propose_timeout: u64,
    /// Prevote timeout in milliseconds
    pub prevote_timeout: u64,
    /// Precommit timeout in milliseconds
    pub precommit_timeout: u64,
    /// Maximum transactions per block
    pub max_transactions_per_block: u32,
    /// Maximum difficulty for PoUW
    pub max_difficulty: u64,
    /// Target difficulty for PoUW
    pub target_difficulty: u64,
    /// Byzantine fault tolerance threshold (typically 1/3)
    pub byzantine_threshold: f64,
    /// Slashing percentage for double signing
    pub slash_double_sign: u8,
    /// Slashing percentage for liveness violation
    pub slash_liveness: u8,
    /// Development mode flag - allows single validator consensus for testing
    pub development_mode: bool,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            consensus_type: ConsensusType::ByzantineFaultTolerance,
            min_stake: 1000 * 1_000_000,           // 1000 SOV tokens
            min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
            max_validators: 100,
            block_time: 10,          // 10 seconds
            epoch_length_blocks: 100,
            propose_timeout: 3000,   // 3 seconds
            prevote_timeout: 1000,   // 1 second
            precommit_timeout: 1000, // 1 second
            max_transactions_per_block: 1000,
            max_difficulty: 0x00000000FFFFFFFF,
            target_difficulty: 0x00000FFF,
            byzantine_threshold: 1.0 / 3.0, // 1/3 Byzantine tolerance
            slash_double_sign: 5,           // 5% slash for double signing
            slash_liveness: 1,              // 1% slash for liveness violation
            development_mode: false,        // Production mode by default
        }
    }
}

/// Fee distribution result from a distribution operation
///
/// Represents the breakdown of fees distributed to different pools
/// according to the 45/30/15/10 split
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FeeDistributionResult {
    /// Amount sent to UBI pool (45%)
    pub ubi_amount: u64,
    /// Amount sent to Consensus rewards pool (30%)
    pub consensus_amount: u64,
    /// Amount sent to Governance pool (15%)
    pub governance_amount: u64,
    /// Amount sent to Treasury pool (10%)
    pub treasury_amount: u64,
    /// Total amount distributed
    pub total_distributed: u64,
}

impl FeeDistributionResult {
    /// Create a new fee distribution result
    pub fn new(
        ubi_amount: u64,
        consensus_amount: u64,
        governance_amount: u64,
        treasury_amount: u64,
    ) -> Self {
        Self {
            ubi_amount,
            consensus_amount,
            governance_amount,
            treasury_amount,
            total_distributed: ubi_amount + consensus_amount + governance_amount + treasury_amount,
        }
    }

}

/// Minimum validators required for BFT consensus mode
///
/// With fewer validators, the network operates in bootstrap mode where
/// a single validator can mine blocks directly.
pub const MIN_BFT_VALIDATORS: usize = 4;

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_type_variants() {
        let types = vec![
            ConsensusType::ProofOfStake,
            ConsensusType::ProofOfStorage,
            ConsensusType::ProofOfUsefulWork,
            ConsensusType::ByzantineFaultTolerance,
        ];
        for ct in types {
            let serialized = serde_json::to_string(&ct).unwrap();
            let deserialized: ConsensusType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(ct, deserialized);
        }
    }

    #[test]
    fn test_vote_type_discriminants() {
        assert_eq!(VoteType::PreVote as u8, 1);
        assert_eq!(VoteType::PreCommit as u8, 2);
        assert_eq!(VoteType::Commit as u8, 3);
        assert_eq!(VoteType::Against as u8, 4);
    }

    #[test]
    fn test_consensus_step_ordering() {
        assert!(ConsensusStep::Propose < ConsensusStep::PreVote);
        assert!(ConsensusStep::PreVote < ConsensusStep::PreCommit);
        assert!(ConsensusStep::PreCommit < ConsensusStep::Commit);
        assert!(ConsensusStep::Commit < ConsensusStep::NewRound);
    }

    #[test]
    fn test_consensus_config_default() {
        let config = ConsensusConfig::default();
        assert_eq!(config.max_validators, 100);
        assert_eq!(config.block_time, 10);
        assert_eq!(config.min_stake, 1000 * 1_000_000);
        assert!(matches!(config.consensus_type, ConsensusType::ByzantineFaultTolerance));
    }

    #[test]
    fn test_consensus_config_serialization() {
        let config = ConsensusConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: ConsensusConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.max_validators, deserialized.max_validators);
        assert_eq!(config.min_stake, deserialized.min_stake);
    }

    #[test]
    fn test_fee_distribution_result() {
        let result = FeeDistributionResult::from_total_fees(1000);
        assert_eq!(result.ubi_amount, 450);        // 45%
        assert_eq!(result.consensus_amount, 300);  // 30%
        assert_eq!(result.governance_amount, 150); // 15%
        assert_eq!(result.treasury_amount, 100);   // 10%
        assert_eq!(result.total_distributed, 1000);
    }

    #[test]
    fn test_fee_distribution_new() {
        let result = FeeDistributionResult::new(100, 200, 300, 400);
        assert_eq!(result.ubi_amount, 100);
        assert_eq!(result.consensus_amount, 200);
        assert_eq!(result.governance_amount, 300);
        assert_eq!(result.treasury_amount, 400);
        assert_eq!(result.total_distributed, 1000);
    }

    #[test]
    fn test_min_bft_validators_constant() {
        assert_eq!(MIN_BFT_VALIDATORS, 4);
    }

    #[test]
    fn test_validator_status_variants() {
        let statuses = vec![
            ValidatorStatus::Active,
            ValidatorStatus::Inactive,
            ValidatorStatus::Slashed,
            ValidatorStatus::Jailed,
        ];
        for status in statuses {
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: ValidatorStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_useful_work_type_variants() {
        let work_types = vec![
            UsefulWorkType::NetworkRouting,
            UsefulWorkType::DataStorage,
            UsefulWorkType::Computation,
            UsefulWorkType::Validation,
            UsefulWorkType::BridgeOperations,
        ];
        for wt in work_types {
            let serialized = serde_json::to_string(&wt).unwrap();
            let deserialized: UsefulWorkType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(wt, deserialized);
        }
    }

    #[test]
    fn test_slash_type_variants() {
        let types = vec![
            SlashType::DoubleSign,
            SlashType::Liveness,
            SlashType::InvalidProposal,
            SlashType::InvalidVote,
        ];
        for st in types {
            // SlashType doesn't implement Serialize, just verify it exists
            let _ = format!("{:?}", st);
        }
    }
}
