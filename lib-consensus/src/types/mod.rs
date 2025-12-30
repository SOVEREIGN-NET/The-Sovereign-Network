//! Core types for ZHTP consensus system

use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export proof types from proofs module
pub use crate::proofs::{ProofOfUsefulWork, StakeProof, StorageChallenge, StorageProof, WorkProof};

/// Consensus mechanism types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusType {
    /// Proof of Stake consensus
    ProofOfStake,
    /// Proof of Storage consensus
    ProofOfStorage,
    /// Proof of Useful Work consensus  
    ProofOfUsefulWork,
    /// Hybrid PoS + PoStorage
    Hybrid,
    /// Byzantine Fault Tolerance
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Consensus round information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRound {
    /// Current block height
    pub height: u64,
    /// Current round number
    pub round: u32,
    /// Current consensus step
    pub step: ConsensusStep,
    /// Round start time
    pub start_time: u64,
    /// Proposer for this round
    pub proposer: Option<IdentityId>,
    /// Received proposals
    pub proposals: Vec<Hash>,
    /// Received votes
    pub votes: HashMap<Hash, Vec<Hash>>,
    /// Whether this round has timed out
    pub timed_out: bool,
    /// Locked proposal (if any)
    pub locked_proposal: Option<Hash>,
    /// Valid proposal (if any)
    pub valid_proposal: Option<Hash>,
}

/// Consensus proposal for new blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// Proposal identifier
    pub id: Hash,
    /// Proposer validator
    pub proposer: IdentityId,
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub previous_hash: Hash,
    /// Proposed block data
    pub block_data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Proposer signature
    pub signature: PostQuantumSignature,
    /// Proof of stake/storage
    pub consensus_proof: ConsensusProof,
}

/// Consensus vote on a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// Vote identifier
    pub id: Hash,
    /// Voter validator
    pub voter: IdentityId,
    /// Proposal being voted on
    pub proposal_id: Hash,
    /// Vote type
    pub vote_type: VoteType,
    /// Block height
    pub height: u64,
    /// Voting round
    pub round: u32,
    /// Timestamp
    pub timestamp: u64,
    /// Voter signature
    pub signature: PostQuantumSignature,
}

/// Consensus proof combining different proof types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProof {
    /// Consensus mechanism type
    pub consensus_type: ConsensusType,
    /// Stake proof (for PoS)
    pub stake_proof: Option<StakeProof>,
    /// Storage proof (for PoStorage)
    pub storage_proof: Option<StorageProof>,
    /// Useful work proof (for PoUW)
    pub work_proof: Option<WorkProof>,
    /// ZK-DID proof for validator identity
    pub zk_did_proof: Option<Vec<u8>>,
    /// Timestamp
    pub timestamp: u64,
}

/// Network state for validation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkState {
    pub total_participants: u64,
    pub average_uptime: f64,
    pub total_bandwidth_shared: u64,
    pub consensus_round: u64,
}

/// Compute result for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeResult {
    pub node_id: [u8; 32],
    pub work_units: u64,
    pub computation_hash: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl ComputeResult {
    pub fn verify(&self) -> anyhow::Result<bool> {
        // Verify compute result authenticity
        // In production, this would verify computation proofs and signatures
        Ok(self.work_units > 0 && !self.signature.is_empty())
    }
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Type of consensus mechanism
    pub consensus_type: ConsensusType,
    /// Minimum stake required to be a validator (in micro-ZHTP)
    pub min_stake: u64,
    /// Minimum storage required to be a validator (in bytes)
    pub min_storage: u64,
    /// Maximum number of validators
    pub max_validators: u32,
    /// Target block time in seconds
    pub block_time: u64,
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
            consensus_type: ConsensusType::Hybrid,
            min_stake: 1000 * 1_000_000,           // 1000 ZHTP tokens
            min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
            max_validators: 100,
            block_time: 10,          // 10 seconds
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

/// Consensus events for pure component communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusEvent {
    /// Start a new consensus round
    StartRound { height: u64, trigger: String },
    /// New block available for consensus
    NewBlock { height: u64, previous_hash: Hash },
    /// Validator joining consensus
    ValidatorJoin { identity: IdentityId, stake: u64 },
    /// Validator leaving consensus
    ValidatorLeave { identity: IdentityId },
    /// Round prepared and ready
    RoundPrepared { height: u64 },
    /// Round completed successfully
    RoundCompleted { height: u64 },
    /// Round failed with error
    RoundFailed { height: u64, error: String },
    /// Validator registered successfully
    ValidatorRegistered { identity: IdentityId },
    /// DAO error occurred
    DaoError { error: String },
    /// Byzantine fault detected
    ByzantineFault { error: String },
    /// Reward calculation error
    RewardError { error: String },
    /// Proposal received
    ProposalReceived { proposal: ConsensusProposal },
    /// Vote received
    VoteReceived { vote: ConsensusVote },
}
