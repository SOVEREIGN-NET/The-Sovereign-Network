//! Core types for ZHTP consensus system

use async_trait::async_trait;
use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export proof types from proofs module
pub use crate::proofs::{
    ProofOfUsefulWork,
    StakeProof,
    StorageCapacityAttestation,
    WorkProof,
};

// Re-export heartbeat types from validator protocol module
pub use crate::validators::validator_protocol::HeartbeatMessage;

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

impl ConsensusStep {
    /// Convert step to ordinal value for comparison and serialization
    pub fn as_ordinal(&self) -> u8 {
        match self {
            ConsensusStep::Propose => 0,
            ConsensusStep::PreVote => 1,
            ConsensusStep::PreCommit => 2,
            ConsensusStep::Commit => 3,
            ConsensusStep::NewRound => 4,
        }
    }

    /// Convert ordinal value back to ConsensusStep
    pub fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(ConsensusStep::Propose),
            1 => Some(ConsensusStep::PreVote),
            2 => Some(ConsensusStep::PreCommit),
            3 => Some(ConsensusStep::Commit),
            4 => Some(ConsensusStep::NewRound),
            _ => None,
        }
    }
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
    pub storage_proof: Option<StorageCapacityAttestation>,
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

/// Consensus configuration.
///
/// # Validator count bounds
///
/// `max_validators` is the governance-adjustable upper bound on the active
/// validator set.  Its valid range at runtime is:
///
/// - **Minimum**: `MIN_VALIDATORS` (= 4) — the BFT safety floor.
///   Governance MUST NOT lower `max_validators` below this value.
/// - **Maximum**: `MAX_VALIDATORS_HARD_CAP` (= 256) — the protocol ceiling.
///   Governance MUST NOT raise `max_validators` above this value without a
///   network upgrade.
///
/// Both bounds are enforced by `DaoEngine::validate_governance_update()` and
/// clamped in `ValidatorManager::new()`.  The default value is `MAX_VALIDATORS`
/// (= 100).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Type of consensus mechanism
    pub consensus_type: ConsensusType,
    /// Minimum stake required to be a validator (in micro-SOV)
    pub min_stake: u64,
    /// Minimum storage required to be a validator (in bytes)
    pub min_storage: u64,
    /// Governance-adjustable upper bound on the active validator set.
    /// Valid range: `[MIN_VALIDATORS, MAX_VALIDATORS_HARD_CAP]` = `[4, 256]`.
    /// Default: `MAX_VALIDATORS` = 100.
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
            consensus_type: ConsensusType::Hybrid,
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
    /// Consensus stalled due to validator timeouts
    ConsensusStalled {
        height: u64,
        round: u32,
        timed_out_validators: Vec<IdentityId>,
        total_validators: usize,
        timestamp: u64,
    },
    /// Consensus recovered from stall
    ConsensusRecovered {
        height: u64,
        round: u32,
        timestamp: u64,
    },
    /// Mode transition from Bootstrap to BFT
    ModeTransitionToBft {
        validator_count: usize,
        height: u64,
        timestamp: u64,
    },
    /// Mode transition from BFT to Bootstrap (degraded state)
    ModeTransitionToBootstrap {
        validator_count: usize,
        min_required: usize,
        height: u64,
        timestamp: u64,
    },
}

/// Block metadata for fee tracking and statistics
///
/// Tracks fees and other metadata for each finalized block.
/// Used for fee collection integration with consensus layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// Block height
    pub height: u64,
    /// Block timestamp (Unix seconds)
    pub timestamp: i64,
    /// Number of transactions in block
    pub transaction_count: u32,
    /// Total fees collected in this block
    pub total_fees_collected: u64,
    /// Block proposer
    pub proposer: IdentityId,
}

impl BlockMetadata {
    /// Create new block metadata
    pub fn new(height: u64, proposer: IdentityId) -> Self {
        Self {
            height,
            timestamp: chrono::Utc::now().timestamp(),
            transaction_count: 0,
            total_fees_collected: 0,
            proposer,
        }
    }

    /// Create block metadata with all fields
    pub fn with_fees(height: u64, proposer: IdentityId, total_fees: u64) -> Self {
        Self {
            height,
            timestamp: chrono::Utc::now().timestamp(),
            transaction_count: 0,
            total_fees_collected: total_fees,
            proposer,
        }
    }
}

/// Canonical validator message for network broadcast
///
/// Invariant CE-ENG-2: ConsensusEngine broadcasts only signed, canonical ValidatorMessages.
/// It never broadcasts raw Vote, Proposal, or internal structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorMessage {
    /// Proposal message for new block
    Propose {
        proposal: ConsensusProposal,
    },
    /// Vote message (PreVote, PreCommit, or Commit votes)
    Vote {
        vote: ConsensusVote,
    },
    /// Heartbeat message for validator liveness detection
    Heartbeat {
        message: HeartbeatMessage,
    },
}

/// Message broadcaster trait for network distribution
///
/// This trait handles peer-to-peer message distribution.
/// The consensus engine dependency-injects this and calls it as a side effect
/// after state transitions, treating it as best-effort telemetry.
///
/// **Invariant CE-ENG-1**: The consensus engine never constructs, configures, or inspects
/// the broadcaster. It only calls it.
///
/// **Invariant CE-ENG-2**: ConsensusEngine broadcasts only signed, canonical ValidatorMessages.
/// It never broadcasts raw Vote, Proposal, or internal structs.
///
/// **Invariant CE-ENG-3**: Broadcast is a side-effect of a completed consensus step, never a prerequisite.
/// This preserves determinism and replayability.
///
/// **Invariant CE-ENG-4**: Consensus correctness MUST NOT depend on broadcast success, failure,
/// or reachability. No retries. No quorum checks. No "if delivered < X then…".
/// All liveness logic belongs elsewhere (timeouts, view change).
///
/// **Invariant CE-ENG-5**: ConsensusEngine never queries network state to determine "who to send to".
/// The network delivers; consensus decides authority. Validator set is passed explicitly.
///
/// **Invariant CE-ENG-6**: Side-effect isolation. Broadcasting is the only external side-effect
/// ConsensusEngine performs. Everything else stays in memory or storage.
///
/// **Invariant CE-ENG-7**: Deterministic emission. Given the same inputs, ConsensusEngine must emit
/// the same sequence of ValidatorMessages, regardless of network behavior. This is what makes
/// simulation and replay possible.
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Broadcast message to all validators in the given validator set
    ///
    /// Invariant CE-ENG-5: ConsensusEngine passes validator set explicitly.
    /// It never queries network state to determine "who to send to".
    ///
    /// Invariant CE-ENG-4: Consensus correctness MUST NOT depend on broadcast success,
    /// failure, or reachability. This is best-effort telemetry only.
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Blockchain provider for consensus block production
///
/// Provides access to blockchain state needed for creating block proposals:
/// - Latest block hash (for chain continuity)
/// - Pending transactions (for block content)
/// - Current blockchain height (for validation)
///
/// This trait is implemented by the runtime layer and injected into ConsensusEngine.
/// The consensus engine never directly accesses blockchain storage.
///
/// # Thread Safety
/// Implementations must be thread-safe (Send + Sync) as the consensus engine
/// may query blockchain state from multiple async contexts.
#[async_trait]
pub trait ConsensusBlockchainProvider: Send + Sync {
    /// Get the hash of the latest committed block
    ///
    /// Returns the hash of the block at `height - 1` when proposing for `height`.
    /// For genesis (height 0), returns a zero hash.
    async fn get_latest_block_hash(&self) -> Result<Hash, Box<dyn std::error::Error + Send + Sync>>;

    /// Get pending transactions from the mempool
    ///
    /// Returns serialized transactions ready to be included in the next block.
    /// The consensus engine includes these in the proposal's block_data field.
    ///
    /// # Returns
    /// - Serialized transaction data (bincode-encoded Vec<Transaction>)
    /// - Empty Vec if no pending transactions
    async fn get_pending_transactions(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get current blockchain height
    ///
    /// Used to validate that consensus height matches blockchain height.
    async fn get_blockchain_height(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Check if blockchain is ready for block production
    ///
    /// Returns false during initialization or sync.
    async fn is_ready(&self) -> bool;
}

/// No-op blockchain provider for testing or when blockchain is not available
pub struct NoOpBlockchainProvider;

#[async_trait]
impl ConsensusBlockchainProvider for NoOpBlockchainProvider {
    async fn get_latest_block_hash(&self) -> Result<Hash, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Hash([0u8; 32]))
    }

    async fn get_pending_transactions(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }

    async fn get_blockchain_height(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0)
    }

    async fn is_ready(&self) -> bool {
        false
    }
}

/// Callback for committing finalized blocks to the blockchain
///
/// When BFT consensus achieves 2/3+1 commit votes on a proposal, this callback
/// is invoked to actually commit the block to the blockchain storage.
///
/// This separates consensus finalization from block storage:
/// - ConsensusEngine determines WHEN a block is finalized (BFT safety)
/// - BlockCommitCallback determines HOW the block is stored (blockchain layer)
///
/// # Thread Safety
/// Implementations must be thread-safe (Send + Sync) as the consensus engine
/// may finalize blocks from multiple async contexts.
#[async_trait]
pub trait BlockCommitCallback: Send + Sync {
    /// Commit a finalized block to the blockchain
    ///
    /// Called when BFT consensus achieves supermajority (2/3+1) commit votes.
    /// The proposal contains the block data that was agreed upon.
    ///
    /// # Arguments
    /// * `proposal` - The consensus proposal that was finalized
    ///
    /// # Returns
    /// * `Ok(())` - Block was successfully committed
    /// * `Err(...)` - Block commit failed (logged but does not affect consensus)
    ///
    /// # Invariants
    /// - This callback is best-effort; consensus correctness does not depend on it
    /// - The same block may be committed multiple times (idempotent handling required)
    async fn commit_finalized_block(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Get the number of active validators for mode switching
    ///
    /// Returns the count of validators currently registered and active.
    /// Used by the mining loop to determine whether to use BFT consensus
    /// (4+ validators) or bootstrap mode (< 4 validators).
    async fn get_active_validator_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>;
}

/// Minimum validators required for BFT consensus mode
///
/// With fewer validators, the network operates in bootstrap mode where
/// a single validator can mine blocks directly. Once this threshold is
/// reached, all block production must go through BFT consensus.
///
/// Value: 4 validators (allows 1 Byzantine fault with f < n/3)
pub const MIN_BFT_VALIDATORS: usize = 4;

// ============================================================================
// FEE COLLECTION TRAIT
// ============================================================================

/// Fee distribution result from a distribution operation
///
/// Represents the breakdown of fees distributed to different pools
/// according to the 45/30/15/10 split:
/// - 45% UBI pool
/// - 30% Consensus/DAO pool
/// - 15% Governance/Emergency reserve
/// - 10% Treasury/Development grants
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

    /// Calculate distribution from total fees using 45/30/15/10 split
    pub fn from_total_fees(total_fees: u64) -> Self {
        let ubi_amount = total_fees * 45 / 100;
        let consensus_amount = total_fees * 30 / 100;
        let governance_amount = total_fees * 15 / 100;
        let treasury_amount = total_fees * 10 / 100;
        Self::new(ubi_amount, consensus_amount, governance_amount, treasury_amount)
    }
}

/// Fee collector trait for consensus-blockchain integration
///
/// This trait defines the interface for fee collection and distribution
/// during block finalization. It is implemented by the FeeRouter contract
/// in lib-blockchain and used by ConsensusEngine.
///
/// # Thread Safety
/// Implementations must be thread-safe (Send + Sync) as fee collection
/// may occur from multiple async contexts during block finalization.
///
/// # Invariants
/// - **FC-1**: Fee collection is a side-effect of block finalization, not a prerequisite
/// - **FC-2**: Fee distribution follows the 45/30/15/10 split exactly
/// - **FC-3**: Distribution is permissionless (anyone can trigger via block finalization)
/// - **FC-4**: All arithmetic uses integer math (no floating point)
pub trait FeeCollector: Send + Sync {
    /// Collect fees for the current block
    ///
    /// Called during block finalization to record fees collected from transactions.
    /// The fees are accumulated until distributed.
    ///
    /// # Arguments
    /// * `amount` - The total fees collected from the block
    ///
    /// # Returns
    /// * `Ok(())` - Fees were collected successfully
    /// * `Err(...)` - Collection failed (fee router not initialized, overflow, etc.)
    fn collect_fee(&mut self, amount: u64) -> Result<(), String>;

    /// Distribute collected fees to pools
    ///
    /// Called during block finalization to distribute accumulated fees
    /// according to the 45/30/15/10 split.
    ///
    /// # Arguments
    /// * `block_height` - The height of the block being finalized
    ///
    /// # Returns
    /// * `Ok(FeeDistributionResult)` - Distribution amounts for each pool
    /// * `Err(...)` - Distribution failed
    fn distribute_fees(&mut self, block_height: u64) -> Result<FeeDistributionResult, String>;

    /// Check if the fee collector is initialized and ready
    fn is_initialized(&self) -> bool;

    /// Get total fees collected but not yet distributed
    fn pending_fees(&self) -> u64;

    /// Get total fees ever collected (audit trail)
    fn total_collected(&self) -> u64;

    /// Get total fees ever distributed (audit trail)
    fn total_distributed(&self) -> u64;
}
