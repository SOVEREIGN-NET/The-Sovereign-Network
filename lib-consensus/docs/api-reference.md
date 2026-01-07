# ZHTP Consensus API Reference

## Table of Contents

- [Consensus Engine](#consensus-engine)
- [Validator Management](#validator-management)
- [DAO Governance](#dao-governance)
- [Difficulty Management](#difficulty-management)
- [Reward System](#reward-system)
- [Byzantine Fault Detection](#byzantine-fault-detection)
- [Proof Systems](#proof-systems)
- [Types and Data Structures](#types-and-data-structures)

## Consensus Engine

### ConsensusEngine

The main consensus engine that combines all consensus mechanisms.

```rust
pub struct ConsensusEngine {
    // Core consensus state
}
```

#### Methods

**`new(config: ConsensusConfig, broadcaster: Arc<dyn MessageBroadcaster>) -> ConsensusResult<Self>`**
- Creates a new consensus engine
- `config`: Consensus configuration
- `broadcaster`: Message broadcaster for network distribution
- Returns: New ConsensusEngine instance

**`register_validator(identity: IdentityId, stake: u64, storage_capacity: u64, consensus_key: Vec<u8>, commission_rate: u8, is_genesis: bool) -> ConsensusResult<()>`**
- Registers a new validator
- `identity`: Validator identity
- `stake`: Staked amount in micro-ZHTP
- `storage_capacity`: Storage capacity in bytes
- `consensus_key`: Validator's consensus public key
- `commission_rate`: Commission rate (0-100)
- `is_genesis`: Whether this is a genesis validator

**`start_consensus() -> ConsensusResult<()>`**
- Starts the consensus process
- Begins processing blocks and participating in consensus

**`handle_consensus_event(event: ConsensusEvent) -> ConsensusResult<Vec<ConsensusEvent>>`**
- Handles a consensus event (event-driven architecture)
- `event`: Consensus event to handle
- Returns: Vector of resulting events

**`dao_engine() -> &DaoEngine`**
- Gets a reference to the DAO engine

**`dao_engine_mut() -> &mut DaoEngine`**
- Gets a mutable reference to the DAO engine

**`validator_manager() -> &ValidatorManager`**
- Gets a reference to the validator manager

**`current_round() -> &ConsensusRound`**
- Gets the current consensus round information

**`config() -> &ConsensusConfig`**
- Gets the consensus configuration

### ConsensusConfig

Configuration for the consensus engine.

```rust
pub struct ConsensusConfig {
    pub consensus_type: ConsensusType,
    pub min_stake: u64,
    pub min_storage: u64,
    pub max_validators: u32,
    pub block_time: u64,
    pub propose_timeout: u64,
    pub prevote_timeout: u64,
    pub precommit_timeout: u64,
    pub max_transactions_per_block: u32,
    pub max_difficulty: u64,
    pub target_difficulty: u64,
    pub byzantine_threshold: f64,
    pub slash_double_sign: u8,
    pub slash_liveness: u8,
    pub development_mode: bool,
}
```

### ConsensusEvent

Events used for communication between consensus components.

```rust
pub enum ConsensusEvent {
    StartRound { height: u64, trigger: String },
    NewBlock { height: u64, previous_hash: Hash },
    ValidatorJoin { identity: IdentityId, stake: u64 },
    ValidatorLeave { identity: IdentityId },
    RoundPrepared { height: u64 },
    RoundCompleted { height: u64 },
    RoundFailed { height: u64, error: String },
    ValidatorRegistered { identity: IdentityId },
    DaoError { error: String },
    ByzantineFault { error: String },
    RewardError { error: String },
    ProposalReceived { proposal: ConsensusProposal },
    VoteReceived { vote: ConsensusVote },
    ConsensusStalled { height: u64, round: u32, timed_out_validators: Vec<IdentityId>, total_validators: usize, timestamp: u64 },
    ConsensusRecovered { height: u64, round: u32, timestamp: u64 },
}
```

## Validator Management

### ValidatorManager

Manages the set of validators in the consensus system.

```rust
pub struct ValidatorManager {
    // Validator management state
}
```

#### Methods

**`new(max_validators: u32, min_stake: u64) -> Self`**
- Creates a new validator manager
- `max_validators`: Maximum number of validators
- `min_stake`: Minimum stake required

**`register_validator(identity: IdentityId, stake: u64, storage_provided: u64, consensus_key: Vec<u8>, commission_rate: u8) -> Result<()>`**
- Registers a new validator
- `identity`: Validator identity
- `stake`: Staked amount
- `storage_provided`: Storage capacity
- `consensus_key`: Consensus public key
- `commission_rate`: Commission rate

**`remove_validator(identity: &IdentityId) -> Result<()>`**
- Removes a validator
- `identity`: Validator identity to remove

**`get_validator(identity: &IdentityId) -> Option<&Validator>`**
- Gets a validator by identity
- Returns: Optional reference to validator

**`get_active_validators() -> Vec<&Validator>`**
- Gets all active validators
- Returns: Vector of active validator references

**`select_proposer(height: u64, round: u32) -> Option<&Validator>`**
- Selects proposer for a given height and round
- Uses deterministic round-robin selection
- Returns: Optional reference to selected proposer

**`slash_validator(identity: &IdentityId, slash_type: SlashType, slash_percentage: u8) -> Result<u64>`**
- Slashes a validator for misbehavior
- `identity`: Validator identity
- `slash_type`: Type of slashing
- `slash_percentage`: Percentage to slash
- Returns: Amount slashed

**`update_validator_activity(identity: &IdentityId)`**
- Updates validator's last activity timestamp

**`is_validator(identity: &IdentityId) -> bool`**
- Checks if a validator exists and is active

**`get_validator_stats() -> ValidatorStats`**
- Gets validator statistics
- Returns: ValidatorStats struct

**`get_byzantine_threshold() -> u64`**
- Calculates Byzantine fault tolerance threshold
- Returns: Threshold voting power

### Validator

Represents a consensus validator.

```rust
pub struct Validator {
    pub identity: IdentityId,
    pub stake: u64,
    pub storage_provided: u64,
    pub status: ValidatorStatus,
    pub consensus_key: Vec<u8>,
    pub voting_power: u64,
    pub commission_rate: u8,
    pub reputation: u32,
    pub last_activity: u64,
    pub slash_count: u32,
    pub jail_until: Option<u64>,
}
```

#### Methods

**`new(identity: IdentityId, stake: u64, storage_provided: u64, consensus_key: Vec<u8>, commission_rate: u8) -> Self`**
- Creates a new validator

**`can_participate() -> bool`**
- Checks if validator can participate in consensus

**`slash(slash_type: SlashType, slash_percentage: u8) -> anyhow::Result<u64>`**
- Slashes the validator
- Returns: Amount slashed

**`jail(duration_seconds: u64)`**
- Jails validator for specified duration

**`try_release_from_jail() -> bool`**
- Attempts to release validator from jail if time expired
- Returns: True if released

**`update_activity()`**
- Updates last activity timestamp

**`is_inactive(max_inactive_seconds: u64) -> bool`**
- Checks if validator has been inactive too long

**`effective_reputation() -> f64`**
- Calculates effective reputation score

**`add_stake(amount: u64)`**
- Adds stake to validator

**`remove_stake(amount: u64) -> anyhow::Result<()>`**
- Removes stake from validator

## DAO Governance

### DaoEngine

DAO governance engine for ZHTP.

```rust
pub struct DaoEngine {
    // DAO governance state
}
```

#### Methods

**`new() -> Self`**
- Creates a new DAO engine

**`create_dao_proposal(proposer: IdentityId, title: String, description: String, proposal_type: DaoProposalType, voting_period_days: u32) -> Result<Hash>`**
- Creates a new DAO proposal
- Returns: Proposal ID

**`cast_dao_vote(voter: IdentityId, proposal_id: Hash, vote_choice: DaoVoteChoice, justification: Option<String>) -> Result<Hash>`**
- Casts a DAO vote
- Returns: Vote ID

**`get_dao_voting_power(user_id: &IdentityId) -> u64`**
- Calculates DAO voting power for a user
- Returns: Voting power

**`calculate_voting_power(token_balance: u64, staked_amount: u64, network_contribution_score: u32, reputation_score: u32, delegated_power: u64) -> u64`**
- Calculates total voting power from components
- Returns: Total voting power

**`encode_execution_params(params: &DaoExecutionParams) -> Result<Vec<u8>>`**
- Encodes execution parameters for on-chain proposal submission

**`decode_execution_params(params: &[u8]) -> Result<DaoExecutionParams>`**
- Decodes execution parameters from on-chain proposal data

**`apply_execution_params(config: &mut ConsensusConfig, params: &DaoExecutionParams) -> Result<()>`**
- Applies governance parameter updates to consensus configuration

**`apply_governance_update_from_proposal(proposal: &DaoProposal, config: &mut ConsensusConfig) -> Result<()>`**
- Applies governance parameter update proposal parameters to consensus configuration

**`process_expired_proposals() -> Result<()>`**
- Processes expired proposals (deprecated - use blockchain methods)

**`get_dao_treasury() -> DaoTreasury`**
- Gets DAO treasury state (deprecated - use blockchain methods)

> **Note:** For full documentation on Difficulty Management, see the [Difficulty Management](#difficulty-management) section below.

### DaoProposal

Represents a DAO proposal.

```rust
pub struct DaoProposal {
    pub id: Hash,
    pub title: String,
    pub description: String,
    pub proposer: IdentityId,
    pub proposal_type: DaoProposalType,
    pub status: DaoProposalStatus,
    pub voting_start_time: u64,
    pub voting_end_time: u64,
    pub quorum_required: u64,
    pub vote_tally: DaoVoteTally,
    pub created_at: u64,
    pub created_at_height: u64,
    pub execution_params: Option<Vec<u8>>,
    pub ubi_impact: Option<UbiImpact>,
    pub economic_impact: Option<EconomicImpact>,
    pub privacy_level: PrivacyLevel,
}
```

### DaoExecutionParams

Execution parameters encoded into DAO proposals (bincode).

```rust
pub struct DaoExecutionParams {
    pub action: DaoExecutionAction,
}

pub enum DaoExecutionAction {
    GovernanceParameterUpdate(GovernanceParameterUpdate),
}

pub struct GovernanceParameterUpdate {
    pub updates: Vec<GovernanceParameterValue>,
}

pub enum GovernanceParameterValue {
    // Consensus engine parameters
    MinStake(u64),
    MinStorage(u64),
    MaxValidators(u32),
    BlockTime(u64),
    ProposeTimeout(u64),
    PrevoteTimeout(u64),
    PrecommitTimeout(u64),
    MaxTransactionsPerBlock(u32),
    MaxDifficulty(u64),              // PoUW difficulty (not blockchain mining)
    TargetDifficulty(u64),           // PoUW difficulty (not blockchain mining)
    ByzantineThreshold(f64),
    SlashDoubleSign(u8),
    SlashLiveness(u8),
    DevelopmentMode(bool),
    // Blockchain mining difficulty parameters (delegated to DifficultyManager)
    BlockchainInitialDifficulty(u32),    // Initial difficulty for genesis block
    BlockchainAdjustmentInterval(u64),   // Blocks between difficulty adjustments
    BlockchainTargetTimespan(u64),       // Target time for adjustment interval (seconds)
}
```

### DaoVote

Represents a DAO vote.

```rust
pub struct DaoVote {
    pub id: Hash,
    pub voter: IdentityId,
    pub proposal_id: Hash,
    pub vote_choice: DaoVoteChoice,
    pub voting_power: u64,
    pub timestamp: u64,
    pub justification: Option<String>,
    pub signature: Option<Signature>,
}
```

## Difficulty Management

The consensus package owns the blockchain mining difficulty adjustment policy. This ensures that difficulty parameters can be governed via DAO proposals and maintains clear separation of concerns.

### DifficultyManager

Manages blockchain mining difficulty calculations and DAO governance updates.

```rust
pub struct DifficultyManager {
    config: DifficultyConfig,
}
```

#### Methods

**`new(config: DifficultyConfig) -> Self`**
- Creates a new difficulty manager with the given configuration
- `config`: Initial difficulty configuration
- Returns: New DifficultyManager instance

**`default() -> Self`**
- Creates a new difficulty manager with Bitcoin-compatible defaults
- Initial difficulty: `0x1d00ffff`
- Adjustment interval: `2016` blocks
- Target timespan: `1209600` seconds (2 weeks)

**`config() -> &DifficultyConfig`**
- Gets the current difficulty configuration
- Returns: Reference to DifficultyConfig

**`initial_difficulty() -> u32`**
- Gets the initial difficulty value
- Returns: Initial difficulty in Bitcoin compact format

**`adjustment_interval() -> u64`**
- Gets the adjustment interval (blocks between difficulty adjustments)
- Returns: Number of blocks

**`target_timespan() -> u64`**
- Gets the target timespan for adjustment intervals
- Returns: Target time in seconds

**`should_adjust(height: u64) -> bool`**
- Checks if difficulty should be adjusted at the given block height
- `height`: Current blockchain height
- Returns: `true` if adjustment should occur

**`calculate_new_difficulty(current_difficulty: u32, actual_timespan: u64) -> DifficultyResult<u32>`**
- Calculates new difficulty based on actual vs target timespan
- `current_difficulty`: Current difficulty in compact format
- `actual_timespan`: Actual time taken for the last interval (seconds)
- Returns: New difficulty value, clamped to prevent extreme changes (4x max)
- Algorithm: `new_difficulty = current * target_timespan / actual_timespan`

**`adjust_difficulty(height: u64, current_difficulty: u32, interval_start_time: u64, interval_end_time: u64) -> DifficultyResult<Option<u32>>`**
- Main entry point for difficulty adjustment
- `height`: Current blockchain height
- `current_difficulty`: Current difficulty value
- `interval_start_time`: Timestamp of block at start of interval
- `interval_end_time`: Timestamp of current block
- Returns: `Some(new_difficulty)` if adjustment occurred, `None` otherwise

**`apply_governance_update(initial_difficulty: Option<u32>, adjustment_interval: Option<u64>, target_timespan: Option<u64>) -> DifficultyResult<()>`**
- Applies DAO governance updates to difficulty parameters
- All parameters are optional (only specified parameters are updated)
- Validates configuration before applying (no zero values, no invalid ranges)
- Returns: `Ok(())` if successful, `Err(...)` if validation fails

**`set_min_difficulty(min_difficulty: u32) -> DifficultyResult<()>`**
- Sets the minimum difficulty bound
- `min_difficulty`: Minimum allowed difficulty
- Returns: Error if `min_difficulty > max_difficulty`

**`set_max_difficulty(max_difficulty: u32) -> DifficultyResult<()>`**
- Sets the maximum difficulty bound
- `max_difficulty`: Maximum allowed difficulty
- Returns: Error if `max_difficulty < min_difficulty`

**`set_max_adjustment_factor(factor: u64) -> DifficultyResult<()>`**
- Sets the maximum adjustment factor per interval
- `factor`: Maximum multiplier/divisor for difficulty changes
- Default: `4` (difficulty can at most quadruple or quarter per interval)

### DifficultyConfig

Configuration for blockchain difficulty adjustment.

```rust
pub struct DifficultyConfig {
    pub initial_difficulty: u32,
    pub adjustment_interval: u64,
    pub target_timespan: u64,
    pub min_difficulty: u32,
    pub max_difficulty: u32,
    pub max_adjustment_factor: u64,
}
```

**Fields:**
- `initial_difficulty`: Initial difficulty for genesis block (Bitcoin compact format)
- `adjustment_interval`: Number of blocks between difficulty adjustments
- `target_timespan`: Target time for completing an adjustment interval (seconds)
- `min_difficulty`: Minimum allowed difficulty (default: `1`)
- `max_difficulty`: Maximum allowed difficulty (default: `0xFFFFFFFF`)
- `max_adjustment_factor`: Maximum change per interval (default: `4`)

**Default Values (Bitcoin-compatible):**
```rust
DifficultyConfig {
    initial_difficulty: 0x1d00ffff,          // Bitcoin's initial difficulty
    adjustment_interval: 2016,                // 2016 blocks
    target_timespan: 14 * 24 * 60 * 60,      // 2 weeks in seconds
    min_difficulty: 1,
    max_difficulty: 0xFFFFFFFF,
    max_adjustment_factor: 4,
}
```

#### Methods

**`new(initial_difficulty: u32, adjustment_interval: u64, target_timespan: u64) -> DifficultyResult<Self>`**
- Creates a new difficulty configuration with custom values
- Validates all parameters before creation
- Returns: Error if any parameter is invalid (e.g., zero values)

**`validate() -> DifficultyResult<()>`**
- Validates the configuration
- Checks: non-zero values, min <= max, valid ranges
- Returns: `Ok(())` if valid, `Err(...)` with specific validation error

### DifficultyError

Errors that can occur during difficulty operations.

```rust
pub enum DifficultyError {
    InvalidDifficulty(String),
    InvalidConfig(String),
    CalculationError(String),
}
```

### Integration with Blockchain

The `BlockchainConsensusCoordinator` (in `lib-blockchain`) manages a `DifficultyManager` instance:

```rust
// In BlockchainConsensusCoordinator
pub async fn get_difficulty_config(&self) -> DifficultyConfig { ... }
pub async fn calculate_difficulty_adjustment(...) -> Result<Option<u32>> { ... }
pub async fn apply_difficulty_governance_update(...) -> Result<()> { ... }
```

The blockchain delegates difficulty calculations to the consensus coordinator:

```rust
// In Blockchain::adjust_difficulty()
if let Some(coordinator) = &self.consensus_coordinator {
    let new_difficulty = coordinator.calculate_difficulty_adjustment(
        height, current_difficulty, start_time, end_time
    ).await?;
    // Apply new difficulty
}
```

### DAO Governance Integration

Difficulty parameters can be updated via DAO proposals:

```rust
// Create a DAO proposal to adjust difficulty parameters
let params = DaoExecutionParams {
    action: DaoExecutionAction::GovernanceParameterUpdate(
        GovernanceParameterUpdate {
            updates: vec![
                GovernanceParameterValue::BlockchainInitialDifficulty(0x1d00fffe),
                GovernanceParameterValue::BlockchainAdjustmentInterval(1000),
                GovernanceParameterValue::BlockchainTargetTimespan(604800), // 1 week
            ]
        }
    )
};

// Submit proposal
let proposal_id = dao_engine.create_dao_proposal(
    proposer,
    "Adjust Mining Difficulty Parameters".to_string(),
    "Reduce adjustment interval to 1000 blocks...".to_string(),
    DaoProposalType::GovernanceRules,
    14, // 14 day voting period
)?;

// After proposal passes, parameters are automatically applied to DifficultyManager
```

## Reward System

### RewardCalculator

Calculates and distributes rewards.

```rust
pub struct RewardCalculator {
    // Reward calculation state
}
```

#### Methods

**`new() -> Self`**
- Creates a new reward calculator

**`calculate_round_rewards(validator_manager: &ValidatorManager, current_height: u64) -> Result<RewardRound>`**
- Calculates rewards for a consensus round
- Returns: RewardRound with calculated rewards

**`distribute_rewards(reward_round: &RewardRound) -> Result<()>`**
- Distributes rewards to validators

**`get_reward_stats() -> RewardStatistics`**
- Gets reward statistics
- Returns: RewardStatistics struct

**`update_work_multiplier(work_type: UsefulWorkType, multiplier: f64)`**
- Updates reward multiplier for a work type

**`adjust_base_reward(new_base_reward: u64)`**
- Adjusts the base reward amount

### RewardRound

Represents a round of rewards.

```rust
pub struct RewardRound {
    pub height: u64,
    pub total_rewards: u64,
    pub validator_rewards: HashMap<IdentityId, ValidatorReward>,
    pub timestamp: u64,
}
```

### ValidatorReward

Represents rewards for a single validator.

```rust
pub struct ValidatorReward {
    pub validator: IdentityId,
    pub base_reward: u64,
    pub work_bonus: u64,
    pub participation_bonus: u64,
    pub total_reward: u64,
    pub work_breakdown: HashMap<UsefulWorkType, u64>,
}
```

## Byzantine Fault Detection

### ByzantineFaultDetector

Detects Byzantine faults among validators.

```rust
pub struct ByzantineFaultDetector {
    // Fault detection state
}
```

#### Methods

**`new() -> Self`**
- Creates a new Byzantine fault detector

**`detect_faults(validator_manager: &ValidatorManager) -> Result<Vec<ByzantineFault>>`**
- Detects Byzantine faults
- Returns: Vector of detected faults

**`record_double_sign(validator: IdentityId, height: u64, round: u32, first_signature: Vec<u8>, second_signature: Vec<u8>)`**
- Records a double signing event

**`record_liveness_violation(validator: IdentityId, height: u64, missed_rounds: u32)`**
- Records a liveness violation

**`record_invalid_proposal(validator: IdentityId, height: u64, proposal_hash: [u8; 32], violation_type: String)`**
- Records an invalid proposal

**`process_faults(faults: Vec<ByzantineFault>, validator_manager: &mut ValidatorManager) -> Result<()>`**
- Processes detected faults and applies penalties

**`detect_equivocation(vote: &ConsensusVote, proposal_id: &Hash, current_time: u64, reported_by_peer: Option<IdentityId>) -> Option<EquivocationEvidence>`**
- Detects equivocation (conflicting votes)
- Returns: Optional equivocation evidence

**`detect_replay_attack(validator: &IdentityId, payload_hash: Hash, current_time: u64) -> Option<ReplayEvidence>`**
- Detects replay attacks
- Returns: Optional replay evidence

**`detect_network_partition(liveness_monitor: &LivenessMonitor, height: u64, round: u32, current_time: u64) -> Option<PartitionSuspectedEvidence>`**
- Detects network partitions
- Returns: Optional partition evidence

### ByzantineFault

Represents a detected Byzantine fault.

```rust
pub struct ByzantineFault {
    pub validator: IdentityId,
    pub fault_type: ByzantineFaultType,
    pub evidence: String,
    pub severity: FaultSeverity,
    pub detected_at: u64,
}
```

## Proof Systems

### StakeProof

Proof of Stake for consensus participation.

```rust
pub struct StakeProof {
    pub validator: IdentityId,
    pub staked_amount: u64,
    pub stake_tx_hash: Hash,
    pub stake_height: u64,
    pub lock_time: u64,
    pub delegations: Vec<StakeDelegation>,
    pub voting_power: u64,
}
```

#### Methods

**`new(validator: IdentityId, staked_amount: u64, stake_tx_hash: Hash, stake_height: u64, lock_time: u64) -> Result<Self>`**
- Creates a new stake proof

**`add_delegation(delegation: StakeDelegation) -> Result<()>`**
- Adds a delegation to this stake proof

**`verify(current_height: u64) -> Result<bool>`**
- Verifies the stake proof is valid

**`total_stake() -> u64`**
- Gets total stake (own stake + delegated stake)

**`calculate_delegation_rewards(total_rewards: u64) -> Vec<(IdentityId, u64)>`**
- Calculates rewards to distribute to delegators

### StorageCapacityAttestation

Consensus-facing storage capacity attestation (sourced from lib-storage).

```rust
pub struct StorageCapacityAttestation {
    pub validator_id: Hash,
    pub storage_capacity: u64,
    pub utilization: u64,
    pub challenge_results: Vec<ChallengeResult>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}
```

#### Methods

**`new(validator_id: Hash, storage_capacity: u64, utilization: u64, challenge_results: Vec<ChallengeResult>) -> Self`**
- Creates a new storage capacity attestation

**`sign(keypair: &KeyPair) -> Result<Self>`**
- Signs the attestation with the validator keypair

**`verify() -> Result<bool>`**
- Verifies the attestation signature

### WorkProof

Proof of Useful Work for consensus.

```rust
pub struct WorkProof {
    pub routing_work: u64,
    pub storage_work: u64,
    pub compute_work: u64,
    pub routes_handled: u64,
    pub data_stored: u64,
    pub computations_performed: u64,
    pub quality_score: f64,
    pub uptime_hours: u64,
    pub bandwidth_provided: u64,
    pub hash: [u8; 32],
    pub nonce: u64,
}
```

#### Methods

**`new(routing_work: u64, storage_work: u64, compute_work: u64, timestamp: u64, node_id: [u8; 32]) -> Result<Self>`**
- Creates a new work proof

**`verify() -> Result<bool>`**
- Verifies the work proof is mathematically correct

**`total_work() -> u64`**
- Calculates the total useful work represented by this proof

## Types and Data Structures

### Consensus Types

```rust
pub enum ConsensusType {
    ProofOfStake,
    ProofOfStorage,
    ProofOfUsefulWork,
    Hybrid,
    ByzantineFaultTolerance,
}
```

### Vote Types

```rust
pub enum VoteType {
    PreVote = 1,
    PreCommit = 2,
    Commit = 3,
    Against = 4,
}
```

### Consensus Steps

```rust
pub enum ConsensusStep {
    Propose,
    PreVote,
    PreCommit,
    Commit,
    NewRound,
}
```

### Consensus Proposal

```rust
pub struct ConsensusProposal {
    pub id: Hash,
    pub proposer: IdentityId,
    pub height: u64,
    pub previous_hash: Hash,
    pub block_data: Vec<u8>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
    pub consensus_proof: ConsensusProof,
}
```

### Consensus Vote

```rust
pub struct ConsensusVote {
    pub id: Hash,
    pub voter: IdentityId,
    pub proposal_id: Hash,
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}
```

### Consensus Proof

```rust
pub struct ConsensusProof {
    pub consensus_type: ConsensusType,
    pub stake_proof: Option<StakeProof>,
    pub storage_proof: Option<StorageCapacityAttestation>,
    pub work_proof: Option<WorkProof>,
    pub zk_did_proof: Option<Vec<u8>>,
    pub timestamp: u64,
}
```

### Message Broadcaster

```rust
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
```

### Validator Message

```rust
pub enum ValidatorMessage {
    Propose { proposal: ConsensusProposal },
    Vote { vote: ConsensusVote },
    Heartbeat { message: HeartbeatMessage },
}
```

## Error Handling

### ConsensusError

```rust
pub enum ConsensusError {
    InvalidConsensusType(String),
    ValidatorError(String),
    ProofVerificationFailed(String),
    ByzantineFault(String),
    DaoError(String),
    RewardError(String),
    NetworkStateError(String),
    CryptoError(anyhow::Error),
    IdentityError(String),
    NetworkError(String),
    ZkError(String),
    InvalidPreviousHash(String),
    SerializationError(serde_json::Error),
    TimeError(std::time::SystemTimeError),
}
```

## Usage Examples

### Basic Consensus Setup

```rust
use lib_consensus::{ConsensusEngine, ConsensusConfig, ConsensusType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create consensus configuration
    let config = ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000,           // 1000 ZHTP
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
        max_validators: 100,
        block_time: 10,
        ..Default::default()
    };

    // Create consensus engine
    let mut consensus = ConsensusEngine::new(config)?;

    // Register as validator
    let identity = IdentityId::from_bytes(b"validator_identity_32_bytes");
    let stake_amount = 5000 * 1_000_000; // 5000 ZHTP
    let storage_capacity = 500 * 1024 * 1024 * 1024; // 500 GB
    let consensus_key = vec![0u8; 32]; // Public key
    let commission_rate = 5; // 5%

    consensus.register_validator(
        identity,
        stake_amount,
        storage_capacity,
        consensus_key,
        commission_rate,
        false, // not genesis
    ).await?;

    // Start consensus
    consensus.start_consensus().await?;

    Ok(())
}
```

### DAO Governance Example

```rust
// Create a proposal
let proposal_id = consensus.dao_engine_mut().create_dao_proposal(
    proposer_id,
    "Increase Validator Rewards".to_string(),
    "Proposal to increase base validator rewards by 20%.".to_string(),
    DaoProposalType::EconomicParams,
    7, // 7 days voting period
).await?;

// Cast a vote
consensus.dao_engine_mut().cast_dao_vote(
    voter_id,
    proposal_id,
    DaoVoteChoice::Yes,
    Some("Supporting increased validator incentives".to_string()),
).await?;
```

### Validator Management Example

```rust
// Get validator statistics
let stats = consensus.validator_manager().get_validator_stats();
println!("Active validators: {}", stats.active_validators);
println!("Total stake: {} ZHTP", stats.total_stake);

// Check Byzantine threshold
let threshold = consensus.validator_manager().get_byzantine_threshold();
println!("Byzantine threshold: {} voting power", threshold);
```

## Best Practices

### Security

1. **Always validate inputs**: Use the provided validation methods
2. **Handle errors properly**: Don't ignore consensus errors
3. **Monitor validator activity**: Use liveness monitoring
4. **Secure key management**: Protect consensus keys
5. **Regular updates**: Keep consensus software up-to-date

### Performance

1. **Optimize validator selection**: Use efficient proposer selection
2. **Minimize network latency**: Ensure fast communication between validators
3. **Monitor resource usage**: Track CPU, memory, and network usage
4. **Tune timeouts**: Adjust timeouts based on network conditions
5. **Use efficient serialization**: Optimize message serialization

### Reliability

1. **Implement proper error handling**: Handle consensus failures gracefully
2. **Use redundancy**: Run multiple validator nodes
3. **Monitor consensus health**: Track key metrics
4. **Implement fallback mechanisms**: Handle network partitions
5. **Regular testing**: Test consensus under various conditions

## Troubleshooting

### Common Issues

**Consensus stalls**: Check validator liveness and network connectivity

**Low participation**: Verify validator registration and stake requirements

**Byzantine faults**: Investigate validator behavior and apply slashing

**Performance issues**: Optimize network configuration and resource allocation

**Security alerts**: Review Byzantine fault detection logs and take appropriate action

### Debugging

Enable detailed logging:

```rust
tracing::info!("Consensus event: {:?}", event);
tracing::warn!("Byzantine fault detected: {:?}", fault);
tracing::error!("Consensus error: {}", error);
```

Use monitoring tools to track consensus metrics and identify issues.
