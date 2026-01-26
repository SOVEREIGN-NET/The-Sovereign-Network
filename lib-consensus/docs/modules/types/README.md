# Core Types Documentation

This document provides comprehensive documentation for all core types, structures, and enums used throughout the ZHTP Consensus System.

##  Overview

The ZHTP Consensus System uses a rich type system to ensure type safety, clear APIs, and maintainable code. This documentation covers all fundamental data structures, enumerations, and type aliases used across the system.

## 🏗️ Core Consensus Types

### ConsensusType

Defines the type of consensus mechanism being used.

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConsensusType {
    /// Pure Proof of Stake consensus
    ProofOfStake,
    /// Pure Proof of Storage consensus
    ProofOfStorage,
    /// Proof of Useful Work consensus  
    ProofOfUsefulWork,
    /// Hybrid PoS + PoStorage
    Hybrid,
    /// Byzantine Fault Tolerance
    ByzantineFaultTolerance,
}
```

**Usage Examples:**
```rust
// Configure hybrid consensus
let config = ConsensusConfig {
    consensus_type: ConsensusType::Hybrid,
    // ... other settings
};

// Check consensus type
match config.consensus_type {
    ConsensusType::ProofOfStake => {
        // Handle PoS specific logic
    },
    ConsensusType::Hybrid => {
        // Handle hybrid consensus
    },
    _ => {
        // Handle other types
    }
}
```

**Use Cases:**
- **ProofOfStake**: Traditional staking-based consensus
- **ProofOfStorage**: Storage provider consensus
- **ProofOfUsefulWork**: Work-based consensus rewarding useful computation
- **Hybrid**: Combines PoS and PoStorage for balanced incentives
- **ByzantineFaultTolerance**: Full BFT with maximum security

### UsefulWorkType

Categorizes different types of useful work that can be performed for consensus rewards.

```rust
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
```

**Reward Multipliers:**
- **NetworkRouting**: 1.2x multiplier for mesh network contribution
- **DataStorage**: 1.1x multiplier for storage provision
- **Computation**: 1.3x multiplier for computational work  
- **Validation**: 1.0x base multiplier for consensus participation
- **BridgeOperations**: 1.5x premium multiplier for cross-chain work

### ValidatorStatus

Represents the current status of a validator in the consensus network.

```rust
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
```

**State Transitions:**
- `Active` → `Inactive`: Voluntary exit or insufficient stake
- `Active` → `Slashed`: Misbehavior detected and penalized  
- `Active` → `Jailed`: Temporary suspension due to violations
- `Jailed` → `Active`: After jail period expires and conditions met
- `Slashed` → `Inactive`: Permanent removal after severe violations

##  Consensus Voting Types

### VoteType

Defines the different types of votes in the BFT consensus protocol.

```rust
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
```

**BFT Consensus Flow:**
1. **PreVote**: Initial voting on proposed blocks
2. **PreCommit**: Commitment to a specific proposal after sufficient prevotes
3. **Commit**: Final commitment when sufficient precommits received
4. **Against**: Explicit rejection of a proposal

### ConsensusStep

Represents the current step in the BFT consensus protocol.

```rust
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
```

**Step Progression:**
1. `NewRound` → `Propose`: Initialize new consensus round
2. `Propose` → `PreVote`: After proposal timeout or valid proposal received
3. `PreVote` → `PreCommit`: After sufficient prevotes collected
4. `PreCommit` → `Commit`: After sufficient precommits collected
5. `Commit` → `NewRound`: After block committed successfully

##  Consensus Data Structures

### ConsensusRound

Tracks the state of a single consensus round.

```rust
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
```

**Key Features:**
- **Height Tracking**: Blockchain height for this consensus round
- **Round Management**: Handle multiple rounds at same height if needed
- **Proposer Selection**: Deterministic proposer selection per round
- **Vote Aggregation**: Collect and organize votes by proposal
- **Locking Mechanism**: Lock onto valid proposals to prevent equivocation
- **Timeout Handling**: Detect and handle round timeouts

### ConsensusProposal

Represents a proposal for a new block in the consensus system.

```rust
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
```

**Validation Requirements:**
- Valid proposer signature using post-quantum cryptography
- Correct previous block hash for blockchain continuity  
- Valid consensus proof based on consensus type
- Reasonable timestamp within acceptable bounds
- Well-formed block data with valid transactions

### ConsensusVote

Represents a vote on a consensus proposal.

```rust
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
```

**Vote Verification:**
- Cryptographic signature verification
- Validator authorization check
- Vote timing validation
- Duplicate vote detection
- Byzantine fault tolerance validation

##  Consensus Proof System

### ConsensusProof

Combines different proof types based on the consensus mechanism.

```rust
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
```

**Proof Requirements by Consensus Type:**
- **ProofOfStake**: Requires `stake_proof` only
- **ProofOfStorage**: Requires `storage_proof` only  
- **ProofOfUsefulWork**: Requires `work_proof` only
- **Hybrid**: Requires both `stake_proof` and `storage_proof`
- **ByzantineFaultTolerance**: May include all proof types for maximum security

### NetworkState

Represents the current state of the consensus network.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkState {
    pub total_participants: u64,
    pub average_uptime: f64,
    pub total_bandwidth_shared: u64,
    pub consensus_round: u64,
}
```

**Usage:**
- Network health monitoring
- Performance metrics calculation
- Dynamic parameter adjustment
- Economic model inputs

##  Configuration Types

### ConsensusConfig

Main configuration structure for the consensus system.

```rust
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
}
```

**Default Configuration:**
```rust
impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            consensus_type: ConsensusType::Hybrid,
            min_stake: 1000 * 1_000_000, // 1000 ZHTP tokens
            min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
            max_validators: 100,
            block_time: 10, // 10 seconds
            propose_timeout: 3000, // 3 seconds
            prevote_timeout: 1000, // 1 second
            precommit_timeout: 1000, // 1 second
            max_transactions_per_block: 1000,
            max_difficulty: 0x00000000FFFFFFFF,
            target_difficulty: 0x00000FFF,
            byzantine_threshold: 1.0 / 3.0, // 1/3 Byzantine tolerance
            slash_double_sign: 5, // 5% slash for double signing
            slash_liveness: 1, // 1% slash for liveness violation
        }
    }
}
```

##  Security and Slashing Types

### SlashType

Defines different types of slashing events for validator misbehavior.

```rust
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
```

**Slashing Severity:**
- **DoubleSign**: 5-10% stake slash (most severe)
- **Liveness**: 1-3% stake slash (moderate)
- **InvalidProposal**: 2% stake slash
- **InvalidVote**: 1% stake slash (least severe)

##  Event System Types

### ConsensusEvent

Defines events for consensus system communication.

```rust
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
```

**Event Categories:**
- **Lifecycle Events**: Round start/end, validator join/leave
- **Consensus Events**: Proposals, votes, block finalization
- **Error Events**: Byzantine faults, DAO errors, reward errors
- **Status Events**: Round preparation, completion, failures

##  Economic Types

### ComputeResult

Represents the result of useful computational work.

```rust
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
        Ok(self.work_units > 0 && !self.signature.is_empty())
    }
}
```

**Verification Process:**
1. Validate work units are positive
2. Verify computation hash correctness
3. Check timestamp validity
4. Validate cryptographic signature
5. Ensure no double-spending of work

##  Error Types

### ConsensusError

Comprehensive error enumeration for the consensus system.

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Invalid consensus type: {0}")]
    InvalidConsensusType(String),
    
    #[error("Validator error: {0}")]
    ValidatorError(String),
    
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    
    #[error("Byzantine fault detected: {0}")]
    ByzantineFault(String),
    
    #[error("DAO governance error: {0}")]
    DaoError(String),
    
    #[error("Reward calculation error: {0}")]
    RewardError(String),
    
    #[error("Network state error: {0}")]
    NetworkStateError(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(#[from] anyhow::Error),
    
    #[error("Identity error: {0}")]
    IdentityError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("ZK proof error: {0}")]
    ZkError(String),
    
    #[error("Invalid previous hash: {0}")]
    InvalidPreviousHash(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("System time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),
}
```

### ConsensusResult

Type alias for consensus operations that may fail.

```rust
pub type ConsensusResult<T> = Result<T, ConsensusError>;
```

##  Usage Patterns

### Type-Safe Configuration

The type system enforces correct configuration:

```rust
// Type-safe consensus configuration
let config = ConsensusConfig {
    consensus_type: ConsensusType::Hybrid, // Enum ensures valid types
    min_stake: 1000 * 1_000_000, // Clear units (micro-ZHTP)
    block_time: 10, // Seconds
    byzantine_threshold: 1.0 / 3.0, // Mathematical precision
    ..Default::default()
};

// Compile-time validation
assert!(config.byzantine_threshold < 0.5); // BFT requires < 50%
```

### Event-Driven Architecture

The event system enables clean component communication:

```rust
async fn handle_consensus_event(event: ConsensusEvent) -> ConsensusResult<Vec<ConsensusEvent>> {
    match event {
        ConsensusEvent::StartRound { height, trigger } => {
            // Handle round start
            Ok(vec![ConsensusEvent::RoundPrepared { height }])
        },
        ConsensusEvent::NewBlock { height, previous_hash } => {
            // Process new block
            match run_consensus_round().await {
                Ok(_) => Ok(vec![ConsensusEvent::RoundCompleted { height }]),
                Err(e) => Ok(vec![ConsensusEvent::RoundFailed { 
                    height, 
                    error: e.to_string() 
                }])
            }
        },
        _ => Ok(vec![])
    }
}
```

### Error Handling Patterns

Comprehensive error handling with context:

```rust
pub async fn validate_proposal(proposal: &ConsensusProposal) -> ConsensusResult<()> {
    // Validate signature
    if !verify_signature(&proposal.signature).await? {
        return Err(ConsensusError::ProofVerificationFailed(
            "Invalid proposal signature".to_string()
        ));
    }
    
    // Validate consensus proof
    if !verify_consensus_proof(&proposal.consensus_proof).await? {
        return Err(ConsensusError::ProofVerificationFailed(
            "Invalid consensus proof".to_string()
        ));
    }
    
    Ok(())
}
```

##  Type Evolution

The type system is designed for evolution:

1. **Backward Compatibility**: New enum variants are additive
2. **Versioning**: Serialization supports version migration
3. **Optional Fields**: New fields use `Option<T>` for compatibility
4. **Feature Flags**: Types can be conditionally compiled

##  Best Practices

### Type Usage Guidelines

1. **Use Enums for States**: Prefer enums over constants for state representation
2. **Leverage Type System**: Use the type system to prevent invalid states
3. **Error Context**: Always provide meaningful error context
4. **Serialization**: Ensure all public types implement Serialize/Deserialize
5. **Documentation**: Document complex types with usage examples

### Performance Considerations

1. **Clone vs Reference**: Most types implement `Clone` for flexibility
2. **Memory Layout**: Structures are optimized for memory efficiency
3. **Serialization**: Binary serialization for performance-critical paths
4. **Hash Maps**: Use `HashMap` for O(1) lookups where appropriate

---

This comprehensive type documentation ensures developers understand all data structures and can use the ZHTP Consensus System type-safely and efficiently.
