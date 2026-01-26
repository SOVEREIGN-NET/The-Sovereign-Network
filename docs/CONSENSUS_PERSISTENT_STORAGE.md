# Consensus-Persistent Storage Gap Analysis

**Status**: ⏳ 30% Complete
**Component**: lib-consensus ↔ lib-storage
**Priority**: CRITICAL (blocking mainnet deployment)

---

## Executive Summary

The consensus protocol currently **has no persistent storage mechanism**. All consensus state (rounds, votes, proposals) exists only in memory. A node restart loses all voting history, round state, and progress, causing the node to rejoin consensus from scratch. Production networks require durability: the ability to recover voting state, restart at the same round, and prove historical consensus decisions.

---

## Current State

### What Works
✅ In-memory vote tracking
✅ In-memory round state management
✅ In-memory proposal cache
✅ Validator state in memory
✅ BFT algorithm correctness
✅ Signature verification

### What's Missing
❌ Persistent voting ledger
❌ Durable round state snapshots
❌ Consensus log (audit trail)
❌ Crash recovery
❌ State sync from snapshots
❌ Validator registration persistence
❌ DAO proposal persistence
❌ Reward calculation history
❌ Byzantine fault evidence storage
❌ Historical query capability

---

## Gap 1: Persistent Voting Ledger

### Problem
All votes are kept in memory (`self.votes: VoteMap`). When a node restarts, it loses all votes for all rounds, effectively restarting consensus from round 0 with no memory of what happened before.

```rust
// Current: All in memory, lost on restart
pub struct ConsensusEngine {
    votes: VoteMap,  // Struct { round -> Vec<ValidatorVote> }
    // ↑ This disappears when node restarts
}

// Needed: Persist votes to durable storage
let vote = ValidatorVote { /* ... */ };
// storage.append_vote(vote).await?;  // ← Missing!
```

### What's Needed

#### 1.1 Vote Storage Trait
```rust
pub trait VoteStore: Send + Sync {
    /// Append a single vote to persistent log
    async fn append_vote(&mut self, vote: ValidatorVote) -> Result<VoteLogEntry>;

    /// Get all votes for a specific round
    async fn get_votes_for_round(&self, round: u32) -> Result<Vec<ValidatorVote>>;

    /// Get all votes by a specific validator
    async fn get_validator_votes(&self, validator_id: &ValidatorId) -> Result<Vec<ValidatorVote>>;

    /// Get latest N votes in chronological order
    async fn get_recent_votes(&self, limit: u32) -> Result<Vec<ValidatorVote>>;

    /// Search votes by properties
    async fn query_votes(&self, query: VoteQuery) -> Result<Vec<ValidatorVote>>;

    /// Get vote count for round
    async fn count_votes_for_round(&self, round: u32) -> Result<u64>;

    /// Check if vote already recorded (prevent duplicates)
    async fn vote_exists(&self, validator_id: &ValidatorId, round: u32) -> Result<bool>;

    /// Get earliest unfinalized round
    async fn get_earliest_open_round(&self) -> Result<u32>;
}

pub struct VoteLogEntry {
    pub id: u64,
    pub vote: ValidatorVote,
    pub timestamp: u64,
    pub recorded_at: Instant,
}

pub struct VoteQuery {
    pub round: Option<u32>,
    pub validator_id: Option<ValidatorId>,
    pub vote_type: Option<VoteType>,
    pub start_height: Option<u64>,
    pub end_height: Option<u64>,
}

pub enum VoteType {
    PreVote,
    PreCommit,
    Commit,
}
```

#### 1.2 Vote Storage Implementation Strategy
Choose storage backend based on deployment:
```rust
pub enum VoteStorageBackend {
    /// RocksDB for single-node validators
    RocksDB {
        db_path: PathBuf,
        max_votes_in_memory: usize,
    },
    /// SQLite for embedded systems
    SQLite {
        db_path: PathBuf,
        batch_writes: bool,
    },
    /// PostgreSQL for distributed systems
    PostgreSQL {
        connection_string: String,
        pool_size: u32,
    },
    /// Hybrid: recent votes in memory, old votes in cold storage
    Hybrid {
        hot_store: Box<dyn VoteStore>,
        cold_store: Box<dyn VoteStore>,
        hot_window_rounds: u32,
    },
}
```

#### 1.3 Integration in Consensus
```rust
// In consensus_engine.rs when recording a vote
async fn record_vote(&mut self, vote: ValidatorVote) -> Result<()> {
    // 1. Persist to durable storage first
    let log_entry = self.vote_store.append_vote(vote.clone()).await?;

    // 2. Update in-memory tracking
    self.votes.add_vote(vote)?;

    // 3. Check for vote duplication
    if let Some(existing) = self.votes.get_validator_vote(&vote.validator_id, vote.round) {
        if existing.block_hash != vote.block_hash {
            // Equivocation detected!
            self.byzantine_detector.record_equivocation(&vote.validator_id)?;
        }
    }

    Ok(())
}
```

---

## Gap 2: Durable Round State Snapshots

### Problem
The current round number, phase, and timeout state only exist in memory. Restarting the node means losing track of which round we're on, forcing restart from round 0.

```rust
// Current: Lost on restart
pub struct ConsensusEngine {
    current_round: u32,         // ← What round am I in?
    current_phase: Phase,       // ← What phase?
    round_start_time: Instant,  // ← When did it start?
}

// Needed: Recover to same round after restart
// state = storage.load_round_state().await?;
// self.current_round = state.round;
// self.current_phase = state.phase;
```

### What's Needed

#### 2.1 Round State Persistence
```rust
pub trait RoundStateStore: Send + Sync {
    /// Save current round state (checkpoint)
    async fn save_round_state(&mut self, state: RoundState) -> Result<()>;

    /// Load last saved round state
    async fn load_round_state(&self) -> Result<Option<RoundState>>;

    /// Get round state at specific height
    async fn get_round_state_at(&self, height: u64) -> Result<Option<RoundState>>;

    /// List all saved round states (for debugging)
    async fn list_round_states(&self, limit: u32) -> Result<Vec<RoundStateSnapshot>>;

    /// Prune old round states after finalization
    async fn prune_before_height(&mut self, height: u64) -> Result<u32>;

    /// Get checkpoint interval (how often to save)
    fn checkpoint_interval(&self) -> u32;
}

pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub phase: ConsensusPhase,
    pub phase_start_time: u64,
    pub proposed_block: Option<BlockHash>,
    pub is_proposer: bool,
    pub validator_count: usize,
    pub quorum_size: usize,
}

pub struct RoundStateSnapshot {
    pub height: u64,
    pub round: u32,
    pub saved_at: u64,
    pub phase_when_saved: ConsensusPhase,
}

pub enum ConsensusPhase {
    Propose,
    PreVote,
    PreCommit,
    Commit,
    Finalize,
}
```

#### 2.2 Recovery on Startup
```rust
pub struct RecoveryManager {
    round_state_store: Arc<dyn RoundStateStore>,
    vote_store: Arc<dyn VoteStore>,
}

impl RecoveryManager {
    /// Recover consensus state from storage on startup
    pub async fn recover(&self) -> Result<RecoveryState> {
        // 1. Load last saved round state
        let round_state = self.round_state_store.load_round_state().await?;

        // 2. If we have a saved state, recover to that round
        if let Some(state) = round_state {
            info!("Recovering from round {} phase {:?}", state.round, state.phase);

            // 3. Load all votes for this round
            let votes = self.vote_store.get_votes_for_round(state.round).await?;

            return Ok(RecoveryState {
                round_state: state,
                round_votes: votes,
                recovered: true,
            });
        }

        // 4. Start from scratch
        Ok(RecoveryState::fresh())
    }
}

pub struct RecoveryState {
    pub round_state: RoundState,
    pub round_votes: Vec<ValidatorVote>,
    pub recovered: bool,
}
```

#### 2.3 Integration in Consensus Initialization
```rust
// In consensus_engine.rs initialization
pub async fn initialize_with_recovery(
    config: ConsensusConfig,
    storage: Arc<dyn RoundStateStore>,
    vote_store: Arc<dyn VoteStore>,
) -> Result<Self> {
    // 1. Attempt recovery
    let recovery_mgr = RecoveryManager {
        round_state_store: storage.clone(),
        vote_store: vote_store.clone(),
    };

    let recovery = recovery_mgr.recover().await?;

    // 2. Create engine
    let mut engine = Self::new(config);

    // 3. Restore state if recovered
    if recovery.recovered {
        engine.current_round = recovery.round_state.round;
        engine.current_phase = recovery.round_state.phase;

        // Restore votes
        for vote in recovery.round_votes {
            engine.votes.add_vote(vote)?;
        }

        info!("Recovered consensus state: round {}", engine.current_round);
    } else {
        info!("Starting fresh consensus from round 0");
    }

    // 4. Assign storage handles
    engine.round_state_store = Some(storage);
    engine.vote_store = Some(vote_store);

    Ok(engine)
}

// During normal operation, checkpoint round state periodically
async fn checkpoint_round_state(&mut self) -> Result<()> {
    if self.current_round % self.round_state_store.checkpoint_interval() == 0 {
        let state = RoundState {
            height: self.height,
            round: self.current_round,
            phase: self.current_phase.clone(),
            phase_start_time: self.phase_start_time,
            proposed_block: self.current_proposal.as_ref().map(|p| p.hash),
            is_proposer: self.is_proposer_for_round(),
            validator_count: self.validators.len(),
            quorum_size: self.quorum_threshold(),
        };

        self.round_state_store.as_mut().unwrap().save_round_state(state).await?;
    }
    Ok(())
}
```

---

## Gap 3: Consensus Audit Log

### Problem
There's no historical record of consensus decisions. Can't audit what validators voted, when Byzantine behavior occurred, or provide proof of finality.

### What's Needed

#### 3.1 Audit Log Storage
```rust
pub trait AuditLog: Send + Sync {
    /// Log consensus event for audit trail
    async fn log_event(&mut self, event: ConsensusEvent) -> Result<LogEntry>;

    /// Log Byzantine fault detection
    async fn log_byzantine_event(
        &mut self,
        event: ByzantineEvent,
    ) -> Result<LogEntry>;

    /// Query audit log by height
    async fn query_by_height(&self, height: u64) -> Result<Vec<LogEntry>>;

    /// Query audit log by validator
    async fn query_by_validator(&self, validator_id: &ValidatorId) -> Result<Vec<LogEntry>>;

    /// Query audit log by date range
    async fn query_by_date_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<LogEntry>>;

    /// Get forensic evidence for dispute
    async fn get_evidence(&self, query: EvidenceQuery) -> Result<DisputeEvidence>;

    /// Export audit log to file for archival
    async fn export(&self, path: PathBuf) -> Result<()>;

    /// Verify log integrity (check signatures/hashes)
    async fn verify_integrity(&self) -> Result<bool>;
}

pub enum ConsensusEvent {
    RoundStarted { round: u32, height: u64 },
    ProposalReceived { round: u32, proposer: ValidatorId, block_hash: BlockHash },
    VoteReceived { round: u32, voter: ValidatorId, vote_type: VoteType },
    PhaseChanged { round: u32, from: ConsensusPhase, to: ConsensusPhase },
    RoundCompleted { round: u32, finalized_block: BlockHash },
    Stalled { reason: String },
}

pub enum ByzantineEvent {
    EquivocationDetected { validator_id: ValidatorId, evidence: EquivocationEvidence },
    InvalidSignature { validator_id: ValidatorId, message: Vec<u8> },
    ReplayAttack { validator_id: ValidatorId, message_hash: BlockHash },
    DoubleVote { validator_id: ValidatorId, vote1: ValidatorVote, vote2: ValidatorVote },
}

pub struct LogEntry {
    pub id: u64,
    pub timestamp: u64,
    pub event: ConsensusEvent,
    pub height: u64,
    pub signature: Option<Signature>,  // Signed by this node for proof
}

pub struct EvidenceQuery {
    pub height: Option<u64>,
    pub validator_id: Option<ValidatorId>,
    pub event_type: Option<String>,
}

pub struct DisputeEvidence {
    pub events: Vec<LogEntry>,
    pub supporting_votes: Vec<ValidatorVote>,
    pub signatures: Vec<Signature>,
    pub merkle_proof: Option<Vec<u8>>,
}
```

#### 3.2 Integration in Consensus
```rust
// In consensus_engine.rs when important events occur
async fn advance_to_pre_vote_phase(&mut self) -> Result<()> {
    let old_phase = self.current_phase.clone();

    self.current_phase = ConsensusPhase::PreVote;

    // Log phase transition
    if let Some(audit_log) = &self.audit_log {
        audit_log.log_event(ConsensusEvent::PhaseChanged {
            round: self.current_round,
            from: old_phase,
            to: ConsensusPhase::PreVote,
        }).await?;
    }

    // ... rest of phase advance logic
    Ok(())
}

// When detecting Byzantine behavior
async fn detect_and_log_byzantine_fault(&mut self, evidence: EquivocationEvidence) -> Result<()> {
    if let Some(audit_log) = &self.audit_log {
        audit_log.log_byzantine_event(ByzantineEvent::EquivocationDetected {
            validator_id: evidence.validator_id.clone(),
            evidence: evidence.clone(),
        }).await?;
    }

    // Slash the validator
    self.slash_validator(&evidence.validator_id, 5)?;

    Ok(())
}
```

---

## Gap 4: Validator Registration Persistence

### Problem
Validators exist only in memory. Restarting means losing track of which validators are active, their stakes, and voting power.

### What's Needed

#### 4.1 Validator Registry Storage
```rust
pub trait ValidatorRegistry: Send + Sync {
    /// Register a new validator
    async fn register_validator(&mut self, validator: Validator) -> Result<()>;

    /// Get active validators at height
    async fn get_validators_at_height(&self, height: u64) -> Result<Vec<Validator>>;

    /// Update validator stake
    async fn update_stake(
        &mut self,
        validator_id: &ValidatorId,
        new_stake: u64,
    ) -> Result<()>;

    /// Update validator status (active/jailed)
    async fn update_status(
        &mut self,
        validator_id: &ValidatorId,
        status: ValidatorStatus,
    ) -> Result<()>;

    /// Get validator by ID
    async fn get_validator(&self, validator_id: &ValidatorId) -> Result<Option<Validator>>;

    /// Get all historical validator sets
    async fn get_validator_history(&self, limit: u32) -> Result<Vec<ValidatorSetSnapshot>>;

    /// Record slashing event
    async fn record_slash(
        &mut self,
        validator_id: &ValidatorId,
        amount: u64,
        reason: String,
    ) -> Result<()>;
}

pub struct ValidatorSetSnapshot {
    pub height: u64,
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
    pub timestamp: u64,
}
```

#### 4.2 Integration with Blockchain
```rust
// Validators should be sourced from blockchain, not consensus memory
// In consensus_engine.rs
async fn load_validators_for_height(&mut self, height: u64) -> Result<()> {
    // Load from blockchain
    let validators = self.blockchain
        .get_validators_at_height(height)
        .await?;

    // Cache in memory
    self.validators = validators.clone();

    // Persist for recovery
    if let Some(registry) = &self.validator_registry {
        for validator in validators {
            registry.register_validator(validator).await?;
        }
    }

    Ok(())
}
```

---

## Gap 5: State Snapshots for Fast Sync

### Problem
A new validator joining the network must replay all historical consensus to build state. With years of history, this is impossibly slow. Need snapshots.

### What's Needed

#### 5.1 Snapshot Storage
```rust
pub trait SnapshotStore: Send + Sync {
    /// Create a snapshot at current height
    async fn create_snapshot(&mut self) -> Result<SnapshotId>;

    /// Get metadata about a snapshot
    async fn get_snapshot_metadata(&self, snapshot_id: &SnapshotId) -> Result<SnapshotMetadata>;

    /// Load complete state from snapshot
    async fn load_from_snapshot(&self, snapshot_id: &SnapshotId) -> Result<ConsensusSnapshot>;

    /// List all available snapshots
    async fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>>;

    /// Get latest snapshot
    async fn get_latest_snapshot(&self) -> Result<Option<SnapshotMetadata>>;

    /// Delete old snapshots (keep only last N)
    async fn prune_snapshots(&mut self, keep_count: u32) -> Result<()>;

    /// Calculate snapshot hash for verification
    async fn verify_snapshot_integrity(&self, snapshot_id: &SnapshotId) -> Result<bool>;
}

pub struct SnapshotId(pub String);  // UUID or height-based identifier

pub struct SnapshotMetadata {
    pub id: SnapshotId,
    pub height: u64,
    pub round: u32,
    pub timestamp: u64,
    pub validator_count: usize,
    pub total_voting_power: u64,
    pub file_size: u64,
    pub merkle_root: Hash256,
}

pub struct ConsensusSnapshot {
    pub metadata: SnapshotMetadata,
    pub validators: Vec<Validator>,
    pub vote_tally: HashMap<ValidatorId, Vec<ValidatorVote>>,
    pub round_state: RoundState,
    pub pending_proposals: Vec<BlockProposal>,
}
```

#### 5.2 Snapshot Creation Strategy
```rust
// Periodically create snapshots (e.g., every 1000 blocks)
async fn maybe_create_snapshot(&mut self) -> Result<()> {
    if self.height % SNAPSHOT_INTERVAL == 0 && self.height > 0 {
        info!("Creating snapshot at height {}", self.height);

        let snapshot = ConsensusSnapshot {
            metadata: SnapshotMetadata {
                id: SnapshotId(uuid::Uuid::new_v4().to_string()),
                height: self.height,
                round: self.current_round,
                timestamp: now_timestamp(),
                validator_count: self.validators.len(),
                total_voting_power: self.total_voting_power(),
                file_size: 0,  // Computed during save
                merkle_root: Hash256::zero(),  // Computed during save
            },
            validators: self.validators.clone(),
            vote_tally: self.votes.clone(),
            round_state: self.get_current_round_state(),
            pending_proposals: vec![],
        };

        if let Some(store) = &self.snapshot_store {
            store.create_snapshot(&snapshot).await?;
        }
    }
    Ok(())
}
```

---

## Gap 6: Byzantine Fault Evidence Storage

### Problem
Byzantine faults are detected but not persistently recorded. When nodes are slashed, there's no audit trail proving the fault occurred.

### What's Needed

#### 6.1 Byzantine Evidence Store
```rust
pub trait ByzantineEvidenceStore: Send + Sync {
    /// Store evidence of Byzantine behavior
    async fn record_evidence(&mut self, evidence: ByzantineEvidence) -> Result<EvidenceId>;

    /// Retrieve evidence by ID
    async fn get_evidence(&self, id: &EvidenceId) -> Result<Option<ByzantineEvidence>>;

    /// Query evidence by validator
    async fn query_by_validator(&self, validator_id: &ValidatorId) -> Result<Vec<ByzantineEvidence>>;

    /// Query evidence by type
    async fn query_by_type(&self, evidence_type: EvidenceType) -> Result<Vec<ByzantineEvidence>>;

    /// Get evidence count for validator (repeat offender detection)
    async fn get_offense_count(&self, validator_id: &ValidatorId) -> Result<u32>;

    /// Verify evidence integrity
    async fn verify_evidence(&self, id: &EvidenceId) -> Result<bool>;
}

pub type EvidenceId = u64;

pub struct ByzantineEvidence {
    pub id: EvidenceId,
    pub validator_id: ValidatorId,
    pub evidence_type: EvidenceType,
    pub timestamp: u64,
    pub height: u64,
    pub details: EvidenceDetails,
    pub submitted_by: ValidatorId,  // Which validator reported it
    pub verified_by_quorum: bool,   // Confirmed by 2/3+ validators
}

pub enum EvidenceType {
    Equivocation,           // Two conflicting votes
    DoubleSign,            // Signed two blocks at same height
    InvalidSignature,      // Signature doesn't verify
    ReplayAttack,          // Reused old vote
    ProposalEquivocation,  // Two different proposals same round
}

pub enum EvidenceDetails {
    Equivocation {
        vote1: ValidatorVote,
        vote2: ValidatorVote,
    },
    DoubleSign {
        block1: BlockHash,
        block2: BlockHash,
    },
    InvalidSignature {
        message: Vec<u8>,
        signature: Signature,
        expected_signer: ValidatorId,
    },
}
```

---

## Gap 7: Reward Calculation History

### Problem
Reward distributions are calculated but not persisted. Can't verify validator rewards or dispute calculations.

### What's Needed

#### 7.1 Reward History Storage
```rust
pub trait RewardHistory: Send + Sync {
    /// Record rewards distributed
    async fn record_distribution(
        &mut self,
        distribution: RewardDistribution,
    ) -> Result<()>;

    /// Get rewards for validator in period
    async fn get_validator_rewards(
        &self,
        validator_id: &ValidatorId,
        start_height: u64,
        end_height: u64,
    ) -> Result<u64>;

    /// Get total rewards distributed
    async fn get_total_distributed(&self, height: u64) -> Result<u64>;

    /// Query distribution events
    async fn query_distributions(
        &self,
        query: DistributionQuery,
    ) -> Result<Vec<RewardDistribution>>;

    /// Export rewards for tax reporting
    async fn export_rewards(
        &self,
        validator_id: &ValidatorId,
        start_height: u64,
        end_height: u64,
    ) -> Result<RewardStatement>;
}

pub struct RewardDistribution {
    pub height: u64,
    pub round: u32,
    pub distributions: Vec<ValidatorReward>,
    pub total_distributed: u64,
    pub treasury_before: u64,
    pub treasury_after: u64,
    pub timestamp: u64,
}

pub struct ValidatorReward {
    pub validator_id: ValidatorId,
    pub amount: u64,
    pub reason: RewardReason,
}

pub enum RewardReason {
    BlockProposal,       // Proposed valid block
    SuccessfulVote,      // Voted for finalized block
    ValidatorStaking,    // Stake-based reward
    StorageProof,        // PoStorage contribution
}

pub struct RewardStatement {
    pub validator_id: ValidatorId,
    pub period_start: u64,
    pub period_end: u64,
    pub total_rewards: u64,
    pub breakdown: HashMap<RewardReason, u64>,
}
```

---

## Implementation Roadmap

### Phase 1: Vote Storage (Week 1-2)
- [ ] Define VoteStore trait
- [ ] Implement with RocksDB backend
- [ ] Add vote persistence in consensus_engine.rs
- [ ] Test voting ledger durability
- [ ] Benchmark write performance

### Phase 2: Round State Snapshots (Week 3)
- [ ] Define RoundStateStore trait
- [ ] Implement checkpoint mechanism
- [ ] Add recovery logic on startup
- [ ] Test restart recovery
- [ ] Verify state consistency

### Phase 3: Audit Log (Week 4)
- [ ] Define AuditLog trait
- [ ] Implement log storage
- [ ] Add Byzantine event logging
- [ ] Create log export/forensic tools
- [ ] Test audit log queries

### Phase 4: Validator Registry (Week 5)
- [ ] Define ValidatorRegistry trait
- [ ] Persist validator changes
- [ ] Implement history tracking
- [ ] Integrate with blockchain
- [ ] Test validator set recovery

### Phase 5: Snapshots (Week 6)
- [ ] Define SnapshotStore trait
- [ ] Implement snapshot creation
- [ ] Add snapshot verification
- [ ] Test fast sync from snapshot
- [ ] Benchmark snapshot size/time

### Phase 6: Byzantine Evidence (Week 7)
- [ ] Define ByzantineEvidenceStore trait
- [ ] Store evidence with validation
- [ ] Implement repeat offender detection
- [ ] Create evidence query tools
- [ ] Test evidence verification

### Phase 7: Reward History (Week 8)
- [ ] Define RewardHistory trait
- [ ] Persist reward distributions
- [ ] Implement reward queries
- [ ] Add tax reporting export
- [ ] Test reward statement accuracy

### Phase 8: Integration & Testing (Week 9-10)
- [ ] End-to-end persistence testing
- [ ] Crash/recovery scenarios
- [ ] Data corruption recovery
- [ ] Storage capacity planning
- [ ] Performance tuning
- [ ] Backup/restore procedures

---

## Storage Architecture Decisions

### Decision 1: Storage Backend Selection
```
Single Validator Node (Soloist Mode):
  - RocksDB: Fast, embedded, no external dependencies
  - On-disk size: ~5-10 GB per year of history
  - Recovery time: < 10 seconds

Distributed Validator:
  - PostgreSQL: Scalable, queryable, replicable
  - Connection pooling for concurrent access
  - Automatic backups

Light Client:
  - SQLite: Minimal footprint, local queries
  - Snapshot-based recovery only (no full history)
```

### Decision 2: Retention Policy
```
Keep all votes:   ❌ Unbounded storage growth
Keep last N blocks: ✅ Bounded, configurable retention
Archive old data: ✅ Move to cold storage after finalization
```
**Chosen**: ✅ Keep votes for last 1000 blocks in hot storage, archive older votes to cold storage

### Decision 3: Write Strategy
```
Synchronous:  ❌ Slow down consensus on every write
Batched:      ✅ Buffer writes, flush periodically
Async:        ⚠️  Risk of data loss on crash
```
**Chosen**: ✅ Batched writes for votes (flush every 100 votes or 5 seconds)

### Decision 4: Snapshot Frequency
```
Every block:   ❌ Too frequent, storage overhead
Every 1000:    ✅ Balance between recovery time and storage
Every 10000:   ❌ Long recovery on crash
```
**Chosen**: ✅ Every 1000 blocks (configurable)

---

## Success Criteria

- [ ] All consensus decisions persisted to durable storage
- [ ] Recovery from crash restores exact consensus state
- [ ] No votes lost even on abrupt shutdown
- [ ] Validator state survives restarts
- [ ] Audit log enables full forensic analysis
- [ ] Byzantine evidence proves validator misconduct
- [ ] Snapshots enable new validators to join in < 1 minute
- [ ] All tests pass (100+ storage integration tests)
- [ ] Performance: vote persistence < 10ms per vote
- [ ] Storage usage: < 1GB per 100,000 blocks
- [ ] Backup/restore procedures documented and tested
- [ ] Data integrity verified on startup

---

## Related Issues

- [ ] Issue #X: RocksDB integration for consensus
- [ ] Issue #X: PostgreSQL adapter for validator nodes
- [ ] Issue #X: Snapshot system design
- [ ] Issue #X: Byzantine evidence collection
- [ ] Issue #X: Recovery procedures and testing

---

## References

- RocksDB Documentation: https://rocksdb.org/
- Database Durability: https://en.wikipedia.org/wiki/Durability_(database_systems)
- WAL (Write-Ahead Logging): https://en.wikipedia.org/wiki/Write-ahead_logging
- Checkpointing: https://en.wikipedia.org/wiki/Checkpoint_(computing)
- Byzantine Fault Tolerance: https://arxiv.org/abs/1902.06822
