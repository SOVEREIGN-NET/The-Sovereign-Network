# Consensus Engines Documentation

This document provides comprehensive documentation for all consensus engines in the ZHTP Consensus System, including Byzantine Fault Tolerant (BFT), Enhanced BFT, Hybrid, and Zero-Knowledge integration engines.

##  Overview

The ZHTP Consensus System implements multiple consensus engines to support different network requirements and security models. Each engine is optimized for specific use cases while maintaining interoperability and shared infrastructure.

## 🏗️ Engine Architecture

### Core Design Principles

1. **Modularity**: Each engine implements the `ConsensusEngine` trait
2. **Interoperability**: Shared types and interfaces across engines
3. **Pluggability**: Easy switching between consensus mechanisms
4. **Performance**: Optimized for high throughput and low latency
5. **Security**: Post-quantum cryptography and Byzantine fault tolerance

### Engine Hierarchy

```
ConsensusEngine (Main)
├── BftEngine (Basic BFT)
├── EnhancedBftEngine (Optimized BFT)
├── HybridEngine (PoS + PoStorage)
└── ZkIntegration (Privacy Layer)
```

## 💪 Main Consensus Engine

### ConsensusEngine

The primary consensus engine that coordinates all consensus mechanisms and provides a unified interface.

```rust
pub struct ConsensusEngine {
    /// Local validator identity
    validator_identity: Option<IdentityId>,
    /// Validator management
    validator_manager: ValidatorManager,
    /// Current consensus round
    current_round: ConsensusRound,
    /// Consensus configuration
    config: ConsensusConfig,
    /// Pending proposals queue
    pending_proposals: VecDeque<ConsensusProposal>,
    /// Vote pool organized by height
    vote_pool: HashMap<u64, HashMap<Hash, ConsensusVote>>,
    /// Consensus state history
    round_history: VecDeque<ConsensusRound>,
    /// DAO governance engine
    dao_engine: DaoEngine,
    /// Byzantine fault detection
    byzantine_detector: ByzantineFaultDetector,
    /// Reward calculation system
    reward_calculator: RewardCalculator,
}
```

### Core Methods

#### Initialization and Configuration

```rust
impl ConsensusEngine {
    /// Create a new consensus engine
    pub fn new(config: ConsensusConfig) -> ConsensusResult<Self> {
        // Initialize all components
        let validator_manager = ValidatorManager::new(
            config.max_validators,
            config.min_stake,
            config.min_storage,
        );
        
        // Set up initial consensus round
        let current_round = ConsensusRound {
            height: 0,
            round: 0,
            step: ConsensusStep::Propose,
            start_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            proposer: None,
            proposals: Vec::new(),
            votes: HashMap::new(),
            timed_out: false,
            locked_proposal: None,
            valid_proposal: None,
        };

        Ok(Self {
            validator_identity: None,
            validator_manager,
            current_round,
            config,
            pending_proposals: VecDeque::new(),
            vote_pool: HashMap::new(),
            round_history: VecDeque::new(),
            dao_engine: DaoEngine::new(),
            byzantine_detector: ByzantineFaultDetector::new(),
            reward_calculator: RewardCalculator::new(),
        })
    }
}
```

#### Validator Registration

```rust
/// Register as a validator in the consensus network
pub async fn register_validator(
    &mut self,
    identity: IdentityId,
    stake: u64,
    storage_capacity: u64,
    consensus_key: Vec<u8>,
    commission_rate: u8,
    is_genesis: bool,
) -> ConsensusResult<()> {
    // Validate minimum requirements (skip for genesis node)
    if !is_genesis && stake < self.config.min_stake {
        return Err(ConsensusError::ValidatorError(
            "Insufficient stake amount".to_string()
        ));
    }

    if storage_capacity < self.config.min_storage {
        return Err(ConsensusError::ValidatorError(
            "Insufficient storage capacity".to_string()
        ));
    }

    // Register with validator manager
    self.validator_manager.register_validator(
        identity.clone(),
        stake,
        storage_capacity,
        consensus_key,
        commission_rate,
    )?;

    // Set as local validator if this is the first one
    if self.validator_identity.is_none() {
        self.validator_identity = Some(identity.clone());
    }

    tracing::info!(" Registered validator {:?} with {} ZHTP stake", identity, stake);
    Ok(())
}
```

#### Event-Driven Consensus

The main consensus engine uses an event-driven architecture for clean component interaction:

```rust
/// Process a single consensus event
pub async fn handle_consensus_event(
    &mut self, 
    event: ConsensusEvent
) -> ConsensusResult<Vec<ConsensusEvent>> {
    match event {
        ConsensusEvent::StartRound { height, trigger } => {
            tracing::info!(" Starting consensus round {} (trigger: {})", height, trigger);
            self.prepare_consensus_round(height).await?;
            Ok(vec![ConsensusEvent::RoundPrepared { height }])
        }
        
        ConsensusEvent::NewBlock { height, previous_hash } => {
            tracing::info!("🧱 Processing new block at height {}", height);
            
            // Validate blockchain continuity
            self.validate_previous_hash(height, &previous_hash).await?;
            
            match self.run_consensus_round().await {
                Ok(_) => {
                    let mut events = vec![ConsensusEvent::RoundCompleted { height }];
                    
                    // Process DAO proposals
                    if let Err(e) = self.dao_engine.process_expired_proposals().await {
                        events.push(ConsensusEvent::DaoError { error: e.to_string() });
                    }
                    
                    // Check for Byzantine faults
                    if let Err(e) = self.byzantine_detector.detect_faults(&self.validator_manager) {
                        events.push(ConsensusEvent::ByzantineFault { error: e.to_string() });
                    }
                    
                    // Calculate rewards
                    if let Err(e) = self.reward_calculator.calculate_round_rewards(
                        &self.validator_manager, 
                        self.current_round.height
                    ) {
                        events.push(ConsensusEvent::RewardError { error: e.to_string() });
                    }
                    
                    Ok(events)
                },
                Err(e) => {
                    tracing::error!(" Consensus round failed: {}", e);
                    Ok(vec![ConsensusEvent::RoundFailed { height, error: e.to_string() }])
                }
            }
        }
        
        ConsensusEvent::ValidatorJoin { identity, stake } => {
            self.handle_validator_registration(identity.clone(), stake).await?;
            Ok(vec![ConsensusEvent::ValidatorRegistered { identity }])
        }
        
        _ => {
            tracing::debug!("Unhandled consensus event: {:?}", event);
            Ok(vec![])
        }
    }
}
```

### Consensus Round Execution

The consensus engine implements a sophisticated multi-phase consensus protocol:

```rust
/// Run a complete consensus round
async fn run_consensus_round(&mut self) -> ConsensusResult<()> {
    self.advance_to_next_round();

    // Select proposer for this round
    let proposer = self.validator_manager
        .select_proposer(self.current_round.height, self.current_round.round)
        .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

    self.current_round.proposer = Some(proposer.identity.clone());

    tracing::info!(
        " Starting consensus round {} at height {} with proposer {:?}",
        self.current_round.round, self.current_round.height, proposer.identity
    );

    // Execute consensus phases
    self.run_propose_step().await?;    // Phase 1: Proposal
    self.run_prevote_step().await?;    // Phase 2: Pre-voting
    self.run_precommit_step().await?;  // Phase 3: Pre-commit
    self.run_commit_step().await?;     // Phase 4: Final commit

    // Archive completed round
    self.archive_completed_round();

    Ok(())
}
```

#### Phase 1: Proposal Step

```rust
async fn run_propose_step(&mut self) -> ConsensusResult<()> {
    self.current_round.step = ConsensusStep::Propose;

    // If we are the proposer, create a proposal
    if let Some(ref validator_id) = self.validator_identity {
        if Some(validator_id) == self.current_round.proposer.as_ref() {
            let proposal = self.create_proposal().await?;
            self.current_round.proposals.push(proposal.id.clone());
            self.pending_proposals.push_back(proposal);
            
            tracing::info!(" Created proposal as proposer");
        }
    }

    // Wait for proposals with timeout
    self.wait_for_step_timeout(self.config.propose_timeout).await;
    Ok(())
}
```

#### Phase 2: Pre-vote Step

```rust
async fn run_prevote_step(&mut self) -> ConsensusResult<()> {
    self.current_round.step = ConsensusStep::PreVote;

    // Cast prevote for the first valid proposal
    if let Some(proposal_id) = self.current_round.proposals.first() {
        self.cast_vote(proposal_id.clone(), VoteType::PreVote).await?;
        tracing::debug!(" Cast prevote for proposal {:?}", proposal_id);
    }

    // Wait for prevotes with timeout
    self.wait_for_step_timeout(self.config.prevote_timeout).await;
    Ok(())
}
```

#### Phase 3: Pre-commit Step

```rust
async fn run_precommit_step(&mut self) -> ConsensusResult<()> {
    self.current_round.step = ConsensusStep::PreCommit;

    // Check if we received enough prevotes
    if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
        let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
        let threshold = self.validator_manager.get_byzantine_threshold();

        if prevote_count >= threshold {
            self.cast_vote(proposal_id.clone(), VoteType::PreCommit).await?;
            self.current_round.valid_proposal = Some(proposal_id);
            tracing::debug!(" Proposal achieved prevote threshold, casting precommit");
        }
    }

    // Wait for precommits with timeout
    self.wait_for_step_timeout(self.config.precommit_timeout).await;
    Ok(())
}
```

#### Phase 4: Commit Step

```rust
async fn run_commit_step(&mut self) -> ConsensusResult<()> {
    self.current_round.step = ConsensusStep::Commit;

    // Check if we received enough precommits
    if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
        let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
        let threshold = self.validator_manager.get_byzantine_threshold();

        if precommit_count >= threshold {
            self.cast_vote(proposal_id.clone(), VoteType::Commit).await?;
            
            tracing::info!(
                " Block committed at height {} with proposal {:?}",
                self.current_round.height, proposal_id
            );

            // Process the committed block
            self.process_committed_block(&proposal_id).await?;
        }
    }

    Ok(())
}
```

### Proposal Creation and Validation

The consensus engine creates cryptographically secure proposals:

```rust
/// Create a new consensus proposal
async fn create_proposal(&self) -> ConsensusResult<ConsensusProposal> {
    let validator_id = self.validator_identity.as_ref()
        .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

    // Get previous block hash from blockchain state
    let previous_hash = self.get_previous_block_hash().await?;

    // Collect pending transactions for this block
    let block_data = self.collect_block_transactions().await?;

    // Generate deterministic proposal ID
    let proposal_id = Hash::from_bytes(&hash_blake3(&[
        &self.current_round.height.to_le_bytes(),
        previous_hash.as_bytes(),
        &block_data,
        validator_id.as_bytes(),
    ].concat()));

    // Create consensus proof based on configured consensus type
    let consensus_proof = self.create_consensus_proof().await?;

    // Sign the proposal data
    let proposal_data = self.serialize_proposal_data(
        &proposal_id,
        validator_id,
        self.current_round.height,
        &previous_hash,
        &block_data,
    )?;
    
    let signature = self.sign_proposal_data(&proposal_data).await?;

    let proposal = ConsensusProposal {
        id: proposal_id,
        proposer: validator_id.clone(),
        height: self.current_round.height,
        previous_hash,
        block_data,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        signature,
        consensus_proof,
    };

    tracing::info!(" Created proposal {:?} for height {}", proposal.id, proposal.height);
    Ok(proposal)
}
```

### Consensus Proof Generation

Different consensus proofs are generated based on the configured consensus type:

```rust
/// Create consensus proof based on configuration
async fn create_consensus_proof(&self) -> ConsensusResult<ConsensusProof> {
    let consensus_type = self.config.consensus_type.clone();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    match consensus_type {
        ConsensusType::ProofOfStake => {
            let stake_proof = self.create_stake_proof().await?;
            Ok(ConsensusProof {
                consensus_type,
                stake_proof: Some(stake_proof),
                storage_proof: None,
                work_proof: None,
                zk_did_proof: None,
                timestamp,
            })
        },
        ConsensusType::ProofOfStorage => {
            let storage_proof = self.create_storage_proof().await?;
            Ok(ConsensusProof {
                consensus_type,
                stake_proof: None,
                storage_proof: Some(storage_proof),
                work_proof: None,
                zk_did_proof: None,
                timestamp,
            })
        },
        ConsensusType::ProofOfUsefulWork => {
            let work_proof = self.create_work_proof().await?;
            Ok(ConsensusProof {
                consensus_type,
                stake_proof: None,
                storage_proof: None,
                work_proof: Some(work_proof),
                zk_did_proof: None,
                timestamp,
            })
        },
        ConsensusType::Hybrid => {
            let stake_proof = self.create_stake_proof().await?;
            let storage_proof = self.create_storage_proof().await?;
            Ok(ConsensusProof {
                consensus_type,
                stake_proof: Some(stake_proof),
                storage_proof: Some(storage_proof),
                work_proof: None,
                zk_did_proof: None,
                timestamp,
            })
        },
        ConsensusType::ByzantineFaultTolerance => {
            // BFT uses all proof types for maximum security
            let stake_proof = self.create_stake_proof().await?;
            let storage_proof = self.create_storage_proof().await?;
            let work_proof = self.create_work_proof().await?;
            Ok(ConsensusProof {
                consensus_type,
                stake_proof: Some(stake_proof),
                storage_proof: Some(storage_proof),
                work_proof: Some(work_proof),
                zk_did_proof: None,
                timestamp,
            })
        },
    }
}
```

##  BFT Engine

### Basic BFT Implementation

The BFT engine provides fundamental Byzantine Fault Tolerance:

```rust
pub struct BftEngine {
    /// Current round state
    round_state: BftRoundState,
    /// Validator set
    validator_set: ValidatorSet,
    /// Vote collector
    vote_collector: VoteCollector,
    /// Message validator
    message_validator: MessageValidator,
}

impl BftEngine {
    /// Process BFT consensus step
    pub async fn process_bft_step(&mut self, step: BftStep) -> Result<BftStepResult> {
        match step {
            BftStep::Propose(proposal) => {
                self.validate_proposal(&proposal).await?;
                self.broadcast_prevote(&proposal).await?;
                Ok(BftStepResult::ProposalProcessed)
            },
            BftStep::Prevote(vote) => {
                self.collect_prevote(vote).await?;
                if self.has_prevote_majority() {
                    self.broadcast_precommit().await?;
                }
                Ok(BftStepResult::PrevoteProcessed)
            },
            BftStep::Precommit(vote) => {
                self.collect_precommit(vote).await?;
                if self.has_precommit_majority() {
                    self.commit_block().await?;
                    return Ok(BftStepResult::BlockCommitted);
                }
                Ok(BftStepResult::PrecommitProcessed)
            },
        }
    }
}
```

### BFT Security Guarantees

The BFT engine provides strong security guarantees:

1. **Safety**: Never commits conflicting blocks
2. **Liveness**: Eventually makes progress under network synchrony
3. **Byzantine Tolerance**: Handles up to 1/3 malicious validators
4. **Deterministic Finality**: Committed blocks are immediately final

##  Enhanced BFT Engine

### Advanced Features

The Enhanced BFT engine adds optimizations and advanced features:

```rust
pub struct EnhancedBftEngine {
    /// Base BFT engine
    base_bft: BftEngine,
    /// Performance optimizations
    optimizations: BftOptimizations,
    /// Zero-knowledge integration
    zk_integration: ZkIntegration,
    /// Advanced vote aggregation
    vote_aggregator: VoteAggregator,
}

#[derive(Debug, Clone)]
pub struct BftOptimizations {
    /// Enable vote batching
    pub enable_vote_batching: bool,
    /// Pipeline consensus rounds
    pub enable_pipelining: bool,
    /// Optimistic responsiveness
    pub enable_optimistic_response: bool,
    /// View synchronization
    pub enable_view_sync: bool,
}

impl EnhancedBftEngine {
    /// Process consensus with optimizations
    pub async fn process_optimized_consensus(
        &mut self,
        input: ConsensusInput
    ) -> Result<ConsensusOutput> {
        // Apply performance optimizations
        if self.optimizations.enable_vote_batching {
            input = self.batch_votes(input).await?;
        }
        
        if self.optimizations.enable_pipelining {
            return self.process_pipelined_consensus(input).await;
        }
        
        // Standard processing with optimizations
        self.process_with_optimizations(input).await
    }
}
```

### Vote Aggregation

Enhanced BFT uses sophisticated vote aggregation:

```rust
impl VoteAggregator {
    /// Aggregate votes using cryptographic techniques
    pub fn aggregate_votes(&mut self, votes: Vec<BftVote>) -> Result<AggregatedVote> {
        // Validate all votes
        for vote in &votes {
            self.validate_vote(vote)?;
        }
        
        // Create aggregated signature
        let aggregated_sig = self.aggregate_signatures(&votes)?;
        
        // Create vote bitmap
        let vote_bitmap = self.create_vote_bitmap(&votes)?;
        
        Ok(AggregatedVote {
            proposal_hash: votes[0].proposal_hash,
            vote_type: votes[0].vote_type,
            aggregated_signature: aggregated_sig,
            voter_bitmap: vote_bitmap,
            vote_count: votes.len(),
        })
    }
}
```

##  Hybrid Engine

### PoS + PoStorage Combination

The Hybrid engine combines Proof of Stake and Proof of Storage:

```rust
pub struct HybridEngine {
    /// Proof of Stake component
    pos_engine: ProofOfStakeEngine,
    /// Proof of Storage component
    pos_storage_engine: ProofOfStorageEngine,
    /// Weight balancing between PoS and PoStorage
    consensus_weights: ConsensusWeights,
}

#[derive(Debug, Clone)]
pub struct ConsensusWeights {
    /// Weight for Proof of Stake (0.0 - 1.0)
    pub stake_weight: f64,
    /// Weight for Proof of Storage (0.0 - 1.0) 
    pub storage_weight: f64,
}

impl HybridEngine {
    /// Calculate hybrid consensus score
    pub fn calculate_consensus_score(
        &self,
        validator: &Validator,
        stake_proof: &StakeProof,
        storage_proof: &StorageCapacityAttestation,
    ) -> Result<f64> {
        // Calculate PoS score
        let stake_score = self.pos_engine.calculate_stake_score(validator, stake_proof)?;
        
        // Calculate PoStorage score
        let storage_score = self.pos_storage_engine.calculate_storage_score(validator, storage_proof)?;
        
        // Combine scores with weights
        let hybrid_score = (stake_score * self.consensus_weights.stake_weight) +
                          (storage_score * self.consensus_weights.storage_weight);
        
        Ok(hybrid_score)
    }
    
    /// Select validator based on hybrid consensus
    pub async fn select_validator(&mut self) -> Result<ValidatorSelection> {
        let mut candidates = Vec::new();
        
        // Evaluate all active validators
        for validator in self.get_active_validators() {
            let stake_proof = validator.get_stake_proof()?;
            let storage_proof = validator.get_storage_proof().await?;
            
            let score = self.calculate_consensus_score(validator, &stake_proof, &storage_proof)?;
            
            candidates.push(ValidatorCandidate {
                validator: validator.clone(),
                consensus_score: score,
                stake_proof,
                storage_proof,
            });
        }
        
        // Sort by consensus score and apply randomization
        candidates.sort_by(|a, b| b.consensus_score.partial_cmp(&a.consensus_score).unwrap());
        
        // Weighted random selection from top candidates
        self.weighted_selection(candidates).await
    }
}
```

### Dynamic Weight Adjustment

The hybrid engine can dynamically adjust consensus weights:

```rust
impl HybridEngine {
    /// Adjust consensus weights based on network conditions
    pub fn adjust_consensus_weights(&mut self, network_state: &NetworkState) -> Result<()> {
        // If storage is abundant, increase storage weight
        if network_state.storage_utilization < 0.5 {
            self.consensus_weights.storage_weight = 0.7;
            self.consensus_weights.stake_weight = 0.3;
        }
        // If stake participation is low, increase stake weight
        else if network_state.stake_participation < 0.6 {
            self.consensus_weights.stake_weight = 0.8;
            self.consensus_weights.storage_weight = 0.2;
        }
        // Balanced weights for normal conditions
        else {
            self.consensus_weights.stake_weight = 0.6;
            self.consensus_weights.storage_weight = 0.4;
        }
        
        tracing::info!(
            " Adjusted consensus weights: stake={:.1}, storage={:.1}",
            self.consensus_weights.stake_weight,
            self.consensus_weights.storage_weight
        );
        
        Ok(())
    }
}
```

##  Zero-Knowledge Integration

### Privacy-Preserving Consensus

The ZK integration module provides privacy features:

```rust
pub struct ZkIntegration {
    /// ZK proof system
    proof_system: ZkProofSystem,
    /// Private state management
    private_state: ZkPrivateState,
    /// Verification keys
    verification_keys: ZkVerificationKeys,
}

impl ZkIntegration {
    /// Generate zero-knowledge proof for consensus participation
    pub async fn generate_consensus_proof(
        &mut self,
        validator_secret: &ValidatorSecret,
        public_inputs: &ConsensusPublicInputs,
    ) -> Result<ZkConsensusProof> {
        // Create witness from secret inputs
        let witness = ZkWitness {
            validator_key: validator_secret.private_key.clone(),
            stake_amount: validator_secret.stake_amount,
            storage_commitment: validator_secret.storage_commitment.clone(),
            random_nonce: self.generate_random_nonce(),
        };
        
        // Generate proof
        let proof = self.proof_system.prove(
            &self.verification_keys.consensus_circuit,
            &witness,
            public_inputs,
        ).await?;
        
        Ok(ZkConsensusProof {
            proof,
            public_inputs: public_inputs.clone(),
            nullifier: self.compute_nullifier(&witness)?,
        })
    }
    
    /// Verify zero-knowledge consensus proof
    pub async fn verify_consensus_proof(
        &self,
        proof: &ZkConsensusProof,
    ) -> Result<bool> {
        // Verify the ZK proof
        let proof_valid = self.proof_system.verify(
            &self.verification_keys.consensus_circuit,
            &proof.proof,
            &proof.public_inputs,
        ).await?;
        
        if !proof_valid {
            return Ok(false);
        }
        
        // Check nullifier hasn't been used
        let nullifier_fresh = !self.private_state.has_nullifier(&proof.nullifier)?;
        
        Ok(proof_valid && nullifier_fresh)
    }
}
```

### Private Validator Set

ZK integration can hide validator identities:

```rust
impl ZkIntegration {
    /// Create anonymous validator proof
    pub async fn create_anonymous_validator_proof(
        &mut self,
        validator: &Validator,
        validator_set: &ValidatorSet,
    ) -> Result<AnonymousValidatorProof> {
        // Create membership proof
        let membership_proof = self.prove_validator_membership(
            validator,
            validator_set,
        ).await?;
        
        // Create stake proof without revealing exact amount
        let stake_range_proof = self.prove_stake_in_range(
            validator.stake,
            self.get_minimum_stake(),
            self.get_maximum_stake(),
        ).await?;
        
        Ok(AnonymousValidatorProof {
            membership_proof,
            stake_range_proof,
            validator_commitment: self.compute_validator_commitment(validator)?,
        })
    }
}
```

##  Performance Characteristics

### Throughput and Latency

Each consensus engine has different performance characteristics:

| Engine | TPS | Latency | Memory | CPU |
|--------|-----|---------|--------|-----|
| BFT Engine | 500-1000 | 3-6s | Low | Moderate |
| Enhanced BFT | 1000-2000 | 1-3s | Moderate | High |
| Hybrid Engine | 800-1500 | 2-4s | Moderate | Moderate |
| ZK Integration | 200-500 | 5-10s | High | Very High |

### Scalability Considerations

```rust
impl ConsensusEngine {
    /// Get performance metrics for current configuration
    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        let validator_count = self.validator_manager.get_active_validators().len();
        
        // Calculate expected throughput based on consensus type and validator count
        let base_throughput = match self.config.consensus_type {
            ConsensusType::ByzantineFaultTolerance => 500,
            ConsensusType::Hybrid => 800,
            ConsensusType::ProofOfStake => 1200,
            _ => 600,
        };
        
        // Adjust for validator count (more validators = more communication overhead)
        let throughput_factor = if validator_count <= 10 {
            1.0
        } else if validator_count <= 50 {
            0.8
        } else {
            0.6
        };
        
        let expected_throughput = (base_throughput as f64 * throughput_factor) as u32;
        
        PerformanceMetrics {
            expected_throughput,
            expected_latency: self.config.block_time,
            validator_count: validator_count as u32,
            consensus_type: self.config.consensus_type.clone(),
            byzantine_threshold: self.validator_manager.get_byzantine_threshold(),
        }
    }
}
```

##  Configuration and Tuning

### Engine-Specific Configuration

Each engine supports specific configuration options:

```rust
#[derive(Debug, Clone)]
pub struct EngineConfiguration {
    /// BFT engine settings
    pub bft_config: BftConfig,
    /// Enhanced BFT optimizations
    pub enhanced_bft_config: EnhancedBftConfig,
    /// Hybrid engine weights
    pub hybrid_config: HybridConfig,
    /// ZK integration settings
    pub zk_config: ZkConfig,
}

#[derive(Debug, Clone)]
pub struct BftConfig {
    /// Timeout for propose phase (ms)
    pub propose_timeout: u64,
    /// Timeout for prevote phase (ms)
    pub prevote_timeout: u64,
    /// Timeout for precommit phase (ms)
    pub precommit_timeout: u64,
    /// Maximum rounds before view change
    pub max_rounds: u32,
}

#[derive(Debug, Clone)]
pub struct EnhancedBftConfig {
    /// Enable performance optimizations
    pub optimizations: BftOptimizations,
    /// Vote aggregation settings
    pub vote_aggregation: VoteAggregationConfig,
    /// Pipelining depth
    pub pipeline_depth: u32,
}
```

### Adaptive Configuration

The engines can adapt their configuration based on network conditions:

```rust
impl ConsensusEngine {
    /// Adapt configuration based on network performance
    pub async fn adapt_configuration(&mut self, metrics: &NetworkMetrics) -> Result<()> {
        // Adjust timeouts based on network latency
        if metrics.average_latency > Duration::from_millis(2000) {
            self.config.propose_timeout *= 2;
            self.config.prevote_timeout *= 2;
            self.config.precommit_timeout *= 2;
            tracing::info!(" Increased timeouts due to high network latency");
        }
        
        // Adjust consensus type based on network conditions
        if metrics.byzantine_faults_detected > 0 && 
           self.config.consensus_type != ConsensusType::ByzantineFaultTolerance {
            self.config.consensus_type = ConsensusType::ByzantineFaultTolerance;
            tracing::warn!(" Switched to full BFT due to detected Byzantine faults");
        }
        
        // Adjust hybrid weights based on resource availability
        if let ConsensusType::Hybrid = self.config.consensus_type {
            self.adjust_hybrid_weights(metrics).await?;
        }
        
        Ok(())
    }
}
```

## 🛠️ Usage Examples

### Basic Consensus Setup

```rust
use lib_consensus::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure consensus
    let config = ConsensusConfig {
        consensus_type: ConsensusType::Hybrid,
        min_stake: 1000 * 1_000_000, // 1000 ZHTP
        min_storage: 100 * 1024 * 1024 * 1024, // 100 GB
        max_validators: 100,
        block_time: 10,
        ..Default::default()
    };
    
    // Create and start consensus engine
    let mut consensus = ConsensusEngine::new(config)?;
    
    // Register as validator
    let identity = create_validator_identity();
    consensus.register_validator(
        identity,
        5000 * 1_000_000, // 5000 ZHTP stake
        500 * 1024 * 1024 * 1024, // 500 GB storage
        generate_consensus_key(),
        5, // 5% commission
        false,
    ).await?;
    
    // Handle consensus events
    loop {
        let event = receive_consensus_event().await;
        let response_events = consensus.handle_consensus_event(event).await?;
        
        for response_event in response_events {
            handle_response_event(response_event).await?;
        }
    }
}
```

### Advanced Engine Configuration

```rust
// Configure enhanced BFT with optimizations
let enhanced_config = EngineConfiguration {
    bft_config: BftConfig {
        propose_timeout: 3000,
        prevote_timeout: 1000,
        precommit_timeout: 1000,
        max_rounds: 3,
    },
    enhanced_bft_config: EnhancedBftConfig {
        optimizations: BftOptimizations {
            enable_vote_batching: true,
            enable_pipelining: true,
            enable_optimistic_response: true,
            enable_view_sync: true,
        },
        vote_aggregation: VoteAggregationConfig {
            batch_size: 50,
            aggregation_timeout: 500,
        },
        pipeline_depth: 3,
    },
    hybrid_config: HybridConfig {
        stake_weight: 0.6,
        storage_weight: 0.4,
        dynamic_adjustment: true,
    },
    zk_config: ZkConfig {
        enable_private_validators: false,
        proof_system: ZkProofSystem::Groth16,
        circuit_size: CircuitSize::Medium,
        verification_key_rotation_blocks: 1000,
    },
};
```

---

This comprehensive documentation covers all consensus engines in the ZHTP system, providing developers with the knowledge needed to understand, configure, and optimize the consensus mechanisms for their specific requirements.
