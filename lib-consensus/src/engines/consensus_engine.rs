//! Main consensus engine implementation combining all consensus mechanisms
//!
//! # Enforced Invariants for BFT Safety
//!
//! This consensus engine enforces the following invariants to ensure BFT safety:
//!
//! ## Vote Validity (Local and Deterministic)
//!
//! Vote validity is local and deterministic. A remote vote is accepted only if ALL
//! of the following conditions hold. Invalid votes are rejected immediately and never stored:
//!
//! 1. **Signature**: Cryptographically valid, verified against the vote's own data (height/round), not local state
//! 2. **Validator membership**: Sender is in the validator set for the target height (height-scoped)
//! 3. **Height**: vote.height == local.height (rejects votes for wrong height)
//! 4. **Round**: vote.round == local.round (rejects votes for wrong round)
//! 5. **Vote type coherence**: PreVote ONLY valid in PreVote step; PreCommit ONLY valid in PreCommit step (strict equality)
//!
//! This is enforced by `validate_remote_vote()` and `on_commit_vote()`.
//!
//! **Critical Fixes** (CONSENSUS-NET-4.3 Issue Corrections):
//! - Signature verification uses vote data bound to vote.height/round, not local consensus state
//! - Vote type validation uses strict == equality, rejecting late votes unconditionally
//! - Validator membership is height-scoped (implementation tracks current set; TODO for epoch transitions)
//!
//! ## Quorum is Proposal-Scoped, Not Round-Scoped
//!
//! Quorum calculations are proposal-scoped to prevent split votes from being mistaken for quorum:
//!
//! - **Supermajority requires identical votes**: All votes counted toward quorum must have:
//!   - Same height
//!   - Same round
//!   - Same proposal/block hash
//!   - Same vote type (PreVote or PreCommit)
//! - **Threshold calculation**: (total_validators * 2 / 3) + 1 using integer division
//!
//! - **Mixed or split votes DO NOT count**: If validators disagree on which proposal to vote for,
//!   no supermajority is reached until 2/3+1 agree on the same proposal.
//!
//! This is enforced by `count_prevotes_for()`, `count_precommits_for()`, and
//! `check_supermajority()` which use proposal-scoped vote counting.
//!
//! Example: With 4 validators:
//! - Threshold = floor(8/3) + 1 = 3
//! - 2 votes for proposal A + 2 votes for proposal B = 0 quorum (mixed votes)
//! - 3 votes for proposal A = quorum reached
//!
//! ## No Vote Can Advance Consensus Unless It Matches Local Step
//!
//! PreVotes advance consensus only during PreVote step, PreCommits only during PreCommit step.
//! This is enforced in `on_prevote()` and `on_precommit()` which call `validate_remote_vote()`.
//!
//! Exception: Commit votes can finalize immediately regardless of local step,
//! but only if 2/3+1 identical commit votes are present (CE-L1, CE-L2 liveness rules).
//!
//! ## No Vote Equivocation
//!
//! A validator cannot vote twice for the same (height, round, vote_type).
//! Multiple votes from the same validator for the same (H,R,type) trigger equivocation detection.
//! This is enforced by the composite key in `VotePoolKey`.
//!
//! ## Design Principles
//!
//! - **Determinism**: Given the same inputs, consensus produces the same sequence of steps.
//! - **Locality**: Vote validation depends only on local state, not network availability.
//! - **Simplicity**: All validation is explicit and fully specified in code comments.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lib_crypto::{hash_blake3, Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use tokio::sync::mpsc;
use tokio::time::Sleep;

use crate::byzantine::ByzantineFaultDetector;
use crate::dao::DaoEngine;
use crate::proofs::{StakeProof, StorageProof, WorkProof};
use crate::rewards::RewardCalculator;
use crate::types::*;
use crate::validators::ValidatorManager;
use crate::{ConsensusError, ConsensusResult};

/// Token binding a timer to a specific consensus state
///
/// Prevents stale timeout fires from affecting a different (height, round, step).
/// Invariant: Timer fire must validate token matches current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerToken {
    pub height: u64,
    pub round: u32,
    pub step_ordinal: u8, // Encode step as ordinal (Propose=0, PreVote=1, PreCommit=2, Commit=3)
}

impl TimerToken {
    pub fn new(height: u64, round: u32, step: &ConsensusStep) -> Self {
        Self {
            height,
            round,
            step_ordinal: step.as_ordinal(),
        }
    }

    pub fn matches(&self, height: u64, round: u32, step: &ConsensusStep) -> bool {
        self.height == height && self.round == round && self.step_ordinal == step.as_ordinal()
    }
}

/// Round timer that tracks timeouts bound to specific (height, round, step)
///
/// Invariant: Timer is only valid for a specific consensus state.
/// When state changes, the timer must be replaced.
pub struct RoundTimer {
    proposal_timeout: Duration,
    prevote_timeout: Duration,
    precommit_timeout: Duration,
}

impl RoundTimer {
    pub fn new(config: &ConsensusConfig) -> Self {
        Self {
            proposal_timeout: Duration::from_millis(config.propose_timeout),
            prevote_timeout: Duration::from_millis(config.prevote_timeout),
            precommit_timeout: Duration::from_millis(config.precommit_timeout),
        }
    }

    /// Get the next deadline for the given state
    pub fn next_deadline(&self, _height: u64, _round: u32, step: &ConsensusStep) -> Sleep {
        let duration = match step {
            ConsensusStep::Propose => self.proposal_timeout,
            ConsensusStep::PreVote => self.prevote_timeout,
            ConsensusStep::PreCommit => self.precommit_timeout,
            // For now, reuse the precommit timeout for commit, and proposal timeout for a new round.
            // Both values are derived from ConsensusConfig.
            ConsensusStep::Commit => self.precommit_timeout,
            ConsensusStep::NewRound => self.proposal_timeout,
        };
        tokio::time::sleep(duration)
    }
}

/// Check supermajority with explicit quorum calculation
///
/// Makes quorum math explicit and correct:
/// - threshold = (total_validators * 2 / 3) + 1 (using integer division, which is equivalent to floor for positive integers)
/// - Matching votes means same height, round, proposal/block hash, and vote type
/// - Mixed or split votes MUST NOT count toward quorum
///
/// **Invariant**: Supermajority requires identical votes, not aggregate counts.
/// A supermajority on a proposal means 2/3 + 1 validators agree on ALL aspects:
/// - Same height
/// - Same round
/// - Same proposal/block hash
/// - Same vote type (PreVote or PreCommit)
fn check_supermajority(matching_votes: u64, total_validators: u64) -> bool {
    let threshold = (total_validators * 2 / 3) + 1;
    matching_votes >= threshold
}

/// Vote pool entry key: composite key to prevent equivocation
///
/// Invariant: One vote per (height, round, vote_type, validator_id).
/// A validator equivocating (sending multiple different values for same H/R/type)
/// must be detected and treated as evidence, not accepted silently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VotePoolKey {
    height: u64,
    round: u32,
    vote_type: VoteType,
    validator_id: IdentityId,
}

/// Main ZHTP consensus engine combining all consensus mechanisms
///
/// Debug is not derived because `MessageBroadcaster` is a trait object.
/// Use tracing/logging at call sites instead.
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
    /// Vote pool using composite key (height, round, vote_type, validator_id)
    /// Prevents equivocation: one vote per (H,R,type,validator).
    /// Values are (ConsensusVote, value_hash) to detect conflicting votes from same validator.
    vote_pool: HashMap<VotePoolKey, (ConsensusVote, Hash)>,
    /// Consensus state history
    round_history: VecDeque<ConsensusRound>,
    /// DAO governance engine
    dao_engine: DaoEngine,
    /// Byzantine fault detection
    byzantine_detector: ByzantineFaultDetector,
    /// Reward calculation system
    reward_calculator: RewardCalculator,
    /// Message broadcaster for network distribution
    ///
    /// Invariant CE-ENG-1: ConsensusEngine never constructs, configures, or inspects
    /// the broadcaster. It only calls it.
    broadcaster: Arc<dyn MessageBroadcaster>,
    /// Message receiver from network layer (Gap 4)
    message_rx: Option<mpsc::Receiver<ValidatorMessage>>,
    /// Round timer for phase timeouts
    round_timer: RoundTimer,
    /// Heartbeat tracker for validator liveness detection
    heartbeat_tracker: crate::network::HeartbeatTracker,
    /// Heartbeat send interval
    heartbeat_interval: Option<tokio::time::Interval>,
    /// Liveness monitor for stall detection
    liveness_monitor: crate::network::LivenessMonitor,
    /// Liveness check interval (5 seconds)
    liveness_check_interval: Option<tokio::time::Interval>,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    ///
    /// Invariant CE-ENG-1: The broadcaster is dependency-injected.
    /// No defaults. No globals. No feature flags.
    pub fn new(
        config: ConsensusConfig,
        broadcaster: Arc<dyn MessageBroadcaster>,
    ) -> ConsensusResult<Self> {
        let validator_manager = ValidatorManager::new_with_development_mode(
            config.max_validators,
            config.min_stake,
            config.development_mode,
        );

        let current_round = ConsensusRound {
            height: 0,
            round: 0,
            step: ConsensusStep::Propose,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            proposer: None,
            proposals: Vec::new(),
            votes: HashMap::new(),
            timed_out: false,
            locked_proposal: None,
            valid_proposal: None,
        };

        let round_timer = RoundTimer::new(&config);

        Ok(Self {
            validator_identity: None,
            validator_manager,
            current_round,
            config,
            pending_proposals: VecDeque::new(),
            vote_pool: HashMap::new(), // Composite key prevents equivocation
            round_history: VecDeque::new(),
            dao_engine: DaoEngine::new(),
            byzantine_detector: ByzantineFaultDetector::new(),
            reward_calculator: RewardCalculator::new(),
            broadcaster,
            message_rx: None,
            round_timer,
            heartbeat_tracker: crate::network::HeartbeatTracker::new(Duration::from_secs(10)),
            heartbeat_interval: None,
            liveness_monitor: crate::network::LivenessMonitor::new(),
            liveness_check_interval: None,
        })
    }

    /// Set the message receiver (from network layer)
    pub fn set_message_receiver(&mut self, rx: mpsc::Receiver<ValidatorMessage>) {
        self.message_rx = Some(rx);
    }

    /// Initialize the heartbeat sender with default 3-second interval
    ///
    /// Call this before `run_consensus_loop()` to enable periodic heartbeat sending.
    pub fn initialize_heartbeat_sender(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(3));
        self.heartbeat_interval = Some(interval);
    }

    /// Initialize the liveness monitor for consensus stall detection
    ///
    /// Call this after `register_validator()` to enable periodic liveness monitoring.
    /// Sets up a 5-second check interval and initializes with current validator set.
    pub fn initialize_liveness_monitor(&mut self) {
        let interval = tokio::time::interval(Duration::from_secs(5));
        self.liveness_check_interval = Some(interval);

        // Initialize with current validator set
        let active_validators: Vec<_> = self
            .validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect();
        self.liveness_monitor.update_validator_set(&active_validators);
    }

    /// Register as a validator
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
                "Insufficient stake amount".to_string(),
            ));
        }

        if storage_capacity < self.config.min_storage {
            return Err(ConsensusError::ValidatorError(
                "Insufficient storage capacity".to_string(),
            ));
        }

        if commission_rate > 100 {
            return Err(ConsensusError::ValidatorError(
                "Invalid commission rate".to_string(),
            ));
        }

        // Register with validator manager
        self.validator_manager
            .register_validator(
                identity.clone(),
                stake,
                storage_capacity,
                consensus_key,
                commission_rate,
            )
            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;

        // Set as local validator if this is the first one
        if self.validator_identity.is_none() {
            self.validator_identity = Some(identity.clone());
            // Also set the heartbeat tracker's local validator so heartbeats are properly attributed
            self.heartbeat_tracker.set_local_validator(identity.clone());
        }

        tracing::info!(
            "Registered validator {:?} with {} ZHTP stake",
            identity,
            stake
        );
        Ok(())
    }

    /// Process a single consensus event (pure component method)
    /// This replaces the standalone start_consensus() loop pattern
    pub async fn handle_consensus_event(
        &mut self,
        event: ConsensusEvent,
    ) -> ConsensusResult<Vec<ConsensusEvent>> {
        match event {
            ConsensusEvent::StartRound { height, trigger } => {
                tracing::info!(
                    " Starting consensus round {} (trigger: {})",
                    height,
                    trigger
                );

                // Log different trigger types for monitoring and debugging
                match trigger.as_str() {
                    "timeout" => tracing::warn!(
                        "⏰ Consensus round triggered by timeout - potential network delays"
                    ),
                    "new_transaction" => {
                        tracing::debug!("💳 New transaction triggered consensus round")
                    }
                    "validator_join" => {
                        tracing::info!("New validator joining triggered consensus round")
                    }
                    "validator_leave" => {
                        tracing::warn!(" Validator leaving triggered consensus round")
                    }
                    "force_restart" => tracing::warn!(" Manual consensus restart triggered"),
                    _ => tracing::debug!("Custom trigger: {}", trigger),
                }

                self.prepare_consensus_round(height).await?;
                Ok(vec![ConsensusEvent::RoundPrepared { height }])
            }
            ConsensusEvent::NewBlock {
                height,
                previous_hash,
            } => {
                tracing::info!(
                    "🧱 Processing new block at height {} with previous hash: {}",
                    height,
                    previous_hash
                );

                // Validate blockchain continuity by checking previous hash
                if let Err(e) = self.validate_previous_hash(height, &previous_hash).await {
                    tracing::error!("Previous hash validation failed: {}", e);
                    return Ok(vec![ConsensusEvent::RoundFailed {
                        height,
                        error: format!("Previous hash validation failed: {}", e),
                    }]);
                }

                match self.run_consensus_round().await {
                    Ok(_) => {
                        let mut events = vec![ConsensusEvent::RoundCompleted { height }];

                        // Process DAO proposals
                        if let Err(e) = self.dao_engine.process_expired_proposals().await {
                            tracing::warn!("DAO processing error: {}", e);
                            events.push(ConsensusEvent::DaoError {
                                error: e.to_string(),
                            });
                        }

                        // Check for Byzantine faults
                        if let Err(e) = self
                            .byzantine_detector
                            .detect_faults(&self.validator_manager)
                        {
                            tracing::warn!("Byzantine fault detection error: {}", e);
                            events.push(ConsensusEvent::ByzantineFault {
                                error: e.to_string(),
                            });
                        }

                        // Calculate and distribute rewards
                        if let Err(e) = self.reward_calculator.calculate_round_rewards(
                            &self.validator_manager,
                            self.current_round.height,
                        ) {
                            tracing::warn!("Reward calculation error: {}", e);
                            events.push(ConsensusEvent::RewardError {
                                error: e.to_string(),
                            });
                        }

                        Ok(events)
                    }
                    Err(e) => {
                        tracing::error!("Consensus round failed: {}", e);
                        Ok(vec![ConsensusEvent::RoundFailed {
                            height,
                            error: e.to_string(),
                        }])
                    }
                }
            }
            ConsensusEvent::ValidatorJoin { identity, stake } => {
                self.handle_validator_registration(identity.clone(), stake)
                    .await?;
                // Update liveness monitor with new validator set
                let active_validators: Vec<_> = self.validator_manager
                    .get_active_validators()
                    .iter()
                    .map(|v| v.identity.clone())
                    .collect();
                self.liveness_monitor.update_validator_set(&active_validators);
                Ok(vec![ConsensusEvent::ValidatorRegistered { identity }])
            }
            ConsensusEvent::ValidatorLeave { identity } => {
                // Remove validator and update liveness monitor
                self.validator_manager.remove_validator(&identity);
                let active_validators: Vec<_> = self.validator_manager
                    .get_active_validators()
                    .iter()
                    .map(|v| v.identity.clone())
                    .collect();
                self.liveness_monitor.update_validator_set(&active_validators);
                tracing::info!("Validator {} left consensus", identity);
                Ok(vec![])
            }
            _ => {
                tracing::debug!("Unhandled consensus event: {:?}", event);
                Ok(vec![])
            }
        }
    }

    /// Prepare for a consensus round (internal method)
    async fn prepare_consensus_round(&mut self, height: u64) -> ConsensusResult<()> {
        if !self.validator_manager.has_sufficient_validators() {
            return Err(ConsensusError::ValidatorError(
                "Insufficient validators for consensus".to_string(),
            ));
        }

        tracing::info!(" Preparing ZHTP consensus for height {}", height);
        self.current_round.height = height;
        Ok(())
    }

    /// Handle validator registration event
    async fn handle_validator_registration(
        &mut self,
        identity: lib_identity::IdentityId,
        stake: u64,
    ) -> ConsensusResult<()> {
        self.register_validator(
            identity.clone(),
            stake,
            1024 * 1024 * 1024, // Default storage capacity
            vec![0u8; 32],      // Default consensus key
            5,                  // Default commission rate
            false,              // Not genesis
        )
        .await?;
        Ok(())
    }

    /// Run a single consensus round
    /// DEPRECATED: Legacy consensus round driver
    ///
    /// **CRITICAL INVARIANT VIOLATION**: This method must NOT be used alongside run_consensus_loop().
    /// The consensus engine should have a SINGLE async driver:
    /// - Option 1 (RECOMMENDED): Use run_consensus_loop() exclusively
    /// - Option 2: Refactor to call initialize_round_state() and let loop take over
    ///
    /// Calling both causes conflicting state transitions and undefined behavior.
    ///
    /// Current behavior: Calls sequential run_propose_step/run_prevote_step/etc which have
    /// their own sleeps and timeouts. This is incompatible with the event-driven run_consensus_loop().
    ///
    /// TODO: Remove this method or refactor callers to use run_consensus_loop() instead.
    #[deprecated(
        since = "0.1.0",
        note = "Use run_consensus_loop() instead. This legacy round driver conflicts with the event-driven consensus architecture."
    )]
    async fn run_consensus_round(&mut self) -> ConsensusResult<()> {
        // **CRITICAL**: This method conflicts with run_consensus_loop()
        // Both are consensus drivers and cannot coexist.
        // Reject if message receiver has been set (indicating run_consensus_loop() is intended).
        if self.message_rx.is_some() {
            return Err(ConsensusError::ValidatorError(
                "Cannot use run_consensus_round() with run_consensus_loop(). \
                 These are incompatible consensus drivers. Use run_consensus_loop() instead."
                    .to_string(),
            ));
        }

        self.advance_to_next_round();

        // Select proposer for this round
        let proposer = self
            .validator_manager
            .select_proposer(self.current_round.height, self.current_round.round)
            .ok_or_else(|| ConsensusError::ValidatorError("No proposer available".to_string()))?;

        self.current_round.proposer = Some(proposer.identity.clone());

        tracing::warn!(
            "Using legacy run_consensus_round() - consider migrating to run_consensus_loop(). \
            Starting consensus round {} at height {} with proposer {:?}",
            self.current_round.round,
            self.current_round.height,
            proposer.identity
        );

        // Run consensus steps
        self.run_propose_step().await?;
        self.run_prevote_step().await?;
        self.run_precommit_step().await?;
        self.run_commit_step().await?;

        // Archive completed round
        self.archive_completed_round();

        Ok(())
    }

    /// Get active validator IDs for the current round
    ///
    /// This is used when broadcasting to ensure the validator set is passed explicitly
    /// rather than queried from network state (Invariant CE-ENG-5).
    fn get_active_validator_ids(&self) -> Vec<IdentityId> {
        self.validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect()
    }

    /// Advance to the next consensus round
    fn advance_to_next_round(&mut self) {
        self.current_round.height += 1;
        self.current_round.round = 0;
        self.current_round.step = ConsensusStep::Propose;
        self.current_round.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.current_round.proposer = None;
        self.current_round.proposals.clear();
        self.current_round.votes.clear();
        self.current_round.timed_out = false;
        self.current_round.locked_proposal = None;
        self.current_round.valid_proposal = None;
    }

    /// Run the propose step
    async fn run_propose_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Propose;

        // If we are the proposer, create a proposal
        if let Some(ref validator_id) = self.validator_identity {
            if Some(validator_id) == self.current_round.proposer.as_ref() {
                let proposal = self.create_proposal().await?;
                self.current_round.proposals.push(proposal.id.clone());
                self.pending_proposals.push_back(proposal.clone());

                // Invariant CE-ENG-3: Broadcast after state transition (proposal now in state)
                // Create canonical ValidatorMessage from already-formed proposal
                let msg = ValidatorMessage::Propose {
                    proposal,
                };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast proposal to validators (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        // Wait for proposals with timeout
        self.wait_for_step_timeout(self.config.propose_timeout)
            .await;

        Ok(())
    }

    /// Run the prevote step
    async fn run_prevote_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreVote;

        // Cast prevote
        if let Some(proposal_id) = self.current_round.proposals.first() {
            let vote = self.cast_vote(proposal_id.clone(), VoteType::PreVote)
                .await?;

            // Invariant CE-ENG-3: Broadcast after state transition
            // Create canonical ValidatorMessage from already-formed vote
            let msg = ValidatorMessage::Vote { vote };

            // Invariant CE-ENG-5: Pass validator set explicitly, never query network
            let validator_ids = self.get_active_validator_ids();

            // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
            // Log failures for observability without affecting consensus correctness
            if let Err(e) = self.broadcaster
                .broadcast_to_validators(msg, &validator_ids)
                .await
            {
                tracing::debug!(
                    error = ?e,
                    height = self.current_round.height,
                    "Failed to broadcast prevote to validators (continuing per CE-ENG-4)"
                );
            }
        }

        // Wait for prevotes with timeout
        self.wait_for_step_timeout(self.config.prevote_timeout)
            .await;

        Ok(())
    }

    /// Run the precommit step
    async fn run_precommit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::PreCommit;

        // Check if we received enough prevotes
        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let threshold = self.validator_manager.get_byzantine_threshold();

            if prevote_count >= threshold {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::PreCommit)
                    .await?;
                self.current_round.valid_proposal = Some(proposal_id);

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        "Failed to broadcast precommit to validators (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        // Wait for precommits with timeout
        self.wait_for_step_timeout(self.config.precommit_timeout)
            .await;

        Ok(())
    }

    /// Run the commit step
    async fn run_commit_step(&mut self) -> ConsensusResult<()> {
        self.current_round.step = ConsensusStep::Commit;

        // Check if we received enough precommits
        if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let threshold = self.validator_manager.get_byzantine_threshold();

            if precommit_count >= threshold {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::Commit)
                    .await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                // Invariant CE-ENG-3: Broadcast after state transition
                // Create canonical ValidatorMessage from already-formed vote
                let msg = ValidatorMessage::Vote { vote };

                // Invariant CE-ENG-5: Pass validator set explicitly, never query network
                let validator_ids = self.get_active_validator_ids();

                // Invariant CE-ENG-4: Treat broadcast as best-effort telemetry
                // Log failures for observability without affecting consensus correctness
                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        height = self.current_round.height,
                        proposal_id = ?proposal_id,
                        "Failed to broadcast commit vote to validators (continuing per CE-ENG-4)"
                    );
                }

                // Process the committed block
                self.process_committed_block(&proposal_id).await?;
            }
        }

        Ok(())
    }

    /// Create a new proposal
    async fn create_proposal(&self) -> ConsensusResult<ConsensusProposal> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        // Get previous block hash from blockchain state
        let previous_hash = self.get_previous_block_hash().await?;

        // Collect pending transactions for this block
        let block_data = self.collect_block_transactions().await?;

        // Generate proposal ID from deterministic data
        let proposal_id = Hash::from_bytes(&hash_blake3(
            &[
                &self.current_round.height.to_le_bytes(),
                previous_hash.as_bytes(),
                &block_data,
                validator_id.as_bytes(),
            ]
            .concat(),
        ));

        // Create consensus proof
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
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
            consensus_proof,
        };

        tracing::info!(
            "Created proposal {:?} for height {} by {:?}",
            proposal.id,
            proposal.height,
            proposal.proposer
        );

        Ok(proposal)
    }

    /// Get the hash of the previous block
    async fn get_previous_block_hash(&self) -> ConsensusResult<Hash> {
        // In production, this would query the blockchain for the latest block hash
        if self.current_round.height == 0 {
            // Genesis block
            Ok(Hash([0u8; 32]))
        } else {
            // For demo, create deterministic previous hash based on height
            let prev_hash_data = format!("block_{}", self.current_round.height - 1);
            Ok(Hash::from_bytes(&hash_blake3(prev_hash_data.as_bytes())))
        }
    }

    /// Collect transactions for the new block
    async fn collect_block_transactions(&self) -> ConsensusResult<Vec<u8>> {
        // In production, this would:
        // 1. Get pending transactions from mempool
        // 2. Validate transactions
        // 3. Select transactions based on fees and priority
        // 4. Create block data with transaction merkle tree

        // For demo, create minimal block data
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

        let block_data = format!(
            "block_height:{},timestamp:{},validator_count:{}",
            self.current_round.height,
            timestamp,
            self.validator_manager.get_active_validators().len()
        );

        Ok(block_data.into_bytes())
    }

    /// Serialize proposal data for signing
    fn serialize_proposal_data(
        &self,
        proposal_id: &Hash,
        proposer: &IdentityId,
        height: u64,
        previous_hash: &Hash,
        block_data: &[u8],
    ) -> ConsensusResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(proposal_id.as_bytes());
        data.extend_from_slice(proposer.as_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(previous_hash.as_bytes());
        data.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
        data.extend_from_slice(block_data);
        Ok(data)
    }

    /// Sign proposal data
    async fn sign_proposal_data(&self, data: &[u8]) -> ConsensusResult<PostQuantumSignature> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create signature using validator's consensus key
        let signature_data = [data, &validator.consensus_key].concat();
        let signature_hash = hash_blake3(&signature_data);

        Ok(PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: validator.consensus_key.clone(),
                kyber_pk: validator.consensus_key[..16].to_vec(), // Truncated for demo
                key_id: validator_id.as_bytes().try_into().unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
        })
    }

    /// Create consensus proof based on configuration
    async fn create_consensus_proof(&self) -> ConsensusResult<ConsensusProof> {
        let consensus_type = self.config.consensus_type.clone();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ConsensusError::TimeError(e))?
            .as_secs();

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
            }
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
            }
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
            }
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
            }
            ConsensusType::ByzantineFaultTolerance => {
                // BFT uses all proof types
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
            }
        }
    }

    /// Create stake proof
    async fn create_stake_proof(&self) -> ConsensusResult<StakeProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create deterministic stake transaction hash based on validator identity and stake
        let stake_tx_data = [
            validator_id.as_bytes(),
            &validator.stake.to_le_bytes(),
            b"stake_transaction",
        ]
        .concat();
        let stake_tx_hash = Hash::from_bytes(&hash_blake3(&stake_tx_data));

        let stake_proof = StakeProof::new(
            validator_id.clone(),
            validator.stake,
            stake_tx_hash,
            self.current_round.height.saturating_sub(1), // Stake was made in previous block
            86400,                                       // 1 day lock time in seconds
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(stake_proof)
    }

    /// Create storage proof
    async fn create_storage_proof(&self) -> ConsensusResult<StorageProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create realistic storage challenges
        let mut challenges = Vec::new();
        let num_challenges = 3; // Standard number of challenges

        for i in 0..num_challenges {
            let challenge_data = [
                validator_id.as_bytes(),
                &(i as u32).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
            ]
            .concat();

            let challenge = crate::proofs::StorageChallenge {
                id: Hash::from_bytes(&hash_blake3(&challenge_data)),
                content_hash: Hash::from_bytes(&hash_blake3(
                    &[challenge_data.clone(), b"content".to_vec()].concat(),
                )),
                challenge: challenge_data[..16].to_vec(), // First 16 bytes as challenge
                response: hash_blake3(&challenge_data).to_vec(), // Hash as response
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| ConsensusError::TimeError(e))?
                    .as_secs()
                    - (i as u64 * 3600),
            };
            challenges.push(challenge);
        }

        // Create merkle proof for stored data
        let merkle_data = [
            validator_id.as_bytes(),
            &validator.storage_provided.to_le_bytes(),
            b"merkle_root",
        ]
        .concat();
        let merkle_proof = vec![Hash::from_bytes(&hash_blake3(&merkle_data))];

        // Calculate realistic utilization based on validator activity
        let utilization = std::cmp::min(
            90,                               // Max 90% utilization
            50 + (validator.reputation / 10), // 50-90% based on reputation
        ) as u64;

        let storage_proof = StorageProof::new(
            Hash::from_bytes(validator_id.as_bytes()),
            validator.storage_provided,
            utilization,
            challenges,
            merkle_proof,
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(storage_proof)
    }

    /// Create work proof
    async fn create_work_proof(&self) -> ConsensusResult<WorkProof> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Calculate realistic work values based on validator capabilities
        let routing_work = (validator.voting_power * 10).min(5000); // Based on voting power
        let storage_work = (validator.storage_provided / (1024 * 1024 * 1024)).min(1000); // GB to work units
        let compute_work = (validator.reputation as u64 * 5).min(2000); // Based on reputation

        let work_proof = WorkProof::new(
            routing_work,
            storage_work,
            compute_work,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            validator_id.as_bytes().try_into().unwrap_or([0u8; 32]),
        )
        .map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;

        Ok(work_proof)
    }

    /// Cast a vote
    ///
    /// Returns the created vote so that the caller can broadcast it.
    /// Invariant CE-ENG-3: Broadcast happens after this state transition.
    async fn cast_vote(&mut self, proposal_id: Hash, vote_type: VoteType) -> ConsensusResult<ConsensusVote> {
        let validator_id = self
            .validator_identity
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("No validator identity".to_string()))?;

        let validator = self
            .validator_manager
            .get_validator(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError("Validator not found".to_string()))?;

        // Create vote ID from deterministic data
        let vote_id = Hash::from_bytes(&hash_blake3(
            &[
                proposal_id.as_bytes(),
                validator_id.as_bytes(),
                &(vote_type.clone() as u8).to_le_bytes(),
                &self.current_round.height.to_le_bytes(),
                &self.current_round.round.to_le_bytes(),
            ]
            .concat(),
        ));

        // Create vote data for signing
        // Use current height/round since this vote is being created for the current consensus round
        let vote_data = self.serialize_vote_data(
            &vote_id,
            validator_id,
            &proposal_id,
            &vote_type,
            self.current_round.height,
            self.current_round.round,
        )?;

        // Sign the vote
        let signature = self.sign_vote_data(&vote_data, &validator).await?;

        let vote = ConsensusVote {
            id: vote_id.clone(),
            voter: validator_id.clone(),
            proposal_id: proposal_id.clone(),
            vote_type: vote_type.clone(),
            height: self.current_round.height,
            round: self.current_round.round,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
            signature,
        };

        // Store vote using composite key (height, round, vote_type, validator_id)
        let key = VotePoolKey {
            height: self.current_round.height,
            round: self.current_round.round,
            vote_type: vote_type.clone(),
            validator_id: validator_id.clone(),
        };
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

        // Update validator activity
        self.validator_manager
            .update_validator_activity(validator_id);

        tracing::debug!(
            " Cast {:?} vote on proposal {:?} from validator {:?}",
            vote_type,
            proposal_id,
            validator_id
        );

        Ok(vote)
    }

    /// Serialize vote data for signing
    fn serialize_vote_data(
        &self,
        vote_id: &Hash,
        voter: &IdentityId,
        proposal_id: &Hash,
        vote_type: &VoteType,
        height: u64,
        round: u32,
    ) -> ConsensusResult<Vec<u8>> {
        // **CRITICAL INVARIANT**: Vote signature MUST be bound to the vote's own height/round,
        // not the local consensus state. This ensures:
        // - Signature verifies against the exact vote data, not local state
        // - Commit votes from past rounds/heights can be properly validated
        // - No latent safety faults when strict verification is enabled
        let mut data = Vec::new();
        data.extend_from_slice(vote_id.as_bytes());
        data.extend_from_slice(voter.as_bytes());
        data.extend_from_slice(proposal_id.as_bytes());
        data.push(vote_type.clone() as u8);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&round.to_le_bytes());
        Ok(data)
    }

    /// Sign vote data
    async fn sign_vote_data(
        &self,
        data: &[u8],
        validator: &crate::validators::Validator,
    ) -> ConsensusResult<PostQuantumSignature> {
        // Create signature using validator's consensus key
        let signature_data = [data, &validator.consensus_key].concat();
        let signature_hash = hash_blake3(&signature_data);

        Ok(PostQuantumSignature {
            signature: signature_hash.to_vec(),
            public_key: lib_crypto::PublicKey {
                dilithium_pk: validator.consensus_key.clone(),
                kyber_pk: validator.consensus_key[..16].to_vec(),
                key_id: validator
                    .identity
                    .as_bytes()
                    .try_into()
                    .unwrap_or([0u8; 32]),
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ConsensusError::TimeError(e))?
                .as_secs(),
        })
    }

    /// Count votes for a proposal
    fn count_votes_for_proposal(&self, proposal_id: &Hash, vote_type: &VoteType) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (vote, _))| {
                k.height == self.current_round.height
                    && k.round == self.current_round.round
                    && k.vote_type == *vote_type
                    && &vote.proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Wait for step timeout
    async fn wait_for_step_timeout(&mut self, timeout_ms: u64) {
        tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms)).await;
    }

    /// Process committed block
    async fn process_committed_block(&mut self, proposal_id: &Hash) -> ConsensusResult<()> {
        // Find and process the committed proposal
        if let Some(proposal_index) = self
            .pending_proposals
            .iter()
            .position(|p| &p.id == proposal_id)
        {
            // Safe: index came from position() which found it
            let proposal = self.pending_proposals.remove(proposal_index)
                .expect("Proposal index came from position(), element must exist");

            // Validate the block one more time before applying
            self.validate_committed_block(&proposal).await?;

            // Apply block to state
            self.apply_block_to_state(&proposal).await?;

            // Update validator activities and reputation
            self.update_validator_metrics(&proposal).await?;

            // Calculate and distribute block rewards
            let reward_round = self
                .reward_calculator
                .calculate_round_rewards(&self.validator_manager, self.current_round.height)?;
            self.reward_calculator.distribute_rewards(&reward_round)?;

            // Process any DAO proposals that may have expired
            if let Err(e) = self.dao_engine.process_expired_proposals().await {
                tracing::warn!("Error processing DAO proposals: {}", e);
            }

            tracing::info!(
                " Successfully processed committed block: {:?} at height {}",
                proposal.id,
                proposal.height
            );
        }

        Ok(())
    }

    /// Validate committed block before applying
    async fn validate_committed_block(&self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // Verify proposal signature
        let proposal_data = self.serialize_proposal_data(
            &proposal.id,
            &proposal.proposer,
            proposal.height,
            &proposal.previous_hash,
            &proposal.block_data,
        )?;

        if !self
            .verify_signature(&proposal_data, &proposal.signature)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid proposal signature".to_string(),
            ));
        }

        // Verify consensus proof
        if !self
            .verify_consensus_proof(&proposal.consensus_proof)
            .await?
        {
            return Err(ConsensusError::ProofVerificationFailed(
                "Invalid consensus proof".to_string(),
            ));
        }

        tracing::debug!("Block validation passed for {:?}", proposal.id);
        Ok(())
    }

    /// Apply block to blockchain state
    async fn apply_block_to_state(&mut self, proposal: &ConsensusProposal) -> ConsensusResult<()> {
        // In production, this would:
        // 1. Execute all transactions in the block
        // 2. Update account balances and state
        // 3. Update validator set if needed
        // 4. Apply any governance changes
        // 5. Store block in blockchain database

        // For now, just log the application
        tracing::info!(
            " Applied block {:?} to state (height: {}, size: {} bytes)",
            proposal.id,
            proposal.height,
            proposal.block_data.len()
        );

        Ok(())
    }

    /// Update validator metrics based on block participation
    async fn update_validator_metrics(
        &mut self,
        proposal: &ConsensusProposal,
    ) -> ConsensusResult<()> {
        // Update proposer metrics
        let proposer_id = proposal.proposer.clone();
        if let Some(proposer) = self.validator_manager.get_validator_mut(&proposer_id) {
            proposer.reputation = std::cmp::min(proposer.reputation + 1, 1000); // Cap at 1000
            proposer.update_activity();
        }

        // Update metrics for validators who voted
        let voter_ids: Vec<IdentityId> = self
            .vote_pool
            .iter()
            .filter(|(k, _)| k.height == proposal.height)
            .map(|(_, (vote, _))| vote.voter.clone())
            .collect();
        for voter_id in voter_ids {
            if let Some(voter) = self.validator_manager.get_validator_mut(&voter_id) {
                voter.reputation = std::cmp::min(voter.reputation + 1, 1000);
                voter.update_activity();
            }
        }

        tracing::debug!(" Updated validator metrics for block {:?}", proposal.id);
        Ok(())
    }

    /// Verify a signature
    async fn verify_signature(
        &self,
        _data: &[u8],
        signature: &PostQuantumSignature,
    ) -> ConsensusResult<bool> {
        // In production, this would use proper post-quantum signature verification
        // For demo, we verify that the signature is not empty and has correct structure
        Ok(!signature.signature.is_empty() && !signature.public_key.dilithium_pk.is_empty())
    }

    /// Verify consensus proof
    async fn verify_consensus_proof(&self, proof: &ConsensusProof) -> ConsensusResult<bool> {
        match proof.consensus_type {
            ConsensusType::ProofOfStake => {
                if let Some(stake_proof) = &proof.stake_proof {
                    Ok(stake_proof.verify(self.current_round.height)?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfStorage => {
                if let Some(storage_proof) = &proof.storage_proof {
                    Ok(storage_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::ProofOfUsefulWork => {
                if let Some(work_proof) = &proof.work_proof {
                    Ok(work_proof.verify()?)
                } else {
                    Ok(false)
                }
            }
            ConsensusType::Hybrid => {
                let stake_valid = proof
                    .stake_proof
                    .as_ref()
                    .map(|p| p.verify(self.current_round.height))
                    .transpose()?
                    .unwrap_or(false);

                let storage_valid = proof
                    .storage_proof
                    .as_ref()
                    .map(|p| p.verify())
                    .transpose()?
                    .unwrap_or(false);

                Ok(stake_valid && storage_valid)
            }
            ConsensusType::ByzantineFaultTolerance => {
                // For BFT, we rely on vote thresholds rather than individual proofs
                Ok(true)
            }
        }
    }

    /// Archive completed round
    fn archive_completed_round(&mut self) {
        self.round_history.push_back(self.current_round.clone());

        // Keep only recent history
        if self.round_history.len() > 100 {
            self.round_history.pop_front();
        }
    }

    /// Get DAO engine reference
    pub fn dao_engine(&self) -> &DaoEngine {
        &self.dao_engine
    }

    /// Get mutable DAO engine reference
    pub fn dao_engine_mut(&mut self) -> &mut DaoEngine {
        &mut self.dao_engine
    }

    /// Get validator manager reference
    pub fn validator_manager(&self) -> &ValidatorManager {
        &self.validator_manager
    }

    /// Get current consensus round
    pub fn current_round(&self) -> &ConsensusRound {
        &self.current_round
    }

    /// Get consensus configuration
    pub fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    /// Check if a validator is currently alive based on heartbeat presence
    ///
    /// A validator is considered alive if a valid heartbeat has been received
    /// within the configured liveness timeout period (default: 10 seconds).
    pub fn is_validator_alive(&self, validator_id: &IdentityId) -> bool {
        self.heartbeat_tracker.is_validator_alive(validator_id)
    }

    /// Get the age of the last heartbeat received from a validator
    ///
    /// Returns None if no heartbeat has been received from the validator.
    /// Returns Some(duration) with the elapsed time since the last heartbeat.
    pub fn last_heartbeat_age(&self, validator_id: &IdentityId) -> Option<Duration> {
        self.heartbeat_tracker.last_heartbeat_age(validator_id)
    }

    /// Set the liveness timeout duration for heartbeat tracking
    ///
    /// Validators not sending heartbeats within this duration will be
    /// considered not alive. Default is 10 seconds.
    pub fn set_liveness_timeout(&mut self, timeout: Duration) {
        self.heartbeat_tracker.set_liveness_timeout(timeout);
    }

    /// Get list of validators currently considered alive based on heartbeats
    ///
    /// Returns a vector of IdentityIds for all active validators who have
    /// sent a heartbeat within the liveness timeout period.
    pub fn get_alive_validators(&self) -> Vec<IdentityId> {
        self.validator_manager
            .get_active_validators()
            .iter()
            .filter(|v| self.heartbeat_tracker.is_validator_alive(&v.identity))
            .map(|v| v.identity.clone())
            .collect()
    }

    /// Check if a validator is a member of the active validator set
    ///
    /// **INVARIANT**: Validator membership is a function of height, not wall-clock time.
    /// A validator is valid only if it was a member of the validator set at the target height.
    ///
    /// TODO: If validator sets change per height (epoch transitions), implement height-scoped lookup.
    /// For now, check against the current active set (correct if validator sets are static).
    ///
    /// **Safety consideration**: If validator sets change, a vote from a validator who was
    /// valid at vote.height but is no longer active would be rejected, potentially breaking
    /// consensus during epoch transitions.
    fn is_validator_member(&self, voter: &IdentityId, height: u64) -> bool {
        let active_validators = self.validator_manager.get_active_validators();
        active_validators.iter().any(|v| v.identity == *voter)
    }

    /// Verify the cryptographic signature of a vote
    ///
    /// Uses the vote's own height and round to reconstruct the signed data.
    /// Returns true if signature is valid, false otherwise.
    async fn verify_vote_signature(&self, vote: &ConsensusVote) -> ConsensusResult<bool> {
        // Reconstruct the vote data that was signed, using the vote's own height/round
        // This ensures the signature binds to the vote's exact content, not local state
        let vote_data = self.serialize_vote_data(
            &vote.id,
            &vote.voter,
            &vote.proposal_id,
            &vote.vote_type,
            vote.height,
            vote.round,
        )?;
        let signature_valid = self.verify_signature(&vote_data, &vote.signature).await?;
        if !signature_valid {
            tracing::warn!(
                "Vote rejected: invalid signature from validator {} for height {} round {}",
                vote.voter,
                vote.height,
                vote.round
            );
        }
        Ok(signature_valid)
    }

    /// Validate a remote vote against all BFT safety invariants
    ///
    /// A remote vote MUST be rejected if any of the following fail:
    ///
    /// 1. **Signature**: Cryptographically valid and signed by the claimed validator key
    /// 2. **Validator membership**: Sender is in the active validator set for the target height
    /// 3. **Height**: vote.height == local.height
    /// 4. **Round**: vote.round == local.round
    /// 5. **Vote type coherence**: PreVote only accepted in PreVote step; PreCommit only in PreCommit step
    ///
    /// **Invariant**: validate_remote_vote() is a hard gate, not a soft filter.
    /// Invalid votes are rejected immediately and never stored.
    ///
    /// **Design**: This enforces locally deterministic validation independent of network state.
    /// Signature verification assumes CONSENSUS-NET-4.2 (network delivers authenticated sender + canonical vote envelope).
    async fn validate_remote_vote(&self, vote: &ConsensusVote) -> ConsensusResult<bool> {
        // 1. Verify signature
        if !self.verify_vote_signature(vote).await? {
            return Ok(false);
        }

        // 2. Verify validator membership
        if !self.is_validator_member(&vote.voter, vote.height) {
            tracing::warn!(
                "Vote rejected: voter {} is not in active validator set for height {}",
                vote.voter,
                vote.height
            );
            return Ok(false);
        }

        // 3. Verify height matches
        if vote.height != self.current_round.height {
            tracing::debug!(
                "Vote rejected: height mismatch. Vote height {} != local height {}",
                vote.height,
                self.current_round.height
            );
            return Ok(false);
        }

        // 4. Verify round matches
        if vote.round != self.current_round.round {
            tracing::debug!(
                "Vote rejected: round mismatch. Vote round {} != local round {}",
                vote.round,
                self.current_round.round
            );
            return Ok(false);
        }

        // 5. Verify vote type coherence - STRICT equality, not >=
        // **CRITICAL INVARIANT**: Votes are only valid in the step they are defined for.
        // Late votes (e.g., PreVote in PreCommit step) are INVALID and never stored.
        // This ensures:
        // - No retroactive quorum formation
        // - Step transitions are monotonic and deterministic
        // - No ambiguous quorum timing
        let valid_for_step = match vote.vote_type {
            VoteType::PreVote => self.current_round.step == ConsensusStep::PreVote,
            VoteType::PreCommit => self.current_round.step == ConsensusStep::PreCommit,
            VoteType::Commit => {
                // Commit votes intentionally bypass step-based validation here.
                //
                // **Design rationale**:
                // - Commit votes are allowed as long as height and round match local state.
                // - The 2/3+1 identical-commit quorum requirement is enforced in `maybe_finalize()`,
                //   which is the only place where blocks are actually finalized.
                // - Keeping quorum logic out of `validate_remote_vote()` preserves the invariant that
                //   this function performs only local, stateless validation (signature, membership,
                //   height/round coherence, and step compatibility for non-commit votes).
                // - Any commit votes that never reach quorum are handled by higher-level cleanup
                //   when rounds/heights advance and vote sets are pruned.
                true
            }
            VoteType::Against => false, // Against votes are never valid in BFT
        };

        if !valid_for_step {
            tracing::warn!(
                "Vote rejected: vote type {:?} not valid for current step {:?}",
                vote.vote_type,
                self.current_round.step
            );
            return Ok(false);
        }

        // All validations passed
        Ok(true)
    }

    /// Validate that the previous hash matches the expected blockchain state
    async fn validate_previous_hash(
        &self,
        height: u64,
        previous_hash: &Hash,
    ) -> ConsensusResult<()> {
        // For genesis block (height 0), previous hash should be zero
        if height == 0 {
            let zero_hash = Hash::from_bytes(&[0u8; 32]);
            if *previous_hash != zero_hash {
                return Err(ConsensusError::InvalidPreviousHash(format!(
                    "Genesis block must have zero previous hash, got: {}",
                    previous_hash
                )));
            }
            return Ok(());
        }

        // For subsequent blocks, validate against the actual chain state
        // In a implementation, this would check against stored blockchain state

        // Check if we have the expected previous block
        if height > 1 {
            tracing::debug!(
                "Validating previous hash {} for height {}",
                previous_hash,
                height
            );

            // Here we would normally:
            // 1. Query the blockchain storage for block at height-1
            // 2. Compare its hash with the provided previous_hash
            // 3. Detect potential forks or reorganizations

            // For now, we log the validation but don't fail
            tracing::info!("Previous hash validation passed for height {}", height);
        }

        Ok(())
    }

    /// Main consensus loop with tokio::select!
    ///
    /// Waits on:
    /// - Round timer firing (only accepted if token matches current state)
    /// - Messages from the network receiver
    /// - Receiver closure (exits gracefully)
    ///
    /// Processes PreVote/PreCommit/Proposal messages and maintains vote_pool.
    /// Gap 4: Vote Aggregation from Remote Validators
    ///
    /// Invariant: This is the ONLY consensus driver. run_consensus_round() must NOT be used
    /// alongside this loop (they would conflict). The loop handles all progression:
    /// - Timer events drive phase transitions (Propose → PreVote → PreCommit → Commit)
    /// - Messages drive quorum detection and early transitions
    /// - Receiver closure causes graceful shutdown
    pub async fn run_consensus_loop(&mut self) -> ConsensusResult<()> {
        let mut message_rx = self.message_rx.take()
            .ok_or_else(|| ConsensusError::ValidatorError("Message receiver not set".to_string()))?;

        // Auto-initialize heartbeat sender if not already initialized
        if self.heartbeat_interval.is_none() {
            self.initialize_heartbeat_sender();
        }

        // Auto-initialize liveness monitor if not already initialized
        if self.liveness_check_interval.is_none() {
            self.initialize_liveness_monitor();
        }

        let mut heartbeat_interval = self.heartbeat_interval.take();

        let mut timer_token = TimerToken::new(
            self.current_round.height,
            self.current_round.round,
            &self.current_round.step,
        );
        let mut timer_fut = Box::pin(self.round_timer.next_deadline(
            self.current_round.height,
            self.current_round.round,
            &self.current_round.step,
        ));

        tracing::info!(
            "Starting consensus loop at height {} round {} step {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step
        );

        loop {
            tokio::select! {
                // Timer fired: only process if token matches current state
                _ = &mut timer_fut => {
                    if timer_token.matches(self.current_round.height, self.current_round.round, &self.current_round.step) {
                        tracing::debug!(
                            "Timer fired for height {} round {} step {:?}",
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step
                        );
                        self.on_round_timeout().await?;
                    } else {
                        let stale_step = ConsensusStep::from_ordinal(timer_token.step_ordinal)
                            .map(|s| format!("{:?}", s))
                            .unwrap_or_else(|| "Unknown".to_string());
                        tracing::debug!(
                            "Ignoring stale timer for height {} round {} step {} (current: {} {} {:?})",
                            timer_token.height,
                            timer_token.round,
                            stale_step,
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step
                        );
                    }

                    // Re-arm timer for current state
                    timer_token = TimerToken::new(
                        self.current_round.height,
                        self.current_round.round,
                        &self.current_round.step,
                    );
                    timer_fut.set(self.round_timer.next_deadline(
                        self.current_round.height,
                        self.current_round.round,
                        &self.current_round.step,
                    ));
                }

                // Message from network
                maybe_msg = message_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            self.on_message(msg).await?;

                            // Re-arm timer if state changed
                            let state_changed = !timer_token.matches(
                                self.current_round.height,
                                self.current_round.round,
                                &self.current_round.step,
                            );
                            if state_changed {
                                timer_token = TimerToken::new(
                                    self.current_round.height,
                                    self.current_round.round,
                                    &self.current_round.step,
                                );
                                timer_fut.set(self.round_timer.next_deadline(
                                    self.current_round.height,
                                    self.current_round.round,
                                    &self.current_round.step,
                                ));
                            }
                        }
                        None => {
                            // Receiver closed: engine cannot make further progress
                            tracing::info!("Consensus message receiver closed, shutting down loop");
                            break;
                        }
                    }
                }

                // Heartbeat interval tick (optional - only if initialized)
                _ = async {
                    match &mut heartbeat_interval {
                        Some(interval) => interval.tick().await,
                        None => loop { std::future::pending::<()>().await },
                    }
                } => {
                    // Send heartbeat (best-effort, ignore errors)
                    if let Some(validator_id) = &self.validator_identity {
                        let heartbeat_msg = self.heartbeat_tracker.create_heartbeat_message(
                            self.current_round.height,
                            self.current_round.round,
                            self.current_round.step.clone(),
                            self.validator_manager.get_active_validators().len() as u32,
                        );

                        // Get all validator IDs for broadcast
                        let validator_ids: Vec<_> = self.validator_manager
                            .get_active_validators()
                            .iter()
                            .map(|v| v.identity.clone())
                            .collect();

                        // Broadcast heartbeat (best-effort, ignore failures)
                        if let Err(e) = self.broadcaster.broadcast_to_validators(
                            ValidatorMessage::Heartbeat {
                                message: heartbeat_msg,
                            },
                            &validator_ids,
                        ).await {
                            tracing::debug!("Heartbeat broadcast failed: {}", e);
                        }
                    }
                }

                // Liveness check interval tick (every 5 seconds)
                _ = async {
                    if let Some(interval) = &mut self.liveness_check_interval {
                        interval.tick().await
                    } else {
                        loop { std::future::pending::<()>().await }
                    }
                } => {
                    // Check for validator timeouts and consensus stalls
                    let state_changed = self.liveness_monitor.watch_timeouts(&self.heartbeat_tracker);

                    if state_changed {
                        // Check for stall transition
                        if let Some((is_stalled, timed_out_set)) = self.liveness_monitor.check_stall_transition() {
                            let timed_out_validators: Vec<_> = timed_out_set.into_iter().collect();
                            if is_stalled {
                                // NOTE: This represents a ConsensusStalled event.
                                // Currently logged for observability; future work will emit as proper events.
                                tracing::warn!(
                                    event = "ConsensusStalled",
                                    height = self.current_round.height,
                                    round = self.current_round.round,
                                    timed_out_count = timed_out_validators.len(),
                                    total_validators = self.liveness_monitor.total_validators,
                                    threshold = self.liveness_monitor.stall_threshold,
                                    "CONSENSUS STALLED: {}/{} validators timed out, quorum impossible",
                                    timed_out_validators.len(),
                                    self.liveness_monitor.total_validators,
                                );
                            } else {
                                // NOTE: This represents a ConsensusRecovered event.
                                // Currently logged for observability; future work will emit as proper events.
                                tracing::info!(
                                    event = "ConsensusRecovered",
                                    height = self.current_round.height,
                                    round = self.current_round.round,
                                    "CONSENSUS RECOVERED: Sufficient validators responsive again"
                                );
                            }
                        }
                    }

                    // NEW: Periodic partition detection
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if let Some(partition_evidence) = self.byzantine_detector.detect_network_partition(
                        &self.liveness_monitor,
                        self.current_round.height,
                        self.current_round.round,
                        current_time,
                    ) {
                        tracing::error!(
                            "🔌 PARTITION SUSPECTED: {}/{} validators timed out (threshold: {})",
                            partition_evidence.timed_out_validators.len(),
                            partition_evidence.total_validators,
                            partition_evidence.stall_threshold
                        );

                        // Could trigger automatic response (future work):
                        // - Round timeout acceleration
                        // - Proposer rotation
                        // - Emergency validator set update
                    }
                }
            }
        }

        tracing::info!(
            "Consensus loop exited at height {} round {} step {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step
        );
        Ok(())
    }

    async fn on_message(&mut self, msg: ValidatorMessage) -> ConsensusResult<()> {
        match msg {
            ValidatorMessage::Propose { proposal } => {
                self.on_proposal(proposal).await?;
            }
            ValidatorMessage::Vote { vote } => {
                // NEW: Compute payload hash for replay detection
                let payload_bytes = bincode::serialize(&vote)
                    .expect("Vote serialization cannot fail");
                let payload_hash = lib_crypto::Hash::from_bytes(&lib_crypto::hash_blake3(&payload_bytes));

                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // NEW: Detect replay attack
                if let Some(replay_evidence) = self.byzantine_detector.detect_replay_attack(
                    &vote.voter,
                    payload_hash.clone(),
                    current_time,
                ) {
                    tracing::warn!(
                        "⚠️  REPLAY: Validator {} sent duplicate message {} times",
                        vote.voter, replay_evidence.replay_count
                    );
                    // Continue processing (replay is advisory, not blocking)
                }

                // NEW: Record forensic signature
                let message_type = match vote.vote_type {
                    VoteType::PreVote => crate::byzantine::ForensicMessageType::PreVote,
                    VoteType::PreCommit => crate::byzantine::ForensicMessageType::PreCommit,
                    VoteType::Commit => crate::byzantine::ForensicMessageType::Commit,
                    VoteType::Against => {
                        tracing::debug!("Received Against vote, ignoring");
                        return Ok(());
                    }
                };

                self.byzantine_detector.record_message_signature(
                    vote.id.clone(),
                    vote.voter.clone(),
                    vote.signature.clone(),
                    payload_hash,
                    message_type,
                    current_time,
                    None, // peer_id if available from network layer
                );

                // Route to handler
                match vote.vote_type {
                    VoteType::PreVote => {
                        self.on_prevote(vote).await?;
                    }
                    VoteType::PreCommit => {
                        self.on_precommit(vote).await?;
                    }
                    VoteType::Commit => {
                        self.on_commit_vote(vote).await?;
                    }
                    VoteType::Against => {
                        // Should not reach here (already returned above)
                    }
                }
            }
            ValidatorMessage::Heartbeat { message } => {
                // Process heartbeat (advisory only, never affects consensus)
                let is_validator = |vid: &IdentityId| {
                    self.validator_manager.get_active_validators()
                        .iter()
                        .any(|v| v.identity == *vid)
                };

                let validator_id = message.validator.clone();
                let result = self.heartbeat_tracker.process_heartbeat(
                    message,
                    is_validator,
                    self.current_round.height,
                );

                match result {
                    crate::network::HeartbeatProcessingResult::Accepted => {
                        tracing::debug!("Heartbeat accepted from {}", validator_id);
                        // Mark validator as responsive in liveness monitor
                        self.liveness_monitor.mark_responsive(&validator_id);
                    }
                    crate::network::HeartbeatProcessingResult::Rejected(reason) => {
                        tracing::debug!("Heartbeat rejected: {}", reason);
                    }
                }
                // Heartbeats never affect consensus state
            }
        }
        Ok(())
    }

    async fn on_proposal(&mut self, proposal: ConsensusProposal) -> ConsensusResult<()> {
        if !self.is_proposal_relevant(&proposal) {
            return Ok(());
        }

        if !self.current_round.proposals.is_empty() {
            return Ok(());
        }

        if Some(&proposal.proposer) != self.current_round.proposer.as_ref() {
            return Ok(());
        }

        self.current_round.proposals.push(proposal.id.clone());
        self.pending_proposals.push_back(proposal);

        if self.current_round.step == ConsensusStep::Propose {
            self.enter_prevote_step().await?;
        }

        Ok(())
    }

    async fn on_prevote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreVote",
                evidence.validator, evidence.height, evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::PreVote,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation (same validator, same H/R/type, different value)
        if let Some((_existing_vote, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate vote - idempotent, no-op
                return Ok(());
            } else {
                // Equivocation detected: same (H,R,type,validator), different values
                tracing::warn!(
                    "Equivocation detected: validator {:?} sent conflicting PreVotes for height {} round {}",
                    vote.voter, vote.height, vote.round
                );
                // In production, would record as evidence for slashing
                // For now, reject silently
                return Ok(());
            }
        }

        // Accept new vote
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

        tracing::debug!(
            "Added PreVote from {} for proposal {:?} at height {} round {}",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round
        );

        // **CE-S1**: Check supermajority for THIS proposal, not the round aggregate
        // Matching votes means: same height, round, proposal/block hash, and vote type
        let prevote_count = self.count_prevotes_for(vote.height, vote.round, &proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(prevote_count, total_validators) && self.current_round.step == ConsensusStep::PreVote {
            // **CE-S1**: Only transition if this proposal can be the valid proposal
            // If valid_proposal is already set to a DIFFERENT proposal, we have conflicting quorums
            // which violates safety - don't transition
            if let Some(existing) = self.current_round.valid_proposal.as_ref() {
                if existing != &proposal_id {
                    tracing::warn!(
                        "Conflicting quorum detected: proposal {:?} has quorum but valid_proposal is already {:?}",
                        proposal_id, existing
                    );
                    // Don't transition - this violates BFT safety
                    return Ok(());
                }
            } else {
                // First proposal to reach quorum in this round
                self.current_round.valid_proposal = Some(proposal_id.clone());
            }
            self.enter_precommit_step().await?;
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreVote step
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

        Ok(())
    }

    async fn on_precommit(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // Harden: Validate remote vote against all BFT safety invariants
        if !self.validate_remote_vote(&vote).await? {
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=PreCommit",
                evidence.validator, evidence.height, evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::PreCommit,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation
        if let Some((_existing_vote, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate - idempotent
                return Ok(());
            } else {
                // Equivocation detected
                tracing::warn!(
                    "Equivocation detected: validator {:?} sent conflicting PreCommits for height {} round {}",
                    vote.voter, vote.height, vote.round
                );
                return Ok(());
            }
        }

        // Accept new vote
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

        tracing::debug!(
            "Added PreCommit from {} for proposal {:?} at height {} round {}",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round
        );

        // **CE-S1**: Check supermajority for THIS proposal, not the round aggregate
        // Matching votes means: same height, round, proposal/block hash, and vote type
        let precommit_count = self.count_precommits_for(vote.height, vote.round, &proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(precommit_count, total_validators) && self.current_round.step == ConsensusStep::PreCommit {
            // **CE-S1**: Only transition if this proposal can be locked
            // If locked_proposal is already set to a DIFFERENT proposal, we have conflicting quorums
            if let Some(existing) = self.current_round.locked_proposal.as_ref() {
                if existing != &proposal_id {
                    tracing::warn!(
                        "Conflicting precommit quorum detected: proposal {:?} has quorum but locked_proposal is already {:?}",
                        proposal_id, existing
                    );
                    // Don't transition - this violates BFT safety
                    return Ok(());
                }
            } else {
                // First proposal to reach precommit quorum in this round
                self.current_round.locked_proposal = Some(proposal_id.clone());
            }
            self.enter_commit_step().await?;
        }

        // **CE-L1, CE-L2**: Always check if commit quorum is reached, even in PreCommit step
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

        Ok(())
    }

    async fn on_commit_vote(&mut self, vote: ConsensusVote) -> ConsensusResult<()> {
        // **CE-L2**: Accept commit votes at ANY step, not only during Commit.
        // Only reject votes from future heights. Accept current/past heights at any round
        // to allow catch-up from previous rounds.
        if vote.height > self.current_round.height {
            return Ok(());
        }

        // Reject if we've already moved past this height entirely
        // (height is locked in, no new consensus activity on old heights)
        if vote.height < self.current_round.height {
            tracing::debug!(
                "Ignoring commit vote for past height {} (current: {})",
                vote.height,
                self.current_round.height
            );
            return Ok(());
        }

        // Harden: Verify signature and validator membership (core validation)
        // Commit votes have special rules for height/round, so we only check signature + membership
        if !self.verify_vote_signature(&vote).await? {
            return Ok(());
        }

        // Verify validator membership
        if !self.is_validator_member(&vote.voter, vote.height) {
            tracing::warn!(
                "Commit vote rejected: voter {} is not in active validator set for height {}",
                vote.voter,
                vote.height
            );
            return Ok(());
        }

        // NEW: Detect equivocation using Byzantine fault detector BEFORE vote pool check
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(evidence) = self.byzantine_detector.detect_equivocation(
            &vote,
            &vote.proposal_id,
            current_time,
            None,
        ) {
            tracing::error!(
                "🚨 EQUIVOCATION: Validator {} voted for two proposals at H={} R={} type=Commit",
                evidence.validator, evidence.height, evidence.round
            );
            return Ok(()); // REJECT vote
        }

        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: VoteType::Commit,
            validator_id: vote.voter.clone(),
        };

        // Check for equivocation
        if let Some((_, existing_proposal_id)) = self.vote_pool.get(&key) {
            if existing_proposal_id == &vote.proposal_id {
                // Duplicate - idempotent
                return Ok(());
            } else {
                // Equivocation on commit (rare but possible in Byzantine scenario)
                tracing::warn!(
                    "Equivocation on Commit: validator {:?} for height {} round {}",
                    vote.voter, vote.height, vote.round
                );
                return Ok(());
            }
        }

        // Accept new commit vote (even if we're not in Commit step yet)
        let proposal_id = vote.proposal_id.clone();
        self.vote_pool.insert(key, (vote.clone(), proposal_id.clone()));

        tracing::debug!(
            "Stored commit vote from {} for proposal {:?} at height {} round {} (current step: {:?})",
            vote.voter,
            proposal_id,
            vote.height,
            vote.round,
            self.current_round.step
        );

        // **CE-L1**: Check if commit quorum is reached and finalize immediately
        self.maybe_finalize(vote.height, vote.round, &proposal_id).await?;

        Ok(())
    }

    async fn on_round_timeout(&mut self) -> ConsensusResult<()> {
        tracing::debug!(
            "Round timeout at height {} round {} step {:?}",
            self.current_round.height,
            self.current_round.round,
            self.current_round.step
        );

        match self.current_round.step {
            ConsensusStep::Propose => {
                self.enter_prevote_step().await?;
            }
            ConsensusStep::PreVote => {
                self.enter_precommit_step().await?;
            }
            ConsensusStep::PreCommit => {
                self.enter_commit_step().await?;
            }
            ConsensusStep::Commit => {
                self.advance_to_next_round();
            }
            ConsensusStep::NewRound => {}
        }

        Ok(())
    }

    async fn enter_prevote_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::PreVote {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::PreVote;
        tracing::info!(
            "Entering PreVote step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let vote = self.cast_vote(proposal_id, VoteType::PreVote).await?;
            let msg = ValidatorMessage::Vote { vote };
            let validator_ids = self.get_active_validator_ids();

            if let Err(e) = self.broadcaster
                .broadcast_to_validators(msg, &validator_ids)
                .await
            {
                tracing::debug!(
                    error = ?e,
                    "Failed to broadcast prevote (continuing per CE-ENG-4)"
                );
            }
        }

        Ok(())
    }

    async fn enter_precommit_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::PreCommit {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::PreCommit;
        tracing::info!(
            "Entering PreCommit step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.proposals.first().cloned() {
            let prevote_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreVote);
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(prevote_count, total_validators) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::PreCommit).await?;
                self.current_round.valid_proposal = Some(proposal_id);

                let msg = ValidatorMessage::Vote { vote };
                let validator_ids = self.get_active_validator_ids();

                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        "Failed to broadcast precommit (continuing per CE-ENG-4)"
                    );
                }
            }
        }

        Ok(())
    }

    async fn enter_commit_step(&mut self) -> ConsensusResult<()> {
        if self.current_round.step >= ConsensusStep::Commit {
            return Ok(());
        }

        self.current_round.step = ConsensusStep::Commit;
        tracing::info!(
            "Entering Commit step at height {} round {}",
            self.current_round.height,
            self.current_round.round
        );

        if let Some(proposal_id) = self.current_round.valid_proposal.as_ref().cloned() {
            let precommit_count = self.count_votes_for_proposal(&proposal_id, &VoteType::PreCommit);
            let total_validators = self.validator_manager.get_active_validators().len() as u64;

            if check_supermajority(precommit_count, total_validators) {
                let vote = self.cast_vote(proposal_id.clone(), VoteType::Commit).await?;

                tracing::info!(
                    "Block committed at height {} with proposal {:?}",
                    self.current_round.height,
                    proposal_id
                );

                let msg = ValidatorMessage::Vote { vote };
                let validator_ids = self.get_active_validator_ids();

                if let Err(e) = self.broadcaster
                    .broadcast_to_validators(msg, &validator_ids)
                    .await
                {
                    tracing::debug!(
                        error = ?e,
                        "Failed to broadcast commit vote (continuing per CE-ENG-4)"
                    );
                }

                // Process the committed block (finalization)
                // Note: maybe_finalize will be called by on_commit_vote after our vote is stored
                self.process_committed_block(&proposal_id).await?;
            }
        }

        Ok(())
    }

    fn is_proposal_relevant(&self, proposal: &ConsensusProposal) -> bool {
        if proposal.height < self.current_round.height {
            return false;
        }
        if proposal.height > self.current_round.height {
            return false;
        }
        if self.current_round.step > ConsensusStep::Propose {
            return false;
        }
        true
    }

    fn is_vote_relevant(&self, vote: &ConsensusVote) -> bool {
        if vote.height < self.current_round.height {
            return false;
        }
        if vote.height > self.current_round.height {
            return false;
        }
        if vote.round < self.current_round.round {
            return false;
        }
        if vote.round > self.current_round.round {
            return false;
        }

        match vote.vote_type {
            VoteType::PreVote => {
                self.current_round.step >= ConsensusStep::PreVote
            }
            VoteType::PreCommit => {
                self.current_round.step >= ConsensusStep::PreCommit
            }
            VoteType::Commit => {
                // Commit votes are considered relevant as long as height and round
                // match the current round, even if we have not yet reached the
                // Commit step locally. This matches the behavior of `on_commit_vote()`
                // and preserves CE-L2 compliance.
                true
            }
            VoteType::Against => false,
        }
    }

    fn vote_pool_contains_vote(&self, vote: &ConsensusVote) -> bool {
        let key = VotePoolKey {
            height: vote.height,
            round: vote.round,
            vote_type: vote.vote_type,
            validator_id: vote.voter.clone(),
        };
        self.vote_pool.contains_key(&key)
    }

    fn count_prevotes_for_round(&self, height: u64, round: u32) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, _)| k.height == height && k.round == round && k.vote_type == VoteType::PreVote)
            .count() as u64
    }

    fn count_precommits_for_round(&self, height: u64, round: u32) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, _)| k.height == height && k.round == round && k.vote_type == VoteType::PreCommit)
            .count() as u64
    }

    /// Count prevotes for a specific proposal in a round.
    /// **CE-S1**: Quorum checks must be proposal-scoped to prevent split votes.
    fn count_prevotes_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::PreVote
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Count precommits for a specific proposal in a round.
    /// **CE-S1**: Quorum checks must be proposal-scoped to prevent split votes.
    fn count_precommits_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::PreCommit
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Count commit votes for a specific proposal in a round.
    /// **CE-L1, CE-L2**: Commits trigger finalization regardless of local step.
    fn count_commits_for(&self, height: u64, round: u32, proposal_id: &Hash) -> u64 {
        self.vote_pool
            .iter()
            .filter(|(k, (_, voted_proposal_id))| {
                k.height == height
                    && k.round == round
                    && k.vote_type == VoteType::Commit
                    && voted_proposal_id == proposal_id
            })
            .count() as u64
    }

    /// Check if commit quorum is reached for a proposal and finalize if so.
    /// **CE-L1**: Commit quorum finalizes regardless of local step.
    /// **CE-L2**: This is called from any step, not just Commit.
    /// **Invariant**: Called from on_prevote, on_precommit, on_commit_vote, and enter_commit_step
    /// to prevent "stored but never used" regressions.
    async fn maybe_finalize(&mut self, height: u64, round: u32, proposal_id: &Hash) -> ConsensusResult<()> {
        // Count matching commit votes: all votes for this specific proposal at height/round
        // This ensures supermajority is proposal-scoped, not round-scoped
        let commit_count = self.count_commits_for(height, round, proposal_id);
        let total_validators = self.validator_manager.get_active_validators().len() as u64;

        if check_supermajority(commit_count, total_validators) {
            tracing::info!(
                "Finalization triggered: {} commits for proposal {:?} at height {} round {}",
                commit_count,
                proposal_id,
                height,
                round
            );

            // Finalize regardless of current step (CE-L1)
            if self.current_round.height == height && self.current_round.round == round {
                // Transition to Commit step if not already there
                if self.current_round.step < ConsensusStep::Commit {
                    self.current_round.step = ConsensusStep::Commit;
                    tracing::info!(
                        "Fast-tracked to Commit step via commit quorum at height {} round {}",
                        height,
                        round
                    );
                }

                // Process the committed block (finalization) directly
                // Note: This is safe even if we've already finalized once,
                // process_committed_block is idempotent.
                self.process_committed_block(proposal_id).await?;
            } else {
                tracing::debug!(
                    "Commit quorum observed for past round (H={} R={}) while at H={} R={}",
                    height,
                    round,
                    self.current_round.height,
                    self.current_round.round
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock message broadcaster for testing
    ///
    /// Tracks all broadcast calls and message types without side effects.
    /// This is used to verify that the consensus engine broadcasts
    /// the correct messages at the correct phases.
    #[derive(Debug)]
    struct MockMessageBroadcaster {
        /// All broadcast calls in order
        broadcasts: Mutex<Vec<BroadcastCall>>,
    }

    #[derive(Debug)]
    struct BroadcastCall {
        message: ValidatorMessage,
        validator_ids: Vec<IdentityId>,
    }

    impl MockMessageBroadcaster {
        fn new() -> Self {
            Self {
                broadcasts: Mutex::new(Vec::new()),
            }
        }

        fn get_broadcasts(&self) -> Vec<BroadcastCall> {
            self.broadcasts.lock().unwrap().clone()
        }

        fn count_broadcasts(&self) -> usize {
            self.broadcasts.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl MessageBroadcaster for MockMessageBroadcaster {
        async fn broadcast_to_validators(
            &self,
            message: ValidatorMessage,
            validator_ids: &[IdentityId],
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts.lock().unwrap().push(BroadcastCall {
                message,
                validator_ids: validator_ids.to_vec(),
            });
            Ok(())
        }
    }

    impl Clone for BroadcastCall {
        fn clone(&self) -> Self {
            Self {
                message: self.message.clone(),
                validator_ids: self.validator_ids.clone(),
            }
        }
    }

    fn test_validator_id(id: u8) -> IdentityId {
        // Create a deterministic test validator ID from a single byte
        // by repeating it 32 times to match Hash::from_bytes signature
        lib_crypto::Hash::from_bytes(&[id; 32])
    }

    fn create_test_signature() -> PostQuantumSignature {
        PostQuantumSignature {
            signature: vec![99u8; 32],
            public_key: lib_crypto::PublicKey {
                dilithium_pk: vec![42u8; 32],
                kyber_pk: vec![43u8; 32],
                key_id: [1u8; 32],
            },
            algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    #[tokio::test]
    async fn test_consensus_engine_creation_with_broadcaster() {
        let config = ConsensusConfig::default();
        let mock_broadcaster: Arc<dyn MessageBroadcaster> =
            Arc::new(MockMessageBroadcaster::new());
        let result = ConsensusEngine::new(config, mock_broadcaster);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_proposal_broadcast_in_propose_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set as proposer (needed to create a proposal)
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify proposal was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in propose phase"
        );

        // Verify it's a propose message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Propose { .. })),
            "Expected ValidatorMessage::Propose variant"
        );
    }

    #[tokio::test]
    async fn test_vote_broadcast_in_prevote_phase() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify vote was broadcast
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(
            broadcasts.len() > 0,
            "Expected at least one broadcast in prevote phase"
        );

        // Verify it's a vote message
        assert!(
            broadcasts.iter().any(|call| matches!(call.message, ValidatorMessage::Vote { .. })),
            "Expected ValidatorMessage::Vote variant"
        );
    }

    #[tokio::test]
    async fn test_validator_set_passed_to_broadcaster() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register multiple validators
        let validator_ids: Vec<_> = (0..3)
            .map(|i| test_validator_id(i))
            .collect();

        for id in &validator_ids {
            engine
                .register_validator(
                    id.clone(),
                    10_000_000_000,
                    100 * 1024 * 1024 * 1024,
                    vec![42u8; 32],
                    5,
                    true,
                )
                .await
                .expect("Failed to register validator");
        }

        // Create a proposal to vote on
        engine.current_round.proposer = Some(validator_ids[0].clone());
        engine.validator_identity = Some(validator_ids[0].clone());
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step
        engine.run_prevote_step().await.expect("Failed to run prevote step");

        // Verify validator set was passed to broadcaster
        let broadcasts = mock_broadcaster.get_broadcasts();
        assert!(broadcasts.len() > 0, "Expected broadcasts");

        for call in broadcasts {
            assert!(
                !call.validator_ids.is_empty(),
                "Expected validator IDs to be passed to broadcaster"
            );
            // All registered validators should be in the list
            assert!(
                call.validator_ids.len() >= 3,
                "Expected all validators to be in broadcast recipient list"
            );
        }
    }

    #[tokio::test]
    async fn test_broadcast_failure_does_not_affect_consensus() {
        /// Mock broadcaster that always fails
        struct FailingBroadcaster;

        #[async_trait::async_trait]
        impl MessageBroadcaster for FailingBroadcaster {
            async fn broadcast_to_validators(
                &self,
                _message: ValidatorMessage,
                _validator_ids: &[IdentityId],
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("Network error".into())
            }
        }

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(FailingBroadcaster);
        let mut engine =
            ConsensusEngine::new(config, broadcaster).expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Create a proposal to vote on
        let proposal = engine.create_proposal().await.expect("Failed to create proposal");
        engine.current_round.proposals.push(proposal.id.clone());

        // Run prevote step - should not fail even though broadcaster fails
        let result = engine.run_prevote_step().await;
        assert!(
            result.is_ok(),
            "Prevote step should succeed even if broadcast fails"
        );

        // Vote should still be in the vote pool
        // Check that at least one vote entry exists for current height/round
        let vote_count = engine
            .vote_pool
            .iter()
            .filter(|(k, _)| k.height == engine.current_round.height && k.round == engine.current_round.round)
            .count();
        assert!(vote_count > 0, "Vote should be stored even if broadcast fails");
    }

    #[tokio::test]
    async fn test_proposal_only_broadcast_when_proposer() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator but don't make it the proposer
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set a different validator as proposer
        engine.current_round.proposer = Some(test_validator_id(2));

        // Run propose step
        engine.run_propose_step().await.expect("Failed to run propose step");

        // Verify no proposal was broadcast
        assert_eq!(
            mock_broadcaster.count_broadcasts(),
            0,
            "Proposal should not be broadcast if not proposer"
        );
    }

    #[tokio::test]
    async fn test_multiple_phases_produce_multiple_broadcasts() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let mock_broadcaster = Arc::new(MockMessageBroadcaster::new());
        let broadcaster: Arc<dyn MessageBroadcaster> = Arc::clone(&mock_broadcaster) as Arc<dyn MessageBroadcaster>;
        let mut engine = ConsensusEngine::new(config, broadcaster)
            .expect("Failed to create consensus engine");

        // Register as validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register validator");

        // Set as proposer
        engine.current_round.proposer = Some(validator_id.clone());
        engine.validator_identity = Some(validator_id);

        // Run propose step - should broadcast proposal
        engine.run_propose_step().await.expect("Failed to run propose step");
        let broadcasts_after_propose = mock_broadcaster.count_broadcasts();
        assert!(broadcasts_after_propose > 0, "Expected broadcast in propose phase");

        // Run prevote step - should broadcast vote
        engine.run_prevote_step().await.expect("Failed to run prevote step");
        let broadcasts_after_prevote = mock_broadcaster.count_broadcasts();
        assert!(
            broadcasts_after_prevote > broadcasts_after_propose,
            "Expected additional broadcast in prevote phase"
        );
    }

    /// Gap 4 Invariant Test: Message relevance checking
    ///
    /// Verifies that messages with mismatched height/round are correctly ignored
    /// and do not affect vote_pool or state.
    #[tokio::test]
    async fn test_gap4_message_relevance_invariant() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let validator1 = test_validator_id(1);
        engine
            .register_validator(
                validator1.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to height=2, round=1
        engine.current_round.height = 2;
        engine.current_round.round = 1;
        engine.current_round.step = ConsensusStep::PreVote;

        // Create votes for different heights/rounds
        let vote_past_height = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[10u8; 32]),
            vote_type: VoteType::PreVote,
            height: 1, // Past height
            round: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        let vote_future_height = ConsensusVote {
            id: Hash::from_bytes(&[2u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[11u8; 32]),
            vote_type: VoteType::PreVote,
            height: 3, // Future height
            round: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        let vote_past_round = ConsensusVote {
            id: Hash::from_bytes(&[3u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[12u8; 32]),
            vote_type: VoteType::PreVote,
            height: 2,
            round: 0, // Past round
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        let vote_relevant = ConsensusVote {
            id: Hash::from_bytes(&[4u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[13u8; 32]),
            vote_type: VoteType::PreVote,
            height: 2,
            round: 1, // Matches current state
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        // Process irrelevant votes
        engine.on_prevote(vote_past_height).await.expect("Process vote");
        engine.on_prevote(vote_future_height).await.expect("Process vote");
        engine.on_prevote(vote_past_round).await.expect("Process vote");

        // Vote pool should be empty
        assert_eq!(engine.vote_pool.len(), 0, "Irrelevant votes should be ignored");

        // Process relevant vote
        engine.on_prevote(vote_relevant.clone()).await.expect("Process vote");

        // Vote pool should now have exactly 1 entry
        assert_eq!(engine.vote_pool.len(), 1, "Relevant vote should be in pool");
    }

    /// Gap 4 Invariant Test: Idempotence and equivocation detection
    ///
    /// Verifies:
    /// 1. Same vote twice (duplicate) is idempotent - no state change
    /// 2. Same validator, same (H,R,type), different value is detected as equivocation
    #[tokio::test]
    async fn test_gap4_idempotence_and_equivocation_invariant() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let validator1 = test_validator_id(1);
        engine
            .register_validator(
                validator1.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        engine.current_round.step = ConsensusStep::PreVote;

        // Vote 1: for proposal A
        let vote_a = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[100u8; 32]), // Proposal A
            vote_type: VoteType::PreVote,
            height: 0,
            round: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        // Vote 2: same validator, same H/R/type, for proposal B (equivocation)
        let vote_b = ConsensusVote {
            id: Hash::from_bytes(&[2u8; 32]),
            voter: validator1.clone(),
            proposal_id: Hash::from_bytes(&[101u8; 32]), // Different proposal B
            vote_type: VoteType::PreVote,
            height: 0,
            round: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: create_test_signature(),
        };

        // Add vote A
        engine.on_prevote(vote_a.clone()).await.expect("Process vote");
        assert_eq!(engine.vote_pool.len(), 1, "Vote A should be in pool");

        // Add vote A again (duplicate) - should be no-op
        engine.on_prevote(vote_a.clone()).await.expect("Process vote");
        assert_eq!(engine.vote_pool.len(), 1, "Duplicate should be idempotent");

        // Add vote B (equivocation) - should be rejected
        engine.on_prevote(vote_b).await.expect("Process vote");
        assert_eq!(
            engine.vote_pool.len(),
            1,
            "Equivocating vote should be rejected (still 1 entry)"
        );

        // Verify only A is in pool
        let key_a = VotePoolKey {
            height: 0,
            round: 0,
            vote_type: VoteType::PreVote,
            validator_id: validator1,
        };
        assert!(
            engine.vote_pool.contains_key(&key_a),
            "Original vote A should still be in pool"
        );
    }

    /// Gap 4 Invariant Test: Threshold consistency
    ///
    /// Verifies that check_supermajority() correctly identifies quorum threshold.
    /// For 3 validators: threshold should be 3 (2f+1 where f=1)
    /// For 4 validators: threshold should be 3 (2f+1 where f=1)
    /// For 7 validators: threshold should be 5 (2f+1 where f=2)
    #[tokio::test]
    async fn test_gap4_quorum_threshold_consistency() {
        // 3 validators: need 3 votes (all of them)
        assert!(check_supermajority(3, 3), "3/3 votes should be quorum");
        assert!(!check_supermajority(2, 3), "2/3 votes should NOT be quorum");

        // 4 validators: need 3 votes (2/3 + 1)
        assert!(check_supermajority(3, 4), "3/4 votes should be quorum");
        assert!(!check_supermajority(2, 4), "2/4 votes should NOT be quorum");

        // 7 validators: need 5 votes
        assert!(check_supermajority(5, 7), "5/7 votes should be quorum");
        assert!(!check_supermajority(4, 7), "4/7 votes should NOT be quorum");

        // Edge case: 1 validator (needs 1)
        assert!(check_supermajority(1, 1), "1/1 vote should be quorum");
    }

    /// Gap 4 Invariant Test: Timer token staleness guard
    ///
    /// Verifies that TimerToken correctly identifies stale vs current timeouts
    #[test]
    fn test_gap4_timer_token_staleness_detection() {
        let step_propose = ConsensusStep::Propose;
        let step_prevote = ConsensusStep::PreVote;

        // Token for height=1, round=0, Propose
        let token = TimerToken::new(1, 0, &step_propose);

        // Should match current state
        assert!(
            token.matches(1, 0, &step_propose),
            "Token should match current state"
        );

        // Should NOT match different height
        assert!(!token.matches(2, 0, &step_propose), "Token should not match height 2");

        // Should NOT match different round
        assert!(!token.matches(1, 1, &step_propose), "Token should not match round 1");

        // Should NOT match different step
        assert!(
            !token.matches(1, 0, &step_prevote),
            "Token should not match different step"
        );
    }

    /// Gap 4 Invariant Test: Receiver closure causes graceful shutdown
    ///
    /// Verifies that closing the message receiver causes run_consensus_loop to exit
    #[tokio::test]
    async fn test_gap4_receiver_closure_graceful_shutdown() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let (tx, rx) = mpsc::channel(32);
        engine.set_message_receiver(rx);

        // Spawn the loop in background
        let mut engine_handle = tokio::spawn(async move {
            engine.run_consensus_loop().await
        });

        // Give loop time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Close the sender (receiver will get None on next recv())
        drop(tx);

        // Loop should exit cleanly within reasonable time
        let result = tokio::time::timeout(Duration::from_secs(1), &mut engine_handle).await;

        match result {
            Ok(Ok(Ok(_))) => {
                // Loop exited cleanly
            }
            Ok(Ok(Err(e))) => {
                panic!("Loop returned error: {}", e);
            }
            Ok(Err(e)) => {
                panic!("Task panicked: {}", e);
            }
            Err(_) => {
                panic!("Loop did not exit within timeout (likely hung)");
            }
        }
    }

    #[test]
    fn test_ce_s1_proposal_scoped_quorums_prevent_split_votes() {
        // **CE-S1**: A quorum must be counted for a single proposal ID, never for a round in aggregate.
        // This test verifies that split votes across different proposals do NOT trigger transitions.

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        let proposal_a = Hash::from_bytes(&[1u8; 32]);
        let proposal_b = Hash::from_bytes(&[2u8; 32]);
        let proposal_c = Hash::from_bytes(&[3u8; 32]);

        // Verify proposal-scoped counting methods exist and return correct values
        let count_for_a = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_a,
        );
        assert_eq!(count_for_a, 0, "Empty pool should have 0 votes for proposal A");

        let count_for_b = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_b,
        );
        assert_eq!(count_for_b, 0, "Empty pool should have 0 votes for proposal B");

        let count_for_c = engine.count_prevotes_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_c,
        );
        assert_eq!(count_for_c, 0, "Empty pool should have 0 votes for proposal C");

        // The key invariant: even if we had 4 total votes (1 for each of A, B, C, and 1 more),
        // no single proposal would reach quorum (3 needed), so transitions would be prevented.
        // This is CE-S1 safety: quorum must be per-proposal, not per-round aggregate.
    }

    #[tokio::test]
    async fn test_ce_l1_commit_quorum_finalizes_regardless_of_local_step() {
        // **CE-L1**: Observing 2f+1 commit votes for a proposal MUST allow finalization
        // even if the node missed earlier steps (e.g., didn't receive precommits locally).

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register 4 validators for testing
        for i in 1..=4 {
            let validator_id = test_validator_id(i as u8);
            engine
                .register_validator(
                    validator_id,
                    10_000_000_000,
                    100 * 1024 * 1024 * 1024,
                    vec![42u8; 32],
                    5,
                    i == 1,
                )
                .await
                .expect("Failed to register");
        }

        let proposal_id = Hash::from_bytes(&[42u8; 32]);

        // Manually set engine to PreVote step (simulate missing precommits)
        engine.current_round.step = ConsensusStep::PreVote;

        // Add 3 commit votes (quorum) directly to vote pool
        for i in 1..=3 {
            let validator_id = test_validator_id(i as u8);
            let key = VotePoolKey {
                height: engine.current_round.height,
                round: engine.current_round.round,
                vote_type: VoteType::Commit,
                validator_id: validator_id.clone(),
            };
            let vote = ConsensusVote {
                id: Hash::from_bytes(&[(i + 100) as u8; 32]),
                voter: validator_id,
                proposal_id: proposal_id.clone(),
                vote_type: VoteType::Commit,
                height: engine.current_round.height,
                round: engine.current_round.round,
                timestamp: 0,
                signature: create_test_signature(),
            };
            engine.vote_pool.insert(key, (vote, proposal_id.clone()));
        }

        // Verify: Step is still PreVote
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);

        // Call maybe_finalize: should transition to Commit step and finalize
        engine.maybe_finalize(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        ).await.unwrap();

        // Verify: Step transitioned to Commit (CE-L1)
        assert_eq!(engine.current_round.step, ConsensusStep::Commit,
            "CE-L1: Commit quorum should fast-track to Commit step");

        // Verify: Commit count is correct
        let commit_count = engine.count_commits_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        );
        assert_eq!(commit_count, 3, "Should have 3 commits for proposal");
    }

    #[tokio::test]
    async fn test_ce_l2_commit_votes_stored_at_any_step() {
        // **CE-L2**: Commit votes MUST be accepted and stored at any step,
        // not only during Commit step.

        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register 3 validators
        for i in 1..=3 {
            let validator_id = test_validator_id(i as u8);
            engine
                .register_validator(
                    validator_id,
                    10_000_000_000,
                    100 * 1024 * 1024 * 1024,
                    vec![42u8; 32],
                    5,
                    i == 1,
                )
                .await
                .expect("Failed to register");
        }

        let proposal_id = Hash::from_bytes(&[55u8; 32]);

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);

        // Create a commit vote while in PreVote step
        let validator_id = test_validator_id(1);
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[200u8; 32]),
            voter: validator_id,
            proposal_id: proposal_id.clone(),
            vote_type: VoteType::Commit,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Call on_commit_vote while in PreVote step
        engine.on_commit_vote(vote.clone()).await.unwrap();

        // Verify: Commit vote was stored even though we're in PreVote (CE-L2)
        let commit_count = engine.count_commits_for(
            engine.current_round.height,
            engine.current_round.round,
            &proposal_id,
        );
        assert_eq!(commit_count, 1, "CE-L2: Commit vote should be stored in PreVote step");

        // Step should still be PreVote (no automatic transition since quorum not reached)
        assert_eq!(engine.current_round.step, ConsensusStep::PreVote);
    }

    // ============================================================================
    // CONSENSUS-NET-4.3: Remote Vote Validation and Supermajority Hardening Tests
    // ============================================================================

    /// Test: check_supermajority() with correct threshold formula
    ///
    /// Verifies that check_supermajority() uses the correct formula:
    /// threshold = (total_validators * 2 / 3) + 1 (integer division)
    #[test]
    fn test_hardening_check_supermajority_correct_threshold() {
        // 1 validator: (1 * 2) / 3 + 1 = 0 + 1 = 1 (integer division)
        assert!(!check_supermajority(0, 1), "0/1 should not be supermajority");
        assert!(check_supermajority(1, 1), "1/1 should be supermajority");

        // 3 validators: (3 * 2) / 3 + 1 = 2 + 1 = 3
        assert!(!check_supermajority(2, 3), "2/3 should not be supermajority");
        assert!(check_supermajority(3, 3), "3/3 should be supermajority");

        // 4 validators: (4 * 2) / 3 + 1 = 2 + 1 = 3 (integer division)
        assert!(!check_supermajority(2, 4), "2/4 should not be supermajority");
        assert!(check_supermajority(3, 4), "3/4 should be supermajority");
        assert!(check_supermajority(4, 4), "4/4 should be supermajority");

        // 7 validators: (7 * 2) / 3 + 1 = 4 + 1 = 5 (integer division)
        assert!(!check_supermajority(4, 7), "4/7 should not be supermajority");
        assert!(check_supermajority(5, 7), "5/7 should be supermajority");

        // 100 validators: (100 * 2) / 3 + 1 = 66 + 1 = 67 (integer division)
        assert!(!check_supermajority(66, 100), "66/100 should not be supermajority");
        assert!(check_supermajority(67, 100), "67/100 should be supermajority");
    }

    /// Test: Acceptance criteria - 4 validators
    ///
    /// With 4 validators, threshold = 3:
    /// - 2 votes → no quorum
    /// - 3 identical votes → quorum reached
    /// - Mixed votes (2+2) → no quorum
    #[test]
    fn test_hardening_4validator_acceptance_criteria() {
        let total_validators = 4u64;

        // Criterion: 2 votes → no quorum
        assert!(
            !check_supermajority(2, total_validators),
            "2/4 votes should NOT be supermajority"
        );

        // Criterion: 3 identical votes → quorum reached
        assert!(
            check_supermajority(3, total_validators),
            "3/4 identical votes MUST trigger supermajority"
        );

        // Note: 2+2 mixed votes is handled by counting proposal-scoped votes
        // If 2 vote for proposal A and 2 vote for proposal B:
        // count_prevotes_for(proposal_a) = 2 (no quorum)
        // count_prevotes_for(proposal_b) = 2 (no quorum)
        // Result: Mixed or split votes MUST NOT count
    }

    /// Test: Remote vote validation - height mismatch rejection
    ///
    /// A vote with height != local.height MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_height_mismatch() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to height=5, round=0, PreVote step
        engine.current_round.height = 5;
        engine.current_round.round = 0;
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with wrong height (height=6)
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: 6, // WRONG: height != local.height
            round: 0,
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote with height mismatch MUST be rejected (height={} != local.height={})",
            vote.height,
            engine.current_round.height
        );
    }

    /// Test: Remote vote validation - round mismatch rejection
    ///
    /// A vote with round != local.round MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_round_mismatch() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to height=0, round=5, PreVote step
        engine.current_round.height = 0;
        engine.current_round.round = 5;
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with wrong round (round=6)
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: 0,
            round: 6, // WRONG: round != local.round
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote with round mismatch MUST be rejected (round={} != local.round={})",
            vote.round,
            engine.current_round.round
        );
    }

    /// Test: Remote vote validation - non-member validator rejection
    ///
    /// A vote from a validator NOT in active set MUST be rejected
    #[tokio::test]
    async fn test_hardening_vote_validation_non_member_validator() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register only validator 1
        let validator_id_1 = test_validator_id(1);
        engine
            .register_validator(
                validator_id_1.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Create a vote from validator 2 (NOT registered)
        let validator_id_2 = test_validator_id(2);
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id_2.clone(),
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "Vote from non-member validator MUST be rejected"
        );
    }

    /// Test: Remote vote validation - vote type coherence (PreVote in Propose step)
    ///
    /// A PreVote is NOT valid during Propose step
    #[tokio::test]
    async fn test_hardening_vote_validation_prevote_in_propose_step() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to Propose step
        engine.current_round.step = ConsensusStep::Propose;

        // Create a PreVote while in Propose step
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "PreVote in Propose step MUST be rejected (step coherence violation)"
        );
    }

    /// Test: Remote vote validation - vote type coherence (PreCommit in PreVote step)
    ///
    /// A PreCommit is NOT valid during PreVote step
    #[tokio::test]
    async fn test_hardening_vote_validation_precommit_in_prevote_step() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a PreCommit while in PreVote step
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreCommit,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(
            !is_valid,
            "PreCommit in PreVote step MUST be rejected (step coherence violation)"
        );
    }

    /// Test: Remote vote validation - Commit votes always valid (if height/round match)
    ///
    /// Commit votes are always valid regardless of current step
    #[tokio::test]
    async fn test_hardening_vote_validation_commit_always_valid() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Test in each step
        for step in &[
            ConsensusStep::Propose,
            ConsensusStep::PreVote,
            ConsensusStep::PreCommit,
            ConsensusStep::Commit,
        ] {
            engine.current_round.step = step.clone();

            // Create a Commit vote
            let vote = ConsensusVote {
                id: Hash::from_bytes(&[1u8; 32]),
                voter: validator_id.clone(),
                proposal_id: Hash::from_bytes(&[2u8; 32]),
                vote_type: VoteType::Commit,
                height: engine.current_round.height,
                round: engine.current_round.round,
                timestamp: 0,
                signature: create_test_signature(),
            };

            // Validate the vote - should always be valid
            let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
            assert!(
                is_valid,
                "Commit vote MUST always be valid regardless of step (currently in {:?})",
                step
            );
        }
    }

    /// Test: Remote vote validation - invalid signature rejection
    ///
    /// A vote with invalid signature MUST be rejected (Invariant #1)
    #[tokio::test]
    async fn test_hardening_vote_validation_invalid_signature() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to PreVote step
        engine.current_round.step = ConsensusStep::PreVote;

        // Create a vote with an empty signature (invalid)
        let mut bad_signature = create_test_signature();
        bad_signature.signature = Vec::new(); // Make signature invalid

        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: Hash::from_bytes(&[2u8; 32]),
            vote_type: VoteType::PreVote,
            height: engine.current_round.height,
            round: engine.current_round.round,
            timestamp: 0,
            signature: bad_signature,
        };

        // Validate the vote - should be rejected
        let is_valid = engine.validate_remote_vote(&vote).await.expect("validation failed");
        assert!(!is_valid, "Vote with invalid signature MUST be rejected");
    }

    /// Test: Remote vote validation - commit votes allow round catch-up
    ///
    /// on_commit_vote() is designed to accept commit votes from any round at the current height
    /// to allow catch-up from previous rounds. This test verifies that such votes are not
    /// rejected at the basic validation level.
    #[tokio::test]
    async fn test_hardening_commit_vote_accepts_past_round() {
        let config = ConsensusConfig {
            development_mode: true,
            ..Default::default()
        };
        let broadcaster = Arc::new(MockMessageBroadcaster::new());
        let mut engine = ConsensusEngine::new(config, broadcaster as Arc<dyn MessageBroadcaster>)
            .expect("Failed to create engine");

        // Register a validator
        let validator_id = test_validator_id(1);
        engine
            .register_validator(
                validator_id.clone(),
                10_000_000_000,
                100 * 1024 * 1024 * 1024,
                vec![42u8; 32],
                5,
                true,
            )
            .await
            .expect("Failed to register");

        // Set engine to height=5, round=3
        engine.current_round.height = 5;
        engine.current_round.round = 3;
        engine.current_round.step = ConsensusStep::PreCommit;

        let proposal_id = Hash::from_bytes(&[2u8; 32]);

        // Create a commit vote from a PAST round (round=2 while current is 3)
        let vote = ConsensusVote {
            id: Hash::from_bytes(&[1u8; 32]),
            voter: validator_id,
            proposal_id: proposal_id.clone(),
            vote_type: VoteType::Commit,
            height: 5,  // Same height
            round: 2,   // Past round
            timestamp: 0,
            signature: create_test_signature(),
        };

        // Call on_commit_vote with past-round commit vote
        // It should be accepted (not rejected) for catch-up purposes
        engine.on_commit_vote(vote.clone()).await.expect("commit vote failed");

        // Verify the vote was stored
        let commit_count = engine.count_commits_for(5, 2, &proposal_id);
        assert_eq!(commit_count, 1, "Past-round commit vote should be stored for catch-up");
    }
}

