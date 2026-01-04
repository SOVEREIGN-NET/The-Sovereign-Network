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
//! - Validator membership is height-scoped using per-height snapshots
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lib_crypto::{Hash, KeyPair};
use lib_identity::IdentityId;
use tokio::sync::mpsc;
use tokio::time::Sleep;

use crate::byzantine::ByzantineFaultDetector;
use crate::dao::DaoEngine;
use crate::dao::dao_types::{DaoExecutionAction, DaoProposal};
use crate::dao::dao_types::{GovernanceParameterUpdate, GovernanceParameterValue};
use crate::rewards::RewardCalculator;
use crate::types::*;
use crate::validators::ValidatorManager;
use crate::{ConsensusError, ConsensusResult};

mod liveness;
mod network;
mod proofs;
mod state_machine;
mod storage;
mod validation;

#[cfg(test)]
mod tests;

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

/// Snapshot of validator membership for a specific height
#[derive(Debug, Clone)]
struct ValidatorSetSnapshot {
    height: u64,
    validators: HashSet<IdentityId>,
}

#[derive(Debug, Clone)]
struct PendingValidatorAdd {
    identity: IdentityId,
    stake: u64,
    storage_capacity: u64,
    consensus_key: Vec<u8>,
    commission_rate: u8,
}

#[derive(Debug, Clone)]
enum ValidatorSetChange {
    Add(PendingValidatorAdd),
    Remove(IdentityId),
}

#[derive(Debug, Clone)]
struct PendingValidatorChange {
    effective_height: u64,
    change: ValidatorSetChange,
}

#[derive(Debug, Clone)]
struct PendingEpochLengthUpdate {
    effective_height: u64,
    new_length: u64,
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
    /// Validator membership snapshots by height (height-scoped validation)
    validator_set_history: VecDeque<ValidatorSetSnapshot>,
    /// Pending validator set changes applied at epoch boundaries
    pending_validator_changes: VecDeque<PendingValidatorChange>,
    /// Pending epoch length updates applied at epoch boundaries
    pending_epoch_length_update: Option<PendingEpochLengthUpdate>,
    /// Whether consensus has begun (genesis window closed)
    chain_started: bool,
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
    /// Local validator signing keypair (required for proposal/vote signing)
    validator_keypair: Option<KeyPair>,
    /// Storage proof provider (lib-storage backed)
    storage_proof_provider: Option<Arc<dyn crate::proofs::StorageProofProvider>>,
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
            validator_set_history: VecDeque::new(),
            pending_validator_changes: VecDeque::new(),
            pending_epoch_length_update: None,
            chain_started: false,
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
            validator_keypair: None,
            storage_proof_provider: None,
        })
    }

    /// Set the message receiver (from network layer)
    pub fn set_message_receiver(&mut self, rx: mpsc::Receiver<ValidatorMessage>) {
        self.message_rx = Some(rx);
    }

    /// Set the local validator signing keypair (required for proposal/vote signing)
    pub fn set_validator_keypair(&mut self, keypair: KeyPair) -> ConsensusResult<()> {
        if let Some(identity) = &self.validator_identity {
            if let Some(validator) = self.validator_manager.get_validator(identity) {
                if validator.consensus_key != keypair.public_key.dilithium_pk {
                    return Err(ConsensusError::ValidatorError(
                        "Validator keypair does not match registered consensus key".to_string(),
                    ));
                }
            }
        }

        self.validator_keypair = Some(keypair);
        Ok(())
    }

    /// Set storage proof provider for Proof-of-Storage attestations
    pub fn set_storage_proof_provider(
        &mut self,
        provider: Arc<dyn crate::proofs::StorageProofProvider>,
    ) {
        self.storage_proof_provider = Some(provider);
    }

    /// Apply governance updates with delayed activation for epoch length changes.
    pub fn apply_governance_update(
        &mut self,
        update: &GovernanceParameterUpdate,
    ) -> ConsensusResult<()> {
        self.dao_engine
            .validate_governance_update(update)
            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;

        let mut passthrough_updates = Vec::new();

        for param in &update.updates {
            match param {
                GovernanceParameterValue::EpochLengthBlocks(value) => {
                    self.schedule_epoch_length_update(*value)?;
                }
                _ => passthrough_updates.push(param.clone()),
            }
        }

        if !passthrough_updates.is_empty() {
            let filtered = GovernanceParameterUpdate {
                updates: passthrough_updates,
            };
            self.dao_engine
                .apply_governance_update(&mut self.config, &filtered)
                .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;
        }

        Ok(())
    }

    /// Apply governance updates from a DAO proposal with delayed activation
    /// for epoch-length changes.
    pub fn apply_governance_update_from_proposal(
        &mut self,
        proposal: &DaoProposal,
    ) -> ConsensusResult<()> {
        let params = proposal
            .execution_params
            .as_ref()
            .ok_or_else(|| ConsensusError::ValidatorError("Proposal missing execution params".to_string()))?;
        let decoded = self
            .dao_engine
            .decode_execution_params(params)
            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;

        match decoded.action {
            DaoExecutionAction::GovernanceParameterUpdate(update) => {
                self.apply_governance_update(&update)
            }
        }
    }

    /// Schedule an epoch length update at the next epoch boundary.
    pub fn schedule_epoch_length_update(&mut self, new_length: u64) -> ConsensusResult<()> {
        if new_length == 0 {
            return Err(ConsensusError::ValidatorError(
                "Epoch length must be greater than zero".to_string(),
            ));
        }

        let effective_height = self.next_epoch_start(self.current_round.height);
        self.pending_epoch_length_update = Some(PendingEpochLengthUpdate {
            effective_height,
            new_length,
        });

        Ok(())
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

        if self.validator_identity.is_none() {
            if let Some(keypair) = &self.validator_keypair {
                if keypair.public_key.dilithium_pk != consensus_key {
                    return Err(ConsensusError::ValidatorError(
                        "Validator keypair does not match registered consensus key".to_string(),
                    ));
                }
            }
        }

        let register_immediately = is_genesis || !self.chain_started;

        if register_immediately {
            self.validator_manager
                .register_validator(
                    identity.clone(),
                    stake,
                    storage_capacity,
                    consensus_key.clone(),
                    commission_rate,
                )
                .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;
        } else {
            self.queue_validator_add(PendingValidatorAdd {
                identity: identity.clone(),
                stake,
                storage_capacity,
                consensus_key: consensus_key.clone(),
                commission_rate,
            })?;
        }

        // Set as local validator if this is the first one
        if self.validator_identity.is_none() {
            self.validator_identity = Some(identity.clone());
            // Also set the heartbeat tracker's local validator so heartbeats are properly attributed
            self.heartbeat_tracker.set_local_validator(identity.clone());
        }

        tracing::info!(
            "Registered validator {:?} with {} ZHTP stake{}",
            identity,
            stake,
            if register_immediately {
                ""
            } else {
                " (pending epoch activation)"
            }
        );
        Ok(())
    }

    fn epoch_length_blocks(&self) -> u64 {
        if self.config.epoch_length_blocks == 0 {
            tracing::warn!("Epoch length blocks is zero; defaulting to 1");
            return 1;
        }
        self.config.epoch_length_blocks
    }

    fn is_epoch_boundary(&self, height: u64) -> bool {
        height % self.epoch_length_blocks() == 0
    }

    fn next_epoch_start(&self, height: u64) -> u64 {
        let epoch_len = self.epoch_length_blocks();
        ((height / epoch_len) + 1) * epoch_len
    }

    fn queue_validator_add(&mut self, pending: PendingValidatorAdd) -> ConsensusResult<()> {
        if self.validator_manager.get_validator(&pending.identity).is_some() {
            return Err(ConsensusError::ValidatorError(
                "Validator already registered".to_string(),
            ));
        }

        let identity = pending.identity.clone();
        let mut removed_pending_remove = false;
        self.pending_validator_changes.retain(|entry| match &entry.change {
            ValidatorSetChange::Remove(existing) if *existing == identity => {
                removed_pending_remove = true;
                false
            }
            ValidatorSetChange::Add(existing) if existing.identity == identity => false,
            _ => true,
        });

        if removed_pending_remove {
            tracing::info!(
                "Removed pending validator removal for {:?} due to new registration request",
                identity
            );
        }

        let effective_height = self.next_epoch_start(self.current_round.height);
        self.pending_validator_changes.push_back(PendingValidatorChange {
            effective_height,
            change: ValidatorSetChange::Add(pending),
        });

        Ok(())
    }

    fn queue_validator_removal(&mut self, identity: IdentityId) -> ConsensusResult<()> {
        let mut removed_pending_add = false;
        self.pending_validator_changes.retain(|entry| match &entry.change {
            ValidatorSetChange::Add(existing) if existing.identity == identity => {
                removed_pending_add = true;
                false
            }
            _ => true,
        });

        if removed_pending_add {
            tracing::info!(
                "Removed pending validator add for {:?} due to removal request",
                identity
            );
            return Ok(());
        }

        if self.validator_manager.get_validator(&identity).is_none() {
            return Err(ConsensusError::ValidatorError(
                "Validator not found for removal".to_string(),
            ));
        }

        let effective_height = self.next_epoch_start(self.current_round.height);
        self.pending_validator_changes.push_back(PendingValidatorChange {
            effective_height,
            change: ValidatorSetChange::Remove(identity),
        });

        Ok(())
    }

    fn apply_epoch_boundary_changes(&mut self, height: u64) -> ConsensusResult<()> {
        if !self.is_epoch_boundary(height) {
            return Ok(());
        }

        if let Some(update) = self.pending_epoch_length_update.clone() {
            if update.effective_height == height {
                self.config.epoch_length_blocks = update.new_length;
                self.pending_epoch_length_update = None;
                tracing::info!(
                    "Epoch length updated to {} at height {}",
                    update.new_length,
                    height
                );
            }
        }

        let mut remaining = VecDeque::new();
        let mut applied_changes = 0usize;

        while let Some(entry) = self.pending_validator_changes.pop_front() {
            if entry.effective_height != height {
                remaining.push_back(entry);
                continue;
            }

            match entry.change {
                ValidatorSetChange::Add(add) => {
                    if self.validator_manager.get_validator(&add.identity).is_none() {
                        self.validator_manager
                            .register_validator(
                                add.identity.clone(),
                                add.stake,
                                add.storage_capacity,
                                add.consensus_key,
                                add.commission_rate,
                            )
                            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;
                        applied_changes += 1;
                    }
                }
                ValidatorSetChange::Remove(identity) => {
                    if self.validator_manager.get_validator(&identity).is_some() {
                        let _ = self
                            .validator_manager
                            .remove_validator(&identity)
                            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;
                        applied_changes += 1;
                    }
                }
            }
        }

        self.pending_validator_changes = remaining;

        if applied_changes > 0 {
            let active_validators: Vec<_> = self
                .validator_manager
                .get_active_validators()
                .iter()
                .map(|v| v.identity.clone())
                .collect();
            self.liveness_monitor.update_validator_set(&active_validators);
        }

        Ok(())
    }

    /// Get active validator IDs for the current round
    ///
    /// This is used when broadcasting to ensure the validator set is passed explicitly
    /// rather than queried from network state (Invariant CE-ENG-5).
    fn get_active_validator_ids(&self) -> Vec<IdentityId> {
        self.get_validator_ids_for_height(self.current_round.height)
    }

    /// Snapshot validator membership for a specific height
    pub(super) fn snapshot_validator_set(&mut self, height: u64) {
        let validators: HashSet<IdentityId> = self
            .validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect();

        if let Some(existing) = self
            .validator_set_history
            .iter_mut()
            .find(|snapshot| snapshot.height == height)
        {
            existing.validators = validators;
            return;
        }

        self.validator_set_history.push_back(ValidatorSetSnapshot {
            height,
            validators,
        });

        if self.validator_set_history.len() > 100 {
            self.validator_set_history.pop_front();
        }
    }

    /// Get the validator set snapshot for a height, if available
    pub(super) fn validator_set_for_height(&self, height: u64) -> Option<&HashSet<IdentityId>> {
        self.validator_set_history
            .iter()
            .find(|snapshot| snapshot.height == height)
            .map(|snapshot| &snapshot.validators)
    }

    /// Get validator IDs for a height, falling back to current active set when missing
    fn get_validator_ids_for_height(&self, height: u64) -> Vec<IdentityId> {
        if let Some(snapshot) = self.validator_set_for_height(height) {
            return snapshot.iter().cloned().collect();
        }

        tracing::debug!(
            "Validator set snapshot missing for height {}, using current active set",
            height
        );

        self.validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect()
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
}
