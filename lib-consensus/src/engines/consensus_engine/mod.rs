//! Consensus engine — Tendermint-like BFT
//!
//! # Consensus Algorithm Specification
//!
//! ## Algorithm Variant: Tendermint-like BFT
//!
//! This consensus engine implements a **Tendermint-like Byzantine Fault Tolerant (BFT)**
//! consensus algorithm. It is derived from the Tendermint protocol as described in:
//! "The latest gossip on BFT consensus" (Buchman et al., 2018).
//!
//! ### Key Properties Inherited from Tendermint
//!
//! - **Safety** (agreement): No two honest validators ever commit different blocks at the
//!   same height, even in the presence of up to f < n/3 Byzantine validators.
//! - **Liveness** (progress): Under a partially-synchronous network model (after GST),
//!   the protocol eventually commits a block at every height.
//! - **Accountability**: Byzantine validators that equivocate can be detected and slashed.
//!
//! ### Phases Per Round
//!
//! Each consensus round progresses through the following steps in order:
//! 1. **Propose** — The designated leader (proposer) broadcasts a proposal.
//! 2. **PreVote** — All validators broadcast a prevote for the proposal (or nil).
//! 3. **PreCommit** — Upon receiving 2f+1 prevotes, validators broadcast a precommit.
//! 4. **Commit** — Upon receiving 2f+1 precommits, the block is committed and finalized.
//!
//! ## Leader Rotation Rule: Round-Robin by Height
//!
//! The proposer (leader) for a given (height, round) is selected **deterministically**
//! using a round-robin algorithm keyed by height:
//!
//! ```text
//! proposer_index = (height + round) % num_validators
//! proposer = sorted_validator_set[proposer_index]
//! ```
//!
//! - The validator set is sorted by identity ID for determinism across all nodes.
//! - At height H, round 0: the leader is `validators[(H) % n]`.
//! - At height H, round R > 0: the leader is `validators[(H + R) % n]`.
//! - This ensures every validator gets an equal opportunity to propose over time.
//! - Leader selection is a pure function of (height, round, validator_set) — no randomness.
//!
//! See `LEADER_ROTATION_RULE` constant and `compute_proposer_for_round()` for enforcement.
//!
//! ## View-Change Trigger Conditions
//!
//! A **view-change** (round increment) is triggered when the current round fails to
//! produce a committed block. The following conditions independently trigger a view-change:
//!
//! 1. **Proposal timeout**: The proposer did not deliver a valid proposal within
//!    `ConsensusConfig::propose_timeout` milliseconds.
//! 2. **PreVote timeout**: The prevote step did not collect 2f+1 prevotes within
//!    `ConsensusConfig::prevote_timeout` milliseconds.
//! 3. **PreCommit timeout**: The precommit step did not collect 2f+1 precommits within
//!    `ConsensusConfig::precommit_timeout` milliseconds.
//! 4. **Liveness stall**: The liveness monitor detects that >f validators are unresponsive,
//!    making quorum impossible (see `LivenessMonitor::is_stalled()`).
//!
//! On view-change: `round += 1`, proposer rotates per the round-robin rule, and a new
//! proposal is awaited. The locked value (if any) from the previous round is preserved
//! per Tendermint safety rules.
//!
//! See `VIEW_CHANGE_CONDITIONS` constant and `RoundTimer` for enforcement.
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
//! 3. **Height**: vote.height == local.height (stale past-height votes are discarded;
//!    future-height votes trigger catch-up sync and are discarded)
//! 4. **Round**: vote.round >= local.round (stale rounds are rejected; higher rounds are
//!    accepted to enable Tendermint round-skip — `on_prevote`/`on_precommit` advance to
//!    the peer's round so all nodes converge without waiting for timer cycles)
//! 5. **Vote type**: Only PreVote, PreCommit, and Commit are valid in BFT; Against is
//!    rejected unconditionally. All three accepted types are stored regardless of the
//!    local step — quorum safety is enforced by `maybe_finalize()` and `vote_pool`
//!    composite-key deduplication, not by step-gating at admission.
//!
//! This is enforced by `validate_remote_vote()` and `on_commit_vote()`.
//!
//! ## Proposal Admission (validate_incoming_proposal)
//!
//! Incoming proposals are validated before storage or prevote transition:
//!
//! 1. **Expected proposer**: Must match `compute_proposer_for_round(height, round)`
//! 2. **Proposal signature**: Valid Dilithium signature from the proposer's registered consensus key
//! 3. **Previous-hash continuity**: Links to local chain tip (when verifiable)
//! 4. **Block payload decode**: `block_data` bytes are decodable by the blockchain provider
//!
//! This is enforced by `validate_incoming_proposal()` in `on_proposal()`.
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
//! - **Threshold calculation**: 6667 basis points (66.67%) via `has_supermajority()`
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
//! ## Step-Independent Vote Storage
//!
//! Votes for the correct height and round are stored regardless of the local consensus
//! step. In an asynchronous network, nodes advance through Propose/PreVote/PreCommit/Commit
//! at different wall-clock times. Step-gating at admission would cause a node in the
//! Commit step to reject valid PreVotes from a peer still in PreVote, making quorum
//! impossible.
//!
//! Safety is preserved because:
//! - Quorum thresholds (2f+1) are enforced in `maybe_finalize()`, not at admission.
//! - Each validator gets exactly one vote per (H, R, type) via `vote_pool` composite-key
//!   deduplication.
//! - Commit votes can finalize immediately regardless of local step (CE-L1, CE-L2).
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
//!
//! ## Validator Rotation Rules and Maximum Churn
//!
//! Validator set changes are **epoch-gated**: all additions and removals take effect only at
//! epoch boundaries (every [`ConsensusConfig::epoch_length_blocks`] blocks).  This prevents
//! mid-epoch validator set instability and ensures every block within an epoch is signed by
//! the same set of validators.
//!
//! ### Maximum churn per epoch
//!
//! To preserve liveness and BFT safety across epoch transitions the number of validators
//! that may change in a single epoch is capped at **one-third of the current active set**:
//!
//! ```text
//! max_churn = floor(active_validators / 3)   (minimum: 1 to allow bootstrapping)
//! ```
//!
//! This is expressed as the constant [`MAX_CHURN_NUMERATOR`] / [`MAX_CHURN_DENOMINATOR`]
//! (= 1/3).  The invariant is enforced by [`ConsensusEngine::apply_epoch_boundary_changes`]
//! before any pending changes are applied.
//!
//! #### Rationale
//!
//! BFT consensus (PBFT/Tendermint) tolerates at most f = floor((n-1)/3) Byzantine validators.
//! If we allowed more than 1/3 of the validator set to be replaced in a single epoch, an
//! adversary could flood the pending queue with registrations and rotate out enough honest
//! validators to break the 2/3 supermajority requirement.  Capping churn at 1/3 per epoch
//! ensures that, even if all incoming validators are adversarial, the existing honest majority
//! is preserved across the transition.
//!
//! #### Rotation priority
//!
//! When the pending change queue contains more changes than the churn budget allows, removals
//! are processed **before** additions (to preserve network safety over growth), and remaining
//! changes are deferred to the following epoch.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lib_crypto::{Hash, KeyPair};
use lib_identity::IdentityId;
use tokio::sync::mpsc;
use tokio::time::Sleep;

use crate::byzantine::ByzantineFaultDetector;
use crate::dao::dao_types::{DaoExecutionAction, DaoProposal};
use crate::dao::dao_types::{GovernanceParameterUpdate, GovernanceParameterValue};
use crate::dao::DaoEngine;
use crate::invariants::{check_invariant, ConsensusInvariant, ConsensusState as InvariantState};
use crate::rewards::RewardCalculator;
use crate::types::*;
use crate::validators::validator_manager::ValidatorInfo as ValidatorInfoTrait;
use crate::validators::ValidatorManager;
use crate::{ConsensusError, ConsensusResult};

// ---------------------------------------------------------------------------
// Validator rotation / churn constants
// ---------------------------------------------------------------------------

/// Numerator of the maximum-churn fraction per epoch.
///
/// At most `MAX_CHURN_NUMERATOR / MAX_CHURN_DENOMINATOR` of the current active
/// validator set may change (additions + removals combined) in a single epoch
/// transition.  Together with [`MAX_CHURN_DENOMINATOR`] this expresses the
/// rule: **at most 1/3 of validators can change per epoch**.
///
/// See the module-level documentation for the full rationale.
pub const MAX_CHURN_NUMERATOR: usize = 1;

/// Denominator of the maximum-churn fraction per epoch (see [`MAX_CHURN_NUMERATOR`]).
pub const MAX_CHURN_DENOMINATOR: usize = 3;

mod liveness;
mod network;
mod proofs;
mod state_machine;
mod storage;
mod validation;

pub use state_machine::ConsensusAuditLog;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Consensus Algorithm Constants (closes #964)
// ---------------------------------------------------------------------------

/// Consensus wire-protocol version.
///
/// Proposals and votes are signed over domain-tagged envelopes that include
/// this version.  Nodes on different protocol versions will deterministically
/// reject each other's proposals/votes (signature mismatch) rather than
/// silently stalling consensus.
///
/// Bump this constant whenever the signed envelope format changes (e.g. new
/// fields bound into the signature, domain tag changes, serialization order).
///
/// History:
///   1 — initial: proposal ID/signature include round + domain tags
///       `ZHTP/PROPOSAL/ID/v1` and `ZHTP/PROPOSAL/SIG/v1`
pub const CONSENSUS_PROTOCOL_VERSION: u32 = 1;

/// Human-readable name of the consensus algorithm variant implemented here.
///
/// This engine implements a Tendermint-like BFT protocol as described in
/// "The latest gossip on BFT consensus" (Buchman et al., 2018).
///
/// Invariant: Any modification to the core voting/commit logic must be
/// accompanied by an update to this constant and the module-level documentation.
pub const CONSENSUS_ALGORITHM: &str = "Tendermint-like BFT";

/// Leader rotation rule in effect for this consensus engine.
///
/// The proposer for (height, round) is selected as:
///   `sorted_validators[(height + round) % num_validators]`
///
/// This is a deterministic round-robin rotation keyed by block height, ensuring
/// all validators get equal proposer opportunities over time.
pub const LEADER_ROTATION_RULE: &str =
    "round-robin by height: proposer = validators[(height + round) % n]";

/// Human-readable description of view-change trigger conditions.
///
/// A view-change (round increment) is triggered by ANY of:
/// 1. Proposal timeout (propose_timeout_ms exceeded with no valid proposal)
/// 2. PreVote timeout (prevote_timeout_ms exceeded with no 2f+1 prevotes)
/// 3. PreCommit timeout (precommit_timeout_ms exceeded with no 2f+1 precommits)
/// 4. Liveness stall (>f validators unresponsive, quorum mathematically impossible)
pub const VIEW_CHANGE_CONDITIONS: &str =
    "proposal_timeout | prevote_timeout | precommit_timeout | liveness_stall(>f_unresponsive)";

/// Minimum number of validators required for BFT consensus mode.
///
/// Below this threshold, the system operates in bootstrap/single-node mode.
/// This is a compile-time constant enforcing the BFT minimum: n >= 3 allows
/// BFT consensus (2f+1 quorum). At n=3, f=0 — no Byzantine fault tolerance,
/// but the protocol still requires unanimity (3 of 3 commits).
///
/// Invariant: Must equal `crate::types::MIN_BFT_VALIDATORS`.
pub const BFT_MIN_VALIDATORS: usize = 3;

// Compile-time assertion: BFT_MIN_VALIDATORS must equal crate::types::MIN_BFT_VALIDATORS.
// If this fails, the constant above is out of sync with the types module.
const _: () = assert!(
    BFT_MIN_VALIDATORS == crate::types::MIN_BFT_VALIDATORS,
    "BFT_MIN_VALIDATORS (consensus engine) must equal MIN_BFT_VALIDATORS (types module)"
);

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
            // Commit: brief broadcast window after 2/3+1 precommits — reuse precommit timeout.
            // NewRound: full proposal timeout to give the new proposer time to broadcast.
            // Both are derived from ConsensusConfig; add separate config knobs if operators
            // need independent tuning for these phases.
            ConsensusStep::Commit => self.precommit_timeout,
            ConsensusStep::NewRound => self.proposal_timeout,
        };
        tokio::time::sleep(duration)
    }
}

/// Check BFT supermajority (2/3+1 quorum).
///
/// Delegates to `lib_types::consensus::threshold::has_supermajority` which
/// uses basis-point arithmetic (6667 bps = 66.67%) instead of raw `>=`
/// comparisons.  This eliminates the risk of off-by-one operator mistakes
/// in consensus-critical threshold checks.
///
/// **Invariant**: Supermajority requires identical votes, not aggregate counts.
/// A supermajority on a proposal means 2/3+1 validators agree on ALL aspects:
/// - Same height
/// - Same round
/// - Same proposal/block hash
/// - Same vote type (PreVote or PreCommit)
fn check_supermajority(matching_votes: u64, total_validators: u64) -> bool {
    lib_types::consensus::threshold::has_supermajority(matching_votes, total_validators)
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

/// All fields required to register a new validator at an upcoming epoch boundary.
///
/// Queued by `queue_validator_add` and consumed by `apply_epoch_boundary_changes`.
#[derive(Debug, Clone)]
struct PendingValidatorAdd {
    identity: IdentityId,
    stake: u64,
    storage_capacity: u64,
    /// BFT vote-signing key (Dilithium5, hot). Must differ from networking_key and rewards_key.
    consensus_key: [u8; 2592],
    /// P2P transport identity key (Ed25519/X25519, hot). Must differ from consensus_key and rewards_key.
    networking_key: Vec<u8>,
    /// Rewards wallet public key (cold-capable). Must differ from consensus_key and networking_key.
    rewards_key: Vec<u8>,
    commission_rate: u8,
}

/// A single pending mutation to the active validator set.
///
/// Changes are enqueued mid-epoch and applied atomically at the next epoch boundary,
/// subject to the max-churn cap (`MAX_CHURN_NUMERATOR / MAX_CHURN_DENOMINATOR`).
/// Removals are processed before additions when the churn budget is tight.
#[derive(Debug, Clone)]
enum ValidatorSetChange {
    Add(PendingValidatorAdd),
    Remove(IdentityId),
}

/// A `ValidatorSetChange` paired with the epoch boundary height at which it takes effect.
///
/// `effective_height` is always a multiple of `epoch_length_blocks` and is computed
/// by `next_epoch_start` at the time the change is queued.
#[derive(Debug, Clone)]
struct PendingValidatorChange {
    effective_height: u64,
    change: ValidatorSetChange,
}

/// A scheduled update to `ConsensusConfig::epoch_length_blocks`.
///
/// Applied at `effective_height` (the next epoch boundary after the governance vote),
/// replacing the current epoch length for all subsequent epoch calculations.
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
    /// Fee collector for fee collection integration
    ///
    /// Implements the FeeCollector trait for collecting and distributing fees
    /// during block finalization. Uses Arc<Mutex<>> for thread-safe access.
    fee_router: Option<std::sync::Arc<std::sync::Mutex<dyn FeeCollector>>>,
    /// Message broadcaster for network distribution
    ///
    /// Invariant CE-ENG-1: ConsensusEngine never constructs, configures, or inspects
    /// the broadcaster. It only calls it.
    broadcaster: Arc<dyn MessageBroadcaster>,
    /// Message receiver from network layer (Gap 4)
    message_rx: Option<mpsc::Receiver<ValidatorMessage>>,
    /// Optional event sender for liveness transitions
    liveness_event_tx: Option<mpsc::UnboundedSender<ConsensusEvent>>,
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
    /// Blockchain provider for block production (injected by runtime)
    blockchain_provider: Option<Arc<dyn crate::types::ConsensusBlockchainProvider>>,
    /// Block commit callback for finalizing blocks to blockchain storage
    ///
    /// When BFT consensus achieves 2/3+1 commit votes, this callback commits
    /// the finalized block to the actual blockchain storage layer.
    block_commit_callback: Option<Arc<dyn crate::types::BlockCommitCallback>>,
    /// Catch-up sync trigger for height-divergence recovery.
    ///
    /// Called when consensus receives a vote for a height > local consensus height,
    /// indicating that the local blockchain is behind peer nodes.  The trigger
    /// fires a background block-download task in the runtime layer.
    catch_up_sync_trigger: Option<Arc<dyn crate::types::CatchUpSyncTrigger>>,
    /// Unix timestamp (seconds) when this consensus engine instance was created.
    /// Used to compute node uptime for work proofs.
    engine_start_time: u64,
    /// Receiver for validator set updates from the runtime.
    /// The consensus loop checks this between iterations and applies updates
    /// without requiring direct engine access from external tasks.
    validator_update_rx: Option<tokio::sync::mpsc::Receiver<ValidatorSetUpdate>>,
    /// Shared atomic tracking the height BFT consensus is actively working on.
    /// Catch-up sync reads this to avoid writing blocks that BFT will finalize.
    /// Updated at the start of each consensus round.
    bft_active_height: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// Validator set update message sent from the runtime to the consensus loop.
///
/// Each entry provides the validator's identity, stake, and consensus key:
/// `(identity_id, stake, consensus_key)`. The engine constructs internal
/// `Validator` instances from this data.
pub struct ValidatorSetUpdate {
    pub entries: Vec<ValidatorUpdateEntry>,
    pub local_identity: Option<IdentityId>,
    pub local_keypair: Option<lib_crypto::KeyPair>,
}

/// Single validator entry for a set update.
pub struct ValidatorUpdateEntry {
    pub identity_id: IdentityId,
    pub stake: u64,
    pub consensus_key: [u8; 2592],
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
            // REMOVED: Wall-clock start_time (nondeterministic)
            // Use deterministic value based on height for consensus ordering
            start_time: 0,
            proposer: None,
            proposals: Vec::new(),
            votes: HashMap::new(),
            timed_out: false,
            locked_proposal: None,
            valid_proposal: None,
        };

        let round_timer = RoundTimer::new(&config);

        let engine_start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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
            fee_router: None,
            broadcaster,
            message_rx: None,
            liveness_event_tx: None,
            round_timer,
            heartbeat_tracker: crate::network::HeartbeatTracker::new(Duration::from_secs(10)),
            heartbeat_interval: None,
            liveness_monitor: crate::network::LivenessMonitor::new(),
            liveness_check_interval: None,
            validator_keypair: None,
            storage_proof_provider: None,
            blockchain_provider: None,
            block_commit_callback: None,
            catch_up_sync_trigger: None,
            engine_start_time,
            validator_update_rx: None,
            bft_active_height: None,
        })
    }

    /// Set the message receiver (from network layer)
    pub fn set_message_receiver(&mut self, rx: mpsc::Receiver<ValidatorMessage>) {
        self.message_rx = Some(rx);
    }

    /// Set the validator update receiver. The consensus loop processes updates
    /// between iterations without requiring direct engine access.
    pub fn set_validator_update_receiver(
        &mut self,
        rx: tokio::sync::mpsc::Receiver<ValidatorSetUpdate>,
    ) {
        self.validator_update_rx = Some(rx);
    }

    /// Set the shared BFT active height atomic.
    /// Catch-up sync reads this to avoid racing with BFT block commits.
    pub fn set_bft_active_height(&mut self, height: Arc<std::sync::atomic::AtomicU64>) {
        self.bft_active_height = Some(height);
    }

    /// Set liveness event sender for monitoring/alert bridges.
    pub fn set_liveness_event_sender(&mut self, tx: mpsc::UnboundedSender<ConsensusEvent>) {
        self.liveness_event_tx = Some(tx);
    }

    /// Set blockchain provider for block production
    ///
    /// The blockchain provider gives the consensus engine access to:
    /// - Latest block hash (for chain continuity in proposals)
    /// - Pending transactions (for block content)
    /// - Current blockchain height (for validation)
    pub fn set_blockchain_provider(
        &mut self,
        provider: Arc<dyn crate::types::ConsensusBlockchainProvider>,
    ) {
        self.blockchain_provider = Some(provider);
        tracing::info!("📦 Blockchain provider connected to consensus engine");
    }

    /// Set block commit callback for finalizing blocks to blockchain storage
    ///
    /// When BFT consensus achieves supermajority (2/3+1) commit votes,
    /// this callback is invoked to commit the finalized block to storage.
    ///
    /// This separates consensus finalization (determining WHEN) from
    /// block storage (determining HOW), maintaining clean layer separation.
    pub fn set_block_commit_callback(
        &mut self,
        callback: Arc<dyn crate::types::BlockCommitCallback>,
    ) {
        self.block_commit_callback = Some(callback);
        tracing::info!("🔗 Block commit callback connected to consensus engine");
    }

    /// Set the catch-up sync trigger for height-divergence recovery.
    ///
    /// When the consensus engine detects that a remote peer is voting at a
    /// higher block height than the local chain, it calls
    /// `trigger.trigger(our_blockchain_height)` so the runtime can schedule
    /// a background block-download task.
    pub fn set_catch_up_sync_trigger(
        &mut self,
        trigger: Arc<dyn crate::types::CatchUpSyncTrigger>,
    ) {
        self.catch_up_sync_trigger = Some(trigger);
        tracing::info!("🔄 Catch-up sync trigger connected to consensus engine");
    }

    /// Synchronize consensus engine height with blockchain
    ///
    /// Called before starting the consensus loop to ensure the engine
    /// starts proposing at the correct height (blockchain_height + 1).
    ///
    /// This is critical for mode transitions:
    /// - Bootstrap mode produces blocks directly to blockchain
    /// - When switching to BFT mode, consensus must continue from the correct height
    pub async fn sync_height_with_blockchain(&mut self) -> ConsensusResult<()> {
        if let Some(ref provider) = self.blockchain_provider {
            match provider.get_blockchain_height().await {
                Ok(blockchain_height) => {
                    let old_height = self.current_round.height;
                    // Consensus proposes for next block, so height = blockchain_height + 1.
                    // If blockchain is at 0 (no blocks yet), start at height 1.
                    self.current_round.height = if blockchain_height == 0 {
                        1
                    } else {
                        blockchain_height + 1
                    };
                    let new_height = self.current_round.height;

                    // BFT-J-1015: enforce monotonic height invariant on sync.
                    // Only MonotonicHeight and NoFork are checked here — QuorumRequired
                    // and FinalityIrreversible do not apply to a sync operation.
                    // Skip when height is unchanged (already in sync with blockchain).
                    //
                    // Note on NoFork: fork_detected is always false here because this
                    // function runs before the consensus loop starts — no commits have
                    // been made at new_height yet, so a conflicting commit cannot exist.
                    // This makes the NoFork check vacuously true at this site. Real fork
                    // detection at sync time would require ConsensusBlockchainProvider to
                    // expose a method for checking conflicting commits at a given height,
                    // which it does not currently provide. If that capability is added,
                    // fork_detected should be populated from the provider response here.
                    if new_height != old_height {
                        let state = InvariantState {
                            current_height: new_height,
                            previous_height: if old_height == 0 {
                                None
                            } else {
                                Some(old_height)
                            },
                            votes_received: 0,
                            total_validators: self.validator_manager.get_active_validators().len()
                                as u64,
                            fork_detected: false, // see note above
                            reorg_detected: false,
                        };
                        for invariant in &[
                            ConsensusInvariant::MonotonicHeight,
                            ConsensusInvariant::NoFork,
                        ] {
                            if let Err(msg) = check_invariant(invariant, &state) {
                                tracing::error!("Height sync invariant violated: {}", msg);
                                return Err(ConsensusError::ValidatorError(msg));
                            }
                        }
                    }

                    tracing::info!(
                        "📊 Consensus height synced: {} → {} (blockchain at {})",
                        old_height,
                        self.current_round.height,
                        blockchain_height
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to sync consensus height with blockchain: {} - using current height {}",
                        e,
                        self.current_round.height
                    );
                    Ok(()) // Non-fatal, continue with current height
                }
            }
        } else {
            tracing::debug!(
                "No blockchain provider - consensus height unchanged at {}",
                self.current_round.height
            );
            Ok(())
        }
    }

    /// Check if BFT consensus mode is active (>= 3 validators)
    ///
    /// Returns true if there are enough validators for BFT consensus.
    /// In bootstrap mode (< 3 validators), the mining loop handles block production directly.
    ///
    /// # Invariant
    ///
    /// BFT mode requires at least `BFT_MIN_VALIDATORS` (= 3) validators. This matches
    /// `crate::types::MIN_BFT_VALIDATORS`. The compile-time assertion in the module
    /// ensures these two constants stay in sync.
    pub fn is_bft_mode_active(&self) -> bool {
        let validator_count = self.validator_manager.get_active_validators().len();
        // Runtime assertion: BFT_MIN_VALIDATORS must match the types-module constant.
        debug_assert_eq!(
            BFT_MIN_VALIDATORS,
            crate::types::MIN_BFT_VALIDATORS,
            "BFT_MIN_VALIDATORS and MIN_BFT_VALIDATORS are out of sync"
        );
        validator_count >= crate::types::MIN_BFT_VALIDATORS
    }

    /// Compute the proposer (leader) for a given (height, round) using round-robin
    /// rotation over the **frozen validator snapshot** for that height.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// proposer_index = (height + round as u64) % num_validators
    /// proposer       = sorted_snapshot_validators[proposer_index]
    /// ```
    ///
    /// The snapshot is sorted by identity ID bytes for determinism. This guarantees
    /// every node independently computes the same proposer for the same (height, round),
    /// regardless of whether the live `validator_manager` set has changed since the
    /// snapshot was sealed.
    ///
    /// Falls back to the live `validator_manager` if no snapshot exists for the
    /// requested height (e.g. during bootstrap before the first snapshot).
    ///
    /// # Invariant
    ///
    /// This implements `LEADER_ROTATION_RULE`. Any change to leader selection logic
    /// must update that constant and the module-level documentation.
    pub fn compute_proposer_for_round(&self, height: u64, round: u32) -> Option<IdentityId> {
        if let Some(snapshot) = self.validator_set_for_height(height) {
            if snapshot.is_empty() {
                return None;
            }
            let mut sorted: Vec<_> = snapshot.iter().cloned().collect();
            sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let index = ((height + round as u64) % sorted.len() as u64) as usize;
            return Some(sorted[index].clone());
        }

        // Fallback: no snapshot yet (bootstrap). Use live set.
        tracing::debug!(
            "No validator snapshot for height {} — falling back to live set for proposer selection",
            height,
        );
        self.validator_manager
            .select_proposer(height, round)
            .map(|v| v.identity.clone())
    }

    /// Get current validator count
    pub fn get_validator_count(&self) -> usize {
        self.validator_manager.get_active_validators().len()
    }

    /// Set fee collector for fee collection integration
    ///
    /// Allows the consensus engine to collect and distribute fees at block finalization.
    /// The fee collector must implement the FeeCollector trait.
    ///
    /// # Arguments
    /// * `fee_collector` - Implementation of FeeCollector trait (e.g., FeeRouter from lib-blockchain)
    pub fn set_fee_router<T: FeeCollector + 'static>(&mut self, fee_collector: T) {
        self.fee_router = Some(std::sync::Arc::new(std::sync::Mutex::new(fee_collector)));
    }

    /// Fire a `ConsensusEvent` to any attached liveness monitor / alert bridge.
    ///
    /// The send is best-effort (`let _ = tx.send(...)`): if no receiver is configured
    /// or the channel is closed, the event is silently dropped. Liveness monitoring
    /// is observability infrastructure and must never block or fail consensus progress.
    fn emit_liveness_event(&self, event: ConsensusEvent) {
        if let Some(tx) = &self.liveness_event_tx {
            let _ = tx.send(event);
        }
    }

    /// Set the local validator signing keypair (required for proposal/vote signing)
    pub fn set_validator_keypair(&mut self, keypair: KeyPair) -> ConsensusResult<()> {
        let identity = self.validator_identity.as_ref().ok_or_else(|| {
            ConsensusError::ValidatorError(
                "Cannot load validator signing keypair: local validator identity is not configured"
                    .to_string(),
            )
        })?;

        let validator = self
            .validator_manager
            .get_validator(identity)
            .ok_or_else(|| {
                ConsensusError::ValidatorError(
                    "Cannot load validator signing keypair: local validator is not registered"
                        .to_string(),
                )
            })?;

        if validator.consensus_key != keypair.public_key.dilithium_pk {
            return Err(ConsensusError::ValidatorError(
                "Validator keypair does not match registered consensus key".to_string(),
            ));
        }

        self.validator_keypair = Some(keypair);
        Ok(())
    }

    /// Sync validators from an external source (e.g. blockchain registry).
    ///
    /// This is the supported way for a node to converge its consensus validator set with
    /// the chain's validator registry without using the queued epoch-change path.
    pub fn sync_validators_from_list<T>(
        &mut self,
        validators: Vec<T>,
    ) -> anyhow::Result<(usize, usize)>
    where
        T: ValidatorInfoTrait,
    {
        self.validator_manager.sync_from_validator_list(validators)
    }

    /// Set the local validator identity (enables proposing/voting).
    ///
    /// The identity must already exist in the current validator set and must match the local
    /// validator keypair, if one is configured.
    pub fn set_local_validator_identity(&mut self, identity: IdentityId) -> ConsensusResult<()> {
        if self.validator_identity.is_some() {
            return Ok(());
        }

        let validator = self
            .validator_manager
            .get_validator(&identity)
            .ok_or_else(|| {
                ConsensusError::ValidatorError("Validator not found for local identity".to_string())
            })?;

        if let Some(kp) = &self.validator_keypair {
            if kp.public_key.dilithium_pk != validator.consensus_key {
                return Err(ConsensusError::ValidatorError(
                    "Local validator keypair does not match validator set consensus key"
                        .to_string(),
                ));
            }
        }

        self.validator_identity = Some(identity.clone());
        self.heartbeat_tracker.set_local_validator(identity);
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
        let params = proposal.execution_params().ok_or_else(|| {
            ConsensusError::ValidatorError("Proposal missing execution params".to_string())
        })?;
        let decoded = self
            .dao_engine
            .decode_execution_params(params)
            .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;

        match decoded.action {
            DaoExecutionAction::GovernanceParameterUpdate(update) => {
                self.apply_governance_update(&update)
            }
            // Mint/burn authorizations are not consensus parameter updates —
            // they are forwarded to the Treasury Kernel for execution.
            DaoExecutionAction::MintAuthorization(_) | DaoExecutionAction::BurnAuthorization(_) => {
                Err(ConsensusError::ValidatorError(
                    "Proposal is not a governance parameter update".to_string(),
                ))
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

    /// Register as a validator.
    ///
    /// # Key Separation
    ///
    /// Three distinct keys are required — `consensus_key`, `networking_key`, and
    /// `rewards_key` — each serving a separate security domain.  All three must be
    /// non-empty and pairwise distinct; this method returns an error if any two are
    /// equal.  See [`Validator`](crate::validators::Validator) for the full rationale.
    pub async fn register_validator(
        &mut self,
        identity: IdentityId,
        stake: u64,
        storage_capacity: u64,
        consensus_key: [u8; 2592],
        networking_key: Vec<u8>,
        rewards_key: Vec<u8>,
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
                    networking_key.clone(),
                    rewards_key.clone(),
                    commission_rate,
                )
                .map_err(|e| ConsensusError::ValidatorError(e.to_string()))?;
        } else {
            self.queue_validator_add(PendingValidatorAdd {
                identity: identity.clone(),
                stake,
                storage_capacity,
                consensus_key: consensus_key.clone(),
                networking_key: networking_key.clone(),
                rewards_key: rewards_key.clone(),
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
            "Registered validator {:?} with {} SOV stake{}",
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

    /// Return the configured epoch length in blocks, with a safe fallback.
    ///
    /// A zero `epoch_length_blocks` in the config is invalid; this method emits a
    /// warning and returns 1 rather than panicking to avoid divide-by-zero in callers.
    fn epoch_length_blocks(&self) -> u64 {
        if self.config.epoch_length_blocks == 0 {
            tracing::warn!("Epoch length blocks is zero; defaulting to 1");
            return 1;
        }
        self.config.epoch_length_blocks
    }

    /// Return `true` if `height` falls exactly on an epoch boundary.
    ///
    /// An epoch boundary is any height that is an exact multiple of `epoch_length_blocks`.
    /// Height 0 is considered a boundary, which triggers the genesis-epoch transition check.
    fn is_epoch_boundary(&self, height: u64) -> bool {
        height % self.epoch_length_blocks() == 0
    }

    /// Return the first block height of the epoch that follows the epoch containing `height`.
    ///
    /// Used to compute `effective_height` when queuing validator set changes and epoch length
    /// updates, ensuring they activate at the start of the next complete epoch.
    fn next_epoch_start(&self, height: u64) -> u64 {
        let epoch_len = self.epoch_length_blocks();
        ((height / epoch_len) + 1) * epoch_len
    }

    /// Enqueue a validator addition for the next epoch boundary.
    ///
    /// If the same identity has a pending *removal* in the queue, that removal is cancelled
    /// and this add supersedes it (re-registration of a departing validator). Duplicate adds
    /// for an already-active or already-pending-add validator are rejected.
    ///
    /// The change takes effect at `next_epoch_start(current_round.height)` and is subject
    /// to the churn cap in `apply_epoch_boundary_changes`.
    fn queue_validator_add(&mut self, pending: PendingValidatorAdd) -> ConsensusResult<()> {
        if self
            .validator_manager
            .get_validator(&pending.identity)
            .is_some()
        {
            return Err(ConsensusError::ValidatorError(
                "Validator already registered".to_string(),
            ));
        }

        let identity = pending.identity.clone();
        let mut removed_pending_remove = false;
        self.pending_validator_changes
            .retain(|entry| match &entry.change {
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
        self.pending_validator_changes
            .push_back(PendingValidatorChange {
                effective_height,
                change: ValidatorSetChange::Add(pending),
            });

        Ok(())
    }

    /// Enqueue a validator removal for the next epoch boundary.
    ///
    /// If the same identity has a pending *addition* in the queue (i.e. the validator has
    /// not yet activated), that add is cancelled and the method returns `Ok(())` without
    /// creating a removal entry — the validator never joined, so nothing needs to be removed.
    ///
    /// Returns an error if the identity is not currently active and has no pending add to cancel.
    fn queue_validator_removal(&mut self, identity: IdentityId) -> ConsensusResult<()> {
        let mut removed_pending_add = false;
        self.pending_validator_changes
            .retain(|entry| match &entry.change {
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
        self.pending_validator_changes
            .push_back(PendingValidatorChange {
                effective_height,
                change: ValidatorSetChange::Remove(identity),
            });

        Ok(())
    }

    /// Apply all pending validator-set changes that are scheduled for this epoch boundary.
    ///
    /// # Validator rotation rules
    ///
    /// Changes are only applied at epoch boundaries (`height % epoch_length == 0`).
    /// Within an epoch the validator set is frozen — no additions or removals occur.
    ///
    /// # Maximum churn enforcement (MAX_CHURN_NUMERATOR / MAX_CHURN_DENOMINATOR = 1/3)
    ///
    /// The total number of validator changes applied in a single epoch transition is
    /// capped at `floor(active_count / MAX_CHURN_DENOMINATOR * MAX_CHURN_NUMERATOR)`
    /// (minimum 1 to allow bootstrapping an empty set).
    ///
    /// **Priority**: removals are processed before additions so that safety is
    /// preserved when the budget is tight.  Changes that exceed the budget are
    /// deferred to the next epoch by keeping them in the pending queue.
    ///
    /// # Assertion
    ///
    /// After applying changes the function asserts that the number of applied changes
    /// does not exceed the computed budget.  This is a safety-critical invariant: if
    /// it fires, the pending-change queuing logic has a bug.
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

        // ---------------------------------------------------------------
        // Compute the maximum churn budget for this epoch transition.
        //
        // Budget = floor(active_count * MAX_CHURN_NUMERATOR / MAX_CHURN_DENOMINATOR)
        // with a floor of 1 so that a single-validator network can still grow.
        // ---------------------------------------------------------------
        let active_count = self.validator_manager.get_active_validators().len();
        let churn_budget = ((active_count * MAX_CHURN_NUMERATOR) / MAX_CHURN_DENOMINATOR).max(1);

        tracing::info!(
            "Epoch boundary at height {}: active_validators={}, churn_budget={}",
            height,
            active_count,
            churn_budget,
        );

        // Partition changes into those due at this height and those deferred.
        let mut due: Vec<_> = Vec::new();
        let mut deferred = VecDeque::new();
        while let Some(entry) = self.pending_validator_changes.pop_front() {
            if entry.effective_height == height {
                due.push(entry);
            } else {
                deferred.push_back(entry);
            }
        }

        // Apply removals first (safety over growth), then additions.
        let mut removals: Vec<_> = due
            .iter()
            .filter(|e| matches!(e.change, ValidatorSetChange::Remove(_)))
            .cloned()
            .collect();
        let mut additions: Vec<_> = due
            .iter()
            .filter(|e| matches!(e.change, ValidatorSetChange::Add(_)))
            .cloned()
            .collect();

        // Enforce churn cap: defer changes that exceed the budget back to next epoch.
        let removals_to_apply = removals.len().min(churn_budget);
        let additions_to_apply = additions
            .len()
            .min(churn_budget.saturating_sub(removals_to_apply));

        // Changes beyond the budget are deferred to the next epoch.
        let deferred_removals = removals.split_off(removals_to_apply);
        let deferred_additions = additions.split_off(additions_to_apply);

        let next_epoch = self.next_epoch_start(height);
        for mut entry in deferred_removals
            .into_iter()
            .chain(deferred_additions.into_iter())
        {
            tracing::info!(
                "Churn budget exceeded at height {}: deferring validator change to epoch at height {}",
                height,
                next_epoch,
            );
            entry.effective_height = next_epoch;
            deferred.push_back(entry);
        }

        self.pending_validator_changes = deferred;

        let mut applied_changes = 0usize;

        for entry in removals.into_iter().chain(additions.into_iter()) {
            match entry.change {
                ValidatorSetChange::Add(add) => {
                    if self
                        .validator_manager
                        .get_validator(&add.identity)
                        .is_none()
                    {
                        self.validator_manager
                            .register_validator(
                                add.identity.clone(),
                                add.stake,
                                add.storage_capacity,
                                add.consensus_key,
                                add.networking_key,
                                add.rewards_key,
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

        // INVARIANT: the number of applied changes must never exceed the churn budget.
        // If this assertion fires, the queuing logic has a bug.
        assert!(
            applied_changes <= churn_budget,
            "MAX CHURN VIOLATED at height {}: applied {} changes but budget is {} \
             (active_count={}, {}/{} rule).  This is a bug in apply_epoch_boundary_changes.",
            height,
            applied_changes,
            churn_budget,
            active_count,
            MAX_CHURN_NUMERATOR,
            MAX_CHURN_DENOMINATOR,
        );

        if applied_changes > 0 {
            tracing::info!(
                "Applied {} validator set change(s) at epoch boundary height {} \
                 (budget: {}, active after: {})",
                applied_changes,
                height,
                churn_budget,
                self.validator_manager.get_active_validators().len(),
            );
            let active_validators: Vec<_> = self
                .validator_manager
                .get_active_validators()
                .iter()
                .map(|v| v.identity.clone())
                .collect();
            self.liveness_monitor
                .update_validator_set(&active_validators);
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

    /// Snapshot validator membership for a specific height.
    ///
    /// **Write-once**: if a snapshot for this height already exists it is NOT
    /// overwritten.  This guarantees that once a height's validator committee
    /// is sealed, no runtime event (validator registration, mode transition,
    /// round-skip) can mutate it.  Membership checks via
    /// `is_validator_member` are therefore immutable for the lifetime of a
    /// height, which is required for BFT safety.
    ///
    /// New validators arriving mid-height are registered in the
    /// `validator_manager` (so they're included in _future_ snapshots) but do
    /// not retroactively join the current height's committee.
    pub(super) fn snapshot_validator_set(&mut self, height: u64) {
        // Write-once: do not overwrite an existing snapshot.
        if self
            .validator_set_history
            .iter()
            .any(|snapshot| snapshot.height == height)
        {
            tracing::debug!(
                "Validator snapshot for height {} already sealed — skipping re-snapshot",
                height,
            );
            return;
        }

        let validators: HashSet<IdentityId> = self
            .validator_manager
            .get_active_validators()
            .iter()
            .map(|v| v.identity.clone())
            .collect();

        self.validator_set_history
            .push_back(ValidatorSetSnapshot { height, validators });

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
