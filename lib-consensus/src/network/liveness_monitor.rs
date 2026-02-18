//! Consensus Liveness Monitor for Stall Detection
//!
//! # Overview
//!
//! This module provides a passive observer that detects when consensus has stalled
//! due to validator liveness failures. It monitors validator heartbeat timeouts and
//! emits `ConsensusStalled` events when quorum becomes impossible.
//!
//! # Liveness Thresholds (Explicit Invariants)
//!
//! All liveness thresholds are declared as named constants below. No magic numbers
//! should appear in monitoring logic; all behavior is derived from these constants.
//!
//! | Constant                       | Value | Meaning                                     |
//! |--------------------------------|-------|---------------------------------------------|
//! | `MAX_MISSED_BLOCKS`            | 100   | Missed blocks before liveness flag          |
//! | `ROUND_TIMEOUT_SECS`           | 30    | Seconds per consensus round before timeout  |
//! | `LIVENESS_JAIL_THRESHOLD`      | 500   | Missed blocks that trigger jailing          |
//! | `MAX_CONSECUTIVE_ROUND_TIMEOUTS` | 10  | Consecutive round timeouts before jail      |
//! | `HEARTBEAT_LIVENESS_TIMEOUT_SECS` | 30 | Seconds of silence before validator deemed offline |
//!
//! # Core Invariants
//!
//! ## Invariant 1: Timeouts are Observable Facts
//!
//! A validator is timed out if and only if `HeartbeatTracker.is_validator_alive()`
//! returns false. There is no inference, prediction, or heuristic. The monitor
//! observes heartbeat ages and reports what it sees.
//!
//! ## Invariant 2: >1/3 Unresponsive Implies No Progress
//!
//! In BFT consensus with n validators:
//! - Quorum requires 2n/3 + 1 validators
//! - If more than n/3 validators are unresponsive, quorum is impossible
//! - This is a mathematical fact, not a policy decision
//!
//! Example with 4 validators:
//! - Quorum = floor(8/3) + 1 = 3 validators
//! - If 2 validators time out, maximum responsive = 2
//! - 2 < 3, so quorum impossible → consensus is stalled
//!
//! ## Invariant 3: Liveness Detection is Independent Per Validator
//!
//! Each validator's timeout state is determined solely by its own heartbeat history.
//! There are no cross-validator dependencies, no aggregate scores, no reputation
//! weighting. If validator V hasn't sent a heartbeat in `HEARTBEAT_LIVENESS_TIMEOUT_SECS`
//! seconds, V is timed out. What other validators do is irrelevant.
//!
//! ## Invariant 4: Recovery is Evidence-Based
//!
//! A validator returns to responsive state when `HeartbeatTracker` receives a
//! valid heartbeat from that validator. There are no automatic timeouts, no
//! grace periods, no "probation" states. Heartbeat received = responsive.
//!
//! ## Invariant 5: Monitor Never Mutates Consensus State
//!
//! This monitor is **read-only** with respect to consensus:
//! - It does not advance rounds
//! - It does not skip proposers
//! - It does not evict validators
//! - It does not trigger slashing
//! - It does not modify validator weights
//! - It does not pause or resume consensus
//!
//! The monitor observes and reports. Higher-level components decide what to do.
//!
//! # Design Philosophy: "Boring and Truthful"
//!
//! This component is intentionally simple:
//! - No machine learning
//! - No predictions or forecasts
//! - No heuristics or tuning parameters (all thresholds are explicit named constants)
//! - No complex state machines
//! - No automatic recovery mechanisms
//!
//! It answers exactly one question: "Can consensus make progress given current
//! validator liveness?" If the answer is no, it says so. That's all.
//!
//! # Non-Scope (Explicitly Out of Scope)
//!
//! The following are **not** handled by this component:
//! - **Proposer skipping**: Deciding which validator proposes next
//! - **Round advancement**: Moving to the next round
//! - **Validator eviction**: Removing validators from the set
//! - **Slashing**: Penalizing validators for downtime
//! - **Automatic recovery**: Restarting consensus or triggering failover
//!
//! These concerns belong to higher-level components that will be implemented
//! in future tickets.

use std::collections::{HashMap, HashSet};
use lib_identity::IdentityId;

// =============================================================================
// CONSENSUS INVARIANT CHECKS — FAIL FAST ON VIOLATION (BFT-J, Issue #1015)
// =============================================================================

/// Enumeration of core BFT consensus safety invariants.
///
/// Each variant describes a property that MUST hold at all times during correct
/// consensus operation.  Violations indicate a safety or liveness bug that
/// requires immediate investigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusInvariant {
    /// No two valid commits exist at the same block height (no forks).
    NoFork,
    /// Committed block height is strictly monotonically increasing.
    MonotonicHeight,
    /// Every commit requires a quorum of ≥ 2/3 + 1 validators.
    QuorumRequired,
    /// Once a block is committed it cannot be reverted (irreversibility).
    FinalityIrreversible,
}

impl ConsensusInvariant {
    /// Returns a human-readable description of this invariant.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoFork => "no two commits may exist at the same height",
            Self::MonotonicHeight => "committed height must increase strictly monotonically",
            Self::QuorumRequired => "every commit requires ≥ 2/3+1 validator agreement",
            Self::FinalityIrreversible => "committed blocks are final and cannot be reverted",
        }
    }
}

/// Validates a single consensus invariant against the provided evidence.
///
/// Returns `Ok(())` if the invariant holds, or an `Err` with a descriptive
/// message if it is violated.
///
/// # Arguments
/// * `invariant` — the invariant to check.
/// * `holds` — caller-supplied boolean indicating whether the invariant holds.
///
/// # Errors
/// Returns `Err` when `holds` is `false`.
pub fn check_invariant(invariant: &ConsensusInvariant, holds: bool) -> Result<(), String> {
    if !holds {
        Err(format!(
            "consensus invariant violated [{:?}]: {}",
            invariant,
            invariant.description()
        ))
    } else {
        Ok(())
    }
}

/// Asserts all consensus invariants simultaneously.
///
/// **Fail-fast**: panics immediately if any invariant is violated.  A panic
/// here indicates a safety or liveness bug in the consensus implementation
/// and must halt the node to prevent further state corruption.
///
/// # Arguments
/// Each boolean argument corresponds to one invariant in declaration order:
/// `no_fork`, `monotonic_height`, `quorum_satisfied`, `finality_irreversible`.
///
/// # Panics
/// Panics with a descriptive message if any invariant is `false`.
pub fn assert_consensus_invariants(
    no_fork: bool,
    monotonic_height: bool,
    quorum_satisfied: bool,
    finality_irreversible: bool,
) {
    let checks = [
        (ConsensusInvariant::NoFork, no_fork),
        (ConsensusInvariant::MonotonicHeight, monotonic_height),
        (ConsensusInvariant::QuorumRequired, quorum_satisfied),
        (ConsensusInvariant::FinalityIrreversible, finality_irreversible),
    ];
    for (invariant, holds) in &checks {
        if !holds {
            panic!(
                "CONSENSUS SAFETY BUG — invariant violated [{:?}]: {}\n\
                 The node must halt to prevent further state corruption.",
                invariant,
                invariant.description()
            );
        }
    }
}

#[cfg(test)]
mod invariant_tests {
    use super::*;

    #[test]
    fn test_check_invariant_passes_when_true() {
        assert!(check_invariant(&ConsensusInvariant::NoFork, true).is_ok());
        assert!(check_invariant(&ConsensusInvariant::MonotonicHeight, true).is_ok());
        assert!(check_invariant(&ConsensusInvariant::QuorumRequired, true).is_ok());
        assert!(check_invariant(&ConsensusInvariant::FinalityIrreversible, true).is_ok());
    }

    #[test]
    fn test_check_invariant_fails_when_false() {
        let err = check_invariant(&ConsensusInvariant::NoFork, false);
        assert!(err.is_err());
        let msg = err.unwrap_err();
        assert!(msg.contains("NoFork"));
        assert!(msg.contains("no two commits may exist at the same height"));
    }

    #[test]
    fn test_assert_consensus_invariants_all_pass() {
        // Should not panic when all invariants hold
        assert_consensus_invariants(true, true, true, true);
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_assert_consensus_invariants_panics_on_fork() {
        assert_consensus_invariants(false, true, true, true);
    }
}

// =============================================================================
// LIVENESS THRESHOLD CONSTANTS
// =============================================================================

/// Maximum number of consecutive missed blocks before a validator is flagged
/// for liveness monitoring.
///
/// A "missed block" is counted when a validator fails to cast a vote (PreVote
/// or PreCommit) in a round where they were expected to participate.
///
/// After `MAX_MISSED_BLOCKS` consecutive misses, the validator is recorded as
/// having a liveness issue. After `LIVENESS_JAIL_THRESHOLD` misses, they are
/// jailed (see `LIVENESS_JAIL_THRESHOLD`).
///
/// # Invariant LIVE-INV-1
///
/// `MAX_MISSED_BLOCKS` must be less than `LIVENESS_JAIL_THRESHOLD`.
/// Blocks-before-flag must come before blocks-before-jail.
pub const MAX_MISSED_BLOCKS: u64 = 100;

/// Seconds allowed per consensus round before the round is declared timed out.
///
/// A consensus round consists of: Propose → PreVote → PreCommit → Commit.
/// If the round does not progress to the next step within `ROUND_TIMEOUT_SECS`
/// seconds, the timeout fires and the round is advanced.
///
/// At the default block time of 10 seconds, `ROUND_TIMEOUT_SECS = 30` allows
/// three full block times of latency before giving up on a round.
///
/// # Invariant LIVE-INV-2
///
/// `ROUND_TIMEOUT_SECS` must be at least 2× the target block time to allow
/// for normal network propagation delays. With block_time=10s, minimum is 20s.
pub const ROUND_TIMEOUT_SECS: u64 = 30;

/// Number of missed blocks that triggers validator jailing for liveness failure.
///
/// When a validator has missed `LIVENESS_JAIL_THRESHOLD` or more consecutive
/// blocks without casting a vote, they are jailed. The jail duration is
/// determined by the slashing policy (see `JAIL_DURATION_BLOCKS` in the
/// slashing module).
///
/// # Invariant LIVE-INV-3
///
/// `LIVENESS_JAIL_THRESHOLD` must be greater than `MAX_MISSED_BLOCKS`:
/// monitoring starts before jailing triggers.
pub const LIVENESS_JAIL_THRESHOLD: u64 = 500;

/// Maximum number of consecutive round timeouts before a validator is jailed.
///
/// A "round timeout" is counted when a validator fails to respond (vote or
/// propose) within `ROUND_TIMEOUT_SECS` in a round where they were expected
/// to participate.
///
/// This threshold is separate from `MAX_MISSED_BLOCKS` because round timeouts
/// are measured per-round while missed blocks are measured per-block.
pub const MAX_CONSECUTIVE_ROUND_TIMEOUTS: u32 = 10;

/// Seconds of heartbeat silence before a validator is considered offline.
///
/// The `HeartbeatTracker` uses this value as the default liveness timeout.
/// If a validator has not sent a heartbeat within this window, they are
/// considered non-responsive by the `LivenessMonitor`.
///
/// At `ROUND_TIMEOUT_SECS = 30` and `HEARTBEAT_LIVENESS_TIMEOUT_SECS = 30`,
/// a validator that misses ~1 round of heartbeats will be flagged as timed out.
///
/// # Invariant LIVE-INV-4
///
/// `HEARTBEAT_LIVENESS_TIMEOUT_SECS` must be at least `ROUND_TIMEOUT_SECS`
/// to prevent false positives during normal round timeouts.
pub const HEARTBEAT_LIVENESS_TIMEOUT_SECS: u64 = 30;

// Compile-time invariant: LIVE-INV-1
const _: () = assert!(
    MAX_MISSED_BLOCKS < LIVENESS_JAIL_THRESHOLD,
    "LIVE-INV-1: MAX_MISSED_BLOCKS must be less than LIVENESS_JAIL_THRESHOLD"
);


// Compile-time invariant: LIVE-INV-2 — round timeout must be at least 20s
const _: () = assert!(
    ROUND_TIMEOUT_SECS >= 20,
    "LIVE-INV-2: ROUND_TIMEOUT_SECS must be at least 20 seconds"
);

// Compile-time invariant: LIVE-INV-4 — heartbeat timeout must be at least round timeout
const _: () = assert!(
    HEARTBEAT_LIVENESS_TIMEOUT_SECS >= ROUND_TIMEOUT_SECS,
    "LIVE-INV-4: HEARTBEAT_LIVENESS_TIMEOUT_SECS must be >= ROUND_TIMEOUT_SECS"
);

/// Validator timeout state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutState {
    /// Validator is responsive (heartbeat within liveness_timeout)
    Responsive,
    /// Validator has timed out (no heartbeat within liveness_timeout)
    TimedOut,
}

/// Liveness monitor for detecting consensus stalls
///
/// Tracks per-validator timeout states and detects when >1/3 of validators
/// are unresponsive, which makes BFT quorum impossible.
#[derive(Debug, Clone)]
pub struct LivenessMonitor {
    /// Per-validator timeout state
    validator_states: HashMap<IdentityId, TimeoutState>,
    /// Last known stall state for transition detection
    last_stall_state: Option<HashSet<IdentityId>>,
    /// Stall threshold: floor(n/3) + 1
    pub stall_threshold: usize,
    /// Total active validators
    pub total_validators: usize,
}

impl LivenessMonitor {
    /// Create a new liveness monitor
    ///
    /// Initially, the validator set is empty. Call `update_validator_set()`
    /// before monitoring to initialize.
    ///
    /// Note: stall_threshold is initialized to usize::MAX (effectively "never stall")
    /// as a sentinel. This prevents false stalls during initialization. Once
    /// update_validator_set() is called, the correct threshold is calculated.
    pub fn new() -> Self {
        Self {
            validator_states: HashMap::new(),
            last_stall_state: None,
            stall_threshold: usize::MAX, // Sentinel: prevents false stalls until initialized
            total_validators: 0,
        }
    }

    /// Update the active validator set
    ///
    /// This MUST be called whenever the validator set changes (validator joins/leaves).
    /// It recalculates the stall threshold and initializes state for new validators.
    ///
    /// # Arguments
    ///
    /// * `active_validators` - Current set of active validator identities
    ///
    /// # Behavior
    ///
    /// - New validators default to Responsive state (innocent until proven timed out)
    /// - Removed validators are deleted from state map
    /// - Stall threshold is recalculated: floor(n/3) + 1
    pub fn update_validator_set(&mut self, active_validators: &[IdentityId]) {
        let new_set: HashSet<_> = active_validators.iter().cloned().collect();

        // Remove validators no longer in the set
        self.validator_states.retain(|id, _| new_set.contains(id));

        // Add new validators with Responsive default
        for validator_id in active_validators {
            self.validator_states
                .entry(validator_id.clone())
                .or_insert(TimeoutState::Responsive);
        }

        // Update cached values
        self.total_validators = active_validators.len();
        self.stall_threshold = (self.total_validators / 3) + 1;

        tracing::debug!(
            "LivenessMonitor: Updated validator set (total: {}, stall_threshold: {})",
            self.total_validators,
            self.stall_threshold
        );
    }

    /// Check validator timeouts against HeartbeatTracker
    ///
    /// This is the core monitoring function. It queries HeartbeatTracker for each
    /// validator's liveness status and updates internal state accordingly.
    ///
    /// # Arguments
    ///
    /// * `heartbeat_tracker` - Reference to HeartbeatTracker for liveness queries
    ///
    /// # Returns
    ///
    /// True if any validator state changed (responsive → timed out or vice versa)
    ///
    /// # Determinism Note
    ///
    /// This function is deterministic given:
    /// 1. The current validator set (set via update_validator_set)
    /// 2. HeartbeatTracker's state (heartbeat timestamps)
    /// 3. Current wall-clock time (used by HeartbeatTracker.is_validator_alive)
    pub fn watch_timeouts(&mut self, heartbeat_tracker: &crate::network::HeartbeatTracker) -> bool {
        let mut state_changed = false;

        for (validator_id, current_state) in self.validator_states.iter_mut() {
            let is_alive = heartbeat_tracker.is_validator_alive(validator_id);
            let new_state = if is_alive {
                TimeoutState::Responsive
            } else {
                TimeoutState::TimedOut
            };

            if *current_state != new_state {
                tracing::debug!(
                    "LivenessMonitor: Validator {} changed from {:?} to {:?}",
                    validator_id,
                    current_state,
                    new_state
                );
                *current_state = new_state;
                state_changed = true;
            }
        }

        state_changed
    }

    /// Mark a validator as timed out
    ///
    /// This is an alternative to `watch_timeouts()` for cases where timeout
    /// is detected externally. Idempotent: calling multiple times has no effect.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to mark as timed out
    ///
    /// # Returns
    ///
    /// True if state changed (was Responsive, now TimedOut), false if already TimedOut
    pub fn report_timeout(&mut self, validator_id: &IdentityId) -> bool {
        match self.validator_states.get_mut(validator_id) {
            Some(state) if *state == TimeoutState::Responsive => {
                *state = TimeoutState::TimedOut;
                tracing::warn!(
                    "LivenessMonitor: Validator {} marked as timed out",
                    validator_id
                );
                true
            }
            Some(_) => false, // Already timed out
            None => {
                // Unknown validator - add it as timed out
                self.validator_states
                    .insert(validator_id.clone(), TimeoutState::TimedOut);
                tracing::warn!(
                    "LivenessMonitor: Unknown validator {} marked as timed out",
                    validator_id
                );
                true
            }
        }
    }

    /// Mark a validator as responsive
    ///
    /// Called when a valid heartbeat is received. Idempotent: calling multiple
    /// times has no effect.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to mark as responsive
    ///
    /// # Returns
    ///
    /// True if state changed (was TimedOut, now Responsive), false if already Responsive
    pub fn mark_responsive(&mut self, validator_id: &IdentityId) -> bool {
        match self.validator_states.get_mut(validator_id) {
            Some(state) if *state == TimeoutState::TimedOut => {
                *state = TimeoutState::Responsive;
                tracing::info!(
                    "LivenessMonitor: Validator {} recovered (now responsive)",
                    validator_id
                );
                true
            }
            Some(_) => false, // Already responsive
            None => {
                // Unknown validator - add it as responsive
                self.validator_states
                    .insert(validator_id.clone(), TimeoutState::Responsive);
                tracing::debug!(
                    "LivenessMonitor: Unknown validator {} marked as responsive",
                    validator_id
                );
                true
            }
        }
    }

    /// Get the set of currently timed-out validators
    ///
    /// # Returns
    ///
    /// Vector of validator IDs that are currently in TimedOut state
    pub fn timed_out_validators(&self) -> Vec<IdentityId> {
        self.validator_states
            .iter()
            .filter(|(_, state)| **state == TimeoutState::TimedOut)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Check if consensus is currently stalled
    ///
    /// # Returns
    ///
    /// True if number of timed-out validators exceeds floor(total/3)
    ///
    /// # BFT Math
    ///
    /// With n validators, BFT consensus requires 2n/3 + 1 for quorum.
    /// If more than n/3 validators are unresponsive, quorum is impossible:
    /// - Total validators: n
    /// - Timed out: t >= floor(n/3) + 1
    /// - Maximum responsive: n - t <= n - (floor(n/3) + 1) = floor(2n/3) < 2n/3 + 1
    /// - Cannot reach quorum
    pub fn is_stalled(&self) -> bool {
        let timed_out_count = self.validator_states
            .values()
            .filter(|state| **state == TimeoutState::TimedOut)
            .count();

        timed_out_count >= self.stall_threshold
    }

    /// Get stall state transition for event emission
    ///
    /// # Returns
    ///
    /// - `Some((true, timed_out_set))` if stalled NOW but wasn't before
    /// - `Some((false, empty_set))` if not stalled NOW but was before
    /// - `None` if no transition occurred
    ///
    /// This enables efficient event emission: only emit events on transitions.
    pub fn check_stall_transition(&mut self) -> Option<(bool, HashSet<IdentityId>)> {
        let currently_stalled = self.is_stalled();
        let timed_out_set: HashSet<_> = self.timed_out_validators().into_iter().collect();

        match (&self.last_stall_state, currently_stalled) {
            (None, true) => {
                // Transition: not stalled → stalled
                self.last_stall_state = Some(timed_out_set.clone());
                Some((true, timed_out_set))
            }
            (Some(_), false) => {
                // Transition: stalled → not stalled
                self.last_stall_state = None;
                Some((false, HashSet::new()))
            }
            (Some(old_set), true) if old_set != &timed_out_set => {
                // Still stalled, but different set of validators
                self.last_stall_state = Some(timed_out_set.clone());
                Some((true, timed_out_set))
            }
            _ => None, // No transition
        }
    }
}

impl Default for LivenessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_timeout_detection() {
        let mut monitor = LivenessMonitor::new();
        let validators = vec![
            IdentityId::from_bytes(&[1u8; 32]),
            IdentityId::from_bytes(&[2u8; 32]),
            IdentityId::from_bytes(&[3u8; 32]),
            IdentityId::from_bytes(&[4u8; 32]),
        ];
        monitor.update_validator_set(&validators);

        // Initially, all responsive
        assert_eq!(monitor.timed_out_validators().len(), 0);
        assert!(!monitor.is_stalled());

        // Mark one validator timed out
        assert!(monitor.report_timeout(&validators[0]));
        assert_eq!(monitor.timed_out_validators().len(), 1);
        assert!(!monitor.is_stalled()); // 1 < threshold 2

        // Mark second validator timed out - should trigger stall
        assert!(monitor.report_timeout(&validators[1]));
        assert_eq!(monitor.timed_out_validators().len(), 2);
        assert!(monitor.is_stalled()); // 2 >= threshold 2
    }

    #[test]
    fn test_idempotent_timeout_marking() {
        let mut monitor = LivenessMonitor::new();
        let validator = IdentityId::from_bytes(&[1u8; 32]);
        monitor.update_validator_set(&vec![validator.clone()]);

        // First call returns true (state changed)
        assert!(monitor.report_timeout(&validator));

        // Second call returns false (already timed out)
        assert!(!monitor.report_timeout(&validator));

        // Mark responsive
        assert!(monitor.mark_responsive(&validator));

        // Second responsive call returns false
        assert!(!monitor.mark_responsive(&validator));
    }

    #[test]
    fn test_stall_threshold_calculation() {
        let mut monitor = LivenessMonitor::new();

        // 4 validators: threshold = floor(4/3) + 1 = 2
        let validators: Vec<_> = (0..4)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators);
        assert_eq!(monitor.stall_threshold, 2);

        // 7 validators: threshold = floor(7/3) + 1 = 3
        let validators: Vec<_> = (0..7)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators);
        assert_eq!(monitor.stall_threshold, 3);

        // 10 validators: threshold = floor(10/3) + 1 = 4
        let validators: Vec<_> = (0..10)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators);
        assert_eq!(monitor.stall_threshold, 4);
    }

    #[test]
    fn test_stall_state_transitions() {
        let mut monitor = LivenessMonitor::new();
        let validators: Vec<_> = (0..4)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators);

        // No transition initially
        assert!(monitor.check_stall_transition().is_none());

        // Mark 2 validators timed out - should transition to stalled
        monitor.report_timeout(&validators[0]);
        monitor.report_timeout(&validators[1]);

        match monitor.check_stall_transition() {
            Some((true, set)) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains(&validators[0]));
                assert!(set.contains(&validators[1]));
            }
            _ => panic!("Expected stalled transition"),
        }

        // No transition on second check (still stalled)
        assert!(monitor.check_stall_transition().is_none());

        // Recover one validator - should transition to not stalled
        monitor.mark_responsive(&validators[0]);

        match monitor.check_stall_transition() {
            Some((false, set)) => assert!(set.is_empty()),
            _ => panic!("Expected recovery transition"),
        }
    }

    #[test]
    fn test_validator_set_updates() {
        let mut monitor = LivenessMonitor::new();
        let validators_v1: Vec<_> = (0..4)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators_v1);

        // Mark one validator timed out
        monitor.report_timeout(&validators_v1[0]);
        assert_eq!(monitor.timed_out_validators().len(), 1);

        // Update set to remove that validator and add new ones
        let validators_v2: Vec<_> = (2..6)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators_v2);

        // Old timed-out validator should be removed
        assert_eq!(monitor.timed_out_validators().len(), 0);

        // New validators should default to responsive
        assert!(!monitor.is_stalled());
    }

    #[test]
    fn test_edge_case_exactly_one_third() {
        let mut monitor = LivenessMonitor::new();
        let validators: Vec<_> = (0..4)
            .map(|i| IdentityId::from_bytes(&[i; 32]))
            .collect();
        monitor.update_validator_set(&validators);

        // With 4 validators, threshold = 2
        // Mark exactly 1 timed out - should NOT stall
        monitor.report_timeout(&validators[0]);
        assert!(!monitor.is_stalled());

        // Mark second timed out (threshold reached) - SHOULD stall
        monitor.report_timeout(&validators[1]);
        assert!(monitor.is_stalled());
    }

    #[test]
    fn test_zero_or_one_validator() {
        // Single validator case
        let mut monitor = LivenessMonitor::new();
        let validator = IdentityId::from_bytes(&[1u8; 32]);
        monitor.update_validator_set(&vec![validator.clone()]);

        // threshold = floor(1/3) + 1 = 1
        assert_eq!(monitor.stall_threshold, 1);

        // Single validator timeout = stalled
        monitor.report_timeout(&validator);
        assert!(monitor.is_stalled());

        // Recovery clears stall
        monitor.mark_responsive(&validator);
        assert!(!monitor.is_stalled());
    }

    // =========================================================================
    // THRESHOLD CONSTANT TESTS
    // =========================================================================

    #[test]
    fn test_constants_satisfy_live_inv1() {
        // LIVE-INV-1: MAX_MISSED_BLOCKS < LIVENESS_JAIL_THRESHOLD
        assert!(
            MAX_MISSED_BLOCKS < LIVENESS_JAIL_THRESHOLD,
            "LIVE-INV-1 violated: MAX_MISSED_BLOCKS ({}) must be < LIVENESS_JAIL_THRESHOLD ({})",
            MAX_MISSED_BLOCKS,
            LIVENESS_JAIL_THRESHOLD
        );
    }

    #[test]
    fn test_constants_satisfy_live_inv2() {
        // LIVE-INV-2: ROUND_TIMEOUT_SECS >= 20
        assert!(
            ROUND_TIMEOUT_SECS >= 20,
            "LIVE-INV-2 violated: ROUND_TIMEOUT_SECS ({}) must be >= 20",
            ROUND_TIMEOUT_SECS
        );
    }

    #[test]
    fn test_constants_satisfy_live_inv4() {
        // LIVE-INV-4: HEARTBEAT_LIVENESS_TIMEOUT_SECS >= ROUND_TIMEOUT_SECS
        assert!(
            HEARTBEAT_LIVENESS_TIMEOUT_SECS >= ROUND_TIMEOUT_SECS,
            "LIVE-INV-4 violated: HEARTBEAT_LIVENESS_TIMEOUT_SECS ({}) must be >= ROUND_TIMEOUT_SECS ({})",
            HEARTBEAT_LIVENESS_TIMEOUT_SECS,
            ROUND_TIMEOUT_SECS
        );
    }

    #[test]
    fn test_liveness_jail_threshold_is_reasonable() {
        // Threshold should be large enough to not trigger on transient outages
        assert!(LIVENESS_JAIL_THRESHOLD >= 100, "LIVENESS_JAIL_THRESHOLD too small");
        // But not so large that misbehaving validators go unpunished for hours
        assert!(LIVENESS_JAIL_THRESHOLD <= 10_000, "LIVENESS_JAIL_THRESHOLD too large");
    }

    #[test]
    fn test_max_missed_blocks_is_reasonable() {
        // Should be low enough to detect persistent downtime
        assert!(MAX_MISSED_BLOCKS >= 10, "MAX_MISSED_BLOCKS too small");
        // But not so low that transient issues trigger false positives
        assert!(MAX_MISSED_BLOCKS <= 1_000, "MAX_MISSED_BLOCKS too large");
    }

    #[test]
    fn test_liveness_constants_known_values() {
        // Known value check — if this changes, the test flags it for review
        assert_eq!(MAX_MISSED_BLOCKS, 100);
        assert_eq!(ROUND_TIMEOUT_SECS, 30);
        assert_eq!(LIVENESS_JAIL_THRESHOLD, 500);
        assert_eq!(MAX_CONSECUTIVE_ROUND_TIMEOUTS, 10);
        assert_eq!(HEARTBEAT_LIVENESS_TIMEOUT_SECS, 30);
    }
}
