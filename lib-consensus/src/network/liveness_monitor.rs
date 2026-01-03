//! Consensus Liveness Monitor for Stall Detection
//!
//! # Overview
//!
//! This module provides a passive observer that detects when consensus has stalled
//! due to validator liveness failures. It monitors validator heartbeat timeouts and
//! emits `ConsensusStalled` events when quorum becomes impossible.
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
//! weighting. If validator V hasn't sent a heartbeat in 10 seconds, V is timed out.
//! What other validators do is irrelevant.
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
//! - No heuristics or tuning parameters
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
}
