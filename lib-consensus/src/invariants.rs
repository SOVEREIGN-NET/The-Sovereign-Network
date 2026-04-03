//! Consensus safety invariants with explicit validation and fail-fast enforcement.
//!
//! This module defines core BFT consensus safety properties and provides utilities
//! for checking and enforcing these invariants during consensus operations.
//!
//! # Design Principles
//!
//! 1. **State-based validation**: Invariant checks accept actual consensus state
//!    data (heights, vote counts, hashes) rather than pre-computed booleans,
//!    making call sites self-documenting and reducing parameter ordering errors.
//!
//! 2. **Fail-fast enforcement**: Invariant violations cause immediate panic to
//!    prevent state corruption. This is appropriate for consensus safety bugs
//!    that should never occur in correct implementations.
//!
//! 3. **Integration with consensus engine**: These checks are designed to be
//!    called during actual consensus operations (block commits, height advances,
//!    fork detection) in the consensus engine and blockchain modules.
//!
//! # Safety Invariants
//!
//! - **NoFork**: No two valid commits may exist at the same block height
//! - **MonotonicHeight**: Committed block height increases strictly monotonically
//! - **QuorumRequired**: Every commit requires a BFT safety quorum (2f+1 validators)
//! - **FinalityIrreversible**: Once committed, blocks cannot be reverted
//!
//! # Usage
//!
//! ```rust,ignore
//! use lib_consensus::invariants::{ConsensusState, enforce_consensus_invariants};
//!
//! // In consensus engine during block commit:
//! let state = ConsensusState {
//!     current_height: new_block.height,
//!     previous_height: last_committed_height,
//!     votes_received: validator_votes.len() as u64,
//!     total_validators: validator_set.len() as u64,
//!     fork_detected: check_for_fork(new_block),
//!     reorg_detected: false,
//! };
//!
//! enforce_consensus_invariants(&state); // Panics on violation
//! ```

use crate::fault_model::safety_quorum;

/// Enumeration of core BFT consensus safety invariants.
///
/// Each variant describes a property that MUST hold at all times during correct
/// consensus operation. Violations indicate a safety or liveness bug that
/// requires immediate investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusInvariant {
    /// No two valid commits exist at the same block height (no forks).
    NoFork,
    /// Committed block height is strictly monotonically increasing.
    MonotonicHeight,
    /// Every commit requires a quorum of validators as defined by safety_quorum().
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
            Self::QuorumRequired => {
                "every commit requires BFT safety quorum (2f+1 where f=(n-1)/3) validators"
            }
            Self::FinalityIrreversible => "committed blocks are final and cannot be reverted",
        }
    }
}

/// Consensus state snapshot used for invariant validation.
///
/// This structure captures the relevant consensus state at a specific point
/// in time, enabling invariant checks to be performed without requiring
/// callers to pre-compute boolean invariant outcomes.
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current block height being committed or validated.
    pub current_height: u64,
    /// Previously committed block height (None if this is genesis).
    pub previous_height: Option<u64>,
    /// Number of validator votes received for the current operation.
    pub votes_received: u64,
    /// Total number of validators in the active set.
    pub total_validators: u64,
    /// Whether a conflicting commit has been detected at current_height.
    pub fork_detected: bool,
    /// Whether a previously committed block has been reverted/reorged.
    pub reorg_detected: bool,
}

impl ConsensusState {
    /// Validates the NoFork invariant.
    ///
    /// Returns true if no fork has been detected at the current height.
    pub fn check_no_fork(&self) -> bool {
        !self.fork_detected
    }

    /// Validates the MonotonicHeight invariant.
    ///
    /// Returns true if current_height is strictly greater than previous_height,
    /// or if previous_height is None (genesis case).
    pub fn check_monotonic_height(&self) -> bool {
        match self.previous_height {
            None => true, // Genesis is always valid
            Some(prev) => self.current_height > prev,
        }
    }

    /// Validates the QuorumRequired invariant.
    ///
    /// Returns true if votes_received meets or exceeds the BFT safety quorum
    /// calculated as 2f+1 where f=(n-1)/3.
    pub fn check_quorum_satisfied(&self) -> bool {
        let required = safety_quorum(self.total_validators);
        self.votes_received >= required
    }

    /// Validates the FinalityIrreversible invariant.
    ///
    /// Returns true if no reorg has been detected.
    pub fn check_finality_irreversible(&self) -> bool {
        !self.reorg_detected
    }

    /// Checks all invariants and returns a vector of violated invariants.
    ///
    /// Returns an empty vector if all invariants hold.
    pub fn check_all_invariants(&self) -> Vec<ConsensusInvariant> {
        let mut violations = Vec::new();

        if !self.check_no_fork() {
            violations.push(ConsensusInvariant::NoFork);
        }
        if !self.check_monotonic_height() {
            violations.push(ConsensusInvariant::MonotonicHeight);
        }
        if !self.check_quorum_satisfied() {
            violations.push(ConsensusInvariant::QuorumRequired);
        }
        if !self.check_finality_irreversible() {
            violations.push(ConsensusInvariant::FinalityIrreversible);
        }

        violations
    }
}

/// Validates a single consensus invariant against the provided state.
///
/// Returns `Ok(())` if the invariant holds, or an `Err` with a descriptive
/// message if it is violated.
///
/// # Arguments
/// * `invariant` - The invariant to check.
/// * `state` - The consensus state to validate against.
///
/// # Errors
/// Returns `Err` when the invariant is violated.
pub fn check_invariant(
    invariant: &ConsensusInvariant,
    state: &ConsensusState,
) -> Result<(), String> {
    let holds = match invariant {
        ConsensusInvariant::NoFork => state.check_no_fork(),
        ConsensusInvariant::MonotonicHeight => state.check_monotonic_height(),
        ConsensusInvariant::QuorumRequired => state.check_quorum_satisfied(),
        ConsensusInvariant::FinalityIrreversible => state.check_finality_irreversible(),
    };

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

/// Enforces all consensus invariants with fail-fast behavior.
///
/// **Fail-fast**: panics immediately if any invariant is violated. A panic
/// here indicates a safety or liveness bug in the consensus implementation
/// and must halt the node to prevent further state corruption.
///
/// # Arguments
/// * `state` - The consensus state to validate.
///
/// # Panics
/// Panics with a descriptive message if any invariant is violated.
pub fn enforce_consensus_invariants(state: &ConsensusState) {
    let violations = state.check_all_invariants();

    if !violations.is_empty() {
        let mut msg = String::from("CONSENSUS SAFETY BUG — invariants violated:\n");
        for invariant in &violations {
            msg.push_str(&format!(
                "  - [{:?}]: {}\n",
                invariant,
                invariant.description()
            ));
        }
        msg.push_str("The node must halt to prevent further state corruption.");
        panic!("{}", msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a valid baseline state.
    fn valid_state() -> ConsensusState {
        ConsensusState {
            current_height: 2,
            previous_height: Some(1),
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        }
    }

    #[test]
    fn test_check_invariant_passes_when_valid() {
        let state = valid_state();
        assert!(check_invariant(&ConsensusInvariant::NoFork, &state).is_ok());
        assert!(check_invariant(&ConsensusInvariant::MonotonicHeight, &state).is_ok());
        assert!(check_invariant(&ConsensusInvariant::QuorumRequired, &state).is_ok());
        assert!(check_invariant(&ConsensusInvariant::FinalityIrreversible, &state).is_ok());
    }

    #[test]
    fn test_check_invariant_fails_on_fork() {
        let mut state = valid_state();
        state.fork_detected = true;

        let err = check_invariant(&ConsensusInvariant::NoFork, &state);
        assert!(err.is_err());
        let msg = err.unwrap_err();
        assert!(msg.contains("NoFork"));
        assert!(msg.contains("no two commits may exist at the same height"));
    }

    #[test]
    fn test_enforce_consensus_invariants_all_pass() {
        let state = valid_state();
        enforce_consensus_invariants(&state); // Should not panic
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_enforce_panics_on_fork() {
        let mut state = valid_state();
        state.fork_detected = true;
        enforce_consensus_invariants(&state);
    }

    #[test]
    fn test_enforce_panic_message_includes_invariant_details() {
        let result = std::panic::catch_unwind(|| {
            let mut state = valid_state();
            state.fork_detected = true;
            enforce_consensus_invariants(&state);
        });

        assert!(result.is_err(), "expected panic on fork violation");

        let panic_msg = match result {
            Err(payload) => {
                if let Some(s) = payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    String::from("non-string panic payload")
                }
            }
            Ok(_) => unreachable!(),
        };

        assert!(
            panic_msg.contains("CONSENSUS SAFETY BUG"),
            "panic message should contain safety prefix, got: {panic_msg}"
        );
        assert!(
            panic_msg.contains("NoFork"),
            "panic message should identify NoFork invariant, got: {panic_msg}"
        );
        assert!(
            panic_msg.contains("no two commits may exist at the same height"),
            "panic message should describe NoFork invariant, got: {panic_msg}"
        );
    }

    #[test]
    fn test_monotonic_height_validation() {
        // Valid: height increases
        let state = ConsensusState {
            current_height: 5,
            previous_height: Some(4),
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(state.check_monotonic_height());

        // Invalid: height regression
        let state = ConsensusState {
            current_height: 3,
            previous_height: Some(4),
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(!state.check_monotonic_height());

        // Invalid: height duplicate
        let state = ConsensusState {
            current_height: 4,
            previous_height: Some(4),
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(!state.check_monotonic_height());

        // Valid: genesis (no previous height)
        let state = ConsensusState {
            current_height: 0,
            previous_height: None,
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(state.check_monotonic_height());
    }

    #[test]
    fn test_quorum_calculation_with_safety_quorum() {
        // 4 validators: safety_quorum = 2*((4-1)/3) + 1 = 2*1 + 1 = 3
        let state = ConsensusState {
            current_height: 1,
            previous_height: None,
            votes_received: 3,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(state.check_quorum_satisfied());

        let state = ConsensusState {
            current_height: 1,
            previous_height: None,
            votes_received: 2,
            total_validators: 4,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(!state.check_quorum_satisfied());

        // 7 validators: safety_quorum = 2*((7-1)/3) + 1 = 2*2 + 1 = 5
        let state = ConsensusState {
            current_height: 1,
            previous_height: None,
            votes_received: 5,
            total_validators: 7,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(state.check_quorum_satisfied());

        let state = ConsensusState {
            current_height: 1,
            previous_height: None,
            votes_received: 4,
            total_validators: 7,
            fork_detected: false,
            reorg_detected: false,
        };
        assert!(!state.check_quorum_satisfied());
    }

    /// MockCommitState simulates a simplified consensus commit sequence
    /// for integration testing. It tracks height progression, fork detection,
    /// and reorg scenarios, then enforces invariants via enforce_consensus_invariants.
    struct MockCommitState {
        last_height: Option<u64>,
        fork_detected: bool,
        reorg_detected: bool,
        total_validators: u64,
    }

    impl MockCommitState {
        fn new(total_validators: u64) -> Self {
            Self {
                last_height: None,
                fork_detected: false,
                reorg_detected: false,
                total_validators,
            }
        }

        /// Apply a commit at the given height with specified vote count.
        ///
        /// This method derives consensus state from the commit operation
        /// and calls enforce_consensus_invariants to emulate enforcement
        /// during actual consensus execution.
        fn apply_commit(&mut self, height: u64, votes_received: u64) {
            // Detect fork: two commits at the same height
            if let Some(last) = self.last_height {
                if height == last {
                    self.fork_detected = true;
                }
            }

            let state = ConsensusState {
                current_height: height,
                previous_height: self.last_height,
                votes_received,
                total_validators: self.total_validators,
                fork_detected: self.fork_detected,
                reorg_detected: self.reorg_detected,
            };

            enforce_consensus_invariants(&state);
            self.last_height = Some(height);
        }

        /// Explicitly trigger a reorg violation.
        fn trigger_reorg_violation(&mut self) {
            self.reorg_detected = true;
            let state = ConsensusState {
                current_height: self.last_height.unwrap_or(0),
                previous_height: self.last_height,
                votes_received: self.total_validators, // Sufficient votes
                total_validators: self.total_validators,
                fork_detected: false,
                reorg_detected: true,
            };
            enforce_consensus_invariants(&state);
        }
    }

    #[test]
    fn test_consensus_commit_sequence_valid() {
        // Simulate valid commits with strictly increasing height and sufficient quorum
        let mut state = MockCommitState::new(4);
        state.apply_commit(1, 3); // 3 votes out of 4 validators
        state.apply_commit(2, 3);
        state.apply_commit(3, 4);
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_consensus_panics_on_height_regression() {
        // Simulate height regression: commit at 3, then 2
        let mut state = MockCommitState::new(4);
        state.apply_commit(1, 3);
        state.apply_commit(3, 3);
        state.apply_commit(2, 3); // Should panic: monotonic height violation
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_consensus_panics_on_quorum_failure() {
        // Simulate commit without sufficient quorum
        let mut state = MockCommitState::new(4);
        state.apply_commit(1, 3);
        state.apply_commit(2, 2); // Should panic: only 2 votes, need 3
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_consensus_panics_on_fork() {
        // Simulate fork: two commits at same height
        let mut state = MockCommitState::new(4);
        state.apply_commit(1, 3);
        state.apply_commit(2, 3);
        state.apply_commit(2, 3); // Should panic: fork detected
    }

    #[test]
    #[should_panic(expected = "CONSENSUS SAFETY BUG")]
    fn test_consensus_panics_on_finality_reorg() {
        // Simulate reorg of committed block
        let mut state = MockCommitState::new(4);
        state.apply_commit(1, 3);
        state.apply_commit(2, 3);
        state.trigger_reorg_violation(); // Should panic: finality violation
    }
}
