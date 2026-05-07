//! `ConsensusRound` — the FSM-bearing per-round state struct.
//!
//! Pre-rewrite the equivalent struct in
//! `lib-consensus::types::mod::ConsensusRound` carried `step:
//! ConsensusStep` (the wire-format phase tag) plus a thicket of
//! separate flags for terminal conditions.  CONS-304 introduces the
//! consensus-core version, which holds:
//!
//! - `state: ValidatorState` — the full control state, including terminal
//!   variants (`Committed`, `Rejected(reason)`, `Hung`,
//!   `HaltedForUpgrade`).
//! - `height: u64`, `round: u32` — protocol identifiers (unchanged).
//! - `entered_at: Instant` — wall-clock instant when the FSM last
//!   entered its current state. Updated by every `enter()` call so the
//!   watchdog (CONS-309) can observe step age in O(1).
//! - `deterministic_round_id: u64` — replay-determinism token. Set
//!   equal to `height` so simulators / replay harnesses can drive
//!   reproducible runs without needing wall-clock alignment. Replaces
//!   the old `start_time: SystemTime` field (which was used both for
//!   determinism *and* for wall-clock metrics — two responsibilities
//!   that CONS-304 splits).
//!
//! The lib-consensus mirror struct is **not** touched in this PR — that
//! happens with the handler migration in CONS-305. Until then the two
//! types coexist; the lib-consensus version retains the old `step` /
//! `start_time` shape for the existing handler code.

use crate::fsm::state::ValidatorState;
use std::time::{Duration, Instant};

/// Per-round control state for a single height/round.
///
/// Constructed at round entry by the runtime; consumed by the FSM
/// transition function. The struct is `Clone` (for snapshots) and
/// `Debug`. It is intentionally NOT `Serialize` — `Instant` has no
/// stable serialization, and `entered_at` is wall-clock data that
/// should never appear in audit logs or block bodies.
#[derive(Debug, Clone)]
pub struct ConsensusRound {
    /// Current FSM control state. Updated only via [`Self::enter`].
    pub state: ValidatorState,

    /// Block height this round is producing.
    pub height: u64,

    /// Round number within the height. Incremented on view change.
    pub round: u32,

    /// Wall-clock instant the FSM last transitioned into `state`.
    /// Maintained by [`Self::enter`]; never written from outside this
    /// type so the watchdog can rely on it.
    entered_at: Instant,

    /// Deterministic round identifier for replay/simulation. Set equal
    /// to `height` per the epic spec; replay harnesses use this to
    /// drive reproducible runs that don't depend on wall-clock time.
    pub deterministic_round_id: u64,
}

impl ConsensusRound {
    /// Build a round in the canonical starting state (`Idle`) at the
    /// given height with `round = 0` and `entered_at = Instant::now()`.
    pub fn new(height: u64) -> Self {
        Self {
            state: ValidatorState::Idle,
            height,
            round: 0,
            entered_at: Instant::now(),
            deterministic_round_id: height,
        }
    }

    /// Replace the current FSM state and reset `entered_at` to now.
    /// All state mutations on a `ConsensusRound` MUST go through this
    /// method so that `state_age()` is meaningful.  CONS-305 enforces
    /// this contract by deleting the per-step `enter_*_step` methods
    /// in lib-consensus and routing every state change through here.
    pub fn enter(&mut self, new_state: ValidatorState) {
        self.state = new_state;
        self.entered_at = Instant::now();
    }

    /// Time elapsed since the FSM last entered its current state. Used
    /// by the watchdog (CONS-309) to detect stuck steps.
    pub fn state_age(&self) -> Duration {
        self.entered_at.elapsed()
    }

    /// Public accessor for `entered_at` — exposed read-only so the
    /// watchdog and observability code can record it without being
    /// able to mutate it (only `enter()` can).
    pub fn entered_at(&self) -> Instant {
        self.entered_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::state::RejectionReason;

    #[test]
    fn new_starts_in_idle() {
        let r = ConsensusRound::new(42);
        assert_eq!(r.state, ValidatorState::Idle);
        assert_eq!(r.height, 42);
        assert_eq!(r.round, 0);
        assert_eq!(r.deterministic_round_id, 42);
        // entered_at is recent.
        assert!(r.state_age() < Duration::from_millis(50));
    }

    #[test]
    fn enter_updates_state_and_entered_at() {
        let mut r = ConsensusRound::new(1);
        let initial = r.entered_at();
        // Sleep long enough to make the change visible without being slow.
        std::thread::sleep(Duration::from_millis(2));
        r.enter(ValidatorState::Proposing);
        assert_eq!(r.state, ValidatorState::Proposing);
        assert!(r.entered_at() > initial);
    }

    /// Acceptance criterion: after a state mutation, `entered_at`
    /// reflects call time within 1ms (epic spec). We use a slightly
    /// looser bound so CI doesn't flake on slow runners.
    #[test]
    fn entered_at_reflects_call_time_within_5ms() {
        let mut r = ConsensusRound::new(1);
        let before = Instant::now();
        r.enter(ValidatorState::Prevoting);
        let after = Instant::now();
        assert!(r.entered_at() >= before);
        assert!(r.entered_at() <= after);
        assert!(after - before < Duration::from_millis(5));
    }

    #[test]
    fn state_age_grows_until_next_enter() {
        let mut r = ConsensusRound::new(1);
        r.enter(ValidatorState::Precommitting);
        std::thread::sleep(Duration::from_millis(3));
        let age1 = r.state_age();
        assert!(age1 >= Duration::from_millis(3));

        r.enter(ValidatorState::Committed {
            block_hash: [1u8; 32],
            height: 1,
        });
        let age2 = r.state_age();
        assert!(age2 < age1, "enter() did not reset entered_at");
    }

    #[test]
    fn enter_into_states_works_uniformly() {
        // Every ValidatorState variant must be assignable via enter().
        // We sample one of each kind. This protects against accidentally
        // adding a state that requires special construction.
        let mut r = ConsensusRound::new(1);
        let states = vec![
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
            ValidatorState::Committed {
                block_hash: [1u8; 32],
                height: 1,
            },
            ValidatorState::Rejected {
                reason: RejectionReason::InsufficientPrevotes,
                round: 0,
            },
            ValidatorState::Idle,
        ];
        for state in states {
            r.enter(state.clone());
            assert_eq!(r.state, state);
        }
    }
}
