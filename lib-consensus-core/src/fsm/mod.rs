//! `ValidatorFsm` — total `transition(state, event) -> (next_state, actions)`.
//!
//! Populated by:
//! - **CONS-301: `FsmState` enum** (Idle, Proposing, Prevoting, Precommitting,
//!   Committed, Rejected, Hung, HaltedForUpgrade) ← shipped.
//! - CONS-302: total `transition()` with compile-time exhaustiveness.
//! - CONS-303: `Event` and `Action` enums.
//! - CONS-304: `step_entered_at: Instant` in the FSM struct.

pub mod state;

pub use state::{FsmState, RejectionReason};
