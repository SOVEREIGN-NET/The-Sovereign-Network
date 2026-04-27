//! `ValidatorFsm` — total `transition(state, event) -> (next_state, actions)`.
//!
//! Populated by:
//! - **CONS-301: `FsmState` enum** (Idle, Proposing, Prevoting, Precommitting,
//!   Committed, Rejected, Hung, HaltedForUpgrade) ← shipped.
//! - **CONS-302: total `transition()`** with compile-time exhaustiveness ← shipped.
//! - **CONS-303: `Event` and `Action` enums** ← shipped (with the simplification
//!   noted in `events.rs`: IDs instead of full `ConsensusProposal`/`Vote`).
//! - CONS-304: `step_entered_at: Instant` in the FSM struct.

pub mod events;
pub mod state;
pub mod transition;

pub use events::{Action, Event};
pub use state::{FsmState, RejectionReason};
pub use transition::transition;
