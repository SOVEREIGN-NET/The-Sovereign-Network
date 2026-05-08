//! Validator FSM — deterministic Markov chain over `ValidatorState`.
//!
//! Two equivalent representations of the same transition matrix:
//!
//! - **`transition()`** — pure match function, compile-time exhaustive
//!   over `(ValidatorState, Event)`.  Executable.
//! - **`transition_table()`** — runtime-queryable `Vec<TransitionRule>`
//!   with `(from_kind, event_kind, to_kind, action_kinds, doc)` rows.
//!   Inspectable.
//!
//! Tests in `transition_table` enforce that the two never drift —
//! every row must match what `transition()` produces.
//!
//! Populated by:
//! - **CONS-301: `ValidatorState`** — 15-variant control-state enum
//!   plus `RejectionReason`, `HaltReason`, `ResumeCondition`,
//!   `PanicReason`, `SlashReason` reason enums.
//! - **CONS-302: `transition()`** — total match function, no panics.
//! - **CONS-303: `Event` and `Action`** — input and output vocabulary
//!   plus `EventKind` / `ActionKind` discriminants for the table.
//! - **CONS-303 (Markov chain): `transition_table()`** — data-driven
//!   enumeration of every transition with `transitions_from(state)`
//!   and `transitions_by_event(event)` query helpers.
//! - CONS-304: `step_entered_at` / FSM struct (see `crate::types::round`).

pub mod events;
pub mod state;
pub mod transition;
pub mod transition_table;

pub use events::{Action, ActionKind, Event, EventKind, ResumeConditionEvent};
pub use state::{
    HaltReason, PanicReason, RejectionReason, ResumeCondition, SlashReason, ValidatorState,
    ValidatorStateKind,
};
pub use transition::transition;
pub use transition_table::{transition_table, transitions_by_event, transitions_from, TransitionRule};
