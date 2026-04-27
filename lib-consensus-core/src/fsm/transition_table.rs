//! Data-driven enumeration of the validator FSM transition matrix.
//!
//! The same transitions implemented by [`super::transition::transition`]
//! exposed here as a `Vec<TransitionRule>` for runtime queries:
//!
//! ```ignore
//! use lib_consensus_core::fsm::transition_table::{transition_table, ValidatorStateKind};
//! let rules = transition_table();
//! let from_prevoting: Vec<_> = rules.iter()
//!     .filter(|r| r.from == ValidatorStateKind::Prevoting)
//!     .collect();
//! ```
//!
//! Two consumers benefit:
//!
//! 1. **Operator tooling** — render the FSM as a Graphviz diagram,
//!    enumerate "what could happen if I send event X to state Y",
//!    audit the protocol against the running code.
//! 2. **Test fuzzing** — drive `transition()` with every kind-pair
//!    enumerated by the table and verify the function output matches
//!    the table's claimed `(to, action_kinds)`. The table thus acts
//!    as the source-of-truth spec; the function is the executable
//!    realization.
//!
//! ## Drift protection
//!
//! `tests::transition_function_matches_table` invokes `transition()`
//! with one representative `(state, event)` per row in the table and
//! asserts both the resulting state-kind and the action-kind sequence.
//! Any divergence between table and function fails CI — the two
//! cannot drift silently.

use crate::fsm::events::{ActionKind, EventKind};
use crate::fsm::state::ValidatorStateKind;

/// One row of the transition matrix — a Markov chain edge.
///
/// `(from, event) → (to, actions)` with a `doc` string describing the
/// real-world reason for the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRule {
    pub from: ValidatorStateKind,
    pub event: EventKind,
    pub to: ValidatorStateKind,
    /// Sequence of action *kinds* the transition emits.  Payload data
    /// (block hashes, quorum proofs) is not represented here — the
    /// table describes the *shape* of the transition, not its data.
    pub actions: Vec<ActionKind>,
    /// One-line description of the edge for diagram labels and audit logs.
    pub doc: &'static str,
}

/// All transitions defined by the FSM, in source order.
///
/// The list is intentionally hand-maintained alongside
/// [`super::transition::transition`].  The drift-protection test in
/// this module enforces that every row's `(from, event) -> (to,
/// actions)` matches what `transition()` produces.
pub fn transition_table() -> Vec<TransitionRule> {
    use ActionKind as A;
    use EventKind as E;
    use ValidatorStateKind as S;

    let mut rules = Vec::new();

    let mut push = |from, event, to, actions: Vec<A>, doc| {
        rules.push(TransitionRule {
            from,
            event,
            to,
            actions,
            doc,
        });
    };

    // ----- Bootstrapping -----
    push(
        S::Bootstrapping,
        E::BootstrapComplete,
        S::Idle,
        vec![A::ResetWatchdog],
        "Genesis bootstrap finished — node is up and Idle.",
    );

    // ----- CatchingUp -----
    push(
        S::CatchingUp,
        E::CaughtUp,
        S::Idle,
        vec![A::ResetWatchdog],
        "Sync reached the network tip — resume normal consensus.",
    );

    // ----- Idle -----
    push(
        S::Idle,
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Local validator was elected proposer for this round.",
    );

    // ----- Proposing -----
    push(
        S::Proposing,
        E::ProposalAdmitted,
        S::Prevoting,
        vec![A::BroadcastProposal, A::SendPrevote, A::ResetWatchdog],
        "Valid proposal admitted; broadcast it and cast our prevote.",
    );
    push(
        S::Proposing,
        E::Timeout,
        S::Prevoting,
        vec![A::ResetWatchdog],
        "Proposal window timed out — walk forward to Prevoting.",
    );
    push(
        S::Proposing,
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Proposing as stuck.",
    );

    // ----- Prevoting -----
    push(
        S::Prevoting,
        E::PrevoteThresholdReached,
        S::Precommitting,
        vec![A::SendPrecommit, A::ResetWatchdog],
        "+2/3 prevotes for one block — send precommit and advance.",
    );
    push(
        S::Prevoting,
        E::Timeout,
        S::Precommitting,
        vec![A::ResetWatchdog],
        "Prevote window timed out — walk forward to Precommitting.",
    );
    push(
        S::Prevoting,
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Prevoting as stuck.",
    );

    // ----- Precommitting -----
    push(
        S::Precommitting,
        E::PrecommitThresholdReached,
        S::Precommitting,
        vec![A::SendCommit, A::ResetWatchdog],
        "+2/3 precommits — send commit vote, stay gathering commits.",
    );
    push(
        S::Precommitting,
        E::CommitQuorumReached,
        S::Committed,
        vec![A::CommitBlock, A::ResetWatchdog],
        "Commit-vote quorum — block finalized, transition to Committed.",
    );
    push(
        S::Precommitting,
        E::Timeout,
        S::Precommitting,
        vec![A::ResetWatchdog],
        "Precommit window timed out — keep gathering commit votes.",
    );
    push(
        S::Precommitting,
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Precommitting as stuck.",
    );

    // ----- Committed -----
    push(
        S::Committed,
        E::Timeout,
        S::Rejected,
        vec![A::AdvanceRound],
        "Commit-vote gathering timed out — view change.",
    );
    push(
        S::Committed,
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Next height: this validator is proposer.",
    );

    // ----- Rejected -----
    push(
        S::Rejected,
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Round +1 entry: this validator is proposer.",
    );

    // ----- Universal: panic -----
    // Source kind doesn't matter for this row — the table records the
    // *event kind*'s effect, and PanicTriggered is handled in
    // `handle_universal()` for any non-critical state.  We pick Idle as
    // a representative source for the spec table.
    push(
        S::Idle,
        E::PanicTriggered,
        S::Panic,
        vec![A::BroadcastPanic, A::LogPanic],
        "Critical condition observed — enter Panic, broadcast to peers.",
    );
    push(
        S::Panic,
        E::PanicCleared,
        S::Idle,
        vec![A::ResetWatchdog],
        "Recoverable panic cleared — return to Idle. \
         (Non-recoverable: see Panic→Halting row.)",
    );
    push(
        S::Panic,
        E::PanicCleared,
        S::Halting,
        vec![A::LogPanic, A::StopBlockProduction],
        "Non-recoverable panic — force Halting{Never}.",
    );

    // ----- Universal: halt + coordinated update -----
    push(
        S::Idle,
        E::HaltScheduled,
        S::Halting,
        vec![A::StopBlockProduction],
        "Operator scheduled a coordinated halt.",
    );
    push(
        S::Halting,
        E::HaltActivated,
        S::CoordinatedUpdate,
        vec![A::EnterUpdateBarrier],
        "Halt window reached — enter coordinated-update barrier.",
    );
    push(
        S::CoordinatedUpdate,
        E::UpdateQuorumReady,
        S::Idle,
        vec![A::BroadcastReadyOnNewVersion, A::ResetWatchdog],
        "Quorum ready on new protocol version — resume Idle.",
    );

    // ----- Universal: shutdown -----
    push(
        S::Idle,
        E::ShutdownRequested,
        S::ShuttingDown,
        vec![A::FlushLogsForShutdown],
        "Operator requested graceful shutdown.",
    );

    // ----- Slashing / eviction -----
    push(
        S::Idle,
        E::SlashEvidenceConfirmed,
        S::Slashed,
        vec![A::LeaveActiveSet],
        "Slashable evidence confirmed — leave active set.",
    );
    push(
        S::Idle,
        E::EvictedFromSet,
        S::Evicted,
        vec![A::LeaveActiveSet],
        "Removed from active set.",
    );
    push(
        S::Slashed,
        E::ReadmittedToSet,
        S::Idle,
        vec![A::RejoinActiveSet],
        "Re-admitted after slashing window closed.",
    );
    push(
        S::Evicted,
        E::ReadmittedToSet,
        S::Idle,
        vec![A::RejoinActiveSet],
        "Re-admitted after re-registration.",
    );

    rules
}

/// Convenience query: all transitions originating from a specific
/// state kind.
pub fn transitions_from(state: ValidatorStateKind) -> Vec<TransitionRule> {
    transition_table()
        .into_iter()
        .filter(|r| r.from == state)
        .collect()
}

/// Convenience query: all transitions triggered by a specific event
/// kind, regardless of source state.
pub fn transitions_by_event(event: EventKind) -> Vec<TransitionRule> {
    transition_table()
        .into_iter()
        .filter(|r| r.event == event)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::events::{Event, ResumeConditionEvent};
    use crate::fsm::state::{
        HaltReason, PanicReason, RejectionReason, ResumeCondition, SlashReason, ValidatorState,
    };
    use crate::fsm::transition::transition;
    use lib_crypto::Hash;
    use lib_types::consensus::BftQuorumProof;
    use std::time::Instant;

    fn dummy_quorum() -> BftQuorumProof {
        BftQuorumProof {
            height: 7,
            proposal_id: [0u8; 32],
            total_validators: 0,
            attestations: Vec::new(),
        }
    }

    /// Build a representative `(state, event)` pair for a `(from,
    /// event_kind)` row. The variants chosen pair one canonical
    /// payload with the kind under test.
    fn representative_state(kind: ValidatorStateKind) -> ValidatorState {
        match kind {
            ValidatorStateKind::Bootstrapping => ValidatorState::Bootstrapping,
            ValidatorStateKind::CatchingUp => ValidatorState::CatchingUp {
                from_height: 0,
                to_height: 100,
            },
            ValidatorStateKind::Idle => ValidatorState::Idle,
            ValidatorStateKind::Proposing => ValidatorState::Proposing,
            ValidatorStateKind::Prevoting => ValidatorState::Prevoting,
            ValidatorStateKind::Precommitting => ValidatorState::Precommitting,
            ValidatorStateKind::Committed => ValidatorState::Committed {
                block_hash: [1u8; 32],
                height: 7,
            },
            ValidatorStateKind::Rejected => ValidatorState::Rejected {
                reason: RejectionReason::InsufficientPrevotes,
                round: 0,
            },
            ValidatorStateKind::Hung => ValidatorState::Hung {
                since: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorStateKind::Halting => ValidatorState::Halting {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 100,
                last_block_hash: None,
                resume_condition: ResumeCondition::QuorumReady,
            },
            ValidatorStateKind::CoordinatedUpdate => ValidatorState::CoordinatedUpdate {
                activate_at_height: 100,
                target_version: 2,
            },
            ValidatorStateKind::Slashed => ValidatorState::Slashed {
                reason: SlashReason::DoubleSign,
            },
            ValidatorStateKind::Evicted => ValidatorState::Evicted,
            ValidatorStateKind::Panic => ValidatorState::Panic {
                // Use a recoverable reason so the (Panic, PanicCleared)
                // row that goes to Idle matches; the non-recoverable
                // row to Halting is exercised separately below.
                reason: PanicReason::HeartbeatMissed,
                triggered_at: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorStateKind::ShuttingDown => ValidatorState::ShuttingDown,
        }
    }

    fn representative_event(kind: EventKind) -> Event {
        match kind {
            EventKind::BootstrapComplete => Event::BootstrapComplete,
            EventKind::CaughtUp => Event::CaughtUp,
            EventKind::ShutdownRequested => Event::ShutdownRequested,
            EventKind::SelectedAsProposer => {
                Event::SelectedAsProposer { height: 1, round: 0 }
            }
            EventKind::ProposalAdmitted => Event::ProposalAdmitted {
                id: Hash([42u8; 32]),
                height: 1,
                round: 0,
            },
            EventKind::PrevoteThresholdReached => Event::PrevoteThresholdReached {
                block_id: Hash([42u8; 32]),
            },
            EventKind::PrecommitThresholdReached => Event::PrecommitThresholdReached {
                block_id: Hash([42u8; 32]),
            },
            EventKind::CommitQuorumReached => Event::CommitQuorumReached {
                block_id: Hash([42u8; 32]),
                quorum: dummy_quorum(),
            },
            EventKind::VoteFailed => Event::VoteFailed(RejectionReason::Timeout),
            EventKind::Timeout => Event::Timeout,
            EventKind::WatchdogFired => Event::WatchdogFired { age_ms: 1 },
            EventKind::PanicTriggered => Event::PanicTriggered {
                reason: PanicReason::WatchdogExpired,
            },
            EventKind::PanicCleared => Event::PanicCleared,
            EventKind::HaltScheduled => Event::HaltScheduled {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 100,
                resume_condition: ResumeConditionEvent::QuorumReady,
            },
            EventKind::HaltActivated => Event::HaltActivated {
                activate_at_height: 100,
                target_version: 2,
            },
            EventKind::UpdateQuorumReady => Event::UpdateQuorumReady,
            EventKind::SlashEvidenceConfirmed => Event::SlashEvidenceConfirmed {
                reason: SlashReason::DoubleSign,
            },
            EventKind::EvictedFromSet => Event::EvictedFromSet,
            EventKind::ReadmittedToSet => Event::ReadmittedToSet,
        }
    }

    /// Drift protection: every row in the table must match what
    /// `transition()` actually produces for one representative
    /// (state, event) pair. If a row diverges from the function,
    /// either the row or the function is wrong — fix one.
    ///
    /// Two rows in the table cover the same (Panic, PanicCleared) pair
    /// — recoverable→Idle and non-recoverable→Halting — disambiguated
    /// by `prior_state`/`reason`. We exercise both branches here.
    #[test]
    fn transition_function_matches_table() {
        for rule in transition_table() {
            // The (Panic, PanicCleared) pair has two table rows. Skip
            // the non-recoverable one for this generic walk; it's
            // exercised in `panic_non_recoverable_row` below.
            if rule.from == ValidatorStateKind::Panic
                && rule.event == EventKind::PanicCleared
                && rule.to == ValidatorStateKind::Halting
            {
                continue;
            }

            let state = representative_state(rule.from);
            let event = representative_event(rule.event);
            let (next, actions) = transition(state.clone(), event.clone());

            assert_eq!(
                next.kind(),
                rule.to,
                "from {:?} via {:?} expected {:?}, got {:?}\n  doc: {}",
                rule.from,
                rule.event,
                rule.to,
                next.kind(),
                rule.doc,
            );

            let action_kinds: Vec<ActionKind> = actions.iter().map(|a| a.kind()).collect();
            assert_eq!(
                action_kinds, rule.actions,
                "from {:?} via {:?} action mismatch\n  doc: {}",
                rule.from, rule.event, rule.doc,
            );
        }
    }

    /// Non-recoverable Panic row: PanicCleared from a Panic with a
    /// non-recoverable reason forces Halting{Never}.
    #[test]
    fn panic_non_recoverable_row() {
        let state = ValidatorState::Panic {
            reason: PanicReason::DoubleVote,
            triggered_at: Instant::now(),
            prior_state: Box::new(ValidatorState::Prevoting),
        };
        let (next, actions) = transition(state, Event::PanicCleared);
        assert_eq!(next.kind(), ValidatorStateKind::Halting);
        let action_kinds: Vec<ActionKind> = actions.iter().map(|a| a.kind()).collect();
        assert_eq!(
            action_kinds,
            vec![ActionKind::LogPanic, ActionKind::StopBlockProduction]
        );
    }

    #[test]
    fn transitions_from_query_works() {
        let from_prevoting = transitions_from(ValidatorStateKind::Prevoting);
        // Prevoting has 3 explicit rows: PrevoteThresholdReached,
        // Timeout, WatchdogFired.
        assert_eq!(from_prevoting.len(), 3);
        assert!(from_prevoting
            .iter()
            .any(|r| r.event == EventKind::PrevoteThresholdReached));
        assert!(from_prevoting
            .iter()
            .any(|r| r.event == EventKind::Timeout));
        assert!(from_prevoting
            .iter()
            .any(|r| r.event == EventKind::WatchdogFired));
    }

    #[test]
    fn transitions_by_event_query_works() {
        let by_timeout = transitions_by_event(EventKind::Timeout);
        // Timeout is defined for 4 source states: Proposing, Prevoting,
        // Precommitting, Committed.
        assert_eq!(by_timeout.len(), 4);
    }

    /// Every row's doc string is non-empty — table is self-documenting.
    #[test]
    fn every_row_has_doc() {
        for rule in transition_table() {
            assert!(
                !rule.doc.is_empty(),
                "rule {:?} via {:?} has empty doc",
                rule.from,
                rule.event,
            );
        }
    }
}
