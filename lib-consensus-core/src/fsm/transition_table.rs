//! Data-driven enumeration of the validator FSM transition matrix.
//!
//! The same transitions implemented by [`super::transition::transition`]
//! exposed here as a `Vec<TransitionRule>` for runtime queries:
//!
//! ```ignore
//! use lib_consensus_core::fsm::transition_table::*;
//! let rules = transition_table();
//! let from_prevoting: Vec<_> = transitions_from(ValidatorStateKind::Prevoting);
//! ```
//!
//! Two consumers benefit:
//!
//! 1. **Operator tooling** — render the FSM as a Graphviz diagram,
//!    enumerate "what could happen if I send event X to state Y",
//!    audit the protocol against the running code.
//! 2. **Test fuzzing** — drive `transition()` with every kind-pair
//!    enumerated by the table and verify the function output matches
//!    the table's claimed `(to, action_kinds)`.
//!
//! ## Universal-event encoding ([`FromKind::Any`])
//!
//! Cross-cutting events (`PanicTriggered`, `HaltScheduled`,
//! `ShutdownRequested`, `SlashEvidenceConfirmed`, `EvictedFromSet`)
//! apply from "every active state" — encoding them as a single
//! `(Specific(Idle), …)` row would have made `transitions_from(X)`
//! incomplete for every other source state. Instead the table uses
//! [`FromKind::Any`] for these rows, and [`transitions_from`]
//! returns both the source-specific and `Any` rows that match a
//! query state. PR #2394 review (Copilot).
//!
//! ## Drift protection (bidirectional)
//!
//! - **Forward**: `transition_function_matches_table` runs every row
//!   through `transition()` and asserts the resulting state-kind and
//!   action-kinds match the table.
//! - **Reverse**: `function_transitions_appear_in_table` walks every
//!   `(state_kind, event_kind)` product, calls `transition()`, and
//!   for every result that produces a *meaningful* transition (state
//!   change OR a non-`LogIgnoredEvent` action) verifies a matching
//!   row exists in the table. This catches the case where the
//!   function adds a transition that the table author forgot to
//!   document. PR #2394 review (Copilot).

use crate::fsm::events::{ActionKind, EventKind};
use crate::fsm::state::ValidatorStateKind;

/// Source side of a transition rule.
///
/// `Specific(K)` matches exactly state-kind `K`. `Any` matches every
/// active state (the runtime restricts the actual set per the
/// universal-event guards in `transition()` — e.g. `PanicTriggered`
/// is logged-ignored from `Panic`/`Halting`/`ShuttingDown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromKind {
    Specific(ValidatorStateKind),
    Any,
}

/// One row of the transition matrix — a Markov chain edge.
///
/// `(from, event) → (to, actions)` with a `doc` string describing the
/// real-world reason for the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRule {
    pub from: FromKind,
    pub event: EventKind,
    pub to: ValidatorStateKind,
    pub actions: Vec<ActionKind>,
    pub doc: &'static str,
}

/// All transitions defined by the FSM, in source order.
///
/// The list is hand-maintained alongside
/// [`super::transition::transition`]. Two drift-protection tests
/// (forward and reverse) enforce the table cannot diverge from the
/// function in either direction.
pub fn transition_table() -> Vec<TransitionRule> {
    use ActionKind as A;
    use EventKind as E;
    use FromKind as F;
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

    // ----- Lifecycle -----
    push(
        F::Specific(S::Bootstrapping),
        E::BootstrapComplete,
        S::Idle,
        vec![A::ResetWatchdog],
        "Genesis bootstrap finished — node is up and Idle.",
    );
    push(
        F::Specific(S::CatchingUp),
        E::CaughtUp,
        S::Idle,
        vec![A::ResetWatchdog],
        "Sync reached the network tip — resume normal consensus.",
    );

    // ----- Idle -----
    push(
        F::Specific(S::Idle),
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Local validator was elected proposer for this round.",
    );
    push(
        F::Specific(S::Idle),
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog fired while Idle — runtime stuck before round start.",
    );

    // ----- Proposing -----
    push(
        F::Specific(S::Proposing),
        E::ProposalAdmitted,
        S::Prevoting,
        vec![A::BroadcastProposal, A::SendPrevote, A::ResetWatchdog],
        "Valid proposal admitted; broadcast it and cast our prevote.",
    );
    push(
        F::Specific(S::Proposing),
        E::Timeout,
        S::Prevoting,
        vec![A::ResetWatchdog],
        "Proposal window timed out — walk forward to Prevoting.",
    );
    push(
        F::Specific(S::Proposing),
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Proposing as stuck.",
    );
    push(
        F::Specific(S::Proposing),
        E::VoteFailed,
        S::Rejected,
        vec![A::AdvanceRound],
        "Vote-tally rejection in Proposing — view change.",
    );

    // ----- Prevoting -----
    push(
        F::Specific(S::Prevoting),
        E::PrevoteThresholdReached,
        S::Precommitting,
        vec![A::SendPrecommit, A::ResetWatchdog],
        "+2/3 prevotes for one block — send precommit and advance.",
    );
    push(
        F::Specific(S::Prevoting),
        E::Timeout,
        S::Precommitting,
        vec![A::ResetWatchdog],
        "Prevote window timed out — walk forward to Precommitting.",
    );
    push(
        F::Specific(S::Prevoting),
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Prevoting as stuck.",
    );
    push(
        F::Specific(S::Prevoting),
        E::VoteFailed,
        S::Rejected,
        vec![A::AdvanceRound],
        "Vote-tally rejection in Prevoting — view change.",
    );

    // ----- Precommitting -----
    push(
        F::Specific(S::Precommitting),
        E::PrecommitThresholdReached,
        S::Precommitting,
        vec![A::SendCommit, A::ResetWatchdog],
        "+2/3 precommits — send commit vote, stay gathering commits.",
    );
    push(
        F::Specific(S::Precommitting),
        E::CommitQuorumReached,
        S::Committed,
        vec![A::CommitBlock, A::ResetWatchdog],
        "Commit-vote quorum — block finalized, transition to Committed.",
    );
    push(
        F::Specific(S::Precommitting),
        E::Timeout,
        S::Precommitting,
        vec![A::ResetWatchdog],
        "Precommit window timed out — keep gathering commit votes.",
    );
    push(
        F::Specific(S::Precommitting),
        E::WatchdogFired,
        S::Hung,
        vec![A::LogHung],
        "Watchdog flagged Precommitting as stuck.",
    );
    push(
        F::Specific(S::Precommitting),
        E::VoteFailed,
        S::Rejected,
        vec![A::AdvanceRound],
        "Vote-tally rejection in Precommitting — view change.",
    );

    // ----- Committed -----
    push(
        F::Specific(S::Committed),
        E::Timeout,
        S::Rejected,
        vec![A::AdvanceRound],
        "Commit-vote gathering timed out — view change.",
    );
    push(
        F::Specific(S::Committed),
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Next height: this validator is proposer.",
    );

    // ----- Rejected -----
    push(
        F::Specific(S::Rejected),
        E::SelectedAsProposer,
        S::Proposing,
        vec![A::CreateProposal, A::ResetWatchdog],
        "Round +1 entry: this validator is proposer.",
    );

    // ----- Universal: PanicTriggered -----
    push(
        F::Any,
        E::PanicTriggered,
        S::Panic,
        vec![A::BroadcastPanic, A::LogPanic],
        "Critical condition observed — enter Panic, broadcast to peers. \
         (Already-Panic/Halting/ShuttingDown sources log-ignore.)",
    );
    // Two rows for (Panic, PanicCleared) — recoverable vs non-recoverable.
    push(
        F::Specific(S::Panic),
        E::PanicCleared,
        S::Idle,
        vec![A::ResetWatchdog],
        "Recoverable panic cleared — return to Idle.",
    );
    push(
        F::Specific(S::Panic),
        E::PanicCleared,
        S::Halting,
        vec![A::LogPanic, A::StopBlockProduction],
        "Non-recoverable panic — force Halting{Never} at the panic-time height.",
    );

    // ----- Universal: HaltScheduled / Halt -> CoordinatedUpdate -> Idle -----
    push(
        F::Any,
        E::HaltScheduled,
        S::Halting,
        vec![A::StopBlockProduction],
        "Operator scheduled a coordinated halt. \
         (Already-Halting/Panic/ShuttingDown/Evicted sources log-ignore.)",
    );
    push(
        F::Specific(S::Halting),
        E::HaltActivated,
        S::CoordinatedUpdate,
        vec![A::EnterUpdateBarrier],
        "Halt window reached — enter coordinated-update barrier.",
    );
    push(
        F::Specific(S::CoordinatedUpdate),
        E::UpdateQuorumReady,
        S::Idle,
        vec![A::BroadcastReadyOnNewVersion, A::ResetWatchdog],
        "Quorum ready on new protocol version — resume Idle.",
    );

    // ----- Universal: shutdown -----
    push(
        F::Any,
        E::ShutdownRequested,
        S::ShuttingDown,
        vec![A::FlushLogsForShutdown],
        "Operator requested graceful shutdown.",
    );

    // ----- Universal: slashing / eviction -----
    push(
        F::Any,
        E::SlashEvidenceConfirmed,
        S::Slashed,
        vec![A::LeaveActiveSet],
        "Slashable evidence confirmed — leave active set. \
         (Already-Slashed/Evicted/ShuttingDown/Panic sources log-ignore.)",
    );
    push(
        F::Any,
        E::EvictedFromSet,
        S::Evicted,
        vec![A::LeaveActiveSet],
        "Removed from active set. \
         (Already-Evicted/ShuttingDown sources log-ignore.)",
    );
    push(
        F::Specific(S::Slashed),
        E::ReadmittedToSet,
        S::Idle,
        vec![A::RejoinActiveSet],
        "Re-admitted after slashing window closed.",
    );
    push(
        F::Specific(S::Evicted),
        E::ReadmittedToSet,
        S::Idle,
        vec![A::RejoinActiveSet],
        "Re-admitted after re-registration.",
    );

    rules
}

/// All transitions whose `from` matches `state` — both
/// `Specific(state)` rows and `Any` rows.
pub fn transitions_from(state: ValidatorStateKind) -> Vec<TransitionRule> {
    transition_table()
        .into_iter()
        .filter(|r| match r.from {
            FromKind::Specific(s) => s == state,
            FromKind::Any => true,
        })
        .collect()
}

/// All transitions triggered by `event`, regardless of source.
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
                reason: PanicReason::HeartbeatMissed,
                triggered_at: Instant::now(),
                at_height: 0,
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
            EventKind::WatchdogFired => Event::WatchdogFired {
                age_ms: 1,
                fired_at: Instant::now(),
            },
            EventKind::PanicTriggered => Event::PanicTriggered {
                reason: PanicReason::WatchdogExpired,
                triggered_at: Instant::now(),
                at_height: 0,
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

    fn all_state_kinds() -> Vec<ValidatorStateKind> {
        vec![
            ValidatorStateKind::Bootstrapping,
            ValidatorStateKind::CatchingUp,
            ValidatorStateKind::Idle,
            ValidatorStateKind::Proposing,
            ValidatorStateKind::Prevoting,
            ValidatorStateKind::Precommitting,
            ValidatorStateKind::Committed,
            ValidatorStateKind::Rejected,
            ValidatorStateKind::Hung,
            ValidatorStateKind::Halting,
            ValidatorStateKind::CoordinatedUpdate,
            ValidatorStateKind::Slashed,
            ValidatorStateKind::Evicted,
            ValidatorStateKind::Panic,
            ValidatorStateKind::ShuttingDown,
        ]
    }

    fn all_event_kinds() -> Vec<EventKind> {
        vec![
            EventKind::BootstrapComplete,
            EventKind::CaughtUp,
            EventKind::ShutdownRequested,
            EventKind::SelectedAsProposer,
            EventKind::ProposalAdmitted,
            EventKind::PrevoteThresholdReached,
            EventKind::PrecommitThresholdReached,
            EventKind::CommitQuorumReached,
            EventKind::VoteFailed,
            EventKind::Timeout,
            EventKind::WatchdogFired,
            EventKind::PanicTriggered,
            EventKind::PanicCleared,
            EventKind::HaltScheduled,
            EventKind::HaltActivated,
            EventKind::UpdateQuorumReady,
            EventKind::SlashEvidenceConfirmed,
            EventKind::EvictedFromSet,
            EventKind::ReadmittedToSet,
        ]
    }

    /// Forward drift: every row's claimed (to_kind, action_kinds)
    /// matches what `transition()` produces.
    ///
    /// Skips:
    /// - `(Panic, PanicCleared) -> Halting` (covered by `panic_non_recoverable_row`
    ///   below — the test-time representative_state uses a *recoverable*
    ///   reason to exercise the Idle row).
    /// - `Any` rows applied to source states where the universal-event
    ///   guard log-ignores (e.g. `PanicTriggered` from `Panic`).
    #[test]
    fn transition_function_matches_table() {
        for rule in transition_table() {
            // Two rows share (Panic, PanicCleared); skip the Halting one.
            if matches!(rule.from, FromKind::Specific(ValidatorStateKind::Panic))
                && rule.event == EventKind::PanicCleared
                && rule.to == ValidatorStateKind::Halting
            {
                continue;
            }

            let source_kinds: Vec<ValidatorStateKind> = match rule.from {
                FromKind::Specific(k) => vec![k],
                // For Any rows, pick a single source state where the
                // guard does NOT log-ignore (e.g. Idle).  Per-source
                // log-ignore behaviour for Any rows is covered by the
                // reverse drift test.
                FromKind::Any => vec![ValidatorStateKind::Idle],
            };

            for source in source_kinds {
                let state = representative_state(source);
                let event = representative_event(rule.event);
                let (next, actions) = transition(state.clone(), event.clone());

                assert_eq!(
                    next.kind(),
                    rule.to,
                    "[forward drift] from {:?} (source={:?}) via {:?} expected {:?}, got {:?}\n  doc: {}",
                    rule.from,
                    source,
                    rule.event,
                    rule.to,
                    next.kind(),
                    rule.doc,
                );

                let action_kinds: Vec<ActionKind> =
                    actions.iter().map(|a| a.kind()).collect();
                assert_eq!(
                    action_kinds, rule.actions,
                    "[forward drift] from {:?} (source={:?}) via {:?} action mismatch\n  doc: {}",
                    rule.from, source, rule.event, rule.doc,
                );
            }
        }
    }

    /// Reverse drift: walk every (state_kind, event_kind) pair, run
    /// `transition()`, and for every result that produces a
    /// *meaningful* transition (state-kind change OR a non-
    /// `LogIgnoredEvent` action) verify a matching row exists.
    ///
    /// Catches the case where the function adds a new transition the
    /// table author forgot to document.
    #[test]
    fn function_transitions_appear_in_table() {
        let table = transition_table();
        for from_kind in all_state_kinds() {
            for event_kind in all_event_kinds() {
                let state = representative_state(from_kind);
                let event = representative_event(event_kind);
                let (next, actions) = transition(state, event);
                let to_kind = next.kind();

                let meaningful = to_kind != from_kind
                    || actions
                        .iter()
                        .any(|a| !matches!(a, crate::fsm::events::Action::LogIgnoredEvent(_)));
                if !meaningful {
                    continue;
                }

                // Build the action-kind sequence for matching.
                let action_kinds: Vec<ActionKind> =
                    actions.iter().map(|a| a.kind()).collect();

                let has_matching_row = table.iter().any(|r| {
                    let from_matches = match r.from {
                        FromKind::Specific(s) => s == from_kind,
                        FromKind::Any => true,
                    };
                    from_matches
                        && r.event == event_kind
                        && r.to == to_kind
                        && r.actions == action_kinds
                });

                assert!(
                    has_matching_row,
                    "[reverse drift] transition({:?}, {:?}) produced ({:?}, {:?}) \
                     but no table row matches",
                    from_kind, event_kind, to_kind, action_kinds,
                );
            }
        }
    }

    /// Non-recoverable Panic row: PanicCleared from a Panic with a
    /// non-recoverable reason forces Halting{Never} at the panic-
    /// time height.
    #[test]
    fn panic_non_recoverable_row() {
        let state = ValidatorState::Panic {
            reason: PanicReason::DoubleVote,
            triggered_at: Instant::now(),
            at_height: 1234,
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
    fn transitions_from_query_includes_specific_and_any() {
        let from_prevoting = transitions_from(ValidatorStateKind::Prevoting);
        // Specific Prevoting rows: PrevoteThresholdReached, Timeout,
        // WatchdogFired, VoteFailed.
        let specific_count = from_prevoting
            .iter()
            .filter(|r| matches!(r.from, FromKind::Specific(_)))
            .count();
        assert_eq!(specific_count, 4);

        // `Any` rows: PanicTriggered, HaltScheduled, ShutdownRequested,
        // SlashEvidenceConfirmed, EvictedFromSet — should all be visible.
        let any_events: Vec<_> = from_prevoting
            .iter()
            .filter(|r| matches!(r.from, FromKind::Any))
            .map(|r| r.event)
            .collect();
        assert!(any_events.contains(&EventKind::PanicTriggered));
        assert!(any_events.contains(&EventKind::HaltScheduled));
        assert!(any_events.contains(&EventKind::ShutdownRequested));
        assert!(any_events.contains(&EventKind::SlashEvidenceConfirmed));
        assert!(any_events.contains(&EventKind::EvictedFromSet));
    }

    #[test]
    fn transitions_by_event_query_works() {
        let by_timeout = transitions_by_event(EventKind::Timeout);
        // Timeout rows: Proposing, Prevoting, Precommitting, Committed.
        assert_eq!(by_timeout.len(), 4);
    }

    /// Every row's doc string is non-empty.
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
