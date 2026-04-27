//! Total `transition(state, event) -> (next_state, actions)`.
//!
//! Single source of truth for control-flow transitions in the
//! validator FSM. Every `(state, event)` pair maps to exactly one
//! `(next_state, actions)` — no panics, no `unreachable!`, no silent
//! drops. Invalid-but-tolerable arrivals (late vote in `Idle`, etc.)
//! map to `Action::LogIgnoredEvent("…")` so they are explicit.
//!
//! ## Markov chain
//!
//! Pair this with [`super::transition_table`], which exposes the same
//! transitions as a runtime-queryable data structure. Tests verify
//! the match function and the table agree, so they cannot drift.
//!
//! ## Sovereign protocol semantics
//!
//! 4 active phases — Proposing → Prevoting → Precommitting → Committed
//! — with **walk-through timeouts**: every step before `Committed`
//! advances on timeout to the next phase. Only `Committed.Timeout`
//! triggers `Rejected(InsufficientPrecommits)` + view change. This
//! matches the existing engine's `on_round_timeout`.

use crate::fsm::events::{Action, Event};
use crate::fsm::state::{HaltReason, RejectionReason, ResumeCondition, ValidatorState};
use std::time::Instant;

/// Compute the next state and the actions to execute.
///
/// Pure function: no side effects, no panics, no `unreachable!`. The
/// caller (CONS-305 runtime) executes the returned actions in order
/// and feeds the resulting events back in.
pub fn transition(state: ValidatorState, event: Event) -> (ValidatorState, Vec<Action>) {
    use Event::*;
    use ValidatorState::*;

    // Highest-priority cross-cutting events: panic, halt, shutdown,
    // eviction. Handled before phase-specific arms so they win from
    // any active state.
    if let Some(out) = handle_universal(&state, &event) {
        return out;
    }

    match (state.clone(), event) {
        // ============================================================
        // Bootstrapping — first-ever start. Exits to Idle on
        // BootstrapComplete; otherwise events are logged-ignored.
        // ============================================================
        (Bootstrapping, BootstrapComplete) => (Idle, vec![Action::ResetWatchdog]),
        (Bootstrapping, _) => (
            Bootstrapping,
            vec![Action::LogIgnoredEvent("event in Bootstrapping")],
        ),

        // ============================================================
        // CatchingUp — local state behind peers. Exits to Idle on
        // CaughtUp; otherwise events are logged-ignored.
        // ============================================================
        (CatchingUp { .. }, CaughtUp) => (Idle, vec![Action::ResetWatchdog]),
        (CatchingUp { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in CatchingUp")],
        ),

        // ============================================================
        // Idle — between rounds. Proposer-elect → Proposing.
        // ============================================================
        (Idle, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::CreateProposal, Action::ResetWatchdog],
        ),
        (Idle, ProposalAdmitted { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "ProposalAdmitted in Idle: proposer-elect path not yet entered",
            )],
        ),
        (Idle, Timeout) => (
            Idle,
            vec![Action::LogIgnoredEvent("Timeout in Idle: no active phase")],
        ),
        (Idle, WatchdogFired { .. }) => (
            Hung {
                since: Instant::now(),
                prior_state: Box::new(Idle),
            },
            vec![Action::LogHung {
                reason: "Watchdog fired while Idle — runtime stuck before round start",
            }],
        ),
        (Idle, _) => (
            Idle,
            vec![Action::LogIgnoredEvent("event in Idle (unrelated)")],
        ),

        // ============================================================
        // Proposing — leader's window. ProposalAdmitted → Prevoting.
        // Timeout walks forward to Prevoting.
        // ============================================================
        (Proposing, ProposalAdmitted { id, .. }) => (
            Prevoting,
            vec![
                Action::BroadcastProposal { id: id.clone() },
                Action::SendPrevote { block_id: id },
                Action::ResetWatchdog,
            ],
        ),
        (Proposing, Timeout) => (Prevoting, vec![Action::ResetWatchdog]),
        (Proposing, VoteFailed(reason)) => (
            Rejected {
                reason,
                round: 0, // runtime fills in current_round on entry
            },
            vec![Action::AdvanceRound],
        ),
        (Proposing, WatchdogFired { .. }) => (
            Hung {
                since: Instant::now(),
                prior_state: Box::new(Proposing),
            },
            vec![Action::LogHung {
                reason: "Watchdog fired while Proposing — proposer or network stuck",
            }],
        ),
        (Proposing, _) => (
            Proposing,
            vec![Action::LogIgnoredEvent("event in Proposing (out-of-phase)")],
        ),

        // ============================================================
        // Prevoting — gathering PreVotes. PrevoteThresholdReached →
        // Precommitting (send precommit). Timeout walks to Precommitting.
        // ============================================================
        (Prevoting, PrevoteThresholdReached { block_id }) => (
            Precommitting,
            vec![
                Action::SendPrecommit { block_id },
                Action::ResetWatchdog,
            ],
        ),
        (Prevoting, Timeout) => (Precommitting, vec![Action::ResetWatchdog]),
        (Prevoting, VoteFailed(reason)) => (
            Rejected { reason, round: 0 },
            vec![Action::AdvanceRound],
        ),
        (Prevoting, WatchdogFired { .. }) => (
            Hung {
                since: Instant::now(),
                prior_state: Box::new(Prevoting),
            },
            vec![Action::LogHung {
                reason: "Watchdog fired while Prevoting — vote pool stuck",
            }],
        ),
        (Prevoting, _) => (
            Prevoting,
            vec![Action::LogIgnoredEvent("event in Prevoting (out-of-phase)")],
        ),

        // ============================================================
        // Precommitting — gathering PreCommits, then Commit votes.
        // Two events advance through this phase:
        //   PrecommitThresholdReached → send commit vote, stay
        //   CommitQuorumReached → finalize, transition to Committed
        // ============================================================
        (Precommitting, PrecommitThresholdReached { block_id }) => (
            Precommitting,
            vec![
                Action::SendCommit { block_id },
                Action::ResetWatchdog,
            ],
        ),
        (
            Precommitting,
            CommitQuorumReached {
                block_id,
                quorum,
            },
        ) => (
            Committed {
                block_hash: block_id.0,
                height: quorum.height,
            },
            vec![
                Action::CommitBlock {
                    id: block_id,
                    quorum,
                },
                Action::ResetWatchdog,
            ],
        ),
        // Walk-through Timeout. View-change happens at Committed.Timeout,
        // not here — the existing engine progresses to "Commit step"
        // on PreCommit timeout, gathering commit votes anyway.
        (Precommitting, Timeout) => (Precommitting, vec![Action::ResetWatchdog]),
        (Precommitting, VoteFailed(reason)) => (
            Rejected { reason, round: 0 },
            vec![Action::AdvanceRound],
        ),
        (Precommitting, WatchdogFired { .. }) => (
            Hung {
                since: Instant::now(),
                prior_state: Box::new(Precommitting),
            },
            vec![Action::LogHung {
                reason: "Watchdog fired while Precommitting — quorum stuck",
            }],
        ),
        (Precommitting, _) => (
            Precommitting,
            vec![Action::LogIgnoredEvent(
                "event in Precommitting (out-of-phase)",
            )],
        ),

        // ============================================================
        // Committed — block finalized at this height. The runtime
        // advances to next height; further events at this height are
        // logged-ignored. SelectedAsProposer at next height triggers
        // the Idle path on round-entry (runtime resets to Idle).
        // ============================================================
        (Committed { .. }, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::CreateProposal, Action::ResetWatchdog],
        ),
        (Committed { .. }, Timeout) => (
            Rejected {
                reason: RejectionReason::InsufficientPrecommits,
                round: 0,
            },
            vec![Action::AdvanceRound],
        ),
        (
            Committed { .. },
            ProposalAdmitted {
                id, height, round,
            },
        ) => (
            // Next height arrived — re-enter Proposing then immediately
            // admit. (Engine resets the round struct on its side.)
            Proposing,
            vec![
                Action::BroadcastProposal { id: id.clone() },
                Action::SendPrevote { block_id: id },
                Action::ResetWatchdog,
                Action::LogIgnoredEvent("auto-rolled Committed→Proposing"),
                // height/round logged for diagnostics
                Action::LogIgnoredEvent(if height > 0 || round > 0 {
                    "next-height entry"
                } else {
                    "next-height entry (zero)"
                }),
            ],
        ),
        (Committed { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Committed")],
        ),

        // ============================================================
        // Rejected — runtime emitted AdvanceRound; events arriving
        // before the next round entry are logged-ignored.
        // ============================================================
        (Rejected { .. }, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::CreateProposal, Action::ResetWatchdog],
        ),
        (Rejected { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Rejected")],
        ),

        // ============================================================
        // Hung — terminal until external recovery.
        // ============================================================
        (Hung { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Hung")],
        ),

        // ============================================================
        // Halting — block production stopped. Exit on HaltActivated
        // (transition to CoordinatedUpdate).
        // ============================================================
        (
            Halting { .. },
            HaltActivated {
                activate_at_height,
                target_version,
            },
        ) => (
            CoordinatedUpdate {
                activate_at_height,
                target_version,
            },
            vec![Action::EnterUpdateBarrier {
                activate_at_height,
                target_version,
            }],
        ),
        (Halting { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Halting")],
        ),

        // ============================================================
        // CoordinatedUpdate — barrier; new binary running, awaiting
        // quorum-ready. UpdateQuorumReady → Idle (next round on the
        // new protocol version).
        // ============================================================
        (
            CoordinatedUpdate {
                target_version, ..
            },
            UpdateQuorumReady,
        ) => (
            Idle,
            vec![
                Action::BroadcastReadyOnNewVersion {
                    version: target_version,
                },
                Action::ResetWatchdog,
            ],
        ),
        (CoordinatedUpdate { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in CoordinatedUpdate")],
        ),

        // ============================================================
        // Slashed — out of active set. Re-enter on ReadmittedToSet.
        // ============================================================
        (Slashed { .. }, ReadmittedToSet) => (Idle, vec![Action::RejoinActiveSet]),
        (Slashed { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Slashed")],
        ),

        // ============================================================
        // Evicted — terminal until re-admission.
        // ============================================================
        (Evicted, ReadmittedToSet) => (Idle, vec![Action::RejoinActiveSet]),
        (Evicted, _) => (Evicted, vec![Action::LogIgnoredEvent("event in Evicted")]),

        // ============================================================
        // Panic — recoverable reasons reset to Idle on PanicCleared;
        // non-recoverable reasons force Halting{Never}. Catch the
        // PanicCleared event here; non-recoverable transitions are
        // emitted via PanicTriggered handling in handle_universal.
        // ============================================================
        (Panic { reason, .. }, PanicCleared) => {
            if reason.is_recoverable() {
                (Idle, vec![Action::ResetWatchdog])
            } else {
                (
                    Halting {
                        reason: HaltReason::EmergencyHalt,
                        triggered_at_height: 0,
                        last_block_hash: None,
                        resume_condition: ResumeCondition::Never,
                    },
                    vec![
                        Action::LogPanic { reason },
                        Action::StopBlockProduction { at_height: 0 },
                    ],
                )
            }
        }
        (Panic { .. }, _) => (
            state,
            vec![Action::LogIgnoredEvent("event in Panic")],
        ),

        // ============================================================
        // ShuttingDown — terminal. All events logged-ignored.
        // ============================================================
        (ShuttingDown, _) => (
            ShuttingDown,
            vec![Action::LogIgnoredEvent("event in ShuttingDown")],
        ),
    }
}

/// Cross-cutting events that override phase-specific transitions.
/// Returns `Some` if the event was handled here, `None` if the main
/// `match` should run.
fn handle_universal(
    state: &ValidatorState,
    event: &Event,
) -> Option<(ValidatorState, Vec<Action>)> {
    use Event::*;
    use ValidatorState::*;

    match event {
        // PanicTriggered — recoverable: enter Panic; non-recoverable:
        // enter Panic and the runtime should observe the reason and
        // emit PanicCleared (which then routes to Halting{Never}).
        PanicTriggered { reason } => {
            // Don't re-enter Panic from Panic / Halting / ShuttingDown.
            if matches!(state, Panic { .. } | Halting { .. } | ShuttingDown) {
                return Some((
                    state.clone(),
                    vec![Action::LogIgnoredEvent(
                        "PanicTriggered while already in critical state",
                    )],
                ));
            }
            Some((
                Panic {
                    reason: reason.clone(),
                    triggered_at: Instant::now(),
                    prior_state: Box::new(state.clone()),
                },
                vec![
                    Action::BroadcastPanic {
                        reason: reason.clone(),
                    },
                    Action::LogPanic {
                        reason: reason.clone(),
                    },
                ],
            ))
        }

        // HaltScheduled — accepted from any active consensus state.
        // Already-halted / panicked / shutting-down ignore.
        HaltScheduled {
            reason,
            triggered_at_height,
            resume_condition,
        } => {
            if matches!(state, Halting { .. } | Panic { .. } | ShuttingDown | Evicted) {
                return Some((
                    state.clone(),
                    vec![Action::LogIgnoredEvent(
                        "HaltScheduled while already halting/panicked/exiting",
                    )],
                ));
            }
            // Capture last_block_hash if we're in Committed.
            let last_block_hash = if let Committed { block_hash, .. } = state {
                Some(*block_hash)
            } else {
                None
            };
            Some((
                Halting {
                    reason: *reason,
                    triggered_at_height: *triggered_at_height,
                    last_block_hash,
                    resume_condition: ResumeCondition::from(*resume_condition),
                },
                vec![Action::StopBlockProduction {
                    at_height: *triggered_at_height,
                }],
            ))
        }

        // ShutdownRequested — accepted from any state. Always
        // transitions to ShuttingDown and flushes logs.
        ShutdownRequested => Some((
            ShuttingDown,
            vec![Action::FlushLogsForShutdown],
        )),

        // SlashEvidenceConfirmed — accepted from any active state.
        SlashEvidenceConfirmed { reason } => {
            if matches!(
                state,
                Slashed { .. } | Evicted | ShuttingDown | Panic { .. }
            ) {
                return Some((
                    state.clone(),
                    vec![Action::LogIgnoredEvent(
                        "SlashEvidenceConfirmed while already slashed/exiting",
                    )],
                ));
            }
            Some((
                Slashed { reason: *reason },
                vec![Action::LeaveActiveSet],
            ))
        }

        // EvictedFromSet — terminal-ish.
        EvictedFromSet => {
            if matches!(state, Evicted | ShuttingDown) {
                return Some((
                    state.clone(),
                    vec![Action::LogIgnoredEvent("EvictedFromSet while already out")],
                ));
            }
            Some((Evicted, vec![Action::LeaveActiveSet]))
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::events::ResumeConditionEvent;
    use crate::fsm::state::{PanicReason, SlashReason};
    use lib_crypto::Hash;
    use lib_types::consensus::BftQuorumProof;

    fn dummy_quorum() -> BftQuorumProof {
        BftQuorumProof {
            height: 7,
            proposal_id: [0u8; 32],
            total_validators: 0,
            attestations: Vec::new(),
        }
    }

    /// Happy path: Idle → Proposing → Prevoting → Precommitting →
    /// Committed → (next round) Proposing.
    #[test]
    fn happy_path_round_completes() {
        let block_id = Hash([42u8; 32]);

        let (s, a) = transition(
            ValidatorState::Idle,
            Event::SelectedAsProposer { height: 1, round: 0 },
        );
        assert_eq!(s, ValidatorState::Proposing);
        assert!(a.contains(&Action::CreateProposal));

        let (s, _) = transition(
            s,
            Event::ProposalAdmitted {
                id: block_id.clone(),
                height: 1,
                round: 0,
            },
        );
        assert_eq!(s, ValidatorState::Prevoting);

        let (s, _) = transition(
            s,
            Event::PrevoteThresholdReached {
                block_id: block_id.clone(),
            },
        );
        assert_eq!(s, ValidatorState::Precommitting);

        let (s, _) = transition(
            s,
            Event::PrecommitThresholdReached {
                block_id: block_id.clone(),
            },
        );
        assert_eq!(s, ValidatorState::Precommitting); // stays for commit-vote gathering

        let (s, a) = transition(
            s,
            Event::CommitQuorumReached {
                block_id: block_id.clone(),
                quorum: dummy_quorum(),
            },
        );
        assert!(matches!(s, ValidatorState::Committed { .. }));
        assert!(a.iter().any(|x| matches!(x, Action::CommitBlock { .. })));
    }

    /// Walk-through timeouts: Proposing → Prevoting → Precommitting,
    /// each by a Timeout. Committed.Timeout view-changes.
    #[test]
    fn timeouts_walk_through_phases() {
        let (s, _) = transition(ValidatorState::Proposing, Event::Timeout);
        assert_eq!(s, ValidatorState::Prevoting);

        let (s, _) = transition(ValidatorState::Prevoting, Event::Timeout);
        assert_eq!(s, ValidatorState::Precommitting);

        let (s, _) = transition(ValidatorState::Precommitting, Event::Timeout);
        // Precommitting.Timeout is walk-forward (engine progresses to
        // Commit step which is folded into Precommitting in this FSM).
        assert_eq!(s, ValidatorState::Precommitting);
    }

    #[test]
    fn committed_timeout_is_view_change() {
        let (s, a) = transition(
            ValidatorState::Committed {
                block_hash: [1u8; 32],
                height: 1,
            },
            Event::Timeout,
        );
        assert!(matches!(
            s,
            ValidatorState::Rejected {
                reason: RejectionReason::InsufficientPrecommits,
                ..
            }
        ));
        assert!(a.contains(&Action::AdvanceRound));
    }

    #[test]
    fn watchdog_from_active_states_hangs() {
        for state in [
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
        ] {
            let (s, a) = transition(state, Event::WatchdogFired { age_ms: 30_000 });
            assert!(matches!(s, ValidatorState::Hung { .. }));
            assert!(a.iter().any(|x| matches!(x, Action::LogHung { .. })));
        }
    }

    #[test]
    fn panic_recoverable_resets_to_idle_on_clear() {
        let (s, _) = transition(
            ValidatorState::Prevoting,
            Event::PanicTriggered {
                reason: PanicReason::HeartbeatMissed,
            },
        );
        assert!(matches!(s, ValidatorState::Panic { .. }));
        let (s, _) = transition(s, Event::PanicCleared);
        assert_eq!(s, ValidatorState::Idle);
    }

    #[test]
    fn panic_non_recoverable_forces_halting_never() {
        let (s, _) = transition(
            ValidatorState::Prevoting,
            Event::PanicTriggered {
                reason: PanicReason::DoubleVote,
            },
        );
        assert!(matches!(s, ValidatorState::Panic { .. }));
        let (s, _) = transition(s, Event::PanicCleared);
        assert!(matches!(
            s,
            ValidatorState::Halting {
                resume_condition: ResumeCondition::Never,
                ..
            }
        ));
    }

    #[test]
    fn panic_broadcasts_to_peers_for_logs() {
        let (_, a) = transition(
            ValidatorState::Prevoting,
            Event::PanicTriggered {
                reason: PanicReason::ByzantineVoteDetected,
            },
        );
        assert!(a.iter().any(|x| matches!(x, Action::BroadcastPanic { .. })));
    }

    #[test]
    fn halt_to_coordinated_update_to_idle_flow() {
        let (s, _) = transition(
            ValidatorState::Idle,
            Event::HaltScheduled {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 100,
                resume_condition: ResumeConditionEvent::QuorumReady,
            },
        );
        assert!(matches!(s, ValidatorState::Halting { .. }));

        let (s, _) = transition(
            s,
            Event::HaltActivated {
                activate_at_height: 100,
                target_version: 2,
            },
        );
        assert!(matches!(s, ValidatorState::CoordinatedUpdate { .. }));

        let (s, a) = transition(s, Event::UpdateQuorumReady);
        assert_eq!(s, ValidatorState::Idle);
        assert!(a
            .iter()
            .any(|x| matches!(x, Action::BroadcastReadyOnNewVersion { .. })));
    }

    #[test]
    fn shutdown_from_any_state() {
        for state in [
            ValidatorState::Idle,
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
            ValidatorState::Committed {
                block_hash: [0; 32],
                height: 1,
            },
            ValidatorState::Bootstrapping,
            ValidatorState::CatchingUp {
                from_height: 0,
                to_height: 1,
            },
        ] {
            let (s, a) = transition(state.clone(), Event::ShutdownRequested);
            assert_eq!(s, ValidatorState::ShuttingDown, "from {:?}", state);
            assert!(a.contains(&Action::FlushLogsForShutdown));
        }
    }

    #[test]
    fn slashing_leaves_set_and_rejoin_returns_to_idle() {
        let (s, a) = transition(
            ValidatorState::Prevoting,
            Event::SlashEvidenceConfirmed {
                reason: SlashReason::DoubleSign,
            },
        );
        assert!(matches!(s, ValidatorState::Slashed { .. }));
        assert!(a.contains(&Action::LeaveActiveSet));

        let (s, a) = transition(s, Event::ReadmittedToSet);
        assert_eq!(s, ValidatorState::Idle);
        assert!(a.contains(&Action::RejoinActiveSet));
    }

    #[test]
    fn bootstrapping_exits_on_complete() {
        let (s, _) = transition(ValidatorState::Bootstrapping, Event::BootstrapComplete);
        assert_eq!(s, ValidatorState::Idle);
    }

    #[test]
    fn catching_up_exits_on_caught_up() {
        let (s, _) = transition(
            ValidatorState::CatchingUp {
                from_height: 0,
                to_height: 100,
            },
            Event::CaughtUp,
        );
        assert_eq!(s, ValidatorState::Idle);
    }

    /// Totality: every (state_kind, event_kind) pair returns a
    /// non-empty action list. Sample one variant per kind.
    #[test]
    fn transition_total_no_silent_drops() {
        let states = [
            ValidatorState::Bootstrapping,
            ValidatorState::CatchingUp {
                from_height: 0,
                to_height: 1,
            },
            ValidatorState::Idle,
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
            ValidatorState::Committed {
                block_hash: [0; 32],
                height: 1,
            },
            ValidatorState::Rejected {
                reason: RejectionReason::Timeout,
                round: 0,
            },
            ValidatorState::Hung {
                since: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorState::Halting {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 0,
                last_block_hash: None,
                resume_condition: ResumeCondition::QuorumReady,
            },
            ValidatorState::CoordinatedUpdate {
                activate_at_height: 0,
                target_version: 2,
            },
            ValidatorState::Slashed {
                reason: SlashReason::DoubleSign,
            },
            ValidatorState::Evicted,
            ValidatorState::Panic {
                reason: PanicReason::HeartbeatMissed,
                triggered_at: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorState::ShuttingDown,
        ];

        let events = [
            Event::BootstrapComplete,
            Event::CaughtUp,
            Event::ShutdownRequested,
            Event::SelectedAsProposer { height: 1, round: 0 },
            Event::ProposalAdmitted {
                id: Hash([0; 32]),
                height: 1,
                round: 0,
            },
            Event::PrevoteThresholdReached {
                block_id: Hash([0; 32]),
            },
            Event::PrecommitThresholdReached {
                block_id: Hash([0; 32]),
            },
            Event::CommitQuorumReached {
                block_id: Hash([0; 32]),
                quorum: dummy_quorum(),
            },
            Event::VoteFailed(RejectionReason::Timeout),
            Event::Timeout,
            Event::WatchdogFired { age_ms: 1 },
            Event::PanicTriggered {
                reason: PanicReason::WatchdogExpired,
            },
            Event::PanicCleared,
            Event::HaltScheduled {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 0,
                resume_condition: ResumeConditionEvent::QuorumReady,
            },
            Event::HaltActivated {
                activate_at_height: 0,
                target_version: 2,
            },
            Event::UpdateQuorumReady,
            Event::SlashEvidenceConfirmed {
                reason: SlashReason::DoubleSign,
            },
            Event::EvictedFromSet,
            Event::ReadmittedToSet,
        ];

        for state in &states {
            for event in &events {
                let (_next, actions) = transition(state.clone(), event.clone());
                assert!(
                    !actions.is_empty(),
                    "transition({:?}, {:?}) returned no actions",
                    state.kind(),
                    event.kind()
                );
            }
        }
    }
}
