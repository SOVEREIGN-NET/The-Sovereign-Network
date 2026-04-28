//! Total `transition(state, event) -> (next_state, actions)`.
//!
//! Single source of truth for control-flow transitions in the
//! validator FSM. Every `(state, event)` pair maps to exactly one
//! `(next_state, actions)` — no panics, no `unreachable!`, no silent
//! drops. Invalid-but-tolerable arrivals (late vote in `Idle`, etc.)
//! map to `Action::LogIgnoredEvent("…")` so they are explicit.
//!
//! ## Pure function, no clock access
//!
//! `transition()` reads no wall clock. Timestamps that flow into
//! `Hung.since` and `Panic.triggered_at` come from the event payload
//! (`WatchdogFired { fired_at }`, `PanicTriggered { triggered_at }`)
//! — the runtime captures them at firing time. PR #2394 review
//! (Copilot) flagged the prior `Instant::now()` calls inside
//! `transition()` as breaking the deterministic / pure contract.
//!
//! ## Markov chain
//!
//! Pair this with [`super::transition_table`], which exposes the
//! same transitions as a runtime-queryable data structure. Tests
//! verify the match function and the table agree, so they cannot
//! drift.
//!
//! ## Sovereign protocol semantics
//!
//! 4 active phases — Proposing → Prevoting → Precommitting →
//! Committed — with **walk-through timeouts**: every step before
//! `Committed` advances on timeout to the next phase. Only
//! `Committed.Timeout` triggers `Rejected(InsufficientPrecommits)` +
//! view change. Matches the existing engine's `on_round_timeout`.

use crate::fsm::events::{Action, Event};
use crate::fsm::state::{
    HaltReason, RejectionReason, ResumeCondition, ValidatorState,
};

/// Compute the next state and the actions to execute.
///
/// Pure function: no side effects, no panics, no `unreachable!`, no
/// clock access. The caller (CONS-305 runtime) executes the returned
/// actions in order and feeds the resulting events back in.
pub fn transition(state: ValidatorState, event: Event) -> (ValidatorState, Vec<Action>) {
    use Event::*;
    use ValidatorState::*;

    match (state, event) {
        // ============================================================
        // Universal events — handled before phase-specific arms so
        // they win from any active state. The order in this match
        // matters: more-specific patterns (e.g. excluded states for
        // PanicTriggered) come before catch-all bindings.
        // ============================================================

        // PanicTriggered: from already-critical states, log and ignore.
        (
            state @ (Panic { .. } | Halting { .. } | ShuttingDown),
            PanicTriggered { .. },
        ) => (
            state,
            vec![Action::LogIgnoredEvent(
                "PanicTriggered while already in critical state",
            )],
        ),
        // PanicTriggered from any other state: enter Panic carrying
        // the prior state, the runtime-captured `triggered_at`, and
        // the current `at_height` so the non-recoverable
        // `(Panic, PanicCleared)` arm can construct a real Halting.
        (
            state,
            PanicTriggered {
                reason,
                triggered_at,
                at_height,
            },
        ) if !matches!(state, Idle | Bootstrapping | CatchingUp { .. }) // any non-trivial state
            || matches!(state, Idle | Bootstrapping | CatchingUp { .. })
        => {
            // Above guard is intentionally `true` for every value of
            // `state` — Rust requires guards on the catch-all arm
            // when other arms with binding patterns are present.
            (
                Panic {
                    reason: reason.clone(),
                    triggered_at,
                    at_height,
                    prior_state: Box::new(state),
                },
                vec![
                    Action::BroadcastPanic {
                        reason: reason.clone(),
                    },
                    Action::LogPanic { reason },
                ],
            )
        }

        // HaltScheduled: from already-halted/panicked/exited, log+ignore.
        (
            state @ (Halting { .. } | Panic { .. } | ShuttingDown | Evicted),
            HaltScheduled { .. },
        ) => (
            state,
            vec![Action::LogIgnoredEvent(
                "HaltScheduled while already halting/panicked/exiting",
            )],
        ),
        // HaltScheduled from any other state. Capture last_block_hash
        // from Committed (if applicable) so operators can correlate
        // the halt with the last finalized block.
        (
            state,
            HaltScheduled {
                reason,
                triggered_at_height,
                resume_condition,
            },
        ) => {
            let last_block_hash = if let Committed { block_hash, .. } = &state {
                Some(*block_hash)
            } else {
                None
            };
            let _ = state; // explicitly drop the prior state
            (
                Halting {
                    reason,
                    triggered_at_height,
                    last_block_hash,
                    resume_condition: ResumeCondition::from(resume_condition),
                },
                vec![Action::StopBlockProduction {
                    at_height: triggered_at_height,
                }],
            )
        }

        // ShutdownRequested: accepted from any state.
        (_state, ShutdownRequested) => {
            (ShuttingDown, vec![Action::FlushLogsForShutdown])
        }

        // SlashEvidenceConfirmed: from already-slashed/exited, log+ignore.
        (
            state @ (Slashed { .. } | Evicted | ShuttingDown | Panic { .. }),
            SlashEvidenceConfirmed { .. },
        ) => (
            state,
            vec![Action::LogIgnoredEvent(
                "SlashEvidenceConfirmed while already slashed/exiting",
            )],
        ),
        (_state, SlashEvidenceConfirmed { reason }) => {
            (Slashed { reason }, vec![Action::LeaveActiveSet])
        }

        // EvictedFromSet: from already-out, log+ignore.
        (state @ (Evicted | ShuttingDown), EvictedFromSet) => (
            state,
            vec![Action::LogIgnoredEvent("EvictedFromSet while already out")],
        ),
        (_state, EvictedFromSet) => (Evicted, vec![Action::LeaveActiveSet]),

        // ============================================================
        // Bootstrapping
        // ============================================================
        (Bootstrapping, BootstrapComplete) => (Idle, vec![Action::ResetWatchdog]),
        (Bootstrapping, _) => (
            Bootstrapping,
            vec![Action::LogIgnoredEvent("event in Bootstrapping")],
        ),

        // ============================================================
        // CatchingUp
        // ============================================================
        (CatchingUp { .. }, CaughtUp) => (Idle, vec![Action::ResetWatchdog]),
        (catching @ CatchingUp { .. }, _) => (
            catching,
            vec![Action::LogIgnoredEvent("event in CatchingUp")],
        ),

        // ============================================================
        // Idle
        // ============================================================
        (Idle, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::CreateProposal, Action::ResetWatchdog],
        ),
        (Idle, ProposalAdmitted { .. }) => (
            // Stay Idle until the runtime drives proposer election.
            // PR #2394 reverse-drift test caught the prior version
            // transitioning state on a logged-ignored action — a
            // contradiction between state change and "this event had
            // no effect" semantics.
            Idle,
            vec![Action::LogIgnoredEvent(
                "ProposalAdmitted in Idle: proposer-elect path not yet entered",
            )],
        ),
        (Idle, Timeout) => (
            Idle,
            vec![Action::LogIgnoredEvent("Timeout in Idle: no active phase")],
        ),
        (Idle, WatchdogFired { fired_at, .. }) => (
            Hung {
                since: fired_at,
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
        // Proposing
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
            Rejected { reason, round: 0 }, // runtime fills round on entry
            vec![
                Action::LogRoundRejected { reason },
                Action::AdvanceRound,
            ],
        ),
        (Proposing, WatchdogFired { fired_at, .. }) => (
            Hung {
                since: fired_at,
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
        // Prevoting
        // ============================================================
        (Prevoting, PrevoteThresholdReached { block_id }) => (
            Precommitting,
            vec![Action::SendPrecommit { block_id }, Action::ResetWatchdog],
        ),
        (Prevoting, Timeout) => (Precommitting, vec![Action::ResetWatchdog]),
        (Prevoting, VoteFailed(reason)) => (
            Rejected { reason, round: 0 },
            vec![
                Action::LogRoundRejected { reason },
                Action::AdvanceRound,
            ],
        ),
        (Prevoting, WatchdogFired { fired_at, .. }) => (
            Hung {
                since: fired_at,
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
        // ============================================================
        // Late prevote quorum (#2405): runtime walked PreVote → PreCommit
        // on timeout BEFORE the prevote quorum arrived; a subsequent
        // late prevote completing the quorum lands here. Emit
        // SendPrecommit so the late case still casts a precommit.
        (Precommitting, PrevoteThresholdReached { block_id }) => (
            Precommitting,
            vec![
                Action::SendPrecommit { block_id },
                Action::ResetWatchdog,
            ],
        ),
        (Precommitting, PrecommitThresholdReached { block_id }) => (
            Precommitting,
            vec![Action::SendCommit { block_id }, Action::ResetWatchdog],
        ),
        (Precommitting, CommitQuorumReached { block_id, quorum }) => (
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
        (Precommitting, Timeout) => (Precommitting, vec![Action::ResetWatchdog]),
        (Precommitting, VoteFailed(reason)) => (
            Rejected { reason, round: 0 },
            vec![
                Action::LogRoundRejected { reason },
                Action::AdvanceRound,
            ],
        ),
        (Precommitting, WatchdogFired { fired_at, .. }) => (
            Hung {
                since: fired_at,
                prior_state: Box::new(Precommitting),
            },
            vec![Action::LogHung {
                reason: "Watchdog fired while Precommitting — quorum stuck",
            }],
        ),
        (Precommitting, _) => (
            Precommitting,
            vec![Action::LogIgnoredEvent("event in Precommitting (out-of-phase)")],
        ),

        // ============================================================
        // Committed — block finalized at this height. The runtime
        // resets the FSM to Idle (next height entry) explicitly; this
        // FSM doesn't auto-transition. PR #2394 review removed an
        // earlier `(Committed, ProposalAdmitted) → Proposing` shortcut
        // that bypassed runtime state-management for the height bump.
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
            vec![
                Action::LogRoundRejected {
                    reason: RejectionReason::InsufficientPrecommits,
                },
                Action::AdvanceRound,
            ],
        ),
        // Late precommit quorum (#2405): wire-level Commit step (the
        // bridge maps that to FSM Committed) gathered enough
        // precommits late. Emit SendCommit so the late case still
        // casts our commit vote.
        (committed @ Committed { .. }, PrecommitThresholdReached { block_id }) => (
            committed,
            vec![Action::SendCommit { block_id }, Action::ResetWatchdog],
        ),
        (committed @ Committed { .. }, _) => (
            committed,
            vec![Action::LogIgnoredEvent(
                "event in Committed (runtime resets to Idle for next height)",
            )],
        ),

        // ============================================================
        // Rejected — runtime emits AdvanceRound on entry; events
        // arriving before next round entry are logged-ignored.
        // ============================================================
        (Rejected { .. }, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::CreateProposal, Action::ResetWatchdog],
        ),
        (rejected @ Rejected { .. }, _) => (
            rejected,
            vec![Action::LogIgnoredEvent("event in Rejected")],
        ),

        // ============================================================
        // Hung — terminal until external recovery.
        // ============================================================
        (hung @ Hung { .. }, _) => (hung, vec![Action::LogIgnoredEvent("event in Hung")]),

        // ============================================================
        // Halting → CoordinatedUpdate
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
        (halting @ Halting { .. }, _) => (
            halting,
            vec![Action::LogIgnoredEvent("event in Halting")],
        ),

        // ============================================================
        // CoordinatedUpdate → Idle on quorum-ready
        // ============================================================
        (CoordinatedUpdate { target_version, .. }, UpdateQuorumReady) => (
            Idle,
            vec![
                Action::BroadcastReadyOnNewVersion {
                    version: target_version,
                },
                Action::ResetWatchdog,
            ],
        ),
        (cu @ CoordinatedUpdate { .. }, _) => (
            cu,
            vec![Action::LogIgnoredEvent("event in CoordinatedUpdate")],
        ),

        // ============================================================
        // Slashed — re-enter on ReadmittedToSet.
        // ============================================================
        (Slashed { .. }, ReadmittedToSet) => (Idle, vec![Action::RejoinActiveSet]),
        (slashed @ Slashed { .. }, _) => (
            slashed,
            vec![Action::LogIgnoredEvent("event in Slashed")],
        ),

        // ============================================================
        // Evicted — re-enter on ReadmittedToSet.
        // ============================================================
        (Evicted, ReadmittedToSet) => (Idle, vec![Action::RejoinActiveSet]),
        (Evicted, _) => (Evicted, vec![Action::LogIgnoredEvent("event in Evicted")]),

        // ============================================================
        // Panic — recoverable resets to Idle on PanicCleared;
        // non-recoverable forces Halting{Never} at the panic-time
        // height, with last_block_hash recovered from prior_state if
        // we panicked from Committed.
        // ============================================================
        (
            Panic {
                reason,
                at_height,
                prior_state,
                ..
            },
            PanicCleared,
        ) => {
            if reason.is_recoverable() {
                (Idle, vec![Action::ResetWatchdog])
            } else {
                let last_block_hash = if let Committed { block_hash, .. } = prior_state.as_ref() {
                    Some(*block_hash)
                } else {
                    None
                };
                (
                    Halting {
                        reason: HaltReason::EmergencyHalt,
                        triggered_at_height: at_height,
                        last_block_hash,
                        resume_condition: ResumeCondition::Never,
                    },
                    vec![
                        Action::LogPanic { reason },
                        Action::StopBlockProduction { at_height },
                    ],
                )
            }
        }
        (panic_state @ Panic { .. }, _) => (
            panic_state,
            vec![Action::LogIgnoredEvent("event in Panic")],
        ),

        // ============================================================
        // ShuttingDown — terminal.
        // ============================================================
        (ShuttingDown, _) => (
            ShuttingDown,
            vec![Action::LogIgnoredEvent("event in ShuttingDown")],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::events::ResumeConditionEvent;
    use crate::fsm::state::{PanicReason, SlashReason};
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

    fn dummy_watchdog() -> Event {
        Event::WatchdogFired {
            age_ms: 30_000,
            fired_at: Instant::now(),
        }
    }

    fn dummy_panic(reason: PanicReason) -> Event {
        Event::PanicTriggered {
            reason,
            triggered_at: Instant::now(),
            at_height: 100,
        }
    }

    /// Happy path: Idle → Proposing → Prevoting → Precommitting → Committed.
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
        assert_eq!(s, ValidatorState::Precommitting);

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

    #[test]
    fn timeouts_walk_through_phases() {
        let (s, _) = transition(ValidatorState::Proposing, Event::Timeout);
        assert_eq!(s, ValidatorState::Prevoting);

        let (s, _) = transition(ValidatorState::Prevoting, Event::Timeout);
        assert_eq!(s, ValidatorState::Precommitting);

        let (s, _) = transition(ValidatorState::Precommitting, Event::Timeout);
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

    /// PR #2394 review: ProposalAdmitted in Committed must NOT
    /// auto-transition to Proposing. The runtime resets to Idle for
    /// the next height; this FSM logs and ignores.
    #[test]
    fn committed_proposal_admitted_is_logged_ignored() {
        let (s, a) = transition(
            ValidatorState::Committed {
                block_hash: [1u8; 32],
                height: 1,
            },
            Event::ProposalAdmitted {
                id: Hash([2u8; 32]),
                height: 2,
                round: 0,
            },
        );
        assert!(matches!(s, ValidatorState::Committed { .. }));
        assert!(a.iter().all(|x| matches!(x, Action::LogIgnoredEvent(_))));
    }

    #[test]
    fn watchdog_from_active_states_hangs_with_event_timestamp() {
        let fired_at = Instant::now();
        for state in [
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
        ] {
            let (s, a) = transition(
                state,
                Event::WatchdogFired {
                    age_ms: 30_000,
                    fired_at,
                },
            );
            // The Hung state's `since` came from the event payload,
            // not Instant::now() inside transition.
            if let ValidatorState::Hung { since, .. } = s {
                assert_eq!(since, fired_at);
            } else {
                panic!("expected Hung, got {:?}", s);
            }
            assert!(a.iter().any(|x| matches!(x, Action::LogHung { .. })));
        }
    }

    #[test]
    fn panic_recoverable_resets_to_idle_on_clear() {
        let (s, _) = transition(
            ValidatorState::Prevoting,
            dummy_panic(PanicReason::HeartbeatMissed),
        );
        assert!(matches!(s, ValidatorState::Panic { .. }));
        let (s, _) = transition(s, Event::PanicCleared);
        assert_eq!(s, ValidatorState::Idle);
    }

    /// Non-recoverable panic forces `Halting{Never}` at the panic-
    /// time height (PR #2394 review: prior placeholder of 0 lost
    /// height context).
    #[test]
    fn panic_non_recoverable_forces_halting_at_correct_height() {
        let (s, _) = transition(
            ValidatorState::Prevoting,
            Event::PanicTriggered {
                reason: PanicReason::DoubleVote,
                triggered_at: Instant::now(),
                at_height: 1234,
            },
        );
        assert!(matches!(s, ValidatorState::Panic { at_height: 1234, .. }));
        let (s, a) = transition(s, Event::PanicCleared);
        match s {
            ValidatorState::Halting {
                resume_condition: ResumeCondition::Never,
                triggered_at_height: 1234,
                ..
            } => {}
            other => panic!("expected Halting{{Never, height=1234}}, got {:?}", other),
        }
        assert!(a.contains(&Action::StopBlockProduction { at_height: 1234 }));
    }

    /// Non-recoverable panic from Committed state preserves the
    /// last_block_hash via the Box<prior_state>.
    #[test]
    fn panic_from_committed_preserves_last_block_hash() {
        let block_hash = [99u8; 32];
        let (s, _) = transition(
            ValidatorState::Committed {
                block_hash,
                height: 100,
            },
            Event::PanicTriggered {
                reason: PanicReason::ConflictingCommits,
                triggered_at: Instant::now(),
                at_height: 100,
            },
        );
        let (s, _) = transition(s, Event::PanicCleared);
        match s {
            ValidatorState::Halting {
                last_block_hash: Some(h),
                ..
            } => assert_eq!(h, block_hash),
            other => panic!("expected Halting with last_block_hash, got {:?}", other),
        }
    }

    #[test]
    fn panic_broadcasts_to_peers_for_logs() {
        let (_, a) = transition(
            ValidatorState::Prevoting,
            dummy_panic(PanicReason::ByzantineVoteDetected),
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
    /// non-empty action list.
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
                at_height: 0,
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
            dummy_watchdog(),
            dummy_panic(PanicReason::WatchdogExpired),
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

    /// CONS-308: every transition into `Rejected` emits a typed
    /// `LogRoundRejected` action carrying the same reason. Walks all
    /// four entry points (Proposing/Prevoting/Precommitting via
    /// `VoteFailed`, plus `Committed` via `Timeout`).
    #[test]
    fn transition_into_rejected_emits_typed_log_event() {
        use RejectionReason::*;

        // Each entry point's reason is determined by either the event
        // payload (VoteFailed carries it) or the FSM hard-codes it
        // (Committed.Timeout → InsufficientPrecommits). The test
        // sweeps a representative reason per entry point so a future
        // refactor that drops the LogRoundRejected emission fails
        // here loudly.
        let cases: Vec<(ValidatorState, Event, RejectionReason)> = vec![
            (
                ValidatorState::Proposing,
                Event::VoteFailed(Timeout),
                Timeout,
            ),
            (
                ValidatorState::Prevoting,
                Event::VoteFailed(InsufficientPrevotes),
                InsufficientPrevotes,
            ),
            (
                ValidatorState::Precommitting,
                Event::VoteFailed(InsufficientPrecommits),
                InsufficientPrecommits,
            ),
            (
                ValidatorState::Committed {
                    block_hash: [0; 32],
                    height: 1,
                },
                Event::Timeout,
                InsufficientPrecommits,
            ),
        ];

        for (state, event, expected_reason) in cases {
            let (next, actions) = transition(state.clone(), event.clone());
            assert!(
                matches!(next, ValidatorState::Rejected { .. }),
                "transition({:?}, {:?}) expected Rejected, got {:?}",
                state.kind(),
                event.kind(),
                next.kind()
            );
            let log_action = actions.iter().find_map(|a| match a {
                Action::LogRoundRejected { reason } => Some(*reason),
                _ => None,
            });
            assert_eq!(
                log_action,
                Some(expected_reason),
                "transition({:?}, {:?}) did not emit LogRoundRejected with reason {:?}; \
                 actions = {:?}",
                state.kind(),
                event.kind(),
                expected_reason,
                actions.iter().map(|a| a.kind()).collect::<Vec<_>>()
            );
        }
    }

    /// CONS-601 watchdog escape coverage: every phase state where a
    /// stuck round can occur must transition to `Hung` on
    /// `WatchdogFired`. This is the FSM-level half of the integration
    /// test the spec calls for; the runtime-spawn half is exercised
    /// in `lib-consensus-runtime::tests::watchdog_*`.
    ///
    /// Asserts:
    /// 1. (Idle | Proposing | Prevoting | Precommitting, WatchdogFired)
    ///    → `Hung { prior_state: <input> }`.
    /// 2. The emitted action list contains a `LogHung` so the
    ///    observability layer sees the escape.
    /// 3. `Hung`'s `prior_state` retains the input state's kind so
    ///    operators can tell which phase wedged.
    #[test]
    fn watchdog_fires_lift_each_phase_state_into_hung() {
        let phase_states = [
            ValidatorState::Idle,
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
        ];
        for state in phase_states {
            let prior_kind = state.kind();
            let event = Event::WatchdogFired {
                age_ms: 1_500,
                fired_at: Instant::now(),
            };
            let (next, actions) = transition(state.clone(), event);
            match next {
                ValidatorState::Hung { ref prior_state, .. } => {
                    assert_eq!(
                        prior_state.kind(),
                        prior_kind,
                        "Hung must remember which phase wedged: \
                         expected prior_state kind {:?}, got {:?}",
                        prior_kind,
                        prior_state.kind()
                    );
                }
                other => panic!(
                    "WatchdogFired in {:?} did not produce Hung — got {:?}",
                    prior_kind,
                    other.kind()
                ),
            }
            assert!(
                actions.iter().any(|a| matches!(a, Action::LogHung { .. })),
                "WatchdogFired in {:?} must emit Action::LogHung; got {:?}",
                prior_kind,
                actions.iter().map(|a| a.kind()).collect::<Vec<_>>()
            );
        }
    }
}
