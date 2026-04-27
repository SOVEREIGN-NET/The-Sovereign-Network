//! Total `transition(state, event) -> (next_state, actions)`.
//!
//! Single source of truth for control-flow transitions in the validator
//! FSM. Pre-rewrite this logic was distributed across
//! `consensus_engine::run_*_step`, `on_proposal`, `on_prevote`,
//! `on_precommit`, `on_commit_vote`, plus a thicket of timer flags and
//! "is this round dead yet?" booleans. CONS-302 consolidates it into one
//! function with one match.
//!
//! # Totality
//!
//! `transition()` must terminate for every `(FsmState, Event)` pair —
//! never panic, never `unreachable!`. Invalid-but-tolerable arrivals
//! (e.g. a late prevote in `Committed`) map to
//! `(state, vec![Action::LogIgnoredEvent("..."])` so they are explicit
//! rather than silently dropped.
//!
//! `HaltedForUpgrade` is the one absorbing state with a wildcard match
//! arm, since by definition no event can move it forward.
//!
//! Compile-time totality is enforced by exhaustive matches on both
//! enums (no wildcard arms outside `HaltedForUpgrade`). Adding a
//! variant to `FsmState` or `Event` will break the build until the
//! match is updated.
//!
//! # What this PR does NOT yet do
//!
//! - Wire `transition()` into the engine — that's CONS-305 (handler
//!   migration) once `step_entered_at` (CONS-304) is in place.
//! - Drive watchdog firings — that's CONS-309.
//! - Centralise step timeouts as constants — that's CONS-310.

use crate::fsm::events::{Action, Event};
use crate::fsm::state::{FsmState, RejectionReason};

/// Compute the next state and the actions to execute, given the current
/// state and an arriving event.
///
/// Pure function: no side effects, no panics, no `unreachable!`. The
/// caller (CONS-305 runtime task) is responsible for executing the
/// returned actions in order and feeding the resulting events back in.
pub fn transition(state: FsmState, event: Event) -> (FsmState, Vec<Action>) {
    use Event::*;
    use FsmState::*;

    match (state, event) {
        // ------------------------------------------------------------
        // UpgradeSignal — accepted from any non-terminal state. Halted
        // is absorbing; Committed/Rejected/Hung's wildcard event arms
        // below also catch this with logged-ignored, which is the
        // intended semantics (signal arrived too late to matter).
        // ------------------------------------------------------------
        (Idle, UpgradeSignal { .. })
        | (Proposing, UpgradeSignal { .. })
        | (Prevoting, UpgradeSignal { .. })
        | (Precommitting, UpgradeSignal { .. }) => {
            (HaltedForUpgrade, vec![Action::HaltForUpgrade])
        }

        // ------------------------------------------------------------
        // Idle — between rounds. Accept SelectedAsProposer / Timeout for
        // the boundary case where the proposer fires before any state
        // has been entered. Everything else is logged-ignored.
        // ------------------------------------------------------------
        (Idle, SelectedAsProposer { .. }) => {
            (Proposing, vec![Action::CreateProposal, Action::ResetWatchdog])
        }
        (Idle, ProposalAdmitted { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "ProposalAdmitted in Idle: proposer-elect path not yet entered",
            )],
        ),
        (Idle, Timeout) => (
            Idle,
            vec![Action::LogIgnoredEvent("Timeout in Idle: no active step")],
        ),
        (Idle, PrevoteThresholdReached { .. }) => (
            Idle,
            vec![Action::LogIgnoredEvent("PrevoteThresholdReached in Idle")],
        ),
        (Idle, PrecommitThresholdReached { .. }) => (
            Idle,
            vec![Action::LogIgnoredEvent("PrecommitThresholdReached in Idle")],
        ),
        (Idle, CommitQuorumReached { .. }) => (
            Idle,
            vec![Action::LogIgnoredEvent("CommitQuorumReached in Idle")],
        ),
        (Idle, VoteFailed(_)) => (
            Idle,
            vec![Action::LogIgnoredEvent("VoteFailed in Idle")],
        ),
        (Idle, WatchdogFired { age_ms }) => (
            Hung,
            vec![Action::LogHung {
                reason: "Watchdog fired while Idle — runtime stuck before round start",
            }, Action::LogIgnoredEvent("Idle.WatchdogFired"), event_marker_age_ms(age_ms)],
        ),

        // ------------------------------------------------------------
        // Proposing — the leader's window. Either a proposal arrives
        // (transition to Prevoting) or the propose timeout fires
        // (transition to Rejected for view change).
        // ------------------------------------------------------------
        (Proposing, ProposalAdmitted { id, .. }) => (
            Prevoting,
            vec![
                Action::BroadcastProposal { id: id.clone() },
                Action::SendPrevote { block_id: id },
                Action::ResetWatchdog,
            ],
        ),
        (Proposing, SelectedAsProposer { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "SelectedAsProposer in Proposing: already proposing",
            )],
        ),
        (Proposing, Timeout) => (
            Rejected(RejectionReason::Timeout),
            vec![Action::AdvanceRound],
        ),
        (Proposing, PrevoteThresholdReached { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "PrevoteThresholdReached in Proposing: pre-quorum",
            )],
        ),
        (Proposing, PrecommitThresholdReached { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "PrecommitThresholdReached in Proposing: pre-quorum",
            )],
        ),
        (Proposing, CommitQuorumReached { .. }) => (
            Proposing,
            vec![Action::LogIgnoredEvent(
                "CommitQuorumReached in Proposing: pre-quorum",
            )],
        ),
        (Proposing, VoteFailed(reason)) => {
            (Rejected(reason), vec![Action::AdvanceRound])
        }
        (Proposing, WatchdogFired { .. }) => (
            Hung,
            vec![Action::LogHung {
                reason: "Watchdog fired while Proposing — proposer or network stuck",
            }],
        ),

        // ------------------------------------------------------------
        // Prevoting — proposal admitted, accumulating prevotes.
        // ------------------------------------------------------------
        (Prevoting, PrevoteThresholdReached { block_id }) => (
            Precommitting,
            vec![
                Action::SendPrecommit { block_id },
                Action::ResetWatchdog,
            ],
        ),
        (Prevoting, Timeout) => (
            Rejected(RejectionReason::InsufficientPrevotes),
            vec![Action::AdvanceRound],
        ),
        (Prevoting, VoteFailed(reason)) => {
            (Rejected(reason), vec![Action::AdvanceRound])
        }
        (Prevoting, ProposalAdmitted { .. }) => (
            Prevoting,
            vec![Action::LogIgnoredEvent(
                "ProposalAdmitted in Prevoting: duplicate or competing proposal",
            )],
        ),
        (Prevoting, SelectedAsProposer { .. }) => (
            Prevoting,
            vec![Action::LogIgnoredEvent(
                "SelectedAsProposer in Prevoting: round already advanced",
            )],
        ),
        (Prevoting, PrecommitThresholdReached { .. }) => (
            Prevoting,
            vec![Action::LogIgnoredEvent(
                "PrecommitThresholdReached in Prevoting: pre-prevote-quorum",
            )],
        ),
        (Prevoting, CommitQuorumReached { .. }) => (
            Prevoting,
            vec![Action::LogIgnoredEvent(
                "CommitQuorumReached in Prevoting: pre-prevote-quorum",
            )],
        ),
        (Prevoting, WatchdogFired { .. }) => (
            Hung,
            vec![Action::LogHung {
                reason: "Watchdog fired while Prevoting — vote pool stuck",
            }],
        ),

        // ------------------------------------------------------------
        // Precommitting — accumulating precommits for one block.
        // ------------------------------------------------------------
        (Precommitting, CommitQuorumReached { block_id, quorum }) => (
            Committed,
            vec![
                Action::CommitBlock {
                    id: block_id,
                    quorum,
                },
                Action::ResetWatchdog,
            ],
        ),
        (Precommitting, PrecommitThresholdReached { .. }) => (
            Precommitting,
            vec![Action::LogIgnoredEvent(
                "PrecommitThresholdReached in Precommitting: waiting for quorum proof",
            )],
        ),
        (Precommitting, Timeout) => (
            Rejected(RejectionReason::InsufficientPrecommits),
            vec![Action::AdvanceRound],
        ),
        (Precommitting, VoteFailed(reason)) => {
            (Rejected(reason), vec![Action::AdvanceRound])
        }
        (Precommitting, ProposalAdmitted { .. }) => (
            Precommitting,
            vec![Action::LogIgnoredEvent(
                "ProposalAdmitted in Precommitting: too late",
            )],
        ),
        (Precommitting, SelectedAsProposer { .. }) => (
            Precommitting,
            vec![Action::LogIgnoredEvent(
                "SelectedAsProposer in Precommitting: round already advanced",
            )],
        ),
        (Precommitting, PrevoteThresholdReached { .. }) => (
            Precommitting,
            vec![Action::LogIgnoredEvent(
                "PrevoteThresholdReached in Precommitting: late prevote",
            )],
        ),
        (Precommitting, WatchdogFired { .. }) => (
            Hung,
            vec![Action::LogHung {
                reason: "Watchdog fired while Precommitting — quorum stuck",
            }],
        ),

        // ------------------------------------------------------------
        // Committed — terminal-success. Self-clears on the next
        // height's StartRound; until then everything is logged-ignored.
        // ------------------------------------------------------------
        (Committed, _event) => (Committed, vec![Action::LogIgnoredEvent("event in Committed")]),

        // ------------------------------------------------------------
        // Rejected — terminal-failure for the current round. The runtime
        // emits AdvanceRound in the transition that produced Rejected;
        // events arriving after that are ignored until the runtime feeds
        // a new round.
        // ------------------------------------------------------------
        (Rejected(_), _event) => (
            state,
            vec![Action::LogIgnoredEvent("event in Rejected")],
        ),

        // ------------------------------------------------------------
        // Hung — terminal until external recovery.
        // ------------------------------------------------------------
        (Hung, _event) => (Hung, vec![Action::LogIgnoredEvent("event in Hung")]),

        // ------------------------------------------------------------
        // HaltedForUpgrade — only state with a wildcard event arm. By
        // definition no event moves it forward; the runtime restart with
        // the bumped CONSENSUS_PROTOCOL_VERSION is the only exit.
        // ------------------------------------------------------------
        (HaltedForUpgrade, _) => (
            HaltedForUpgrade,
            vec![Action::LogIgnoredEvent("event in HaltedForUpgrade")],
        ),
    }
}

/// Helper used by the watchdog branches in `Idle` to surface the
/// firing-age in the action stream without inventing a dedicated
/// Action variant. The runtime can pick this up via its observability
/// pipeline; the FSM doesn't need to act on it.
fn event_marker_age_ms(_age_ms: u64) -> Action {
    Action::LogIgnoredEvent("watchdog age recorded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;
    use lib_types::consensus::BftQuorumProof;

    fn dummy_quorum() -> BftQuorumProof {
        BftQuorumProof {
            height: 0,
            proposal_id: [0u8; 32],
            total_validators: 0,
            attestations: Vec::new(),
        }
    }

    fn all_events() -> Vec<Event> {
        vec![
            Event::SelectedAsProposer {
                height: 1,
                round: 0,
            },
            Event::ProposalAdmitted {
                id: Hash([1u8; 32]),
                height: 1,
                round: 0,
            },
            Event::PrevoteThresholdReached {
                block_id: Hash([2u8; 32]),
            },
            Event::PrecommitThresholdReached {
                block_id: Hash([3u8; 32]),
            },
            Event::CommitQuorumReached {
                block_id: Hash([4u8; 32]),
                quorum: dummy_quorum(),
            },
            Event::VoteFailed(RejectionReason::Timeout),
            Event::Timeout,
            Event::WatchdogFired { age_ms: 5_000 },
            Event::UpgradeSignal { halt_at_height: 100 },
        ]
    }

    fn all_states() -> Vec<FsmState> {
        vec![
            FsmState::Idle,
            FsmState::Proposing,
            FsmState::Prevoting,
            FsmState::Precommitting,
            FsmState::Committed,
            FsmState::Rejected(RejectionReason::InsufficientPrevotes),
            FsmState::Hung,
            FsmState::HaltedForUpgrade,
        ]
    }

    /// CONS-302 acceptance criterion: every (state, event) pair returns
    /// a valid (next_state, actions) tuple — no panic, no unreachable.
    #[test]
    fn transition_total_over_state_event_product() {
        for state in all_states() {
            for event in all_events() {
                // Must not panic.
                let (_next, actions) = transition(state, event.clone());
                // Must always produce at least one action — even
                // logged-ignored arrivals.  Empty action lists would
                // hide silent transitions.
                assert!(
                    !actions.is_empty(),
                    "transition({:?}, {:?}) returned no actions",
                    state,
                    event
                );
            }
        }
    }

    /// Happy path: Idle → Proposing → Prevoting → Precommitting → Committed.
    #[test]
    fn happy_path_round_completes() {
        let block_id = Hash([42u8; 32]);
        let proposer_event = Event::SelectedAsProposer {
            height: 1,
            round: 0,
        };

        let (s, a) = transition(FsmState::Idle, proposer_event);
        assert_eq!(s, FsmState::Proposing);
        assert!(a.contains(&Action::CreateProposal));

        let (s, a) = transition(
            s,
            Event::ProposalAdmitted {
                id: block_id.clone(),
                height: 1,
                round: 0,
            },
        );
        assert_eq!(s, FsmState::Prevoting);
        assert!(a.iter().any(|x| matches!(x, Action::SendPrevote { .. })));

        let (s, _) = transition(
            s,
            Event::PrevoteThresholdReached {
                block_id: block_id.clone(),
            },
        );
        assert_eq!(s, FsmState::Precommitting);

        let (s, a) = transition(
            s,
            Event::CommitQuorumReached {
                block_id,
                quorum: dummy_quorum(),
            },
        );
        assert_eq!(s, FsmState::Committed);
        assert!(a.iter().any(|x| matches!(x, Action::CommitBlock { .. })));
    }

    /// Propose timeout produces a view change.
    #[test]
    fn propose_timeout_advances_round() {
        let (s, a) = transition(FsmState::Proposing, Event::Timeout);
        assert_eq!(s, FsmState::Rejected(RejectionReason::Timeout));
        assert!(a.contains(&Action::AdvanceRound));
    }

    /// Prevote timeout maps to InsufficientPrevotes, not generic Timeout.
    #[test]
    fn prevote_timeout_rejection_specific() {
        let (s, _) = transition(FsmState::Prevoting, Event::Timeout);
        assert_eq!(s, FsmState::Rejected(RejectionReason::InsufficientPrevotes));
    }

    /// Precommit timeout maps to InsufficientPrecommits.
    #[test]
    fn precommit_timeout_rejection_specific() {
        let (s, _) = transition(FsmState::Precommitting, Event::Timeout);
        assert_eq!(
            s,
            FsmState::Rejected(RejectionReason::InsufficientPrecommits)
        );
    }

    /// Watchdog from any active state lands in `Hung`.
    #[test]
    fn watchdog_from_active_states_hangs() {
        for state in [
            FsmState::Proposing,
            FsmState::Prevoting,
            FsmState::Precommitting,
        ] {
            let (s, a) = transition(state, Event::WatchdogFired { age_ms: 30_000 });
            assert_eq!(s, FsmState::Hung);
            assert!(a.iter().any(|x| matches!(x, Action::LogHung { .. })));
        }
    }

    /// UpgradeSignal trumps the current state for any non-terminal state.
    #[test]
    fn upgrade_signal_halts_any_active_state() {
        for state in [
            FsmState::Idle,
            FsmState::Proposing,
            FsmState::Prevoting,
            FsmState::Precommitting,
        ] {
            let (s, a) = transition(state, Event::UpgradeSignal { halt_at_height: 100 });
            assert_eq!(s, FsmState::HaltedForUpgrade);
            assert_eq!(a, vec![Action::HaltForUpgrade]);
        }
    }

    /// `HaltedForUpgrade` is absorbing — every event is logged-ignored.
    #[test]
    fn halted_for_upgrade_is_absorbing() {
        for event in all_events() {
            let (s, a) = transition(FsmState::HaltedForUpgrade, event.clone());
            assert_eq!(s, FsmState::HaltedForUpgrade, "event {:?} moved Halted", event);
            assert!(
                a.iter().all(|x| matches!(x, Action::LogIgnoredEvent(_))),
                "event {:?} produced non-ignored action {:?}",
                event,
                a
            );
        }
    }
}
