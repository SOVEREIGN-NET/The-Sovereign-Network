//! FSM Event/Action vocabulary.
//!
//! These enums are the only way the [`transition()`] function (CONS-302)
//! observes the outside world or expresses its decisions.
//!
//! [`transition()`]: super::transition::transition
//!
//! ## Naming
//!
//! Variant names follow the wire-level vocabulary: `Prevote`,
//! `Precommit`, `Commit` match the `VoteType` tags carried in
//! [`ConsensusVote`](crate::types). Higher-level documentation may
//! describe phases as "Voting / Finalizing / Committed" but internal
//! state and event names stay close to the wire so there's a single
//! consistent vocabulary across the whole stack.
//!
//! ## Why IDs and not full `ConsensusProposal`/`ConsensusVote`
//!
//! `ConsensusProposal::consensus_proof::storage_proof` references
//! `lib_storage::proofs::StorageCapacityAttestation`. Adding lib-storage
//! as a dep on lib-consensus-core is forbidden by AD-002. Until the
//! StorageCapacityAttestation home is resolved (deferred from CONS-104
//! and CONS-201), the FSM operates on `Hash` IDs only. The runtime
//! holds proposal/vote bodies and looks them up when an `Action`
//! references one.

use crate::fsm::state::{HaltReason, PanicReason, RejectionReason, SlashReason};
use lib_crypto::Hash;
use lib_types::consensus::BftQuorumProof;
use std::time::Instant;

/// Inputs the FSM consumes during one [`transition`] call.
///
/// Produced by the runtime (timers, vote pool, network, watchdog) and
/// fed to the FSM in arrival order. The runtime is responsible for
/// pre-validating each event before delivery: the FSM trusts that a
/// `ProposalAdmitted` has already passed signature and proposer
/// checks, that a `*ThresholdReached` has already counted +2/3 by
/// stake.
///
/// [`transition`]: super::transition::transition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    // ----- Lifecycle -----
    /// Genesis bootstrap finished; local state initialised.
    BootstrapComplete,

    /// Catch-up sync reached the network tip.
    CaughtUp,

    /// Operator-initiated graceful shutdown.
    ShutdownRequested,

    // ----- Active consensus -----
    /// The local validator was elected proposer for the current
    /// (height, round).
    SelectedAsProposer { height: u64, round: u32 },

    /// A proposal arrived and passed all pre-FSM validation
    /// (signature, height, round, proposer election).
    ProposalAdmitted {
        id: Hash,
        height: u64,
        round: u32,
    },

    /// Vote pool counted +2/3 PreVotes for `block_id`.
    PrevoteThresholdReached { block_id: Hash },

    /// Vote pool counted +2/3 PreCommits for `block_id`.
    PrecommitThresholdReached { block_id: Hash },

    /// Vote pool counted +2/3 Commit votes and assembled a
    /// `BftQuorumProof` — block ready for finalization.
    CommitQuorumReached {
        block_id: Hash,
        quorum: BftQuorumProof,
    },

    /// Vote tallying ended without quorum, with a specific reason.
    VoteFailed(RejectionReason),

    /// A step-level timeout fired. The FSM walks Proposing →
    /// Prevoting → Precommitting → Committed; only Committed-phase
    /// timeouts trigger a view change.
    Timeout,

    // ----- Watchdog / panic -----
    /// Watchdog fired without observing any progress action for
    /// longer than the configured threshold. The runtime captures
    /// `fired_at` so the FSM can record the firing instant in `Hung`
    /// without calling `Instant::now()` itself (PR #2394 review:
    /// keeps `transition()` time-free / pure).
    WatchdogFired { age_ms: u64, fired_at: Instant },

    /// A condition that warrants entering [`ValidatorState::Panic`]
    /// was observed. Carries the height at which the panic fired and
    /// the wall-clock instant captured by the runtime — both
    /// propagate into the resulting `Panic` state so the FSM stays
    /// time-free (PR #2394 review).
    ///
    /// [`ValidatorState::Panic`]: crate::fsm::state::ValidatorState::Panic
    PanicTriggered {
        reason: PanicReason,
        triggered_at: Instant,
        at_height: u64,
    },

    /// The condition that put the FSM into Panic has cleared
    /// (recoverable panics only). Resets to `Idle`.
    PanicCleared,

    // ----- Operator coordination -----
    /// Operator scheduled a halt at `triggered_at_height` for `reason`.
    HaltScheduled {
        reason: HaltReason,
        triggered_at_height: u64,
        resume_condition: ResumeConditionEvent,
    },

    /// Halt window reached; transition Halting → CoordinatedUpdate.
    HaltActivated {
        activate_at_height: u64,
        target_version: u32,
    },

    /// 2/3+ validators reported ready on the new protocol version.
    UpdateQuorumReady,

    // ----- Punishment -----
    /// Validator was slashed for `reason`.
    SlashEvidenceConfirmed { reason: SlashReason },

    /// Validator was removed from the active set.
    EvictedFromSet,

    /// Validator was re-admitted to the active set after slashing
    /// or eviction.
    ReadmittedToSet,
}

/// Wire-friendly companion of [`crate::fsm::state::ResumeCondition`]
/// for events. Identical variants; named distinctly so `Event` types
/// stay self-contained without a circular re-export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeConditionEvent {
    ManualRestart,
    QuorumReady,
    UpgradeComplete,
    Never,
}

impl From<ResumeConditionEvent> for crate::fsm::state::ResumeCondition {
    fn from(e: ResumeConditionEvent) -> Self {
        use crate::fsm::state::ResumeCondition::*;
        match e {
            ResumeConditionEvent::ManualRestart => ManualRestart,
            ResumeConditionEvent::QuorumReady => QuorumReady,
            ResumeConditionEvent::UpgradeComplete => UpgradeComplete,
            ResumeConditionEvent::Never => Never,
        }
    }
}

/// Outputs the FSM emits during one [`transition`] call.
///
/// The runtime executes these in order. Side effects (broadcast,
/// finalize, log, panic-broadcast, log-flush) are encapsulated here
/// so the FSM stays IO-free per AD-002.
///
/// [`transition`]: super::transition::transition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    // ----- Lifecycle -----
    /// Begin downloading state from genesis.
    StartBootstrap,

    /// Begin catch-up sync from the local height to network tip.
    StartCatchUp,

    /// Flush logs, persist any in-flight state, prepare for exit.
    FlushLogsForShutdown,

    // ----- Active consensus -----
    /// Build a fresh proposal for the current (height, round).
    CreateProposal,

    /// Broadcast the proposal identified by `id` to all peers.
    BroadcastProposal { id: Hash },

    /// Sign and send a `VoteType::PreVote` for `block_id`.
    SendPrevote { block_id: Hash },

    /// Sign and send a `VoteType::PreCommit` for `block_id`.
    SendPrecommit { block_id: Hash },

    /// Sign and send a `VoteType::Commit` for `block_id`.
    SendCommit { block_id: Hash },

    /// Finalize the block identified by `id` using the supplied
    /// quorum proof — calls `BlockFinalizationSink` on the runtime.
    CommitBlock { id: Hash, quorum: BftQuorumProof },

    /// Increment the round counter. Resets the FSM to `Idle` for
    /// (height, round + 1).
    AdvanceRound,

    /// Reset the watchdog timer because progress was made.
    ResetWatchdog,

    // ----- Operator coordination -----
    /// Stop accepting new heights at `at_height`. Emitted on
    /// `HaltScheduled`.
    StopBlockProduction { at_height: u64 },

    /// Begin the post-halt barrier — wait for `UpdateQuorumReady` at
    /// the activation height.
    EnterUpdateBarrier { activate_at_height: u64, target_version: u32 },

    /// Announce readiness to peers on the new protocol version.
    BroadcastReadyOnNewVersion { version: u32 },

    // ----- Punishment / safety -----
    /// Drop out of the active validator set; stop emitting votes.
    LeaveActiveSet,

    /// Re-enter the active set after slashing window / re-registration.
    RejoinActiveSet,

    /// Broadcast `Panic` notice to peers so they can save logs and
    /// prepare for this validator's shutdown.
    BroadcastPanic { reason: PanicReason },

    /// Emit observability event with the given panic reason and the
    /// prior state's kind.
    LogPanic { reason: PanicReason },

    /// Emit a `Hung` observability event with the given reason.
    LogHung { reason: &'static str },

    /// Emit an "ignored event" observability log — used when an
    /// event arrives in a state where it has no effect (e.g. late
    /// vote in `Idle`). Explicit instead of silent.
    LogIgnoredEvent(&'static str),
}

/// Discriminant of [`Event`] without payload data. Used by the
/// transition table for runtime queries and diagram generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    BootstrapComplete,
    CaughtUp,
    ShutdownRequested,
    SelectedAsProposer,
    ProposalAdmitted,
    PrevoteThresholdReached,
    PrecommitThresholdReached,
    CommitQuorumReached,
    VoteFailed,
    Timeout,
    WatchdogFired,
    PanicTriggered,
    PanicCleared,
    HaltScheduled,
    HaltActivated,
    UpdateQuorumReady,
    SlashEvidenceConfirmed,
    EvictedFromSet,
    ReadmittedToSet,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        match self {
            Event::BootstrapComplete => EventKind::BootstrapComplete,
            Event::CaughtUp => EventKind::CaughtUp,
            Event::ShutdownRequested => EventKind::ShutdownRequested,
            Event::SelectedAsProposer { .. } => EventKind::SelectedAsProposer,
            Event::ProposalAdmitted { .. } => EventKind::ProposalAdmitted,
            Event::PrevoteThresholdReached { .. } => EventKind::PrevoteThresholdReached,
            Event::PrecommitThresholdReached { .. } => EventKind::PrecommitThresholdReached,
            Event::CommitQuorumReached { .. } => EventKind::CommitQuorumReached,
            Event::VoteFailed(_) => EventKind::VoteFailed,
            Event::Timeout => EventKind::Timeout,
            Event::WatchdogFired { .. } => EventKind::WatchdogFired,
            Event::PanicTriggered { .. } => EventKind::PanicTriggered,
            Event::PanicCleared => EventKind::PanicCleared,
            Event::HaltScheduled { .. } => EventKind::HaltScheduled,
            Event::HaltActivated { .. } => EventKind::HaltActivated,
            Event::UpdateQuorumReady => EventKind::UpdateQuorumReady,
            Event::SlashEvidenceConfirmed { .. } => EventKind::SlashEvidenceConfirmed,
            Event::EvictedFromSet => EventKind::EvictedFromSet,
            Event::ReadmittedToSet => EventKind::ReadmittedToSet,
        }
    }
}

/// Discriminant of [`Action`] without payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionKind {
    StartBootstrap,
    StartCatchUp,
    FlushLogsForShutdown,
    CreateProposal,
    BroadcastProposal,
    SendPrevote,
    SendPrecommit,
    SendCommit,
    CommitBlock,
    AdvanceRound,
    ResetWatchdog,
    StopBlockProduction,
    EnterUpdateBarrier,
    BroadcastReadyOnNewVersion,
    LeaveActiveSet,
    RejoinActiveSet,
    BroadcastPanic,
    LogPanic,
    LogHung,
    LogIgnoredEvent,
}

impl Action {
    pub fn kind(&self) -> ActionKind {
        match self {
            Action::StartBootstrap => ActionKind::StartBootstrap,
            Action::StartCatchUp => ActionKind::StartCatchUp,
            Action::FlushLogsForShutdown => ActionKind::FlushLogsForShutdown,
            Action::CreateProposal => ActionKind::CreateProposal,
            Action::BroadcastProposal { .. } => ActionKind::BroadcastProposal,
            Action::SendPrevote { .. } => ActionKind::SendPrevote,
            Action::SendPrecommit { .. } => ActionKind::SendPrecommit,
            Action::SendCommit { .. } => ActionKind::SendCommit,
            Action::CommitBlock { .. } => ActionKind::CommitBlock,
            Action::AdvanceRound => ActionKind::AdvanceRound,
            Action::ResetWatchdog => ActionKind::ResetWatchdog,
            Action::StopBlockProduction { .. } => ActionKind::StopBlockProduction,
            Action::EnterUpdateBarrier { .. } => ActionKind::EnterUpdateBarrier,
            Action::BroadcastReadyOnNewVersion { .. } => ActionKind::BroadcastReadyOnNewVersion,
            Action::LeaveActiveSet => ActionKind::LeaveActiveSet,
            Action::RejoinActiveSet => ActionKind::RejoinActiveSet,
            Action::BroadcastPanic { .. } => ActionKind::BroadcastPanic,
            Action::LogPanic { .. } => ActionKind::LogPanic,
            Action::LogHung { .. } => ActionKind::LogHung,
            Action::LogIgnoredEvent(_) => ActionKind::LogIgnoredEvent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_quorum() -> BftQuorumProof {
        BftQuorumProof {
            height: 0,
            proposal_id: [0u8; 32],
            total_validators: 0,
            attestations: Vec::new(),
        }
    }

    #[test]
    fn all_event_variants_constructible() {
        let _ = Event::BootstrapComplete;
        let _ = Event::CaughtUp;
        let _ = Event::ShutdownRequested;
        let _ = Event::SelectedAsProposer { height: 1, round: 0 };
        let _ = Event::ProposalAdmitted {
            id: Hash([1u8; 32]),
            height: 1,
            round: 0,
        };
        let _ = Event::PrevoteThresholdReached {
            block_id: Hash([2u8; 32]),
        };
        let _ = Event::PrecommitThresholdReached {
            block_id: Hash([3u8; 32]),
        };
        let _ = Event::CommitQuorumReached {
            block_id: Hash([4u8; 32]),
            quorum: dummy_quorum(),
        };
        let _ = Event::VoteFailed(RejectionReason::Timeout);
        let _ = Event::Timeout;
        let _ = Event::WatchdogFired {
            age_ms: 5_000,
            fired_at: Instant::now(),
        };
        let _ = Event::PanicTriggered {
            reason: PanicReason::WatchdogExpired,
            triggered_at: Instant::now(),
            at_height: 100,
        };
        let _ = Event::PanicCleared;
        let _ = Event::HaltScheduled {
            reason: HaltReason::UpgradeScheduled,
            triggered_at_height: 100,
            resume_condition: ResumeConditionEvent::QuorumReady,
        };
        let _ = Event::HaltActivated {
            activate_at_height: 100,
            target_version: 2,
        };
        let _ = Event::UpdateQuorumReady;
        let _ = Event::SlashEvidenceConfirmed {
            reason: SlashReason::DoubleSign,
        };
        let _ = Event::EvictedFromSet;
        let _ = Event::ReadmittedToSet;
    }

    #[test]
    fn all_action_variants_constructible() {
        let _ = Action::StartBootstrap;
        let _ = Action::StartCatchUp;
        let _ = Action::FlushLogsForShutdown;
        let _ = Action::CreateProposal;
        let _ = Action::BroadcastProposal { id: Hash([1u8; 32]) };
        let _ = Action::SendPrevote {
            block_id: Hash([2u8; 32]),
        };
        let _ = Action::SendPrecommit {
            block_id: Hash([3u8; 32]),
        };
        let _ = Action::SendCommit {
            block_id: Hash([4u8; 32]),
        };
        let _ = Action::CommitBlock {
            id: Hash([5u8; 32]),
            quorum: dummy_quorum(),
        };
        let _ = Action::AdvanceRound;
        let _ = Action::ResetWatchdog;
        let _ = Action::StopBlockProduction { at_height: 100 };
        let _ = Action::EnterUpdateBarrier {
            activate_at_height: 100,
            target_version: 2,
        };
        let _ = Action::BroadcastReadyOnNewVersion { version: 2 };
        let _ = Action::LeaveActiveSet;
        let _ = Action::RejoinActiveSet;
        let _ = Action::BroadcastPanic {
            reason: PanicReason::DoubleVote,
        };
        let _ = Action::LogPanic {
            reason: PanicReason::DoubleVote,
        };
        let _ = Action::LogHung { reason: "test" };
        let _ = Action::LogIgnoredEvent("test");
    }

    #[test]
    fn kinds_round_trip_correctly() {
        let pairs: Vec<(Event, EventKind)> = vec![
            (Event::BootstrapComplete, EventKind::BootstrapComplete),
            (Event::Timeout, EventKind::Timeout),
            (Event::PanicCleared, EventKind::PanicCleared),
            (Event::UpdateQuorumReady, EventKind::UpdateQuorumReady),
        ];
        for (e, k) in pairs {
            assert_eq!(e.kind(), k);
        }
    }
}
