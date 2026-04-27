//! FSM Event/Action vocabulary.
//!
//! These enums are the only way the [`transition()`] function (CONS-302)
//! observes the outside world or expresses its decisions. The FSM:
//!
//! - **Consumes** [`Event`] values produced by the runtime: timer firings,
//!   admitted proposals, vote-tally thresholds, watchdog signals, upgrade
//!   signals.
//! - **Emits** [`Action`] values that the runtime executes:
//!   create/broadcast a proposal, send a vote, commit a block, advance a
//!   round, reset the watchdog, halt for upgrade.
//!
//! The FSM never touches `tokio`, the network, the keypair, the
//! blockchain, or wall-clock time — those side effects all flow through
//! `Action`s and back through `Event`s.
//!
//! [`transition()`]: super::transition
//!
//! # Why IDs and not full `ConsensusProposal`/`ConsensusVote`
//!
//! The CONS-303 epic draft suggested `Event::ReceivedProposal(ConsensusProposal)`
//! / `Action::CommitBlock(ConsensusProposal, BftQuorumProof)`.  Plumbing
//! the full proposal type through the FSM would require moving
//! `ConsensusProposal` (and its `ConsensusProof`) into lib-consensus-core,
//! and `ConsensusProof::storage_proof` references
//! `lib_storage::proofs::StorageCapacityAttestation`. Adding lib-storage
//! as a dep on lib-consensus-core is forbidden by AD-002 (see `lib.rs`).
//!
//! The cycle was already noted on CONS-104 review and CONS-201's deferred
//! Scope B.  Until the StorageCapacityAttestation home is resolved, the
//! FSM operates on `Hash` IDs only — the runtime holds the proposal/vote
//! bodies (already keyed by ID in the engine's existing maps) and looks
//! them up when an `Action` references one.

use crate::fsm::state::RejectionReason;
use lib_crypto::Hash;
use lib_types::consensus::BftQuorumProof;
use serde::{Deserialize, Serialize};

/// Inputs the FSM consumes during one [`transition`] call.
///
/// Produced by the runtime (timers, vote pool, network, watchdog) and
/// fed to the FSM in arrival order.  The runtime is responsible for
/// pre-validating each event before delivery: the FSM trusts that an
/// `ProposalAdmitted` has already passed signature and proposer checks,
/// that a `*ThresholdReached` has already counted +2/3 by stake.
///
/// [`transition`]: super::transition::transition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// The local validator was elected proposer for the current
    /// (height, round). Engine should produce a proposal.
    SelectedAsProposer { height: u64, round: u32 },

    /// A proposal arrived and passed all pre-FSM validation
    /// (signature, height, round, proposer election).
    ProposalAdmitted {
        id: Hash,
        height: u64,
        round: u32,
    },

    /// The vote pool counted +2/3 prevotes by stake for `block_id`.
    PrevoteThresholdReached { block_id: Hash },

    /// The vote pool counted +2/3 precommits by stake for `block_id`.
    PrecommitThresholdReached { block_id: Hash },

    /// A `BftQuorumProof` was assembled from the precommit votes.
    /// Carries the proof so the runtime can finalize without re-aggregating.
    CommitQuorumReached {
        block_id: Hash,
        quorum: BftQuorumProof,
    },

    /// Vote tallying ended without quorum, with a specific reason.
    VoteFailed(RejectionReason),

    /// A step-level timeout fired (Propose, PreVote, or PreCommit).
    /// The FSM resolves the appropriate [`RejectionReason`] internally.
    Timeout,

    /// The watchdog (CONS-309) fired without observing any progress
    /// action for longer than the configured threshold.
    WatchdogFired { age_ms: u64 },

    /// External signal that the operator has scheduled a halt at a
    /// specific height for protocol upgrade (CONS-203 cutover).
    UpgradeSignal { halt_at_height: u64 },
}

/// Outputs the FSM emits during one [`transition`] call.
///
/// The runtime executes these in order. Side effects (broadcast, finalize,
/// log) are encapsulated here so the FSM stays IO-free per AD-002.
///
/// [`transition`]: super::transition::transition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Build a fresh proposal for the current (height, round) and feed
    /// the resulting `ProposalAdmitted` event back to the FSM.
    CreateProposal,

    /// Broadcast the proposal identified by `id` to all peers.
    BroadcastProposal { id: Hash },

    /// Sign and send a prevote for `block_id` to all peers.
    SendPrevote { block_id: Hash },

    /// Sign and send a precommit for `block_id` to all peers.
    SendPrecommit { block_id: Hash },

    /// Commit the block identified by `id` using the supplied quorum
    /// proof — calls `BlockFinalizationSink` on the runtime.
    CommitBlock {
        id: Hash,
        quorum: BftQuorumProof,
    },

    /// Increment the round counter and reset to `FsmState::Idle` for
    /// (height, round + 1). View change.
    AdvanceRound,

    /// Reset the watchdog timer because progress was made.
    ResetWatchdog,

    /// Stop admitting messages and stay in `HaltedForUpgrade` until the
    /// operator restarts the node with the bumped protocol version.
    HaltForUpgrade,

    /// Emit a `Hung` observability event with the given reason.
    LogHung { reason: &'static str },

    /// Emit an "ignored event" observability log — used when an event
    /// arrives in a state where it has no effect (e.g. late prevote
    /// after `Committed`). Explicit instead of silent.
    LogIgnoredEvent(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that every Event variant is constructible.
    #[test]
    fn all_event_variants_constructible() {
        let _ = Event::SelectedAsProposer {
            height: 1,
            round: 0,
        };
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
            quorum: BftQuorumProof {
                height: 0,
                proposal_id: [0u8; 32],
                total_validators: 0,
                attestations: Vec::new(),
            },
        };
        let _ = Event::VoteFailed(RejectionReason::Timeout);
        let _ = Event::Timeout;
        let _ = Event::WatchdogFired { age_ms: 5_000 };
        let _ = Event::UpgradeSignal { halt_at_height: 100 };
    }

    /// Sanity check that every Action variant is constructible.
    #[test]
    fn all_action_variants_constructible() {
        let _ = Action::CreateProposal;
        let _ = Action::BroadcastProposal { id: Hash([1u8; 32]) };
        let _ = Action::SendPrevote {
            block_id: Hash([2u8; 32]),
        };
        let _ = Action::SendPrecommit {
            block_id: Hash([3u8; 32]),
        };
        let _ = Action::CommitBlock {
            id: Hash([4u8; 32]),
            quorum: BftQuorumProof {
                height: 0,
                proposal_id: [0u8; 32],
                total_validators: 0,
                attestations: Vec::new(),
            },
        };
        let _ = Action::AdvanceRound;
        let _ = Action::ResetWatchdog;
        let _ = Action::HaltForUpgrade;
        let _ = Action::LogHung {
            reason: "test",
        };
        let _ = Action::LogIgnoredEvent("test");
    }
}
