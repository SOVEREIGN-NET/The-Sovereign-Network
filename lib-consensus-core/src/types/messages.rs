//! P2P wire messages: `ValidatorMessage` + its three variants and the
//! supporting `Justification`, `ConsensusStateView`, `NetworkSummary`.
//!
//! Migrated here from `lib-consensus-net::validator_protocol` per
//! CONS-401. They were stuck one crate higher than ideal because
//! `MessageBroadcaster` (the consensus port that takes
//! `ValidatorMessage`) was defined in `lib-consensus-net` too. Moving
//! both down the dep graph keeps the port-trait + value-type pair
//! together in `lib-consensus-core`, giving downstream crates one
//! canonical import path.
//!
//! `lib-consensus-net::validator_protocol` re-exports these so the
//! existing import paths
//! (`lib_consensus_net::validator_protocol::ValidatorMessage`, etc.)
//! keep working unchanged.

use std::collections::BTreeMap;

use lib_crypto::{Hash, PostQuantumSignature};
use lib_identity::IdentityId;
use lib_types::consensus::ConsensusStep;
use serde::{Deserialize, Serialize};

use crate::types::{ConsensusProposal, ConsensusVote};

/// Unified P2P message — the canonical wire form sent by every
/// `MessageBroadcaster` implementation. Three variants: `Propose` from
/// the round leader, `Vote` from any validator (PreVote / PreCommit /
/// Commit votes are distinguished by `VoteType` inside the inner
/// `ConsensusVote`), and `Heartbeat` for liveness telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorMessage {
    /// Proposal message from the designated round proposer.
    Propose(ProposeMessage),
    /// Vote message — `PreVote`, `PreCommit`, or `Commit` per the
    /// inner `ConsensusVote::vote_type`.
    Vote(VoteMessage),
    /// Validator heartbeat for liveness tracking.
    Heartbeat(HeartbeatMessage),
}

/// Proposal envelope. Carries the `ConsensusProposal` payload plus a
/// `Justification` for view-changes and a Dilithium outer-envelope
/// signature so receivers can verify the message before content
/// validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeMessage {
    pub message_id: Hash,
    pub proposer: IdentityId,
    pub proposal: ConsensusProposal,
    pub justification: Option<Justification>,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

/// Vote envelope. Wraps a `ConsensusVote` with a snapshot of the
/// voter's local state (for tally-debugging) and the Dilithium outer
/// envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    pub message_id: Hash,
    pub voter: IdentityId,
    pub vote: ConsensusVote,
    pub consensus_state: ConsensusStateView,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

/// Heartbeat envelope — advisory liveness telemetry. Per the original
/// `lib-consensus/src/network/heartbeat.rs` invariants, heartbeats
/// **never** affect consensus correctness; they're observability only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub message_id: Hash,
    pub validator: IdentityId,
    pub height: u64,
    pub round: u32,
    pub step: ConsensusStep,
    pub network_summary: NetworkSummary,
    pub timestamp: u64,
    pub signature: PostQuantumSignature,
}

/// Snapshot of a voter's local view of the round, included on every
/// `VoteMessage` for debug visibility.
///
/// **CRITICAL INVARIANT**: `vote_counts` uses `BTreeMap` (not
/// `HashMap`) so iteration order is canonical. Non-deterministic
/// iteration would break signature/hash consensus across nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStateView {
    pub height: u64,
    pub round: u32,
    pub step: ConsensusStep,
    pub known_proposals: Vec<Hash>,
    pub vote_counts: BTreeMap<Hash, u32>,
}

/// Lightweight network-health rollup carried on heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub active_validators: u32,
    pub health_score: f64,
    pub block_rate: f64,
}

/// Justification for a proposal — the votes from the prior round that
/// authorized this leader to repropose. Sent only when the round
/// counter is non-zero (view changes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Justification {
    pub round: u32,
    pub votes: Vec<ConsensusVote>,
    pub vote_power: u64,
}
