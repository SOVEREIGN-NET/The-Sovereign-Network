//! Outbound consensus-message port (CONS-401).
//!
//! Migrated from `lib-consensus::types::MessageBroadcaster`. The
//! engine's only outbound side-effect goes through this trait — every
//! `enter_*_step`, heartbeat, and proposal-relay site emits a
//! `ValidatorMessage` and a recipient list, the runtime's executor
//! task picks them up and calls `broadcast_to_validators` exactly
//! once per envelope (CONS-306).
//!
//! ## Invariants
//!
//! - **CE-ENG-1**: ConsensusEngine never constructs, configures, or
//!   inspects the broadcaster — it only calls it.
//! - **CE-ENG-2**: ConsensusEngine broadcasts only signed, canonical
//!   `ValidatorMessage`s. Never raw `Vote`, `Proposal`, or internal
//!   structs.
//! - **CE-ENG-3**: Broadcast is a side-effect of a completed consensus
//!   step, never a prerequisite. Preserves determinism + replayability.
//! - **CE-ENG-4**: Consensus correctness MUST NOT depend on broadcast
//!   success, failure, or reachability. No retries. No quorum checks.
//!   No "if delivered < X then…". Liveness logic belongs elsewhere
//!   (timeouts, view change).
//! - **CE-ENG-5**: ConsensusEngine never queries network state to
//!   determine "who to send to". The network delivers; consensus
//!   decides authority. Validator set is passed explicitly.
//! - **CE-ENG-6**: Side-effect isolation. Broadcasting is the only
//!   external side-effect ConsensusEngine performs.
//! - **CE-ENG-7**: Deterministic emission. Given the same inputs,
//!   ConsensusEngine emits the same sequence of `ValidatorMessage`s
//!   regardless of network behavior — what makes simulation + replay
//!   possible.
//!
//! `lib-consensus::types::MessageBroadcaster` is now a re-export of
//! this trait so the existing import path keeps working.

use async_trait::async_trait;
use lib_identity::IdentityId;

use crate::types::ValidatorMessage;

/// Send a signed canonical `ValidatorMessage` to the given validator
/// set. Best-effort per CE-ENG-4 — errors are surfaced for telemetry,
/// not used for control flow.
#[async_trait]
pub trait MessageBroadcaster: Send + Sync {
    /// Broadcast `message` to the validators in `validator_ids`.
    ///
    /// Invariant CE-ENG-5: the engine passes the validator set
    /// explicitly. It never queries network state to determine
    /// "who to send to".
    async fn broadcast_to_validators(
        &self,
        message: ValidatorMessage,
        validator_ids: &[IdentityId],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
