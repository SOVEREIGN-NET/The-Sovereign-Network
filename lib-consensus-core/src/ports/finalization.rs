//! Block-finalization port (CONS-402).
//!
//! Replaces the legacy async `BlockCommitCallback` (in
//! `lib-consensus/src/types/mod.rs`) with a fire-and-forget shape that
//! matches the architectural goal:
//!
//! - **`finalized()` is synchronous** — the engine drops a finalized
//!   `(proposal, proof)` envelope into a channel the impl owns and
//!   returns immediately. No `.await` on the storage layer from the
//!   engine, satisfying CE-ENG-4.
//! - **`recent_failure()` is async but only polled at round
//!   boundaries** — never inline. The engine queries it between
//!   rounds; a `Some(error)` transitions the FSM to `Halting` on the
//!   next iteration.
//!
//! ## Status
//!
//! This PR delivers the trait + `FinalizationError` enum + NoOp impl.
//! The actual rewiring of the engine away from `BlockCommitCallback`
//! happens in **CONS-504** (`Rewrite ConsensusBlockCommitter as
//! BlockFinalizationSink`). Until then, the legacy callback path
//! coexists; the runtime's commit executor (CONS-307) already
//! enforces the equivalent behaviour through the
//! `runtime_event_rx` failure feedback channel.
//!
//! ## Why both halves of the trait
//!
//! `finalized` is the hot path — every committed block. `recent_failure`
//! is the cold path — operator-driven recovery. Splitting them keeps
//! the hot path zero-async and the cold path explicit.

use async_trait::async_trait;
use lib_types::consensus::BftQuorumProof;

use crate::types::ConsensusProposal;

/// Failure kinds the engine cares about when reading
/// [`BlockFinalizationSink::recent_failure`]. Each variant maps to a
/// distinct halt reason at the FSM level.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FinalizationError {
    /// The storage layer rejected the commit (sled write error,
    /// disk full, schema mismatch). Persistent — operator must
    /// triage manually.
    #[error("storage failure at height {height}: {detail}")]
    StorageFailure { height: u64, detail: String },

    /// The committed block could not be applied because local state
    /// has diverged from the network's view (different parent hash,
    /// different validator set than expected at this height). BFT
    /// safety violation — halt to prevent voting on a fork.
    #[error("local chain divergence at height {height}: {detail}")]
    Divergence { height: u64, detail: String },

    /// The commit didn't complete within the runtime's per-block
    /// budget. Less severe than the other two — usually means the
    /// storage layer is wedged, not corrupt.
    #[error("commit timeout at height {height} after {elapsed_ms} ms")]
    Timeout { height: u64, elapsed_ms: u64 },
}

/// The runtime adapter that turns BFT-finalized blocks into durable
/// storage writes. Lives one crate above this trait
/// (`lib-consensus-runtime` / `lib-blockchain`); the engine never
/// holds a concrete implementation, only a `dyn BlockFinalizationSink`.
#[async_trait]
pub trait BlockFinalizationSink: Send + Sync {
    /// Hand off a finalized `(proposal, proof)` pair. Synchronous and
    /// best-effort — the impl typically pushes onto an
    /// `mpsc::UnboundedSender` and returns. Failures surface
    /// asynchronously through [`Self::recent_failure`].
    fn finalized(&self, proposal: ConsensusProposal, proof: BftQuorumProof);

    /// Return the most recent finalization failure, if any. The
    /// engine polls this once per round-boundary tick; a `Some(...)`
    /// drives the FSM into `Halting` on the next select! iteration.
    /// Returning `None` is the normal "everything is fine" signal.
    ///
    /// Calling this is allowed to clear the buffer — the contract is
    /// "report a failure at most once per call". Persistent failures
    /// re-trigger by surfacing again on the next tick if the impl
    /// re-buffers them, which is the impl's choice.
    async fn recent_failure(&self) -> Option<FinalizationError>;
}

/// No-op default for tests, bootstrap mode, or contexts where block
/// finalization is not yet wired. Drops every `finalized()` call
/// silently; never reports a failure.
#[derive(Debug, Default)]
pub struct NoOpBlockFinalizationSink;

#[async_trait]
impl BlockFinalizationSink for NoOpBlockFinalizationSink {
    fn finalized(&self, _proposal: ConsensusProposal, _proof: BftQuorumProof) {}
    async fn recent_failure(&self) -> Option<FinalizationError> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_finalized_returns_unit_and_no_failure() {
        let sink = NoOpBlockFinalizationSink;
        // Just confirms the trait surface compiles and the NoOp doesn't
        // panic; no assertions on internal state because there isn't any.
        let proposal = test_proposal();
        let proof = test_proof();
        sink.finalized(proposal, proof);
        assert!(sink.recent_failure().await.is_none());
    }

    fn test_proposal() -> ConsensusProposal {
        use crate::types::ConsensusProof;
        use lib_crypto::{Hash, PostQuantumSignature};
        use lib_identity::IdentityId;
        use lib_types::consensus::ConsensusType;
        ConsensusProposal {
            id: Hash::default(),
            proposer: IdentityId::default(),
            height: 1,
            round: 0,
            protocol_version: 1,
            previous_hash: Hash::default(),
            block_data: vec![],
            timestamp: 0,
            signature: PostQuantumSignature::default(),
            consensus_proof: ConsensusProof::empty(ConsensusType::ByzantineFaultTolerance, 0),
            valid_round: None,
        }
    }

    fn test_proof() -> BftQuorumProof {
        BftQuorumProof {
            height: 1,
            proposal_id: [0; 32],
            total_validators: 0,
            attestations: vec![],
        }
    }
}
