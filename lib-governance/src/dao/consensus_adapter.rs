//! Adapter implementing `lib_consensus_core::ports::GovernanceCallback` over
//! the in-memory `DaoEngine`.
//!
//! Per **AD-005**, the trait is fire-and-forget: failures are logged here,
//! never propagated to the engine. The engine just emits one
//! `on_round_finalized(height)` per finalized round; this adapter walks
//! expired proposals and runs them.
//!
//! Async work inside the adapter is bridged via a Tokio handle reference
//! captured at construction (or `tokio::runtime::Handle::try_current()` if
//! none is provided). If no runtime is available the call is logged and
//! dropped — production callers always wire a handle.

use crate::dao::DaoEngine;
use lib_consensus_core::ports::GovernanceCallback;
use std::sync::Mutex;
use tokio::runtime::Handle;

/// Runtime-side adapter that executes governance work in response to engine
/// `on_round_finalized` events.
pub struct ConsensusGovernanceAdapter {
    engine: Mutex<DaoEngine>,
    /// Runtime handle used to drive `process_expired_proposals` (which is
    /// `async`). `None` means "use the ambient runtime if any" — primarily
    /// for tests; production should pass an explicit handle.
    runtime: Option<Handle>,
}

impl ConsensusGovernanceAdapter {
    /// Create a new adapter wrapping a fresh `DaoEngine`. Captures the current
    /// Tokio runtime handle if one is available.
    pub fn new() -> Self {
        Self {
            engine: Mutex::new(DaoEngine::new()),
            runtime: Handle::try_current().ok(),
        }
    }

    /// Create from an existing `DaoEngine` and an explicit runtime handle.
    pub fn with_runtime(engine: DaoEngine, runtime: Handle) -> Self {
        Self {
            engine: Mutex::new(engine),
            runtime: Some(runtime),
        }
    }
}

impl Default for ConsensusGovernanceAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceCallback for ConsensusGovernanceAdapter {
    fn on_round_finalized(&self, height: u64) {
        let runtime = match self.runtime.clone().or_else(|| Handle::try_current().ok()) {
            Some(rt) => rt,
            None => {
                tracing::warn!(
                    height,
                    "GovernanceCallback fired without a Tokio runtime handle — \
                     skipping process_expired_proposals"
                );
                return;
            }
        };

        // Take a snapshot of the engine for the async work; the lock is held
        // only briefly. If multiple finalize calls race, the second waits at
        // the mutex — they are run sequentially.
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // process_expired_proposals is async; block_on within the captured
        // runtime context. Using a block_in_place + handle.block_on pattern
        // would deadlock on a current-thread runtime — for the multi-thread
        // runtime that zhtp uses, plain `runtime.block_on` is fine when called
        // from a non-runtime thread.
        //
        // The DaoEngine method is `#[deprecated]` (the canonical path is
        // `blockchain.execute_dao_proposal` in lib-blockchain). Suppress the
        // warning here — moving to the blockchain-backed path is a separate
        // refactor outside CONS-106's scope.
        #[allow(deprecated)]
        if let Err(e) = runtime.block_on(engine.process_expired_proposals()) {
            tracing::warn!(
                error = %e,
                height,
                "DAO process_expired_proposals failed"
            );
        }
    }
}
