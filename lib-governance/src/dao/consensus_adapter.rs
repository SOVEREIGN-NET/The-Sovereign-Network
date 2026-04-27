//! Adapter implementing `lib_consensus_core::ports::GovernanceCallback` over
//! the in-memory `DaoEngine`.
//!
//! Per **AD-005** the trait is fire-and-forget: failures are logged here,
//! never propagated to the engine. The engine emits one
//! `on_round_finalized(height)` per finalized round; this adapter spawns
//! a task that walks expired proposals and runs them.
//!
//! ## Why spawn (not `Handle::block_on`)
//!
//! `on_round_finalized` is invoked from inside the consensus engine's async
//! event loop, i.e. from a thread that is *already* running on a Tokio
//! runtime worker. Calling `Handle::block_on` from such a thread panics on
//! a multi-thread runtime (`Cannot start a runtime from within a runtime`)
//! and can deadlock on a current-thread runtime. PR #2385 review (Copilot)
//! flagged this — fix is to schedule the async work via `Handle::spawn` and
//! switch the engine lock to `tokio::sync::Mutex` so the guard can safely
//! cross await points.

use crate::dao::DaoEngine;
use lib_consensus_core::ports::GovernanceCallback;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::Mutex;

/// Runtime-side adapter that executes governance work in response to engine
/// `on_round_finalized` events.
pub struct ConsensusGovernanceAdapter {
    engine: Arc<Mutex<DaoEngine>>,
    /// Runtime handle used to spawn `process_expired_proposals`. `None`
    /// means "discover the ambient runtime at call time" — primarily for
    /// tests; production wires an explicit handle via [`with_runtime`].
    runtime: Option<Handle>,
}

impl ConsensusGovernanceAdapter {
    /// Create a new adapter wrapping a fresh `DaoEngine`. Captures the current
    /// Tokio runtime handle if one is available at construction time.
    pub fn new() -> Self {
        Self {
            engine: Arc::new(Mutex::new(DaoEngine::new())),
            runtime: Handle::try_current().ok(),
        }
    }

    /// Create from an existing `DaoEngine` and an explicit runtime handle.
    pub fn with_runtime(engine: DaoEngine, runtime: Handle) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
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

        let engine = Arc::clone(&self.engine);
        runtime.spawn(async move {
            let mut engine = engine.lock().await;
            // process_expired_proposals is `#[deprecated]` (the canonical path
            // is `blockchain.execute_dao_proposal` in lib-blockchain). Suppress
            // the warning here — moving to the blockchain-backed path is a
            // separate refactor outside CONS-106's scope.
            #[allow(deprecated)]
            if let Err(e) = engine.process_expired_proposals().await {
                tracing::warn!(
                    error = %e,
                    height,
                    "DAO process_expired_proposals failed"
                );
            }
        });
    }
}
