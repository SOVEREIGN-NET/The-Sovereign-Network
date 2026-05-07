//! Governance port — engine emits one event per finalized round; runtime
//! adapter handles expired proposals and parameter updates.
//!
//! Per **AD-005** (`docs/epics/consensus-rewrite-decisions.md`), this trait is
//! fire-and-forget: methods are sync, return nothing, and the engine does not
//! branch on success. Failures inside the implementation surface as
//! observability events, not engine errors.
//!
//! Defined here in `lib-consensus-core` so the runtime adapter (in
//! `lib-governance`) can implement it without depending on `lib-consensus`.

/// Governance hook called by the consensus engine.
///
/// The implementation owns the DAO engine + side effects (proposal execution,
/// treasury updates, parameter validation); the engine knows nothing about
/// proposal types, voting power formulas, or treasury accounting.
pub trait GovernanceCallback: Send + Sync {
    /// Called once per finalized round. Implementation walks expired
    /// proposals at `height` and executes any that passed.
    fn on_round_finalized(&self, height: u64);
}

/// No-op default for tests, bootstrap mode, or any context where governance
/// is not yet wired. Drops every call silently — the engine never sees a
/// difference.
#[derive(Debug, Default)]
pub struct NoOpGovernanceCallback;

impl GovernanceCallback for NoOpGovernanceCallback {
    fn on_round_finalized(&self, _height: u64) {}
}
