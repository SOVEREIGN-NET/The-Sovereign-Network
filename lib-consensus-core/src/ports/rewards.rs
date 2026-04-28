//! Reward port — engine emits one finalized-round event; runtime computes and
//! distributes the rewards.
//!
//! Per **AD-005** (`docs/epics/consensus-rewrite-decisions.md`), this trait is
//! fire-and-forget: methods are sync, return nothing, and the engine does not
//! branch on success. Failures inside the implementation surface as
//! observability events, not engine errors.
//!
//! Defined here in `lib-consensus-core` so the runtime adapter (in
//! `lib-economy`) can implement it without depending on `lib-consensus`.

use lib_identity::IdentityId;

/// Per-validator data needed to compute a round's rewards.
///
/// The engine constructs one of these per active validator from its
/// `ValidatorManager` snapshot and hands the slice to the callback. This keeps
/// the trait independent of `lib-consensus`'s `ValidatorManager` type.
#[derive(Debug, Clone)]
pub struct ValidatorRewardInput {
    pub identity: IdentityId,
    pub stake: u64,
    pub storage_provided: u64,
    pub voting_power: u64,
    pub reputation: u32,
}

/// Reward distribution hook called by the consensus engine at end-of-round.
///
/// The implementation owns the calculator + distribution side effects; the
/// engine knows nothing about reward formulas, ledger writes, or governance
/// adjustments.
pub trait RewardCallback: Send + Sync {
    /// Called once per finalized round. `validators` is the snapshot of
    /// active validators at `height`; `height` is the just-finalized block
    /// height.
    fn on_round_finalized(&self, validators: &[ValidatorRewardInput], height: u64);
}

/// No-op default for tests, bootstrap mode, or any context where reward
/// distribution is not yet wired. Drops every call silently — the engine
/// never sees a difference.
#[derive(Debug, Default)]
pub struct NoOpRewardCallback;

impl RewardCallback for NoOpRewardCallback {
    fn on_round_finalized(&self, _validators: &[ValidatorRewardInput], _height: u64) {}
}
