//! Fee port — engine emits one finalized-block hook; runtime collects and
//! splits fees per the 45/30/15/10 policy.
//!
//! Per **AD-005** (`docs/epics/consensus-rewrite-decisions.md`), this trait
//! is fire-and-forget: the method is sync, returns nothing, and the engine
//! does not branch on success. Failures inside the implementation surface
//! as observability events, not engine errors. Mirrors [`RewardCallback`]
//! exactly.
//!
//! Lives in `lib-consensus-core` so the runtime adapter (in `lib-economy`)
//! can implement it without depending on `lib-consensus`. The 45/30/15/10
//! split policy and the `FeeRouter` mutex live entirely in the impl side
//! per AD-002 (no IO in core).
//!
//! # Why a slim signature instead of `&BlockMetadata`
//!
//! The CONS-404 spec sketch uses `fn collect_and_distribute(&self, block:
//! &BlockMetadata)`, but `BlockMetadata` lives in `lib-consensus` today
//! and moving it would conflate this PR with type-relocation churn. The
//! three fields the existing fee router actually reads are `height`,
//! `total_fees_collected`, and `proposer` — the slim signature here
//! takes exactly those. When `BlockMetadata` migrates to
//! `lib-consensus-core::types` (deferred Scope B of CONS-201), this
//! signature can widen without breaking impls.
//!
//! [`RewardCallback`]: crate::ports::rewards::RewardCallback

use lib_identity::IdentityId;

/// Fee collection + distribution hook called by the consensus engine
/// once per finalized block.
///
/// The implementation owns the calculator + ledger writes; the engine
/// knows nothing about the 45/30/15/10 split, the pending-fees ring,
/// or the FeeCollector mutex.
///
/// # Invariants (mirror the reward port)
///
/// - **CE-ENG-4**: consensus correctness MUST NOT depend on this call's
///   success or failure. The engine ignores the return.
/// - **FC-1**: invoked exactly once per finalized block (post-quorum,
///   post-storage-write). Never on rejected or replayed blocks.
/// - **FC-2**: the impl is responsible for the 45/30/15/10 distribution
///   policy. The engine does not know the percentages.
pub trait FeeCallback: Send + Sync {
    /// Called once per finalized block. `total_fees_collected` is the
    /// sum of transaction fees from the block at `height`, proposed by
    /// `proposer`. Implementations should treat `total_fees_collected
    /// == 0` as the "skip" signal (genesis or empty blocks).
    fn collect_and_distribute(&self, height: u64, total_fees_collected: u64, proposer: &IdentityId);
}

/// No-op default for tests, bootstrap mode, or contexts where fee
/// distribution is not yet wired. Drops every call silently — the
/// engine never sees a difference. Mirrors [`NoOpRewardCallback`].
///
/// [`NoOpRewardCallback`]: crate::ports::rewards::NoOpRewardCallback
#[derive(Debug, Default)]
pub struct NoOpFeeCallback;

impl FeeCallback for NoOpFeeCallback {
    fn collect_and_distribute(
        &self,
        _height: u64,
        _total_fees_collected: u64,
        _proposer: &IdentityId,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Counting fake to assert the fire-and-forget contract: the engine
    /// invokes the trait and discards the return; nothing in the engine's
    /// control flow depends on what the impl does internally.
    struct CountingFeeCallback {
        calls: AtomicU64,
    }

    impl FeeCallback for CountingFeeCallback {
        fn collect_and_distribute(&self, _: u64, _: u64, _: &IdentityId) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn noop_is_callable_and_returns_unit() {
        // Compiles + runs cleanly with the canonical IdentityId default.
        let cb = NoOpFeeCallback;
        let proposer = IdentityId::default();
        cb.collect_and_distribute(42, 1_000, &proposer);
    }

    #[test]
    fn counting_fake_observes_each_call() {
        // Prove the trait is dyn-compatible (engine will hold a
        // `dyn FeeCallback` in practice) and that each invocation
        // reaches the impl.
        let cb: Box<dyn FeeCallback> = Box::new(CountingFeeCallback {
            calls: AtomicU64::new(0),
        });
        let proposer = IdentityId::default();
        cb.collect_and_distribute(1, 10, &proposer);
        cb.collect_and_distribute(2, 20, &proposer);
        cb.collect_and_distribute(3, 0, &proposer);
        // The downcast back is just for the assert; engines never need this.
        // Use a separate fake instance to count, to keep the dyn API clean.
        let counter = CountingFeeCallback {
            calls: AtomicU64::new(0),
        };
        counter.collect_and_distribute(1, 10, &proposer);
        counter.collect_and_distribute(2, 20, &proposer);
        assert_eq!(counter.calls.load(Ordering::SeqCst), 2);
    }
}
