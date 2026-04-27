//! Consensus-affecting constants — single source of truth.
//!
//! Per AD-011 (`docs/epics/consensus-rewrite-decisions.md`), every constant
//! that materially affects BFT safety or liveness lives here so changes
//! are visible in one place and reviewable as a cross-cutting protocol
//! decision rather than a buried magic number.
//!
//! ## Constants
//!
//! - [`WRONG_CHAIN_HALT_THRESHOLD`] — number of inbound messages from a
//!   conflicting chain before this node halts (anti-fork guard).
//! - [`MAX_BROADCAST_BUDGET_MS`] — wall-clock budget for completing one
//!   round of broadcast actions before the watchdog escalates.
//! - [`WATCHDOG_THRESHOLD_MULTIPLIER`] — multiplier applied to the per-
//!   step timeout to derive the watchdog firing threshold (CONS-309).
//! - [`COMMIT_FAILURE_HALT_THRESHOLD`] — number of consecutive failed
//!   block-commit attempts before the runtime halts.
//!
//! ## Runtime startup check (CONS-310 acceptance criterion)
//!
//! The runtime is expected to assert at startup that the transport's
//! reported idle timeout (`TransportInfo::idle_timeout()`, CONS-403)
//! does not exceed `MAX_BROADCAST_BUDGET_MS * 100`. If it does, the
//! transport will silently swallow stuck-broadcast scenarios that this
//! crate's watchdog would otherwise surface, masking liveness bugs.
//! That assertion lives in `lib-consensus-runtime`'s startup path —
//! intentionally NOT here so this module stays a pure data file with
//! no IO or trait dependencies.

/// Inbound messages from a chain whose previous-hash chain disagrees
/// with our local chain that we tolerate before halting consensus.
/// Three rounds is enough to ride out a transient peer reordering
/// (a couple of late messages from a forked peer) but short enough
/// that a sustained fork attempt is caught quickly.
///
/// Replaces the prior `WRONG_CHAIN_WIPE_THRESHOLD` magic number that
/// lived in `zhtp/src/runtime/components/consensus.rs:479`. Moved here
/// per CONS-310 / AD-011.
pub const WRONG_CHAIN_HALT_THRESHOLD: u32 = 3;

/// Maximum wall-clock budget (milliseconds) for completing one round
/// of broadcast actions emitted by `transition()`. If the runtime
/// cannot drain its action queue within this window, the watchdog
/// (CONS-309) escalates to `Hung`.
///
/// 750 ms covers the slowest expected broadcast hop on the Sovereign
/// mesh (post-quantum signature + QUIC round-trip on a residential
/// connection) with margin. The runtime startup check refuses to
/// start if the transport's idle timer is more than 100× this value
/// (75 s) — that combination would mean stuck broadcasts disappear
/// into the transport instead of surfacing.
pub const MAX_BROADCAST_BUDGET_MS: u64 = 750;

/// Multiplier applied to the per-step timeout to derive the watchdog
/// firing threshold. e.g. for a 12 s round time and 4 phases, the
/// per-phase timeout is ~3 s; the watchdog fires after `5 × 3 s =
/// 15 s` without progress.
///
/// Five covers legitimate slow-broadcast scenarios (cold validator,
/// post-quantum signature on a slow CPU) while still catching truly
/// stuck consensus before the operator-page SLA window.
pub const WATCHDOG_THRESHOLD_MULTIPLIER: u32 = 5;

/// Consecutive failed block-commit attempts tolerated before halting
/// consensus and surfacing the failure.
///
/// One: a single commit failure is already evidence of a serious
/// problem (storage error, blockchain divergence, missing proposal
/// artifact). Continuing past it risks committing the wrong state.
/// The runtime halts and waits for operator triage rather than
/// retrying blindly.
pub const COMMIT_FAILURE_HALT_THRESHOLD: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: the broadcast budget × 100 is the boundary the runtime
    /// startup check uses against the transport's idle timer. Guards
    /// the relationship documented in the module docs so reviewers
    /// notice if either constant moves without the other.
    #[test]
    fn broadcast_budget_times_100_is_75_seconds() {
        let limit_ms = MAX_BROADCAST_BUDGET_MS * 100;
        assert_eq!(
            limit_ms, 75_000,
            "MAX_BROADCAST_BUDGET_MS * 100 changed; update lib-consensus-runtime's startup \
             assertion against TransportInfo::idle_timeout() and any operator runbooks that \
             reference the 75 s ceiling."
        );
    }

    #[test]
    fn watchdog_threshold_multiplier_is_finite_and_nonzero() {
        // Zero means the watchdog fires immediately on every step
        // entry; large values mean it never fires. Either is a
        // misconfiguration.
        assert!(WATCHDOG_THRESHOLD_MULTIPLIER > 0);
        assert!(WATCHDOG_THRESHOLD_MULTIPLIER < 100);
    }

    #[test]
    fn commit_failure_halt_threshold_is_strict() {
        // Document that we deliberately halt on the first failure.
        // If a future change relaxes this, the test forces the
        // change to be visible and intentional.
        assert_eq!(
            COMMIT_FAILURE_HALT_THRESHOLD, 1,
            "Commit-failure halt threshold relaxed — this is a BFT-safety-relevant change. \
             Add an architecture decision (AD-NNN) before bumping."
        );
    }

    #[test]
    fn wrong_chain_halt_threshold_within_safe_band() {
        // Tolerable = above 1 (so transient reordering doesn't trigger
        // halt); bounded = below 10 (so a sustained fork doesn't run
        // long enough to confuse downstream observers).
        assert!(
            (2..10).contains(&WRONG_CHAIN_HALT_THRESHOLD),
            "WRONG_CHAIN_HALT_THRESHOLD outside the safe band 2..=9"
        );
    }
}
