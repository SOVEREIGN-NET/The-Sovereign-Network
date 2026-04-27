//! FSM state types for the consensus validator.
//!
//! These types describe the *control state* of a single validator FSM
//! at a single (height, round). They replace the implicit state machine
//! that previously lived in `lib_consensus::engines::consensus_engine`
//! as a soup of [`ConsensusStep`] checks, timer flags, and ad-hoc
//! "is this round dead yet?" booleans.
//!
//! [`ConsensusStep`]: crate::types
//!
//! # State diagram
//!
//! ```text
//!                              ┌──────────────────────────┐
//!                              │                          ▼
//! ┌──────┐  StartRound   ┌──────────┐  ProposalAccepted  ┌────────────┐
//! │ Idle │──────────────▶│ Proposing│───────────────────▶│ Prevoting  │
//! └──────┘               └──────────┘                    └─────┬──────┘
//!     ▲                       │                                │
//!     │ NewRound /             │ Timeout / InvalidProposal     │ +2/3 prevotes
//!     │ HeightAdvance          ▼                               ▼
//!     │                  ┌──────────┐                   ┌───────────────┐
//!     │                  │ Rejected │                   │ Precommitting │
//!     │                  │ (reason) │                   └────┬──────────┘
//!     │                  └──────────┘                        │
//!     │                       │                              │ +2/3 precommits
//!     │                       │                              ▼
//!     │                       │                        ┌───────────┐
//!     │                       │                        │ Committed │
//!     │                       │                        └───────────┘
//!     │                       │
//!     │              ┌────────┴─────────┐
//!     │              ▼                  ▼
//!     │         ┌─────────┐    ┌───────────────────┐
//!     └─────────│  Hung   │    │ HaltedForUpgrade  │
//!               └─────────┘    └───────────────────┘
//!     watchdog timeout      protocol-version mismatch
//! ```
//!
//! # Variant invariants
//!
//! - **`Idle`** — between rounds. No timers running, no votes admitted.
//! - **`Proposing`** — leader's window to broadcast a proposal. Followers
//!   accept proposals from the height-elected proposer; non-followers wait.
//! - **`Prevoting`** — proposal admitted; collecting prevotes. Exits to
//!   `Precommitting` on +2/3 prevotes for a single block, or to `Rejected`
//!   on timeout / nil-vote quorum.
//! - **`Precommitting`** — exits to `Committed` on +2/3 precommits, or to
//!   `Rejected` on timeout.
//! - **`Committed`** — terminal-success for the round; the height advances
//!   and the FSM resets to `Idle` for the next height.
//! - **`Rejected(reason)`** — terminal-failure for the round; the round
//!   number advances (view change) and the FSM transitions to `Idle` with
//!   the same height. Carries the `RejectionReason` for observability.
//! - **`Hung`** — the watchdog timed out (CONS-309) without any progress
//!   action being emitted. Terminal until external recovery.
//! - **`HaltedForUpgrade`** — protocol-version mismatch detected. The FSM
//!   stops admitting messages until operator intervention bumps the local
//!   `CONSENSUS_PROTOCOL_VERSION` and restarts the node.
//!
//! # Why this enum and not `ConsensusStep`
//!
//! `ConsensusStep` (Propose / PreVote / PreCommit / Commit / NewRound) is
//! the *wire-format* phase tag used in vote messages and audit logs. It
//! cannot represent terminal states (`Committed`, `Rejected`, `Hung`,
//! `HaltedForUpgrade`) — those were tracked separately as flags on the
//! engine, which is what the rewrite is consolidating. `FsmState` carries
//! the full control state so the `transition()` function (CONS-302) can be
//! total: `(state, event) -> (state, actions)` with no implicit branches.

use serde::{Deserialize, Serialize};

/// Why a round transitioned to [`FsmState::Rejected`].
///
/// Produced by `transition()` (CONS-302) when a round terminates without
/// reaching `Committed`. Each variant maps to a distinct timeout or
/// validation failure observed by the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// Prevote step ended without a +2/3 quorum for any single block.
    /// Either the prevote timeout fired, or +2/3 prevoted nil.
    InsufficientPrevotes,

    /// Precommit step ended without a +2/3 quorum for any single block.
    /// Either the precommit timeout fired, or +2/3 precommitted nil.
    InsufficientPrecommits,

    /// A step-level timeout fired during `Proposing` or while waiting for
    /// the proposer's first message. Distinct from quorum-shortfall
    /// timeouts (which use the more specific `InsufficientPre*` reasons).
    Timeout,

    /// The proposal failed local validation: bad signature, wrong proposer
    /// for (height, round), bad parent hash, malformed block data, etc.
    /// The proposal is rejected before any prevote is cast.
    InvalidBlock,
}

/// Control state of a single validator FSM at a single (height, round).
///
/// See the module-level state diagram for transitions. Pre-rewrite the
/// equivalent state was distributed across `ConsensusRound.step` (the
/// happy-path tag) plus several boolean flags for terminal conditions —
/// `FsmState` consolidates them into a single enum so `transition()`
/// (CONS-302) can be total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsmState {
    /// No active round at the current height.  Entered at startup and
    /// after each round-completion event.
    Idle,

    /// The local validator (or a remote validator we follow) is in the
    /// proposal window. The FSM waits for either a valid proposal from
    /// the elected proposer or a propose-timeout.
    Proposing,

    /// A valid proposal was admitted.  The FSM accepts and tallies
    /// prevotes; exits when a single block clears the +2/3 prevote
    /// threshold or the prevote step times out.
    Prevoting,

    /// +2/3 prevotes observed for a single block. The FSM accepts and
    /// tallies precommits; exits when the same block clears the +2/3
    /// precommit threshold or the precommit step times out.
    Precommitting,

    /// +2/3 precommits observed for a single block at this round. This
    /// height is committed; the FSM resets to `Idle` for the next height.
    /// Terminal-success.
    Committed,

    /// The round terminated without reaching `Committed`. The FSM
    /// transitions back to `Idle` with `round + 1` (view change) at the
    /// same height. Terminal-failure for this round only.
    Rejected(RejectionReason),

    /// The watchdog (CONS-309) detected no progress action emitted for
    /// `WATCHDOG_THRESHOLD_MULTIPLIER × max_step_timeout` and halted the
    /// FSM. Terminal until external recovery.
    Hung,

    /// A protocol-version mismatch was detected (e.g. peer running v1 vs
    /// local v2). The FSM stops admitting messages until the operator
    /// resolves the mismatch.  Terminal until external intervention.
    HaltedForUpgrade,
}

impl FsmState {
    /// Returns true for states that the FSM does not exit on its own.
    /// `Committed` and `Rejected` round-trip back to `Idle`; `Hung` and
    /// `HaltedForUpgrade` require external recovery.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            FsmState::Committed
                | FsmState::Rejected(_)
                | FsmState::Hung
                | FsmState::HaltedForUpgrade
        )
    }

    /// Returns true for states reachable via external recovery only.
    /// Distinct from [`is_terminal`]: `Committed` and `Rejected` are
    /// terminal but self-clearing on the next round; `Hung` and
    /// `HaltedForUpgrade` are not.
    ///
    /// [`is_terminal`]: Self::is_terminal
    pub fn requires_external_recovery(&self) -> bool {
        matches!(self, FsmState::Hung | FsmState::HaltedForUpgrade)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CONS-301 acceptance criterion: all 8 variants reachable in tests.
    /// Constructs each variant once and exercises a small property on it
    /// so future enum changes break the test, not just the build.
    #[test]
    fn all_variants_constructible_and_distinct() {
        let states = [
            FsmState::Idle,
            FsmState::Proposing,
            FsmState::Prevoting,
            FsmState::Precommitting,
            FsmState::Committed,
            FsmState::Rejected(RejectionReason::InsufficientPrevotes),
            FsmState::Hung,
            FsmState::HaltedForUpgrade,
        ];
        // Every variant is distinct under PartialEq.
        for (i, a) in states.iter().enumerate() {
            for (j, b) in states.iter().enumerate() {
                assert_eq!(a == b, i == j, "{:?} vs {:?}", a, b);
            }
        }
    }

    #[test]
    fn rejected_carries_distinct_reasons() {
        let reasons = [
            RejectionReason::InsufficientPrevotes,
            RejectionReason::InsufficientPrecommits,
            RejectionReason::Timeout,
            RejectionReason::InvalidBlock,
        ];
        // All 4 reasons distinct.
        for (i, a) in reasons.iter().enumerate() {
            for (j, b) in reasons.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
        // `Rejected` discriminates on the inner reason.
        assert_ne!(
            FsmState::Rejected(RejectionReason::Timeout),
            FsmState::Rejected(RejectionReason::InvalidBlock)
        );
    }

    #[test]
    fn is_terminal_classifies_correctly() {
        assert!(!FsmState::Idle.is_terminal());
        assert!(!FsmState::Proposing.is_terminal());
        assert!(!FsmState::Prevoting.is_terminal());
        assert!(!FsmState::Precommitting.is_terminal());

        assert!(FsmState::Committed.is_terminal());
        assert!(FsmState::Rejected(RejectionReason::Timeout).is_terminal());
        assert!(FsmState::Hung.is_terminal());
        assert!(FsmState::HaltedForUpgrade.is_terminal());
    }

    #[test]
    fn requires_external_recovery_only_for_hung_and_halted() {
        assert!(!FsmState::Idle.requires_external_recovery());
        assert!(!FsmState::Committed.requires_external_recovery());
        assert!(!FsmState::Rejected(RejectionReason::Timeout).requires_external_recovery());

        assert!(FsmState::Hung.requires_external_recovery());
        assert!(FsmState::HaltedForUpgrade.requires_external_recovery());
    }

    /// Compile-time check that both types implement the serde traits.
    /// lib-consensus-core deliberately doesn't take a serde_json or bincode
    /// dependency, so a runtime round-trip test would force a new dep just
    /// to prove what the derive macro already does. The fn-pointer
    /// assignment fails to compile if `Serialize`/`Deserialize` aren't on
    /// the type — same guarantee.
    #[test]
    fn states_implement_serde_traits() {
        fn assert_serializable<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}
        assert_serializable::<FsmState>();
        assert_serializable::<RejectionReason>();
    }
}
