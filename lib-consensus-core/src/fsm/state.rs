//! `ValidatorState` — the full validator FSM control state.
//!
//! Designed as a deterministic Markov chain: every `(state, event)`
//! pair maps to exactly one `(next_state, actions)` tuple, computed by
//! the pure [`transition()`] function. The same set of transitions is
//! also exposed as a runtime-queryable data table in
//! [`super::transition_table`] for diagrams, fuzzing, and operator
//! tooling — both forms are kept in sync by tests.
//!
//! [`transition()`]: super::transition::transition
//!
//! ## State landscape
//!
//! Active consensus phases (one round-trip per height):
//!
//! ```text
//! Idle ─→ Proposing ─→ Prevoting ─→ Precommitting ─→ Committed ─→ Idle (next height)
//! ```
//!
//! The phase names match the wire-level `VoteType` (PreVote, PreCommit,
//! Commit) so internal control state and on-the-wire vote tags stay
//! consistent. Walk-through timeout semantics (see [`transition()`])
//! mirror the existing Sovereign engine: each phase before
//! `Committed` advances on timeout to the next phase; only
//! `Committed.Timeout` triggers `Rejected` + view change.
//!
//! Lifecycle states (entry/exit at the network boundary):
//!
//! - [`Bootstrapping`] — first-ever start, no local state, downloading
//!   from genesis.
//! - [`CatchingUp`] — local state exists, height behind peers; sync to
//!   the tip then transition to `Idle`.
//! - [`ShuttingDown`] — graceful exit. Logs flushed; no more events
//!   processed.
//!
//! Failure / coordination states:
//!
//! - [`Rejected`] — a round terminated without finalization. Transient
//!   between rounds; runtime resets to `Idle` at `round + 1`.
//! - [`Hung`] — the watchdog detected no progress; carries the prior
//!   state and `since` timestamp so the runtime can decide whether
//!   to recover or escalate.
//! - [`Halting`] — operator-coordinated halt at a specific height
//!   (upgrade scheduled, emergency, fork detected). Block production
//!   stops at `triggered_at_height`.
//! - [`CoordinatedUpdate`] — second phase of a planned upgrade: the
//!   *new* binary is running and waiting at a barrier height for
//!   quorum readiness. On quorum-ready: transition to `Idle` on the
//!   new protocol version.
//! - [`Slashed`] — validator was punished; out of the active set
//!   until the slashing window closes.
//! - [`Evicted`] — validator was removed from the active set
//!   (insufficient stake, repeated misbehavior, etc.). Terminal until
//!   re-admission via re-registration.
//! - [`Panic`] — runtime detected a critical error (Byzantine
//!   evidence, state corruption, OOM, …). Carries the prior state so
//!   recovery can re-enter where the FSM was. Recoverable panics
//!   reset to `Idle`; non-recoverable force a transition to `Halting`
//!   with `ResumeCondition::Never`.
//!
//! [`Bootstrapping`]: ValidatorState::Bootstrapping
//! [`CatchingUp`]: ValidatorState::CatchingUp
//! [`ShuttingDown`]: ValidatorState::ShuttingDown
//! [`Rejected`]: ValidatorState::Rejected
//! [`Hung`]: ValidatorState::Hung
//! [`Halting`]: ValidatorState::Halting
//! [`CoordinatedUpdate`]: ValidatorState::CoordinatedUpdate
//! [`Slashed`]: ValidatorState::Slashed
//! [`Evicted`]: ValidatorState::Evicted
//! [`Panic`]: ValidatorState::Panic

use std::time::Instant;

/// Why a round terminated in [`ValidatorState::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// Prevote phase ended without +2/3 prevotes for any single block.
    InsufficientPrevotes,
    /// Precommit phase ended without +2/3 precommits for any single block.
    InsufficientPrecommits,
    /// Generic / unspecified timeout-driven rejection — surfaces only
    /// from explicit `VoteFailed(Timeout)` injections.
    Timeout,
    /// The proposal failed local validation: bad signature, wrong
    /// proposer for (height, round), bad parent hash, malformed block.
    InvalidBlock,
}

/// Why an operator initiated a coordinated halt (or one fired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HaltReason {
    /// Scheduled protocol upgrade — operators bumping
    /// `CONSENSUS_PROTOCOL_VERSION` and restarting binaries.
    UpgradeScheduled,
    /// Operator-triggered emergency halt.
    EmergencyHalt,
    /// End-of-epoch barrier (validator set change, parameter change).
    EpochBoundary,
    /// Consensus stuck for too long; manual halt to investigate.
    ConsensusFailure,
    /// Active validator count fell below the safety threshold.
    InsufficientValidators,
    /// Two committed blocks at the same height observed — fork.
    ForkDetected,
}

/// What it takes to leave [`ValidatorState::Halting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeCondition {
    /// Operator must restart the node manually.
    ManualRestart,
    /// 2/3+ validators report ready (used after coordinated upgrade).
    QuorumReady,
    /// Specific upgrade target version reached and validated.
    UpgradeComplete,
    /// No automatic resume — terminal until manual `--force` flag.
    Never,
}

/// Why a validator entered [`ValidatorState::Panic`]. Broadest
/// possible coverage — every panic-able runtime condition has a tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PanicReason {
    // ----- Consensus safety -----
    /// Same validator double-voted at the same (height, round).
    DoubleVote,
    /// A non-elected validator broadcast a proposal.
    UnauthorizedProposer,
    /// Equivocation or other Byzantine vote pattern detected.
    ByzantineVoteDetected,
    /// A slashable offense was committed by a peer or self.
    SlashableOffense,
    /// Two committed blocks at the same height — chain fork.
    ConflictingCommits,

    // ----- Liveness -----
    /// Watchdog timeout fired without any progress signal.
    WatchdogExpired,
    /// Heartbeat from required peer missed beyond threshold.
    HeartbeatMissed,
    /// Block production halted for longer than tolerated.
    BlockProductionStopped,
    /// Active peer count below the BFT safety threshold.
    PeerCountBelowThreshold,

    // ----- State integrity -----
    /// Internal state machine reached an impossible state.
    StateMachineCorrupted,
    /// Local height regressed (saw lower height than committed).
    HeightRegression { expected: u64, got: u64 },
    /// Local round regressed within a height.
    RoundRegression { expected: u32, got: u32 },
    /// `transition()` called with an impossible (state, event) — the
    /// match is exhaustive so this should never fire; catching it as
    /// a panic preserves the totality contract instead of unreachable!.
    InvalidTransition { from: String, event: String },

    // ----- Network -----
    /// Gossip publish failed beyond retry budget.
    GossipFailure,
    /// Mesh partition detected (split-brain risk).
    MeshPartition,
    /// Required peer unreachable beyond timeout.
    PeerUnreachable,

    // ----- Runtime -----
    /// A core async channel closed unexpectedly.
    ChannelClosed,
    /// Out-of-memory condition observed.
    OOMDetected,
    /// Disk write failed because storage is full.
    DiskFull,
    /// `std::panic` caught at the consensus task boundary.
    PanicCaught { message: String },

    // ----- Upgrade -----
    /// Peer ran a different protocol version.
    VersionMismatch { expected: String, got: String },
    /// Halting state did not transition to CoordinatedUpdate within
    /// the configured timeout.
    HaltTimeout,
    /// CoordinatedUpdate barrier did not reach quorum-ready.
    UpgradeQuorumNotReached,

    // ----- Security -----
    /// Inbound message claimed an identity not in the validator set.
    UnknownValidator,
    /// Cryptographic signature verification failed for a proposal or
    /// vote that should have been signed.
    SignatureVerificationFailed,
}

impl PanicReason {
    /// Recoverable panics reset to `Idle` after the runtime drains;
    /// non-recoverable panics force a transition to
    /// `Halting { resume_condition: Never }`.
    ///
    /// Per the design table: only network/liveness flutters are
    /// recoverable. Anything that touched safety, state integrity,
    /// or security forces an unrecoverable halt.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            PanicReason::HeartbeatMissed
                | PanicReason::PeerUnreachable
                | PanicReason::GossipFailure
                | PanicReason::MeshPartition
        )
    }
}

/// Why a validator entered [`ValidatorState::Slashed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlashReason {
    /// Double-signed two votes at the same (height, round).
    DoubleSign,
    /// Equivocation evidence accepted by 2/3+.
    Equivocation,
    /// Repeated consensus inactivity beyond threshold.
    Liveness,
    /// Byzantine behavior reported by peers and validated.
    Byzantine,
}

/// Full validator FSM control state.
///
/// Designed to be a node in a deterministic Markov chain — every
/// `(state, event)` produces exactly one `(next_state, actions)` per
/// [`transition()`]. Variants carry the minimum data needed to make
/// each terminal state self-describing for observability (e.g.
/// `Committed` carries `block_hash + height`, `Hung` carries the
/// prior state for resume).
///
/// [`transition()`]: super::transition::transition
///
/// `Instant` fields (`Hung.since`, `Panic.triggered_at`) intentionally
/// prevent automatic `Serialize / Deserialize` derives; wall-clock data
/// shouldn't appear in audit logs or block bodies. For wire/log
/// purposes use [`ValidatorStateKind`] and the structured data fields
/// directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorState {
    // ----- Lifecycle -----
    /// First-ever start, no local state, downloading from genesis.
    Bootstrapping,

    /// Local state exists but height is behind peers. Sync from
    /// `from_height` to `to_height`, then transition to `Idle`.
    CatchingUp {
        from_height: u64,
        to_height: u64,
    },

    // ----- Active consensus -----
    /// Between rounds. Awaiting `SelectedAsProposer` or `ProposalAdmitted`.
    Idle,

    /// Propose phase: leader's window. Either build the proposal
    /// (local validator is proposer) or wait for one.
    Proposing,

    /// Prevote phase (engine's `PreVote` step): cast and gather
    /// `VoteType::PreVote`s.
    Prevoting,

    /// Precommit phase (engine's `PreCommit` + `Commit` steps): cast
    /// and gather `VoteType::PreCommit`s, then `VoteType::Commit`s.
    Precommitting,

    /// Block finalized at this height. Carries the finalized block's
    /// hash and height for observability. Transitions to `Idle` for
    /// the next height on the next round-entry signal.
    Committed {
        block_hash: [u8; 32],
        height: u64,
    },

    // ----- Failure / recovery -----
    /// Round terminated without finalization. The runtime has emitted
    /// `AdvanceRound`; this state self-clears to `Idle` at `round + 1`.
    Rejected {
        reason: RejectionReason,
        round: u32,
    },

    /// Watchdog detected no progress action. Carries the prior state
    /// for diagnostic resume.
    Hung {
        since: Instant,
        prior_state: Box<ValidatorState>,
    },

    // ----- Operator coordination -----
    /// Operator-coordinated halt at a specific height. Block
    /// production stops at `triggered_at_height`. Resume governed by
    /// `resume_condition`.
    Halting {
        reason: HaltReason,
        triggered_at_height: u64,
        last_block_hash: Option<[u8; 32]>,
        resume_condition: ResumeCondition,
    },

    /// Second phase of a coordinated upgrade: the *new* binary is
    /// running, waiting at the barrier height. On quorum-ready,
    /// transition to `Idle` on the new protocol version.
    CoordinatedUpdate {
        activate_at_height: u64,
        target_version: u32,
    },

    // ----- Punishment -----
    /// Validator was punished and removed from the active set for
    /// the slashing window. May re-enter via re-staking.
    Slashed {
        reason: SlashReason,
    },

    /// Validator was removed from the active set (insufficient stake,
    /// repeated misbehavior). Terminal until re-admission via
    /// re-registration.
    Evicted,

    // ----- Critical -----
    /// Runtime detected a critical error. Carries prior state for
    /// diagnostic resume; recoverable reasons (per
    /// [`PanicReason::is_recoverable`]) reset to `Idle`, non-
    /// recoverable transition to `Halting{Never}`.
    Panic {
        reason: PanicReason,
        triggered_at: Instant,
        prior_state: Box<ValidatorState>,
    },

    /// Graceful exit. Logs flushed; no more events processed.
    /// Terminal — process exits after this state.
    ShuttingDown,
}

/// Discriminant of [`ValidatorState`] without the data fields.
///
/// Used by the runtime-queryable transition table
/// (`super::transition_table`) and by audit logs / metrics where
/// only the state name is meaningful. Implements all the derive
/// traits the full enum can't because of `Instant` and `Box<Self>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidatorStateKind {
    Bootstrapping,
    CatchingUp,
    Idle,
    Proposing,
    Prevoting,
    Precommitting,
    Committed,
    Rejected,
    Hung,
    Halting,
    CoordinatedUpdate,
    Slashed,
    Evicted,
    Panic,
    ShuttingDown,
}

impl ValidatorState {
    /// Project to the data-free discriminant.
    pub fn kind(&self) -> ValidatorStateKind {
        match self {
            ValidatorState::Bootstrapping => ValidatorStateKind::Bootstrapping,
            ValidatorState::CatchingUp { .. } => ValidatorStateKind::CatchingUp,
            ValidatorState::Idle => ValidatorStateKind::Idle,
            ValidatorState::Proposing => ValidatorStateKind::Proposing,
            ValidatorState::Prevoting => ValidatorStateKind::Prevoting,
            ValidatorState::Precommitting => ValidatorStateKind::Precommitting,
            ValidatorState::Committed { .. } => ValidatorStateKind::Committed,
            ValidatorState::Rejected { .. } => ValidatorStateKind::Rejected,
            ValidatorState::Hung { .. } => ValidatorStateKind::Hung,
            ValidatorState::Halting { .. } => ValidatorStateKind::Halting,
            ValidatorState::CoordinatedUpdate { .. } => ValidatorStateKind::CoordinatedUpdate,
            ValidatorState::Slashed { .. } => ValidatorStateKind::Slashed,
            ValidatorState::Evicted => ValidatorStateKind::Evicted,
            ValidatorState::Panic { .. } => ValidatorStateKind::Panic,
            ValidatorState::ShuttingDown => ValidatorStateKind::ShuttingDown,
        }
    }

    /// True for states that the FSM does not exit on its own without
    /// external recovery (operator restart, re-registration, etc.).
    pub fn requires_external_recovery(&self) -> bool {
        matches!(
            self,
            ValidatorState::Halting {
                resume_condition: ResumeCondition::Never | ResumeCondition::ManualRestart,
                ..
            } | ValidatorState::Evicted
                | ValidatorState::ShuttingDown
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_kinds() -> Vec<ValidatorStateKind> {
        vec![
            ValidatorStateKind::Bootstrapping,
            ValidatorStateKind::CatchingUp,
            ValidatorStateKind::Idle,
            ValidatorStateKind::Proposing,
            ValidatorStateKind::Prevoting,
            ValidatorStateKind::Precommitting,
            ValidatorStateKind::Committed,
            ValidatorStateKind::Rejected,
            ValidatorStateKind::Hung,
            ValidatorStateKind::Halting,
            ValidatorStateKind::CoordinatedUpdate,
            ValidatorStateKind::Slashed,
            ValidatorStateKind::Evicted,
            ValidatorStateKind::Panic,
            ValidatorStateKind::ShuttingDown,
        ]
    }

    /// Construct one instance of every variant; verify .kind() is
    /// correct and all 15 kinds are distinct.
    #[test]
    fn all_variants_constructible_with_correct_kind() {
        let states = vec![
            ValidatorState::Bootstrapping,
            ValidatorState::CatchingUp {
                from_height: 0,
                to_height: 100,
            },
            ValidatorState::Idle,
            ValidatorState::Proposing,
            ValidatorState::Prevoting,
            ValidatorState::Precommitting,
            ValidatorState::Committed {
                block_hash: [0u8; 32],
                height: 1,
            },
            ValidatorState::Rejected {
                reason: RejectionReason::InsufficientPrevotes,
                round: 0,
            },
            ValidatorState::Hung {
                since: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorState::Halting {
                reason: HaltReason::UpgradeScheduled,
                triggered_at_height: 100,
                last_block_hash: None,
                resume_condition: ResumeCondition::QuorumReady,
            },
            ValidatorState::CoordinatedUpdate {
                activate_at_height: 100,
                target_version: 2,
            },
            ValidatorState::Slashed {
                reason: SlashReason::DoubleSign,
            },
            ValidatorState::Evicted,
            ValidatorState::Panic {
                reason: PanicReason::WatchdogExpired,
                triggered_at: Instant::now(),
                prior_state: Box::new(ValidatorState::Idle),
            },
            ValidatorState::ShuttingDown,
        ];
        let kinds: Vec<_> = states.iter().map(|s| s.kind()).collect();
        assert_eq!(kinds, all_kinds());

        // All 15 kinds distinct under PartialEq.
        for (i, a) in kinds.iter().enumerate() {
            for (j, b) in kinds.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }

    #[test]
    fn panic_recoverability_classifies_per_design_table() {
        // Recoverable per the design table.
        for r in [
            PanicReason::HeartbeatMissed,
            PanicReason::PeerUnreachable,
            PanicReason::GossipFailure,
            PanicReason::MeshPartition,
        ] {
            assert!(r.is_recoverable(), "{:?} should be recoverable", r);
        }
        // Non-recoverable per the design table.
        for r in [
            PanicReason::DoubleVote,
            PanicReason::ByzantineVoteDetected,
            PanicReason::SlashableOffense,
            PanicReason::ConflictingCommits,
            PanicReason::StateMachineCorrupted,
            PanicReason::SignatureVerificationFailed,
        ] {
            assert!(!r.is_recoverable(), "{:?} must NOT be recoverable", r);
        }
    }

    #[test]
    fn requires_external_recovery_is_correct() {
        assert!(!ValidatorState::Idle.requires_external_recovery());
        assert!(!ValidatorState::Proposing.requires_external_recovery());
        assert!(!ValidatorState::Bootstrapping.requires_external_recovery());
        assert!(!ValidatorState::CatchingUp {
            from_height: 0,
            to_height: 1,
        }
        .requires_external_recovery());

        assert!(ValidatorState::Halting {
            reason: HaltReason::UpgradeScheduled,
            triggered_at_height: 0,
            last_block_hash: None,
            resume_condition: ResumeCondition::Never,
        }
        .requires_external_recovery());

        assert!(ValidatorState::Halting {
            reason: HaltReason::EmergencyHalt,
            triggered_at_height: 0,
            last_block_hash: None,
            resume_condition: ResumeCondition::ManualRestart,
        }
        .requires_external_recovery());

        // QuorumReady / UpgradeComplete don't require external action.
        assert!(!ValidatorState::Halting {
            reason: HaltReason::UpgradeScheduled,
            triggered_at_height: 0,
            last_block_hash: None,
            resume_condition: ResumeCondition::QuorumReady,
        }
        .requires_external_recovery());

        assert!(ValidatorState::Evicted.requires_external_recovery());
        assert!(ValidatorState::ShuttingDown.requires_external_recovery());
    }
}
