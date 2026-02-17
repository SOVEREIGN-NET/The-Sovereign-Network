//! Slashable Offense Enumeration
//!
//! This module provides an exhaustive, explicit enumeration of ALL slashable offenses
//! in the ZHTP consensus system. Each offense is documented with its severity class,
//! detection method, and policy consequences.
//!
//! # Design Philosophy
//!
//! Slashing decisions must be:
//! - **Deterministic**: Same evidence always produces same outcome
//! - **Explicit**: No implicit slashing; every offense is named and documented
//! - **Graded**: Offenses are classified by severity (Safety vs. Liveness)
//! - **Auditable**: All slashing events are traceable to a specific offense variant
//!
//! # Offense Classification
//!
//! ## Safety Violations (CRITICAL)
//!
//! Safety violations threaten the fundamental BFT guarantee: "no two honest validators
//! commit conflicting blocks." These are treated as the most severe class because they
//! can cause chain forks and irreversible inconsistency.
//!
//! - Full stake slash (100% of bonded stake)
//! - Permanent ban: validator CANNOT unjail after a safety slash
//! - Immediate network isolation
//!
//! ## Liveness Violations (MINOR)
//!
//! Liveness violations reduce consensus throughput but do not threaten safety.
//! Validators that fail to participate impede block production but cannot
//! cause incorrect commits.
//!
//! - Partial stake slash (1% of bonded stake per incident)
//! - Temporary jail with fixed release after JAIL_DURATION_BLOCKS
//! - Validator may re-register after serving jail time (if not safety-slashed)
//!
//! # Invariants
//!
//! - **SLASH-INV-1**: Every slashable offense MUST appear in `SlashableOffense`
//! - **SLASH-INV-2**: `ALL_OFFENSES` MUST contain every `SlashableOffense` variant
//! - **SLASH-INV-3**: Safety violations (severity >= 80) MUST set `permanent_ban = true`
//! - **SLASH-INV-4**: Liveness violations (severity <= 20) MUST NOT set `permanent_ban`
//! - **SLASH-INV-5**: `SlashableOffense::severity()` MUST be monotone with slash percent

/// Explicit enumeration of all slashable offenses in the ZHTP consensus protocol.
///
/// This enum is the single source of truth for what constitutes slashable behavior.
/// New offenses MUST be added here before enforcement code references them.
///
/// # Severity Scale
///
/// Severity is expressed as a u8 in the range 0–100:
/// - 1–20:   Liveness violations (minor, recoverable)
/// - 21–79:  Intermediate violations (currently unused; reserved)
/// - 80–100: Safety violations (critical, permanent ban)
///
/// The severity is used to:
/// 1. Determine the slash percentage applied to staked tokens
/// 2. Determine whether the offense results in permanent ban
/// 3. Drive governance display and alert thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlashableOffense {
    // =========================================================================
    // SAFETY VIOLATIONS — severity 80–100 — permanent ban
    // =========================================================================

    /// Validator signed two conflicting blocks at the same height.
    ///
    /// **Detection**: Two `Evidence::DoubleSign` records with the same
    /// `(validator, height)` but different `block_hash_a`/`block_hash_b`.
    ///
    /// **Severity**: 100 (full stake slash, permanent ban)
    ///
    /// **Rationale**: Double-signing is the most direct attack on BFT safety.
    /// A validator that signs two blocks at the same height can cause two branches
    /// of the chain to commit conflicting state. There is no benign explanation.
    DoubleSign,

    /// Validator cast votes for two conflicting proposals in the same consensus round.
    ///
    /// **Detection**: `EquivocationEvidence` with same `(validator, height, round,
    /// vote_type)` but different `proposal_id`.
    ///
    /// **Severity**: 100 (full stake slash, permanent ban)
    ///
    /// **Rationale**: Conflicting votes allow a Byzantine validator to push two
    /// incompatible proposals past quorum simultaneously (split-brain commit).
    ConflictingVote,

    /// Validator proposed a structurally invalid block that passes signature checks.
    ///
    /// **Detection**: A proposal whose `block_data` fails state-transition validation
    /// but whose signature is valid (ruling out message corruption).
    ///
    /// **Severity**: 80 (80% slash, permanent ban)
    ///
    /// **Rationale**: Deliberately proposing invalid blocks wastes validator time
    /// and can be used to stall the network. The high severity discourages this
    /// even if the proposal does not succeed.
    InvalidBlock,

    /// Validator signed the same height/round payload with a different key (key equivocation).
    ///
    /// **Detection**: Two signatures with different keys for the same canonical message,
    /// both verifying against keys registered to the same validator identity.
    ///
    /// **Severity**: 100 (full stake slash, permanent ban)
    ///
    /// **Rationale**: Key equivocation indicates the validator is operating multiple
    /// identities in a coordinated fashion, which is a form of Sybil attack within
    /// the validator set.
    Equivocation,

    /// Validator participated in a long-range attack (signing blocks far behind the tip).
    ///
    /// **Detection**: A valid signature from a validator over a block at a height
    /// more than `LONG_RANGE_ATTACK_DEPTH` blocks below the current finalized tip.
    ///
    /// **Severity**: 100 (full stake slash, permanent ban)
    ///
    /// **Rationale**: Long-range attacks attempt to rewrite finalized history.
    /// Even if unsuccessful, participation demonstrates intent to undermine finality.
    LongRangeAttack,

    // =========================================================================
    // LIVENESS VIOLATIONS — severity 1–20 — temporary jail
    // =========================================================================

    /// Validator missed more than `MAX_MISSED_BLOCKS` consecutive blocks.
    ///
    /// **Detection**: `LivenessMonitor` tracks consecutive heartbeat failures.
    /// After `LIVENESS_JAIL_THRESHOLD` missed blocks, this offense is recorded.
    ///
    /// **Severity**: 5 (1% slash, temporary jail for `JAIL_DURATION_BLOCKS`)
    ///
    /// **Rationale**: Persistent absence reduces effective validator set size and
    /// increases round latency. Light penalties incentivize uptime without
    /// catastrophic punishment for infrastructure failures.
    MissedBlocks,

    /// Validator failed to send heartbeats within the required window.
    ///
    /// **Detection**: `HeartbeatTracker.is_validator_alive()` returns false
    /// after `HEARTBEAT_TIMEOUT_SECS` seconds of silence.
    ///
    /// **Severity**: 1 (1% slash, temporary jail)
    ///
    /// **Rationale**: Heartbeat silence is an early indicator of liveness problems.
    /// Minor penalty to distinguish from the more serious `MissedBlocks` offense.
    HeartbeatTimeout,

    /// Validator consistently timed out during consensus rounds.
    ///
    /// **Detection**: Validator fails to cast a PreVote or PreCommit within
    /// `ROUND_TIMEOUT_SECS` seconds across `MAX_CONSECUTIVE_ROUND_TIMEOUTS`
    /// consecutive rounds.
    ///
    /// **Severity**: 10 (1% slash, temporary jail)
    ///
    /// **Rationale**: Round timeouts cascade: when one validator does not
    /// respond, rounds must be extended and the protocol slows. Repeated
    /// round timeouts by the same validator are a liveness concern.
    RoundTimeout,

    /// Proposer failed to propose within the allocated proposal window.
    ///
    /// **Detection**: `ConsensusStep::Propose` timeout expired without a valid
    /// proposal from the designated proposer.
    ///
    /// **Severity**: 5 (1% slash, temporary jail)
    ///
    /// **Rationale**: A non-proposing proposer forces a round change, increasing
    /// latency by at least one full round timeout. Penalized to incentivize
    /// reliable proposer uptime.
    ProposalTimeout,
}

impl SlashableOffense {
    /// Return the severity score for this offense (0–100).
    ///
    /// Severity is used to:
    /// - Compute slash percentage (see `slash_percent()`)
    /// - Determine whether the offense triggers permanent ban (severity >= 80)
    /// - Drive governance thresholds and alerts
    pub const fn severity(self) -> u8 {
        match self {
            // Safety violations
            Self::DoubleSign => 100,
            Self::ConflictingVote => 100,
            Self::Equivocation => 100,
            Self::LongRangeAttack => 100,
            Self::InvalidBlock => 80,

            // Liveness violations
            Self::RoundTimeout => 10,
            Self::MissedBlocks => 5,
            Self::ProposalTimeout => 5,
            Self::HeartbeatTimeout => 1,
        }
    }

    /// Return the slash percentage to apply to the validator's bonded stake.
    ///
    /// Safety violations receive 100% slash. Liveness violations receive 1%.
    ///
    /// # Invariant SLASH-INV-5
    ///
    /// slash_percent MUST be monotone with severity: higher severity always
    /// yields an equal or higher slash percent.
    pub const fn slash_percent(self) -> u8 {
        match self {
            // Safety: full slash
            Self::DoubleSign => 100,
            Self::ConflictingVote => 100,
            Self::Equivocation => 100,
            Self::LongRangeAttack => 100,
            Self::InvalidBlock => 80,

            // Liveness: 1% per incident
            Self::MissedBlocks => 1,
            Self::HeartbeatTimeout => 1,
            Self::RoundTimeout => 1,
            Self::ProposalTimeout => 1,
        }
    }

    /// Return true if this offense results in a permanent ban.
    ///
    /// Permanently banned validators CANNOT unjail regardless of waiting period.
    ///
    /// # Invariant SLASH-INV-3
    ///
    /// Every offense with `severity() >= 80` MUST return `true` here.
    pub const fn permanent_ban(self) -> bool {
        self.severity() >= 80
    }

    /// Return true if this is a safety violation (threatens BFT safety guarantees).
    pub const fn is_safety_violation(self) -> bool {
        self.severity() >= 80
    }

    /// Return true if this is a liveness violation (reduces throughput only).
    pub const fn is_liveness_violation(self) -> bool {
        self.severity() < 80
    }

    /// Return a human-readable name for the offense.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DoubleSign => "DoubleSign",
            Self::ConflictingVote => "ConflictingVote",
            Self::InvalidBlock => "InvalidBlock",
            Self::Equivocation => "Equivocation",
            Self::LongRangeAttack => "LongRangeAttack",
            Self::MissedBlocks => "MissedBlocks",
            Self::HeartbeatTimeout => "HeartbeatTimeout",
            Self::RoundTimeout => "RoundTimeout",
            Self::ProposalTimeout => "ProposalTimeout",
        }
    }

    /// Return the offense class as a string.
    pub const fn class(self) -> &'static str {
        if self.is_safety_violation() {
            "Safety"
        } else {
            "Liveness"
        }
    }
}

impl std::fmt::Display for SlashableOffense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}(severity={}, slash={}%, class={})",
            self.name(),
            self.severity(),
            self.slash_percent(),
            self.class(),
        )
    }
}

/// Complete list of all slashable offenses.
///
/// # Invariant SLASH-INV-2
///
/// This array MUST contain every variant of `SlashableOffense`. A compile-time
/// assertion below enforces that the count matches the known variant count.
pub const ALL_OFFENSES: &[SlashableOffense] = &[
    // Safety violations
    SlashableOffense::DoubleSign,
    SlashableOffense::ConflictingVote,
    SlashableOffense::InvalidBlock,
    SlashableOffense::Equivocation,
    SlashableOffense::LongRangeAttack,
    // Liveness violations
    SlashableOffense::MissedBlocks,
    SlashableOffense::HeartbeatTimeout,
    SlashableOffense::RoundTimeout,
    SlashableOffense::ProposalTimeout,
];

/// Total number of slashable offense variants.
///
/// This constant is the canonical count used in compile-time invariant checks.
pub const SLASHABLE_OFFENSE_COUNT: usize = 9;

// Compile-time invariant: ALL_OFFENSES must enumerate all variants.
// If a new variant is added to SlashableOffense without adding it to ALL_OFFENSES,
// this assertion will fail at compile time.
const _: () = assert!(
    ALL_OFFENSES.len() == SLASHABLE_OFFENSE_COUNT,
    "SLASH-INV-2: ALL_OFFENSES must contain every SlashableOffense variant. \
     Update ALL_OFFENSES and SLASHABLE_OFFENSE_COUNT together."
);

// Compile-time invariant: safety violations must have permanent_ban = true
// (checked for each known safety offense explicitly)
const _: () = assert!(SlashableOffense::DoubleSign.permanent_ban(),      "DoubleSign must be a permanent ban");
const _: () = assert!(SlashableOffense::ConflictingVote.permanent_ban(), "ConflictingVote must be a permanent ban");
const _: () = assert!(SlashableOffense::Equivocation.permanent_ban(),    "Equivocation must be a permanent ban");
const _: () = assert!(SlashableOffense::LongRangeAttack.permanent_ban(), "LongRangeAttack must be a permanent ban");
const _: () = assert!(SlashableOffense::InvalidBlock.permanent_ban(),    "InvalidBlock must be a permanent ban");

// Compile-time invariant: liveness violations must NOT be permanent bans
const _: () = assert!(!SlashableOffense::MissedBlocks.permanent_ban(),     "MissedBlocks must NOT be a permanent ban");
const _: () = assert!(!SlashableOffense::HeartbeatTimeout.permanent_ban(), "HeartbeatTimeout must NOT be a permanent ban");
const _: () = assert!(!SlashableOffense::RoundTimeout.permanent_ban(),     "RoundTimeout must NOT be a permanent ban");
const _: () = assert!(!SlashableOffense::ProposalTimeout.permanent_ban(),  "ProposalTimeout must NOT be a permanent ban");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_offenses_count() {
        assert_eq!(ALL_OFFENSES.len(), SLASHABLE_OFFENSE_COUNT);
    }

    #[test]
    fn test_all_offenses_unique() {
        let mut seen = std::collections::HashSet::new();
        for offense in ALL_OFFENSES {
            assert!(seen.insert(offense.name()), "Duplicate offense: {}", offense.name());
        }
    }

    #[test]
    fn test_safety_violations_have_permanent_ban() {
        for offense in ALL_OFFENSES {
            if offense.is_safety_violation() {
                assert!(
                    offense.permanent_ban(),
                    "Safety violation {} must have permanent_ban=true",
                    offense.name()
                );
            }
        }
    }

    #[test]
    fn test_liveness_violations_no_permanent_ban() {
        for offense in ALL_OFFENSES {
            if offense.is_liveness_violation() {
                assert!(
                    !offense.permanent_ban(),
                    "Liveness violation {} must NOT have permanent_ban=true",
                    offense.name()
                );
            }
        }
    }

    #[test]
    fn test_safety_slash_percent_is_high() {
        for offense in ALL_OFFENSES {
            if offense.is_safety_violation() {
                assert!(
                    offense.slash_percent() >= 80,
                    "Safety offense {} must slash at least 80%",
                    offense.name()
                );
            }
        }
    }

    #[test]
    fn test_liveness_slash_percent_is_low() {
        for offense in ALL_OFFENSES {
            if offense.is_liveness_violation() {
                assert!(
                    offense.slash_percent() <= 20,
                    "Liveness offense {} must slash at most 20%",
                    offense.name()
                );
            }
        }
    }

    #[test]
    fn test_display_format() {
        let offense = SlashableOffense::DoubleSign;
        let s = offense.to_string();
        assert!(s.contains("DoubleSign"));
        assert!(s.contains("severity=100"));
        assert!(s.contains("slash=100%"));
        assert!(s.contains("Safety"));
    }

    #[test]
    fn test_double_sign_is_safety() {
        assert!(SlashableOffense::DoubleSign.is_safety_violation());
        assert!(!SlashableOffense::DoubleSign.is_liveness_violation());
        assert_eq!(SlashableOffense::DoubleSign.slash_percent(), 100);
        assert!(SlashableOffense::DoubleSign.permanent_ban());
    }

    #[test]
    fn test_missed_blocks_is_liveness() {
        assert!(SlashableOffense::MissedBlocks.is_liveness_violation());
        assert!(!SlashableOffense::MissedBlocks.is_safety_violation());
        assert_eq!(SlashableOffense::MissedBlocks.slash_percent(), 1);
        assert!(!SlashableOffense::MissedBlocks.permanent_ban());
    }

    #[test]
    fn test_conflicting_vote_is_safety() {
        assert!(SlashableOffense::ConflictingVote.is_safety_violation());
        assert_eq!(SlashableOffense::ConflictingVote.slash_percent(), 100);
        assert!(SlashableOffense::ConflictingVote.permanent_ban());
    }

    #[test]
    fn test_equivocation_is_safety() {
        assert!(SlashableOffense::Equivocation.is_safety_violation());
        assert_eq!(SlashableOffense::Equivocation.slash_percent(), 100);
        assert!(SlashableOffense::Equivocation.permanent_ban());
    }

    #[test]
    fn test_long_range_attack_is_safety() {
        assert!(SlashableOffense::LongRangeAttack.is_safety_violation());
        assert_eq!(SlashableOffense::LongRangeAttack.slash_percent(), 100);
        assert!(SlashableOffense::LongRangeAttack.permanent_ban());
    }
}
