//! Slashing Severity and Jail/Removal Policy
//!
//! This module defines the authoritative constants, policies, and enforcement
//! logic for validator slashing, jailing, and permanent removal in the ZHTP
//! consensus system.
//!
//! # Slashing Policy Summary
//!
//! | Offense Class    | Slash %  | Jail?    | Permanent Ban? |
//! |------------------|----------|----------|----------------|
//! | Safety violation | 100%     | Yes      | YES (forever)  |
//! | Liveness failure | 1%       | Yes      | No             |
//!
//! ## Safety Violations (Double-sign, Equivocation, etc.)
//!
//! Safety violations are treated as the worst class of misbehavior because they
//! threaten the fundamental BFT guarantee of consistent commits. A validator
//! that double-signs or equivocates:
//!
//! 1. Has their **entire bonded stake slashed** (`DOUBLE_SIGN_SLASH_PERCENT = 100`)
//! 2. Is **permanently banned** from the validator set — they CANNOT unjail
//! 3. Are **immediately isolated** from the peer network
//!
//! Rationale: there is no honest explanation for double-signing. Even if caused
//! by misconfiguration (e.g., running two nodes with the same key), the operator
//! bears full responsibility for key management.
//!
//! ## Liveness Violations (Missed blocks, round timeouts, etc.)
//!
//! Liveness violations reduce throughput but do not threaten safety. A validator
//! that fails to participate:
//!
//! 1. Has **1% of bonded stake slashed** (`LIVENESS_SLASH_PERCENT = 1`)
//! 2. Is **jailed for `JAIL_DURATION_BLOCKS` blocks**
//! 3. May **unjail** after serving the full jail period (see recovery rules)
//!
//! # Invariants
//!
//! - **POL-INV-1**: `DOUBLE_SIGN_SLASH_PERCENT` must be exactly 100
//! - **POL-INV-2**: `LIVENESS_SLASH_PERCENT` must be in range 1..=5
//! - **POL-INV-3**: `JAIL_DURATION_BLOCKS` must be at least 100 blocks
//! - **POL-INV-4**: Safety-slashed validators CANNOT unjail (permanent ban)
//! - **POL-INV-5**: Liveness-slashed validators CAN unjail after jail period
//! - **POL-INV-6**: Slash percent for safety >= slash percent for liveness (monotonicity)

// =============================================================================
// SLASH PERCENTAGE CONSTANTS
// =============================================================================

/// Slash percentage applied for double-signing (safety violation).
///
/// A validator that signs two conflicting blocks at the same height loses
/// 100% of their bonded stake. This is a full slash.
///
/// # Invariant POL-INV-1
///
/// This constant MUST equal 100. Any reduction would make double-signing
/// economically viable if the attacker holds less than 100% of their stake
/// in the validator set.
///
/// # Rationale
///
/// Full slashing creates a strong economic disincentive against safety attacks.
/// Because BFT safety attacks require coordinated Byzantine behavior, the
/// punishment must be severe enough to deter even well-funded attackers.
pub const DOUBLE_SIGN_SLASH_PERCENT: u8 = 100;

/// Slash percentage applied for liveness violations.
///
/// A validator that misses blocks, fails heartbeats, or times out in rounds
/// loses 1% of their bonded stake per violation event.
///
/// # Invariant POL-INV-2
///
/// This constant MUST be in the range 1..=5. Too low and it creates no
/// incentive; too high and it punishes validators with legitimate infrastructure
/// issues as severely as Byzantine actors.
pub const LIVENESS_SLASH_PERCENT: u8 = 1;

// Compile-time assertion: POL-INV-1 — double-sign slash must be 100%
const _: () = assert!(
    DOUBLE_SIGN_SLASH_PERCENT == 100,
    "POL-INV-1: DOUBLE_SIGN_SLASH_PERCENT must equal 100"
);

// Compile-time assertion: POL-INV-2 — liveness slash must be 1..=5
const _: () = assert!(
    LIVENESS_SLASH_PERCENT >= 1 && LIVENESS_SLASH_PERCENT <= 5,
    "POL-INV-2: LIVENESS_SLASH_PERCENT must be in range 1..=5"
);

// Compile-time assertion: POL-INV-6 — safety slash >= liveness slash (monotonicity)
const _: () = assert!(
    DOUBLE_SIGN_SLASH_PERCENT >= LIVENESS_SLASH_PERCENT,
    "POL-INV-6: DOUBLE_SIGN_SLASH_PERCENT must be >= LIVENESS_SLASH_PERCENT"
);

// =============================================================================
// JAIL DURATION CONSTANT
// =============================================================================

/// Number of blocks a liveness-slashed validator must remain jailed.
///
/// After being jailed, a validator must wait at least `JAIL_DURATION_BLOCKS`
/// finalized blocks before they are eligible to submit an unjail transaction.
///
/// At a target block time of 10 seconds, 1000 blocks ≈ 2.8 hours.
///
/// # Invariant POL-INV-3
///
/// This constant MUST be at least 100 blocks. A shorter jail would allow
/// liveness violators to rapidly re-enter the validator set and immediately
/// miss blocks again, creating a tight loop of small penalties with no
/// real consequence for persistent downtime.
pub const JAIL_DURATION_BLOCKS: u64 = 1000;

// Compile-time assertion: POL-INV-3 — jail duration must be at least 100 blocks
const _: () = assert!(
    JAIL_DURATION_BLOCKS >= 100,
    "POL-INV-3: JAIL_DURATION_BLOCKS must be at least 100"
);

// =============================================================================
// REMOVAL POLICY
// =============================================================================

/// Minimum slash count before a liveness violator is permanently removed.
///
/// A validator that accumulates `REMOVAL_SLASH_COUNT` liveness violations
/// without successfully exiting jail between them is permanently removed from
/// the validator set. This prevents chronic underperformers from cycling
/// through jail indefinitely.
///
/// # Note
///
/// Safety-slashed validators are removed immediately on first offense
/// (see `SAFETY_OFFENSE_ALWAYS_PERMANENT`). This count only applies
/// to liveness violations.
pub const REMOVAL_SLASH_COUNT: u32 = 10;

/// Whether a safety offense ALWAYS results in permanent removal.
///
/// This constant is `true` and MUST NOT be set to `false`. It is provided
/// as a named constant (rather than a comment) so that enforcement code can
/// reference it explicitly rather than using a bare `true` literal.
///
/// # Invariant POL-INV-4
///
/// Safety-slashed validators are permanently removed from the validator set.
/// They CANNOT unjail. They CANNOT re-register. Any attempt to unjail a
/// safety-slashed validator MUST be rejected with `SlashPolicyError::PermanentBan`.
pub const SAFETY_OFFENSE_ALWAYS_PERMANENT: bool = true;

// Compile-time assertion: safety offense must always be permanent
const _: () = assert!(
    SAFETY_OFFENSE_ALWAYS_PERMANENT,
    "POL-INV-4: SAFETY_OFFENSE_ALWAYS_PERMANENT must be true"
);

// =============================================================================
// SLASH POLICY ENUM
// =============================================================================

/// Classification of a slashing event, determining the enforcement path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashSeverity {
    /// Safety violation: full slash + permanent ban
    ///
    /// Applies to: DoubleSign, ConflictingVote, Equivocation, LongRangeAttack, InvalidBlock
    Safety,
    /// Liveness violation: partial slash + temporary jail
    ///
    /// Applies to: MissedBlocks, HeartbeatTimeout, RoundTimeout, ProposalTimeout
    Liveness,
}

impl SlashSeverity {
    /// Return the slash percentage for this severity.
    ///
    /// Returns either `DOUBLE_SIGN_SLASH_PERCENT` (100) or `LIVENESS_SLASH_PERCENT` (1).
    pub const fn slash_percent(self) -> u8 {
        match self {
            Self::Safety => DOUBLE_SIGN_SLASH_PERCENT,
            Self::Liveness => LIVENESS_SLASH_PERCENT,
        }
    }

    /// Return the jail duration in blocks for this severity.
    ///
    /// Safety violations result in permanent ban (represented as `u64::MAX`).
    /// Liveness violations use `JAIL_DURATION_BLOCKS`.
    pub const fn jail_duration_blocks(self) -> u64 {
        match self {
            Self::Safety => u64::MAX, // Permanent: never released
            Self::Liveness => JAIL_DURATION_BLOCKS,
        }
    }

    /// Return true if this severity results in a permanent ban.
    ///
    /// # Invariant POL-INV-4
    pub const fn is_permanent_ban(self) -> bool {
        matches!(self, Self::Safety)
    }

    /// Return true if the validator can eventually unjail.
    ///
    /// # Invariant POL-INV-5
    pub const fn can_unjail(self) -> bool {
        matches!(self, Self::Liveness)
    }
}

impl std::fmt::Display for SlashSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safety => write!(f, "Safety(slash={}%, permanent_ban=true)", DOUBLE_SIGN_SLASH_PERCENT),
            Self::Liveness => write!(f, "Liveness(slash={}%, jail_blocks={})", LIVENESS_SLASH_PERCENT, JAIL_DURATION_BLOCKS),
        }
    }
}

// =============================================================================
// SLASH POLICY ERROR
// =============================================================================

/// Errors returned when a slashing policy is violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashPolicyError {
    /// Attempted to unjail a validator that was permanently banned.
    ///
    /// Invariant POL-INV-4: safety-slashed validators cannot unjail.
    PermanentBan,

    /// Attempted to unjail a validator before jail period expired.
    ///
    /// The u64 field is the block height at which unjailing becomes eligible.
    JailPeriodNotExpired { eligible_at_block: u64 },

    /// Validator not found in the active set.
    ValidatorNotFound,

    /// Slash percentage out of valid range.
    InvalidSlashPercent { got: u8 },
}

impl std::fmt::Display for SlashPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermanentBan => write!(
                f,
                "Validator is permanently banned due to safety violation and cannot unjail"
            ),
            Self::JailPeriodNotExpired { eligible_at_block } => write!(
                f,
                "Jail period not yet expired; validator eligible to unjail at block {}",
                eligible_at_block
            ),
            Self::ValidatorNotFound => write!(f, "Validator not found in active set"),
            Self::InvalidSlashPercent { got } => {
                write!(f, "Invalid slash percentage: got {}%, expected 1..=100", got)
            }
        }
    }
}

// =============================================================================
// POLICY ENFORCEMENT HELPER
// =============================================================================

/// Determine whether a validator's unjail request should be accepted.
///
/// Returns `Ok(())` if unjailing is permitted, or a `SlashPolicyError` if not.
///
/// # Arguments
///
/// * `permanently_banned` - True if the validator was safety-slashed
/// * `jail_end_block` - Block height at which the jail period expires
/// * `current_block` - The current finalized block height
///
/// # Invariant POL-INV-4
///
/// If `permanently_banned` is true, this function MUST return
/// `Err(SlashPolicyError::PermanentBan)` regardless of other parameters.
///
/// # Invariant POL-INV-5
///
/// If `permanently_banned` is false and `current_block >= jail_end_block`,
/// this function MUST return `Ok(())`.
pub fn check_unjail_eligibility(
    permanently_banned: bool,
    jail_end_block: u64,
    current_block: u64,
) -> Result<(), SlashPolicyError> {
    // POL-INV-4: Safety-slashed validators cannot unjail
    if permanently_banned {
        return Err(SlashPolicyError::PermanentBan);
    }

    // POL-INV-5: Liveness-slashed validators can unjail after jail period
    if current_block < jail_end_block {
        return Err(SlashPolicyError::JailPeriodNotExpired {
            eligible_at_block: jail_end_block,
        });
    }

    Ok(())
}

/// Calculate the slash amount from a stake and slash percentage.
///
/// Uses saturating arithmetic to prevent overflow.
///
/// # Arguments
///
/// * `stake` - The validator's current bonded stake
/// * `slash_percent` - The percentage to slash (1..=100)
///
/// # Returns
///
/// The amount to slash (always <= stake).
pub fn calculate_slash_amount(stake: u64, slash_percent: u8) -> u64 {
    assert!(
        slash_percent >= 1 && slash_percent <= 100,
        "slash_percent must be in range 1..=100, got {}",
        slash_percent
    );
    stake.saturating_mul(slash_percent as u64) / 100
}

/// Calculate the block height at which a jailed validator becomes eligible to unjail.
///
/// # Arguments
///
/// * `jailed_at_block` - The block height when the validator was jailed
/// * `severity` - The severity of the offense that caused jailing
///
/// # Returns
///
/// For liveness violations: `jailed_at_block + JAIL_DURATION_BLOCKS`
/// For safety violations: `u64::MAX` (never eligible)
pub fn jail_end_block(jailed_at_block: u64, severity: SlashSeverity) -> u64 {
    match severity {
        SlashSeverity::Liveness => jailed_at_block.saturating_add(JAIL_DURATION_BLOCKS),
        SlashSeverity::Safety => u64::MAX, // Permanent ban: never eligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_satisfy_invariants() {
        // POL-INV-1
        assert_eq!(DOUBLE_SIGN_SLASH_PERCENT, 100);
        // POL-INV-2
        assert!(LIVENESS_SLASH_PERCENT >= 1 && LIVENESS_SLASH_PERCENT <= 5);
        // POL-INV-3
        assert!(JAIL_DURATION_BLOCKS >= 100);
        // POL-INV-4
        assert!(SAFETY_OFFENSE_ALWAYS_PERMANENT);
        // POL-INV-6
        assert!(DOUBLE_SIGN_SLASH_PERCENT >= LIVENESS_SLASH_PERCENT);
    }

    #[test]
    fn test_safety_severity_is_permanent_ban() {
        let s = SlashSeverity::Safety;
        assert_eq!(s.slash_percent(), 100);
        assert_eq!(s.jail_duration_blocks(), u64::MAX);
        assert!(s.is_permanent_ban());
        assert!(!s.can_unjail());
    }

    #[test]
    fn test_liveness_severity_is_temporary() {
        let s = SlashSeverity::Liveness;
        assert_eq!(s.slash_percent(), LIVENESS_SLASH_PERCENT);
        assert_eq!(s.jail_duration_blocks(), JAIL_DURATION_BLOCKS);
        assert!(!s.is_permanent_ban());
        assert!(s.can_unjail());
    }

    #[test]
    fn test_unjail_permanent_ban_rejected() {
        let result = check_unjail_eligibility(true, 0, 99999);
        assert_eq!(result, Err(SlashPolicyError::PermanentBan));
    }

    #[test]
    fn test_unjail_before_jail_period_rejected() {
        let jail_end = 1000u64;
        let current = 500u64;
        let result = check_unjail_eligibility(false, jail_end, current);
        assert_eq!(
            result,
            Err(SlashPolicyError::JailPeriodNotExpired { eligible_at_block: 1000 })
        );
    }

    #[test]
    fn test_unjail_after_jail_period_accepted() {
        let jail_end = 1000u64;
        let current = 1000u64; // exactly at end
        let result = check_unjail_eligibility(false, jail_end, current);
        assert_eq!(result, Ok(()));

        let current_past = 2000u64;
        let result2 = check_unjail_eligibility(false, jail_end, current_past);
        assert_eq!(result2, Ok(()));
    }

    #[test]
    fn test_calculate_slash_amount_full() {
        // Full slash: 100% of 1000 = 1000
        assert_eq!(calculate_slash_amount(1000, 100), 1000);
    }

    #[test]
    fn test_calculate_slash_amount_one_percent() {
        // 1% of 10000 = 100
        assert_eq!(calculate_slash_amount(10_000, 1), 100);
    }

    #[test]
    fn test_calculate_slash_amount_zero_stake() {
        // 0 stake, nothing to slash
        assert_eq!(calculate_slash_amount(0, 100), 0);
    }

    #[test]
    fn test_jail_end_block_liveness() {
        let jailed_at = 500u64;
        let end = jail_end_block(jailed_at, SlashSeverity::Liveness);
        assert_eq!(end, jailed_at + JAIL_DURATION_BLOCKS);
    }

    #[test]
    fn test_jail_end_block_safety_is_max() {
        let jailed_at = 500u64;
        let end = jail_end_block(jailed_at, SlashSeverity::Safety);
        assert_eq!(end, u64::MAX);
    }

    #[test]
    fn test_slash_severity_display() {
        let safety_str = SlashSeverity::Safety.to_string();
        assert!(safety_str.contains("100%"));
        assert!(safety_str.contains("permanent_ban=true"));

        let liveness_str = SlashSeverity::Liveness.to_string();
        assert!(liveness_str.contains("1%") || liveness_str.contains(&format!("{}%", LIVENESS_SLASH_PERCENT)));
        assert!(liveness_str.contains(&JAIL_DURATION_BLOCKS.to_string()));
    }
}
