//! Validator Recovery Rules: Jail Exit and Stake Restoration
//!
//! This module defines the authoritative rules governing how a jailed validator
//! can exit jail, restore their stake, and re-enter the active validator set.
//!
//! # Recovery Policy Summary
//!
//! | Offense Class    | Can Unjail? | Wait Period           | Stake Restorable? |
//! |------------------|-------------|----------------------|-------------------|
//! | Safety violation | NO          | N/A (permanent ban)  | NO                |
//! | Liveness failure | YES         | JAIL_EXIT_WAIT_BLOCKS| YES (partial)     |
//!
//! ## Safety-Slashed Validators: Permanent Ban
//!
//! A validator slashed for a safety violation (double-sign, equivocation, etc.)
//! is permanently removed from the validator set. They:
//!
//! 1. CANNOT unjail — `check_unjail_eligibility` returns `RecoveryError::PermanentBan`
//! 2. CANNOT restore their stake — the slashed portion is burned
//! 3. CANNOT re-register with the same identity key
//!
//! This is an absolute invariant with no governance override.
//!
//! ## Liveness-Slashed Validators: Temporary Jail
//!
//! A validator slashed for liveness failure is jailed for `JAIL_EXIT_WAIT_BLOCKS`
//! blocks. After that period, they:
//!
//! 1. MAY submit an unjail transaction
//! 2. MUST have remaining stake above `MIN_STAKE_TO_UNJAIL`
//! 3. MAY have their unslashed stake returned (the 1% slash is NOT restored)
//!
//! # Constants
//!
//! - `JAIL_EXIT_WAIT_BLOCKS = 1000`: Must wait this many blocks before unjailing
//! - `MIN_STAKE_TO_UNJAIL`: Minimum remaining stake to be eligible for unjail
//!
//! # Invariants
//!
//! - **REC-INV-1**: Safety-slashed validators CANNOT unjail (permanent ban)
//! - **REC-INV-2**: Liveness-slashed validators MUST wait JAIL_EXIT_WAIT_BLOCKS
//! - **REC-INV-3**: Unjail is only permitted if remaining stake >= MIN_STAKE_TO_UNJAIL
//! - **REC-INV-4**: Slashed stake is NOT restored on unjail (slash is permanent loss)
//! - **REC-INV-5**: Validator must explicitly submit unjail tx (no auto-release)
//! - **REC-INV-6**: JAIL_EXIT_WAIT_BLOCKS must be >= 100 blocks

// =============================================================================
// RECOVERY CONSTANTS
// =============================================================================

/// Number of finalized blocks a validator must wait before submitting an unjail
/// transaction.
///
/// After being jailed for a liveness violation, the validator is ineligible to
/// re-enter the active set until at least `JAIL_EXIT_WAIT_BLOCKS` blocks have
/// been finalized since the jailing block.
///
/// At a target block time of 10 seconds, 1000 blocks ≈ 2.8 hours.
///
/// # Invariant REC-INV-2
///
/// A validator that submits an unjail transaction before `current_block >=
/// jail_block + JAIL_EXIT_WAIT_BLOCKS` MUST have their request rejected.
///
/// # Invariant REC-INV-6
///
/// `JAIL_EXIT_WAIT_BLOCKS` must be at least 100 blocks to ensure meaningful
/// deterrence.
pub const JAIL_EXIT_WAIT_BLOCKS: u64 = 1000;

/// Minimum remaining stake (in micro-SOV) for a validator to be eligible to unjail.
///
/// A validator that was slashed down to zero (or below this threshold) cannot
/// unjail because they would immediately be below the minimum stake threshold
/// required to participate in consensus.
///
/// This prevents a validator from unjailing with no effective economic stake,
/// which would give them consensus participation rights without skin in the game.
///
/// Value: 1000 SOV tokens (in micro-SOV units, 1 SOV = 1_000_000 micro-SOV)
///
/// Matches the network minimum validator stake to ensure unjailing validators
/// retain meaningful economic stake.
pub const MIN_STAKE_TO_UNJAIL: u64 = 1000 * 1_000_000; // 1000 SOV in micro-SOV

// Compile-time invariant: REC-INV-6
const _: () = assert!(
    JAIL_EXIT_WAIT_BLOCKS >= 100,
    "REC-INV-6: JAIL_EXIT_WAIT_BLOCKS must be at least 100 blocks"
);

// =============================================================================
// LEGACY SLASHING POLICY COMPATIBILITY
// =============================================================================

/// Slash percentage applied for safety faults (double-sign, equivocation).
pub const DOUBLE_SIGN_SLASH_PERCENT: u8 = 100;

/// Slash percentage applied for liveness faults.
pub const LIVENESS_SLASH_PERCENT: u8 = 1;

/// Legacy name for liveness jail duration.
pub const JAIL_DURATION_BLOCKS: u64 = JAIL_EXIT_WAIT_BLOCKS;

/// Count of repeated liveness faults before removal logic may apply.
pub const REMOVAL_SLASH_COUNT: u32 = 10;

/// Safety offenses are always permanent bans.
pub const SAFETY_OFFENSE_ALWAYS_PERMANENT: bool = true;

/// Legacy severity classification maintained for API compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashSeverity {
    Safety,
    Liveness,
}

impl SlashSeverity {
    pub const fn slash_percent(self) -> u8 {
        match self {
            Self::Safety => DOUBLE_SIGN_SLASH_PERCENT,
            Self::Liveness => LIVENESS_SLASH_PERCENT,
        }
    }

    pub const fn jail_duration_blocks(self) -> Option<u64> {
        match self {
            Self::Safety => None,
            Self::Liveness => Some(JAIL_DURATION_BLOCKS),
        }
    }

    pub const fn is_permanent_ban(self) -> bool {
        matches!(self, Self::Safety)
    }

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
// VALIDATOR JAIL STATUS
// =============================================================================

/// The jail status of a validator, capturing both the reason and policy implications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailStatus {
    /// Validator is not jailed and can participate in consensus.
    Active,

    /// Validator is jailed for liveness failure.
    ///
    /// Fields:
    /// - `jailed_at_block`: Block height when jailing occurred
    /// - `eligible_at_block`: Block height when unjail becomes eligible
    ///   (= jailed_at_block + JAIL_EXIT_WAIT_BLOCKS)
    LivenessJail {
        jailed_at_block: u64,
        eligible_at_block: u64,
    },

    /// Validator is permanently banned due to safety violation.
    ///
    /// # Invariant REC-INV-1
    ///
    /// A validator in `PermanentBan` status CANNOT transition to `Active`.
    /// Any unjail request for a permanently banned validator MUST be rejected.
    PermanentBan {
        /// Block height when the safety slash was applied
        banned_at_block: u64,
        /// Human-readable reason for the ban
        reason: BanReason,
    },
}

/// Reason for permanent ban.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanReason {
    /// Validator double-signed a block.
    DoubleSign,
    /// Validator cast conflicting votes.
    ConflictingVote,
    /// Validator equivocated (signed with two keys).
    Equivocation,
    /// Validator proposed an invalid block deliberately.
    InvalidBlock,
    /// Validator participated in a long-range attack.
    LongRangeAttack,
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoubleSign => write!(f, "DoubleSign"),
            Self::ConflictingVote => write!(f, "ConflictingVote"),
            Self::Equivocation => write!(f, "Equivocation"),
            Self::InvalidBlock => write!(f, "InvalidBlock"),
            Self::LongRangeAttack => write!(f, "LongRangeAttack"),
        }
    }
}

impl JailStatus {
    /// Return true if the validator can currently participate in consensus.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Return true if the validator is permanently banned.
    ///
    /// # Invariant REC-INV-1
    pub fn is_permanently_banned(&self) -> bool {
        matches!(self, Self::PermanentBan { .. })
    }

    /// Return true if the validator is temporarily jailed (liveness).
    pub fn is_liveness_jailed(&self) -> bool {
        matches!(self, Self::LivenessJail { .. })
    }

    /// Return the block height at which unjailing becomes eligible, if applicable.
    ///
    /// Returns `None` for `Active` and `PermanentBan` statuses.
    pub fn eligible_at_block(&self) -> Option<u64> {
        match self {
            Self::LivenessJail { eligible_at_block, .. } => Some(*eligible_at_block),
            _ => None,
        }
    }
}

// =============================================================================
// RECOVERY ERROR
// =============================================================================

/// Errors returned when a recovery (unjail/stake restoration) request is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// Attempted to unjail a permanently banned validator.
    ///
    /// # Invariant REC-INV-1
    ///
    /// Safety-slashed validators CANNOT unjail under any circumstances.
    PermanentBan { reason: BanReason },

    /// Unjail submitted before the required wait period has passed.
    ///
    /// # Invariant REC-INV-2
    JailPeriodNotExpired { eligible_at_block: u64 },

    /// Validator's remaining stake is below the minimum required to unjail.
    ///
    /// # Invariant REC-INV-3
    InsufficientStake { remaining_stake: u64, required: u64 },

    /// Validator is not jailed (unjail request is invalid for active validator).
    NotJailed,

    /// Validator not found.
    ValidatorNotFound,
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermanentBan { reason } => write!(
                f,
                "Permanent ban for {} — validator cannot unjail",
                reason
            ),
            Self::JailPeriodNotExpired { eligible_at_block } => write!(
                f,
                "Jail period not expired; eligible to unjail at block {}",
                eligible_at_block
            ),
            Self::InsufficientStake { remaining_stake, required } => write!(
                f,
                "Insufficient stake to unjail: {} < {} required",
                remaining_stake,
                required
            ),
            Self::NotJailed => write!(f, "Validator is not jailed"),
            Self::ValidatorNotFound => write!(f, "Validator not found"),
        }
    }
}

/// Legacy policy error retained for compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashPolicyError {
    PermanentBan,
    JailPeriodNotExpired { eligible_at_block: u64 },
    ValidatorNotFound,
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
// RECOVERY ENFORCEMENT
// =============================================================================

/// Check whether a validator is eligible to exit jail.
///
/// This function enforces all recovery invariants (REC-INV-1 through REC-INV-3).
/// Call this before processing any unjail transaction.
///
/// # Arguments
///
/// * `jail_status` — Current jail status of the validator
/// * `remaining_stake` — Current bonded stake after any slashing
/// * `current_block` — Current finalized block height
///
/// # Returns
///
/// * `Ok(())` — Validator may unjail
/// * `Err(RecoveryError)` — Unjail request must be rejected
///
/// # Invariant REC-INV-1
///
/// If `jail_status` is `PermanentBan`, ALWAYS returns `Err(RecoveryError::PermanentBan)`.
///
/// # Invariant REC-INV-2
///
/// If `current_block < eligible_at_block`, returns `Err(JailPeriodNotExpired)`.
///
/// # Invariant REC-INV-3
///
/// If `remaining_stake < MIN_STAKE_TO_UNJAIL`, returns `Err(InsufficientStake)`.
pub fn check_unjail_eligibility(
    jail_status: &JailStatus,
    remaining_stake: u64,
    current_block: u64,
) -> Result<(), RecoveryError> {
    match jail_status {
        // REC-INV-1: Safety-slashed validators cannot unjail
        JailStatus::PermanentBan { reason, .. } => {
            return Err(RecoveryError::PermanentBan { reason: reason.clone() });
        }

        // Not jailed — unjail request is invalid
        JailStatus::Active => {
            return Err(RecoveryError::NotJailed);
        }

        // Liveness jail: check wait period and stake
        JailStatus::LivenessJail { jailed_at_block, eligible_at_block } => {
            // REC-INV-2: Validate that eligible_at_block matches computed expectation
            let computed_eligible = jailed_at_block.saturating_add(JAIL_EXIT_WAIT_BLOCKS);
            debug_assert_eq!(
                *eligible_at_block, computed_eligible,
                "REC-INV-2 violation: eligible_at_block ({}) != jailed_at_block ({}) + JAIL_EXIT_WAIT_BLOCKS ({})",
                eligible_at_block, jailed_at_block, JAIL_EXIT_WAIT_BLOCKS
            );
            if current_block < computed_eligible {
                return Err(RecoveryError::JailPeriodNotExpired {
                    eligible_at_block: computed_eligible,
                });
            }
        }
    }

    // REC-INV-3: Must have sufficient stake to unjail
    if remaining_stake < MIN_STAKE_TO_UNJAIL {
        return Err(RecoveryError::InsufficientStake {
            remaining_stake,
            required: MIN_STAKE_TO_UNJAIL,
        });
    }

    Ok(())
}

/// Legacy helper retained for compatibility with older call sites.
pub fn check_unjail_eligibility_legacy(
    permanently_banned: bool,
    jail_end_block: u64,
    current_block: u64,
) -> Result<(), SlashPolicyError> {
    if permanently_banned {
        return Err(SlashPolicyError::PermanentBan);
    }

    if current_block < jail_end_block {
        return Err(SlashPolicyError::JailPeriodNotExpired {
            eligible_at_block: jail_end_block,
        });
    }

    Ok(())
}

/// Compute the jail status after a liveness slash.
///
/// Creates a `JailStatus::LivenessJail` with the correct `eligible_at_block`
/// derived from `jailed_at_block + JAIL_EXIT_WAIT_BLOCKS`.
///
/// # Invariant REC-INV-2
///
/// `eligible_at_block = jailed_at_block + JAIL_EXIT_WAIT_BLOCKS`
pub fn liveness_jail_status(jailed_at_block: u64) -> JailStatus {
    JailStatus::LivenessJail {
        jailed_at_block,
        eligible_at_block: jailed_at_block.saturating_add(JAIL_EXIT_WAIT_BLOCKS),
    }
}

/// Compute the jail status after a safety slash (permanent ban).
///
/// Creates a `JailStatus::PermanentBan`. The ban CANNOT be lifted.
///
/// # Invariant REC-INV-1
pub fn safety_ban_status(banned_at_block: u64, reason: BanReason) -> JailStatus {
    JailStatus::PermanentBan { banned_at_block, reason }
}

/// Determine the stake restoration amount after unjailing.
///
/// When a validator unjails after a liveness violation, they recover their
/// current `remaining_stake`. The slashed portion (1%) is burned and NOT
/// returned to the validator.
///
/// # Invariant REC-INV-4
///
/// The return value is `remaining_stake` — the pre-slash stake is NOT restored.
/// There is no stake restoration beyond what the validator currently holds.
///
/// # Arguments
///
/// * `remaining_stake` - The validator's current bonded stake (post-slash)
///
/// # Returns
///
/// The stake the validator is authorized to use after unjailing (= remaining_stake).
pub fn stake_after_unjail(remaining_stake: u64) -> u64 {
    // REC-INV-4: No restoration — slashed amount is permanently burned.
    // The validator retains only what they currently hold.
    remaining_stake
}

/// Calculate slash amount from stake and percentage using saturating arithmetic.
pub fn calculate_slash_amount(stake: u64, slash_percent: u8) -> Result<u64, SlashPolicyError> {
    if !(1..=100).contains(&slash_percent) {
        return Err(SlashPolicyError::InvalidSlashPercent { got: slash_percent });
    }
    Ok(stake.saturating_mul(slash_percent as u64) / 100)
}

/// Calculate the first eligible block for unjail for a given slash severity.
pub fn jail_end_block(jailed_at_block: u64, severity: SlashSeverity) -> Option<u64> {
    match severity {
        SlashSeverity::Liveness => Some(jailed_at_block.saturating_add(JAIL_DURATION_BLOCKS)),
        SlashSeverity::Safety => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn liveness_jailed(at_block: u64) -> JailStatus {
        liveness_jail_status(at_block)
    }

    fn safety_banned(at_block: u64) -> JailStatus {
        safety_ban_status(at_block, BanReason::DoubleSign)
    }

    // =========================================================================
    // CONSTANT TESTS
    // =========================================================================

    #[test]
    fn test_jail_exit_wait_blocks_value() {
        assert_eq!(JAIL_EXIT_WAIT_BLOCKS, 1000);
    }

    #[test]
    fn test_min_stake_to_unjail_value() {
        // 100 SOV in micro-SOV
        assert_eq!(MIN_STAKE_TO_UNJAIL, 100 * 1_000_000);
    }

    #[test]
    fn test_rec_inv6_jail_exit_wait_at_least_100() {
        assert!(JAIL_EXIT_WAIT_BLOCKS >= 100, "REC-INV-6 violated");
    }

    // =========================================================================
    // JAIL STATUS TESTS
    // =========================================================================

    #[test]
    fn test_active_status_is_active() {
        assert!(JailStatus::Active.is_active());
        assert!(!JailStatus::Active.is_permanently_banned());
        assert!(!JailStatus::Active.is_liveness_jailed());
    }

    #[test]
    fn test_liveness_jail_status() {
        let status = liveness_jail_status(500);
        assert!(!status.is_active());
        assert!(!status.is_permanently_banned());
        assert!(status.is_liveness_jailed());
        assert_eq!(status.eligible_at_block(), Some(500 + JAIL_EXIT_WAIT_BLOCKS));
    }

    #[test]
    fn test_safety_ban_status() {
        let status = safety_ban_status(100, BanReason::DoubleSign);
        assert!(!status.is_active());
        assert!(status.is_permanently_banned());
        assert!(!status.is_liveness_jailed());
        assert_eq!(status.eligible_at_block(), None);
    }

    // =========================================================================
    // UNJAIL ELIGIBILITY TESTS
    // =========================================================================

    #[test]
    fn test_rec_inv1_permanent_ban_cannot_unjail() {
        let status = safety_banned(100);
        let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL + 1, 99999);
        assert!(matches!(result, Err(RecoveryError::PermanentBan { .. })),
            "REC-INV-1: permanent ban must be rejected");
    }

    #[test]
    fn test_rec_inv1_all_ban_reasons_rejected() {
        for reason in [
            BanReason::DoubleSign,
            BanReason::ConflictingVote,
            BanReason::Equivocation,
            BanReason::InvalidBlock,
            BanReason::LongRangeAttack,
        ] {
            let status = safety_ban_status(100, reason.clone());
            let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL + 1, 99999);
            assert!(
                matches!(result, Err(RecoveryError::PermanentBan { .. })),
                "REC-INV-1: {} ban must be rejected",
                reason
            );
        }
    }

    #[test]
    fn test_rec_inv2_jail_period_not_expired() {
        let jailed_at = 1000u64;
        let status = liveness_jailed(jailed_at);
        let eligible_at = jailed_at + JAIL_EXIT_WAIT_BLOCKS;

        // One block before eligible
        let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL + 1, eligible_at - 1);
        assert_eq!(
            result,
            Err(RecoveryError::JailPeriodNotExpired { eligible_at_block: eligible_at }),
            "REC-INV-2: must reject before jail period expires"
        );
    }

    #[test]
    fn test_rec_inv2_exactly_at_eligible_block() {
        let jailed_at = 1000u64;
        let status = liveness_jailed(jailed_at);
        let eligible_at = jailed_at + JAIL_EXIT_WAIT_BLOCKS;

        // Exactly at eligible block
        let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL + 1, eligible_at);
        assert_eq!(result, Ok(()), "Must accept at exactly eligible_at_block");
    }

    #[test]
    fn test_rec_inv2_after_eligible_block() {
        let jailed_at = 1000u64;
        let status = liveness_jailed(jailed_at);
        let eligible_at = jailed_at + JAIL_EXIT_WAIT_BLOCKS;

        // Long after eligible
        let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL + 1, eligible_at + 9999);
        assert_eq!(result, Ok(()), "Must accept after eligible_at_block");
    }

    #[test]
    fn test_rec_inv3_insufficient_stake_rejected() {
        let jailed_at = 1000u64;
        let status = liveness_jailed(jailed_at);
        let eligible_at = jailed_at + JAIL_EXIT_WAIT_BLOCKS;

        // Zero stake
        let result = check_unjail_eligibility(&status, 0, eligible_at + 1);
        assert!(matches!(result, Err(RecoveryError::InsufficientStake { .. })),
            "REC-INV-3: zero stake must be rejected");

        // Just below minimum
        let result2 = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL - 1, eligible_at + 1);
        assert!(matches!(result2, Err(RecoveryError::InsufficientStake { .. })),
            "REC-INV-3: below-minimum stake must be rejected");
    }

    #[test]
    fn test_rec_inv3_exact_minimum_stake_accepted() {
        let jailed_at = 1000u64;
        let status = liveness_jailed(jailed_at);
        let eligible_at = jailed_at + JAIL_EXIT_WAIT_BLOCKS;

        let result = check_unjail_eligibility(&status, MIN_STAKE_TO_UNJAIL, eligible_at + 1);
        assert_eq!(result, Ok(()), "REC-INV-3: exact minimum stake must be accepted");
    }

    #[test]
    fn test_not_jailed_unjail_rejected() {
        let result = check_unjail_eligibility(&JailStatus::Active, MIN_STAKE_TO_UNJAIL + 1, 1000);
        assert_eq!(result, Err(RecoveryError::NotJailed));
    }

    // =========================================================================
    // STAKE RESTORATION TESTS
    // =========================================================================

    #[test]
    fn test_rec_inv4_no_slash_restoration() {
        // Stake after unjail is exactly the remaining (post-slash) stake
        let remaining = 990_000_000u64; // 990 SOV (after 1% slash from 1000 SOV)
        let restored = stake_after_unjail(remaining);
        assert_eq!(restored, remaining, "REC-INV-4: no slash restoration");
    }

    #[test]
    fn test_stake_after_unjail_zero() {
        assert_eq!(stake_after_unjail(0), 0);
    }

    #[test]
    fn test_liveness_jail_eligible_at_block_calculation() {
        let jailed_at = 7500u64;
        let status = liveness_jail_status(jailed_at);
        match status {
            JailStatus::LivenessJail { jailed_at_block, eligible_at_block } => {
                assert_eq!(jailed_at_block, 7500);
                assert_eq!(eligible_at_block, 7500 + JAIL_EXIT_WAIT_BLOCKS);
            }
            _ => panic!("Expected LivenessJail"),
        }
    }

    #[test]
    fn test_ban_reason_display() {
        assert_eq!(BanReason::DoubleSign.to_string(), "DoubleSign");
        assert_eq!(BanReason::ConflictingVote.to_string(), "ConflictingVote");
        assert_eq!(BanReason::Equivocation.to_string(), "Equivocation");
        assert_eq!(BanReason::InvalidBlock.to_string(), "InvalidBlock");
        assert_eq!(BanReason::LongRangeAttack.to_string(), "LongRangeAttack");
    }
}
