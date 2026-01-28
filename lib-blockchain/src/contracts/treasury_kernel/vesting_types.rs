//! Vesting Types for Treasury Kernel
//!
//! Defines data structures for time-locked token vesting:
//! - VestingSchedule: cliff, start, end epochs and total amount
//! - VestingStatus: current state of a vesting lock
//! - VestingLock: tracks an individual vesting lock instance
//!
//! # Vesting Model
//!
//! Tokens vest linearly between `start_epoch` and `end_epoch`, but cannot be
//! released until after `cliff_epoch`. This follows the standard cliff vesting model:
//!
//! ```text
//! |----cliff----|--------linear vesting--------|
//! ^             ^                              ^
//! start_epoch   cliff_epoch                    end_epoch
//! ```
//!
//! - Before cliff: 0% releasable (tokens locked)
//! - At cliff: vested amount based on linear schedule becomes releasable
//! - After end: 100% releasable
//!
//! # Consensus-Critical
//!
//! All calculations use integer math only. No floating point.
//! Vesting state must be deterministically serializable (BTreeMap ordering).

use serde::{Deserialize, Serialize};

/// Unique identifier for a vesting lock
pub type VestingId = [u8; 32];

/// Vesting schedule parameters
///
/// Defines the time-based rules for token release.
/// All epochs are inclusive bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Epoch when vesting calculation begins (tokens start accruing)
    pub start_epoch: u64,

    /// Epoch when tokens first become releasable (cliff)
    /// Must be >= start_epoch
    pub cliff_epoch: u64,

    /// Epoch when all tokens are fully vested
    /// Must be >= cliff_epoch
    pub end_epoch: u64,

    /// Total amount of tokens in this vesting schedule
    pub total_amount: u64,
}

impl VestingSchedule {
    /// Create a new vesting schedule
    ///
    /// # Arguments
    /// * `start_epoch` - When vesting calculation begins
    /// * `cliff_epoch` - When tokens first become releasable
    /// * `end_epoch` - When all tokens are fully vested
    /// * `total_amount` - Total tokens to vest
    ///
    /// # Returns
    /// Some(VestingSchedule) if valid, None if invalid parameters
    pub fn new(
        start_epoch: u64,
        cliff_epoch: u64,
        end_epoch: u64,
        total_amount: u64,
    ) -> Option<Self> {
        // Validate: start <= cliff <= end
        if cliff_epoch < start_epoch || end_epoch < cliff_epoch {
            return None;
        }
        // Validate: non-zero amount
        if total_amount == 0 {
            return None;
        }

        Some(Self {
            start_epoch,
            cliff_epoch,
            end_epoch,
            total_amount,
        })
    }

    /// Calculate the amount vested at a given epoch
    ///
    /// Uses linear vesting between start_epoch and end_epoch.
    /// Returns 0 if before start_epoch, total_amount if after end_epoch.
    ///
    /// # Arguments
    /// * `current_epoch` - The epoch to calculate vested amount for
    ///
    /// # Returns
    /// Amount of tokens vested (not necessarily releasable)
    pub fn vested_amount(&self, current_epoch: u64) -> u64 {
        if current_epoch < self.start_epoch {
            return 0;
        }
        if current_epoch >= self.end_epoch {
            return self.total_amount;
        }

        // Linear vesting: (current - start) / (end - start) * total
        // Using integer math to avoid precision loss
        let elapsed = current_epoch - self.start_epoch;
        let duration = self.end_epoch - self.start_epoch;

        if duration == 0 {
            // Instant vesting (start == end)
            return self.total_amount;
        }

        // Calculate with u128 to prevent overflow
        let vested = (self.total_amount as u128)
            .saturating_mul(elapsed as u128)
            / (duration as u128);

        vested as u64
    }

    /// Calculate the amount releasable at a given epoch
    ///
    /// Returns 0 if cliff not reached. Otherwise returns vested_amount.
    ///
    /// # Arguments
    /// * `current_epoch` - The epoch to check
    ///
    /// # Returns
    /// Amount of tokens releasable (vested and past cliff)
    pub fn releasable_amount(&self, current_epoch: u64) -> u64 {
        if current_epoch < self.cliff_epoch {
            return 0;
        }
        self.vested_amount(current_epoch)
    }

    /// Check if the vesting schedule is valid
    pub fn is_valid(&self) -> bool {
        self.cliff_epoch >= self.start_epoch
            && self.end_epoch >= self.cliff_epoch
            && self.total_amount > 0
    }

    /// Get the vesting duration in epochs
    pub fn duration(&self) -> u64 {
        self.end_epoch.saturating_sub(self.start_epoch)
    }

    /// Get the cliff duration in epochs (from start to cliff)
    pub fn cliff_duration(&self) -> u64 {
        self.cliff_epoch.saturating_sub(self.start_epoch)
    }
}

/// Status of a vesting lock
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VestingStatus {
    /// Vesting has not started yet (before start_epoch)
    Pending,
    /// Before cliff - tokens accruing but not releasable
    BeforeCliff,
    /// After cliff - tokens actively vesting and releasable
    Active,
    /// All tokens fully vested and released
    Completed,
    /// Vesting was revoked (for revocable grants)
    Revoked,
}

impl std::fmt::Display for VestingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::BeforeCliff => write!(f, "Before cliff"),
            Self::Active => write!(f, "Active"),
            Self::Completed => write!(f, "Completed"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

/// A vesting lock instance
///
/// Tracks the state of a specific vesting grant for a beneficiary.
/// Immutable once created except for `amount_released` which increases
/// monotonically as tokens are claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingLock {
    /// Unique identifier for this vesting lock
    pub id: VestingId,

    /// Beneficiary who can claim the vested tokens
    pub beneficiary: [u8; 32],

    /// The vesting schedule parameters
    pub schedule: VestingSchedule,

    /// Amount already released to beneficiary (monotonically increasing)
    pub amount_released: u64,

    /// Epoch when this vesting lock was created
    pub created_epoch: u64,

    /// Whether this vesting can be revoked by governance
    pub revocable: bool,

    /// If revoked, the epoch when revocation occurred
    pub revoked_epoch: Option<u64>,
}

impl VestingLock {
    /// Create a new vesting lock
    ///
    /// # Arguments
    /// * `id` - Unique identifier
    /// * `beneficiary` - Recipient of vested tokens
    /// * `schedule` - Vesting schedule parameters
    /// * `created_epoch` - Current epoch when creating
    /// * `revocable` - Whether governance can revoke this vesting
    pub fn new(
        id: VestingId,
        beneficiary: [u8; 32],
        schedule: VestingSchedule,
        created_epoch: u64,
        revocable: bool,
    ) -> Self {
        Self {
            id,
            beneficiary,
            schedule,
            amount_released: 0,
            created_epoch,
            revocable,
            revoked_epoch: None,
        }
    }

    /// Get current status of this vesting lock
    pub fn status(&self, current_epoch: u64) -> VestingStatus {
        if self.revoked_epoch.is_some() {
            return VestingStatus::Revoked;
        }
        if self.amount_released >= self.schedule.total_amount {
            return VestingStatus::Completed;
        }
        if current_epoch < self.schedule.start_epoch {
            return VestingStatus::Pending;
        }
        if current_epoch < self.schedule.cliff_epoch {
            return VestingStatus::BeforeCliff;
        }
        VestingStatus::Active
    }

    /// Calculate amount available to release now
    ///
    /// # Arguments
    /// * `current_epoch` - Current epoch
    ///
    /// # Returns
    /// Amount that can be released (releasable - already_released)
    pub fn available_to_release(&self, current_epoch: u64) -> u64 {
        if self.revoked_epoch.is_some() {
            return 0;
        }

        let releasable = self.schedule.releasable_amount(current_epoch);
        releasable.saturating_sub(self.amount_released)
    }

    /// Record a release of tokens
    ///
    /// # Arguments
    /// * `amount` - Amount being released
    ///
    /// # Returns
    /// Ok(()) if valid, Err if would exceed total
    pub fn record_release(&mut self, amount: u64) -> Result<(), String> {
        let new_total = self
            .amount_released
            .checked_add(amount)
            .ok_or("Release amount overflow")?;

        if new_total > self.schedule.total_amount {
            return Err("Would exceed total vesting amount".to_string());
        }

        self.amount_released = new_total;
        Ok(())
    }

    /// Revoke this vesting lock (if revocable)
    ///
    /// # Arguments
    /// * `current_epoch` - Epoch when revocation occurs
    ///
    /// # Returns
    /// Ok(unvested_amount) if revoked, Err if not revocable or already revoked
    pub fn revoke(&mut self, current_epoch: u64) -> Result<u64, String> {
        if !self.revocable {
            return Err("Vesting lock is not revocable".to_string());
        }
        if self.revoked_epoch.is_some() {
            return Err("Vesting lock already revoked".to_string());
        }

        // Calculate unvested amount that will be returned
        let vested = self.schedule.vested_amount(current_epoch);
        let unvested = self.schedule.total_amount.saturating_sub(vested);

        self.revoked_epoch = Some(current_epoch);
        Ok(unvested)
    }

    /// Get remaining locked amount
    pub fn remaining_locked(&self) -> u64 {
        self.schedule.total_amount.saturating_sub(self.amount_released)
    }

    /// Check if fully vested and released
    pub fn is_complete(&self) -> bool {
        self.amount_released >= self.schedule.total_amount
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vesting_schedule_new_valid() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000);
        assert!(schedule.is_some());
        let s = schedule.unwrap();
        assert!(s.is_valid());
    }

    #[test]
    fn test_vesting_schedule_new_invalid_cliff_before_start() {
        let schedule = VestingSchedule::new(100, 90, 200, 10000);
        assert!(schedule.is_none());
    }

    #[test]
    fn test_vesting_schedule_new_invalid_end_before_cliff() {
        let schedule = VestingSchedule::new(100, 150, 140, 10000);
        assert!(schedule.is_none());
    }

    #[test]
    fn test_vesting_schedule_new_invalid_zero_amount() {
        let schedule = VestingSchedule::new(100, 110, 200, 0);
        assert!(schedule.is_none());
    }

    #[test]
    fn test_vested_amount_before_start() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        assert_eq!(schedule.vested_amount(50), 0);
        assert_eq!(schedule.vested_amount(99), 0);
    }

    #[test]
    fn test_vested_amount_at_start() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        assert_eq!(schedule.vested_amount(100), 0);
    }

    #[test]
    fn test_vested_amount_linear() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        // 50% through = 50% vested
        assert_eq!(schedule.vested_amount(150), 5000);
        // 25% through = 25% vested
        assert_eq!(schedule.vested_amount(125), 2500);
    }

    #[test]
    fn test_vested_amount_at_end() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        assert_eq!(schedule.vested_amount(200), 10000);
    }

    #[test]
    fn test_vested_amount_after_end() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        assert_eq!(schedule.vested_amount(300), 10000);
    }

    #[test]
    fn test_releasable_before_cliff() {
        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        // Vested but not releasable (before cliff)
        assert_eq!(schedule.vested_amount(125), 2500);
        assert_eq!(schedule.releasable_amount(125), 0);
    }

    #[test]
    fn test_releasable_at_cliff() {
        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        // At cliff, 50% vested and now releasable
        assert_eq!(schedule.releasable_amount(150), 5000);
    }

    #[test]
    fn test_releasable_after_cliff() {
        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        // After cliff, vested == releasable
        assert_eq!(schedule.releasable_amount(175), 7500);
    }

    #[test]
    fn test_vesting_lock_new() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        let lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        assert_eq!(lock.amount_released, 0);
        assert_eq!(lock.created_epoch, 100);
        assert!(!lock.revocable);
        assert!(lock.revoked_epoch.is_none());
    }

    #[test]
    fn test_vesting_lock_status_pending() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        let lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 50, false);

        assert_eq!(lock.status(50), VestingStatus::Pending);
        assert_eq!(lock.status(99), VestingStatus::Pending);
    }

    #[test]
    fn test_vesting_lock_status_before_cliff() {
        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        let lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        assert_eq!(lock.status(100), VestingStatus::BeforeCliff);
        assert_eq!(lock.status(149), VestingStatus::BeforeCliff);
    }

    #[test]
    fn test_vesting_lock_status_active() {
        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        let lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        assert_eq!(lock.status(150), VestingStatus::Active);
        assert_eq!(lock.status(199), VestingStatus::Active);
    }

    #[test]
    fn test_vesting_lock_status_completed() {
        let schedule = VestingSchedule::new(100, 110, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);
        lock.amount_released = 10000;

        assert_eq!(lock.status(250), VestingStatus::Completed);
    }

    #[test]
    fn test_vesting_lock_available_to_release() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        // At 150, 50% vested, none released
        assert_eq!(lock.available_to_release(150), 5000);

        // Release 3000
        lock.record_release(3000).unwrap();
        assert_eq!(lock.available_to_release(150), 2000);
    }

    #[test]
    fn test_vesting_lock_record_release() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        assert!(lock.record_release(3000).is_ok());
        assert_eq!(lock.amount_released, 3000);

        assert!(lock.record_release(7000).is_ok());
        assert_eq!(lock.amount_released, 10000);
    }

    #[test]
    fn test_vesting_lock_record_release_exceeds_total() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        let result = lock.record_release(10001);
        assert!(result.is_err());
    }

    #[test]
    fn test_vesting_lock_revoke() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, true);

        // At epoch 150, 50% vested, so unvested = 5000
        let result = lock.revoke(150);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5000);
        assert_eq!(lock.revoked_epoch, Some(150));
        assert_eq!(lock.status(150), VestingStatus::Revoked);
    }

    #[test]
    fn test_vesting_lock_revoke_not_revocable() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, false);

        let result = lock.revoke(150);
        assert!(result.is_err());
    }

    #[test]
    fn test_vesting_lock_revoke_already_revoked() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, true);

        lock.revoke(150).unwrap();
        let result = lock.revoke(160);
        assert!(result.is_err());
    }

    #[test]
    fn test_vesting_lock_available_after_revoke() {
        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let mut lock = VestingLock::new([1u8; 32], [2u8; 32], schedule, 100, true);

        lock.revoke(150).unwrap();
        assert_eq!(lock.available_to_release(200), 0);
    }

    #[test]
    fn test_instant_vesting() {
        // Same start and end = instant vesting
        let schedule = VestingSchedule::new(100, 100, 100, 10000).unwrap();
        assert_eq!(schedule.vested_amount(100), 10000);
        assert_eq!(schedule.releasable_amount(100), 10000);
    }
}
