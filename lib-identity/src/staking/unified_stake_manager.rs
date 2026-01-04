//! Unified Stake Manager with tier calculation and progressive unlocking
//!
//! ## Security Model
//!
//! This module implements critical financial operations with the following security guarantees:
//!
//! 1. **Authentication**: All stake operations require caller identity verification
//! 2. **Overflow Protection**: All arithmetic uses checked operations
//! 3. **Input Validation**: All parameters are validated against safe bounds
//! 4. **Rate Limiting**: Maximum stake entries per identity enforced
//! 5. **Audit Logging**: All operations are logged for security auditing
//!
//! ## Thread Safety
//!
//! **WARNING**: This manager is NOT thread-safe internally.
//! For concurrent access, wrap in `std::sync::RwLock` or `tokio::sync::RwLock`.
//!
//! ```ignore
//! use std::sync::RwLock;
//! let manager = RwLock::new(UnifiedStakeManager::new());
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::staking::StakeTier;
use crate::types::IdentityId;

// =============================================================================
// Security Constants
// =============================================================================

/// Maximum stake amount per operation (prevents overflow attacks)
/// Note: u64 max in micro-SOV is ~18M SOV, so we cap at 1M SOV for safety
pub const MAX_STAKE_AMOUNT: u64 = 1_000_000_000_000_000_000; // 1M SOV in micro-SOV

/// Maximum lock period in blocks (~10 years at 1 block/second)
pub const MAX_LOCK_PERIOD: u64 = 315_360_000; // ~10 years

/// Maximum stake entries per identity (prevents DoS via memory exhaustion)
pub const MAX_STAKE_ENTRIES: usize = 1000;

// =============================================================================
// Data Structures
// =============================================================================

/// Warning issued when a withdrawal would affect tier status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWarning {
    /// Current tier before withdrawal
    current_tier: StakeTier,
    /// Tier after withdrawal if proceeded
    resulting_tier: StakeTier,
    /// Amount that can be withdrawn without downgrade
    safe_withdrawal_amount: u64,
    /// Human-readable message
    message: String,
}

impl WithdrawalWarning {
    /// Get the current tier
    pub fn current_tier(&self) -> StakeTier {
        self.current_tier
    }

    /// Get the resulting tier after withdrawal
    pub fn resulting_tier(&self) -> StakeTier {
        self.resulting_tier
    }

    /// Get the safe withdrawal amount
    pub fn safe_withdrawal_amount(&self) -> u64 {
        self.safe_withdrawal_amount
    }

    /// Get the warning message
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Result of a withdrawal attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalResult {
    /// Whether withdrawal succeeded
    success: bool,
    /// New total staked amount
    new_total_staked: u64,
    /// New tier after withdrawal
    new_tier: StakeTier,
    /// Warning if tier was downgraded
    warning: Option<WithdrawalWarning>,
}

impl WithdrawalResult {
    /// Whether the withdrawal succeeded
    pub fn success(&self) -> bool {
        self.success
    }

    /// Get new total staked amount
    pub fn new_total_staked(&self) -> u64 {
        self.new_total_staked
    }

    /// Get new tier after withdrawal
    pub fn new_tier(&self) -> StakeTier {
        self.new_tier
    }

    /// Get warning if tier was downgraded
    pub fn warning(&self) -> Option<&WithdrawalWarning> {
        self.warning.as_ref()
    }
}

/// Stake record for an identity (fields are private to prevent direct manipulation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRecord {
    /// Identity that owns the stake
    identity_id: IdentityId,
    /// Total staked amount (in micro-SOV)
    total_staked: u64,
    /// Current tier based on stake
    current_tier: StakeTier,
    /// Block height of last stake change
    last_updated: u64,
    /// Individual stake entries for progressive unlocking
    stake_entries: Vec<StakeEntry>,
}

impl StakeRecord {
    /// Get the identity ID
    pub fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    /// Get total staked amount
    pub fn total_staked(&self) -> u64 {
        self.total_staked
    }

    /// Get current tier
    pub fn current_tier(&self) -> StakeTier {
        self.current_tier
    }

    /// Get last updated block height
    pub fn last_updated(&self) -> u64 {
        self.last_updated
    }

    /// Get stake entries (read-only)
    pub fn stake_entries(&self) -> &[StakeEntry] {
        &self.stake_entries
    }

    /// Get number of stake entries
    pub fn entry_count(&self) -> usize {
        self.stake_entries.len()
    }
}

/// Individual stake entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEntry {
    /// Amount staked
    amount: u64,
    /// Block height when staked
    staked_at_height: u64,
    /// Lock period in blocks (0 = unlocked)
    lock_period: u64,
}

impl StakeEntry {
    /// Get stake amount
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Get block height when staked
    pub fn staked_at_height(&self) -> u64 {
        self.staked_at_height
    }

    /// Get lock period
    pub fn lock_period(&self) -> u64 {
        self.lock_period
    }

    /// Check if this entry is unlocked at the given height
    ///
    /// Returns Err if the unlock height calculation would overflow.
    pub fn is_unlocked_at(&self, current_height: u64) -> Result<bool> {
        let unlock_height = self
            .staked_at_height
            .checked_add(self.lock_period)
            .ok_or_else(|| {
                anyhow!(
                    "Lock period overflow: staked_at_height ({}) + lock_period ({}) exceeds u64::MAX",
                    self.staked_at_height,
                    self.lock_period
                )
            })?;
        Ok(current_height >= unlock_height)
    }
}

/// Unified Stake Manager - handles tier calculation and progressive unlocking
///
/// ## Thread Safety
///
/// **WARNING**: This struct is NOT thread-safe.
/// For concurrent access, wrap in `std::sync::RwLock` or `tokio::sync::RwLock`.
#[derive(Debug)]
pub struct UnifiedStakeManager {
    /// Stake records by identity
    stakes: HashMap<IdentityId, StakeRecord>,
}

impl Default for UnifiedStakeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedStakeManager {
    /// Create a new stake manager
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
        }
    }

    /// Calculate tier from total staked amount (in micro-SOV)
    pub fn calculate_tier(total_staked: u64) -> StakeTier {
        if total_staked >= 10_000_000_000_000_000 {
            // 10,000 SOV
            StakeTier::Validator
        } else if total_staked >= 2_000_000_000_000_000 {
            // 2,000 SOV
            StakeTier::DaoFounder
        } else if total_staked >= 500_000_000_000_000 {
            // 500 SOV
            StakeTier::Citizenship
        } else {
            StakeTier::None
        }
    }

    /// Get stake record for an identity (read-only)
    pub fn get_stake_record(&self, identity_id: &IdentityId) -> Option<&StakeRecord> {
        self.stakes.get(identity_id)
    }

    /// Get current tier for an identity
    pub fn get_tier(&self, identity_id: &IdentityId) -> StakeTier {
        self.stakes
            .get(identity_id)
            .map(|r| r.current_tier)
            .unwrap_or(StakeTier::None)
    }

    /// Add stake for an identity
    ///
    /// ## Security
    ///
    /// - **Authentication**: Caller must match identity_id (caller == target)
    /// - **Input Validation**: Amount and lock_period are validated
    /// - **Rate Limiting**: Maximum stake entries enforced
    ///
    /// ## Parameters
    ///
    /// - `caller`: The identity making the request (for authentication)
    /// - `identity_id`: The identity to add stake for
    /// - `amount`: Amount to stake in micro-SOV (must be > 0, <= MAX_STAKE_AMOUNT)
    /// - `current_height`: Current block height
    /// - `lock_period`: Lock period in blocks (0 = unlocked, <= MAX_LOCK_PERIOD)
    ///
    /// ## Errors
    ///
    /// - Unauthorized if caller != identity_id
    /// - Invalid amount (0 or > MAX_STAKE_AMOUNT)
    /// - Invalid lock period (> MAX_LOCK_PERIOD)
    /// - Lock period overflow
    /// - Maximum stake entries exceeded
    pub fn add_stake(
        &mut self,
        caller: &IdentityId,
        identity_id: &IdentityId,
        amount: u64,
        current_height: u64,
        lock_period: u64,
    ) -> Result<StakeTier> {
        // SECURITY FIX #1: Authentication - verify caller owns the stake
        if caller != identity_id {
            tracing::warn!(
                event = "stake_add_unauthorized",
                caller = %hex::encode(&caller.0[..8]),
                target = %hex::encode(&identity_id.0[..8]),
                "Unauthorized stake add attempt"
            );
            return Err(anyhow!(
                "Unauthorized: caller {} does not own stake for {}",
                hex::encode(&caller.0[..8]),
                hex::encode(&identity_id.0[..8])
            ));
        }

        // SECURITY FIX #5: Input validation
        if amount == 0 {
            return Err(anyhow!("Stake amount must be greater than 0"));
        }
        if amount > MAX_STAKE_AMOUNT {
            return Err(anyhow!(
                "Stake amount {} exceeds maximum {}",
                amount,
                MAX_STAKE_AMOUNT
            ));
        }
        if lock_period > MAX_LOCK_PERIOD {
            return Err(anyhow!(
                "Lock period {} exceeds maximum {} blocks (~10 years)",
                lock_period,
                MAX_LOCK_PERIOD
            ));
        }

        // SECURITY FIX #2: Validate lock period won't overflow
        current_height.checked_add(lock_period).ok_or_else(|| {
            anyhow!(
                "Lock period overflow: current_height ({}) + lock_period ({}) exceeds u64::MAX",
                current_height,
                lock_period
            )
        })?;

        let record = self
            .stakes
            .entry(identity_id.clone())
            .or_insert_with(|| StakeRecord {
                identity_id: identity_id.clone(),
                total_staked: 0,
                current_tier: StakeTier::None,
                last_updated: current_height,
                stake_entries: Vec::new(),
            });

        // SECURITY FIX #7: Rate limiting - check entry count
        if record.stake_entries.len() >= MAX_STAKE_ENTRIES {
            return Err(anyhow!(
                "Maximum stake entries exceeded: {} >= {}. Consolidate existing stakes first.",
                record.stake_entries.len(),
                MAX_STAKE_ENTRIES
            ));
        }

        // Add the stake entry
        record.stake_entries.push(StakeEntry {
            amount,
            staked_at_height: current_height,
            lock_period,
        });

        // Update total and recalculate tier (using checked arithmetic)
        record.total_staked = record.total_staked.checked_add(amount).ok_or_else(|| {
            anyhow!(
                "Total stake overflow: {} + {} exceeds u64::MAX",
                record.total_staked,
                amount
            )
        })?;
        record.current_tier = Self::calculate_tier(record.total_staked);
        record.last_updated = current_height;

        // SECURITY FIX #8: Security event logging
        tracing::info!(
            event = "stake_added",
            identity = %hex::encode(&identity_id.0[..8]),
            amount = amount,
            lock_period = lock_period,
            new_total = record.total_staked,
            new_tier = %record.current_tier,
            height = current_height,
            "Stake added successfully"
        );

        Ok(record.current_tier)
    }

    /// Calculate safe withdrawal amount (amount that won't cause tier downgrade)
    pub fn calculate_safe_withdrawal(&self, identity_id: &IdentityId) -> u64 {
        let Some(record) = self.stakes.get(identity_id) else {
            return 0;
        };

        let current_tier_minimum = record.current_tier.minimum_stake();

        // SECURITY FIX #4: Bounds check to prevent underflow
        if record.total_staked > current_tier_minimum {
            record.total_staked - current_tier_minimum
        } else {
            0
        }
    }

    /// Check withdrawal and return warning if it would cause downgrade
    pub fn check_withdrawal(
        &self,
        identity_id: &IdentityId,
        amount: u64,
    ) -> Option<WithdrawalWarning> {
        let Some(record) = self.stakes.get(identity_id) else {
            return None;
        };

        let new_total = record.total_staked.saturating_sub(amount);
        let new_tier = Self::calculate_tier(new_total);
        let safe_amount = self.calculate_safe_withdrawal(identity_id);

        if new_tier < record.current_tier {
            Some(WithdrawalWarning {
                current_tier: record.current_tier,
                resulting_tier: new_tier,
                safe_withdrawal_amount: safe_amount,
                message: format!(
                    "Warning: Withdrawing {} micro-SOV will downgrade you from {} to {}. \
                     You can safely withdraw up to {} micro-SOV without losing your tier.",
                    amount, record.current_tier, new_tier, safe_amount
                ),
            })
        } else {
            None
        }
    }

    /// Withdraw stake with progressive unlocking
    ///
    /// ## Security
    ///
    /// - **Authentication**: Caller must match identity_id
    /// - **Lock Period**: Only unlocked stakes can be withdrawn
    /// - **Tier Protection**: Warns before downgrade, requires force_downgrade flag
    ///
    /// ## Parameters
    ///
    /// - `caller`: The identity making the request (for authentication)
    /// - `identity_id`: The identity to withdraw from
    /// - `amount`: Amount to withdraw in micro-SOV
    /// - `current_height`: Current block height
    /// - `force_downgrade`: If true, allows withdrawal even if it causes tier downgrade
    pub fn withdraw_stake(
        &mut self,
        caller: &IdentityId,
        identity_id: &IdentityId,
        amount: u64,
        current_height: u64,
        force_downgrade: bool,
    ) -> Result<WithdrawalResult> {
        // SECURITY FIX #1: Authentication - verify caller owns the stake
        if caller != identity_id {
            tracing::warn!(
                event = "stake_withdraw_unauthorized",
                caller = %hex::encode(&caller.0[..8]),
                target = %hex::encode(&identity_id.0[..8]),
                "Unauthorized withdrawal attempt"
            );
            return Err(anyhow!(
                "Unauthorized: caller {} does not own stake for {}",
                hex::encode(&caller.0[..8]),
                hex::encode(&identity_id.0[..8])
            ));
        }

        // SECURITY FIX #8: Log withdrawal attempt
        tracing::info!(
            event = "stake_withdrawal_attempt",
            identity = %hex::encode(&identity_id.0[..8]),
            amount = amount,
            height = current_height,
            force_downgrade = force_downgrade,
            "Withdrawal attempt initiated"
        );

        let record = self
            .stakes
            .get_mut(identity_id)
            .ok_or_else(|| anyhow!("No stake record found for identity"))?;

        // Check for tier downgrade warning
        let new_total = record.total_staked.saturating_sub(amount);
        let new_tier = Self::calculate_tier(new_total);

        // SECURITY FIX #4: Safe calculation of safe_amount
        let safe_amount = if record.total_staked > record.current_tier.minimum_stake() {
            record.total_staked - record.current_tier.minimum_stake()
        } else {
            0
        };

        let warning = if new_tier < record.current_tier {
            Some(WithdrawalWarning {
                current_tier: record.current_tier,
                resulting_tier: new_tier,
                safe_withdrawal_amount: safe_amount,
                message: format!(
                    "Warning: Withdrawing {} micro-SOV will downgrade from {} to {}. \
                     Safe withdrawal: {} micro-SOV",
                    amount, record.current_tier, new_tier, safe_amount
                ),
            })
        } else {
            None
        };

        if warning.is_some() && !force_downgrade {
            tracing::info!(
                event = "stake_withdrawal_blocked",
                identity = %hex::encode(&identity_id.0[..8]),
                amount = amount,
                current_tier = %record.current_tier,
                would_downgrade_to = %new_tier,
                "Withdrawal blocked - would cause tier downgrade"
            );
            return Ok(WithdrawalResult {
                success: false,
                new_total_staked: record.total_staked,
                new_tier: record.current_tier,
                warning,
            });
        }

        // SECURITY FIX #2: Calculate available (unlocked) stake with checked arithmetic
        let mut unlocked_amount: u64 = 0;
        for entry in record.stake_entries.iter() {
            // Use checked_add for unlock height calculation
            let unlock_height = entry
                .staked_at_height
                .checked_add(entry.lock_period)
                .ok_or_else(|| {
                    anyhow!(
                        "Lock period overflow in entry: staked_at_height ({}) + lock_period ({}) exceeds u64::MAX",
                        entry.staked_at_height,
                        entry.lock_period
                    )
                })?;

            if current_height >= unlock_height {
                unlocked_amount = unlocked_amount.saturating_add(entry.amount);
            }
        }

        if amount > unlocked_amount {
            tracing::warn!(
                event = "stake_withdrawal_insufficient_unlocked",
                identity = %hex::encode(&identity_id.0[..8]),
                requested = amount,
                unlocked = unlocked_amount,
                "Requested withdrawal exceeds unlocked stake"
            );
            return Err(anyhow!(
                "Requested withdrawal {} exceeds unlocked stake {}",
                amount,
                unlocked_amount
            ));
        }

        // Process withdrawal from unlocked entries
        let mut remaining_to_withdraw = amount;
        record.stake_entries.retain_mut(|entry| {
            if remaining_to_withdraw == 0 {
                return true;
            }

            // SECURITY FIX #2: Use checked_add for unlock height
            let unlock_height = match entry.staked_at_height.checked_add(entry.lock_period) {
                Some(h) => h,
                None => return true, // Keep entries with overflow (shouldn't happen after validation)
            };

            if current_height >= unlock_height {
                if entry.amount <= remaining_to_withdraw {
                    remaining_to_withdraw -= entry.amount;
                    false // Remove fully withdrawn entry
                } else {
                    entry.amount -= remaining_to_withdraw;
                    remaining_to_withdraw = 0;
                    true // Keep partially withdrawn entry
                }
            } else {
                true // Keep locked entries
            }
        });

        // Update total and tier
        record.total_staked = record.total_staked.saturating_sub(amount);
        record.current_tier = Self::calculate_tier(record.total_staked);
        record.last_updated = current_height;

        // SECURITY FIX #8: Log successful withdrawal
        tracing::info!(
            event = "stake_withdrawal_completed",
            identity = %hex::encode(&identity_id.0[..8]),
            amount = amount,
            new_total = record.total_staked,
            new_tier = %record.current_tier,
            height = current_height,
            "Withdrawal completed successfully"
        );

        Ok(WithdrawalResult {
            success: true,
            new_total_staked: record.total_staked,
            new_tier: record.current_tier,
            warning,
        })
    }

    /// Get unlocked stake amount for an identity at the given height
    pub fn get_unlocked_amount(
        &self,
        identity_id: &IdentityId,
        current_height: u64,
    ) -> Result<u64> {
        let Some(record) = self.stakes.get(identity_id) else {
            return Ok(0);
        };

        let mut unlocked = 0u64;
        for entry in record.stake_entries.iter() {
            if entry.is_unlocked_at(current_height)? {
                unlocked = unlocked.saturating_add(entry.amount);
            }
        }
        Ok(unlocked)
    }

    /// Get locked stake amount for an identity at the given height
    pub fn get_locked_amount(&self, identity_id: &IdentityId, current_height: u64) -> Result<u64> {
        let Some(record) = self.stakes.get(identity_id) else {
            return Ok(0);
        };

        let mut locked = 0u64;
        for entry in record.stake_entries.iter() {
            if !entry.is_unlocked_at(current_height)? {
                locked = locked.saturating_add(entry.amount);
            }
        }
        Ok(locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    fn make_identity(seed: u8) -> IdentityId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        Hash(bytes)
    }

    #[test]
    fn test_tier_calculation() {
        assert_eq!(UnifiedStakeManager::calculate_tier(0), StakeTier::None);
        assert_eq!(
            UnifiedStakeManager::calculate_tier(499_999_999_999_999),
            StakeTier::None
        );
        assert_eq!(
            UnifiedStakeManager::calculate_tier(500_000_000_000_000),
            StakeTier::Citizenship
        );
        assert_eq!(
            UnifiedStakeManager::calculate_tier(1_999_999_999_999_999),
            StakeTier::Citizenship
        );
        assert_eq!(
            UnifiedStakeManager::calculate_tier(2_000_000_000_000_000),
            StakeTier::DaoFounder
        );
        assert_eq!(
            UnifiedStakeManager::calculate_tier(9_999_999_999_999_999),
            StakeTier::DaoFounder
        );
        assert_eq!(
            UnifiedStakeManager::calculate_tier(10_000_000_000_000_000),
            StakeTier::Validator
        );
    }

    #[test]
    fn test_add_stake_with_auth() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);
        let other = make_identity(2);

        // Should succeed when caller == identity
        let result = manager.add_stake(&id, &id, 500_000_000_000_000, 100, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), StakeTier::Citizenship);

        // Should fail when caller != identity
        let result = manager.add_stake(&other, &id, 500_000_000_000_000, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unauthorized"));
    }

    #[test]
    fn test_add_stake_input_validation() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Zero amount should fail
        let result = manager.add_stake(&id, &id, 0, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("greater than 0"));

        // Excessive amount should fail
        let result = manager.add_stake(&id, &id, MAX_STAKE_AMOUNT + 1, 100, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));

        // Excessive lock period should fail
        let result = manager.add_stake(&id, &id, 1000, 100, MAX_LOCK_PERIOD + 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Lock period"));
    }

    #[test]
    fn test_lock_period_overflow_protection() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Should fail when height + lock_period would overflow
        let result = manager.add_stake(&id, &id, 1000, u64::MAX - 100, 200);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflow"));
    }

    #[test]
    fn test_safe_withdrawal_calculation() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Add exactly citizenship tier
        manager
            .add_stake(&id, &id, 500_000_000_000_000, 100, 0)
            .unwrap();

        // Safe withdrawal should be 0 (at exact tier boundary)
        assert_eq!(manager.calculate_safe_withdrawal(&id), 0);

        // Add more stake
        manager
            .add_stake(&id, &id, 100_000_000_000_000, 100, 0)
            .unwrap();

        // Safe withdrawal should be the excess
        assert_eq!(manager.calculate_safe_withdrawal(&id), 100_000_000_000_000);
    }

    #[test]
    fn test_withdrawal_with_auth() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);
        let other = make_identity(2);

        // Add stake
        manager
            .add_stake(&id, &id, 600_000_000_000_000, 100, 0)
            .unwrap();

        // Should fail when caller != identity
        let result = manager.withdraw_stake(&other, &id, 100_000_000_000_000, 100, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unauthorized"));

        // Should succeed when caller == identity
        let result = manager.withdraw_stake(&id, &id, 100_000_000_000_000, 100, false);
        assert!(result.is_ok());
        assert!(result.unwrap().success());
    }

    #[test]
    fn test_progressive_unlocking() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Add stake with lock period
        manager
            .add_stake(&id, &id, 100_000_000_000_000, 100, 50)
            .unwrap(); // Unlocks at 150
        manager
            .add_stake(&id, &id, 200_000_000_000_000, 100, 100)
            .unwrap(); // Unlocks at 200

        // At height 100, nothing unlocked
        assert_eq!(manager.get_unlocked_amount(&id, 100).unwrap(), 0);

        // At height 150, first entry unlocked
        assert_eq!(
            manager.get_unlocked_amount(&id, 150).unwrap(),
            100_000_000_000_000
        );

        // At height 200, all unlocked
        assert_eq!(
            manager.get_unlocked_amount(&id, 200).unwrap(),
            300_000_000_000_000
        );
    }

    #[test]
    fn test_tier_downgrade_protection() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Add stake for citizenship tier
        manager
            .add_stake(&id, &id, 600_000_000_000_000, 100, 0)
            .unwrap();

        // Try to withdraw all - should be blocked without force
        let result = manager.withdraw_stake(&id, &id, 600_000_000_000_000, 100, false);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.success());
        assert!(result.warning().is_some());

        // Try again with force - should succeed
        let result = manager.withdraw_stake(&id, &id, 600_000_000_000_000, 100, true);
        assert!(result.is_ok());
        assert!(result.unwrap().success());
    }

    #[test]
    fn test_rate_limiting() {
        let mut manager = UnifiedStakeManager::new();
        let id = make_identity(1);

        // Add MAX_STAKE_ENTRIES entries
        for i in 0..MAX_STAKE_ENTRIES {
            let result = manager.add_stake(&id, &id, 1000, i as u64, 0);
            assert!(result.is_ok(), "Failed at entry {}", i);
        }

        // Next entry should fail
        let result = manager.add_stake(&id, &id, 1000, MAX_STAKE_ENTRIES as u64, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Maximum stake entries"));
    }
}
