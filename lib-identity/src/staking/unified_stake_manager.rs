//! Unified Stake Manager with tier calculation and progressive unlocking

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::staking::StakeTier;
use crate::types::IdentityId;

/// Warning issued when a withdrawal would affect tier status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalWarning {
    /// Current tier before withdrawal
    pub current_tier: StakeTier,
    /// Tier after withdrawal if proceeded
    pub resulting_tier: StakeTier,
    /// Amount that can be withdrawn without downgrade
    pub safe_withdrawal_amount: u64,
    /// Human-readable message
    pub message: String,
}

/// Result of a withdrawal attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalResult {
    /// Whether withdrawal succeeded
    pub success: bool,
    /// New total staked amount
    pub new_total_staked: u64,
    /// New tier after withdrawal
    pub new_tier: StakeTier,
    /// Warning if tier was downgraded
    pub warning: Option<WithdrawalWarning>,
}

/// Stake record for an identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeRecord {
    /// Identity that owns the stake
    pub identity_id: IdentityId,
    /// Total staked amount (in micro-SOV)
    pub total_staked: u64,
    /// Current tier based on stake
    pub current_tier: StakeTier,
    /// Timestamp of last stake change
    pub last_updated: u64,
    /// Individual stake entries for tracking
    pub stake_entries: Vec<StakeEntry>,
}

/// Individual stake entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEntry {
    /// Amount staked
    pub amount: u64,
    /// Block height when staked
    pub staked_at_height: u64,
    /// Lock period in blocks (0 = unlocked)
    pub lock_period: u64,
}

/// Unified Stake Manager - handles tier calculation and progressive unlocking
#[derive(Debug)]
pub struct UnifiedStakeManager {
    /// Stake records by identity
    stakes: HashMap<IdentityId, StakeRecord>,
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
        if total_staked >= 10_000_000_000_000_000 {  // 10,000 SOV
            StakeTier::Validator
        } else if total_staked >= 2_000_000_000_000_000 {  // 2,000 SOV
            StakeTier::DaoFounder
        } else if total_staked >= 500_000_000_000_000 {  // 500 SOV
            StakeTier::Citizenship
        } else {
            StakeTier::None
        }
    }

    /// Add stake for an identity
    pub fn add_stake(
        &mut self,
        identity_id: IdentityId,
        amount: u64,
        current_height: u64,
        lock_period: u64,
    ) -> Result<StakeTier> {
        let record = self.stakes.entry(identity_id.clone()).or_insert_with(|| {
            StakeRecord {
                identity_id: identity_id.clone(),
                total_staked: 0,
                current_tier: StakeTier::None,
                last_updated: current_height,
                stake_entries: Vec::new(),
            }
        });

        // Add the stake entry
        record.stake_entries.push(StakeEntry {
            amount,
            staked_at_height: current_height,
            lock_period,
        });

        // Update total and recalculate tier
        record.total_staked = record.total_staked.saturating_add(amount);
        record.current_tier = Self::calculate_tier(record.total_staked);
        record.last_updated = current_height;

        tracing::info!(
            "Stake added for {}: {} micro-SOV, new tier: {}",
            hex::encode(&identity_id.0[..8]),
            amount,
            record.current_tier
        );

        Ok(record.current_tier)
    }

    /// Calculate safe withdrawal amount (amount that won't cause tier downgrade)
    pub fn calculate_safe_withdrawal(&self, identity_id: &IdentityId) -> u64 {
        let Some(record) = self.stakes.get(identity_id) else {
            return 0;
        };

        let current_tier_minimum = record.current_tier.minimum_stake();

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
                    amount,
                    record.current_tier,
                    new_tier,
                    safe_amount
                ),
            })
        } else {
            None
        }
    }

    /// Withdraw stake with progressive unlocking
    /// Returns error if trying to withdraw locked stake
    pub fn withdraw_stake(
        &mut self,
        identity_id: &IdentityId,
        amount: u64,
        current_height: u64,
        force_downgrade: bool,
    ) -> Result<WithdrawalResult> {
        let record = self.stakes.get_mut(identity_id)
            .ok_or_else(|| anyhow!("No stake record found for identity"))?;

        // Check for tier downgrade warning
        let new_total = record.total_staked.saturating_sub(amount);
        let new_tier = Self::calculate_tier(new_total);
        let safe_amount = record.total_staked.saturating_sub(record.current_tier.minimum_stake());

        let warning = if new_tier < record.current_tier {
            Some(WithdrawalWarning {
                current_tier: record.current_tier,
                resulting_tier: new_tier,
                safe_withdrawal_amount: safe_amount,
                message: format!(
                    "Warning: Withdrawing {} micro-SOV will downgrade from {} to {}. \
                     Safe withdrawal: {} micro-SOV",
                    amount,
                    record.current_tier,
                    new_tier,
                    safe_amount
                ),
            })
        } else {
            None
        };

        if warning.is_some() && !force_downgrade {
            return Ok(WithdrawalResult {
                success: false,
                new_total_staked: record.total_staked,
                new_tier: record.current_tier,
                warning,
            });
        }

        // Calculate available (unlocked) stake
        let unlocked_amount: u64 = record.stake_entries.iter()
            .filter(|entry| {
                let unlock_height = entry.staked_at_height.saturating_add(entry.lock_period);
                current_height >= unlock_height
            })
            .map(|entry| entry.amount)
            .sum();

        if amount > unlocked_amount {
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

            // Check if entry is unlocked
            let unlock_height = entry.staked_at_height.saturating_add(entry.lock_period);
            if current_height < unlock_height {
                return true; // Keep locked entries
            }

            if entry.amount <= remaining_to_withdraw {
                remaining_to_withdraw -= entry.amount;
                false // Remove fully withdrawn entry
            } else {
                entry.amount -= remaining_to_withdraw;
                remaining_to_withdraw = 0;
                true // Keep partially withdrawn entry
            }
        });

        // Update totals
        record.total_staked = record.total_staked.saturating_sub(amount);
        let final_tier = Self::calculate_tier(record.total_staked);
        record.current_tier = final_tier;
        record.last_updated = current_height;

        tracing::info!(
            "Stake withdrawn for {}: {} micro-SOV, new tier: {}",
            hex::encode(&identity_id.0[..8]),
            amount,
            final_tier
        );

        Ok(WithdrawalResult {
            success: true,
            new_total_staked: record.total_staked,
            new_tier: final_tier,
            warning,
        })
    }

    /// Get current tier for an identity
    pub fn get_tier(&self, identity_id: &IdentityId) -> StakeTier {
        self.stakes
            .get(identity_id)
            .map(|r| r.current_tier)
            .unwrap_or(StakeTier::None)
    }

    /// Get total staked amount for an identity
    pub fn get_total_staked(&self, identity_id: &IdentityId) -> u64 {
        self.stakes
            .get(identity_id)
            .map(|r| r.total_staked)
            .unwrap_or(0)
    }

    /// Get full stake record for an identity
    pub fn get_stake_record(&self, identity_id: &IdentityId) -> Option<&StakeRecord> {
        self.stakes.get(identity_id)
    }
}

impl Default for UnifiedStakeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    fn test_identity() -> IdentityId {
        Hash::from_bytes(&[1u8; 32])
    }

    #[test]
    fn test_tier_calculation() {
        assert_eq!(UnifiedStakeManager::calculate_tier(0), StakeTier::None);
        assert_eq!(UnifiedStakeManager::calculate_tier(499_999_999_999_999), StakeTier::None);
        assert_eq!(UnifiedStakeManager::calculate_tier(500_000_000_000_000), StakeTier::Citizenship);
        assert_eq!(UnifiedStakeManager::calculate_tier(1_999_999_999_999_999), StakeTier::Citizenship);
        assert_eq!(UnifiedStakeManager::calculate_tier(2_000_000_000_000_000), StakeTier::DaoFounder);
        assert_eq!(UnifiedStakeManager::calculate_tier(9_999_999_999_999_999), StakeTier::DaoFounder);
        assert_eq!(UnifiedStakeManager::calculate_tier(10_000_000_000_000_000), StakeTier::Validator);
    }

    #[test]
    fn test_add_stake_and_tier_upgrade() {
        let mut manager = UnifiedStakeManager::new();
        let id = test_identity();

        // Add below citizenship threshold
        let tier = manager.add_stake(id.clone(), 400_000_000_000_000, 1, 0).unwrap();
        assert_eq!(tier, StakeTier::None);

        // Add more to reach citizenship
        let tier = manager.add_stake(id.clone(), 100_000_000_000_000, 2, 0).unwrap();
        assert_eq!(tier, StakeTier::Citizenship);

        // Add more to reach DaoFounder
        let tier = manager.add_stake(id.clone(), 1_500_000_000_000_000, 3, 0).unwrap();
        assert_eq!(tier, StakeTier::DaoFounder);
    }

    #[test]
    fn test_safe_withdrawal_calculation() {
        let mut manager = UnifiedStakeManager::new();
        let id = test_identity();

        // Stake 3000 SOV (DaoFounder tier, which requires 2000 SOV)
        manager.add_stake(id.clone(), 3_000_000_000_000_000, 1, 0).unwrap();

        // Safe withdrawal should be 1000 SOV
        let safe = manager.calculate_safe_withdrawal(&id);
        assert_eq!(safe, 1_000_000_000_000_000);
    }

    #[test]
    fn test_withdrawal_warning() {
        let mut manager = UnifiedStakeManager::new();
        let id = test_identity();

        // Stake exactly 2000 SOV (DaoFounder minimum)
        manager.add_stake(id.clone(), 2_000_000_000_000_000, 1, 0).unwrap();

        // Check withdrawal of any amount
        let warning = manager.check_withdrawal(&id, 1);
        assert!(warning.is_some());
        assert_eq!(warning.unwrap().resulting_tier, StakeTier::Citizenship);
    }

    #[test]
    fn test_progressive_unlocking() {
        let mut manager = UnifiedStakeManager::new();
        let id = test_identity();

        // Stake with different lock periods
        manager.add_stake(id.clone(), 500_000_000_000_000, 100, 0).unwrap();      // Unlocked
        manager.add_stake(id.clone(), 500_000_000_000_000, 100, 1000).unwrap();   // Locked until 1100

        // At height 500, only first stake is unlocked
        let result = manager.withdraw_stake(&id, 500_000_000_000_000, 500, true).unwrap();
        assert!(result.success);

        // Can't withdraw the locked stake
        let result = manager.withdraw_stake(&id, 500_000_000_000_000, 500, true);
        assert!(result.is_err());

        // After lock period, can withdraw
        let result = manager.withdraw_stake(&id, 500_000_000_000_000, 1100, true).unwrap();
        assert!(result.success);
    }
}
