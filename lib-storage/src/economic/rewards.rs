//! Reward System for Storage Providers
//! 
//! Implements a comprehensive reward system for storage providers based on:
//! - Storage performance metrics
//! - Reliability and uptime
//! - Data integrity
//! - Network participation

use crate::types::{NodeId, RewardTier, RewardThreshold};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_crypto::Hash;


/// Storage reward tracker for storage providers
/// Tracks metrics and performance, delegates actual reward calculation to lib-economy
#[derive(Debug)]
pub struct StorageRewardTracker {
    /// Reward tier thresholds
    tier_thresholds: HashMap<RewardTier, RewardThreshold>,
    /// Provider performance history
    provider_performance: HashMap<NodeId, ProviderPerformance>,
    /// Reward history
    reward_history: Vec<RewardEvent>,
    /// Total rewards distributed
    total_rewards_distributed: u64,
}

/// Provider performance tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPerformance {
    /// Provider node ID
    pub node_id: NodeId,
    /// Current reputation score
    pub reputation: f64,
    /// Uptime percentage
    pub uptime: f64,
    /// Data integrity score
    pub data_integrity: f64,
    /// Response time average
    pub avg_response_time: u64,
    /// Total storage provided (bytes)
    pub total_storage_provided: u64,
    /// Contracts fulfilled
    pub contracts_fulfilled: u32,
    /// Current tier
    pub current_tier: RewardTier,
}

/// Reward event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardEvent {
    /// Event ID
    pub id: Hash,
    /// Provider node ID
    pub provider_id: NodeId,
    /// Reward amount
    pub amount: u64,
    /// Reward tier
    pub tier: RewardTier,
    /// Reason for reward
    pub reason: String,
    /// Timestamp
    pub timestamp: u64,
}

impl StorageRewardTracker {
    /// Create new storage reward tracker
    pub fn new() -> Self {
        let mut tier_thresholds = HashMap::new();

        // Basic tier - entry level
        tier_thresholds.insert(RewardTier::Basic, RewardThreshold {
            min_reputation: 0.0,
            min_uptime: 0.90,
            min_contracts: 0,
            min_storage: 0,
            min_data_integrity: 0.95,
            base_multiplier: 1.0,
            bonus_multiplier: 1.0,
        });

        // Bronze tier
        tier_thresholds.insert(RewardTier::Bronze, RewardThreshold {
            min_reputation: 0.7,
            min_uptime: 0.95,
            min_contracts: 10,
            min_storage: 1024 * 1024 * 1024, // 1GB
            min_data_integrity: 0.97,
            base_multiplier: 1.2,
            bonus_multiplier: 1.1,
        });

        // Silver tier
        tier_thresholds.insert(RewardTier::Silver, RewardThreshold {
            min_reputation: 0.8,
            min_uptime: 0.98,
            min_contracts: 50,
            min_storage: 10 * 1024 * 1024 * 1024, // 10GB
            min_data_integrity: 0.99,
            base_multiplier: 1.5,
            bonus_multiplier: 1.3,
        });

        // Gold tier
        tier_thresholds.insert(RewardTier::Gold, RewardThreshold {
            min_reputation: 0.9,
            min_uptime: 0.995,
            min_contracts: 100,
            min_storage: 100 * 1024 * 1024 * 1024, // 100GB
            min_data_integrity: 0.995,
            base_multiplier: 2.0,
            bonus_multiplier: 1.6,
        });

        // Platinum tier - highest level
        tier_thresholds.insert(RewardTier::Platinum, RewardThreshold {
            min_reputation: 0.95,
            min_uptime: 0.999,
            min_contracts: 500,
            min_storage: 1024 * 1024 * 1024 * 1024, // 1TB
            min_data_integrity: 0.999,
            base_multiplier: 3.0,
            bonus_multiplier: 2.0,
        });

        Self {
            tier_thresholds,
            provider_performance: HashMap::new(),
            reward_history: Vec::new(),
            total_rewards_distributed: 0,
        }
    }

    /// Calculate rewards for a provider
    pub fn calculate_provider_rewards(&self, provider_id: &NodeId, storage_provided: u64) -> Result<u64> {
        let performance = self.provider_performance.get(provider_id)
            .ok_or_else(|| anyhow!("Provider performance not found"))?;

        let tier = self.determine_tier(performance);
        let threshold = self.tier_thresholds.get(&tier).unwrap();

        // Base reward calculation
        let base_reward = storage_provided / 1_000_000; // 1 SOV per MB
        let tier_multiplied = (base_reward as f64 * threshold.base_multiplier) as u64;

        // Performance bonus
        let performance_score = (performance.reputation + performance.uptime + performance.data_integrity) / 3.0;
        let bonus = if performance_score > 0.95 {
            (tier_multiplied as f64 * threshold.bonus_multiplier) as u64
        } else {
            0
        };

        Ok(tier_multiplied + bonus)
    }

    /// Determine reward tier for a provider
    pub fn determine_tier(&self, performance: &ProviderPerformance) -> RewardTier {
        // Check from highest to lowest tier
        for &tier in &[RewardTier::Platinum, RewardTier::Gold, RewardTier::Silver, RewardTier::Bronze] {
            if let Some(threshold) = self.tier_thresholds.get(&tier) {
                if performance.reputation >= threshold.min_reputation
                    && performance.uptime >= threshold.min_uptime
                    && performance.data_integrity >= threshold.min_data_integrity
                {
                    return tier;
                }
            }
        }
        RewardTier::Basic
    }

    /// Update provider performance
    pub fn update_provider_performance(&mut self, performance: ProviderPerformance) {
        let tier = self.determine_tier(&performance);
        let mut updated_performance = performance;
        updated_performance.current_tier = tier;
        
        let node_id = updated_performance.node_id.clone();
        self.provider_performance.insert(node_id, updated_performance);
    }

    /// Distribute rewards to a provider
    pub fn distribute_rewards(
        &mut self,
        provider_id: NodeId,
        amount: u64,
        reason: String,
    ) -> Result<RewardEvent> {
        let performance = self.provider_performance.get(&provider_id)
            .ok_or_else(|| anyhow!("Provider not found"))?;

        let event = RewardEvent {
            id: Hash::from_bytes(&rand::random::<[u8; 32]>()),
            provider_id,
            amount,
            tier: performance.current_tier,
            reason,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.reward_history.push(event.clone());
        self.total_rewards_distributed += amount;

        Ok(event)
    }

    /// Get provider reward history
    pub fn get_provider_rewards(&self, provider_id: &NodeId) -> Vec<&RewardEvent> {
        self.reward_history
            .iter()
            .filter(|event| &event.provider_id == provider_id)
            .collect()
    }

    /// Calculate total rewards for a provider
    pub fn calculate_total_provider_rewards(&self, provider_id: &NodeId) -> u64 {
        self.reward_history
            .iter()
            .filter(|event| &event.provider_id == provider_id)
            .map(|event| event.amount)
            .sum()
    }

    /// Get tier statistics
    pub fn get_tier_statistics(&self) -> HashMap<RewardTier, TierStats> {
        let mut stats = HashMap::new();

        for tier in [RewardTier::Basic, RewardTier::Bronze, RewardTier::Silver, RewardTier::Gold, RewardTier::Platinum] {
            let providers_in_tier = self.provider_performance
                .values()
                .filter(|p| p.current_tier == tier)
                .count();

            let total_rewards = self.reward_history
                .iter()
                .filter(|event| event.tier == tier)
                .map(|event| event.amount)
                .sum();

            stats.insert(tier, TierStats {
                provider_count: providers_in_tier as u64,
                total_rewards,
                average_performance: self.calculate_tier_average_performance(tier),
            });
        }

        stats
    }

    /// Calculate average performance for a tier
    fn calculate_tier_average_performance(&self, tier: RewardTier) -> f64 {
        let providers_in_tier: Vec<_> = self.provider_performance
            .values()
            .filter(|p| p.current_tier == tier)
            .collect();

        if providers_in_tier.is_empty() {
            return 0.0;
        }

        let total_performance: f64 = providers_in_tier
            .iter()
            .map(|p| (p.reputation + p.uptime + p.data_integrity) / 3.0)
            .sum();

        total_performance / providers_in_tier.len() as f64
    }

    /// Get reward statistics
    pub fn get_reward_stats(&self) -> RewardStats {
        RewardStats {
            total_rewards_distributed: self.total_rewards_distributed,
            total_providers: self.provider_performance.len() as u64,
            average_tier_distribution: self.get_tier_statistics(),
        }
    }
}

/// Statistics for a reward tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierStats {
    /// Number of providers in this tier
    pub provider_count: u64,
    /// Total rewards distributed to this tier
    pub total_rewards: u64,
    /// Average performance score for this tier
    pub average_performance: f64,
}

/// Overall reward statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardStats {
    /// Total rewards distributed
    pub total_rewards_distributed: u64,
    /// Total number of providers
    pub total_providers: u64,
    /// Distribution across tiers
    pub average_tier_distribution: HashMap<RewardTier, TierStats>,
}

impl Default for StorageRewardTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reward_manager_creation() {
        let manager = StorageRewardTracker::new();
        assert_eq!(manager.tier_thresholds.len(), 5);
        assert_eq!(manager.provider_performance.len(), 0);
    }

    #[test]
    fn test_tier_determination() {
        let manager = StorageRewardTracker::new();
        
        let high_performance = ProviderPerformance {
            node_id: NodeId::from_bytes([1u8; 32]),
            reputation: 0.95,
            uptime: 0.999,
            data_integrity: 0.999,
            avg_response_time: 100,
            total_storage_provided: 1_000_000_000,
            contracts_fulfilled: 100,
            current_tier: RewardTier::Basic, // Will be updated
        };

        let tier = manager.determine_tier(&high_performance);
        assert_eq!(tier, RewardTier::Platinum);
    }

    #[test]
    fn test_reward_calculation() {
        let mut manager = StorageRewardTracker::new();
        let node_id = NodeId::from_bytes([1u8; 32]);

        let performance = ProviderPerformance {
            node_id: node_id.clone(),
            reputation: 0.8,
            uptime: 0.98,
            data_integrity: 0.99,
            avg_response_time: 200,
            total_storage_provided: 100_000_000,
            contracts_fulfilled: 10,
            current_tier: RewardTier::Silver,
        };

        manager.update_provider_performance(performance);
        
        let rewards = manager.calculate_provider_rewards(&node_id, 100_000_000).unwrap();
        assert!(rewards > 100); // Should have tier multiplier applied
    }
}
