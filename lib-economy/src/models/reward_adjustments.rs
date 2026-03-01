//! Reward adjustment algorithms for network optimization
//! 
//! Implements algorithms to adjust rewards based on network conditions
//! while maintaining stable infrastructure economics.

use anyhow::Result;
use crate::types::{NetworkStats, NetworkStatsExt};
use crate::models::TokenReward;
use crate::wasm::logging::info;

/// Reward adjustment configuration
#[derive(Debug, Clone)]
pub struct RewardAdjustmentConfig {
    /// Maximum adjustment percentage (e.g., 20 = 20%)
    pub max_adjustment_percent: u64,
    /// Minimum reward floor (prevents rewards from going to zero)
    pub min_reward_floor: u64,
    /// Enable dynamic adjustments
    pub enable_dynamic_adjustments: bool,
}

impl RewardAdjustmentConfig {
    /// Create default configuration
    pub fn new() -> Self {
        RewardAdjustmentConfig {
            max_adjustment_percent: 20, // Max 20% adjustment
            min_reward_floor: 1,        // Always at least 1 token reward
            enable_dynamic_adjustments: true,
        }
    }
    
    /// Conservative configuration for stable infrastructure economics
    pub fn conservative() -> Self {
        RewardAdjustmentConfig {
            max_adjustment_percent: 10, // Max 10% adjustment
            min_reward_floor: 1,
            enable_dynamic_adjustments: true,
        }
    }
}

/// Apply network condition adjustments to rewards
pub fn adjust_rewards_for_network_conditions(
    base_reward: &mut TokenReward,
    network_stats: &NetworkStats,
    config: &RewardAdjustmentConfig,
) -> Result<()> {
    if !config.enable_dynamic_adjustments {
        return Ok(());
    }
    
    let adjustment_multiplier = network_stats.get_reward_adjustment_multiplier();
    
    // Apply adjustment with limits
    let capped_multiplier = if adjustment_multiplier > 100 {
        // Increase rewards (high utilization)
        let increase = adjustment_multiplier - 100;
        let capped_increase = increase.min(config.max_adjustment_percent);
        100 + capped_increase
    } else {
        // Decrease rewards (low utilization)
        let decrease = 100 - adjustment_multiplier;
        let capped_decrease = decrease.min(config.max_adjustment_percent);
        100 - capped_decrease
    };
    
    // Apply adjustment to all reward components
    base_reward.routing_reward = (base_reward.routing_reward * capped_multiplier) / 100;
    base_reward.storage_reward = (base_reward.storage_reward * capped_multiplier) / 100;
    base_reward.compute_reward = (base_reward.compute_reward * capped_multiplier) / 100;
    
    // Recalculate total
    let base_total = base_reward.routing_reward + base_reward.storage_reward + base_reward.compute_reward;
    base_reward.total_reward = base_total + base_reward.quality_bonus + base_reward.uptime_bonus;
    
    // Apply minimum floor
    if base_reward.total_reward < config.min_reward_floor {
        base_reward.total_reward = config.min_reward_floor;
        base_reward.routing_reward = config.min_reward_floor;
    }
    
    if capped_multiplier != 100 {
        info!(
            "Applied {}% reward adjustment based on network conditions",
            capped_multiplier
        );
    }
    
    Ok(())
}

/// Apply quality-based reward adjustments
pub fn adjust_rewards_for_quality(
    base_reward: &mut TokenReward,
    quality_score: f64,
    config: &RewardAdjustmentConfig,
) -> Result<()> {
    if !config.enable_dynamic_adjustments {
        return Ok(());
    }
    
    // Quality-based adjustments (more conservative than network adjustments)
    let quality_multiplier = if quality_score > 0.95 {
        110 // +10% for excellent quality
    } else if quality_score < 0.80 {
        90  // -10% for poor quality
    } else {
        100 // No adjustment for adequate quality
    };
    
    // Apply quality adjustment to quality bonus only
    base_reward.quality_bonus = (base_reward.quality_bonus * quality_multiplier) / 100;
    
    // Recalculate total
    let base_total = base_reward.routing_reward + base_reward.storage_reward + base_reward.compute_reward;
    base_reward.total_reward = base_total + base_reward.quality_bonus + base_reward.uptime_bonus;
    
    // Ensure minimum floor
    if base_reward.total_reward < config.min_reward_floor {
        base_reward.total_reward = config.min_reward_floor;
    }
    
    Ok(())
}

/// Apply time-based reward adjustments (e.g., for peak/off-peak periods)
pub fn adjust_rewards_for_time_period(
    base_reward: &mut TokenReward,
    is_peak_period: bool,
    config: &RewardAdjustmentConfig,
) -> Result<()> {
    if !config.enable_dynamic_adjustments {
        return Ok(());
    }
    
    let time_multiplier = if is_peak_period {
        105 // +5% during peak periods
    } else {
        95  // -5% during off-peak periods
    };
    
    // Apply time adjustment
    base_reward.routing_reward = (base_reward.routing_reward * time_multiplier) / 100;
    base_reward.storage_reward = (base_reward.storage_reward * time_multiplier) / 100;
    base_reward.compute_reward = (base_reward.compute_reward * time_multiplier) / 100;
    
    // Recalculate total
    let base_total = base_reward.routing_reward + base_reward.storage_reward + base_reward.compute_reward;
    base_reward.total_reward = base_total + base_reward.quality_bonus + base_reward.uptime_bonus;
    
    // Ensure minimum floor
    if base_reward.total_reward < config.min_reward_floor {
        base_reward.total_reward = config.min_reward_floor;
    }
    
    Ok(())
}

/// Comprehensive reward adjustment combining all factors
pub fn apply_comprehensive_adjustments(
    base_reward: &mut TokenReward,
    network_stats: &NetworkStats,
    quality_score: f64,
    is_peak_period: bool,
    config: &RewardAdjustmentConfig,
) -> Result<()> {
    // Apply adjustments in order of importance
    adjust_rewards_for_network_conditions(base_reward, network_stats, config)?;
    adjust_rewards_for_quality(base_reward, quality_score, config)?;
    adjust_rewards_for_time_period(base_reward, is_peak_period, config)?;
    
    Ok(())
}

impl Default for RewardAdjustmentConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NetworkStats;
    use crate::models::TokenReward;

    #[test]
    fn test_network_condition_adjustment() {
        let mut reward = TokenReward {
            routing_reward: 100,
            storage_reward: 200,
            compute_reward: 50,
            quality_bonus: 10,
            uptime_bonus: 5,
            total_reward: 365,
            currency: "SOV".to_string(),
        };
        
        let mut stats = NetworkStats::new();
        stats.update_utilization(0.95); // High utilization
        
        let config = RewardAdjustmentConfig::new();
        adjust_rewards_for_network_conditions(&mut reward, &stats, &config).unwrap();
        
        // Should increase rewards due to high utilization
        assert!(reward.total_reward > 365);
    }

    #[test]
    fn test_quality_adjustment() {
        let mut reward = TokenReward::default();
        reward.quality_bonus = 10;
        reward.total_reward = 100;
        
        let config = RewardAdjustmentConfig::new();
        adjust_rewards_for_quality(&mut reward, 0.98, &config).unwrap();
        
        // Should increase quality bonus for excellent quality
        assert!(reward.quality_bonus > 10);
    }

    #[test]
    fn test_minimum_floor() {
        let mut reward = TokenReward::default();
        let config = RewardAdjustmentConfig::new();
        
        let mut stats = NetworkStats::new();
        stats.update_utilization(0.1); // Very low utilization
        
        adjust_rewards_for_network_conditions(&mut reward, &stats, &config).unwrap();
        
        // Should respect minimum floor
        assert!(reward.total_reward >= config.min_reward_floor);
    }

    #[test]
    fn test_comprehensive_adjustments() {
        let mut reward = TokenReward {
            routing_reward: 100,
            storage_reward: 100,
            compute_reward: 100,
            quality_bonus: 10,
            uptime_bonus: 10,
            total_reward: 320,
            currency: "SOV".to_string(),
        };
        
        let mut stats = NetworkStats::new();
        stats.update_utilization(0.7);
        stats.update_avg_quality(0.9);
        
        let config = RewardAdjustmentConfig::new();
        apply_comprehensive_adjustments(&mut reward, &stats, 0.96, true, &config).unwrap();
        
        // Should apply multiple adjustments
        assert!(reward.total_reward != 320);
    }
}
