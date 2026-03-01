//! Token reward calculation and distribution
//! 
//! Calculates rewards for network services based on infrastructure economics,
//! similar to how ISPs and CDNs compensate for bandwidth and storage.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::{WorkMetrics, IspBypassWork, WorkMetricsExt};
use crate::models::EconomicModel;

/// Token reward for infrastructure services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReward {
    /// Reward for routing work
    pub routing_reward: u64,
    /// Reward for storage work
    pub storage_reward: u64,
    /// Reward for computational work
    pub compute_reward: u64,
    /// Bonus for exceptional quality
    pub quality_bonus: u64,
    /// Bonus for high uptime
    pub uptime_bonus: u64,
    /// Total reward amount
    pub total_reward: u64,
    /// Currency type (always SOV)
    pub currency: String,
}

impl Default for TokenReward {
    fn default() -> Self {
        Self {
            routing_reward: 0,
            storage_reward: 0,
            compute_reward: 0,
            quality_bonus: 0,
            uptime_bonus: 0,
            total_reward: 0,
            currency: "SOV".to_string(),
        }
    }
}

impl TokenReward {
    /// Calculate comprehensive token rewards based on useful work
    pub fn calculate(work: &WorkMetrics, model: &EconomicModel) -> Result<Self> {
        // INTERNET INFRASTRUCTURE REWARDS (like ISP/CDN revenue sharing)
        // Routing: 1 SOV per MB of data routed (actual bandwidth costs)
        let routing_reward = (work.routing_work / 1_000_000).saturating_mul(model.base_routing_rate); // bytes to MB
        
        // Storage: 10 SOV per GB stored per month (cloud storage pricing model)
        let storage_reward = (work.storage_work / 1_000_000_000).saturating_mul(model.base_storage_rate); // bytes to GB
        
        // Compute: Minimal processing fee for consensus validation
        let compute_reward = work.compute_work.saturating_mul(model.base_compute_rate);
        
        // MINIMAL BONUSES (infrastructure is expected to be reliable)
        let quality_bonus = if work.qualifies_for_quality_bonus() {
            let base_reward = routing_reward.saturating_add(storage_reward).saturating_add(compute_reward);
            ((base_reward as f64) * model.quality_multiplier) as u64
        } else {
            0 // No bonus unless exceptional
        };
        
        let uptime_bonus = if work.qualifies_for_uptime_bonus() {
            let base_reward = routing_reward.saturating_add(storage_reward).saturating_add(compute_reward);
            ((base_reward as f64) * model.uptime_multiplier) as u64
        } else {
            0 // No bonus unless near-perfect uptime
        };
        
        let total_reward = routing_reward.saturating_add(storage_reward)
            .saturating_add(compute_reward)
            .saturating_add(quality_bonus)
            .saturating_add(uptime_bonus);
        
        // Ensure minimum reward floor for network participation
        let final_total = if total_reward == 0 { 1 } else { total_reward };

        Ok(TokenReward {
            routing_reward,
            storage_reward,
            compute_reward,
            quality_bonus,
            uptime_bonus,
            total_reward: final_total,
            currency: "SOV".to_string(),
        })
    }

    /// Enable calculation adjustment (for parameter optimization)
    pub fn adjust_calculation(&mut self) -> Result<()> {
        // Recalculate total from components
        self.total_reward = self.routing_reward + self.storage_reward + self.compute_reward 
            + self.quality_bonus + self.uptime_bonus;
        
        // MINIMUM REWARD FLOOR for network security
        if self.total_reward < 1 {
            self.total_reward = 1; // Always some minimal reward
            self.routing_reward = 1; // Ensure at least routing reward
        }
        
        Ok(())
    }
    
    /// Calculate  specific rewards
    pub fn calculate_isp_bypass(work: &IspBypassWork) -> Result<Self> {
        //  REWARDS - replacing traditional ISP revenue
        let bandwidth_reward = work.bandwidth_shared_gb.saturating_mul(crate::ISP_BYPASS_CONNECTIVITY_RATE);
        let routing_reward = work.packets_routed_mb.saturating_mul(crate::ISP_BYPASS_MESH_RATE);
        let uptime_bonus = work.uptime_hours.saturating_mul(crate::ISP_BYPASS_UPTIME_BONUS);
        
        // Quality multiplier for high-quality connections
        let base_total = bandwidth_reward.saturating_add(routing_reward).saturating_add(uptime_bonus);
        let quality_bonus = if work.connection_quality > 0.9 {
            ((base_total as f64) * 0.5) as u64 // 50% bonus for excellent quality
        } else {
            0
        };
        
        let total_reward = base_total.saturating_add(quality_bonus);
        
        Ok(TokenReward {
            routing_reward,
            storage_reward: 0, // Not applicable for 
            compute_reward: 0, // Not applicable for 
            quality_bonus,
            uptime_bonus,
            total_reward,
            currency: "SOV".to_string(),
        })
    }
    
    /// Combine multiple reward sources
    pub fn combine(&mut self, other: &TokenReward) {
        self.routing_reward = self.routing_reward.saturating_add(other.routing_reward);
        self.storage_reward = self.storage_reward.saturating_add(other.storage_reward);
        self.compute_reward = self.compute_reward.saturating_add(other.compute_reward);
        self.quality_bonus = self.quality_bonus.saturating_add(other.quality_bonus);
        self.uptime_bonus = self.uptime_bonus.saturating_add(other.uptime_bonus);
        self.total_reward = self.total_reward.saturating_add(other.total_reward);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WorkMetrics;
    use crate::models::EconomicModel;

    #[test]
    fn test_token_reward_calculation() {
        let model = EconomicModel::new();
        let mut work = WorkMetrics::new();
        work.add_routing_work(1_000_000); // 1MB
        work.add_storage_work(1_000_000_000); // 1GB
        work.add_compute_work(100);
        work.update_quality_score(0.96); // Above 0.95 threshold

        let reward = TokenReward::calculate(&work, &model).unwrap();
        assert!(reward.routing_reward > 0);
        assert!(reward.storage_reward > 0);
        assert!(reward.compute_reward > 0);
        assert!(reward.quality_bonus > 0); // Should qualify for quality bonus
        assert_eq!(reward.total_reward, 
                   reward.routing_reward + reward.storage_reward + reward.compute_reward + 
                   reward.quality_bonus + reward.uptime_bonus);
    }

    #[test]
    fn test_zero_work_minimum_reward() {
        let model = EconomicModel::new();
        let work = WorkMetrics::new();

        let reward = TokenReward::calculate(&work, &model).unwrap();
        assert_eq!(reward.routing_reward, 0);
        assert_eq!(reward.storage_reward, 0);
        assert_eq!(reward.compute_reward, 0);
        assert_eq!(reward.quality_bonus, 0);
        assert_eq!(reward.uptime_bonus, 0);
        assert_eq!(reward.total_reward, 1); // Minimum floor
    }

    #[test]
    fn test_reward_combination() {
        let mut reward1 = TokenReward {
            routing_reward: 100,
            storage_reward: 200,
            compute_reward: 50,
            quality_bonus: 30,
            uptime_bonus: 20,
            total_reward: 400,
            currency: "SOV".to_string(),
        };

        let reward2 = TokenReward {
            routing_reward: 150,
            storage_reward: 100,
            compute_reward: 25,
            quality_bonus: 10,
            uptime_bonus: 15,
            total_reward: 300,
            currency: "SOV".to_string(),
        };

        reward1.combine(&reward2);

        assert_eq!(reward1.routing_reward, 250);
        assert_eq!(reward1.storage_reward, 300);
        assert_eq!(reward1.compute_reward, 75);
        assert_eq!(reward1.quality_bonus, 40);
        assert_eq!(reward1.uptime_bonus, 35);
        assert_eq!(reward1.total_reward, 700);
    }
}
