//! Token reward calculation and distribution
//! 
//! Calculates rewards for network services based on infrastructure economics,
//! similar to how ISPs and CDNs compensate for bandwidth and storage.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::{WorkMetrics, IspBypassWork};
use crate::models::EconomicModel; calculation and         // Routing: 10 SOV per MB routed (covers bandwidth costs)
        let routing_reward = (work.routing_work / 1_000_000).saturating_mul(model.base_routing_rate); // bytes to MB
        
        // Storage: 10 SOV per GB stored per month (cloud storage pricing model)
        let storage_reward = (work.storage_work / 1_000_000_000).saturating_mul(model.base_storage_rate); // bytes to GB
        
        // Compute: Minimal processing fee for consensus validation
        let compute_reward = work.compute_work.saturating_mul(model.base_compute_rate);tion
//! 
//! Calculates rewards for network services based on infrastructure economics,
//! similar to how ISPs and CDNs compensate for bandwidth and storage.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::*;
use crate::models::EconomicModel;

/// Token reward structure for network services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenReward {
    /// Reward for routing packets/data
    pub routing_reward: u64,
    /// Reward for providing storage
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
    
    /// Apply economic adjustments based on network conditions
    pub fn apply_economic_adjustments(&mut self, _model: &EconomicModel) -> Result<()> {
        // NO COMPLEX ADJUSTMENTS - this is infrastructure, not speculation!
        // Rewards stay stable like internet infrastructure pricing
        
        // ONLY BASIC SUPPLY MANAGEMENT
        // No artificial scarcity - tokens are minted as needed for network operation
        // Think of it like "bandwidth credits" or "compute credits"
        
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
        let bandwidth_reward = work.bandwidth_shared_gb * crate::ISP_BYPASS_CONNECTIVITY_RATE;
        let routing_reward = work.packets_routed_mb * crate::ISP_BYPASS_MESH_RATE;
        let uptime_bonus = work.uptime_hours * crate::ISP_BYPASS_UPTIME_BONUS;
        
        // Quality multiplier for high-quality connections
        let base_total = bandwidth_reward + routing_reward + uptime_bonus;
        let quality_bonus = if work.connection_quality > 0.9 {
            ((base_total as f64) * 0.5) as u64 // 50% bonus for excellent quality
        } else {
            0
        };
        
        let total_reward = base_total + quality_bonus;
        
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
        self.routing_reward += other.routing_reward;
        self.storage_reward += other.storage_reward;
        self.compute_reward += other.compute_reward;
        self.quality_bonus += other.quality_bonus;
        self.uptime_bonus += other.uptime_bonus;
        self.total_reward += other.total_reward;
    }
    
    /// Get breakdown of rewards
    pub fn get_breakdown(&self) -> serde_json::Value {
        serde_json::json!({
            "routing_reward": self.routing_reward,
            "storage_reward": self.storage_reward,
            "compute_reward": self.compute_reward,
            "quality_bonus": self.quality_bonus,
            "uptime_bonus": self.uptime_bonus,
            "total_reward": self.total_reward,
            "currency": self.currency
        })
    }
}

impl Default for TokenReward {
    fn default() -> Self {
        TokenReward {
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
