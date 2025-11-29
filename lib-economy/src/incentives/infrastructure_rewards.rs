//! Infrastructure-based reward calculation for ISP replacement economics
//! 
//! Implements the core economic model that rewards infrastructure providers
//! with token payments similar to how ISPs and CDNs generate revenue.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::{WorkMetrics, IspBypassWork};
use crate::models::EconomicModel;
use crate::wasm::logging::info;

/// Infrastructure reward categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureRewards {
    /// Routing rewards (like ISP bandwidth revenue)
    pub routing_rewards: u64,
    /// Storage rewards (like CDN/cloud storage revenue)
    pub storage_rewards: u64,
    /// Compute rewards (like processing/validation fees)
    pub compute_rewards: u64,
    /// Total infrastructure rewards
    pub total_infrastructure_rewards: u64,
}

impl InfrastructureRewards {
    /// Calculate infrastructure rewards based on work performed
    pub fn calculate(work: &WorkMetrics, model: &EconomicModel) -> Result<Self> {
        // INTERNET INFRASTRUCTURE REWARDS (like ISP/CDN revenue sharing)
        // Routing: 1 SOV per MB of data routed (actual bandwidth costs)
        let routing_rewards = (work.routing_work / 1_000_000) * model.base_routing_rate; // bytes to MB
        
        // Storage: 10 SOV per GB stored per month (cloud storage pricing model)
        let storage_rewards = (work.storage_work / 1_000_000_000) * model.base_storage_rate; // bytes to GB
        
        // Compute: Minimal processing fee for consensus validation
        let compute_rewards = work.compute_work * model.base_compute_rate;
        
        let total_infrastructure_rewards = routing_rewards + storage_rewards + compute_rewards;
        
        info!(
            "Infrastructure rewards calculated: routing={} ZHTP, storage={} ZHTP, compute={} ZHTP, total={} ZHTP",
            routing_rewards, storage_rewards, compute_rewards, total_infrastructure_rewards
        );
        
        Ok(InfrastructureRewards {
            routing_rewards,
            storage_rewards,
            compute_rewards,
            total_infrastructure_rewards,
        })
    }
    
    /// Calculate  specific infrastructure rewards
    pub fn calculate_isp_bypass(work: &IspBypassWork) -> Result<Self> {
        //  INFRASTRUCTURE REWARDS - replacing traditional ISP revenue
        
        // Bandwidth sharing reward: 100 SOV per GB shared (like ISP revenue per customer)
        let bandwidth_reward = work.bandwidth_shared_gb * crate::ISP_BYPASS_CONNECTIVITY_RATE;
        
        // Packet routing reward: 1 SOV per MB routed (like peering fees)
        let routing_reward = work.packets_routed_mb * crate::ISP_BYPASS_MESH_RATE;
        
        // Uptime bonus: 10 SOV per hour of connectivity provided
        let uptime_reward = work.uptime_hours * crate::ISP_BYPASS_UPTIME_BONUS;
        
        // Quality multiplier for high-quality connections (like premium ISP tiers)
        let base_total = bandwidth_reward + routing_reward + uptime_reward;
        let quality_multiplier = if work.connection_quality > 0.9 {
            1.5 // 50% bonus for excellent connection quality
        } else if work.connection_quality > 0.8 {
            1.2 // 20% bonus for good connection quality
        } else {
            1.0 // No bonus for basic quality
        };
        
        let total_with_quality = ((base_total as f64) * quality_multiplier) as u64;
        
        info!(
            " rewards: bandwidth={}GB ({}ZHTP), routing={}MB ({}ZHTP), uptime={}h ({}ZHTP), quality={:.1}x, total={} ZHTP",
            work.bandwidth_shared_gb, bandwidth_reward,
            work.packets_routed_mb, routing_reward,
            work.uptime_hours, uptime_reward,
            quality_multiplier, total_with_quality
        );
        
        Ok(InfrastructureRewards {
            routing_rewards: routing_reward,
            storage_rewards: 0, // Not applicable for 
            compute_rewards: 0, // Not applicable for 
            total_infrastructure_rewards: total_with_quality,
        })
    }
    
    /// Apply infrastructure scaling adjustments
    pub fn apply_infrastructure_scaling(&mut self, network_load_factor: f64) -> Result<()> {
        // INFRASTRUCTURE SCALING (like ISP capacity planning)
        // Higher network load = higher rewards to incentivize more infrastructure
        
        let scaling_multiplier = if network_load_factor > 0.9 {
            1.1 // +10% for high network load
        } else if network_load_factor > 0.7 {
            1.05 // +5% for medium-high load
        } else if network_load_factor < 0.3 {
            0.95 // -5% for low load (slight optimization)
        } else {
            1.0 // No adjustment for normal load
        };
        
        self.routing_rewards = ((self.routing_rewards as f64) * scaling_multiplier) as u64;
        self.storage_rewards = ((self.storage_rewards as f64) * scaling_multiplier) as u64;
        self.compute_rewards = ((self.compute_rewards as f64) * scaling_multiplier) as u64;
        self.total_infrastructure_rewards = self.routing_rewards + self.storage_rewards + self.compute_rewards;
        
        if scaling_multiplier != 1.0 {
            info!(
                "Applied infrastructure scaling: {:.1}x multiplier due to network load {:.1}%",
                scaling_multiplier, network_load_factor * 100.0
            );
        }
        
        Ok(())
    }
    
    /// Get detailed infrastructure reward breakdown
    pub fn get_breakdown(&self) -> serde_json::Value {
        serde_json::json!({
            "routing_rewards": self.routing_rewards,
            "routing_percentage": if self.total_infrastructure_rewards > 0 {
                (self.routing_rewards as f64 / self.total_infrastructure_rewards as f64) * 100.0
            } else { 0.0 },
            "storage_rewards": self.storage_rewards,
            "storage_percentage": if self.total_infrastructure_rewards > 0 {
                (self.storage_rewards as f64 / self.total_infrastructure_rewards as f64) * 100.0
            } else { 0.0 },
            "compute_rewards": self.compute_rewards,
            "compute_percentage": if self.total_infrastructure_rewards > 0 {
                (self.compute_rewards as f64 / self.total_infrastructure_rewards as f64) * 100.0
            } else { 0.0 },
            "total_infrastructure_rewards": self.total_infrastructure_rewards,
            "reward_sources": {
                "routing": "Bandwidth routing (like ISP revenue)",
                "storage": "Data storage (like CDN revenue)",
                "compute": "Processing/validation (like service fees)"
            }
        })
    }
}
