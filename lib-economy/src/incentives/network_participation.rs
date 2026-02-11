//! Network participation rewards for bandwidth sharing and mesh networking
//! 
//! Implements rewards for active network participation including mesh networking,
//! bandwidth sharing, and connectivity provision similar to ISP revenue models.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::IspBypassWork;
use crate::wasm::logging::info;

/// Network participation reward structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParticipationRewards {
    /// Bandwidth sharing rewards
    pub bandwidth_sharing_rewards: u64,
    /// Mesh networking rewards
    pub mesh_networking_rewards: u64,
    /// Connectivity provision rewards
    pub connectivity_provision_rewards: u64,
    /// Anti-Sybil detection bonuses
    pub anti_sybil_bonuses: u64,
    /// Total participation rewards
    pub total_participation_rewards: u64,
}

impl NetworkParticipationRewards {
    /// Calculate network participation rewards
    pub fn calculate(work: &IspBypassWork, peers_connected: u32) -> Result<Self> {
        // BANDWIDTH SHARING REWARDS (like ISP revenue per customer)
        let bandwidth_sharing_rewards = work.bandwidth_shared_gb * crate::ISP_BYPASS_CONNECTIVITY_RATE;
        
        // MESH NETWORKING REWARDS (fixed reward for maintaining mesh connectivity)
        // Anti-Sybil design: not per-peer to avoid gaming, fixed for maintaining mesh
        let mesh_networking_rewards = if peers_connected >= crate::MESH_CONNECTIVITY_THRESHOLD {
            crate::ISP_BYPASS_UPTIME_BONUS // 10 SOV per hour for maintaining mesh connectivity
        } else {
            0 // No reward for insufficient connectivity
        };
        
        // CONNECTIVITY PROVISION REWARDS (like ISP infrastructure payments)
        let connectivity_provision_rewards = work.uptime_hours * crate::ISP_BYPASS_UPTIME_BONUS;
        
        // ANTI-SYBIL BONUSES (reward infrastructure, not fake nodes)
        let anti_sybil_bonuses = if work.users_served > 5 && work.connection_quality > 0.8 {
            // Bonus for serving users with good quality (anti-Sybil)
            work.users_served * 5 // 5 SOV per user served
        } else {
            0
        };
        
        let total_participation_rewards = bandwidth_sharing_rewards + 
                                        mesh_networking_rewards + 
                                        connectivity_provision_rewards + 
                                        anti_sybil_bonuses;
        
        info!(
            "Network participation rewards: bandwidth={}SOV, mesh={}SOV, connectivity={}SOV, anti-sybil={}SOV, total={}SOV",
            bandwidth_sharing_rewards, mesh_networking_rewards, connectivity_provision_rewards, anti_sybil_bonuses, total_participation_rewards
        );
        
        Ok(NetworkParticipationRewards {
            bandwidth_sharing_rewards,
            mesh_networking_rewards,
            connectivity_provision_rewards,
            anti_sybil_bonuses,
            total_participation_rewards,
        })
    }
    
    /// Calculate mesh discovery and maintenance rewards
    pub fn calculate_mesh_maintenance(peers_connected: u32, mesh_uptime_hours: u64) -> Result<u64> {
        // INFRASTRUCTURE MAINTENANCE MODEL
        // Like network maintenance contracts or ISP infrastructure payments
        
        // Fixed reward for maintaining network connectivity (not per-peer to avoid Sybil)
        let base_reward = if peers_connected >= crate::MESH_CONNECTIVITY_THRESHOLD {
            crate::ISP_BYPASS_UPTIME_BONUS // 10 SOV per hour for maintaining mesh connectivity
        } else {
            0 // No reward for insufficient connectivity
        };
        
        // Uptime multiplier for consistent service
        let uptime_multiplier = if mesh_uptime_hours >= 23 { // 95%+ mesh uptime
            2 // Double rewards for excellent mesh maintenance
        } else if mesh_uptime_hours >= 20 { // 83%+ mesh uptime
            1 // Standard rewards for good mesh maintenance
        } else {
            0 // No rewards for poor mesh maintenance
        };
        
        let total_reward = base_reward * uptime_multiplier;
        
        if total_reward > 0 {
            info!(
                "Mesh maintenance reward: {} peers, {} hours uptime = {} SOV",
                peers_connected, mesh_uptime_hours, total_reward
            );
        }
        
        Ok(total_reward)
    }
    
    /// Calculate  routing rewards with hop bonuses
    pub fn calculate_bypass_routing(bytes_routed: u64, hops: u32) -> Result<u64> {
        // INTERNET INFRASTRUCTURE PRICING MODEL
        // Like ISP peering agreements or CDN revenue sharing
        
        // 1 SOV per MB routed (standard bandwidth pricing)
        let base_reward = bytes_routed / 1_000_000; // bytes to MB
        
        // Minimal hop bonus (like transit costs in ISP networks)
        let hop_bonus = (hops as u64).saturating_sub(1) * 1; // 1 extra token per additional hop
        
        let total_reward = base_reward + hop_bonus;
        
        if total_reward > 0 {
            info!(
                " routing reward: {} MB through {} hops = {} SOV",
                bytes_routed / 1_000_000, hops, total_reward
            );
        }
        
        Ok(total_reward)
    }
    
    /// Check if participation qualifies for anti-Sybil bonuses
    pub fn qualifies_for_anti_sybil_bonus(work: &IspBypassWork) -> bool {
        // infrastructure indicators (anti-Sybil detection)
        work.users_served > 3 &&                    // Serving users
        work.connection_quality > 0.8 &&            // Good connection quality
        work.bandwidth_shared_gb > 10 &&            // Significant bandwidth contribution
        work.uptime_hours > 12                      // Reasonable uptime commitment
    }
    
    /// Get participation tier based on contribution level
    pub fn get_participation_tier(&self) -> &'static str {
        if self.total_participation_rewards >= 1000 {
            "Major Infrastructure Provider"
        } else if self.total_participation_rewards >= 500 {
            "Infrastructure Provider"
        } else if self.total_participation_rewards >= 100 {
            "Active Participant"
        } else if self.total_participation_rewards >= 10 {
            "Contributor"
        } else {
            "Basic Participant"
        }
    }
    
    /// Get detailed participation breakdown
    pub fn get_breakdown(&self) -> serde_json::Value {
        serde_json::json!({
            "bandwidth_sharing_rewards": self.bandwidth_sharing_rewards,
            "mesh_networking_rewards": self.mesh_networking_rewards,
            "connectivity_provision_rewards": self.connectivity_provision_rewards,
            "anti_sybil_bonuses": self.anti_sybil_bonuses,
            "total_participation_rewards": self.total_participation_rewards,
            "participation_tier": self.get_participation_tier(),
            "reward_sources": {
                "bandwidth_sharing": "ISP-style revenue for bandwidth sharing",
                "mesh_networking": "Infrastructure maintenance payments",
                "connectivity_provision": "Uptime-based connectivity rewards",
                "anti_sybil": "Bonuses for serving users"
            }
        })
    }
}
