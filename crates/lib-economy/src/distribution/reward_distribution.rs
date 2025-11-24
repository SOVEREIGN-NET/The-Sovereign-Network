//! Reward distribution system for network participants
//! 
//! Manages distribution of rewards to infrastructure providers, validators,
//! and other network participants based on their contributions.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::models::TokenReward;
use crate::types::{WorkMetrics, IspBypassWork};
use crate::wallets::WalletBalance;
use crate::wasm::logging::info;
use std::collections::HashMap;

/// Reward distribution engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    /// Total rewards distributed
    pub total_rewards_distributed: u64,
    /// Rewards distributed by category
    pub rewards_by_category: HashMap<String, u64>,
    /// Number of participants rewarded
    pub participants_rewarded: u64,
    /// Last distribution timestamp
    pub last_distribution: u64,
}

impl RewardDistribution {
    /// Create new reward distribution system
    pub fn new() -> Self {
        RewardDistribution {
            total_rewards_distributed: 0,
            rewards_by_category: HashMap::new(),
            participants_rewarded: 0,
            last_distribution: 0,
        }
    }
    
    /// Distribute infrastructure rewards to participants
    pub fn distribute_infrastructure_rewards(
        &mut self,
        participants: &mut [(&mut WalletBalance, &WorkMetrics)],
        reward_pool: u64,
    ) -> Result<()> {
        if participants.is_empty() || reward_pool == 0 {
            return Ok(());
        }
        
        let total_work = participants.iter()
            .map(|(_, metrics)| metrics.routing_work + metrics.storage_work + metrics.compute_work)
            .sum::<u64>();
            
        if total_work == 0 {
            return Ok(());
        }
        
        let mut distributed_total = 0u64;
        
        for (wallet, metrics) in participants.iter_mut() {
            let participant_work = metrics.routing_work + metrics.storage_work + metrics.compute_work;
            let reward_share = (participant_work * reward_pool) / total_work;
            
            if reward_share > 0 {
                let reward = TokenReward {
                    routing_reward: (metrics.routing_work * reward_share) / participant_work,
                    storage_reward: (metrics.storage_work * reward_share) / participant_work,
                    compute_reward: (metrics.compute_work * reward_share) / participant_work,
                    quality_bonus: if metrics.qualifies_for_quality_bonus() { reward_share / 20 } else { 0 },
                    uptime_bonus: if metrics.qualifies_for_uptime_bonus() { reward_share / 10 } else { 0 },
                    total_reward: reward_share,
                    currency: "SOV".to_string(),
                };
                
                wallet.add_reward(&reward)?;
                distributed_total += reward_share;
                
                info!(
                    "Distributed {} ZHTP infrastructure reward to participant",
                    reward_share
                );
            }
        }
        
        self.total_rewards_distributed += distributed_total;
        *self.rewards_by_category.entry("infrastructure".to_string()).or_insert(0) += distributed_total;
        self.participants_rewarded += participants.len() as u64;
        self.last_distribution = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        
        info!(
            "🏭 Distributed {} ZHTP total infrastructure rewards to {} participants",
            distributed_total, participants.len()
        );
        
        Ok(())
    }
    
    /// Distribute  rewards
    pub fn distribute_isp_bypass_rewards(
        &mut self,
        participants: &mut [(&mut WalletBalance, &IspBypassWork)],
        reward_pool: u64,
    ) -> Result<()> {
        if participants.is_empty() || reward_pool == 0 {
            return Ok(());
        }
        
        let total_isp_work = participants.iter()
            .map(|(_, work)| work.total_isp_bypass_value())
            .sum::<u64>();
            
        if total_isp_work == 0 {
            return Ok(());
        }
        
        let mut distributed_total = 0u64;
        
        for (wallet, work) in participants.iter_mut() {
            let participant_value = work.total_isp_bypass_value();
            let reward_share = (participant_value * reward_pool) / total_isp_work;
            
            if reward_share > 0 {
                let reward = TokenReward {
                    routing_reward: (work.packets_routed_mb * reward_share) / participant_value,
                    storage_reward: 0, //  doesn't include storage
                    compute_reward: 0, //  doesn't include compute
                    quality_bonus: if work.connection_quality > 0.9 { reward_share / 10 } else { 0 },
                    uptime_bonus: (work.uptime_hours * reward_share) / participant_value,
                    total_reward: reward_share,
                    currency: "SOV".to_string(),
                };
                
                wallet.add_reward(&reward)?;
                distributed_total += reward_share;
                
                info!(
                    "Distributed {} ZHTP  reward to participant",
                    reward_share
                );
            }
        }
        
        self.total_rewards_distributed += distributed_total;
        *self.rewards_by_category.entry("isp_bypass".to_string()).or_insert(0) += distributed_total;
        self.participants_rewarded += participants.len() as u64;
        self.last_distribution = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        
        info!(
            "Distributed {} ZHTP total  rewards to {} participants",
            distributed_total, participants.len()
        );
        
        Ok(())
    }
    
    /// Distribute validation rewards (for consensus participants)
    pub fn distribute_validation_rewards(
        &mut self,
        validators: &mut [&mut WalletBalance],
        reward_pool: u64,
    ) -> Result<()> {
        if validators.is_empty() || reward_pool == 0 {
            return Ok(());
        }
        
        let reward_per_validator = reward_pool / validators.len() as u64;
        let mut distributed_total = 0u64;
        
        for validator in validators.iter_mut() {
            if reward_per_validator > 0 {
                let reward = TokenReward {
                    routing_reward: 0,
                    storage_reward: 0,
                    compute_reward: reward_per_validator,
                    quality_bonus: 0,
                    uptime_bonus: 0,
                    total_reward: reward_per_validator,
                    currency: "SOV".to_string(),
                };
                
                validator.add_reward(&reward)?;
                distributed_total += reward_per_validator;
                
                info!(
                    " Distributed {} ZHTP validation reward to validator",
                    reward_per_validator
                );
            }
        }
        
        self.total_rewards_distributed += distributed_total;
        *self.rewards_by_category.entry("validation".to_string()).or_insert(0) += distributed_total;
        self.participants_rewarded += validators.len() as u64;
        self.last_distribution = crate::wasm::compatibility::current_timestamp().unwrap_or(0);
        
        info!(
            " Distributed {} ZHTP total validation rewards to {} validators",
            distributed_total, validators.len()
        );
        
        Ok(())
    }
    
    /// Get distribution statistics
    pub fn get_distribution_stats(&self) -> serde_json::Value {
        let avg_reward_per_participant = if self.participants_rewarded > 0 {
            self.total_rewards_distributed / self.participants_rewarded
        } else {
            0
        };
        
        serde_json::json!({
            "total_rewards_distributed": self.total_rewards_distributed,
            "participants_rewarded": self.participants_rewarded,
            "avg_reward_per_participant": avg_reward_per_participant,
            "rewards_by_category": self.rewards_by_category,
            "last_distribution": self.last_distribution,
            "distribution_categories": self.rewards_by_category.len()
        })
    }
    
    /// Reset distribution statistics (for testing or new periods)
    pub fn reset_stats(&mut self) {
        self.total_rewards_distributed = 0;
        self.rewards_by_category.clear();
        self.participants_rewarded = 0;
        self.last_distribution = 0;
    }
}

/// Distribute rewards to network participants
pub fn distribute_rewards(
    infrastructure_participants: &mut [(&mut WalletBalance, &WorkMetrics)],
    isp_bypass_participants: &mut [(&mut WalletBalance, &IspBypassWork)],
    validators: &mut [&mut WalletBalance],
    total_reward_pool: u64,
) -> Result<()> {
    let mut distribution = RewardDistribution::new();
    
    // Allocate reward pool
    let infrastructure_pool = (total_reward_pool * 60) / 100; // 60% to infrastructure
    let isp_bypass_pool = (total_reward_pool * 30) / 100;     // 30% to 
    let validation_pool = (total_reward_pool * 10) / 100;     // 10% to validation
    
    // Distribute rewards
    distribution.distribute_infrastructure_rewards(infrastructure_participants, infrastructure_pool)?;
    distribution.distribute_isp_bypass_rewards(isp_bypass_participants, isp_bypass_pool)?;
    distribution.distribute_validation_rewards(validators, validation_pool)?;
    
    let stats = distribution.get_distribution_stats();
    info!(
        "Completed reward distribution: {} ZHTP to {} participants",
        stats["total_rewards_distributed"], stats["participants_rewarded"]
    );
    
    Ok(())
}

impl Default for RewardDistribution {
    fn default() -> Self {
        Self::new()
    }
}
