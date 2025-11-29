//! Reward calculation engine for economics
//! 
//! Provides reward calculation capabilities without dependencies on lib-consensus

use std::collections::HashMap;
use crate::rewards::types::*;

/// Reward calculation engine for economics
#[derive(Debug, Clone)]
pub struct RewardCalculator {
    /// Base reward per block
    base_reward: u64,
    /// Reward multipliers for different work types
    work_multipliers: HashMap<UsefulWorkType, f64>,
    /// Historical reward data
    reward_history: Vec<RewardRound>,
}

impl RewardCalculator {
    /// Create a new reward calculator
    pub fn new() -> Self {
        let mut work_multipliers = HashMap::new();
        work_multipliers.insert(UsefulWorkType::NetworkRouting, 1.2);
        work_multipliers.insert(UsefulWorkType::DataStorage, 1.1);
        work_multipliers.insert(UsefulWorkType::Computation, 1.3);
        work_multipliers.insert(UsefulWorkType::Validation, 1.0);
        work_multipliers.insert(UsefulWorkType::BridgeOperations, 1.5);
        work_multipliers.insert(UsefulWorkType::MeshDiscovery, 1.4);
        work_multipliers.insert(UsefulWorkType::IspBypass, 1.6);
        work_multipliers.insert(UsefulWorkType::UbiDistribution, 1.1);

        Self {
            base_reward: 100 * 1_000_000, // 100 ZHTP base reward
            work_multipliers,
            reward_history: Vec::new(),
        }
    }

    /// Calculate reward for useful work
    pub fn calculate_work_reward(&self, work_type: UsefulWorkType, work_amount: u64) -> u64 {
        let multiplier = self.work_multipliers.get(&work_type).unwrap_or(&1.0);
        (work_amount as f64 * multiplier * 10.0) as u64 // 10 SOV per unit of work
    }

    /// Calculate reward for a simple reward structure
    pub fn calculate_simple_reward(&self, base_amount: u64, work_bonus: u64) -> ValidatorReward {
        let work_breakdown = HashMap::new();
        ValidatorReward {
            validator: [0u8; 32], // Will be filled by caller
            base_reward: base_amount,
            work_bonus,
            participation_bonus: 0,
            total_reward: base_amount + work_bonus,
            work_breakdown,
        }
    }

    /// Calculate work bonus based on useful work performed
    pub fn calculate_work_bonus(&self, work_breakdown: &HashMap<UsefulWorkType, u64>) -> u64 {
        let mut total_bonus = 0u64;

        for (work_type, amount) in work_breakdown {
            if let Some(multiplier) = self.work_multipliers.get(work_type) {
                let bonus = (*amount as f64 * multiplier * 10.0) as u64; // 10 SOV per unit
                total_bonus += bonus;
            }
        }

        total_bonus
    }

    /// Get reward statistics
    pub fn get_reward_stats(&self) -> RewardStatistics {
        let total_rounds = self.reward_history.len();
        let total_rewards: u64 = self.reward_history.iter().map(|r| r.total_rewards).sum();
        let average_per_round = if total_rounds > 0 { total_rewards / total_rounds as u64 } else { 0 };

        RewardStatistics {
            total_rounds: total_rounds as u64,
            total_rewards_distributed: total_rewards,
            average_rewards_per_round: average_per_round,
            current_base_reward: self.base_reward,
        }
    }

    /// Update reward multipliers
    pub fn update_work_multiplier(&mut self, work_type: UsefulWorkType, multiplier: f64) {
        tracing::info!("Updated reward multiplier for {:?}: {}", work_type, multiplier);
        self.work_multipliers.insert(work_type, multiplier);
    }

    /// Adjust base reward
    pub fn adjust_base_reward(&mut self, new_base_reward: u64) {
        let old_reward = self.base_reward;
        self.base_reward = new_base_reward;
        tracing::info!("Base reward adjusted: {} -> {} ZHTP", old_reward, new_base_reward);
    }

    /// Get current base reward
    pub fn get_base_reward(&self) -> u64 {
        self.base_reward
    }

    /// Get work multiplier for a specific work type
    pub fn get_work_multiplier(&self, work_type: &UsefulWorkType) -> f64 {
        self.work_multipliers.get(work_type).copied().unwrap_or(1.0)
    }
}

impl Default for RewardCalculator {
    fn default() -> Self {
        Self::new()
    }
}
