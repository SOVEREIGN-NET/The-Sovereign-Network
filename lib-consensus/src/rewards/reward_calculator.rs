//! Reward calculation system

use crate::types::UsefulWorkType;
use crate::validators::ValidatorManager;
use anyhow::Result;
use lib_identity::IdentityId;
use std::collections::HashMap;

/// Reward calculation engine
#[derive(Debug, Clone)]
pub struct RewardCalculator {
    /// Base reward per block
    base_reward: u64,
    /// Reward multipliers for different work types
    work_multipliers: HashMap<UsefulWorkType, f64>,
    /// Historical reward data
    reward_history: Vec<RewardRound>,
}

/// Reward round information
#[derive(Debug, Clone)]
pub struct RewardRound {
    pub height: u64,
    pub total_rewards: u64,
    pub validator_rewards: HashMap<IdentityId, ValidatorReward>,
    pub timestamp: u64,
}

/// Individual validator reward
#[derive(Debug, Clone)]
pub struct ValidatorReward {
    pub validator: IdentityId,
    pub base_reward: u64,
    pub work_bonus: u64,
    pub participation_bonus: u64,
    pub total_reward: u64,
    pub work_breakdown: HashMap<UsefulWorkType, u64>,
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

        Self {
            base_reward: 100 * 1_000_000, // 100 ZHTP base reward
            work_multipliers,
            reward_history: Vec::new(),
        }
    }

    /// Calculate rewards for a consensus round
    pub fn calculate_round_rewards(
        &mut self,
        validator_manager: &ValidatorManager,
        current_height: u64,
    ) -> Result<RewardRound> {
        let active_validators = validator_manager.get_active_validators();
        let mut validator_rewards = HashMap::new();
        let mut total_rewards = 0u64;

        for validator in active_validators {
            let reward = self.calculate_validator_reward(validator)?;
            total_rewards += reward.total_reward;
            validator_rewards.insert(validator.identity.clone(), reward);
        }

        let reward_round = RewardRound {
            height: current_height,
            total_rewards,
            validator_rewards: validator_rewards.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.reward_history.push(reward_round.clone());

        // Keep only recent history
        if self.reward_history.len() > 1000 {
            self.reward_history.remove(0);
        }

        tracing::info!(
            "Calculated round rewards: {} ZHTP total to {} validators",
            total_rewards,
            validator_rewards.len()
        );

        Ok(reward_round)
    }

    /// Calculate reward for a single validator
    fn calculate_validator_reward(
        &self,
        validator: &crate::validators::Validator,
    ) -> Result<ValidatorReward> {
        // Base reward based primarily on stake (traditional validator model)
        let stake_factor = (validator.stake as f64).sqrt() / 1000.0;
        let base_reward = (self.base_reward as f64 * stake_factor) as u64;

        // Optional storage bonus (only if validator provides storage)
        let _storage_bonus = if validator.storage_provided > 0 {
            let storage_gb = validator.storage_provided as f64 / (1024.0 * 1024.0 * 1024.0);
            (base_reward as f64 * 0.1 * storage_gb.ln().max(0.0)).min(base_reward as f64 * 0.2)
                as u64
        } else {
            0
        };

        // Work bonuses (simplified - in production would use actual work proofs)
        let mut work_breakdown = HashMap::new();
        let routing_work = validator.voting_power / 10; // All validators do consensus work
        let storage_work = if validator.storage_provided > 0 {
            validator.storage_provided / (1024 * 1024 * 1024) // GB storage provided
        } else {
            0
        };
        let compute_work = validator.reputation as u64 / 10; // Based on reputation

        work_breakdown.insert(UsefulWorkType::NetworkRouting, routing_work);
        work_breakdown.insert(UsefulWorkType::DataStorage, storage_work);
        work_breakdown.insert(UsefulWorkType::Computation, compute_work);

        let work_bonus = self.calculate_work_bonus(&work_breakdown);

        // Participation bonus based on reputation
        let participation_bonus = (validator.reputation as u64 * self.base_reward) / 10000;

        let total_reward = base_reward + work_bonus + participation_bonus;

        Ok(ValidatorReward {
            validator: validator.identity.clone(),
            base_reward,
            work_bonus,
            participation_bonus,
            total_reward,
            work_breakdown,
        })
    }

    /// Calculate work bonus based on useful work performed
    fn calculate_work_bonus(&self, work_breakdown: &HashMap<UsefulWorkType, u64>) -> u64 {
        let mut total_bonus = 0u64;

        for (work_type, amount) in work_breakdown {
            if let Some(multiplier) = self.work_multipliers.get(work_type) {
                let bonus = (*amount as f64 * multiplier * 10.0) as u64; // 10 ZHTP per unit
                total_bonus += bonus;
            }
        }

        total_bonus
    }

    /// Distribute rewards to validators
    pub fn distribute_rewards(&self, reward_round: &RewardRound) -> Result<()> {
        for (validator_id, reward) in &reward_round.validator_rewards {
            // In a implementation, this would:
            // 1. Create reward transactions
            // 2. Update validator balances
            // 3. Handle delegation rewards
            // 4. Update staking pools

            tracing::info!(
                " Distributed {} ZHTP to validator {:?} (base: {}, work: {}, participation: {})",
                reward.total_reward,
                validator_id,
                reward.base_reward,
                reward.work_bonus,
                reward.participation_bonus
            );
        }

        Ok(())
    }

    /// Get reward statistics
    pub fn get_reward_stats(&self) -> RewardStatistics {
        let total_rounds = self.reward_history.len();
        let total_rewards: u64 = self.reward_history.iter().map(|r| r.total_rewards).sum();
        let average_per_round = if total_rounds > 0 {
            total_rewards / total_rounds as u64
        } else {
            0
        };

        RewardStatistics {
            total_rounds: total_rounds as u64,
            total_rewards_distributed: total_rewards,
            average_rewards_per_round: average_per_round,
            current_base_reward: self.base_reward,
        }
    }

    /// Update reward multipliers
    pub fn update_work_multiplier(&mut self, work_type: UsefulWorkType, multiplier: f64) {
        tracing::info!(
            "Updated reward multiplier for {:?}: {}",
            work_type,
            multiplier
        );
        self.work_multipliers.insert(work_type, multiplier);
    }

    /// Adjust base reward (governance decision)
    pub fn adjust_base_reward(&mut self, new_base_reward: u64) {
        let old_reward = self.base_reward;
        self.base_reward = new_base_reward;
        tracing::info!(
            "Base reward adjusted: {} -> {} ZHTP",
            old_reward,
            new_base_reward
        );
    }
}

/// Reward system statistics
#[derive(Debug, Clone)]
pub struct RewardStatistics {
    pub total_rounds: u64,
    pub total_rewards_distributed: u64,
    pub average_rewards_per_round: u64,
    pub current_base_reward: u64,
}
