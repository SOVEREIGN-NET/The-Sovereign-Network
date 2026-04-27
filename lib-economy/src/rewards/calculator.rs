//! Reward calculator and `RewardCallback` adapter.
//!
//! Relocated from `lib-consensus/src/rewards/reward_calculator.rs` per **CONS-103**
//! and **AD-003**. The orchestration interface (`calculate_round_rewards` /
//! `distribute_rewards`) now takes a slice of
//! `lib_consensus_core::ports::ValidatorRewardInput` instead of a
//! `&ValidatorManager`, so this crate has zero dependency on `lib-consensus`.
//!
//! `ConsensusRewardAdapter` implements `lib_consensus_core::ports::RewardCallback`
//! and is the runtime adapter the engine calls at end-of-round.

use crate::rewards::types::*;
use anyhow::Result;
use lib_consensus_core::ports::{RewardCallback, ValidatorRewardInput};
use std::collections::HashMap;
use std::sync::Mutex;

/// Reward calculation engine.
///
/// Public surface preserved from `lib-consensus`'s `RewardCalculator` (modulo
/// the `&ValidatorManager` → `&[ValidatorRewardInput]` change on the orchestration
/// methods). All amounts are SOV atoms (`u128`).
#[derive(Debug)]
pub struct RewardCalculator {
    /// Base reward per block, in SOV atoms.
    base_reward: u128,
    /// Multiplier per useful-work category.
    work_multipliers: HashMap<UsefulWorkType, f64>,
    /// Bounded reward history for diagnostics.
    reward_history: Vec<RewardRound>,
}

impl Default for RewardCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl RewardCalculator {
    /// Create a new calculator with default multipliers and a 100-SOV base reward.
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
            base_reward: lib_types::sov::atoms(100),
            work_multipliers,
            reward_history: Vec::new(),
        }
    }

    /// Calculate per-validator rewards for a finalized round.
    pub fn calculate_round_rewards(
        &mut self,
        validators: &[ValidatorRewardInput],
        current_height: u64,
    ) -> Result<RewardRound> {
        let mut validator_rewards = HashMap::new();
        let mut total_rewards = 0u128;

        for v in validators {
            let reward = self.calculate_validator_reward(v);
            total_rewards += reward.total_reward;
            validator_rewards.insert(v.identity.clone(), reward);
        }

        let reward_round = RewardRound {
            height: current_height,
            total_rewards,
            validator_rewards,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.reward_history.push(reward_round.clone());
        if self.reward_history.len() > 1000 {
            self.reward_history.remove(0);
        }

        tracing::debug!(
            total_rewards,
            validators = reward_round.validator_rewards.len(),
            height = current_height,
            "calculated round rewards"
        );

        Ok(reward_round)
    }

    /// Distribute rewards (currently a logging stub — real distribution writes
    /// happen in the runtime's wallet/treasury layer).
    pub fn distribute_rewards(&self, reward_round: &RewardRound) -> Result<()> {
        for (validator_id, reward) in &reward_round.validator_rewards {
            tracing::debug!(
                validator = %hex::encode(&validator_id.as_bytes()[..8]),
                total = reward.total_reward,
                base = reward.base_reward,
                work = reward.work_bonus,
                participation = reward.participation_bonus,
                "distributed reward"
            );
        }
        Ok(())
    }

    /// Get reward statistics across the bounded history window.
    pub fn get_reward_stats(&self) -> RewardStatistics {
        let total_rounds = self.reward_history.len();
        let total_rewards: u128 = self.reward_history.iter().map(|r| r.total_rewards).sum();
        let average_per_round = if total_rounds > 0 {
            total_rewards / total_rounds as u128
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

    /// Update the multiplier for one useful-work category (governance hook).
    pub fn update_work_multiplier(&mut self, work_type: UsefulWorkType, multiplier: f64) {
        tracing::info!(?work_type, multiplier, "updated reward multiplier");
        self.work_multipliers.insert(work_type, multiplier);
    }

    /// Adjust the base reward (governance hook).
    pub fn adjust_base_reward(&mut self, new_base_reward: u128) {
        let old_reward = self.base_reward;
        self.base_reward = new_base_reward;
        tracing::info!(old_reward, new_base_reward, "base reward adjusted");
    }

    /// Get the current base reward (atoms).
    pub fn base_reward(&self) -> u128 {
        self.base_reward
    }

    /// Get the multiplier for a specific work type, defaulting to 1.0.
    pub fn work_multiplier(&self, work_type: &UsefulWorkType) -> f64 {
        self.work_multipliers.get(work_type).copied().unwrap_or(1.0)
    }

    /// Convert a fractional multiplier (e.g. `1.2`) to an integer
    /// parts-per-million representation so the work-reward math can stay in
    /// integer space (no float→int truncation, no precision loss).
    /// Negative or non-finite multipliers map to 0.
    fn multiplier_to_ppm(multiplier: f64) -> u128 {
        const MULTIPLIER_PPM_SCALE: f64 = 1_000_000.0;
        if !multiplier.is_finite() || multiplier <= 0.0 {
            return 0;
        }
        (multiplier * MULTIPLIER_PPM_SCALE).round() as u128
    }

    /// Calculate the reward for a single unit of useful work, in SOV atoms.
    ///
    /// `work_amount × 10 SOV × multiplier` — kept in integer atom units
    /// throughout so the result is unit-consistent with the calculator's
    /// `base_reward` (also atoms). Caught in PR #2382 review: the previous
    /// implementation `(amount as f64 * multiplier * 10.0) as u128` produced
    /// raw whole-SOV-ish numbers that were 18 orders of magnitude smaller
    /// than the atom-scaled `base_reward`, making work bonuses effectively
    /// invisible.
    pub fn calculate_work_reward(&self, work_type: UsefulWorkType, work_amount: u64) -> u128 {
        const MULTIPLIER_PPM_SCALE: u128 = 1_000_000;
        let multiplier = self.work_multipliers.get(&work_type).copied().unwrap_or(1.0);
        let multiplier_ppm = Self::multiplier_to_ppm(multiplier);
        let reward_per_unit = lib_types::sov::atoms(10);

        (work_amount as u128)
            .saturating_mul(reward_per_unit)
            .saturating_mul(multiplier_ppm)
            / MULTIPLIER_PPM_SCALE
    }

    fn calculate_validator_reward(&self, v: &ValidatorRewardInput) -> ValidatorReward {
        // Base reward scales with sqrt(stake) — diminishing returns favour
        // distribution over concentration.
        let stake_factor = (v.stake as f64).sqrt() / 1000.0;
        let base_reward = (self.base_reward as f64 * stake_factor) as u128;

        // Work breakdown — placeholder amounts derived from validator metadata.
        // Production would source these from actual work proofs.
        let mut work_breakdown = HashMap::new();
        work_breakdown.insert(UsefulWorkType::NetworkRouting, v.voting_power / 10);
        work_breakdown.insert(
            UsefulWorkType::DataStorage,
            if v.storage_provided > 0 {
                v.storage_provided / (1024 * 1024 * 1024)
            } else {
                0
            },
        );
        work_breakdown.insert(UsefulWorkType::Computation, v.reputation as u64 / 10);

        let work_bonus = self.calculate_work_bonus(&work_breakdown);
        let participation_bonus = (v.reputation as u128 * self.base_reward) / 10_000;
        let total_reward = base_reward + work_bonus + participation_bonus;

        ValidatorReward {
            validator: v.identity.clone(),
            base_reward,
            work_bonus,
            participation_bonus,
            total_reward,
            work_breakdown,
        }
    }

    fn calculate_work_bonus(&self, work_breakdown: &HashMap<UsefulWorkType, u64>) -> u128 {
        let mut total_bonus = 0u128;
        for (work_type, amount) in work_breakdown {
            if let Some(multiplier) = self.work_multipliers.get(work_type) {
                let bonus = (*amount as f64 * multiplier * 10.0) as u128; // 10 SOV per unit
                total_bonus += bonus;
            }
        }
        total_bonus
    }
}

/// Adapter implementing `lib_consensus_core::ports::RewardCallback` over a
/// `RewardCalculator`. This is the runtime-side wiring per **AD-005**:
/// fire-and-forget, no engine-visible failure mode (errors logged here).
pub struct ConsensusRewardAdapter {
    calculator: Mutex<RewardCalculator>,
}

impl ConsensusRewardAdapter {
    /// Create a new adapter wrapping a fresh calculator.
    pub fn new() -> Self {
        Self {
            calculator: Mutex::new(RewardCalculator::new()),
        }
    }

    /// Create from an existing calculator (e.g. governance pre-configured one).
    pub fn from_calculator(calculator: RewardCalculator) -> Self {
        Self {
            calculator: Mutex::new(calculator),
        }
    }
}

impl Default for ConsensusRewardAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RewardCallback for ConsensusRewardAdapter {
    fn on_round_finalized(&self, validators: &[ValidatorRewardInput], height: u64) {
        let mut calc = match self.calculator.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let round = match calc.calculate_round_rewards(validators, height) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, height, "reward calculation failed");
                return;
            }
        };
        if let Err(e) = calc.distribute_rewards(&round) {
            tracing::warn!(error = %e, height, "reward distribution failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    fn validator(seed: u8, stake: u64, storage: u64, voting: u64, reputation: u32) -> ValidatorRewardInput {
        ValidatorRewardInput {
            identity: Hash([seed; 32]),
            stake,
            storage_provided: storage,
            voting_power: voting,
            reputation,
        }
    }

    #[test]
    fn calculator_zero_validators_zero_total() {
        let mut calc = RewardCalculator::new();
        let round = calc.calculate_round_rewards(&[], 1).unwrap();
        assert_eq!(round.height, 1);
        assert_eq!(round.total_rewards, 0);
        assert!(round.validator_rewards.is_empty());
    }

    #[test]
    fn calculator_two_validators_history_grows() {
        let mut calc = RewardCalculator::new();
        let inputs = vec![
            validator(1, 1_000_000, 0, 100, 50),
            validator(2, 4_000_000, 1024 * 1024 * 1024 * 10, 200, 80),
        ];
        let round = calc.calculate_round_rewards(&inputs, 7).unwrap();
        assert_eq!(round.height, 7);
        assert_eq!(round.validator_rewards.len(), 2);
        assert!(round.total_rewards > 0);

        let stats = calc.get_reward_stats();
        assert_eq!(stats.total_rounds, 1);
        assert_eq!(stats.total_rewards_distributed, round.total_rewards);
    }

    #[test]
    fn adapter_implements_callback_without_panic() {
        let adapter = ConsensusRewardAdapter::new();
        adapter.on_round_finalized(&[validator(3, 2_000_000, 0, 150, 60)], 42);
        // No assertion — just verify no panic when the path runs.
    }

    #[test]
    fn adjust_base_reward_changes_subsequent_calculation() {
        let mut calc = RewardCalculator::new();
        let inputs = vec![validator(1, 1_000_000, 0, 100, 50)];
        let before = calc.calculate_round_rewards(&inputs, 1).unwrap().total_rewards;
        calc.adjust_base_reward(lib_types::sov::atoms(200));
        let after = calc.calculate_round_rewards(&inputs, 2).unwrap().total_rewards;
        assert!(after > before, "doubling base_reward must increase total");
    }
}
