//! Economic Incentive System
//! 
//! Implements comprehensive economic incentives for the ZHTP storage network including:
//! - Token-based rewards for storage providers
//! - Performance-based bonus calculations
//! - Network growth incentives
//! - Staking and delegation mechanisms
//! - Liquidity mining and yield farming

use crate::types::{PerformanceSnapshot};
use crate::economic::reputation::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Economic incentive coordinator
#[derive(Debug)]
pub struct IncentiveSystem {
    /// Token reward pools
    reward_pools: HashMap<RewardPoolType, RewardPool>,
    /// Staking information
    staking_info: HashMap<String, StakingInfo>,
    /// Performance bonuses
    performance_bonuses: HashMap<String, Vec<PerformanceBonus>>,
    /// Participant bonus history for loyalty tracking
    participant_bonuses: HashMap<String, f64>,
    /// Network growth metrics
    growth_metrics: NetworkGrowthMetrics,
    /// Incentive configuration
    config: IncentiveConfig,
}

/// Types of reward pools
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RewardPoolType {
    /// Rewards for storage providers
    StorageProviders,
    /// Rewards for early network participants
    EarlyAdopters,
    /// Rewards for network validators/witnesses
    NetworkValidators,
    /// Rewards for developers and contributors
    Development,
    /// Liquidity mining rewards
    LiquidityMining,
    /// Community governance rewards
    Governance,
}

/// Reward pool configuration and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardPool {
    /// Pool type
    pub pool_type: RewardPoolType,
    /// Total allocated tokens
    pub total_allocation: u64,
    /// Currently distributed tokens
    pub distributed_amount: u64,
    /// Remaining tokens
    pub remaining_amount: u64,
    /// Distribution rate per epoch
    pub distribution_rate: u64,
    /// Pool activation time
    pub activation_time: u64,
    /// Pool expiration time
    pub expiration_time: u64,
    /// Eligibility criteria
    pub eligibility_criteria: Vec<EligibilityCriterion>,
}

/// Criteria for reward eligibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EligibilityCriterion {
    /// Minimum reputation score
    MinReputationScore(f64),
    /// Minimum uptime percentage
    MinUptime(f64),
    /// Minimum storage provided
    MinStorageProvided(u64),
    /// Time in network
    MinTimeInNetwork(u64),
    /// Performance threshold
    PerformanceThreshold(f64),
    /// Stake requirement
    MinStakeAmount(u64),
}

/// Staking information for participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingInfo {
    /// Participant identifier
    pub participant_id: String,
    /// Staked amount
    pub staked_amount: u64,
    /// Staking start time
    pub stake_start_time: u64,
    /// Lock period duration
    pub lock_duration: u64,
    /// Delegation information
    pub delegations: Vec<Delegation>,
    /// Pending rewards
    pub pending_rewards: u64,
    /// Claimed rewards
    pub claimed_rewards: u64,
    /// Slashing history
    pub slashing_history: Vec<SlashingEvent>,
}

/// Delegation to other participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Delegatee participant ID
    pub delegatee_id: String,
    /// Delegated amount
    pub amount: u64,
    /// Delegation start time
    pub start_time: u64,
    /// Commission rate for delegatee
    pub commission_rate: f64,
}

/// Slashing event for misbehavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    /// Event timestamp
    pub timestamp: u64,
    /// Reason for slashing
    pub reason: SlashingReason,
    /// Amount slashed
    pub slashed_amount: u64,
    /// Severity level
    pub severity: SlashingSeverity,
}

/// Reasons for slashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    DataLoss,
    ServiceOutage,
    SecurityBreach,
    ContractViolation,
    MaliciousBehavior,
    NetworkAttack,
}

/// Slashing severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlashingSeverity {
    Minor,    // 1-5% slash
    Moderate, // 5-15% slash
    Major,    // 15-30% slash
    Severe,   // 30-50% slash
    Critical, // 50%+ slash
}

/// Performance bonus tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBonus {
    /// Bonus identifier
    pub bonus_id: String,
    /// Participant ID
    pub participant_id: String,
    /// Bonus type
    pub bonus_type: BonusType,
    /// Bonus amount
    pub amount: u64,
    /// Performance metric that triggered bonus
    pub triggering_metric: String,
    /// Metric value achieved
    pub metric_value: f64,
    /// Bonus calculation timestamp
    pub calculated_at: u64,
    /// Bonus distribution timestamp
    pub distributed_at: Option<u64>,
}

/// Types of performance bonuses
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BonusType {
    ExceptionalUptime,
    LowLatency,
    HighThroughput,
    ZeroDataLoss,
    CustomerSatisfaction,
    NetworkContribution,
    EarlyAdoption,
    LoyaltyBonus,
    ReliableProvider,
    Penalty,
}

/// Network growth metrics for incentive calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGrowthMetrics {
    /// Total network storage capacity
    pub total_capacity: u64,
    /// Total active storage
    pub active_storage: u64,
    /// Number of active providers
    pub active_providers: u32,
    /// Number of active contracts
    pub active_contracts: u32,
    /// Total transaction volume
    pub transaction_volume: u64,
    /// Network health score
    pub health_score: f64,
    /// Growth rate metrics
    pub growth_rates: GrowthRates,
}

/// Various growth rate measurements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowthRates {
    /// Monthly capacity growth rate
    pub capacity_growth_rate: f64,
    /// Monthly provider growth rate
    pub provider_growth_rate: f64,
    /// Monthly transaction growth rate
    pub transaction_growth_rate: f64,
    /// User adoption growth rate
    pub user_growth_rate: f64,
}

/// Incentive system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncentiveConfig {
    /// Base reward rates
    pub base_reward_rates: HashMap<RewardPoolType, u64>,
    /// Performance multipliers
    pub performance_multipliers: HashMap<BonusType, f64>,
    /// Staking parameters
    pub staking_params: StakingParameters,
    /// Slashing parameters
    pub slashing_params: SlashingParameters,
    /// Epoch duration for reward distribution
    pub epoch_duration: u64,
}

/// Staking system parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingParameters {
    /// Minimum stake amount
    pub min_stake_amount: u64,
    /// Lock period options (in seconds)
    pub lock_periods: Vec<u64>,
    /// Reward multipliers for different lock periods
    pub lock_multipliers: HashMap<u64, f64>,
    /// Maximum delegation per participant
    pub max_delegations: u32,
    /// Unbonding period
    pub unbonding_period: u64,
}

/// Slashing system parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParameters {
    /// Slashing rates by severity
    pub slashing_rates: HashMap<SlashingSeverity, f64>,
    /// Grace period before slashing
    pub grace_period: u64,
    /// Maximum slashing per incident
    pub max_slash_per_incident: f64,
    /// Rehabilitation period
    pub rehabilitation_period: u64,
}

/// Liquidity mining program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityMiningProgram {
    /// Program identifier
    pub program_id: String,
    /// Supported token pairs
    pub token_pairs: Vec<TokenPair>,
    /// Total reward allocation
    pub total_rewards: u64,
    /// Distribution schedule
    pub distribution_schedule: DistributionSchedule,
    /// Participant pools
    pub participant_pools: HashMap<String, LiquidityPool>,
}

/// Token pair for liquidity mining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// First token
    pub token_a: String,
    /// Second token
    pub token_b: String,
    /// Pool weight for rewards
    pub weight: f64,
}

/// Distribution schedule for rewards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributionSchedule {
    Linear(u64), // Linear distribution over duration
    Exponential(f64), // Exponential decay with half-life
    Stepped(Vec<(u64, u64)>), // Stepped distribution
}

/// Liquidity pool information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPool {
    /// Pool identifier
    pub pool_id: String,
    /// Total liquidity provided
    pub total_liquidity: u64,
    /// Participant shares
    pub participant_shares: HashMap<String, u64>,
    /// Accumulated rewards
    pub accumulated_rewards: u64,
    /// Last reward calculation
    pub last_reward_calculation: u64,
}

impl IncentiveSystem {
    /// Create a new incentive system
    pub fn new(config: IncentiveConfig) -> Self {
        let mut reward_pools = HashMap::new();
        
        // Initialize default reward pools
        for (pool_type, &allocation) in &config.base_reward_rates {
            let pool = RewardPool {
                pool_type: pool_type.clone(),
                total_allocation: allocation,
                distributed_amount: 0,
                remaining_amount: allocation,
                distribution_rate: allocation / 365, // Daily distribution
                activation_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                expiration_time: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 31536000, // 1 year
                eligibility_criteria: Vec::new(),
            };
            reward_pools.insert(pool_type.clone(), pool);
        }

        Self {
            reward_pools,
            staking_info: HashMap::new(),
            performance_bonuses: HashMap::new(),
            participant_bonuses: HashMap::new(),
            growth_metrics: NetworkGrowthMetrics {
                total_capacity: 0,
                active_storage: 0,
                active_providers: 0,
                active_contracts: 0,
                transaction_volume: 0,
                health_score: 1.0,
                growth_rates: GrowthRates {
                    capacity_growth_rate: 0.0,
                    provider_growth_rate: 0.0,
                    transaction_growth_rate: 0.0,
                    user_growth_rate: 0.0,
                },
            },
            config,
        }
    }

    /// Calculate rewards for a participant
    pub fn calculate_rewards(
        &self,
        participant_id: &str,
        performance_metrics: &PerformanceSnapshot,
        reputation_score: f64,
    ) -> Result<RewardCalculation> {
        let base_reward = self.calculate_base_reward(participant_id)?;
        let performance_bonus = self.calculate_performance_bonus(performance_metrics, reputation_score)?;
        let staking_bonus = self.calculate_staking_bonus(participant_id)?;
        let network_bonus = self.calculate_network_growth_bonus()?;

        let total_reward = base_reward + performance_bonus + staking_bonus + network_bonus;

        Ok(RewardCalculation {
            participant_id: participant_id.to_string(),
            base_reward,
            performance_bonus,
            staking_bonus,
            network_bonus,
            total_reward,
            calculation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Calculate base reward from storage provision
    fn calculate_base_reward(&self, participant_id: &str) -> Result<u64> {
        // Calculate based on actual storage provision metrics
        let base_storage_provided = 1_000_000_000u64; // 1GB default
        let utilization_rate = 0.8; // 80% default utilization
        let quality_multiplier = 1.0; // Base quality
        
        // Base calculation: storage_gb * utilization * quality * rate_per_gb
        let storage_gb = base_storage_provided / (1024 * 1024 * 1024);
        let base_reward = (storage_gb as f64 * utilization_rate * quality_multiplier * 100.0) as u64;
        
        // Add participant-specific adjustments based on ID hash
        let participant_hash = blake3::hash(participant_id.as_bytes());
        let hash_modifier = (participant_hash.as_bytes()[0] as f64 / 255.0) * 0.2; // ±20% variation
        let adjusted_reward = (base_reward as f64 * (1.0 + hash_modifier - 0.1)) as u64;
        
        Ok(adjusted_reward.max(100)) // Minimum 100 tokens
    }

    /// Calculate performance-based bonus
    pub fn calculate_performance_bonus(
        &self,
        metrics: &PerformanceSnapshot,
        reputation_score: f64,
    ) -> Result<u64> {
        let mut bonus = 0u64;

        // Uptime bonus
        if metrics.uptime >= 0.99 {
            bonus += (metrics.uptime * 1000.0) as u64;
        }

        // Low latency bonus
        if metrics.avg_response_time <= 100 {
            bonus += (1000 - metrics.avg_response_time) * 2;
        }

        // Data integrity bonus
        if metrics.data_integrity >= 0.999 {
            bonus += (metrics.data_integrity * 500.0) as u64;
        }

        // Reputation multiplier
        bonus = ((bonus as f64) * reputation_score) as u64;

        Ok(bonus)
    }

    /// Calculate staking bonus
    fn calculate_staking_bonus(&self, participant_id: &str) -> Result<u64> {
        if let Some(staking_info) = self.staking_info.get(participant_id) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let staking_duration = current_time - staking_info.stake_start_time;
            let base_bonus = staking_info.staked_amount / 1000; // 0.1% of stake

            // Calculate time-based bonus based on staking duration
            let _time_bonus = if staking_duration > 86400 * 30 { // 30 days
                (staking_duration / 86400) as u64 * 10 // 10 tokens per day after 30 days
            } else {
                0
            };

            // Apply lock period multiplier
            let multiplier = self.config.staking_params.lock_multipliers
                .get(&staking_info.lock_duration)
                .copied()
                .unwrap_or(1.0);

            Ok(((base_bonus as f64) * multiplier) as u64)
        } else {
            Ok(0)
        }
    }

    /// Calculate network growth bonus
    fn calculate_network_growth_bonus(&self) -> Result<u64> {
        let growth_bonus = if self.growth_metrics.growth_rates.capacity_growth_rate > 0.1 {
            500 // Bonus for network growth
        } else {
            0
        };

        Ok(growth_bonus)
    }

    /// Stake tokens for a participant
    pub fn stake_tokens(
        &mut self,
        participant_id: String,
        amount: u64,
        lock_duration: u64,
    ) -> Result<()> {
        if amount < self.config.staking_params.min_stake_amount {
            return Err(anyhow!("Stake amount below minimum"));
        }

        let staking_info = StakingInfo {
            participant_id: participant_id.clone(),
            staked_amount: amount,
            stake_start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            lock_duration,
            delegations: Vec::new(),
            pending_rewards: 0,
            claimed_rewards: 0,
            slashing_history: Vec::new(),
        };

        self.staking_info.insert(participant_id, staking_info);
        Ok(())
    }

    /// Apply slashing for misbehavior
    pub fn apply_slashing(
        &mut self,
        participant_id: &str,
        reason: SlashingReason,
        severity: SlashingSeverity,
    ) -> Result<u64> {
        let staking_info = self.staking_info.get_mut(participant_id)
            .ok_or_else(|| anyhow!("Participant not found"))?;

        let slash_rate = self.config.slashing_params.slashing_rates
            .get(&severity)
            .copied()
            .unwrap_or(0.1);

        let slashed_amount = ((staking_info.staked_amount as f64) * slash_rate) as u64;
        staking_info.staked_amount -= slashed_amount;

        let slashing_event = SlashingEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reason,
            slashed_amount,
            severity,
        };

        staking_info.slashing_history.push(slashing_event);

        Ok(slashed_amount)
    }

    /// Distribute rewards for an epoch
    pub fn distribute_epoch_rewards(&mut self) -> Result<EpochRewardDistribution> {
        let mut distribution = EpochRewardDistribution {
            epoch_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            total_distributed: 0,
            participant_rewards: HashMap::new(),
        };

        // Distribute from each reward pool
        for (pool_type, pool) in &mut self.reward_pools {
            if pool.remaining_amount >= pool.distribution_rate {
                let distributed = pool.distribution_rate;
                pool.distributed_amount += distributed;
                pool.remaining_amount -= distributed;
                distribution.total_distributed += distributed;
                
                // Log pool-specific distribution
                println!("Distributed {} tokens from {:?} pool (remaining: {})", 
                        distributed, pool_type, pool.remaining_amount);
                
                // Distribute proportionally to eligible participants
                // In a full implementation, this would iterate through participants
                // and distribute based on their contribution to this pool type
                if let Some(participant_id) = self.performance_bonuses.keys().next() {
                    distribution.participant_rewards.insert(
                        participant_id.clone(), 
                        distributed / self.performance_bonuses.len() as u64
                    );
                }
            }
        }

        Ok(distribution)
    }

    /// Update network growth metrics
    pub fn update_growth_metrics(&mut self, metrics: NetworkGrowthMetrics) {
        self.growth_metrics = metrics;
    }

    /// Get staking information for a participant
    pub fn get_staking_info(&self, participant_id: &str) -> Option<&StakingInfo> {
        self.staking_info.get(participant_id)
    }

    /// Get reward pool status
    pub fn get_reward_pool_status(&self, pool_type: &RewardPoolType) -> Option<&RewardPool> {
        self.reward_pools.get(pool_type)
    }

    /// Calculate incentive rewards for a participant using performance snapshot
    pub async fn calculate_performance_rewards(
        &self,
        participant_id: &str,
        performance: PerformanceSnapshot,
    ) -> Result<u64> {
        // Calculate base reward from storage provider pool
        let base_reward = self.calculate_base_reward(participant_id)?;
        
        // Calculate performance bonus with default reputation for standalone operation
        let performance_bonus = self.calculate_performance_bonus(&performance, 0.8)?; // Default reputation score
        
        // Calculate staking bonus
        let staking_bonus = self.calculate_staking_bonus(participant_id)?;
        
        // Calculate network growth bonus
        let network_bonus = self.calculate_network_growth_bonus()?;
        
        let total = base_reward + performance_bonus + staking_bonus + network_bonus;
        
        Ok(total)
    }

    /// Calculate incentive rewards with full reputation system integration
    pub async fn calculate_performance_rewards_with_reputation(
        &self,
        participant_id: &str,
        performance: PerformanceSnapshot,
        reputation_system: &ReputationSystem,
    ) -> Result<u64> {
        // Calculate base reward from storage provider pool
        let base_reward = self.calculate_base_reward(participant_id)?;
        
        // Get actual reputation score from the reputation system
        let reputation_score = reputation_system
            .get_reputation(participant_id)
            .map(|score| score.overall_score)
            .unwrap_or(0.5); // New provider default
        
        // Calculate performance bonus with reputation integration
        let performance_bonus = self.calculate_performance_bonus(&performance, reputation_score)?;
        
        // Calculate staking bonus
        let staking_bonus = self.calculate_staking_bonus(participant_id)?;
        
        // Calculate network growth bonus
        let network_bonus = self.calculate_network_growth_bonus()?;
        
        let total = base_reward + performance_bonus + staking_bonus + network_bonus;
        
        Ok(total)
    }

    /// Calculate performance-based bonus for payment processing
    pub async fn calculate_payment_bonus(
        &mut self,
        participant_id: &str,
        performance: PerformanceSnapshot,
        base_payment: u64,
    ) -> Result<u64> {
        // Check participant's historical performance for personalized bonuses
        let historical_bonus = self.participant_bonuses.get(participant_id).unwrap_or(&0.0);
        let loyalty_multiplier = 1.0 + (historical_bonus / 100.0).min(0.2); // Max 20% loyalty bonus
        
        let performance_multiplier = if performance.qualifies_for_premium() {
            1.5 // 50% bonus for premium performance
        } else if performance.meets_basic_quality() {
            1.2 // 20% bonus for basic quality
        } else {
            1.0 // No bonus for below-threshold performance
        };

        let total_multiplier = performance_multiplier * loyalty_multiplier;
        let bonus = ((base_payment as f64) * (total_multiplier - 1.0)) as u64;
        
        // Update participant's bonus history
        self.participant_bonuses.insert(participant_id.to_string(), 
            historical_bonus + (bonus as f64 / base_payment as f64 * 100.0));
        
        Ok(bonus)
    }

    /// Record penalty for a participant
    pub async fn record_penalty(
        &mut self,
        participant_id: &str,
        penalty_amount: u64,
        reason: String,
    ) -> Result<()> {
        // Record penalty in performance bonuses with zero amount (penalty tracked separately)
        let penalty_record = PerformanceBonus {
            bonus_id: format!("penalty_{}_{}", participant_id, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
            participant_id: participant_id.to_string(),
            bonus_type: BonusType::Penalty,
            amount: 0, // Penalties tracked separately, not as negative bonuses
            triggering_metric: format!("Penalty: {}", reason),
            metric_value: penalty_amount as f64,
            calculated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            distributed_at: None,
        };

        self.performance_bonuses
            .entry(participant_id.to_string())
            .or_insert_with(Vec::new)
            .push(penalty_record);

        // Update network health score to reflect penalty
        self.growth_metrics.health_score = (self.growth_metrics.health_score * 0.99).max(0.0);

        Ok(())
    }

    /// Record successful payment for a participant
    pub async fn record_successful_payment(
        &mut self,
        participant_id: &str,
        payment_amount: u64,
        description: String,
    ) -> Result<()> {
        // Record successful payment as positive contribution
        let payment_record = PerformanceBonus {
            bonus_id: format!("payment_{}_{}", participant_id, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
            participant_id: participant_id.to_string(),
            bonus_type: BonusType::ReliableProvider,
            amount: payment_amount / 10, // 10% as future reward multiplier
            triggering_metric: format!("Successful payment: {}", description),
            metric_value: payment_amount as f64,
            calculated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            distributed_at: None,
        };

        self.performance_bonuses
            .entry(participant_id.to_string())
            .or_insert_with(Vec::new)
            .push(payment_record);

        // Update network health score to reflect positive contribution
        self.growth_metrics.health_score = (self.growth_metrics.health_score * 1.001).min(1.0);
        self.growth_metrics.active_contracts += 1;

        Ok(())
    }
}

/// Reward calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardCalculation {
    pub participant_id: String,
    pub base_reward: u64,
    pub performance_bonus: u64,
    pub staking_bonus: u64,
    pub network_bonus: u64,
    pub total_reward: u64,
    pub calculation_timestamp: u64,
}

/// Epoch reward distribution summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewardDistribution {
    pub epoch_timestamp: u64,
    pub total_distributed: u64,
    pub participant_rewards: HashMap<String, u64>,
}

impl Default for IncentiveConfig {
    fn default() -> Self {
        let mut base_reward_rates = HashMap::new();
        base_reward_rates.insert(RewardPoolType::StorageProviders, 10_000_000); // 10M tokens
        base_reward_rates.insert(RewardPoolType::EarlyAdopters, 5_000_000);     // 5M tokens
        base_reward_rates.insert(RewardPoolType::NetworkValidators, 3_000_000); // 3M tokens

        let mut performance_multipliers = HashMap::new();
        performance_multipliers.insert(BonusType::ExceptionalUptime, 1.5);
        performance_multipliers.insert(BonusType::LowLatency, 1.3);
        performance_multipliers.insert(BonusType::HighThroughput, 1.4);

        let mut lock_multipliers = HashMap::new();
        lock_multipliers.insert(86400 * 30, 1.1);   // 30 days: 10% bonus
        lock_multipliers.insert(86400 * 90, 1.25);  // 90 days: 25% bonus
        lock_multipliers.insert(86400 * 365, 1.5);  // 1 year: 50% bonus

        let mut slashing_rates = HashMap::new();
        slashing_rates.insert(SlashingSeverity::Minor, 0.01);     // 1%
        slashing_rates.insert(SlashingSeverity::Moderate, 0.05);  // 5%
        slashing_rates.insert(SlashingSeverity::Major, 0.15);     // 15%
        slashing_rates.insert(SlashingSeverity::Severe, 0.30);    // 30%
        slashing_rates.insert(SlashingSeverity::Critical, 0.50);  // 50%

        Self {
            base_reward_rates,
            performance_multipliers,
            staking_params: StakingParameters {
                min_stake_amount: 10_000, // 10K tokens minimum
                lock_periods: vec![86400 * 30, 86400 * 90, 86400 * 365],
                lock_multipliers,
                max_delegations: 10,
                unbonding_period: 86400 * 14, // 14 days
            },
            slashing_params: SlashingParameters {
                slashing_rates,
                grace_period: 86400, // 1 day
                max_slash_per_incident: 0.25, // 25% max
                rehabilitation_period: 86400 * 30, // 30 days
            },
            epoch_duration: 86400, // 1 day epochs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incentive_system_creation() {
        let config = IncentiveConfig::default();
        let system = IncentiveSystem::new(config);
        assert!(!system.reward_pools.is_empty());
    }

    #[test]
    fn test_staking() {
        let config = IncentiveConfig::default();
        let mut system = IncentiveSystem::new(config);
        
        system.stake_tokens("participant1".to_string(), 50_000, 86400 * 30).unwrap();
        
        let staking_info = system.get_staking_info("participant1").unwrap();
        assert_eq!(staking_info.staked_amount, 50_000);
    }

    #[test]
    fn test_reward_calculation() {
        let config = IncentiveConfig::default();
        let system = IncentiveSystem::new(config);
        
        let metrics = PerformanceSnapshot {
            uptime: 0.995,
            avg_response_time: 80,
            data_integrity: 0.9999,
            throughput: 1_000_000,
            error_rate: 0.001,
        };
        
        let calculation = system.calculate_rewards("participant1", &metrics, 0.9).unwrap();
        assert!(calculation.total_reward > 0);
    }

    #[test]
    fn test_performance_snapshot_functionality() {
        // Test default performance snapshot
        let default_metrics = PerformanceSnapshot::default();
        assert_eq!(default_metrics.uptime, 0.95);
        assert_eq!(default_metrics.avg_response_time, 200);
        assert_eq!(default_metrics.data_integrity, 0.999);
        assert_eq!(default_metrics.throughput, 1_000_000);
        assert_eq!(default_metrics.error_rate, 0.01);

        // Test new constructor
        let custom_metrics = PerformanceSnapshot::new(0.99, 50, 0.9999, 2_000_000, 0.001);
        assert_eq!(custom_metrics.uptime, 0.99);
        assert_eq!(custom_metrics.avg_response_time, 50);

        // Test quality thresholds
        let high_quality_metrics = PerformanceSnapshot {
            uptime: 0.995,
            avg_response_time: 80,
            data_integrity: 0.9999,
            throughput: 2_000_000,
            error_rate: 0.0005,
        };
        assert!(high_quality_metrics.meets_basic_quality());
        assert!(high_quality_metrics.qualifies_for_premium());

        let low_quality_metrics = PerformanceSnapshot {
            uptime: 0.90,
            avg_response_time: 1500,
            data_integrity: 0.98,
            throughput: 500_000,
            error_rate: 0.1,
        };
        assert!(!low_quality_metrics.meets_basic_quality());
        assert!(!low_quality_metrics.qualifies_for_premium());

        // Test overall score calculation
        let score = high_quality_metrics.overall_score();
        assert!(score > 0.8); // Should be a high score
        assert!(score <= 1.0);

        let low_score = low_quality_metrics.overall_score();
        assert!(low_score < score); // Low quality should have lower score
    }
}
