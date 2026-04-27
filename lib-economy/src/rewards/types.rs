//! Reward calculation types
//!
//! Pure data types for reward calculations. Uses `IdentityId` (not `[u8; 32]`)
//! and `u128` SOV atoms (not `u64`) to match the post-#2287 widening that aligns
//! reward amounts with the rest of the value layer.

use lib_identity::IdentityId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Individual validator reward information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator: IdentityId,
    pub base_reward: u128,
    pub work_bonus: u128,
    pub participation_bonus: u128,
    pub total_reward: u128,
    pub work_breakdown: HashMap<UsefulWorkType, u64>,
}

/// Useful-work categories for reward calculation. Each variant has a multiplier
/// in `RewardCalculator::work_multipliers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UsefulWorkType {
    NetworkRouting,
    DataStorage,
    Computation,
    Validation,
    BridgeOperations,
    MeshDiscovery,
    IspBypass,
    UbiDistribution,
}

impl std::fmt::Display for UsefulWorkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            UsefulWorkType::NetworkRouting => "network_routing",
            UsefulWorkType::DataStorage => "data_storage",
            UsefulWorkType::Computation => "computation",
            UsefulWorkType::Validation => "validation",
            UsefulWorkType::BridgeOperations => "bridge_operations",
            UsefulWorkType::MeshDiscovery => "mesh_discovery",
            UsefulWorkType::IspBypass => "isp_bypass",
            UsefulWorkType::UbiDistribution => "ubi_distribution",
        };
        f.write_str(name)
    }
}

/// Aggregate of one consensus round's reward distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardRound {
    pub height: u64,
    pub total_rewards: u128,
    pub validator_rewards: HashMap<IdentityId, ValidatorReward>,
    pub timestamp: u64,
}

/// Reward system statistics for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardStatistics {
    pub total_rounds: u64,
    pub total_rewards_distributed: u128,
    pub average_rewards_per_round: u128,
    pub current_base_reward: u128,
}
