//! Reward calculation types
//! 
//! Types needed for reward calculations in the economics system

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Individual validator reward information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator: [u8; 32], // Using byte array instead of IdentityId to avoid dependencies
    pub base_reward: u64,
    pub work_bonus: u64,
    pub participation_bonus: u64,
    pub total_reward: u64,
    pub work_breakdown: HashMap<String, u64>, // Work type as string to avoid dependencies
}

/// Useful work types for reward calculation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        match self {
            UsefulWorkType::NetworkRouting => write!(f, "network_routing"),
            UsefulWorkType::DataStorage => write!(f, "data_storage"),
            UsefulWorkType::Computation => write!(f, "computation"),
            UsefulWorkType::Validation => write!(f, "validation"),
            UsefulWorkType::BridgeOperations => write!(f, "bridge_operations"),
            UsefulWorkType::MeshDiscovery => write!(f, "mesh_discovery"),
            UsefulWorkType::IspBypass => write!(f, "isp_bypass"),
            UsefulWorkType::UbiDistribution => write!(f, "ubi_distribution"),
        }
    }
}

/// Reward round information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardRound {
    pub height: u64,
    pub total_rewards: u64,
    pub validator_rewards: HashMap<[u8; 32], ValidatorReward>,
    pub timestamp: u64,
}

/// Reward system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardStatistics {
    pub total_rounds: u64,
    pub total_rewards_distributed: u64,
    pub average_rewards_per_round: u64,
    pub current_base_reward: u64,
}
