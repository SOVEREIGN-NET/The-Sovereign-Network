//! Stake tier definitions for the Sovereign Network

use serde::{Deserialize, Serialize};

/// Stake tiers determine access levels and voting power
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum StakeTier {
    /// No stake - basic access only
    None,
    /// Citizenship tier - 500 SOV minimum
    Citizenship,
    /// DAO Founder tier - 2,000 SOV minimum
    DaoFounder,
    /// Validator tier - 10,000 SOV minimum
    Validator,
}

impl StakeTier {
    /// Get the minimum stake required for this tier (in micro-SOV)
    pub fn minimum_stake(&self) -> u64 {
        match self {
            StakeTier::None => 0,
            StakeTier::Citizenship => 500_000_000_000_000,      // 500 SOV
            StakeTier::DaoFounder => 2_000_000_000_000_000,     // 2,000 SOV
            StakeTier::Validator => 10_000_000_000_000_000,     // 10,000 SOV
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            StakeTier::None => "None",
            StakeTier::Citizenship => "Citizenship",
            StakeTier::DaoFounder => "DAO Founder",
            StakeTier::Validator => "Validator",
        }
    }
}

impl Default for StakeTier {
    fn default() -> Self {
        StakeTier::None
    }
}

impl std::fmt::Display for StakeTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
