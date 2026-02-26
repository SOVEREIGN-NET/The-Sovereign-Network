//! DAO voting power types (dao-5)

use serde::{Deserialize, Serialize};

/// Determines how token balances translate to voting weight.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VotingPowerMode {
    /// Every identity gets exactly 1 vote (universal suffrage, Phase 0 default).
    #[default]
    Identity,
    /// Voting power scales linearly with SOV balance (1 SOV = 1 vote unit).
    Linear,
    /// Voting power scales as the square root of SOV balance (whale dampening).
    Quadratic,
}
