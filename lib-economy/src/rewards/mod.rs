//! Reward calculation system.
//!
//! Owns `RewardCalculator` (relocated from `lib-consensus/src/rewards/`
//! in **CONS-103**) and the `ConsensusRewardAdapter` that implements
//! `lib_consensus_core::ports::RewardCallback`. Depends on `lib-consensus-core`
//! for the trait but never on `lib-consensus` itself — see **AD-003**.

pub mod calculator;
pub mod types;

pub use calculator::{ConsensusRewardAdapter, RewardCalculator};
pub use types::{RewardRound, RewardStatistics, UsefulWorkType, ValidatorReward};
