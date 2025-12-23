//! Staking module for the Sovereign Network
//!
//! Provides stake tier calculation, progressive unlocking, and stake management.
//!
//! ## Security Notes
//!
//! This module implements critical financial operations. All public methods
//! require caller authentication via `IdentityId` to prevent unauthorized access.

mod stake_tier;
mod unified_stake_manager;

pub use stake_tier::StakeTier;
pub use unified_stake_manager::{
    StakeEntry,
    StakeRecord,
    UnifiedStakeManager,
    WithdrawalResult,
    WithdrawalWarning,
};
