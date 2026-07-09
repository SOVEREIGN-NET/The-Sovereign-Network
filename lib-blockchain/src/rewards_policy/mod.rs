//! `zhtp/rewards-policy/v1` — DAO reward distribution policy document.
//!
//! Referenced on-chain via `RewardsModuleState.policy_hash` (BLAKE3 of canonical JSON).
//! Schema: `schemas/zhtp/rewards-policy/v1.schema.json`

mod types;
mod validate;

pub use types::*;
pub use validate::{canonical_policy_bytes, policy_hash, validate_rewards_policy, RewardsPolicyError};