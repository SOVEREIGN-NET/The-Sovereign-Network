//! `zhtp/rewards-policy/v1` — DAO reward distribution policy document.
//!
//! Referenced on-chain via `RewardsModuleState.policy_hash` (BLAKE3 of canonical JSON).
//! Schema: `schemas/zhtp/rewards-policy/v1.schema.json`

mod types;
mod validate;

pub use types::*;
pub use validate::{
    canonical_policy_bytes, expected_amount_for_trigger, legacy_bubl_policy, policy_hash,
    validate_rewards_policy, validate_rewards_policy_value, weekly_partner_cap, RewardsPolicyError,
};