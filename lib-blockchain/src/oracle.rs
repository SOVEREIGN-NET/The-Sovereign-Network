//! Oracle Protocol v1 consensus state types.
//!
//! This module contains deterministic state models used by consensus to manage:
//! - oracle committee membership
//! - oracle configuration
//! - per-epoch finalized prices

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Fixed-point scale for SOV/USD oracle prices (8 decimals).
pub const ORACLE_PRICE_SCALE: u128 = 100_000_000;

/// Governance-controlled oracle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OracleConfig {
    /// Epoch duration in seconds.
    pub epoch_duration_secs: u64,
    /// Maximum accepted source age in seconds.
    pub max_source_age_secs: u64,
    /// Maximum allowed deviation from median in basis points.
    pub max_deviation_bps: u32,
    /// Maximum allowed staleness (in epochs) for consumers.
    pub max_price_staleness_epochs: u64,
    /// Fixed-point price scale. Must remain 1e8 for v1.
    pub price_scale: u128,
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            epoch_duration_secs: 300,
            max_source_age_secs: 60,
            max_deviation_bps: 500,
            max_price_staleness_epochs: 2,
            price_scale: ORACLE_PRICE_SCALE,
        }
    }
}

/// Pending governance committee update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCommitteeUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// New committee members (validator public keys).
    pub members: Vec<[u8; 32]>,
    /// Optional threshold override for this committee.
    pub threshold_override: Option<u16>,
}

/// Active oracle committee state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleCommitteeState {
    /// Active committee members (sorted, deduplicated).
    pub members: Vec<[u8; 32]>,
    /// Optional threshold override.
    pub threshold_override: Option<u16>,
    /// Pending update, if scheduled.
    pub pending_update: Option<PendingCommitteeUpdate>,
}

impl OracleCommitteeState {
    /// Threshold with optional override; default is floor(2N/3)+1.
    pub fn threshold(&self) -> u16 {
        let n = self.members.len() as u16;
        let default_t = if n == 0 { 0 } else { (2 * n) / 3 + 1 };
        self.threshold_override.unwrap_or(default_t)
    }
}

/// Canonical finalized price for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedPrice {
    pub epoch_id: u64,
    pub price: u128,
}

/// Oracle aggregation/finalization status for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleEpochState {
    /// First price to hit threshold for this epoch.
    pub winning_price: Option<u128>,
    /// Whether this epoch is finalized.
    pub finalized: bool,
}

/// Root oracle consensus state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleState {
    #[serde(default)]
    pub config: OracleConfig,
    #[serde(default)]
    pub committee: OracleCommitteeState,
    /// One immutable finalized price per epoch.
    #[serde(default)]
    pub finalized_prices: BTreeMap<u64, FinalizedPrice>,
    /// Per-epoch transient/finalization status.
    #[serde(default)]
    pub epoch_state: BTreeMap<u64, OracleEpochState>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_threshold_defaults_to_supermajority() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            threshold_override: None,
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 3);
    }

    #[test]
    fn committee_threshold_override_wins() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            threshold_override: Some(4),
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 4);
    }
}
