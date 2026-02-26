//! Oracle Protocol v1 consensus state types.
//!
//! This module contains deterministic state models used by consensus to manage:
//! - oracle committee membership
//! - oracle configuration
//! - per-epoch finalized prices

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
}

/// Pending governance config update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingConfigUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// Config values that become active at `activate_at_epoch`.
    pub config: OracleConfig,
}

/// Active oracle committee state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OracleCommitteeState {
    /// Active committee members (sorted, deduplicated).
    pub members: Vec<[u8; 32]>,
    /// Pending update, if scheduled.
    pub pending_update: Option<PendingCommitteeUpdate>,
}

impl OracleCommitteeState {
    /// Threshold formula: floor(2N/3)+1.
    pub fn threshold(&self) -> u16 {
        let n = self.members.len() as u16;
        if n == 0 { 0 } else { (2 * n) / 3 + 1 }
    }
}

/// Canonical finalized price for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedOraclePrice {
    pub epoch_id: u64,
    #[serde(alias = "price")]
    pub sov_usd_price: u128,
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
    /// Pending config update, if scheduled.
    #[serde(default)]
    pub pending_config_update: Option<PendingConfigUpdate>,
    /// One immutable finalized price per epoch.
    #[serde(default)]
    pub finalized_prices: BTreeMap<u64, FinalizedOraclePrice>,
    /// Per-epoch transient/finalization status.
    #[serde(default)]
    pub epoch_state: BTreeMap<u64, OracleEpochState>,
}

impl OracleState {
    /// Deterministic epoch id derived from canonical block timestamp.
    pub fn epoch_id(&self, block_timestamp: u64) -> u64 {
        let duration = self.config.epoch_duration_secs.max(1);
        block_timestamp / duration
    }

    /// Queue a committee update for activation at the next epoch boundary.
    pub fn schedule_committee_update(
        &mut self,
        members: Vec<[u8; 32]>,
        current_epoch: u64,
    ) -> Result<(), String> {
        if members.is_empty() {
            return Err("oracle committee must not be empty".to_string());
        }

        let uniq_len = members.iter().copied().collect::<BTreeSet<_>>().len();
        if uniq_len != members.len() {
            return Err("oracle committee must not contain duplicate members".to_string());
        }

        self.committee.pending_update = Some(PendingCommitteeUpdate {
            activate_at_epoch: current_epoch.saturating_add(1),
            members,
        });
        Ok(())
    }

    /// Queue an oracle config update for activation at the next epoch boundary.
    pub fn schedule_config_update(
        &mut self,
        config: OracleConfig,
        current_epoch: u64,
    ) -> Result<(), String> {
        if config.epoch_duration_secs == 0 {
            return Err("oracle epoch duration must be > 0".to_string());
        }
        if config.max_source_age_secs == 0 {
            return Err("oracle max source age must be > 0".to_string());
        }
        if config.max_deviation_bps > 10_000 {
            return Err("oracle max deviation bps must be <= 10000".to_string());
        }
        if config.price_scale == 0 {
            return Err("oracle price scale must be > 0".to_string());
        }

        self.pending_config_update = Some(PendingConfigUpdate {
            activate_at_epoch: current_epoch.saturating_add(1),
            config,
        });
        Ok(())
    }

    /// Apply pending committee/config updates once activation epoch is reached.
    pub fn apply_pending_updates(&mut self, current_epoch: u64) {
        if let Some(pending) = &self.committee.pending_update {
            if current_epoch >= pending.activate_at_epoch {
                self.committee.members = pending.members.clone();
                self.committee.pending_update = None;
            }
        }

        if let Some(pending) = &self.pending_config_update {
            if current_epoch >= pending.activate_at_epoch {
                self.config = pending.config.clone();
                self.pending_config_update = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_threshold_defaults_to_supermajority() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]],
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 3);
    }

    #[test]
    fn committee_threshold_for_small_sets() {
        let committee = OracleCommitteeState {
            members: vec![[1u8; 32], [2u8; 32]],
            pending_update: None,
        };
        assert_eq!(committee.threshold(), 2);
    }

    #[test]
    fn pending_committee_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        state.committee.members = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        state
            .schedule_committee_update(vec![[9u8; 32], [8u8; 32], [7u8; 32]], 12)
            .expect("schedule must succeed");

        state.apply_pending_updates(12);
        assert_eq!(state.committee.members, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);

        state.apply_pending_updates(13);
        assert_eq!(state.committee.members, vec![[9u8; 32], [8u8; 32], [7u8; 32]]);
        assert!(state.committee.pending_update.is_none());
    }

    #[test]
    fn pending_config_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        let mut next = state.config.clone();
        next.max_price_staleness_epochs = 5;
        next.max_deviation_bps = 350;

        state
            .schedule_config_update(next.clone(), 3)
            .expect("schedule must succeed");

        state.apply_pending_updates(3);
        assert_ne!(state.config.max_price_staleness_epochs, 5);
        assert_ne!(state.config.max_deviation_bps, 350);

        state.apply_pending_updates(4);
        assert_eq!(state.config.max_price_staleness_epochs, 5);
        assert_eq!(state.config.max_deviation_bps, 350);
        assert!(state.pending_config_update.is_none());
    }
}
