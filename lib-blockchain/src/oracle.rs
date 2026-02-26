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
    #[serde(
        default = "default_price_scale",
        deserialize_with = "deserialize_price_scale"
    )]
    price_scale: u128,
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

fn default_price_scale() -> u128 {
    ORACLE_PRICE_SCALE
}

fn deserialize_price_scale<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u128::deserialize(deserializer)?;
    if value != ORACLE_PRICE_SCALE {
        return Err(serde::de::Error::custom(format!(
            "invalid oracle price_scale {}; expected {}",
            value, ORACLE_PRICE_SCALE
        )));
    }
    Ok(value)
}

impl OracleConfig {
    pub fn price_scale(&self) -> u128 {
        self.price_scale
    }
}

/// Pending governance committee update, activated at an epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCommitteeUpdate {
    /// Epoch where this update becomes active.
    pub activate_at_epoch: u64,
    /// New committee members (validator public keys).
    #[serde(default, deserialize_with = "deserialize_members_sorted_dedup")]
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
    #[serde(default, deserialize_with = "deserialize_members_sorted_dedup")]
    members: Vec<[u8; 32]>,
    /// Pending update, if scheduled.
    pending_update: Option<PendingCommitteeUpdate>,
}

impl OracleCommitteeState {
    pub fn new(members: Vec<[u8; 32]>, pending_update: Option<PendingCommitteeUpdate>) -> Self {
        Self {
            members: normalize_members(members),
            pending_update: normalize_pending_update(pending_update),
        }
    }

    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    pub fn pending_update(&self) -> Option<&PendingCommitteeUpdate> {
        self.pending_update.as_ref()
    }

    pub fn set_members(&mut self, members: Vec<[u8; 32]>) {
        self.members = normalize_members(members);
    }

    pub fn set_pending_update(&mut self, pending_update: Option<PendingCommitteeUpdate>) {
        self.pending_update = normalize_pending_update(pending_update);
    }

    /// Threshold formula: floor(2N/3)+1.
    pub fn threshold(&self) -> u16 {
        let n = self.members.len() as u64;
        let threshold = (2 * n) / 3 + 1;
        threshold.min(u16::MAX as u64) as u16
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
    #[serde(default, deserialize_with = "deserialize_finalized_prices")]
    finalized_prices: BTreeMap<u64, FinalizedOraclePrice>,
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
            members: normalize_members(members),
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
        if config.price_scale() != ORACLE_PRICE_SCALE {
            return Err("oracle price scale must be canonical 1e8".to_string());
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
                self.committee.members = normalize_members(pending.members.clone());
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

    /// Finalize a price for an epoch exactly once.
    ///
    /// Returns `true` if the price was written, `false` if that epoch already has
    /// a finalized price (first-write-wins).
    pub fn try_finalize_price(&mut self, finalized_price: FinalizedOraclePrice) -> bool {
        let epoch_id = finalized_price.epoch_id;
        if self.finalized_prices.contains_key(&epoch_id) {
            return false;
        }
        let winning_price = finalized_price.sov_usd_price;
        self.finalized_prices.insert(epoch_id, finalized_price);
        let epoch_state = self.epoch_state.entry(epoch_id).or_default();
        epoch_state.winning_price = Some(winning_price);
        epoch_state.finalized = true;
        true
    }

    pub fn finalized_price(&self, epoch_id: u64) -> Option<&FinalizedOraclePrice> {
        self.finalized_prices.get(&epoch_id)
    }

    pub fn finalized_prices_len(&self) -> usize {
        self.finalized_prices.len()
    }
}

fn normalize_members(mut members: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    members.sort_unstable();
    members.dedup();
    members
}

fn normalize_pending_update(
    pending_update: Option<PendingCommitteeUpdate>,
) -> Option<PendingCommitteeUpdate> {
    pending_update.map(|mut update| {
        update.members = normalize_members(update.members);
        update
    })
}

fn deserialize_members_sorted_dedup<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let members = Vec::<[u8; 32]>::deserialize(deserializer)?;
    Ok(normalize_members(members))
}

fn deserialize_finalized_prices<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<u64, FinalizedOraclePrice>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = BTreeMap::<u64, FinalizedOraclePrice>::deserialize(deserializer)?;
    for (epoch_key, price) in &map {
        if *epoch_key != price.epoch_id {
            return Err(serde::de::Error::custom(format!(
                "finalized_prices key {} does not match payload epoch_id {}",
                epoch_key, price.epoch_id
            )));
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_threshold_defaults_to_supermajority() {
        let committee =
            OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]], None);
        assert_eq!(committee.threshold(), 3);
    }

    #[test]
    fn committee_threshold_for_small_sets() {
        let committee = OracleCommitteeState::new(vec![[1u8; 32], [2u8; 32]], None);
        assert_eq!(committee.threshold(), 2);
    }

    #[test]
    fn committee_threshold_empty_is_one() {
        let committee = OracleCommitteeState::default();
        assert_eq!(committee.threshold(), 1);
    }

    #[test]
    fn committee_members_are_normalized() {
        let committee = OracleCommitteeState::new(vec![[2u8; 32], [1u8; 32], [2u8; 32]], None);
        assert_eq!(committee.members().len(), 2);
        assert_eq!(committee.members()[0], [1u8; 32]);
        assert_eq!(committee.members()[1], [2u8; 32]);
    }

    #[test]
    fn pending_committee_update_members_are_normalized() {
        let pending = PendingCommitteeUpdate {
            activate_at_epoch: 10,
            members: vec![[3u8; 32], [1u8; 32], [3u8; 32], [2u8; 32]],
        };
        let committee = OracleCommitteeState::new(vec![], Some(pending));
        let pending = committee.pending_update().expect("pending update must be set");
        assert_eq!(pending.members, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
    }

    #[test]
    fn finalize_price_is_first_write_wins_per_epoch() {
        let mut state = OracleState::default();
        let first = FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 100_000_000,
        };
        let second = FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 200_000_000,
        };

        assert!(state.try_finalize_price(first.clone()));
        assert!(
            !state.try_finalize_price(second),
            "second finalized price for same epoch must be rejected"
        );
        assert_eq!(state.finalized_price(7), Some(&first));
    }

    #[test]
    fn finalize_price_allows_distinct_epochs() {
        let mut state = OracleState::default();
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 1,
            sov_usd_price: 100_000_000,
        }));
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 2,
            sov_usd_price: 120_000_000,
        }));
        assert_eq!(state.finalized_prices_len(), 2);
    }

    #[test]
    fn finalize_price_sets_epoch_state_winning_price_and_finalized_flag() {
        let mut state = OracleState::default();
        assert!(state.try_finalize_price(FinalizedOraclePrice {
            epoch_id: 7,
            sov_usd_price: 123_000_000,
        }));
        let epoch_state = state.epoch_state.get(&7).expect("epoch state must exist");
        assert_eq!(epoch_state.winning_price, Some(123_000_000));
        assert!(epoch_state.finalized);
    }

    #[test]
    fn deserialize_rejects_noncanonical_price_scale() {
        let invalid = r#"{
            "epoch_duration_secs":300,
            "max_source_age_secs":60,
            "max_deviation_bps":500,
            "max_price_staleness_epochs":2,
            "price_scale":123
        }"#;
        let err =
            serde_json::from_str::<OracleConfig>(invalid).expect_err("must reject non-1e8 scale");
        assert!(
            err.to_string().contains("invalid oracle price_scale"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn deserialize_rejects_mismatched_finalized_price_epoch_key() {
        let invalid = r#"{
            "finalized_prices": {
                "7": { "epoch_id": 8, "sov_usd_price": 100000000 }
            },
            "epoch_state": {}
        }"#;
        let err =
            serde_json::from_str::<OracleState>(invalid).expect_err("must reject mismatched key");
        assert!(
            err.to_string().contains("does not match payload epoch_id"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn pending_committee_update_activates_at_next_epoch() {
        let mut state = OracleState::default();
        state.committee.set_members(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        state
            .schedule_committee_update(vec![[9u8; 32], [8u8; 32], [7u8; 32]], 12)
            .expect("schedule must succeed");

        state.apply_pending_updates(12);
        assert_eq!(state.committee.members(), &[[1u8; 32], [2u8; 32], [3u8; 32]]);

        state.apply_pending_updates(13);
        assert_eq!(state.committee.members(), &[[7u8; 32], [8u8; 32], [9u8; 32]]);
        assert!(state.committee.pending_update().is_none());
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
