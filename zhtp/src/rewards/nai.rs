//! Network Activity Index (NAI) — dynamic epoch pool sizing.
//!
//! Computed once per epoch from on-chain state. No oracle, no external inputs.
//! The NAI multiplier scales the per-epoch PoUW reward pool based on network
//! activity: bonding curve inflows, new registrations, transaction volume.

use serde::{Deserialize, Serialize};

// ── Protocol constants (governance-adjustable via canonical.rs in future) ─────

/// Scale factor for bonding curve reserve delta component.
pub const CURVE_SCALE_FACTOR: u128 = 1_000_000_000_000_000_000; // 1 SOV
/// Scale factor for new registration component.
pub const REGISTRATION_SCALE_FACTOR: u128 = 100;
/// Scale factor for transaction count component.
pub const TX_SCALE_FACTOR: u128 = 10_000;
/// Hard cap on NAI multiplier — protocol constant, never exceeded.
pub const MAX_NAI_MULTIPLIER: f64 = 3.0;
/// Minimum per-node cap (atoms) — floor even when NAI is low.
pub const MIN_PER_NODE_CAP: u128 = 1_000_000_000_000; // 0.000001 SOV
/// Maximum per-node cap (atoms) — ceiling even when NAI is high.
pub const MAX_PER_NODE_CAP: u128 = 1_000_000_000_000_000_000; // 1 SOV

/// DEV_GRANT_POOL lifetime ceiling — 100B SOV in atoms.
/// After PoUW sub-budget (2.1M SOV) exhausts, rewards continue from this
/// broader pool as long as NAI justifies them.
pub const DEV_GRANT_POOL_CEILING: u128 = lib_types::sov::atoms(100_000_000_000); // 100B SOV

/// Snapshot of on-chain activity for one epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkActivityIndex {
    /// SOV added to bonding curve reserve this epoch (pre-graduation).
    /// Post-graduation: transaction fee volume this epoch (same slot, same weight).
    pub bonding_curve_reserve_delta: u128,
    /// New DIDs registered this epoch.
    pub new_registrations: u64,
    /// Total transactions this epoch.
    pub transaction_count: u64,
    /// Nodes that submitted PoUW receipts this epoch.
    pub active_node_count: u64,
    /// Whether the bonding curve has graduated.
    /// When true, bonding_curve_reserve_delta is populated with tx fee volume instead.
    pub graduated: bool,
}

impl NetworkActivityIndex {
    /// Compute NAI from chain state for a given epoch.
    ///
    /// All inputs come from on-chain state — no external feeds.
    /// Pre-graduation: `value_delta` is bonding curve reserve SOV added this epoch.
    /// Post-graduation: `value_delta` is transaction fee volume this epoch.
    /// Same slot, same weight in the multiplier formula.
    pub fn compute(
        value_delta: u128,
        new_registrations: u64,
        transaction_count: u64,
        active_node_count: u64,
        graduated: bool,
    ) -> Self {
        Self {
            bonding_curve_reserve_delta: value_delta,
            new_registrations,
            transaction_count,
            active_node_count,
            graduated,
        }
    }

    /// Compute the NAI multiplier (1.0 = baseline, capped at MAX_NAI_MULTIPLIER).
    pub fn multiplier(&self) -> f64 {
        let base = 1.0_f64;

        let curve_component = if CURVE_SCALE_FACTOR > 0 {
            self.bonding_curve_reserve_delta as f64 / CURVE_SCALE_FACTOR as f64
        } else {
            0.0
        };

        let reg_component = if REGISTRATION_SCALE_FACTOR > 0 {
            self.new_registrations as f64 / REGISTRATION_SCALE_FACTOR as f64
        } else {
            0.0
        };

        let tx_component = if TX_SCALE_FACTOR > 0 {
            self.transaction_count as f64 / TX_SCALE_FACTOR as f64
        } else {
            0.0
        };

        (base + curve_component + reg_component + tx_component).min(MAX_NAI_MULTIPLIER)
    }

    /// Compute the dynamic epoch pool given a base pool size.
    pub fn epoch_pool(&self, base_pool: u128) -> u128 {
        let multiplied = base_pool as f64 * self.multiplier();
        multiplied as u128
    }

    /// Compute the per-node cap for this epoch.
    pub fn per_node_cap(&self, base_pool: u128) -> u128 {
        let pool = self.epoch_pool(base_pool);
        let nodes = (self.active_node_count as u128).max(1);
        let raw_cap = pool / nodes;
        raw_cap.max(MIN_PER_NODE_CAP).min(MAX_PER_NODE_CAP)
    }
}

/// Persisted epoch state — tracks dynamic pool and per-node accumulators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochState {
    /// Current epoch number.
    pub epoch: u64,
    /// NAI snapshot for this epoch.
    pub nai: NetworkActivityIndex,
    /// Dynamic epoch pool (base × NAI multiplier).
    pub epoch_pool: u128,
    /// Per-node cap for this epoch.
    pub per_node_cap: u128,
    /// Per-node accumulated rewards this epoch (DID hex → atoms paid).
    pub per_node_paid: std::collections::HashMap<String, u128>,
}

impl EpochState {
    pub fn new(epoch: u64, base_pool: u128, nai: NetworkActivityIndex) -> Self {
        let epoch_pool = nai.epoch_pool(base_pool);
        let per_node_cap = nai.per_node_cap(base_pool);
        Self {
            epoch,
            nai,
            epoch_pool,
            per_node_cap,
            per_node_paid: std::collections::HashMap::new(),
        }
    }

    /// Check if a node can receive more rewards this epoch.
    pub fn can_pay_node(&self, did: &str, amount: u128) -> bool {
        let paid = self.per_node_paid.get(did).copied().unwrap_or(0);
        paid + amount <= self.per_node_cap
    }

    /// Record a payment to a node.
    pub fn record_node_payment(&mut self, did: &str, amount: u128) {
        *self.per_node_paid.entry(did.to_string()).or_insert(0) += amount;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_multiplier() {
        let nai = NetworkActivityIndex::default();
        assert!((nai.multiplier() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_multiplier_capped() {
        let nai = NetworkActivityIndex {
            bonding_curve_reserve_delta: u128::MAX,
            new_registrations: u64::MAX,
            transaction_count: u64::MAX,
            active_node_count: 1,
            graduated: false,
        };
        assert!(nai.multiplier() <= MAX_NAI_MULTIPLIER);
    }

    #[test]
    fn test_per_node_cap_bounds() {
        let nai = NetworkActivityIndex {
            active_node_count: 1,
            ..Default::default()
        };
        let base_pool = 1_000_000_000_000_000_000_000u128; // 1000 SOV
        let cap = nai.per_node_cap(base_pool);
        assert!(cap >= MIN_PER_NODE_CAP);
        assert!(cap <= MAX_PER_NODE_CAP);
    }

    #[test]
    fn test_epoch_state_node_tracking() {
        let nai = NetworkActivityIndex {
            active_node_count: 10,
            ..Default::default()
        };
        let mut state = EpochState::new(0, 100_000_000_000_000_000_000u128, nai);
        assert!(state.can_pay_node("did:zhtp:abc", 1_000));
        state.record_node_payment("did:zhtp:abc", 1_000);
        assert_eq!(state.per_node_paid.get("did:zhtp:abc"), Some(&1_000));
    }
}
