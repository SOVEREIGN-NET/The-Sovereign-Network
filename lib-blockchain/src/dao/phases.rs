//! DAO Phase Transition types (dao-3)

use serde::{Deserialize, Serialize};

/// Snapshot of decentralization health metrics at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecentralizationSnapshot {
    /// Number of verified citizens (registered identities).
    pub verified_citizen_count: u64,
    /// Maximum single-wallet SOV holding as basis points of total supply (e.g. 1500 = 15%).
    pub max_wallet_pct_bps: u16,
    /// Block height at which this snapshot was taken.
    pub snapshot_height: u64,
}

/// Configurable thresholds that gate phase advancement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransitionConfig {
    /// Minimum citizen count to allow Bootstrap→Hybrid transition (condition A). Default: 10_000.
    pub min_citizens_for_phase1: u64,
    /// Max single-wallet concentration in bps for Bootstrap→Hybrid (condition B). Default: 1500 (15%).
    pub max_wallet_pct_bps_for_phase1: u16,
    /// If set, Bootstrap phase auto-triggers after this many blocks (condition C).
    pub phase0_max_duration_blocks: Option<u64>,
    /// Minimum citizen count to allow Hybrid→FullDAO transition. Default: 50_000.
    pub min_citizens_for_phase2: u64,
    /// Max single-wallet concentration in bps for Hybrid→FullDAO. Default: 500 (5%).
    pub max_wallet_pct_bps_for_phase2: u16,
    /// Consecutive governance cycles with quorum required before Phase 2. Default: 3.
    pub phase2_quorum_consecutive_cycles: u32,
}

impl Default for PhaseTransitionConfig {
    fn default() -> Self {
        Self {
            min_citizens_for_phase1: 10_000,
            max_wallet_pct_bps_for_phase1: 1_500,
            phase0_max_duration_blocks: None,
            min_citizens_for_phase2: 50_000,
            max_wallet_pct_bps_for_phase2: 500,
            phase2_quorum_consecutive_cycles: 3,
        }
    }
}
