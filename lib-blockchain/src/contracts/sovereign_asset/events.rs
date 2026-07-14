//! Sovereign Asset chain events (SA-3 / ADR §6.1).

use serde::{Deserialize, Serialize};

/// Emitted when an [`AssetLaunch`] transaction is applied (ADR §6.1 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetLaunchedEvent {
    pub asset_id: [u8; 32],
    pub module_bitmask: u8,
    pub block_height: u64,
    pub block_time: u64,
    pub symbol: String,
}

impl AssetLaunchedEvent {
    pub fn event_type() -> &'static str {
        "AssetLaunched"
    }
}