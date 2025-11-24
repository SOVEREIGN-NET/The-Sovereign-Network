use serde::{Deserialize, Serialize};
use lib_crypto::PublicKey;
use crate::types::relay_type::LongRangeRelayType;

/// Long-range relay for extending mesh network reach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongRangeRelay {
    /// Relay identifier
    pub relay_id: String,
    /// Relay type (LoRaWAN, Satellite, Cellular)
    pub relay_type: LongRangeRelayType,
    /// Geographic coverage area
    pub coverage_radius_km: f64,
    /// Maximum throughput
    pub max_throughput_mbps: u32,
    /// Cost per MB for relay usage
    pub cost_per_mb_tokens: u64,
    /// Relay operator's public key
    pub operator: PublicKey,
    /// Revenue sharing percentage for UBI
    pub ubi_share_percentage: f32,
}
