use serde::{Deserialize, Serialize};

/// Governance-configurable fee parameters for the legacy size-based fee model.
///
/// Formula:
/// fee = base_fee + ceil(effective_size / bytes_per_sov)
/// effective_size = payload_bytes + min(witness_bytes, witness_cap)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxFeeConfig {
    /// Fixed base fee (in atomic units)
    pub base_fee: u64,
    /// Bytes per 1 SOV unit (fee slope)
    pub bytes_per_sov: u64,
    /// Witness bytes cap applied to fee calculation
    pub witness_cap: u32,
}

impl Default for TxFeeConfig {
    fn default() -> Self {
        Self {
            base_fee: 100,
            bytes_per_sov: 100,
            witness_cap: 500,
        }
    }
}
