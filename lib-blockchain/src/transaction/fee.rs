use serde::{Deserialize, Serialize};

pub const DEFAULT_TX_BASE_FEE: u64 = 100;
pub const DEFAULT_TX_BYTES_PER_SOV: u64 = 100;
pub const DEFAULT_TX_WITNESS_CAP: u32 = 500;
pub const DEFAULT_TOKEN_CREATION_FEE: u64 = 1_000;

fn default_token_creation_fee() -> u64 {
    DEFAULT_TOKEN_CREATION_FEE
}

/// Governance-configurable fee parameters for the legacy size-based fee model.
///
/// Formula:
/// fee = base_fee + ceil(effective_size / bytes_per_sov)
/// effective_size = payload_bytes + min(witness_bytes, witness_cap)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TxFeeConfig {
    /// Fixed base fee (in atomic units)
    pub base_fee: u64,
    /// Bytes per 1 SOV unit (fee slope)
    pub bytes_per_sov: u64,
    /// Witness bytes cap applied to fee calculation
    pub witness_cap: u32,
    /// Fixed DAO-governed fee for canonical TokenCreation transactions
    #[serde(default = "default_token_creation_fee")]
    pub token_creation_fee: u64,
}

impl Default for TxFeeConfig {
    fn default() -> Self {
        Self {
            base_fee: DEFAULT_TX_BASE_FEE,
            bytes_per_sov: DEFAULT_TX_BYTES_PER_SOV,
            witness_cap: DEFAULT_TX_WITNESS_CAP,
            token_creation_fee: DEFAULT_TOKEN_CREATION_FEE,
        }
    }
}

pub fn required_token_creation_fee(config: &TxFeeConfig) -> u64 {
    config.token_creation_fee
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_fee_config_deserializes_missing_token_creation_fee_with_default() {
        let json = r#"{"base_fee":123,"bytes_per_sov":45,"witness_cap":67}"#;

        let fee_config: TxFeeConfig = serde_json::from_str(json).unwrap();

        assert_eq!(fee_config.base_fee, 123);
        assert_eq!(fee_config.bytes_per_sov, 45);
        assert_eq!(fee_config.witness_cap, 67);
        assert_eq!(fee_config.token_creation_fee, DEFAULT_TOKEN_CREATION_FEE);
    }
}
