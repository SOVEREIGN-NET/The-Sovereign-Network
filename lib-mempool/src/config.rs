//! Mempool Configuration
//!
//! Limits and thresholds for mempool admission.

use serde::{Deserialize, Serialize};
use lib_types::Amount;

/// Configuration for mempool admission checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    // =========================================================================
    // Size Limits
    // =========================================================================
    /// Maximum total mempool size in bytes
    pub max_mempool_bytes: u64,
    /// Maximum number of transactions in mempool
    pub max_tx_count: u32,
    /// Maximum transactions per sender address
    pub max_per_sender: u32,

    // =========================================================================
    // Transaction Limits
    // =========================================================================
    /// Maximum transaction size in bytes
    pub max_tx_bytes: u32,
    /// Maximum witness size per transaction in bytes
    pub max_witness_bytes: u32,
    /// Maximum number of signatures per transaction
    pub max_signatures: u8,
    /// Maximum number of inputs per transaction
    pub max_inputs: u16,
    /// Maximum number of outputs per transaction
    pub max_outputs: u16,

    // =========================================================================
    // Fee Thresholds
    // =========================================================================
    /// Minimum fee multiplier (1.0 = exact minimum, 1.1 = 10% above)
    /// Stored as basis points: 10000 = 1.0x, 11000 = 1.1x
    pub min_fee_multiplier_bps: u16,

    // =========================================================================
    // Rate Limiting
    // =========================================================================
    /// Maximum transactions per sender per block period
    pub max_per_sender_per_period: u32,
    /// Rate limit period in blocks
    pub rate_limit_period_blocks: u32,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            // Size limits
            max_mempool_bytes: 50 * 1024 * 1024, // 50 MB
            max_tx_count: 50_000,
            max_per_sender: 100,

            // Transaction limits
            max_tx_bytes: 100_000,      // 100 KB max tx
            max_witness_bytes: 50_000,  // 50 KB witness
            max_signatures: 16,
            max_inputs: 256,
            max_outputs: 256,

            // Fee thresholds
            min_fee_multiplier_bps: 10_000, // 1.0x (exact minimum)

            // Rate limiting
            max_per_sender_per_period: 10,
            rate_limit_period_blocks: 10,
        }
    }
}

impl MempoolConfig {
    /// Create a permissive config for testing
    pub fn for_testing() -> Self {
        Self {
            max_mempool_bytes: u64::MAX,
            max_tx_count: u32::MAX,
            max_per_sender: u32::MAX,
            max_tx_bytes: u32::MAX,
            max_witness_bytes: u32::MAX,
            max_signatures: u8::MAX,
            max_inputs: u16::MAX,
            max_outputs: u16::MAX,
            min_fee_multiplier_bps: 10_000,
            max_per_sender_per_period: u32::MAX,
            rate_limit_period_blocks: 1,
        }
    }

    /// Calculate the effective minimum fee given the computed fee
    pub fn effective_min_fee(&self, computed_fee: Amount) -> Amount {
        // Apply multiplier: fee * multiplier_bps / 10000
        computed_fee
            .saturating_mul(self.min_fee_multiplier_bps as Amount)
            / 10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MempoolConfig::default();
        assert_eq!(config.max_mempool_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_tx_count, 50_000);
        assert_eq!(config.min_fee_multiplier_bps, 10_000);
    }

    #[test]
    fn test_effective_min_fee() {
        let mut config = MempoolConfig::default();

        // 1.0x multiplier
        config.min_fee_multiplier_bps = 10_000;
        assert_eq!(config.effective_min_fee(1000), 1000);

        // 1.5x multiplier
        config.min_fee_multiplier_bps = 15_000;
        assert_eq!(config.effective_min_fee(1000), 1500);

        // 2.0x multiplier
        config.min_fee_multiplier_bps = 20_000;
        assert_eq!(config.effective_min_fee(1000), 2000);
    }
}
