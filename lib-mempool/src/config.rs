//! Mempool Configuration
//!
//! Limits and thresholds for mempool admission.
//! 
//! Note: The canonical type definition has moved to lib-types.
//! This module provides extension behavior via the MempoolConfigExt trait.

pub use lib_types::mempool::MempoolConfig;
use lib_types::Amount;

/// Extension trait for MempoolConfig with behavior methods
pub trait MempoolConfigExt {
    /// Create a permissive config for testing
    fn for_testing() -> Self;
    /// Calculate the effective minimum fee given the computed fee
    fn effective_min_fee(&self, computed_fee: Amount) -> Amount;
}

impl MempoolConfigExt for MempoolConfig {
    fn for_testing() -> Self {
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

    fn effective_min_fee(&self, computed_fee: Amount) -> Amount {
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
        assert_eq!(config.max_mempool_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_tx_count, 100_000);
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
