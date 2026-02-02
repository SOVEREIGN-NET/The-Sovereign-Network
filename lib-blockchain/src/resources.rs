//! Block-level Resource Accounting
//!
//! Tracks cumulative resource usage during block execution.
//! Block is rejected if any limit is exceeded.

use crate::execution::errors::BlockApplyError;

/// Limits for block-level resource consumption
#[derive(Debug, Clone, Copy)]
pub struct BlockLimits {
    /// Maximum total payload bytes (serialized tx data)
    pub max_payload_bytes: u64,
    /// Maximum total witness bytes (signatures, proofs)
    pub max_witness_bytes: u64,
    /// Maximum total verification units (signature/proof verification cost)
    pub max_verify_units: u64,
    /// Maximum total state write bytes
    pub max_state_write_bytes: u64,
    /// Maximum transaction count
    pub max_tx_count: u32,
}

impl Default for BlockLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 1_048_576,      // 1 MB
            max_witness_bytes: 524_288,        // 512 KB
            max_verify_units: 1_000_000,       // 1M verify units
            max_state_write_bytes: 2_097_152,  // 2 MB
            max_tx_count: 10_000,              // 10k txs
        }
    }
}

impl BlockLimits {
    /// Create limits suitable for testing (permissive)
    pub fn for_testing() -> Self {
        Self {
            max_payload_bytes: u64::MAX,
            max_witness_bytes: u64::MAX,
            max_verify_units: u64::MAX,
            max_state_write_bytes: u64::MAX,
            max_tx_count: u32::MAX,
        }
    }
}

/// Accumulates resource usage during block execution.
///
/// Updated before each transaction application.
/// Block is rejected if any limit is exceeded.
#[derive(Debug, Clone, Default)]
pub struct BlockAccumulator {
    /// Cumulative payload bytes (serialized tx data)
    pub payload_bytes: u64,
    /// Cumulative witness bytes (signatures, proofs)
    pub witness_bytes: u64,
    /// Cumulative verification units
    pub verify_units: u64,
    /// Cumulative state write bytes
    pub state_write_bytes: u64,
    /// Transaction count
    pub tx_count: u32,
}

impl BlockAccumulator {
    /// Create a new empty accumulator
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the accumulator for a new block
    pub fn reset(&mut self) {
        self.payload_bytes = 0;
        self.witness_bytes = 0;
        self.verify_units = 0;
        self.state_write_bytes = 0;
        self.tx_count = 0;
    }

    /// Add transaction resources to the accumulator.
    ///
    /// Call this BEFORE applying each transaction.
    /// Returns error if any limit would be exceeded.
    pub fn add_tx(
        &mut self,
        limits: &BlockLimits,
        payload_bytes: u64,
        witness_bytes: u64,
        verify_units: u64,
        state_write_bytes: u64,
    ) -> Result<(), BlockApplyError> {
        // Check each limit before accumulating
        let new_payload = self.payload_bytes.saturating_add(payload_bytes);
        if new_payload > limits.max_payload_bytes {
            return Err(BlockApplyError::BlockTooLarge {
                size: new_payload as usize,
                max: limits.max_payload_bytes as usize,
            });
        }

        let new_witness = self.witness_bytes.saturating_add(witness_bytes);
        if new_witness > limits.max_witness_bytes {
            return Err(BlockApplyError::ValidationFailed(format!(
                "witness bytes exceeded: {} > {}",
                new_witness, limits.max_witness_bytes
            )));
        }

        let new_verify = self.verify_units.saturating_add(verify_units);
        if new_verify > limits.max_verify_units {
            return Err(BlockApplyError::ValidationFailed(format!(
                "verify units exceeded: {} > {}",
                new_verify, limits.max_verify_units
            )));
        }

        let new_state_write = self.state_write_bytes.saturating_add(state_write_bytes);
        if new_state_write > limits.max_state_write_bytes {
            return Err(BlockApplyError::ValidationFailed(format!(
                "state write bytes exceeded: {} > {}",
                new_state_write, limits.max_state_write_bytes
            )));
        }

        let new_tx_count = self.tx_count.saturating_add(1);
        if new_tx_count > limits.max_tx_count {
            return Err(BlockApplyError::ValidationFailed(format!(
                "transaction count exceeded: {} > {}",
                new_tx_count, limits.max_tx_count
            )));
        }

        // All checks passed, commit the accumulation
        self.payload_bytes = new_payload;
        self.witness_bytes = new_witness;
        self.verify_units = new_verify;
        self.state_write_bytes = new_state_write;
        self.tx_count = new_tx_count;

        Ok(())
    }

    /// Get current resource usage as a tuple
    pub fn usage(&self) -> (u64, u64, u64, u64, u32) {
        (
            self.payload_bytes,
            self.witness_bytes,
            self.verify_units,
            self.state_write_bytes,
            self.tx_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_add_tx() {
        let limits = BlockLimits {
            max_payload_bytes: 1000,
            max_witness_bytes: 500,
            max_verify_units: 100,
            max_state_write_bytes: 200,
            max_tx_count: 10,
        };

        let mut acc = BlockAccumulator::new();

        // First tx should succeed
        acc.add_tx(&limits, 100, 50, 10, 20).unwrap();
        assert_eq!(acc.payload_bytes, 100);
        assert_eq!(acc.witness_bytes, 50);
        assert_eq!(acc.verify_units, 10);
        assert_eq!(acc.state_write_bytes, 20);
        assert_eq!(acc.tx_count, 1);

        // Second tx should succeed
        acc.add_tx(&limits, 100, 50, 10, 20).unwrap();
        assert_eq!(acc.tx_count, 2);
    }

    #[test]
    fn test_accumulator_payload_limit() {
        let limits = BlockLimits {
            max_payload_bytes: 100,
            max_witness_bytes: u64::MAX,
            max_verify_units: u64::MAX,
            max_state_write_bytes: u64::MAX,
            max_tx_count: u32::MAX,
        };

        let mut acc = BlockAccumulator::new();
        acc.add_tx(&limits, 50, 0, 0, 0).unwrap();

        // This should fail - exceeds payload limit
        let result = acc.add_tx(&limits, 60, 0, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_accumulator_witness_limit() {
        let limits = BlockLimits {
            max_payload_bytes: u64::MAX,
            max_witness_bytes: 100,
            max_verify_units: u64::MAX,
            max_state_write_bytes: u64::MAX,
            max_tx_count: u32::MAX,
        };

        let mut acc = BlockAccumulator::new();
        acc.add_tx(&limits, 0, 50, 0, 0).unwrap();

        // This should fail - exceeds witness limit
        let result = acc.add_tx(&limits, 0, 60, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_accumulator_verify_units_limit() {
        let limits = BlockLimits {
            max_payload_bytes: u64::MAX,
            max_witness_bytes: u64::MAX,
            max_verify_units: 100,
            max_state_write_bytes: u64::MAX,
            max_tx_count: u32::MAX,
        };

        let mut acc = BlockAccumulator::new();
        acc.add_tx(&limits, 0, 0, 50, 0).unwrap();

        // This should fail - exceeds verify units
        let result = acc.add_tx(&limits, 0, 0, 60, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_accumulator_state_write_limit() {
        let limits = BlockLimits {
            max_payload_bytes: u64::MAX,
            max_witness_bytes: u64::MAX,
            max_verify_units: u64::MAX,
            max_state_write_bytes: 100,
            max_tx_count: u32::MAX,
        };

        let mut acc = BlockAccumulator::new();
        acc.add_tx(&limits, 0, 0, 0, 50).unwrap();

        // This should fail - exceeds state write limit
        let result = acc.add_tx(&limits, 0, 0, 0, 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_accumulator_tx_count_limit() {
        let limits = BlockLimits {
            max_payload_bytes: u64::MAX,
            max_witness_bytes: u64::MAX,
            max_verify_units: u64::MAX,
            max_state_write_bytes: u64::MAX,
            max_tx_count: 2,
        };

        let mut acc = BlockAccumulator::new();
        acc.add_tx(&limits, 0, 0, 0, 0).unwrap();
        acc.add_tx(&limits, 0, 0, 0, 0).unwrap();

        // Third tx should fail
        let result = acc.add_tx(&limits, 0, 0, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_accumulator_reset() {
        let limits = BlockLimits::for_testing();
        let mut acc = BlockAccumulator::new();

        acc.add_tx(&limits, 100, 50, 10, 20).unwrap();
        assert_eq!(acc.tx_count, 1);

        acc.reset();
        assert_eq!(acc.payload_bytes, 0);
        assert_eq!(acc.witness_bytes, 0);
        assert_eq!(acc.verify_units, 0);
        assert_eq!(acc.state_write_bytes, 0);
        assert_eq!(acc.tx_count, 0);
    }
}
