//! # Gas and Execution Limits [BFT-A][R3]
//!
//! ## Invariant
//! All execution limits MUST be enforced as hard bounds during block validation.
//! Blocks exceeding these limits MUST be rejected by all validators.

/// Maximum gas units per transaction.
/// Prevents single transactions from monopolizing block resources.
pub const MAX_TX_GAS: u64 = 10_000_000;

/// Maximum total gas per block.
/// Ensures blocks can be validated within the consensus round timeout.
pub const MAX_BLOCK_GAS: u64 = 100_000_000;

/// Maximum number of transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 10_000;

/// Maximum block size in bytes (excludes consensus metadata).
pub const MAX_BLOCK_SIZE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum execution depth (call stack) for contract calls.
pub const MAX_EXECUTION_DEPTH: u32 = 128;

/// Maximum script size in bytes for transaction scripts.
pub const MAX_SCRIPT_SIZE_BYTES: usize = 10_240; // 10 KiB

/// Returns an error if block transaction count exceeds MAX_TXS_PER_BLOCK.
///
/// Replaces the previous `assert_block_tx_limit` (which used `debug_assert` and
/// was therefore silently skipped in release builds). This version performs a
/// runtime check in all build configurations and returns a typed error so
/// callers can handle the violation gracefully.
pub fn check_block_tx_count(tx_count: usize) -> Result<(), String> {
    if tx_count > MAX_TXS_PER_BLOCK {
        return Err(format!(
            "BFT invariant violated: block contains {} transactions, max is {}",
            tx_count, MAX_TXS_PER_BLOCK
        ));
    }
    Ok(())
}

/// Returns an error if block size exceeds the limit.
pub fn check_block_size(size_bytes: usize) -> Result<(), String> {
    if size_bytes > MAX_BLOCK_SIZE_BYTES {
        return Err(format!(
            "Block size {} bytes exceeds maximum {} bytes",
            size_bytes, MAX_BLOCK_SIZE_BYTES
        ));
    }
    Ok(())
}

/// Returns an error if transaction gas exceeds the per-tx limit.
pub fn check_tx_gas(gas: u64) -> Result<(), String> {
    if gas > MAX_TX_GAS {
        return Err(format!(
            "Transaction gas {} exceeds maximum {} per transaction",
            gas, MAX_TX_GAS
        ));
    }
    Ok(())
}

/// Returns an error if total block gas exceeds the per-block limit.
pub fn check_block_gas(total_gas: u64) -> Result<(), String> {
    if total_gas > MAX_BLOCK_GAS {
        return Err(format!(
            "Block gas {} exceeds limit {}",
            total_gas, MAX_BLOCK_GAS
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_limit_constants_are_consistent() {
        assert!(MAX_TX_GAS < MAX_BLOCK_GAS,
            "Per-tx gas must be less than per-block gas");
        assert!(MAX_BLOCK_GAS > 0, "Block gas limit must be positive");
        assert!(MAX_TXS_PER_BLOCK > 0, "Max txs per block must be positive");
    }

    #[test]
    fn test_check_tx_gas_accepts_valid() {
        assert!(check_tx_gas(0).is_ok());
        assert!(check_tx_gas(MAX_TX_GAS).is_ok());
    }

    #[test]
    fn test_check_tx_gas_rejects_over_limit() {
        assert!(check_tx_gas(MAX_TX_GAS + 1).is_err());
    }

    #[test]
    fn test_check_block_size_accepts_valid() {
        assert!(check_block_size(0).is_ok());
        assert!(check_block_size(MAX_BLOCK_SIZE_BYTES).is_ok());
    }

    #[test]
    fn test_check_block_size_rejects_over_limit() {
        assert!(check_block_size(MAX_BLOCK_SIZE_BYTES + 1).is_err());
    }

    #[test]
    fn test_block_gas_accommodates_one_tx() {
        assert!(
            MAX_BLOCK_GAS >= MAX_TX_GAS,
            "Block gas limit must accommodate at least one max-gas transaction"
        );
    }
}
