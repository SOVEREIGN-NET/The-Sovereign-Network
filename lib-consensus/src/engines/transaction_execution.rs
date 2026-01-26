//! Transaction Execution Layer
//!
//! Handles transaction inclusion in blocks, fee extraction, and execution.
//! Replaces Week 7's BlockMetadata stub with actual transaction processing.
//!
//! Week 9: Full transaction execution integration

use crate::mempool::Mempool;
use lib_identity::IdentityId;

/// Block execution context
#[derive(Debug, Clone)]
pub struct BlockExecutionContext {
    /// Height of the block being executed
    pub height: u64,
    /// Proposer of the block
    pub proposer: IdentityId,
    /// Transactions included in this block
    pub transaction_hashes: Vec<[u8; 32]>,
    /// Total fees collected from transactions
    pub total_fees: u64,
    /// Fees collected per transaction type
    pub fees_by_type: std::collections::HashMap<String, u64>,
}

/// Transaction execution result
#[derive(Debug, Clone)]
pub struct TransactionExecutionResult {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Fee paid by this transaction
    pub fee: u64,
    /// Whether transaction executed successfully
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl BlockExecutionContext {
    /// Create new execution context
    pub fn new(height: u64, proposer: IdentityId) -> Self {
        Self {
            height,
            proposer,
            transaction_hashes: Vec::new(),
            total_fees: 0,
            fees_by_type: std::collections::HashMap::new(),
        }
    }

    /// Add transaction to block
    pub fn include_transaction(&mut self, tx_hash: [u8; 32], fee: u64, tx_type: &str) {
        self.transaction_hashes.push(tx_hash);
        self.total_fees = self.total_fees.saturating_add(fee);
        *self.fees_by_type.entry(tx_type.to_string()).or_insert(0) += fee;
    }

    /// Get fees collected for a transaction type
    pub fn get_fees_for_type(&self, tx_type: &str) -> u64 {
        self.fees_by_type.get(tx_type).copied().unwrap_or(0)
    }
}

/// Transaction execution engine
#[derive(Debug)]
pub struct TransactionExecutor {
    /// Mempool for pending transactions
    pub mempool: Mempool,
    /// Maximum transactions per block
    pub max_transactions_per_block: usize,
    /// Maximum block size in bytes
    pub max_block_size_bytes: u64,
}

impl TransactionExecutor {
    /// Create new transaction executor
    pub fn new(
        max_transactions_per_block: usize,
        max_block_size_bytes: u64,
        mempool_max_size: usize,
        mempool_max_age: u64,
    ) -> Self {
        Self {
            mempool: Mempool::new(mempool_max_size, mempool_max_age),
            max_transactions_per_block,
            max_block_size_bytes,
        }
    }

    /// Prepare transactions for block proposal
    /// Selects highest-priority transactions that fit in the block
    pub fn prepare_block_transactions(
        &mut self,
        current_height: u64,
    ) -> (Vec<[u8; 32]>, u64, usize) {
        // Clean expired transactions first
        let evicted = self.mempool.evict_expired(current_height);
        if evicted > 0 {
            tracing::debug!("Evicted {} expired transactions from mempool", evicted);
        }

        // Select transactions by priority
        let selected = self.mempool.select_transactions(
            self.max_transactions_per_block,
            current_height,
        );

        // Calculate total fees and size for selected transactions
        let mut total_fees = 0u64;
        let mut total_size = 0usize;

        for tx_hash in &selected {
            if let Some(tx) = self.mempool.get_transaction(tx_hash) {
                total_fees = total_fees.saturating_add(tx.fee);
                total_size = total_size.saturating_add(tx.size as usize);

                // Stop if block would exceed size limit
                if total_size as u64 > self.max_block_size_bytes {
                    break;
                }
            }
        }

        (selected, total_fees, total_size)
    }

    /// Execute transactions and collect fees
    pub fn execute_transactions(
        &self,
        tx_hashes: &[[u8; 32]],
        _current_height: u64,
    ) -> (u64, Vec<TransactionExecutionResult>) {
        let mut total_fees = 0u64;
        let mut results = Vec::new();

        for tx_hash in tx_hashes {
            if let Some(tx) = self.mempool.get_transaction(tx_hash) {
                // In Week 9, we extract the fee from the transaction
                // In Week 10+, we'll validate inputs, execute contract logic, etc.
                total_fees = total_fees.saturating_add(tx.fee);

                results.push(TransactionExecutionResult {
                    tx_hash: *tx_hash,
                    fee: tx.fee,
                    success: true,
                    error: None,
                });
            } else {
                results.push(TransactionExecutionResult {
                    tx_hash: *tx_hash,
                    fee: 0,
                    success: false,
                    error: Some("Transaction not found in mempool".to_string()),
                });
            }
        }

        (total_fees, results)
    }

    /// Finalize block execution (remove from mempool, update state)
    pub fn finalize_block_execution(&mut self, tx_hashes: &[[u8; 32]]) {
        for tx_hash in tx_hashes {
            self.mempool.remove_transaction(tx_hash);
        }
    }

    /// Get mempool statistics
    pub fn get_mempool_stats(&self) -> crate::mempool::MempoolStats {
        self.mempool.stats()
    }

    /// Get mempool size
    pub fn get_mempool_size(&self) -> usize {
        self.mempool.size()
    }

    /// Check if transaction is pending
    pub fn is_pending(&self, tx_hash: &[u8; 32]) -> bool {
        self.mempool.contains(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_execution_context() {
        let proposer = IdentityId::from(lib_crypto::Hash::from_bytes(&[1u8; 32]));
        let mut ctx = BlockExecutionContext::new(100, proposer);

        ctx.include_transaction([1u8; 32], 1000, "transfer");
        ctx.include_transaction([2u8; 32], 500, "ubi_claim");

        assert_eq!(ctx.total_fees, 1500);
        assert_eq!(ctx.transaction_hashes.len(), 2);
        assert_eq!(ctx.get_fees_for_type("transfer"), 1000);
        assert_eq!(ctx.get_fees_for_type("ubi_claim"), 500);
    }

    #[test]
    fn test_transaction_executor() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        // Add transactions to mempool
        executor.mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        executor.mempool.add_transaction([2u8; 32], 500, 100, 100, 1000000).ok();

        // Prepare block
        let (selected, fees, size) = executor.prepare_block_transactions(100);

        assert!(selected.len() > 0);
        assert!(fees > 0);
        assert!(size > 0);
    }

    #[test]
    fn test_transaction_execution() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        executor.mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();

        let (total_fees, results) = executor.execute_transactions(&[[1u8; 32]], 100);

        assert_eq!(total_fees, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].fee, 1000);
    }
}
