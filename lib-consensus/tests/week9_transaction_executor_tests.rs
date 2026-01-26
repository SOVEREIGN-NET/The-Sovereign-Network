//! Week 9: Transaction Execution Layer Integration Tests
//!
//! Tests for mempool, transaction executor, and consensus integration.
//! Validates fee extraction, priority-based selection, and consensus finalization.

#[cfg(test)]
mod transaction_executor_tests {
    use lib_consensus::{Mempool, MempoolTransaction};
    use lib_consensus::engines::{TransactionExecutor, BlockExecutionContext};

    #[test]
    fn test_mempool_add_and_remove() {
        let mut mempool = Mempool::new(100, 1000);
        let tx_hash = [1u8; 32];

        // Add transaction
        assert!(mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000).is_ok());
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.total_pending_fees(), 1000);

        // Remove transaction
        let removed = mempool.remove_transaction(&tx_hash);
        assert!(removed.is_some());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_pending_fees(), 0);
    }

    #[test]
    fn test_mempool_priority_selection() {
        let mut mempool = Mempool::new(100, 1000);

        // Add transactions with different fees
        mempool.add_transaction([1u8; 32], 100, 100, 100, 1000000).ok();
        mempool.add_transaction([2u8; 32], 1000, 100, 100, 1000000).ok(); // High fee
        mempool.add_transaction([3u8; 32], 500, 100, 100, 1000000).ok();

        // Select top 2 by priority
        let selected = mempool.select_transactions(2, 100);
        assert_eq!(selected.len(), 2);

        // High-fee transaction should be in selection
        assert!(selected.contains(&[2u8; 32]));
    }

    #[test]
    fn test_transaction_executor_creation() {
        let executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);
        assert_eq!(executor.get_mempool_size(), 0);
        assert_eq!(executor.get_mempool_stats().transaction_count, 0);
    }

    #[test]
    fn test_transaction_executor_prepare_block() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        // Add transactions to mempool
        executor.mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        executor.mempool.add_transaction([2u8; 32], 500, 100, 100, 1000000).ok();
        executor.mempool.add_transaction([3u8; 32], 300, 150, 100, 1000000).ok();

        // Prepare block
        let (selected, total_fees, total_size) = executor.prepare_block_transactions(100);

        assert!(selected.len() > 0);
        assert!(total_fees > 0);
        assert!(total_size > 0);

        // Verify total fees match sum of selected
        let expected_fees: u64 = selected
            .iter()
            .filter_map(|tx_hash| {
                executor.mempool.get_transaction(tx_hash).map(|tx| tx.fee)
            })
            .sum();
        assert_eq!(total_fees, expected_fees);
    }

    #[test]
    fn test_transaction_executor_execute_transactions() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        // Add transaction to mempool
        executor.mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();

        // Execute transaction
        let (total_fees, results) = executor.execute_transactions(&[[1u8; 32]], 100);

        assert_eq!(total_fees, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].fee, 1000);
    }

    #[test]
    fn test_transaction_executor_finalize_block() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        // Add transaction to mempool
        executor.mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        assert_eq!(executor.get_mempool_size(), 1);

        // Finalize block (remove from mempool)
        executor.finalize_block_execution(&[[1u8; 32]]);
        assert_eq!(executor.get_mempool_size(), 0);
    }

    #[test]
    fn test_mempool_eviction() {
        let mut mempool = Mempool::new(100, 10); // 10 block max age

        // Add transaction
        mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        assert_eq!(mempool.size(), 1);

        // Evict expired transactions (block 115 > 100 + 10)
        let evicted = mempool.evict_expired(115);
        assert_eq!(evicted, 1);
        assert_eq!(mempool.size(), 0);
    }

    #[test]
    fn test_block_execution_context() {
        let proposer = [1u8; 32];
        let mut ctx = BlockExecutionContext::new(100, proposer);

        // Add transactions
        ctx.include_transaction([1u8; 32], 1000, "transfer");
        ctx.include_transaction([2u8; 32], 500, "ubi_claim");

        assert_eq!(ctx.total_fees, 1500);
        assert_eq!(ctx.transaction_hashes.len(), 2);
        assert_eq!(ctx.get_fees_for_type("transfer"), 1000);
        assert_eq!(ctx.get_fees_for_type("ubi_claim"), 500);
    }

    #[test]
    fn test_mempool_statistics() {
        let mut mempool = Mempool::new(100, 1000);

        mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        mempool.add_transaction([2u8; 32], 500, 150, 100, 1000000).ok();

        let stats = mempool.stats();
        assert_eq!(stats.transaction_count, 2);
        assert_eq!(stats.total_fees, 1500);
        assert_eq!(stats.min_fee, 500);
        assert_eq!(stats.max_fee, 1000);
        assert_eq!(stats.avg_fee, 750);
    }

    #[test]
    fn test_transaction_priority_calculation() {
        // Test priority score increases with age
        let tx = MempoolTransaction {
            tx_hash: [1u8; 32],
            fee: 1000,
            size: 100,
            received_at_height: 100,
            received_at_time: 1000000,
            retry_count: 0,
        };

        let priority_at_100 = tx.priority_score(100);
        let priority_at_110 = tx.priority_score(110); // 10 blocks later

        // Older transactions should have higher priority (age bonus)
        assert!(priority_at_110 > priority_at_100);
    }

    #[test]
    fn test_mempool_duplicate_prevention() {
        let mut mempool = Mempool::new(100, 1000);
        let tx_hash = [1u8; 32];

        // Add transaction
        assert!(mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000).is_ok());

        // Try to add duplicate
        let result = mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in mempool"));
    }

    #[test]
    fn test_mempool_capacity_enforcement() {
        let mut mempool = Mempool::new(2, 1000); // Capacity 2

        // Add 2 transactions
        mempool.add_transaction([1u8; 32], 1000, 200, 100, 1000000).ok();
        mempool.add_transaction([2u8; 32], 500, 100, 100, 1000000).ok();
        assert_eq!(mempool.size(), 2);

        // Try to add 3rd (should fail)
        let result = mempool.add_transaction([3u8; 32], 300, 150, 100, 1000000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("full"));
    }

    #[test]
    fn test_transaction_executor_pending_check() {
        let mut executor = TransactionExecutor::new(100, 1_000_000, 1000, 1000);

        let tx_hash = [1u8; 32];
        executor.mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000).ok();

        // Check if transaction is pending
        assert!(executor.is_pending(&tx_hash));

        // Remove and check again
        executor.mempool.remove_transaction(&tx_hash);
        assert!(!executor.is_pending(&tx_hash));
    }

    #[test]
    fn test_mempool_fee_per_byte_priority() {
        let mut mempool = Mempool::new(100, 1000);

        // Low fee, small tx: fee/byte = 1000/100 = 10
        mempool.add_transaction([1u8; 32], 1000, 100, 100, 1000000).ok();

        // High fee, large tx: fee/byte = 1000/200 = 5
        mempool.add_transaction([2u8; 32], 1000, 200, 100, 1000000).ok();

        // First transaction should have higher priority (higher fee/byte)
        let tx1_priority = mempool.get_transaction(&[1u8; 32]).unwrap().priority_score(100);
        let tx2_priority = mempool.get_transaction(&[2u8; 32]).unwrap().priority_score(100);

        assert!(tx1_priority > tx2_priority);
    }

    #[test]
    fn test_mempool_selection_respects_size_limit() {
        let mut executor = TransactionExecutor::new(5, 500, 1000, 1000); // Max 5 txs, 500 bytes

        // Add transactions
        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            executor
                .mempool
                .add_transaction(hash, 100 + i as u64, 60, 100, 1000000)
                .ok();
        }

        // Prepare block with size constraint
        let (selected, _, total_size) = executor.prepare_block_transactions(100);

        assert!(selected.len() <= 5); // Max 5 transactions
        assert!(total_size <= 500); // Max 500 bytes
    }

    #[test]
    fn test_consensus_block_execution_context_fees() {
        let proposer = [1u8; 32];
        let mut ctx = BlockExecutionContext::new(100, proposer);

        // Simulate mixed transaction types
        for i in 0..100 {
            ctx.include_transaction([i; 32], 100 + i as u64, "transfer");
        }
        for i in 0..50 {
            ctx.include_transaction([100 + i; 32], 200 + i as u64, "ubi_claim");
        }

        // Verify totals
        let expected_transfer_fees: u64 = (0..100).map(|i| 100 + i).sum();
        let expected_ubi_fees: u64 = (0..50).map(|i| 200 + i).sum();
        let expected_total = expected_transfer_fees + expected_ubi_fees;

        assert_eq!(ctx.get_fees_for_type("transfer"), expected_transfer_fees);
        assert_eq!(ctx.get_fees_for_type("ubi_claim"), expected_ubi_fees);
        assert_eq!(ctx.total_fees, expected_total);
    }
}
