//! Transaction Mempool and Pool Management
//!
//! Manages pending transactions waiting to be included in blocks.
//! Implements priority-based transaction selection for block proposal.
//!
//! Week 9: Full transaction execution layer foundation

use std::collections::{HashMap, BinaryHeap};
use std::cmp::Ordering;
use serde::{Serialize, Deserialize};

/// Transaction wrapper with metadata for priority calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolTransaction {
    /// Unique transaction hash
    pub tx_hash: [u8; 32],
    /// Transaction fee (for priority calculation)
    pub fee: u64,
    /// Transaction size in bytes (for fee per byte calculation)
    pub size: u32,
    /// Block height when tx was added
    pub received_at_height: u64,
    /// Timestamp when tx was added (milliseconds)
    pub received_at_time: u64,
    /// Number of times this transaction has been in a failed block
    pub retry_count: u32,
}

impl MempoolTransaction {
    /// Calculate priority score for transaction selection
    ///
    /// Priority = (fee per byte) * (age bonus) * (retry penalty reduction)
    /// Higher score = higher priority
    pub fn priority_score(&self, current_height: u64) -> u128 {
        let fee_per_byte = if self.size > 0 {
            (self.fee as u128 * 1000) / (self.size as u128) // Scaled to avoid floating point
        } else {
            0
        };

        let age_blocks = current_height.saturating_sub(self.received_at_height) as u128;
        let age_bonus = 1 + (age_blocks / 10); // Increase priority by 10% per 10 blocks

        let retry_penalty = if self.retry_count > 0 {
            100 / (1 + self.retry_count as u128) // Reduce priority slightly for retries
        } else {
            100
        };

        (fee_per_byte * age_bonus * retry_penalty) / 100
    }

    /// Check if transaction should be retried (not in mempool too long)
    pub fn should_retry(&self, max_mempool_age_blocks: u64, current_height: u64) -> bool {
        current_height.saturating_sub(self.received_at_height) <= max_mempool_age_blocks
    }
}

impl PartialEq for MempoolTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash == other.tx_hash
    }
}

impl Eq for MempoolTransaction {}

/// Comparable wrapper for BinaryHeap (max-heap)
#[derive(Debug, Clone)]
struct MempoolPriority {
    tx: MempoolTransaction,
    priority: u128,
}

impl PartialEq for MempoolPriority {
    fn eq(&self, other: &Self) -> bool {
        self.tx.tx_hash == other.tx.tx_hash
    }
}

impl Eq for MempoolPriority {}

impl PartialOrd for MempoolPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap ordering: higher priority values are popped first
        self.priority.cmp(&other.priority)
            .then_with(|| self.tx.fee.cmp(&other.tx.fee))
            .then_with(|| other.tx.received_at_height.cmp(&self.tx.received_at_height))
    }
}

/// Transaction Mempool
///
/// Stores pending transactions and selects them for block inclusion
/// based on fee and priority metrics.
#[derive(Debug, Clone)]
pub struct Mempool {
    /// Map of transaction hash → MempoolTransaction
    transactions: HashMap<[u8; 32], MempoolTransaction>,
    /// Priority queue for transaction selection
    priority_queue: BinaryHeap<MempoolPriority>,
    /// Maximum number of transactions in mempool
    max_size: usize,
    /// Maximum age of transaction in mempool (blocks)
    max_mempool_age: u64,
    /// Statistics
    pub total_fees_pending: u64,
    pub total_size_bytes: u64,
}

impl Mempool {
    /// Create new mempool with configuration
    pub fn new(max_size: usize, max_mempool_age_blocks: u64) -> Self {
        Self {
            transactions: HashMap::new(),
            priority_queue: BinaryHeap::new(),
            max_size,
            max_mempool_age: max_mempool_age_blocks,
            total_fees_pending: 0,
            total_size_bytes: 0,
        }
    }

    /// Add transaction to mempool
    ///
    /// Returns Ok(()) if added, Err if mempool is full or transaction exists
    pub fn add_transaction(
        &mut self,
        tx_hash: [u8; 32],
        fee: u64,
        size: u32,
        current_height: u64,
        current_time: u64,
    ) -> Result<(), String> {
        // Check if transaction already exists
        if self.transactions.contains_key(&tx_hash) {
            return Err("Transaction already in mempool".to_string());
        }

        // Check if mempool is full
        if self.transactions.len() >= self.max_size {
            return Err(format!("Mempool full ({} transactions)", self.max_size));
        }

        let tx = MempoolTransaction {
            tx_hash,
            fee,
            size,
            received_at_height: current_height,
            received_at_time: current_time,
            retry_count: 0,
        };

        let priority = tx.priority_score(current_height);
        self.transactions.insert(tx_hash, tx.clone());
        self.priority_queue.push(MempoolPriority {
            tx,
            priority,
        });

        self.total_fees_pending += fee;
        self.total_size_bytes += size as u64;

        Ok(())
    }

    /// Remove transaction from mempool (after it's included in block)
    pub fn remove_transaction(&mut self, tx_hash: &[u8; 32]) -> Option<MempoolTransaction> {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            self.total_fees_pending = self.total_fees_pending.saturating_sub(tx.fee);
            self.total_size_bytes = self.total_size_bytes.saturating_sub(tx.size as u64);
            Some(tx)
        } else {
            None
        }
    }

    /// Get next N transactions for block inclusion (by priority)
    pub fn select_transactions(&mut self, max_count: usize, current_height: u64) -> Vec<[u8; 32]> {
        let mut selected = Vec::new();

        while selected.len() < max_count && !self.priority_queue.is_empty() {
            if let Some(priority_tx) = self.priority_queue.pop() {
                // Check if transaction is still in mempool and should be selected
                if self.transactions.contains_key(&priority_tx.tx.tx_hash) {
                    // Check if transaction has expired
                    if priority_tx.tx.should_retry(self.max_mempool_age, current_height) {
                        selected.push(priority_tx.tx.tx_hash);
                    } else {
                        // Transaction expired, remove it
                        self.remove_transaction(&priority_tx.tx.tx_hash);
                    }
                }
            }
        }

        selected
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, tx_hash: &[u8; 32]) -> Option<&MempoolTransaction> {
        self.transactions.get(tx_hash)
    }

    /// Check if transaction is in mempool
    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// Get mempool size (number of transactions)
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Get total fees in pending transactions
    pub fn total_pending_fees(&self) -> u64 {
        self.total_fees_pending
    }

    /// Clear expired transactions from mempool
    pub fn evict_expired(&mut self, current_height: u64) -> usize {
        let initial_count = self.transactions.len();

        self.transactions.retain(|tx_hash, tx| {
            if tx.should_retry(self.max_mempool_age, current_height) {
                true
            } else {
                self.total_fees_pending = self.total_fees_pending.saturating_sub(tx.fee);
                self.total_size_bytes = self.total_size_bytes.saturating_sub(tx.size as u64);
                false
            }
        });

        initial_count - self.transactions.len()
    }

    /// Get pending transaction hashes (for debugging/testing)
    pub fn pending_transactions(&self) -> Vec<[u8; 32]> {
        self.transactions.keys().copied().collect()
    }

    /// Get statistics about mempool state
    pub fn stats(&self) -> MempoolStats {
        let (total_size, total_fees, min_fee, max_fee) = self.transactions.values().fold(
            (0u64, 0u64, u64::MAX, 0u64),
            |(size, fees, min_f, max_f), tx| {
                (
                    size + tx.size as u64,
                    fees + tx.fee,
                    min_f.min(tx.fee),
                    max_f.max(tx.fee),
                )
            },
        );

        MempoolStats {
            transaction_count: self.transactions.len(),
            total_size_bytes: total_size,
            total_fees: total_fees,
            min_fee: if min_fee == u64::MAX { 0 } else { min_fee },
            max_fee,
            avg_fee: if !self.transactions.is_empty() {
                total_fees / self.transactions.len() as u64
            } else {
                0
            },
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    pub transaction_count: usize,
    pub total_size_bytes: u64,
    pub total_fees: u64,
    pub min_fee: u64,
    pub max_fee: u64,
    pub avg_fee: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mempool_add_and_remove() {
        let mut mempool = Mempool::new(100, 1000);
        let tx_hash = [1u8; 32];

        // Add transaction
        assert!(mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000).is_ok());
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.total_pending_fees(), 1000);

        // Try to add duplicate
        assert!(mempool.add_transaction(tx_hash, 1000, 200, 100, 1000000).is_err());

        // Remove transaction
        let removed = mempool.remove_transaction(&tx_hash);
        assert!(removed.is_some());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_pending_fees(), 0);
    }

    #[test]
    fn test_priority_score_calculation() {
        let tx = MempoolTransaction {
            tx_hash: [1u8; 32],
            fee: 1000,
            size: 100,
            received_at_height: 100,
            received_at_time: 1000000,
            retry_count: 0,
        };

        // At received height: priority = (1000/100)*1000*100 = 10,000,000
        let priority_at_100 = tx.priority_score(100);
        assert!(priority_at_100 > 0);

        // At height 110 (10 blocks later): age_bonus increases, priority increases
        let priority_at_110 = tx.priority_score(110);
        assert!(priority_at_110 > priority_at_100);
    }

    #[test]
    fn test_mempool_full() {
        let mut mempool = Mempool::new(2, 1000);

        // Add 2 transactions
        assert!(mempool.add_transaction([1u8; 32], 1000, 100, 100, 1000000).is_ok());
        assert!(mempool.add_transaction([2u8; 32], 1000, 100, 100, 1000000).is_ok());
        assert_eq!(mempool.size(), 2);

        // Try to add 3rd (should fail - mempool full)
        assert!(mempool.add_transaction([3u8; 32], 1000, 100, 100, 1000000).is_err());
    }

    #[test]
    fn test_transaction_selection_by_priority() {
        let mut mempool = Mempool::new(100, 1000);

        // Add transactions with different fees
        mempool.add_transaction([1u8; 32], 100, 100, 100, 1000000).ok();
        mempool.add_transaction([2u8; 32], 1000, 100, 100, 1000000).ok(); // High fee
        mempool.add_transaction([3u8; 32], 500, 100, 100, 1000000).ok();

        let selected = mempool.select_transactions(2, 100);
        assert_eq!(selected.len(), 2);
        // Higher fee transaction should be selected first (hash [2u8; 32])
        assert!(selected.contains(&[2u8; 32]));
    }
}
