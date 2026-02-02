//! Mempool State
//!
//! Tracks current mempool usage for admission checks.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use lib_types::Address;

/// Current state of the mempool for admission checks
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MempoolState {
    /// Current total bytes in mempool
    pub total_bytes: u64,
    /// Current transaction count
    pub tx_count: u32,
    /// Transactions per sender address
    pub per_sender: HashMap<Address, SenderState>,
}

/// Per-sender state tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SenderState {
    /// Number of pending transactions from this sender
    pub pending_count: u32,
    /// Total bytes from this sender
    pub total_bytes: u64,
    /// Transactions in current rate limit period
    pub period_count: u32,
    /// Block height when period started
    pub period_start_block: u64,
}

impl MempoolState {
    /// Create empty mempool state
    pub fn new() -> Self {
        Self::default()
    }

    /// Get sender state, creating if not exists
    pub fn get_sender(&self, address: &Address) -> Option<&SenderState> {
        self.per_sender.get(address)
    }

    /// Get sender's pending transaction count
    pub fn sender_pending_count(&self, address: &Address) -> u32 {
        self.per_sender
            .get(address)
            .map(|s| s.pending_count)
            .unwrap_or(0)
    }

    /// Get sender's transactions in current period
    pub fn sender_period_count(&self, address: &Address, current_block: u64, period_blocks: u32) -> u32 {
        self.per_sender
            .get(address)
            .map(|s| {
                // Check if we're still in the same period
                if current_block < s.period_start_block + period_blocks as u64 {
                    s.period_count
                } else {
                    0 // New period, count resets
                }
            })
            .unwrap_or(0)
    }

    /// Record a transaction being added to mempool
    pub fn add_tx(&mut self, sender: Address, tx_bytes: u64, current_block: u64, period_blocks: u32) {
        self.total_bytes = self.total_bytes.saturating_add(tx_bytes);
        self.tx_count = self.tx_count.saturating_add(1);

        let sender_state = self.per_sender.entry(sender).or_default();
        sender_state.pending_count = sender_state.pending_count.saturating_add(1);
        sender_state.total_bytes = sender_state.total_bytes.saturating_add(tx_bytes);

        // Update rate limit tracking
        if current_block >= sender_state.period_start_block + period_blocks as u64 {
            // New period
            sender_state.period_start_block = current_block;
            sender_state.period_count = 1;
        } else {
            sender_state.period_count = sender_state.period_count.saturating_add(1);
        }
    }

    /// Record a transaction being removed from mempool
    pub fn remove_tx(&mut self, sender: &Address, tx_bytes: u64) {
        self.total_bytes = self.total_bytes.saturating_sub(tx_bytes);
        self.tx_count = self.tx_count.saturating_sub(1);

        if let Some(sender_state) = self.per_sender.get_mut(sender) {
            sender_state.pending_count = sender_state.pending_count.saturating_sub(1);
            sender_state.total_bytes = sender_state.total_bytes.saturating_sub(tx_bytes);

            // Remove entry if empty
            if sender_state.pending_count == 0 {
                self.per_sender.remove(sender);
            }
        }
    }

    /// Check if mempool has capacity for more bytes
    pub fn has_byte_capacity(&self, max_bytes: u64) -> bool {
        self.total_bytes < max_bytes
    }

    /// Check if mempool has capacity for more transactions
    pub fn has_tx_capacity(&self, max_count: u32) -> bool {
        self.tx_count < max_count
    }

    /// Get remaining byte capacity
    pub fn remaining_bytes(&self, max_bytes: u64) -> u64 {
        max_bytes.saturating_sub(self.total_bytes)
    }

    /// Clear all state (e.g., after block commit)
    pub fn clear(&mut self) {
        self.total_bytes = 0;
        self.tx_count = 0;
        self.per_sender.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove_tx() {
        let mut state = MempoolState::new();
        let sender = Address::default();

        state.add_tx(sender, 1000, 100, 10);
        assert_eq!(state.total_bytes, 1000);
        assert_eq!(state.tx_count, 1);
        assert_eq!(state.sender_pending_count(&sender), 1);

        state.add_tx(sender, 500, 100, 10);
        assert_eq!(state.total_bytes, 1500);
        assert_eq!(state.tx_count, 2);
        assert_eq!(state.sender_pending_count(&sender), 2);

        state.remove_tx(&sender, 1000);
        assert_eq!(state.total_bytes, 500);
        assert_eq!(state.tx_count, 1);
        assert_eq!(state.sender_pending_count(&sender), 1);
    }

    #[test]
    fn test_rate_limit_period() {
        let mut state = MempoolState::new();
        let sender = Address::default();

        // Add 3 txs in period starting at block 100
        state.add_tx(sender, 100, 100, 10);
        state.add_tx(sender, 100, 105, 10);
        state.add_tx(sender, 100, 109, 10);

        assert_eq!(state.sender_period_count(&sender, 105, 10), 3);

        // New period at block 110
        assert_eq!(state.sender_period_count(&sender, 110, 10), 0);
    }

    #[test]
    fn test_capacity_checks() {
        let mut state = MempoolState::new();
        let sender = Address::default();

        assert!(state.has_byte_capacity(1000));
        assert!(state.has_tx_capacity(10));

        state.add_tx(sender, 900, 100, 10);
        assert!(state.has_byte_capacity(1000));
        assert!(!state.has_byte_capacity(900));
    }
}
