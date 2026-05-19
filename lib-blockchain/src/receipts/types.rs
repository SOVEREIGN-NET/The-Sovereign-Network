//! Transaction Receipt Types
//!
//! Defines transaction receipt structures for tracking transaction status
//! through the confirmation and finality pipeline.

use crate::types::Hash;
use serde::{Deserialize, Serialize};

/// Status of a transaction in the confirmation pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction in mempool, awaiting inclusion in block
    Pending,
    /// Transaction included in block but <12 confirmations
    Confirmed,
    /// Transaction has 12+ confirmations (finalized)
    Finalized,
    /// Transaction failed with error message
    Failed,
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Pending => write!(f, "Pending"),
            TransactionStatus::Confirmed => write!(f, "Confirmed"),
            TransactionStatus::Finalized => write!(f, "Finalized"),
            TransactionStatus::Failed => write!(f, "Failed"),
        }
    }
}

/// Receipt for a transaction included in a block
///
/// Contains confirmation status, fee information, block height/hash,
/// and audit trail for tracking transaction lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Block hash containing this transaction
    pub block_hash: Hash,
    /// Block height at inclusion
    pub block_height: u64,
    /// Index of transaction within block
    pub tx_index: u32,
    /// Gas used by transaction (0 for now, reserved for future)
    pub gas_used: u64,
    /// Fee paid by sender
    pub fee_paid: u64,
    /// Execution logs (empty for now, reserved for contract execution)
    pub logs: Vec<String>,
    /// Unix timestamp of block creation
    pub timestamp: u64,
}

impl TransactionReceipt {
    /// Create new transaction receipt
    pub fn new(
        tx_hash: Hash,
        block_hash: Hash,
        block_height: u64,
        tx_index: u32,
        fee_paid: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            tx_hash,
            block_hash,
            block_height,
            tx_index,
            gas_used: 0,
            fee_paid,
            logs: Vec::new(),
            timestamp,
        }
    }

    /// Status as of `current_height`, derived from height.
    ///
    /// A stored receipt always belongs to an included transaction, so it is
    /// `Confirmed` until it reaches finality depth, then `Finalized`. Status
    /// is computed, not a stored field that must be rewritten on every tick.
    pub fn status(&self, current_height: u64) -> TransactionStatus {
        if self.is_finalized(current_height) {
            TransactionStatus::Finalized
        } else {
            TransactionStatus::Confirmed
        }
    }

    /// Confirmations as of `current_height`.
    ///
    /// Derived, never stored: `current_height − block_height`. Confirmation
    /// counts must not be a stored, mutated field — that forced rewriting the
    /// entire receipt history on every finality tick.
    pub fn confirmations(&self, current_height: u64) -> u64 {
        current_height.saturating_sub(self.block_height)
    }

    /// Whether the transaction is finalized (12+ confirmations) as of
    /// `current_height`. Derived from height — not stored mutable state.
    pub fn is_finalized(&self, current_height: u64) -> bool {
        self.confirmations(current_height) >= 12
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_creation() {
        let hash = Hash::from_slice(&[0u8; 32]);
        let receipt = TransactionReceipt::new(hash, hash, 100, 0, 1000, 12345);

        assert_eq!(receipt.tx_hash, hash);
        assert_eq!(receipt.block_height, 100);
        assert_eq!(receipt.fee_paid, 1000);
        assert_eq!(receipt.status(100), TransactionStatus::Confirmed);
        assert_eq!(receipt.status(120), TransactionStatus::Finalized);
        assert!(!receipt.is_finalized(100));
    }

    #[test]
    fn test_confirmations_are_derived() {
        let hash = Hash::from_slice(&[0u8; 32]);
        let receipt = TransactionReceipt::new(hash, hash, 100, 0, 1000, 12345);

        assert_eq!(receipt.confirmations(105), 5);
        assert!(!receipt.is_finalized(105));

        assert_eq!(receipt.confirmations(112), 12);
        assert!(receipt.is_finalized(112));

        // Below inclusion height saturates to zero, never underflows.
        assert_eq!(receipt.confirmations(50), 0);
    }
}
