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
    /// Current status (Pending/Confirmed/Finalized/Failed)
    pub status: TransactionStatus,
    /// Gas used by transaction (0 for now, reserved for future)
    pub gas_used: u64,
    /// Fee paid by sender
    pub fee_paid: u64,
    /// Execution logs (empty for now, reserved for contract execution)
    pub logs: Vec<String>,
    /// Unix timestamp of block creation
    pub timestamp: u64,
    /// Number of confirmations (blocks since inclusion)
    pub confirmations: u64,
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
            status: TransactionStatus::Confirmed,
            gas_used: 0,
            fee_paid,
            logs: Vec::new(),
            timestamp,
            confirmations: 0,
        }
    }

    /// Update confirmation count based on current blockchain height
    pub fn update_confirmations(&mut self, current_height: u64) {
        if current_height >= self.block_height {
            self.confirmations = current_height - self.block_height;
        }
    }

    /// Check if transaction is finalized (12+ confirmations)
    pub fn is_finalized(&self) -> bool {
        self.confirmations >= 12
    }

    /// Mark transaction as finalized and update status
    pub fn finalize(&mut self) {
        if self.is_finalized() {
            self.status = TransactionStatus::Finalized;
        }
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
        assert_eq!(receipt.status, TransactionStatus::Confirmed);
        assert!(!receipt.is_finalized());
    }

    #[test]
    fn test_confirmation_counting() {
        let hash = Hash::from_slice(&[0u8; 32]);
        let mut receipt = TransactionReceipt::new(hash, hash, 100, 0, 1000, 12345);

        receipt.update_confirmations(105);
        assert_eq!(receipt.confirmations, 5);
        assert!(!receipt.is_finalized());

        receipt.update_confirmations(112);
        assert_eq!(receipt.confirmations, 12);
        assert!(receipt.is_finalized());
    }

    #[test]
    fn test_finalization() {
        let hash = Hash::from_slice(&[0u8; 32]);
        let mut receipt = TransactionReceipt::new(hash, hash, 100, 0, 1000, 12345);

        assert_eq!(receipt.status, TransactionStatus::Confirmed);
        receipt.confirmations = 12;
        receipt.finalize();
        assert_eq!(receipt.status, TransactionStatus::Finalized);
    }
}
