//! UTXO Types
//!
//! Core types for UTXO-based transactions.

use serde::{Deserialize, Serialize};
use lib_types::{Address, Amount, BlockHeight, TxHash};

/// OutPoint - Reference to a specific output in a transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Transaction hash containing the output
    pub tx_hash: TxHash,
    /// Index of the output in the transaction
    pub output_index: u32,
}

impl OutPoint {
    /// Create a new OutPoint
    pub const fn new(tx_hash: TxHash, output_index: u32) -> Self {
        Self { tx_hash, output_index }
    }

    /// Convert to bytes for storage key
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[..32].copy_from_slice(self.tx_hash.as_bytes());
        bytes[32..36].copy_from_slice(&self.output_index.to_le_bytes());
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8; 36]) -> Self {
        let mut tx_bytes = [0u8; 32];
        tx_bytes.copy_from_slice(&bytes[..32]);
        let output_index = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        Self {
            tx_hash: TxHash::new(tx_bytes),
            output_index,
        }
    }
}

/// Unspent Transaction Output
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Amount in the output
    pub amount: Amount,
    /// Owner address
    pub owner: Address,
    /// Block height when created
    pub created_at: BlockHeight,
    /// Optional lock until height
    pub locked_until: Option<BlockHeight>,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(amount: Amount, owner: Address, created_at: BlockHeight) -> Self {
        Self {
            amount,
            owner,
            created_at,
            locked_until: None,
        }
    }

    /// Create a locked UTXO
    pub fn new_locked(
        amount: Amount,
        owner: Address,
        created_at: BlockHeight,
        locked_until: BlockHeight,
    ) -> Self {
        Self {
            amount,
            owner,
            created_at,
            locked_until: Some(locked_until),
        }
    }

    /// Check if the UTXO is spendable at the given height
    pub fn is_spendable(&self, current_height: BlockHeight) -> bool {
        match self.locked_until {
            Some(lock_height) => current_height >= lock_height,
            None => true,
        }
    }
}

/// Transaction input (reference to UTXO being spent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    /// Reference to the UTXO being spent
    pub outpoint: OutPoint,
    /// Nullifier (prevents double-spend in ZK context)
    pub nullifier: [u8; 32],
}

/// Transaction output (new UTXO being created)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount to send
    pub amount: Amount,
    /// Recipient address
    pub recipient: Address,
    /// Optional lock height
    pub locked_until: Option<BlockHeight>,
}

/// Result of successful native transfer
#[derive(Debug, Clone)]
pub struct TransferOutcome {
    /// Number of inputs spent
    pub inputs_spent: usize,
    /// Number of outputs created
    pub outputs_created: usize,
    /// Total input value
    pub total_input: Amount,
    /// Total output value
    pub total_output: Amount,
    /// Fee paid
    pub fee: Amount,
}

/// Trait for UTXO storage operations
///
/// Implementations must provide atomic UTXO operations.
pub trait UtxoStore {
    /// Get a UTXO by outpoint
    fn get_utxo(&self, outpoint: &OutPoint) -> UtxoResult<Option<Utxo>>;

    /// Check if a UTXO exists
    fn utxo_exists(&self, outpoint: &OutPoint) -> UtxoResult<bool> {
        Ok(self.get_utxo(outpoint)?.is_some())
    }

    /// Spend a UTXO (mark as consumed)
    ///
    /// Returns the UTXO that was spent, or error if not found.
    fn spend_utxo(&self, outpoint: &OutPoint) -> UtxoResult<Utxo>;

    /// Create a new UTXO
    ///
    /// The UTXO is pending until block commit.
    fn create_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> UtxoResult<()>;
}

use crate::errors::UtxoResult;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outpoint_serialization() {
        let outpoint = OutPoint::new(TxHash::default(), 42);
        let bytes = outpoint.to_bytes();
        let restored = OutPoint::from_bytes(&bytes);
        assert_eq!(outpoint, restored);
    }

    #[test]
    fn test_utxo_spendable() {
        let utxo = Utxo::new(1000, Address::default(), 100);
        assert!(utxo.is_spendable(100));
        assert!(utxo.is_spendable(200));
    }

    #[test]
    fn test_utxo_locked() {
        let utxo = Utxo::new_locked(1000, Address::default(), 100, 200);
        assert!(!utxo.is_spendable(100));
        assert!(!utxo.is_spendable(199));
        assert!(utxo.is_spendable(200));
        assert!(utxo.is_spendable(300));
    }
}
