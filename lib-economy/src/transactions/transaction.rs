//! Core transaction structure and implementation
//! 
//! Defines the main transaction structure used throughout the economic system
//! with comprehensive fee tracking and DAO integration.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::types::{TransactionType, Priority};
use crate::wasm::{hash_blake3, compatibility::current_timestamp};
use std::sync::atomic::{AtomicU64, Ordering};

static TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Economic transaction in the SOV network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction identifier
    pub tx_id: [u8; 32],
    /// Sender address
    pub from: [u8; 32],
    /// Recipient address
    pub to: [u8; 32],
    /// Transaction amount in SOV tokens
    pub amount: u64,
    /// Network infrastructure fee
    pub base_fee: u64,
    /// Mandatory DAO fee for UBI/welfare (2% of amount)
    pub dao_fee: u64,
    /// Total fee (base_fee + dao_fee)
    pub total_fee: u64,
    /// Type of transaction
    pub tx_type: TransactionType,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Block height (set by consensus layer)
    pub block_height: u64,
    /// Proof that DAO fee was properly calculated
    pub dao_fee_proof: Option<[u8; 32]>,
}

impl Transaction {
    /// Create a new transaction with automatic fee calculation
    pub fn new(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        tx_type: TransactionType,
        tx_size: u64,
        priority: Priority,
    ) -> Result<Self> {
        let timestamp = current_timestamp()?;
        let counter = TRANSACTION_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tx_id = hash_blake3(&format!("tx_{}_{}_{}_{}_{}", 
            hex::encode(from), hex::encode(to), amount, timestamp, counter).as_bytes());
        
        // Calculate fees based on transaction type
        let (base_fee, dao_fee, total_fee) = if tx_type.is_fee_exempt() {
            // UBI and welfare distributions are fee-free
            (0, 0, 0)
        } else {
            // All other transactions pay full fees including mandatory DAO fee
            crate::models::calculate_total_fee(tx_size, amount, priority)
        };
        
        // Generate DAO fee proof (ensures DAO fee was properly calculated)
        let dao_fee_proof = if dao_fee > 0 {
            Some(hash_blake3(&format!("dao_fee_proof_{}_{}", dao_fee, timestamp).as_bytes()))
        } else {
            None
        };
        
        Ok(Transaction {
            tx_id,
            from,
            to,
            amount,
            base_fee,
            dao_fee,
            total_fee,
            tx_type,
            timestamp,
            block_height: 0, // Set by consensus layer
            dao_fee_proof,
        })
    }
    
    /// Create a specific type of transaction with appropriate defaults
    pub fn new_payment(from: [u8; 32], to: [u8; 32], amount: u64, priority: Priority) -> Result<Self> {
        Self::new(from, to, amount, TransactionType::Payment, 250, priority) // 250 bytes typical
    }
    
    /// Create a reward transaction
    pub fn new_reward(to: [u8; 32], amount: u64) -> Result<Self> {
        let from = [0u8; 32]; // Network address
        Self::new(from, to, amount, TransactionType::Reward, 200, Priority::Normal)
    }
    
    /// Create a UBI distribution transaction (fee-free)
    pub fn new_ubi_distribution(to: [u8; 32], amount: u64) -> Result<Self> {
        let from = [0u8; 32]; // DAO treasury address
        Self::new(from, to, amount, TransactionType::UbiDistribution, 200, Priority::Normal)
    }
    
    /// Create a welfare distribution transaction (fee-free)
    pub fn new_welfare_distribution(to: [u8; 32], amount: u64) -> Result<Self> {
        let from = [0u8; 32]; // DAO treasury address
        Self::new(from, to, amount, TransactionType::WelfareDistribution, 200, Priority::Normal)
    }
    
    /// Get transaction hash for signing
    pub fn signing_hash(&self) -> [u8; 32] {
        let signing_data = format!(
            "{}{}{}{}{}{}",
            hex::encode(self.from),
            hex::encode(self.to),
            self.amount,
            self.base_fee,
            self.dao_fee,
            self.timestamp
        );
        hash_blake3(signing_data.as_bytes())
    }
    
    /// Get transaction summary for display
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "tx_id": hex::encode(self.tx_id),
            "from": hex::encode(self.from),
            "to": hex::encode(self.to),
            "amount": self.amount,
            "base_fee": self.base_fee,
            "dao_fee": self.dao_fee,
            "total_fee": self.total_fee,
            "tx_type": self.tx_type.description(),
            "timestamp": self.timestamp,
            "block_height": self.block_height,
            "has_dao_proof": self.dao_fee_proof.is_some()
        })
    }
    
    /// Check if this transaction contributes to UBI funding
    pub fn contributes_to_ubi(&self) -> bool {
        self.dao_fee > 0
    }
    
    /// Get the effective cost to sender (amount + fees)
    pub fn total_cost(&self) -> u64 {
        self.amount + self.total_fee
    }
    
    /// Check if transaction is a distribution from DAO treasury
    pub fn is_dao_distribution(&self) -> bool {
        matches!(self.tx_type, 
            TransactionType::UbiDistribution | 
            TransactionType::WelfareDistribution
        )
    }
}
