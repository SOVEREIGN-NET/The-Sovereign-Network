//! Memory pool (mempool) for pending transactions
//! 
//! Manages transactions waiting to be included in blocks.

use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};
use crate::types::Hash;
use crate::transaction::{Transaction, ValidationError};

/// Transaction memory pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mempool {
    /// Pending transactions by hash
    transactions: HashMap<Hash, Transaction>,
    /// Transaction order for prioritization
    transaction_queue: VecDeque<Hash>,
    /// Maximum size of the mempool
    max_size: usize,
    /// Minimum fee rate for acceptance
    min_fee_rate: u64,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(max_size: usize, min_fee_rate: u64) -> Self {
        Self {
            transactions: HashMap::new(),
            transaction_queue: VecDeque::new(),
            max_size,
            min_fee_rate,
        }
    }

    /// Add a transaction to the mempool
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), MempoolError> {
        let tx_hash = transaction.hash();

        // Check if already exists
        if self.transactions.contains_key(&tx_hash) {
            return Err(MempoolError::TransactionExists);
        }

        // Validate transaction
        self.validate_transaction(&transaction)?;

        // Check fee rate
        let fee_rate = transaction.fee as f64 / transaction.size() as f64;
        if fee_rate < self.min_fee_rate as f64 {
            return Err(MempoolError::InsufficientFee);
        }

        // Make room if necessary
        while self.transactions.len() >= self.max_size {
            self.evict_lowest_fee_transaction()?;
        }

        // Add to mempool
        self.transactions.insert(tx_hash, transaction);
        self.transaction_queue.push_back(tx_hash);

        Ok(())
    }

    /// Remove a transaction from the mempool
    pub fn remove_transaction(&mut self, tx_hash: &Hash) -> Option<Transaction> {
        if let Some(transaction) = self.transactions.remove(tx_hash) {
            self.transaction_queue.retain(|hash| hash != tx_hash);
            Some(transaction)
        } else {
            None
        }
    }

    /// Get a transaction by hash
    pub fn get_transaction(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.transactions.get(tx_hash)
    }

    /// Get all pending transactions
    pub fn get_all_transactions(&self) -> Vec<&Transaction> {
        self.transactions.values().collect()
    }

    /// Get transactions for block creation (highest fee first)
    pub fn get_transactions_for_block(&self, max_count: usize, max_size: usize) -> Vec<Transaction> {
        let mut selected = Vec::new();
        let mut total_size = 0;

        // Sort by fee rate (highest first)
        let mut tx_refs: Vec<_> = self.transactions.values().collect();
        tx_refs.sort_by(|a, b| {
            let fee_rate_a = a.fee as f64 / a.size() as f64;
            let fee_rate_b = b.fee as f64 / b.size() as f64;
            fee_rate_b.partial_cmp(&fee_rate_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        for tx in tx_refs {
            if selected.len() >= max_count {
                break;
            }
            
            let tx_size = tx.size();
            if total_size + tx_size > max_size {
                continue;
            }

            selected.push(tx.clone());
            total_size += tx_size;
        }

        selected
    }

    /// Remove multiple transactions (after block inclusion)
    pub fn remove_transactions(&mut self, tx_hashes: &[Hash]) {
        for tx_hash in tx_hashes {
            self.remove_transaction(tx_hash);
        }
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let total_fees: u64 = self.transactions.values().map(|tx| tx.fee).sum();
        let total_size: usize = self.transactions.values().map(|tx| tx.size()).sum();
        let avg_fee_rate = if total_size > 0 {
            total_fees as f64 / total_size as f64
        } else {
            0.0
        };

        MempoolStats {
            transaction_count: self.transactions.len(),
            total_fees,
            total_size,
            average_fee_rate: avg_fee_rate,
            min_fee_rate: self.min_fee_rate,
            max_size: self.max_size,
        }
    }

    /// Check if mempool contains transaction
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// Clear all transactions
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.transaction_queue.clear();
    }

    /// Validate transaction for mempool inclusion
    fn validate_transaction(&self, transaction: &Transaction) -> Result<(), MempoolError> {
        // Use transaction validator
        let validator = crate::transaction::validation::TransactionValidator::new();
        
        match validator.validate_transaction(transaction) {
            Ok(()) => {
                log::info!("Transaction validation successful");
                Ok(())
            },
            Err(ValidationError::DoubleSpend) => {
                log::error!("Validation failed: DoubleSpend");
                Err(MempoolError::DoubleSpend)
            },
            Err(ValidationError::InvalidSignature) => {
                log::error!("Validation failed: InvalidSignature");
                Err(MempoolError::InvalidSignature)
            },
            Err(ValidationError::InvalidZkProof) => {
                log::error!("Validation failed: InvalidZkProof - ZK proof verification failed");
                Err(MempoolError::InvalidProof)
            },
            Err(e) => {
                log::error!("Validation failed: {:?}", e);
                Err(MempoolError::InvalidTransaction)
            },
        }
    }

    /// Evict lowest fee transaction to make room
    fn evict_lowest_fee_transaction(&mut self) -> Result<(), MempoolError> {
        if self.transactions.is_empty() {
            return Err(MempoolError::MempoolEmpty);
        }

        // Find transaction with lowest fee rate
        let mut lowest_fee_rate = f64::INFINITY;
        let mut lowest_hash = None;

        for (hash, tx) in &self.transactions {
            let fee_rate = tx.fee as f64 / tx.size() as f64;
            if fee_rate < lowest_fee_rate {
                lowest_fee_rate = fee_rate;
                lowest_hash = Some(*hash);
            }
        }

        if let Some(hash) = lowest_hash {
            self.remove_transaction(&hash);
            Ok(())
        } else {
            Err(MempoolError::EvictionFailed)
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(10000, 1) // Default: 10k transactions, 1 unit/byte min fee
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    pub transaction_count: usize,
    pub total_fees: u64,
    pub total_size: usize,
    pub average_fee_rate: f64,
    pub min_fee_rate: u64,
    pub max_size: usize,
}

/// Mempool error types
#[derive(Debug, Clone)]
pub enum MempoolError {
    TransactionExists,
    InsufficientFee,
    InvalidTransaction,
    InvalidSignature,
    InvalidProof,
    DoubleSpend,
    MempoolFull,
    MempoolEmpty,
    EvictionFailed,
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::TransactionExists => write!(f, "Transaction already exists in mempool"),
            MempoolError::InsufficientFee => write!(f, "Transaction fee too low"),
            MempoolError::InvalidTransaction => write!(f, "Invalid transaction"),
            MempoolError::InvalidSignature => write!(f, "Invalid transaction signature"),
            MempoolError::InvalidProof => write!(f, "Invalid zero-knowledge proof"),
            MempoolError::DoubleSpend => write!(f, "Double spend detected"),
            MempoolError::MempoolFull => write!(f, "Mempool is full"),
            MempoolError::MempoolEmpty => write!(f, "Mempool is empty"),
            MempoolError::EvictionFailed => write!(f, "Failed to evict transaction"),
        }
    }
}

impl std::error::Error for MempoolError {}
