//! Block creation utilities
//! 
//! Functions for creating new blocks from transactions.

use anyhow::Result;
use crate::block::{Block, BlockHeader};
use crate::transaction::Transaction;
use crate::types::Hash;

/// Block builder for constructing new blocks
#[derive(Debug)]
pub struct BlockBuilder {
    version: u32,
    previous_block_hash: Hash,
    timestamp: u64,
    height: u64,
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    /// Create a new block builder
    pub fn new(
        previous_block_hash: Hash,
        height: u64,
    ) -> Self {
        Self {
            version: 1,
            previous_block_hash,
            timestamp: crate::utils::time::current_timestamp(),
            height,
            transactions: Vec::new(),
        }
    }

    /// Set block version
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set block timestamp
    pub fn timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Add a transaction to the block
    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// Add multiple transactions to the block
    pub fn add_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions.extend(transactions);
        self
    }

    /// Set all transactions (replacing existing ones)
    pub fn transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    /// Build the block
    pub fn build(self) -> Result<Block> {
        // Calculate merkle root
        let merkle_root = crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions);

        // Calculate block size
        let transaction_count = self.transactions.len() as u32;
        let block_size = self.calculate_block_size();

        // Create header
        let header = BlockHeader::new(
            self.version,
            self.previous_block_hash,
            merkle_root,
            self.timestamp,
            self.height,
            transaction_count,
            block_size,
        );

        Ok(Block::new(header, self.transactions))
    }

    /// Calculate the size of the block being built
    fn calculate_block_size(&self) -> u32 {
        let header_size = 200; // Approximate header size
        let transactions_size: usize = self.transactions
            .iter()
            .map(|tx| crate::utils::size::transaction_size(tx))
            .sum();
        (header_size + transactions_size) as u32
    }
}

/// Create a new block from transactions
pub fn create_block(
    transactions: Vec<Transaction>,
    previous_block_hash: Hash,
    height: u64,
) -> Result<Block> {
    BlockBuilder::new(previous_block_hash, height)
        .transactions(transactions)
        .build()
}

/// Create genesis block
pub fn create_genesis_block_with_transactions(transactions: Vec<Transaction>) -> Result<Block> {
    BlockBuilder::new(Hash::default(), 0)
        .timestamp(crate::GENESIS_TIMESTAMP)
        .transactions(transactions)
        .build()
}


/// Select transactions for block creation
pub fn select_transactions_for_block(
    available_transactions: &[Transaction],
    max_transactions: usize,
    max_block_size: usize,
) -> Vec<Transaction> {
    let mut selected = Vec::new();
    let mut total_size = 0;
    
    // Sort by fee rate (highest first)
    let mut tx_refs: Vec<_> = available_transactions.iter().collect();
    tx_refs.sort_by(|a, b| {
        let fee_rate_a = crate::utils::fees::calculate_fee_rate(a);
        let fee_rate_b = crate::utils::fees::calculate_fee_rate(b);
        fee_rate_b.partial_cmp(&fee_rate_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    for tx in tx_refs {
        if selected.len() >= max_transactions {
            break;
        }
        
        let tx_size = crate::utils::size::transaction_size(tx);
        if total_size + tx_size > max_block_size {
            continue;
        }
        
        selected.push(tx.clone());
        total_size += tx_size;
    }
    
    selected
}

/// Block creation utilities
pub mod utils {
    use super::*;
    
    /// Calculate optimal block size for given transactions
    pub fn calculate_optimal_block_size(transactions: &[Transaction]) -> usize {
        transactions
            .iter()
            .map(|tx| crate::utils::size::transaction_size(tx))
            .sum::<usize>() + 200 // Add header size
    }
    
    /// Validate transactions for block inclusion
    pub fn validate_transactions_for_block(transactions: &[Transaction]) -> Result<()> {
        for transaction in transactions {
            if !crate::utils::validation::quick_validate_transaction(transaction) {
                return Err(anyhow::anyhow!("Invalid transaction in block"));
            }
        }
        Ok(())
    }
    
    /// Check if block would exceed limits
    pub fn check_block_limits(transactions: &[Transaction]) -> Result<()> {
        if transactions.len() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(anyhow::anyhow!("Too many transactions for block"));
        }
        
        let total_size = calculate_optimal_block_size(transactions);
        if total_size > crate::MAX_BLOCK_SIZE {
            return Err(anyhow::anyhow!("Block size exceeds limit"));
        }
        
        Ok(())
    }
}
