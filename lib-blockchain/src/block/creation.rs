//! Block creation utilities
//!
//! Functions for creating new blocks from transactions.

use crate::block::{Block, BlockHeader};
use crate::transaction::Transaction;
use crate::types::{Difficulty, Hash};
use anyhow::Result;

/// Block builder for constructing new blocks
#[derive(Debug)]
pub struct BlockBuilder {
    version: u32,
    previous_block_hash: Hash,
    timestamp: u64,
    difficulty: Difficulty,
    height: u64,
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    /// Create a new block builder
    pub fn new(previous_block_hash: Hash, height: u64, difficulty: Difficulty) -> Self {
        Self {
            version: 1,
            previous_block_hash,
            timestamp: crate::utils::time::current_timestamp(),
            difficulty,
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
        let merkle_root =
            crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions);

        // Calculate block size
        let transaction_count = self.transactions.len() as u32;
        let block_size = self.calculate_block_size();

        // Calculate cumulative difficulty (simplified)
        let cumulative_difficulty = self.difficulty;

        // Create header
        let header = BlockHeader::new(
            self.version,
            self.previous_block_hash,
            merkle_root,
            self.timestamp,
            self.difficulty,
            self.height,
            transaction_count,
            block_size,
            cumulative_difficulty,
        );

        Ok(Block::new(header, self.transactions))
    }

    /// Calculate the size of the block being built
    fn calculate_block_size(&self) -> u32 {
        let header_size = 200; // Approximate header size
        let transactions_size: usize = self
            .transactions
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
    difficulty: Difficulty,
) -> Result<Block> {
    BlockBuilder::new(previous_block_hash, height, difficulty)
        .transactions(transactions)
        .build()
}

/// Create genesis block
pub fn create_genesis_block_with_transactions(transactions: Vec<Transaction>) -> Result<Block> {
    BlockBuilder::new(Hash::default(), 0, Difficulty::minimum())
        .timestamp(crate::GENESIS_TIMESTAMP)
        .transactions(transactions)
        .build()
}

/// Mine a block (find valid nonce)
///
/// # Arguments
/// * `block` - Block to mine
/// * `max_iterations` - Maximum iterations before giving up
///
/// # Deprecated
/// Use `mine_block_with_config` instead for environment-aware mining
pub fn mine_block(mut block: Block, max_iterations: u64) -> Result<Block> {
    mine_block_internal(&mut block, max_iterations, false)
}

/// Mine a block using environment-aware configuration
///
/// # Arguments
/// * `block` - Block to mine
/// * `config` - Mining configuration from MiningProfile
///
/// This is the preferred method for mining as it uses profile-appropriate settings.
pub fn mine_block_with_config(
    mut block: Block,
    config: &crate::types::MiningConfig,
) -> Result<Block> {
    // If instant mining is allowed and we're in bootstrap mode, skip PoW entirely
    if config.allow_instant_mining {
        block.header.set_nonce(0);
        // For bootstrap, we accept any hash - just set nonce and return
        tracing::info!("⚡ Bootstrap mode: instant mining enabled, skipping PoW");
        return Ok(block);
    }

    mine_block_internal(
        &mut block,
        config.max_iterations,
        config.max_iterations <= 100_000,
    )
}

/// Internal mining implementation
fn mine_block_internal(
    block: &mut Block,
    max_iterations: u64,
    low_iteration_mode: bool,
) -> Result<Block> {
    let mut iterations = 0;
    let log_interval = if low_iteration_mode {
        10_000
    } else {
        1_000_000
    };

    while iterations < max_iterations {
        // Update nonce and recalculate hash
        block.header.set_nonce(iterations);

        // Check if block meets difficulty target
        if block.header.meets_difficulty_target() {
            tracing::info!("✓ Block mined in {} iterations", iterations);
            return Ok(block.clone());
        }

        iterations += 1;

        // Log progress
        if iterations % log_interval == 0 {
            tracing::info!("Mining progress: {} iterations", iterations);
        }
    }

    Err(anyhow::anyhow!(
        "Failed to mine block within {} iterations",
        max_iterations
    ))
}

/// Estimate block creation time
pub fn estimate_block_time(transaction_count: usize, difficulty: Difficulty) -> u64 {
    // Very rough estimation based on transaction count and difficulty
    let base_time = 10; // 10 seconds base
    let tx_time = transaction_count as u64 / 100; // 100 tx/second processing
    let difficulty_factor = difficulty.bits() >> 24; // Rough difficulty scaling

    base_time + tx_time + difficulty_factor as u64
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
        fee_rate_b
            .partial_cmp(&fee_rate_a)
            .unwrap_or(std::cmp::Ordering::Equal)
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
            .sum::<usize>()
            + 200 // Add header size
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
