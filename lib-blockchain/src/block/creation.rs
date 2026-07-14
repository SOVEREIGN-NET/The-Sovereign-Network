//! Block creation utilities
//!
//! Functions for creating new blocks from transactions.

use crate::block::{Block, BlockHeader};
use crate::transaction::Transaction;
use crate::types::{Difficulty, Hash, MiningConfig};
use anyhow::Result;
use std::collections::HashSet;

/// Block builder for constructing new blocks
#[derive(Debug)]
pub struct BlockBuilder {
    version: u32,
    previous_hash: Hash,
    timestamp: u64,
    height: u64,
    transactions: Vec<Transaction>,
}

impl BlockBuilder {
    /// Create a new block builder
    pub fn new(previous_hash: Hash, height: u64, _difficulty: Difficulty) -> Self {
        Self {
            version: 1,
            previous_hash,
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
        let data_helix_root =
            crate::transaction::hashing::calculate_transaction_merkle_root(&self.transactions);

        // Create header
        let header = BlockHeader::new(
            self.version,
            self.previous_hash,
            data_helix_root,
            self.timestamp,
            self.height,
        );

        Ok(Block::new(header, self.transactions))
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
    BlockBuilder::new(Hash::default(), 0, Difficulty::maximum())
        .timestamp(crate::GENESIS_TIMESTAMP)
        .transactions(transactions)
        .build()
}

/// Mine a block with a bounded number of nonce iterations.
pub fn mine_block(block: Block, max_iterations: u64) -> Result<Block> {
    let mut config = MiningConfig::testnet();
    config.max_iterations = max_iterations;
    mine_block_with_config(block, &config)
}

/// Mine a block using a provided mining configuration.
pub fn mine_block_with_config(mut block: Block, _config: &MiningConfig) -> Result<Block> {
    block.header.block_hash = block.header.calculate_hash();
    Ok(block)
}

/// Estimate expected mining time in seconds at a given hash rate.
pub fn estimate_block_time(difficulty: Difficulty, hash_rate_hps: f64) -> f64 {
    if hash_rate_hps <= 0.0 {
        return f64::INFINITY;
    }
    (difficulty.bits() as f64).max(1.0) / hash_rate_hps
}

/// Select transactions for block creation.
///
/// Transactions are sorted by fee rate (highest first) and selected greedily
/// up to the block limits.  The optional `is_valid` predicate is called for
/// each candidate — if it returns `false` the transaction is skipped.  Pass
/// a nonce-checking closure here to prevent stale-nonce transactions from
/// entering a block proposal.
pub fn select_transactions_for_block(
    available_transactions: &[Transaction],
    max_transactions: usize,
    max_block_size: usize,
) -> Vec<Transaction> {
    select_transactions_for_block_filtered(available_transactions, max_transactions, max_block_size, |_| true)
}

/// Like [`select_transactions_for_block`] but accepts a predicate that gates
/// each candidate transaction.  Transactions for which `is_valid` returns
/// `false` are silently skipped.
pub fn select_transactions_for_block_filtered(
    available_transactions: &[Transaction],
    max_transactions: usize,
    max_block_size: usize,
    is_valid: impl Fn(&Transaction) -> bool,
) -> Vec<Transaction> {
    let mut selected = Vec::new();
    let mut total_size = 0;
    let mut seen_hashes = HashSet::new();

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

        if !is_valid(tx) {
            continue;
        }

        if !seen_hashes.insert(tx.hash()) {
            continue;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::types::TransactionType;

    fn make_tx(fee: u64) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee,
            signature: Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new([1u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: vec![],
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    #[test]
    fn select_transactions_filters_token_creation_at_sunset_block_height() {
        use crate::contracts::sovereign_asset::token_creation_allowed_in_block_at_height_with_sunset;
        use crate::types::TransactionType;

        let sunset = 10u64;
        let block_height = sunset;
        let token_tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenCreation,
            inputs: vec![],
            outputs: vec![],
            fee: 100,
            signature: crate::integration::crypto_integration::Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new([1u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: vec![],
            payload: crate::transaction::TransactionPayload::None,
        };
        let transfer = make_tx(200);

        let selected = select_transactions_for_block_filtered(
            &[token_tx, transfer],
            10,
            usize::MAX,
            |tx| {
                if tx.transaction_type == TransactionType::TokenCreation {
                    token_creation_allowed_in_block_at_height_with_sunset(block_height, sunset)
                } else {
                    true
                }
            },
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].transaction_type, TransactionType::Transfer);
    }

    #[test]
    fn select_transactions_dedupes_by_hash() {
        let tx = make_tx(100);
        let duplicate = tx.clone();
        let other = make_tx(200);

        let selected = select_transactions_for_block(
            &[tx, duplicate, other],
            10,
            usize::MAX,
        );

        assert_eq!(selected.len(), 2);
        assert_ne!(selected[0].hash(), selected[1].hash());
        assert_eq!(selected[0].fee, 200);
        assert_eq!(selected[1].fee, 100);
    }
}
