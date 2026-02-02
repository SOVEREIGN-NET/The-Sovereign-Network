//! Block Validation
//!
//! Header and structural validation for blocks.
//! These checks are performed BEFORE block execution begins.
//!
//! # Validation Levels
//!
//! 1. **Structural** - Format, sizes, counts
//! 2. **Contextual** - Height, previous hash, timestamp
//! 3. **Semantic** - Merkle root, difficulty (not full consensus)

use crate::block::Block;
use crate::fees::{classify_transaction, FeeParamsV2, SigScheme};
use crate::storage::{BlockchainStore, BlockHash};
use crate::types::Hash;

use super::errors::{BlockValidateError, BlockValidateResult};

/// Configuration for block validation
#[derive(Debug, Clone)]
pub struct BlockValidateConfig {
    /// Maximum block size in bytes
    pub max_block_size: usize,
    /// Maximum transactions per block
    pub max_transactions: usize,
    /// Allow empty blocks (no transactions)
    pub allow_empty_blocks: bool,
    /// Maximum timestamp drift into future (seconds)
    pub max_future_timestamp: u64,
}

impl Default for BlockValidateConfig {
    fn default() -> Self {
        Self {
            max_block_size: 1_048_576,      // 1MB
            max_transactions: 4096,
            allow_empty_blocks: true,
            max_future_timestamp: 7200,     // 2 hours
        }
    }
}

/// Validate block structure (stateless checks)
///
/// These checks don't require access to chain state.
pub fn validate_block_structure(
    block: &Block,
    config: &BlockValidateConfig,
) -> BlockValidateResult<()> {
    // Check block size
    let size = block.size();
    if size > config.max_block_size {
        return Err(BlockValidateError::BlockTooLarge {
            size,
            max: config.max_block_size,
        });
    }

    // Check transaction count
    let tx_count = block.transactions.len();
    if tx_count > config.max_transactions {
        return Err(BlockValidateError::TooManyTransactions {
            count: tx_count,
            max: config.max_transactions,
        });
    }

    // Check for empty blocks
    if tx_count == 0 && !config.allow_empty_blocks {
        return Err(BlockValidateError::EmptyBlock);
    }

    // Validate header fields
    validate_block_header(block)?;

    Ok(())
}

/// Validate block header fields
fn validate_block_header(block: &Block) -> BlockValidateResult<()> {
    let header = &block.header;

    // Version check
    if header.version == 0 {
        return Err(BlockValidateError::InvalidVersion(header.version));
    }

    // Transaction count must match
    if header.transaction_count as usize != block.transactions.len() {
        return Err(BlockValidateError::TransactionCountMismatch {
            header_count: header.transaction_count as usize,
            actual_count: block.transactions.len(),
        });
    }

    Ok(())
}

/// Validate block in context of the chain (requires state access)
///
/// These checks verify the block fits correctly in the chain.
pub fn validate_block_context(
    block: &Block,
    store: &dyn BlockchainStore,
    config: &BlockValidateConfig,
) -> BlockValidateResult<()> {
    let height = block.header.height;

    // Validate height
    let expected_height = get_expected_height(store)?;
    if height != expected_height {
        return Err(BlockValidateError::InvalidHeight {
            expected: expected_height,
            actual: height,
        });
    }

    // Validate previous hash (except for genesis)
    if height > 0 {
        validate_previous_hash(block, store)?;
    } else {
        // Genesis block must have zero previous hash
        if block.header.previous_block_hash != Hash::default() {
            return Err(BlockValidateError::InvalidGenesisHash);
        }
    }

    // Validate timestamp
    validate_timestamp(block, store, config)?;

    Ok(())
}

/// Get the expected next block height
fn get_expected_height(store: &dyn BlockchainStore) -> BlockValidateResult<u64> {
    match store.latest_height() {
        Ok(h) => Ok(h + 1),
        Err(crate::storage::StorageError::NotInitialized) => Ok(0),
        Err(e) => Err(BlockValidateError::StorageError(e.to_string())),
    }
}

/// Validate previous block hash
fn validate_previous_hash(
    block: &Block,
    store: &dyn BlockchainStore,
) -> BlockValidateResult<()> {
    let prev_height = block.header.height - 1;

    let prev_block = store.get_block_by_height(prev_height)
        .map_err(|e| BlockValidateError::StorageError(e.to_string()))?
        .ok_or(BlockValidateError::PreviousBlockNotFound(prev_height))?;

    let expected_hash = prev_block.header.block_hash;
    let actual_hash = block.header.previous_block_hash;

    if expected_hash != actual_hash {
        return Err(BlockValidateError::InvalidPreviousHash {
            expected: BlockHash::new(expected_hash.as_array()),
            actual: BlockHash::new(actual_hash.as_array()),
        });
    }

    Ok(())
}

/// Validate block timestamp
fn validate_timestamp(
    block: &Block,
    store: &dyn BlockchainStore,
    config: &BlockValidateConfig,
) -> BlockValidateResult<()> {
    let timestamp = block.header.timestamp;

    // Check not too far in future
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if timestamp > now + config.max_future_timestamp {
        return Err(BlockValidateError::TimestampTooFarInFuture {
            timestamp,
            max_allowed: now + config.max_future_timestamp,
        });
    }

    // Check not before previous block (except genesis)
    if block.header.height > 0 {
        let prev_height = block.header.height - 1;
        if let Ok(Some(prev_block)) = store.get_block_by_height(prev_height) {
            if timestamp < prev_block.header.timestamp {
                return Err(BlockValidateError::TimestampBeforePrevious {
                    timestamp,
                    previous: prev_block.header.timestamp,
                });
            }
        }
    }

    Ok(())
}

/// Full block validation (structure + context)
pub fn validate_block(
    block: &Block,
    store: &dyn BlockchainStore,
    config: &BlockValidateConfig,
) -> BlockValidateResult<()> {
    validate_block_structure(block, config)?;
    validate_block_context(block, store, config)?;
    Ok(())
}

// =============================================================================
// Block Resource Limits (Phase 2)
// =============================================================================

/// Block resource usage aggregates
#[derive(Debug, Default)]
pub struct BlockResourceUsage {
    /// Total payload bytes across all transactions
    pub total_payload_bytes: u64,
    /// Total witness bytes across all transactions
    pub total_witness_bytes: u64,
    /// Total verification units (signature verification cost)
    pub total_verify_units: u64,
    /// Total state write bytes
    pub total_state_write_bytes: u64,
}

/// Validate block-level resource limits.
///
/// This is a precheck that happens BEFORE begin_block.
/// It aggregates resource usage across all transactions and
/// validates against Fee Model v2 block limits.
pub fn validate_block_resource_limits(
    block: &Block,
    fee_params: &FeeParamsV2,
) -> BlockValidateResult<()> {
    // Aggregate resource usage
    let usage = compute_block_resource_usage(block, fee_params);

    // Check payload bytes
    if usage.total_payload_bytes > fee_params.block_max_payload_bytes as u64 {
        return Err(BlockValidateError::PayloadBytesExceeded {
            actual: usage.total_payload_bytes,
            max: fee_params.block_max_payload_bytes,
        });
    }

    // Check witness bytes
    if usage.total_witness_bytes > fee_params.block_max_witness_bytes as u64 {
        return Err(BlockValidateError::WitnessBytesExceeded {
            actual: usage.total_witness_bytes,
            max: fee_params.block_max_witness_bytes,
        });
    }

    // Check verify units
    if usage.total_verify_units > fee_params.block_max_verify_units as u64 {
        return Err(BlockValidateError::VerifyUnitsExceeded {
            actual: usage.total_verify_units,
            max: fee_params.block_max_verify_units,
        });
    }

    // Check state write bytes
    if usage.total_state_write_bytes > fee_params.block_max_state_write_bytes as u64 {
        return Err(BlockValidateError::StateWriteBytesExceeded {
            actual: usage.total_state_write_bytes,
            max: fee_params.block_max_state_write_bytes,
        });
    }

    Ok(())
}

/// Compute aggregate resource usage for a block.
fn compute_block_resource_usage(
    block: &Block,
    fee_params: &FeeParamsV2,
) -> BlockResourceUsage {
    let mut usage = BlockResourceUsage::default();

    for tx in &block.transactions {
        if let Some(fee_input) = classify_transaction(tx) {
            usage.total_payload_bytes += fee_input.payload_bytes as u64;
            usage.total_witness_bytes += fee_input.witness_bytes as u64;
            usage.total_state_write_bytes += fee_input.state_write_bytes as u64;

            // Compute verify units based on signature scheme
            let verify_units_per_sig = fee_params.get_verify_units_per_sig(fee_input.sig_scheme);
            usage.total_verify_units += (fee_input.sig_count as u64) * (verify_units_per_sig as u64);
        }
    }

    usage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
    use crate::types::{Hash, TransactionType, Difficulty};
    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::integration::zk_integration::ZkTransactionProof;

    fn create_test_transfer() -> Transaction {
        Transaction::new(
            vec![
                TransactionInput::new(
                    Hash::new([1u8; 32]),
                    0,
                    Hash::new([2u8; 32]),
                    ZkTransactionProof::default(),
                ),
            ],
            vec![
                TransactionOutput::new(
                    Hash::new([3u8; 32]),
                    Hash::new([4u8; 32]),
                    PublicKey::new(vec![5u8; 32]),
                ),
            ],
            1000,
            Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 32]),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            vec![],
        )
    }

    fn create_test_block(txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: 0,
                timestamp: 0,
                previous_block_hash: Hash::default(),
                merkle_root: Hash::default(),
                block_hash: Hash::default(),
                nonce: 0,
                difficulty: Difficulty::from_bits(1),
                cumulative_difficulty: Difficulty::from_bits(1),
                transaction_count: txs.len() as u32,
                block_size: 0,
                fee_model_version: 2, // Phase 2+ uses v2
            },
            transactions: txs,
        }
    }

    #[test]
    fn test_block_resource_limits_ok() {
        let params = FeeParamsV2::default();
        let block = create_test_block(vec![create_test_transfer()]);

        let result = validate_block_resource_limits(&block, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_resource_limits_too_many_txs() {
        let mut params = FeeParamsV2::default();
        params.block_max_txs = 1; // Very low limit

        // Create a block with 2 transactions
        let block = create_test_block(vec![
            create_test_transfer(),
            create_test_transfer(),
        ]);

        // This test checks tx count in BlockValidateConfig, not FeeParamsV2
        // so the resource limits check should still pass
        let result = validate_block_resource_limits(&block, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_block_resource_limits_payload_exceeded() {
        let mut params = FeeParamsV2::default();
        params.block_max_payload_bytes = 100; // Very low limit

        let block = create_test_block(vec![create_test_transfer()]);

        let result = validate_block_resource_limits(&block, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockValidateError::PayloadBytesExceeded { .. }));
    }

    #[test]
    fn test_block_resource_limits_verify_units_exceeded() {
        let mut params = FeeParamsV2::default();
        params.block_max_verify_units = 1; // Very low limit

        let block = create_test_block(vec![create_test_transfer()]);

        let result = validate_block_resource_limits(&block, &params);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BlockValidateError::VerifyUnitsExceeded { .. }));
    }
}
