//! Validation Errors
//!
//! Error types for block and transaction validation.
//! These are distinct from execution errors - validation errors
//! indicate the block/tx is malformed or invalid BEFORE execution.

use thiserror::Error;

use crate::storage::{BlockHash, OutPoint};

/// Block validation error
#[derive(Error, Debug)]
pub enum BlockValidateError {
    #[error("Block too large: {size} bytes, max {max}")]
    BlockTooLarge { size: usize, max: usize },

    #[error("Too many transactions: {count}, max {max}")]
    TooManyTransactions { count: usize, max: usize },

    #[error("Empty block (no transactions)")]
    EmptyBlock,

    #[error("Invalid block version: {0}")]
    InvalidVersion(u32),

    #[error("Transaction count mismatch: header says {header_count}, actual {actual_count}")]
    TransactionCountMismatch { header_count: usize, actual_count: usize },

    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidHeight { expected: u64, actual: u64 },

    #[error("Invalid previous block hash: expected {expected}, got {actual}")]
    InvalidPreviousHash { expected: BlockHash, actual: BlockHash },

    #[error("Previous block not found at height {0}")]
    PreviousBlockNotFound(u64),

    #[error("Genesis block must have zero previous hash")]
    InvalidGenesisHash,

    #[error("Timestamp too far in future: {timestamp} > {max_allowed}")]
    TimestampTooFarInFuture { timestamp: u64, max_allowed: u64 },

    #[error("Timestamp before previous block: {timestamp} < {previous}")]
    TimestampBeforePrevious { timestamp: u64, previous: u64 },

    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    #[error("Invalid difficulty")]
    InvalidDifficulty,

    #[error("Storage error: {0}")]
    StorageError(String),

    // =========================================================================
    // Block Resource Limit Errors
    // =========================================================================

    #[error("Block payload bytes exceeded: {actual} > max {max}")]
    PayloadBytesExceeded { actual: u64, max: u32 },

    #[error("Block witness bytes exceeded: {actual} > max {max}")]
    WitnessBytesExceeded { actual: u64, max: u32 },

    #[error("Block verify units exceeded: {actual} > max {max}")]
    VerifyUnitsExceeded { actual: u64, max: u32 },

    #[error("Block state write bytes exceeded: {actual} > max {max}")]
    StateWriteBytesExceeded { actual: u64, max: u32 },
}

/// Transaction validation error
#[derive(Error, Debug, Clone)]
pub enum TxValidateError {
    // =========================================================================
    // Type Errors
    // =========================================================================

    #[error("Unsupported transaction type for Phase 2: {0}")]
    UnsupportedType(String),

    #[error("Invalid transaction version: {0}")]
    InvalidVersion(u32),

    // =========================================================================
    // Structure Errors
    // =========================================================================

    #[error("Transaction has no inputs")]
    EmptyInputs,

    #[error("Transaction has no outputs")]
    EmptyOutputs,

    #[error("Duplicate input: {0}")]
    DuplicateInput(OutPoint),

    #[error("Coinbase transaction must not have inputs")]
    CoinbaseHasInputs,

    #[error("Invalid transaction structure: {0}")]
    InvalidStructure(String),

    // =========================================================================
    // UTXO Errors
    // =========================================================================

    #[error("UTXO not found: {0}")]
    UtxoNotFound(OutPoint),

    #[error("Insufficient inputs: have {have}, need {need}")]
    InsufficientInputs { have: u64, need: u64 },

    // =========================================================================
    // Fee Errors
    // =========================================================================

    #[error("Fee too low: {fee} < minimum {min_fee}")]
    FeeTooLow { fee: u64, min_fee: u64 },

    #[error("TokenMint must have zero fee, got {0}")]
    TokenMintNonZeroFee(u64),

    #[error("Coinbase must have zero fee, got {0}")]
    CoinbaseNonZeroFee(u64),

    // =========================================================================
    // Signature Errors
    // =========================================================================

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // =========================================================================
    // Field Errors
    // =========================================================================

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    // =========================================================================
    // Block Limit Errors
    // =========================================================================

    #[error("Block limit exceeded: {0}")]
    BlockLimitExceeded(String),

    // =========================================================================
    // General Errors
    // =========================================================================

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Result type for block validation
pub type BlockValidateResult<T> = Result<T, BlockValidateError>;

/// Result type for transaction validation
pub type TxValidateResult<T> = Result<T, TxValidateError>;
