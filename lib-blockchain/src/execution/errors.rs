//! Execution Errors
//!
//! Error types for block and transaction execution.
//! These are distinct from storage errors - execution errors represent
//! semantic failures (invalid tx, double spend, etc).

use thiserror::Error;

use crate::storage::{BlockHash, OutPoint, Address, TokenId, StorageError};

/// Error during block application
#[derive(Error, Debug)]
pub enum BlockApplyError {
    #[error("Block height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },

    #[error("Block hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: BlockHash, actual: BlockHash },

    #[error("Invalid previous block hash: expected {expected}, got {actual}")]
    InvalidPreviousHash { expected: BlockHash, actual: BlockHash },

    #[error("Block validation failed: {0}")]
    ValidationFailed(String),

    #[error("Invalid fee model version: got {actual}, expected {expected} at height {height}")]
    InvalidFeeModelVersion {
        height: u64,
        actual: u16,
        expected: u16,
    },

    #[error("Transaction failed at index {index}: {reason}")]
    TxFailed { index: usize, reason: TxApplyError },

    #[error("Failed to persist block: {0}")]
    PersistFailed(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Empty block (no transactions)")]
    EmptyBlock,

    #[error("Block too large: {size} bytes, max {max}")]
    BlockTooLarge { size: usize, max: usize },

    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
}

/// Error during transaction application
#[derive(Error, Debug, Clone)]
pub enum TxApplyError {
    // =========================================================================
    // Validation Errors (stateless)
    // =========================================================================

    #[error("Invalid transaction version: {0}")]
    InvalidVersion(u32),

    #[error("Invalid transaction type: {0}")]
    InvalidType(String),

    #[error("Unsupported transaction type for Phase 2: {0}")]
    UnsupportedType(String),

    #[error("Empty inputs")]
    EmptyInputs,

    #[error("Empty outputs")]
    EmptyOutputs,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Duplicate input: {0}")]
    DuplicateInput(OutPoint),

    #[error("Insufficient fee: required {required}, paid {paid}")]
    InsufficientFee { required: u64, paid: u64 },

    // =========================================================================
    // UTXO Errors (stateful)
    // =========================================================================

    #[error("UTXO not found: {0}")]
    UtxoNotFound(OutPoint),

    #[error("UTXO already spent: {0}")]
    UtxoAlreadySpent(OutPoint),

    #[error("Input/output value mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    ValueMismatch { inputs: u64, outputs: u64, fee: u64 },

    #[error("Insufficient input value: have {have}, need {need}")]
    InsufficientInputs { have: u64, need: u64 },

    // =========================================================================
    // Token Errors (stateful)
    // =========================================================================

    #[error("Insufficient token balance: have {have}, need {need}, token={token}")]
    InsufficientBalance { have: u128, need: u128, token: TokenId },

    #[error("Token not found: {0}")]
    TokenNotFound(TokenId),

    #[error("Invalid token amount: {0}")]
    InvalidTokenAmount(String),

    // =========================================================================
    // Account Errors
    // =========================================================================

    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Account not found: {0}")]
    AccountNotFound(Address),

    // =========================================================================
    // Authorization Errors
    // =========================================================================

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    // =========================================================================
    // General Errors
    // =========================================================================

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<StorageError> for TxApplyError {
    fn from(e: StorageError) -> Self {
        TxApplyError::Storage(e.to_string())
    }
}

/// Result type for block application
pub type BlockApplyResult<T> = Result<T, BlockApplyError>;

/// Result type for transaction application
pub type TxApplyResult<T> = Result<T, TxApplyError>;
