//! UTXO Errors

use thiserror::Error;
use lib_types::Amount;

use crate::types::OutPoint;

/// Error during UTXO operations
#[derive(Error, Debug, Clone)]
pub enum UtxoError {
    #[error("UTXO not found: {0:?}")]
    NotFound(OutPoint),

    #[error("UTXO already spent: {0:?}")]
    AlreadySpent(OutPoint),

    #[error("UTXO locked until height {lock_height}, current height is {current_height}")]
    Locked {
        outpoint: OutPoint,
        lock_height: u64,
        current_height: u64,
    },

    #[error("Duplicate input: {0:?}")]
    DuplicateInput(OutPoint),

    #[error("Insufficient input value: have {have}, need {need}")]
    InsufficientInput { have: Amount, need: Amount },

    #[error("Value mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    ValueMismatch {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },

    #[error("Empty inputs")]
    EmptyInputs,

    #[error("Empty outputs")]
    EmptyOutputs,

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Arithmetic overflow")]
    Overflow,

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type for UTXO operations
pub type UtxoResult<T> = Result<T, UtxoError>;
