//! Token Contract Errors

use lib_types::{Amount, TokenId};
use thiserror::Error;

/// Error during token operations
#[derive(Error, Debug, Clone)]
pub enum TokenError {
    #[error("Contract is paused")]
    Paused,

    #[error("Transfer not allowed by policy: {0}")]
    TransferNotAllowed(String),

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: Amount, need: Amount },

    #[error("Token not found: {0:?}")]
    TokenNotFound(TokenId),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Zero amount not allowed")]
    ZeroAmount,

    #[error("Arithmetic overflow")]
    Overflow,

    #[error("Arithmetic underflow")]
    Underflow,

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Supply cap exceeded: max {max}, would have {would_have}")]
    SupplyCapExceeded { max: Amount, would_have: Amount },

    #[error("Invalid spec version: expected 2, got {0}")]
    InvalidSpecVersion(u16),

    #[error("Conservation invariant violated: {0}")]
    ConservationViolated(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type for token operations
pub type TokenResult<T> = Result<T, TokenError>;
