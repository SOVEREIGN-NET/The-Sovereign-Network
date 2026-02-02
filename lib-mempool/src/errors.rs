//! Mempool Admission Errors

use thiserror::Error;
use lib_types::{Address, Amount};

/// Specific reason for admission rejection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitErrorKind {
    // Fee errors
    InsufficientFee { required: Amount, provided: Amount },

    // Size errors
    TxTooLarge { size: u32, max: u32 },
    WitnessTooLarge { size: u32, max: u32 },
    TooManyInputs { count: u16, max: u16 },
    TooManyOutputs { count: u16, max: u16 },
    TooManySignatures { count: u8, max: u8 },

    // Mempool capacity errors
    MempoolFull,
    MempoolBytesFull { current: u64, max: u64 },
    SenderLimitReached { sender: Address, count: u32, max: u32 },
    RateLimited { sender: Address, period_count: u32, max: u32 },

    // Validation errors
    InvalidTransaction(String),
    DuplicateTransaction,
}

/// Error during mempool admission
#[derive(Error, Debug, Clone)]
#[error("Admission rejected: {kind:?}")]
pub struct AdmitError {
    pub kind: AdmitErrorKind,
}

impl AdmitError {
    pub fn new(kind: AdmitErrorKind) -> Self {
        Self { kind }
    }

    pub fn insufficient_fee(required: Amount, provided: Amount) -> Self {
        Self::new(AdmitErrorKind::InsufficientFee { required, provided })
    }

    pub fn tx_too_large(size: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::TxTooLarge { size, max })
    }

    pub fn witness_too_large(size: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::WitnessTooLarge { size, max })
    }

    pub fn too_many_inputs(count: u16, max: u16) -> Self {
        Self::new(AdmitErrorKind::TooManyInputs { count, max })
    }

    pub fn too_many_outputs(count: u16, max: u16) -> Self {
        Self::new(AdmitErrorKind::TooManyOutputs { count, max })
    }

    pub fn too_many_signatures(count: u8, max: u8) -> Self {
        Self::new(AdmitErrorKind::TooManySignatures { count, max })
    }

    pub fn mempool_full() -> Self {
        Self::new(AdmitErrorKind::MempoolFull)
    }

    pub fn mempool_bytes_full(current: u64, max: u64) -> Self {
        Self::new(AdmitErrorKind::MempoolBytesFull { current, max })
    }

    pub fn sender_limit(sender: Address, count: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::SenderLimitReached { sender, count, max })
    }

    pub fn rate_limited(sender: Address, period_count: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::RateLimited { sender, period_count, max })
    }

    pub fn invalid_transaction(reason: impl Into<String>) -> Self {
        Self::new(AdmitErrorKind::InvalidTransaction(reason.into()))
    }

    pub fn duplicate() -> Self {
        Self::new(AdmitErrorKind::DuplicateTransaction)
    }
}

impl From<AdmitErrorKind> for AdmitError {
    fn from(kind: AdmitErrorKind) -> Self {
        Self::new(kind)
    }
}
