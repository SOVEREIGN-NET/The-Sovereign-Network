//! Mempool Admission Errors
//!
//! Note: The canonical error kind definition (`AdmitErrorKind`) lives in lib-types
//! and is re-exported here. This module defines `AdmitError` and provides
//! convenience constructors for building specific admission errors.

pub use lib_types::mempool::AdmitErrorKind;
use lib_types::{Address, Amount};
use thiserror::Error;

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
        Self::new(AdmitErrorKind::MempoolBytesFull {
            prospective_total_bytes: current,
            max,
        })
    }

    pub fn sender_limit(sender: Address, count: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::SenderLimitReached { sender, count, max })
    }

    pub fn rate_limited(sender: Address, period_count: u32, max: u32) -> Self {
        Self::new(AdmitErrorKind::RateLimited {
            sender,
            period_count,
            max,
        })
    }

    pub fn invalid_transaction(msg: impl Into<String>) -> Self {
        Self::new(AdmitErrorKind::InvalidTransaction(msg.into()))
    }

    pub fn duplicate_transaction() -> Self {
        Self::new(AdmitErrorKind::DuplicateTransaction)
    }

    /// Deprecated alias for `duplicate_transaction()`
    #[deprecated(since = "0.1.0", note = "Use duplicate_transaction() instead")]
    pub fn duplicate() -> Self {
        Self::duplicate_transaction()
    }
}

impl From<AdmitErrorKind> for AdmitError {
    fn from(kind: AdmitErrorKind) -> Self {
        Self::new(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_constructors() {
        let err = AdmitError::insufficient_fee(100, 50);
        assert!(matches!(
            err.kind,
            AdmitErrorKind::InsufficientFee {
                required: 100,
                provided: 50
            }
        ));

        let err = AdmitError::tx_too_large(200, 100);
        assert!(matches!(
            err.kind,
            AdmitErrorKind::TxTooLarge {
                size: 200,
                max: 100
            }
        ));

        let err = AdmitError::mempool_full();
        assert!(matches!(err.kind, AdmitErrorKind::MempoolFull));

        let err = AdmitError::duplicate_transaction();
        assert!(matches!(err.kind, AdmitErrorKind::DuplicateTransaction));
    }

    #[test]
    fn test_error_display() {
        let err = AdmitError::mempool_full();
        let display = format!("{}", err);
        assert!(display.contains("Admission rejected"));
    }
}
