//! Storage-specific error types and recovery strategies

use thiserror::Error;

/// Storage layer result type
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage-specific errors with recovery information
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Storage corruption detected: {0}")]
    Corruption(String),

    #[error("Write operation failed: {0}")]
    WriteFailed(String),

    #[error("WAL recovery failed: {0}")]
    WalRecovery(String),

    #[error("Cache operation failed: {0}")]
    CacheError(String),

    #[error("State inconsistency detected: {0}")]
    StateInconsistency(String),

    #[error("Sled backend error: {0}")]
    BackendError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid state root: {0}")]
    InvalidStateRoot(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::SerializationError(err.to_string())
    }
}

impl From<String> for StorageError {
    fn from(msg: String) -> Self {
        StorageError::Internal(anyhow::anyhow!(msg))
    }
}

/// Recovery strategy for different error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy {
    /// Fail the operation and propagate error
    Fail,
    /// Use the last known good state
    UseLastGoodState,
    /// Skip this operation and continue
    Skip,
    /// Attempt automatic repair
    Repair,
    /// Require manual intervention
    Manual,
}

impl StorageError {
    /// Determine the appropriate recovery strategy for this error
    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            StorageError::Corruption(_) => RecoveryStrategy::Manual,
            StorageError::WriteFailed(_) => RecoveryStrategy::Repair,
            StorageError::WalRecovery(_) => RecoveryStrategy::Repair,
            StorageError::CacheError(_) => RecoveryStrategy::Skip,
            StorageError::StateInconsistency(_) => RecoveryStrategy::UseLastGoodState,
            StorageError::BackendError(_) => RecoveryStrategy::Fail,
            StorageError::SerializationError(_) => RecoveryStrategy::Fail,
            StorageError::InvalidStateRoot(_) => RecoveryStrategy::Repair,
            StorageError::KeyNotFound(_) => RecoveryStrategy::Skip,
            StorageError::Internal(_) => RecoveryStrategy::Fail,
        }
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        !matches!(self.recovery_strategy(), RecoveryStrategy::Fail | RecoveryStrategy::Manual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_strategies() {
        assert_eq!(
            StorageError::CacheError("test".to_string()).recovery_strategy(),
            RecoveryStrategy::Skip
        );
        assert_eq!(
            StorageError::Corruption("test".to_string()).recovery_strategy(),
            RecoveryStrategy::Manual
        );
    }
}
