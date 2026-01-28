//! Cross-contract call error types
//!
//! All errors from cross-contract calls are wrapped in CrossContractError
//! to prevent ABI leakage and maintain deterministic failure modes.

use std::fmt;

/// Type alias for contract ID (32-byte hash)
pub type ContractId = [u8; 32];

/// Error code returned by called contract
///
/// Only the category is exposed, not the original error message,
/// to prevent ABI information leakage between contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CalleeErrorCode {
    /// Called contract's validation failed
    ValidationFailed = 1,
    /// Called contract's execution failed
    ExecutionFailed = 2,
    /// Method not found in callee
    NotFound = 3,
    /// Caller lacks permission
    PermissionDenied = 4,
    /// Call depth exceeded (recursion limit)
    CallDepthExceeded = 5,
    /// Unknown error
    Unknown = 99,
}

impl fmt::Display for CalleeErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed => write!(f, "ValidationFailed"),
            Self::ExecutionFailed => write!(f, "ExecutionFailed"),
            Self::NotFound => write!(f, "NotFound"),
            Self::PermissionDenied => write!(f, "PermissionDenied"),
            Self::CallDepthExceeded => write!(f, "CallDepthExceeded"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Error from a cross-contract call
///
/// Wraps all errors from called contracts to prevent information leakage.
/// Callers only see:
/// - Which contract failed
/// - Which method was called
/// - Error category (not detailed message)
/// - Hash of original error (for debugging/logging)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossContractError {
    /// ID of the contract that failed
    pub callee: ContractId,
    /// Name of the method that failed
    pub method: String,
    /// Error category
    pub code: CalleeErrorCode,
    /// Blake3 hash of original error details (for debugging)
    pub reason_hash: [u8; 32],
}

impl CrossContractError {
    /// Create a new cross-contract error
    pub fn new(
        callee: ContractId,
        method: String,
        code: CalleeErrorCode,
        reason_hash: [u8; 32],
    ) -> Self {
        Self {
            callee,
            method,
            code,
            reason_hash,
        }
    }

    /// Create error from validation failure
    pub fn validation_failed(
        callee: ContractId,
        method: String,
        reason: &str,
    ) -> Self {
        let reason_hash = blake3::hash(reason.as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(reason_hash.as_bytes());

        Self::new(callee, method, CalleeErrorCode::ValidationFailed, hash_bytes)
    }

    /// Create error from execution failure
    pub fn execution_failed(
        callee: ContractId,
        method: String,
        reason: &str,
    ) -> Self {
        let reason_hash = blake3::hash(reason.as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(reason_hash.as_bytes());

        Self::new(callee, method, CalleeErrorCode::ExecutionFailed, hash_bytes)
    }

    /// Create error for method not found
    pub fn not_found(callee: ContractId, method: String) -> Self {
        let reason_hash = blake3::hash(format!("method_not_found:{}", method).as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(reason_hash.as_bytes());

        Self::new(callee, method, CalleeErrorCode::NotFound, hash_bytes)
    }

    /// Create error for permission denied
    pub fn permission_denied(callee: ContractId, method: String) -> Self {
        let reason_hash = blake3::hash(format!("permission_denied:{}", method).as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(reason_hash.as_bytes());

        Self::new(callee, method, CalleeErrorCode::PermissionDenied, hash_bytes)
    }

    /// Create error for call depth exceeded
    pub fn call_depth_exceeded(
        callee: ContractId,
        method: String,
        depth: u16,
    ) -> Self {
        let reason_hash = blake3::hash(format!("depth:{}", depth).as_bytes());
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(reason_hash.as_bytes());

        Self::new(callee, method, CalleeErrorCode::CallDepthExceeded, hash_bytes)
    }
}

impl fmt::Display for CrossContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cross-contract call failed: callee={:?}, method={}, code={}",
            self.callee, self.method, self.code
        )
    }
}

impl std::error::Error for CrossContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(CalleeErrorCode::ValidationFailed.to_string(), "ValidationFailed");
        assert_eq!(CalleeErrorCode::ExecutionFailed.to_string(), "ExecutionFailed");
        assert_eq!(CalleeErrorCode::NotFound.to_string(), "NotFound");
        assert_eq!(CalleeErrorCode::PermissionDenied.to_string(), "PermissionDenied");
        assert_eq!(CalleeErrorCode::CallDepthExceeded.to_string(), "CallDepthExceeded");
        assert_eq!(CalleeErrorCode::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_error_reason_hash_deterministic() {
        let contract_id: ContractId = [0u8; 32];

        // Same reason should produce same hash
        let err1 = CrossContractError::validation_failed(
            contract_id,
            "test_method".to_string(),
            "reason",
        );
        let err2 = CrossContractError::validation_failed(
            contract_id,
            "test_method".to_string(),
            "reason",
        );
        assert_eq!(err1.reason_hash, err2.reason_hash);

        // Different reasons should produce different hashes
        let err3 = CrossContractError::validation_failed(
            contract_id,
            "test_method".to_string(),
            "different_reason",
        );
        assert_ne!(err1.reason_hash, err3.reason_hash);
    }

    #[test]
    fn test_error_constructors() {
        let contract_id: ContractId = [0u8; 32];

        let validation_err =
            CrossContractError::validation_failed(contract_id, "method".to_string(), "test");
        assert_eq!(validation_err.code, CalleeErrorCode::ValidationFailed);

        let execution_err =
            CrossContractError::execution_failed(contract_id, "method".to_string(), "test");
        assert_eq!(execution_err.code, CalleeErrorCode::ExecutionFailed);

        let not_found_err =
            CrossContractError::not_found(contract_id, "method".to_string());
        assert_eq!(not_found_err.code, CalleeErrorCode::NotFound);

        let perm_err =
            CrossContractError::permission_denied(contract_id, "method".to_string());
        assert_eq!(perm_err.code, CalleeErrorCode::PermissionDenied);

        let depth_err = CrossContractError::call_depth_exceeded(contract_id, "method".to_string(), 20);
        assert_eq!(depth_err.code, CalleeErrorCode::CallDepthExceeded);
    }
}
