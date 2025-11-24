//! Verification result types and error handling
//! 
//! Provides comprehensive result types for ZK proof verification operations,
//! including detailed error information for debugging and validation.

use serde::{Serialize, Deserialize};
use std::fmt;
use crate::types::zk_proof::ZkProofType;

/// Result of ZK proof verification with detailed information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Proof is valid and verified
    Valid {
        /// Circuit identifier
        circuit_id: String,
        /// Verification time in milliseconds
        verification_time_ms: u64,
        /// Public inputs that were verified
        public_inputs: Vec<u64>,
    },
    /// Proof is invalid with specific reason
    Invalid(String),
    /// System error during verification
    Error(String),
}

impl VerificationResult {
    /// Check if the verification was successful
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid { .. })
    }

    /// Check if the verification failed
    pub fn is_invalid(&self) -> bool {
        matches!(self, VerificationResult::Invalid(_))
    }

    /// Check if there was a system error
    pub fn is_error(&self) -> bool {
        matches!(self, VerificationResult::Error(_))
    }

    /// Get error message if verification failed
    pub fn error_message(&self) -> Option<&str> {
        match self {
            VerificationResult::Invalid(msg) => Some(msg),
            VerificationResult::Error(msg) => Some(msg),
            _ => None,
        }
    }

    /// Get verification time if available
    pub fn verification_time_ms(&self) -> Option<u64> {
        match self {
            VerificationResult::Valid { verification_time_ms, .. } => Some(*verification_time_ms),
            _ => None,
        }
    }

    /// Get proof type from circuit ID
    pub fn proof_type(&self) -> ZkProofType {
        match self {
            VerificationResult::Valid { circuit_id, .. } => {
                if circuit_id.contains("transaction") {
                    ZkProofType::Transaction
                } else if circuit_id.contains("identity") {
                    ZkProofType::Identity
                } else if circuit_id.contains("range") {
                    ZkProofType::Range
                } else if circuit_id.contains("merkle") {
                    ZkProofType::Merkle
                } else if circuit_id.contains("storage") {
                    ZkProofType::Storage
                } else if circuit_id.contains("routing") {
                    ZkProofType::Routing
                } else if circuit_id.contains("data_integrity") {
                    ZkProofType::DataIntegrity
                } else if circuit_id.contains("recursive") {
                    ZkProofType::Custom("recursive".to_string())
                } else {
                    ZkProofType::Custom("generic".to_string())
                }
            }
            _ => ZkProofType::Custom("generic".to_string()),
        }
    }

    /// Get error description if available
    pub fn error_description(&self) -> Option<String> {
        match self {
            VerificationResult::Valid { .. } => None,
            VerificationResult::Invalid(err) => Some(err.to_string()),
            VerificationResult::Error(msg) => Some(msg.clone()),
        }
    }
}

/// Specific verification error types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationError {
    /// Proof format is invalid or corrupted
    InvalidFormat,
    /// Proof system type not supported
    UnsupportedProofSystem,
    /// Public inputs don't match expected values
    InvalidPublicInputs,
    /// Verification key is invalid or missing
    InvalidVerificationKey,
    /// Cryptographic verification failed
    CryptographicFailure,
    /// Range constraints violated
    RangeViolation { min: u64, max: u64, actual: u64 },
    /// Merkle proof verification failed
    MerkleVerificationFailed,
    /// Identity proof requirements not met
    IdentityRequirementsNotMet,
    /// Transaction constraints violated
    TransactionConstraintsViolated,
    /// Nullifier already used (double-spending)
    NullifierAlreadyUsed,
    /// Insufficient balance for transaction
    InsufficientBalance,
    /// Plonky2 circuit verification failed
    Plonky2VerificationFailed,
    /// Custom error with message
    Custom(String),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidFormat => write!(f, "Invalid proof format"),
            VerificationError::UnsupportedProofSystem => write!(f, "Unsupported proof system"),
            VerificationError::InvalidPublicInputs => write!(f, "Invalid public inputs"),
            VerificationError::InvalidVerificationKey => write!(f, "Invalid verification key"),
            VerificationError::CryptographicFailure => write!(f, "Cryptographic verification failed"),
            VerificationError::RangeViolation { min, max, actual } => {
                write!(f, "Range violation: {} not in [{}, {}]", actual, min, max)
            }
            VerificationError::MerkleVerificationFailed => write!(f, "Merkle proof verification failed"),
            VerificationError::IdentityRequirementsNotMet => write!(f, "Identity requirements not met"),
            VerificationError::TransactionConstraintsViolated => write!(f, "Transaction constraints violated"),
            VerificationError::NullifierAlreadyUsed => write!(f, "Nullifier already used (double-spending)"),
            VerificationError::InsufficientBalance => write!(f, "Insufficient balance for transaction"),
            VerificationError::Plonky2VerificationFailed => write!(f, "Plonky2 circuit verification failed"),
            VerificationError::Custom(msg) => write!(f, "Custom error: {}", msg),
        }
    }
}

impl std::error::Error for VerificationError {}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationResult::Valid { circuit_id, verification_time_ms, .. } => {
                write!(f, "Valid (circuit: {}, time: {}ms)", circuit_id, verification_time_ms)
            }
            VerificationResult::Invalid(err) => write!(f, "Invalid: {}", err),
            VerificationResult::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Convert boolean verification result to VerificationResult
impl From<bool> for VerificationResult {
    fn from(valid: bool) -> Self {
        if valid {
            VerificationResult::Valid {
                circuit_id: "unknown".to_string(),
                verification_time_ms: 0,
                public_inputs: vec![],
            }
        } else {
            VerificationResult::Invalid("Unknown error".to_string())
        }
    }
}

/// Convert anyhow::Error to VerificationResult
impl From<anyhow::Error> for VerificationResult {
    fn from(err: anyhow::Error) -> Self {
        VerificationResult::Error(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_result_valid() {
        let result = VerificationResult::Valid {
            circuit_id: "test".to_string(),
            verification_time_ms: 100,
            public_inputs: vec![1, 2, 3],
        };
        assert!(result.is_valid());
        assert!(!result.is_invalid());
        assert!(!result.is_error());
        assert!(result.error_description().is_none());
        assert_eq!(result.verification_time_ms(), Some(100));
    }

    #[test]
    fn test_verification_result_invalid() {
        let result = VerificationResult::Invalid("Invalid format".to_string());
        assert!(!result.is_valid());
        assert!(result.is_invalid());
        assert!(!result.is_error());
        assert!(result.error_description().is_some());
    }

    #[test]
    fn test_verification_result_error() {
        let result = VerificationResult::Error("System error".to_string());
        assert!(!result.is_valid());
        assert!(!result.is_invalid());
        assert!(result.is_error());
        assert_eq!(result.error_description(), Some("System error".to_string()));
    }

    #[test]
    fn test_verification_error_display() {
        let error = VerificationError::RangeViolation { min: 0, max: 100, actual: 150 };
        assert_eq!(error.to_string(), "Range violation: 150 not in [0, 100]");
    }

    #[test]
    fn test_from_bool() {
        let valid: VerificationResult = true.into();
        assert!(valid.is_valid());

        let invalid: VerificationResult = false.into();
        assert!(invalid.is_invalid());
    }
}
