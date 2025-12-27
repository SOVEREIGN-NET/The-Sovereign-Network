//! Structured error types for ZHTP CLI
//!
//! Provides domain-specific error types that replace generic Result<()>
//! and enable proper error handling and testability.

use thiserror::Error;

/// ZHTP CLI error types with proper context
#[derive(Error, Debug)]
pub enum CliError {
    // Identity operations
    #[error("Identity operation failed: {0}")]
    IdentityError(String),

    #[error("Failed to create identity '{name}': {reason}")]
    IdentityCreationFailed { name: String, reason: String },

    #[error("Failed to load keystore: {0}")]
    KeystoreLoadFailed(String),

    #[error("Invalid keystore format: {0}")]
    InvalidKeystore(String),

    // Wallet operations
    #[error("Wallet operation failed: {0}")]
    WalletError(String),

    #[error("Failed to create wallet '{name}': {reason}")]
    WalletCreationFailed { name: String, reason: String },

    #[error("Insufficient balance for operation: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },

    // Node operations
    #[error("Node configuration error: {0}")]
    NodeConfigError(String),

    #[error("Failed to start node: {0}")]
    NodeStartFailed(String),

    #[error("Node not running at {addr}")]
    NodeNotRunning { addr: String },

    // Deployment
    #[error("Deployment failed for domain '{domain}': {reason}")]
    DeploymentFailed { domain: String, reason: String },

    #[error("Invalid build directory: {0}")]
    InvalidBuildDirectory(String),

    #[error("File processing error: {0}")]
    FileProcessingError(String),

    // Network operations
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Failed to connect to node at {addr}: {reason}")]
    ConnectionFailed { addr: String, reason: String },

    #[error("API call to {endpoint} failed: {status} - {reason}")]
    ApiCallFailed { endpoint: String, status: u16, reason: String },

    // Configuration
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Failed to load config from {path}: {reason}")]
    ConfigLoadFailed { path: String, reason: String },

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    // Path operations
    #[error("Path error: {0}")]
    PathError(String),

    #[error("Home directory not found")]
    HomeDirectoryNotFound,

    #[error("Failed to resolve path '{path}': {reason}")]
    PathResolutionFailed { path: String, reason: String },

    // I/O operations
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    // Serialization
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    // HTTP/Network
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    // Generic
    #[error("{0}")]
    Other(String),
}

impl From<String> for CliError {
    fn from(s: String) -> Self {
        CliError::Other(s)
    }
}

impl From<&str> for CliError {
    fn from(s: &str) -> Self {
        CliError::Other(s.to_string())
    }
}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        CliError::Other(err.to_string())
    }
}

/// Result type for CLI operations
pub type CliResult<T> = Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation_error() {
        let err = CliError::IdentityCreationFailed {
            name: "test".to_string(),
            reason: "key generation failed".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to create identity 'test': key generation failed"
        );
    }

    #[test]
    fn test_insufficient_balance_error() {
        let err = CliError::InsufficientBalance {
            required: 1000,
            available: 500,
        };
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
    }
}
