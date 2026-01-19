//! Error types for the ZHTP client library
//!
//! Provides a unified error type that works across all platforms:
//! - Native Rust
//! - UniFFI (iOS/Android)
//! - WASM (Web)

use thiserror::Error;

/// Client library error type
#[derive(Error, Debug, Clone)]
pub enum ClientError {
    /// Cryptographic operation failed
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// UHP handshake protocol error
    #[error("Handshake error: {0}")]
    HandshakeError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Signature verification failed
    #[error("Invalid signature")]
    InvalidSignature,

    /// Session has expired or is invalid
    #[error("Session expired")]
    SessionExpired,

    /// Invalid message format or wire protocol error
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Identity not found or not loaded
    #[error("Identity error: {0}")]
    IdentityError(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
}

/// Result type alias for client operations
pub type Result<T> = std::result::Result<T, ClientError>;

impl From<std::io::Error> for ClientError {
    fn from(err: std::io::Error) -> Self {
        ClientError::SerializationError(err.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(err: serde_json::Error) -> Self {
        ClientError::SerializationError(err.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for ClientError {
    fn from(err: ciborium::de::Error<std::io::Error>) -> Self {
        ClientError::SerializationError(err.to_string())
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for ClientError {
    fn from(err: ciborium::ser::Error<std::io::Error>) -> Self {
        ClientError::SerializationError(err.to_string())
    }
}

#[cfg(feature = "wasm")]
impl From<ClientError> for wasm_bindgen::JsValue {
    fn from(err: ClientError) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}
