use anyhow::Result;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fmt;
use log::{error, warn, debug};
use uuid::Uuid;

/// Secure error response that doesn't leak sensitive information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureErrorResponse {
    /// Error code for client handling
    pub error_code: String,
    /// User-friendly error message
    pub message: String,
    /// Request ID for support correlation
    pub request_id: String,
    /// Additional context for the client (sanitized)
    pub details: Option<HashMap<String, String>>,
    /// Timestamp of the error
    pub timestamp: u64,
}

/// Internal error types for the ZHTP system
#[derive(Debug, Clone)]
pub enum ZhtpError {
    // Authentication and authorization errors
    AuthenticationFailed(String),
    AuthorizationFailed(String),
    InvalidToken(String),
    SessionExpired(String),
    AccountLocked(String),
    
    // Input validation errors
    InvalidInput(String),
    ValidationFailed(String),
    MalformedRequest(String),
    
    // Rate limiting errors
    RateLimitExceeded(String),
    QuotaExceeded(String),
    
    // Network and connectivity errors
    NetworkError(String),
    ConnectionFailed(String),
    TimeoutError(String),
    
    // Consensus and blockchain errors
    ConsensusError(String),
    BlockValidationFailed(String),
    TransactionFailed(String),
    
    // Storage and data errors
    StorageError(String),
    DataNotFound(String),
    DataCorrupted(String),
    
    // Cryptographic errors
    CryptographicError(String),
    KeyGenerationFailed(String),
    SignatureVerificationFailed(String),
    
    // TLS/SSL errors
    TlsError(String),
    
    // Configuration and system errors
    ConfigurationError(String),
    SystemError(String),
    ServiceUnavailable(String),
    
    // Generic errors
    InternalError(String),
    NotImplemented(String),
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
}

impl ZhtpError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ZhtpError::AuthenticationFailed(_) => StatusCode::UNAUTHORIZED,
            ZhtpError::AuthorizationFailed(_) => StatusCode::FORBIDDEN,
            ZhtpError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            ZhtpError::SessionExpired(_) => StatusCode::UNAUTHORIZED,
            ZhtpError::AccountLocked(_) => StatusCode::FORBIDDEN,
            
            ZhtpError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            ZhtpError::ValidationFailed(_) => StatusCode::BAD_REQUEST,
            ZhtpError::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            
            ZhtpError::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            ZhtpError::QuotaExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            
            ZhtpError::NetworkError(_) => StatusCode::BAD_GATEWAY,
            ZhtpError::ConnectionFailed(_) => StatusCode::BAD_GATEWAY,
            ZhtpError::TimeoutError(_) => StatusCode::GATEWAY_TIMEOUT,
            
            ZhtpError::ConsensusError(_) => StatusCode::SERVICE_UNAVAILABLE,
            ZhtpError::BlockValidationFailed(_) => StatusCode::BAD_REQUEST,
            ZhtpError::TransactionFailed(_) => StatusCode::BAD_REQUEST,
            
            ZhtpError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::DataNotFound(_) => StatusCode::NOT_FOUND,
            ZhtpError::DataCorrupted(_) => StatusCode::INTERNAL_SERVER_ERROR,
            
            ZhtpError::CryptographicError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::KeyGenerationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::SignatureVerificationFailed(_) => StatusCode::BAD_REQUEST,
            
            ZhtpError::TlsError(_) => StatusCode::BAD_GATEWAY,
            
            ZhtpError::ConfigurationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::SystemError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            
            ZhtpError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ZhtpError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ZhtpError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ZhtpError::Forbidden(_) => StatusCode::FORBIDDEN,
            ZhtpError::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    /// Get the error code for client identification
    pub fn error_code(&self) -> &'static str {
        match self {
            ZhtpError::AuthenticationFailed(_) => "AUTH_FAILED",
            ZhtpError::AuthorizationFailed(_) => "AUTH_INSUFFICIENT",
            ZhtpError::InvalidToken(_) => "TOKEN_INVALID",
            ZhtpError::SessionExpired(_) => "SESSION_EXPIRED",
            ZhtpError::AccountLocked(_) => "ACCOUNT_LOCKED",
            
            ZhtpError::InvalidInput(_) => "INPUT_INVALID",
            ZhtpError::ValidationFailed(_) => "VALIDATION_FAILED",
            ZhtpError::MalformedRequest(_) => "REQUEST_MALFORMED",
            
            ZhtpError::RateLimitExceeded(_) => "RATE_LIMIT_EXCEEDED",
            ZhtpError::QuotaExceeded(_) => "QUOTA_EXCEEDED",
            
            ZhtpError::NetworkError(_) => "NETWORK_ERROR",
            ZhtpError::ConnectionFailed(_) => "CONNECTION_FAILED",
            ZhtpError::TimeoutError(_) => "TIMEOUT",
            
            ZhtpError::ConsensusError(_) => "CONSENSUS_ERROR",
            ZhtpError::BlockValidationFailed(_) => "BLOCK_INVALID",
            ZhtpError::TransactionFailed(_) => "TRANSACTION_FAILED",
            
            ZhtpError::StorageError(_) => "STORAGE_ERROR",
            ZhtpError::DataNotFound(_) => "DATA_NOT_FOUND",
            ZhtpError::DataCorrupted(_) => "DATA_CORRUPTED",
            
            ZhtpError::CryptographicError(_) => "CRYPTO_ERROR",
            ZhtpError::KeyGenerationFailed(_) => "KEY_GENERATION_FAILED",
            ZhtpError::SignatureVerificationFailed(_) => "SIGNATURE_INVALID",
            
            ZhtpError::TlsError(_) => "TLS_ERROR",
            
            ZhtpError::ConfigurationError(_) => "CONFIG_ERROR",
            ZhtpError::SystemError(_) => "SYSTEM_ERROR",
            ZhtpError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            
            ZhtpError::InternalError(_) => "INTERNAL_ERROR",
            ZhtpError::NotImplemented(_) => "NOT_IMPLEMENTED",
            ZhtpError::BadRequest(_) => "BAD_REQUEST",
            ZhtpError::Forbidden(_) => "FORBIDDEN",
            ZhtpError::NotFound(_) => "NOT_FOUND",
        }
    }

    /// Get a user-friendly message (sanitized)
    pub fn user_message(&self) -> String {
        match self {
            ZhtpError::AuthenticationFailed(_) => "Authentication failed. Please check your credentials.".to_string(),
            ZhtpError::AuthorizationFailed(_) => "You don't have permission to perform this action.".to_string(),
            ZhtpError::InvalidToken(_) => "Your session token is invalid. Please log in again.".to_string(),
            ZhtpError::SessionExpired(_) => "Your session has expired. Please log in again.".to_string(),
            ZhtpError::AccountLocked(_) => "Your account has been temporarily locked. Please try again later.".to_string(),
            
            ZhtpError::InvalidInput(_) => "The provided input is invalid. Please check your request.".to_string(),
            ZhtpError::ValidationFailed(_) => "Request validation failed. Please check the required fields.".to_string(),
            ZhtpError::MalformedRequest(_) => "The request format is invalid.".to_string(),
            
            ZhtpError::RateLimitExceeded(_) => "Too many requests. Please slow down and try again later.".to_string(),
            ZhtpError::QuotaExceeded(_) => "You have exceeded your usage quota. Please try again later.".to_string(),
            
            ZhtpError::NetworkError(_) => "Network error occurred. Please try again.".to_string(),
            ZhtpError::ConnectionFailed(_) => "Unable to connect to the service. Please try again.".to_string(),
            ZhtpError::TimeoutError(_) => "Request timed out. Please try again.".to_string(),
            
            ZhtpError::ConsensusError(_) => "Consensus error occurred. Please try again later.".to_string(),
            ZhtpError::BlockValidationFailed(_) => "Block validation failed.".to_string(),
            ZhtpError::TransactionFailed(_) => "Transaction processing failed.".to_string(),
            
            ZhtpError::StorageError(_) => "Storage error occurred. Please try again.".to_string(),
            ZhtpError::DataNotFound(_) => "The requested data was not found.".to_string(),
            ZhtpError::DataCorrupted(_) => "Data corruption detected. Please contact support.".to_string(),
            
            ZhtpError::CryptographicError(_) => "Cryptographic operation failed.".to_string(),
            ZhtpError::KeyGenerationFailed(_) => "Key generation failed.".to_string(),
            ZhtpError::SignatureVerificationFailed(_) => "Signature verification failed.".to_string(),
            
            ZhtpError::TlsError(_) => "Secure connection error. Please try again.".to_string(),
            
            ZhtpError::ConfigurationError(_) => "Service configuration error. Please contact support.".to_string(),
            ZhtpError::SystemError(_) => "System error occurred. Please try again later.".to_string(),
            ZhtpError::ServiceUnavailable(_) => "Service is temporarily unavailable. Please try again later.".to_string(),
            
            ZhtpError::InternalError(_) => "An internal error occurred. Please contact support if this persists.".to_string(),
            ZhtpError::NotImplemented(_) => "This feature is not yet implemented.".to_string(),
            ZhtpError::BadRequest(_) => "Bad request. Please check your input.".to_string(),
            ZhtpError::Forbidden(_) => "Access forbidden.".to_string(),
            ZhtpError::NotFound(_) => "Resource not found.".to_string(),
        }
    }

    /// Get the internal error message (for logging)
    pub fn internal_message(&self) -> &str {
        match self {
            ZhtpError::AuthenticationFailed(msg) => msg,
            ZhtpError::AuthorizationFailed(msg) => msg,
            ZhtpError::InvalidToken(msg) => msg,
            ZhtpError::SessionExpired(msg) => msg,
            ZhtpError::AccountLocked(msg) => msg,
            ZhtpError::InvalidInput(msg) => msg,
            ZhtpError::ValidationFailed(msg) => msg,
            ZhtpError::MalformedRequest(msg) => msg,
            ZhtpError::RateLimitExceeded(msg) => msg,
            ZhtpError::QuotaExceeded(msg) => msg,
            ZhtpError::NetworkError(msg) => msg,
            ZhtpError::ConnectionFailed(msg) => msg,
            ZhtpError::TimeoutError(msg) => msg,
            ZhtpError::ConsensusError(msg) => msg,
            ZhtpError::BlockValidationFailed(msg) => msg,
            ZhtpError::TransactionFailed(msg) => msg,
            ZhtpError::StorageError(msg) => msg,
            ZhtpError::DataNotFound(msg) => msg,
            ZhtpError::DataCorrupted(msg) => msg,
            ZhtpError::CryptographicError(msg) => msg,
            ZhtpError::KeyGenerationFailed(msg) => msg,
            ZhtpError::SignatureVerificationFailed(msg) => msg,
            ZhtpError::TlsError(msg) => msg,
            ZhtpError::ConfigurationError(msg) => msg,
            ZhtpError::SystemError(msg) => msg,
            ZhtpError::ServiceUnavailable(msg) => msg,
            ZhtpError::InternalError(msg) => msg,
            ZhtpError::NotImplemented(msg) => msg,
            ZhtpError::BadRequest(msg) => msg,
            ZhtpError::Forbidden(msg) => msg,
            ZhtpError::NotFound(msg) => msg,
        }
    }

    /// Check if this error should be logged as a security event
    pub fn is_security_event(&self) -> bool {
        matches!(self,
            ZhtpError::AuthenticationFailed(_) |
            ZhtpError::AuthorizationFailed(_) |
            ZhtpError::InvalidToken(_) |
            ZhtpError::AccountLocked(_) |
            ZhtpError::RateLimitExceeded(_) |
            ZhtpError::ValidationFailed(_) |
            ZhtpError::MalformedRequest(_) |
            ZhtpError::SignatureVerificationFailed(_) |
            ZhtpError::Forbidden(_)
        )
    }

    /// Check if this error should be logged as an error (vs warning)
    pub fn is_error_level(&self) -> bool {
        matches!(self,
            ZhtpError::InternalError(_) |
            ZhtpError::SystemError(_) |
            ZhtpError::StorageError(_) |
            ZhtpError::DataCorrupted(_) |
            ZhtpError::CryptographicError(_) |
            ZhtpError::KeyGenerationFailed(_) |
            ZhtpError::ConfigurationError(_) |
            ZhtpError::ConsensusError(_)
        )
    }
}

impl fmt::Display for ZhtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.internal_message())
    }
}

impl std::error::Error for ZhtpError {}

/// Error handler for converting ZhtpError to HTTP responses
pub struct ErrorHandler;

impl ErrorHandler {
    /// Convert ZhtpError to a secure HTTP response
    pub fn handle_error(error: ZhtpError, request_id: Option<String>) -> Response {
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let status_code = error.status_code();
        
        // Log the error with appropriate level
        if error.is_error_level() {
            error!("Request {} failed with error: {} - {}", 
                request_id, error.error_code(), error.internal_message());
        } else if error.is_security_event() {
            warn!("Security event for request {}: {} - {}", 
                request_id, error.error_code(), error.internal_message());
        } else {
            debug!("Request {} failed: {} - {}", 
                request_id, error.error_code(), error.internal_message());
        }

        let error_response = SecureErrorResponse {
            error_code: error.error_code().to_string(),
            message: error.user_message(),
            request_id,
            details: None, // Add specific details if needed
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        (status_code, Json(error_response)).into_response()
    }

    /// Handle anyhow::Error by converting to ZhtpError
    pub fn handle_anyhow_error(error: anyhow::Error, request_id: Option<String>) -> Response {
        let error_msg = error.to_string();
        
        // Try to classify the error based on the message
        let zhtp_error = if error_msg.contains("authentication") || error_msg.contains("invalid credentials") {
            ZhtpError::AuthenticationFailed(error_msg)
        } else if error_msg.contains("authorization") || error_msg.contains("permission") {
            ZhtpError::AuthorizationFailed(error_msg)
        } else if error_msg.contains("rate limit") {
            ZhtpError::RateLimitExceeded(error_msg)
        } else if error_msg.contains("validation") {
            ZhtpError::ValidationFailed(error_msg)
        } else if error_msg.contains("network") || error_msg.contains("connection") {
            ZhtpError::NetworkError(error_msg)
        } else if error_msg.contains("timeout") {
            ZhtpError::TimeoutError(error_msg)
        } else if error_msg.contains("not found") {
            ZhtpError::NotFound(error_msg)
        } else {
            ZhtpError::InternalError(error_msg)
        };

        Self::handle_error(zhtp_error, request_id)
    }

    /// Handle panic by converting to a safe error response
    pub fn handle_panic(request_id: Option<String>) -> Response {
        let error = ZhtpError::InternalError("A panic occurred during request processing".to_string());
        Self::handle_error(error, request_id)
    }
}

/// Result type alias for ZHTP operations
pub type ZhtpResult<T> = Result<T, ZhtpError>;

/// Macro for creating ZHTP errors with context
#[macro_export]
macro_rules! zhtp_error {
    ($variant:ident, $($arg:tt)*) => {
        $crate::errors::ZhtpError::$variant(format!($($arg)*))
    };
}

/// Macro for converting anyhow errors to ZHTP errors
#[macro_export]
macro_rules! zhtp_anyhow {
    ($expr:expr, $variant:ident) => {
        $expr.map_err(|e| $crate::errors::ZhtpError::$variant(e.to_string()))
    };
}

/// Trait for converting other error types to ZhtpError
pub trait IntoZhtpError<T> {
    fn into_zhtp_error(self, error_type: fn(String) -> ZhtpError) -> ZhtpResult<T>;
}

impl<T, E: std::error::Error> IntoZhtpError<T> for Result<T, E> {
    fn into_zhtp_error(self, error_type: fn(String) -> ZhtpError) -> ZhtpResult<T> {
        self.map_err(|e| error_type(e.to_string()))
    }
}

/// Implementation of IntoResponse for ZhtpError
impl IntoResponse for ZhtpError {
    fn into_response(self) -> Response {
        ErrorHandler::handle_error(self, None)
    }
}

/// Validation error builder for input validation
pub struct ValidationError {
    field: String,
    message: String,
    value: Option<String>,
}

impl ValidationError {
    pub fn new(field: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            message: message.to_string(),
            value: None,
        }
    }

    pub fn with_value(mut self, value: &str) -> Self {
        self.value = Some(value.to_string());
        self
    }

    pub fn into_zhtp_error(self) -> ZhtpError {
        ZhtpError::ValidationFailed(format!(
            "Field '{}': {}{}",
            self.field,
            self.message,
            self.value.map(|v| format!(" (value: {})", v)).unwrap_or_default()
        ))
    }
}

/// Validation result collector
pub struct ValidationResult {
    errors: Vec<ValidationError>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    pub fn add_field_error(&mut self, field: &str, message: &str) {
        self.errors.push(ValidationError::new(field, message));
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn into_result(self) -> ZhtpResult<()> {
        if self.has_errors() {
            let error_messages: Vec<String> = self.errors
                .into_iter()
                .map(|e| format!("{}: {}", e.field, e.message))
                .collect();
            
            Err(ZhtpError::ValidationFailed(error_messages.join("; ")))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let error = ZhtpError::AuthenticationFailed("test".to_string());
        assert_eq!(error.error_code(), "AUTH_FAILED");
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        assert!(error.is_security_event());
        assert!(!error.is_error_level());
    }

    #[test]
    fn test_validation_result() {
        let mut validation = ValidationResult::new();
        validation.add_field_error("username", "cannot be empty");
        validation.add_field_error("password", "too short");
        
        assert!(validation.has_errors());
        
        let result = validation.into_result();
        assert!(result.is_err());
        
        if let Err(ZhtpError::ValidationFailed(msg)) = result {
            assert!(msg.contains("username: cannot be empty"));
            assert!(msg.contains("password: too short"));
        }
    }

    #[test]
    fn test_error_classification() {
        let auth_error = ZhtpError::AuthenticationFailed("test".to_string());
        assert!(auth_error.is_security_event());
        assert!(!auth_error.is_error_level());

        let internal_error = ZhtpError::InternalError("test".to_string());
        assert!(!internal_error.is_security_event());
        assert!(internal_error.is_error_level());
    }
}
