//! ZHTP Status Codes
//! 
//! Status codes for ZHTP protocol responses, extending traditional HTTP status codes
//! with Web4-specific codes for zero-knowledge proofs, DAO fees, and mesh networking.

use serde::{Deserialize, Serialize};

/// ZHTP status codes with Web4 extensions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ZhtpStatus {
    // 2xx Success
    /// Request successful
    Ok = 200,
    /// Created successfully
    Created = 201,
    /// Request accepted for processing
    Accepted = 202,
    /// No content available
    NoContent = 204,

    // 3xx Redirection
    /// Multiple choices available
    MultipleChoices = 300,
    /// Moved permanently
    MovedPermanently = 301,
    /// Found (temporary redirect)
    Found = 302,
    /// Not modified
    NotModified = 304,

    // 4xx Client Error
    /// Bad request
    BadRequest = 400,
    /// Authentication required
    Unauthorized = 401,
    /// Payment required (DAO fee)
    PaymentRequired = 402,
    /// Access forbidden
    Forbidden = 403,
    /// Resource not found
    NotFound = 404,
    /// Method not allowed
    MethodNotAllowed = 405,
    /// Request timeout
    RequestTimeout = 408,
    /// Conflict
    Conflict = 409,
    /// Gone
    Gone = 410,
    /// Length required
    LengthRequired = 411,
    /// Payload too large
    PayloadTooLarge = 413,
    /// Request header fields too large
    RequestHeaderFieldsTooLarge = 431,
    /// Too many requests (rate limited)
    TooManyRequests = 429,

    // 5xx Server Error
    /// Internal server error
    InternalServerError = 500,
    /// Not implemented
    NotImplemented = 501,
    /// Bad gateway
    BadGateway = 502,
    /// Service unavailable
    ServiceUnavailable = 503,
    /// Gateway timeout
    GatewayTimeout = 504,

    // 6xx Web4 Zero-Knowledge Errors
    /// Zero-knowledge proof invalid
    ZkProofInvalid = 600,
    /// Zero-knowledge proof required
    ZkProofRequired = 601,
    /// Zero-knowledge verification failed
    ZkVerificationFailed = 602,
    /// Privacy violation detected
    PrivacyViolation = 603,
    /// Identity proof invalid
    IdentityProofInvalid = 604,

    // 7xx Web4 Economic Errors
    /// DAO fee required
    DaoFeeRequired = 700,
    /// DAO fee insufficient
    DaoFeeInsufficient = 701,
    /// DAO fee proof invalid
    DaoFeeProofInvalid = 702,
    /// Economic validation failed
    EconomicValidationFailed = 703,
    /// UBI funding requirements not met
    UbiFundingRequired = 704,
    /// Network fee insufficient
    NetworkFeeInsufficient = 705,

    // 8xx Web4 Mesh Network Errors
    /// Mesh network unavailable
    MeshUnavailable = 800,
    /// Peer not found
    PeerNotFound = 801,
    /// Routing failed
    RoutingFailed = 802,
    ///  failed
    IspBypassFailed = 803,
    /// Network congestion
    NetworkCongestion = 804,
    /// Bandwidth limit exceeded
    BandwidthLimitExceeded = 805,

    // 9xx Web4 Protocol Errors
    /// Post-quantum cryptography required
    PostQuantumRequired = 900,
    /// Signature invalid
    SignatureInvalid = 901,
    /// Encryption required
    EncryptionRequired = 902,
    /// Protocol version not supported
    ProtocolVersionNotSupported = 903,
    /// Content integrity check failed
    ContentIntegrityFailed = 904,
    /// Access control violation
    AccessControlViolation = 905,
}

impl ZhtpStatus {
    /// Get the numeric status code
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Get the reason phrase for the status code
    pub fn reason_phrase(&self) -> &'static str {
        match self {
            // 2xx Success
            ZhtpStatus::Ok => "OK",
            ZhtpStatus::Created => "Created",
            ZhtpStatus::Accepted => "Accepted",
            ZhtpStatus::NoContent => "No Content",

            // 3xx Redirection
            ZhtpStatus::MultipleChoices => "Multiple Choices",
            ZhtpStatus::MovedPermanently => "Moved Permanently",
            ZhtpStatus::Found => "Found",
            ZhtpStatus::NotModified => "Not Modified",

            // 4xx Client Error
            ZhtpStatus::BadRequest => "Bad Request",
            ZhtpStatus::Unauthorized => "Unauthorized",
            ZhtpStatus::PaymentRequired => "Payment Required",
            ZhtpStatus::Forbidden => "Forbidden",
            ZhtpStatus::NotFound => "Not Found",
            ZhtpStatus::MethodNotAllowed => "Method Not Allowed",
            ZhtpStatus::RequestTimeout => "Request Timeout",
            ZhtpStatus::Conflict => "Conflict",
            ZhtpStatus::Gone => "Gone",
            ZhtpStatus::LengthRequired => "Length Required",
            ZhtpStatus::PayloadTooLarge => "Payload Too Large",
            ZhtpStatus::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            ZhtpStatus::TooManyRequests => "Too Many Requests",

            // 5xx Server Error
            ZhtpStatus::InternalServerError => "Internal Server Error",
            ZhtpStatus::NotImplemented => "Not Implemented",
            ZhtpStatus::BadGateway => "Bad Gateway",
            ZhtpStatus::ServiceUnavailable => "Service Unavailable",
            ZhtpStatus::GatewayTimeout => "Gateway Timeout",

            // 6xx Web4 Zero-Knowledge Errors
            ZhtpStatus::ZkProofInvalid => "Zero-Knowledge Proof Invalid",
            ZhtpStatus::ZkProofRequired => "Zero-Knowledge Proof Required",
            ZhtpStatus::ZkVerificationFailed => "Zero-Knowledge Verification Failed",
            ZhtpStatus::PrivacyViolation => "Privacy Violation",
            ZhtpStatus::IdentityProofInvalid => "Identity Proof Invalid",

            // 7xx Web4 Economic Errors
            ZhtpStatus::DaoFeeRequired => "DAO Fee Required",
            ZhtpStatus::DaoFeeInsufficient => "DAO Fee Insufficient",
            ZhtpStatus::DaoFeeProofInvalid => "DAO Fee Proof Invalid",
            ZhtpStatus::EconomicValidationFailed => "Economic Validation Failed",
            ZhtpStatus::UbiFundingRequired => "UBI Funding Requirements Not Met",
            ZhtpStatus::NetworkFeeInsufficient => "Network Fee Insufficient",

            // 8xx Web4 Mesh Network Errors
            ZhtpStatus::MeshUnavailable => "Mesh Network Unavailable",
            ZhtpStatus::PeerNotFound => "Peer Not Found",
            ZhtpStatus::RoutingFailed => "Routing Failed",
            ZhtpStatus::IspBypassFailed => " Failed",
            ZhtpStatus::NetworkCongestion => "Network Congestion",
            ZhtpStatus::BandwidthLimitExceeded => "Bandwidth Limit Exceeded",

            // 9xx Web4 Protocol Errors
            ZhtpStatus::PostQuantumRequired => "Post-Quantum Cryptography Required",
            ZhtpStatus::SignatureInvalid => "Signature Invalid",
            ZhtpStatus::EncryptionRequired => "Encryption Required",
            ZhtpStatus::ProtocolVersionNotSupported => "Protocol Version Not Supported",
            ZhtpStatus::ContentIntegrityFailed => "Content Integrity Check Failed",
            ZhtpStatus::AccessControlViolation => "Access Control Violation",
        }
    }

    /// Check if the status represents success (2xx)
    pub fn is_success(&self) -> bool {
        matches!(self.code(), 200..=299)
    }

    /// Check if the status represents redirection (3xx)
    pub fn is_redirection(&self) -> bool {
        matches!(self.code(), 300..=399)
    }

    /// Check if the status represents client error (4xx)
    pub fn is_client_error(&self) -> bool {
        matches!(self.code(), 400..=499)
    }

    /// Check if the status represents server error (5xx)
    pub fn is_server_error(&self) -> bool {
        matches!(self.code(), 500..=599)
    }

    /// Check if the status represents Web4 zero-knowledge error (6xx)
    pub fn is_zk_error(&self) -> bool {
        matches!(self.code(), 600..=699)
    }

    /// Check if the status represents Web4 economic error (7xx)
    pub fn is_economic_error(&self) -> bool {
        matches!(self.code(), 700..=799)
    }

    /// Check if the status represents Web4 mesh network error (8xx)
    pub fn is_mesh_error(&self) -> bool {
        matches!(self.code(), 800..=899)
    }

    /// Check if the status represents Web4 protocol error (9xx)
    pub fn is_protocol_error(&self) -> bool {
        matches!(self.code(), 900..=999)
    }

    /// Check if the status represents any Web4-specific error (6xx-9xx)
    pub fn is_web4_error(&self) -> bool {
        matches!(self.code(), 600..=999)
    }

    /// Parse status code from u16
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            // 2xx Success
            200 => Some(ZhtpStatus::Ok),
            201 => Some(ZhtpStatus::Created),
            202 => Some(ZhtpStatus::Accepted),
            204 => Some(ZhtpStatus::NoContent),

            // 3xx Redirection
            300 => Some(ZhtpStatus::MultipleChoices),
            301 => Some(ZhtpStatus::MovedPermanently),
            302 => Some(ZhtpStatus::Found),
            304 => Some(ZhtpStatus::NotModified),

            // 4xx Client Error
            400 => Some(ZhtpStatus::BadRequest),
            401 => Some(ZhtpStatus::Unauthorized),
            402 => Some(ZhtpStatus::PaymentRequired),
            403 => Some(ZhtpStatus::Forbidden),
            404 => Some(ZhtpStatus::NotFound),
            405 => Some(ZhtpStatus::MethodNotAllowed),
            408 => Some(ZhtpStatus::RequestTimeout),
            409 => Some(ZhtpStatus::Conflict),
            410 => Some(ZhtpStatus::Gone),
            411 => Some(ZhtpStatus::LengthRequired),
            413 => Some(ZhtpStatus::PayloadTooLarge),
            429 => Some(ZhtpStatus::TooManyRequests),
            431 => Some(ZhtpStatus::RequestHeaderFieldsTooLarge),

            // 5xx Server Error
            500 => Some(ZhtpStatus::InternalServerError),
            501 => Some(ZhtpStatus::NotImplemented),
            502 => Some(ZhtpStatus::BadGateway),
            503 => Some(ZhtpStatus::ServiceUnavailable),
            504 => Some(ZhtpStatus::GatewayTimeout),

            // 6xx Web4 Zero-Knowledge Errors
            600 => Some(ZhtpStatus::ZkProofInvalid),
            601 => Some(ZhtpStatus::ZkProofRequired),
            602 => Some(ZhtpStatus::ZkVerificationFailed),
            603 => Some(ZhtpStatus::PrivacyViolation),
            604 => Some(ZhtpStatus::IdentityProofInvalid),

            // 7xx Web4 Economic Errors
            700 => Some(ZhtpStatus::DaoFeeRequired),
            701 => Some(ZhtpStatus::DaoFeeInsufficient),
            702 => Some(ZhtpStatus::DaoFeeProofInvalid),
            703 => Some(ZhtpStatus::EconomicValidationFailed),
            704 => Some(ZhtpStatus::UbiFundingRequired),
            705 => Some(ZhtpStatus::NetworkFeeInsufficient),

            // 8xx Web4 Mesh Network Errors
            800 => Some(ZhtpStatus::MeshUnavailable),
            801 => Some(ZhtpStatus::PeerNotFound),
            802 => Some(ZhtpStatus::RoutingFailed),
            803 => Some(ZhtpStatus::IspBypassFailed),
            804 => Some(ZhtpStatus::NetworkCongestion),
            805 => Some(ZhtpStatus::BandwidthLimitExceeded),

            // 9xx Web4 Protocol Errors
            900 => Some(ZhtpStatus::PostQuantumRequired),
            901 => Some(ZhtpStatus::SignatureInvalid),
            902 => Some(ZhtpStatus::EncryptionRequired),
            903 => Some(ZhtpStatus::ProtocolVersionNotSupported),
            904 => Some(ZhtpStatus::ContentIntegrityFailed),
            905 => Some(ZhtpStatus::AccessControlViolation),

            _ => None,
        }
    }
}

impl std::fmt::Display for ZhtpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code(), self.reason_phrase())
    }
}

impl From<u16> for ZhtpStatus {
    fn from(code: u16) -> Self {
        Self::from_code(code).unwrap_or(ZhtpStatus::InternalServerError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_conversion() {
        assert_eq!(ZhtpStatus::Ok.code(), 200);
        assert_eq!(ZhtpStatus::NotFound.code(), 404);
        assert_eq!(ZhtpStatus::ZkProofInvalid.code(), 600);
        assert_eq!(ZhtpStatus::DaoFeeRequired.code(), 700);
    }

    #[test]
    fn test_reason_phrases() {
        assert_eq!(ZhtpStatus::Ok.reason_phrase(), "OK");
        assert_eq!(ZhtpStatus::DaoFeeInsufficient.reason_phrase(), "DAO Fee Insufficient");
        assert_eq!(ZhtpStatus::ZkProofInvalid.reason_phrase(), "Zero-Knowledge Proof Invalid");
    }

    #[test]
    fn test_status_categories() {
        assert!(ZhtpStatus::Ok.is_success());
        assert!(ZhtpStatus::NotFound.is_client_error());
        assert!(ZhtpStatus::InternalServerError.is_server_error());
        assert!(ZhtpStatus::ZkProofInvalid.is_zk_error());
        assert!(ZhtpStatus::DaoFeeRequired.is_economic_error());
        assert!(ZhtpStatus::MeshUnavailable.is_mesh_error());
        assert!(ZhtpStatus::PostQuantumRequired.is_protocol_error());
    }

    #[test]
    fn test_web4_error_detection() {
        assert!(ZhtpStatus::ZkProofInvalid.is_web4_error());
        assert!(ZhtpStatus::DaoFeeRequired.is_web4_error());
        assert!(ZhtpStatus::MeshUnavailable.is_web4_error());
        assert!(ZhtpStatus::PostQuantumRequired.is_web4_error());
        assert!(!ZhtpStatus::Ok.is_web4_error());
        assert!(!ZhtpStatus::NotFound.is_web4_error());
    }

    #[test]
    fn test_from_code() {
        assert_eq!(ZhtpStatus::from_code(200), Some(ZhtpStatus::Ok));
        assert_eq!(ZhtpStatus::from_code(700), Some(ZhtpStatus::DaoFeeRequired));
        assert_eq!(ZhtpStatus::from_code(999), None);
    }

    #[test]
    fn test_display_format() {
        assert_eq!(ZhtpStatus::Ok.to_string(), "200 OK");
        assert_eq!(ZhtpStatus::DaoFeeRequired.to_string(), "700 DAO Fee Required");
    }
}
