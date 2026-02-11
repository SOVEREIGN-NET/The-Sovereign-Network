//! Core Web4 Protocol Types
//! 
//! This module contains all the fundamental types used across the ZHTP protocol stack,
//! including request/response types, status codes, headers, and content structures.

pub mod status;
pub mod method;
pub mod headers;
pub mod request;
pub mod response;
pub mod access_policy;
pub mod content;
pub mod economic;

// Re-export all types for convenience
pub use status::ZhtpStatus;
pub use method::ZhtpMethod;
pub use headers::ZhtpHeaders;
pub use request::ZhtpRequest;
pub use response::ZhtpResponse;
pub use access_policy::{AccessPolicy, TimeRestriction};
pub use content::{ContentMetadata, ServerContent, EncryptionInfo, CompressionInfo, ContentChunk, ReplicationInfo};
pub use economic::EconomicAssessment;

// Types defined in this module are automatically available:
// - StorageRequirements, StorageQuality, etc.

use serde::{Deserialize, Serialize};

/// Protocol version constants
pub const ZHTP_VERSION: &str = "1.0";
pub const ZDNS_VERSION: &str = "1.0";

/// Maximum request size (16MB)
pub const MAX_REQUEST_SIZE: usize = 16 * 1024 * 1024;

/// Maximum header size (64KB)
pub const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Default request timeout (30 seconds)
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Default cache TTL (1 hour)
pub const DEFAULT_CACHE_TTL: u64 = 3600;

/// Minimum DAO fee (5 SOV tokens)
pub const MIN_DAO_FEE: u64 = 5;

/// DAO fee percentage (2.00%)
pub const DAO_FEE_PERCENTAGE: u64 = 200; // Basis points (200/10000 = 2%)

/// Default privacy level (maximum)
pub const DEFAULT_PRIVACY_LEVEL: u8 = 100;

/// ZDNS record types for zero-knowledge DNS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ZdnsRecordType {
    /// Address record (maps domain to ZHTP address)
    A,
    /// IPv6 address record
    AAAA,
    /// Canonical name record
    CNAME,
    /// Mail exchange record
    MX,
    /// Text record
    TXT,
    /// Service record
    SRV,
    /// Zero-knowledge identity record
    ZKI,
    /// Zero-knowledge proof record
    ZKP,
    /// Content hash record
    CHR,
    /// Name server record
    NS,
    /// Start of authority record
    SOA,
    /// Pointer record
    PTR,
}

impl ZdnsRecordType {
    /// Get the string representation of the record type
    pub fn as_str(&self) -> &'static str {
        match self {
            ZdnsRecordType::A => "A",
            ZdnsRecordType::AAAA => "AAAA",
            ZdnsRecordType::CNAME => "CNAME",
            ZdnsRecordType::MX => "MX",
            ZdnsRecordType::TXT => "TXT",
            ZdnsRecordType::SRV => "SRV",
            ZdnsRecordType::ZKI => "ZKI",
            ZdnsRecordType::ZKP => "ZKP",
            ZdnsRecordType::CHR => "CHR",
            ZdnsRecordType::NS => "NS",
            ZdnsRecordType::SOA => "SOA",
            ZdnsRecordType::PTR => "PTR",
        }
    }

    /// Parse record type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(ZdnsRecordType::A),
            "AAAA" => Some(ZdnsRecordType::AAAA),
            "CNAME" => Some(ZdnsRecordType::CNAME),
            "MX" => Some(ZdnsRecordType::MX),
            "TXT" => Some(ZdnsRecordType::TXT),
            "SRV" => Some(ZdnsRecordType::SRV),
            "ZKI" => Some(ZdnsRecordType::ZKI),
            "ZKP" => Some(ZdnsRecordType::ZKP),
            "CHR" => Some(ZdnsRecordType::CHR),
            "NS" => Some(ZdnsRecordType::NS),
            "SOA" => Some(ZdnsRecordType::SOA),
            "PTR" => Some(ZdnsRecordType::PTR),
            _ => None,
        }
    }
}

/// ZDNS record with zero-knowledge privacy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsRecord {
    /// Domain name
    pub name: String,
    /// Record type
    pub record_type: ZdnsRecordType,
    /// Record value (may be encrypted)
    pub value: Vec<u8>,
    /// Time to live (seconds)
    pub ttl: u32,
    /// Record priority (for MX, SRV records)
    pub priority: Option<u16>,
    /// Zero-knowledge proof of record ownership
    pub ownership_proof: lib_proofs::ZeroKnowledgeProof,
    /// Record creation timestamp
    pub created_at: u64,
    /// Record expiration timestamp
    pub expires_at: Option<u64>,
    /// Record signature
    pub signature: lib_crypto::PostQuantumSignature,
    /// Access control policy for this record
    pub access_policy: Option<AccessPolicy>,
}

/// ZDNS query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsQuery {
    /// Query ID
    pub id: u16,
    /// Domain name to query
    pub name: String,
    /// Record type to query
    pub record_type: ZdnsRecordType,
    /// Query flags
    pub flags: ZdnsFlags,
    /// Requester identity (for private queries)
    pub requester: Option<lib_identity::IdentityId>,
    /// Alternative field name for compatibility
    pub requester_identity: Option<lib_identity::IdentityId>,
    /// Zero-knowledge proof of access rights
    pub access_proof: Option<lib_proofs::ZeroKnowledgeProof>,
    /// Query timestamp
    pub timestamp: u64,
}

/// ZDNS response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsResponse {
    /// Query ID
    pub id: u16,
    /// Response flags
    pub flags: ZdnsFlags,
    /// Response code
    pub response_code: ZdnsResponseCode,
    /// Queried domain name
    pub name: String,
    /// Answer records
    pub answers: Vec<ZdnsRecord>,
    /// Authority records
    pub authorities: Vec<ZdnsRecord>,
    /// Additional records
    pub additional: Vec<ZdnsRecord>,
    /// Response timestamp
    pub timestamp: u64,
    /// Responder identity
    pub responder: Option<lib_identity::IdentityId>,
    /// Zero-knowledge proof of response authenticity
    pub authenticity_proof: Option<lib_proofs::ZeroKnowledgeProof>,
}

/// ZDNS query/response flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsFlags {
    /// Query/Response flag
    pub qr: bool,
    /// Authoritative answer
    pub aa: bool,
    /// Truncated message
    pub tc: bool,
    /// Recursion desired
    pub rd: bool,
    /// Recursion available
    pub ra: bool,
    /// Zero-knowledge privacy requested
    pub zk: bool,
    /// Authenticated data
    pub ad: bool,
    /// Checking disabled
    pub cd: bool,
}

impl Default for ZdnsFlags {
    fn default() -> Self {
        Self {
            qr: false,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            zk: true, // Default to zero-knowledge privacy
            ad: false,
            cd: false,
        }
    }
}

/// ZDNS response codes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZdnsResponseCode {
    /// No error
    NoError = 0,
    /// Format error
    FormatError = 1,
    /// Server failure
    ServerFailure = 2,
    /// Name error (domain doesn't exist)
    NameError = 3,
    /// Not implemented
    NotImplemented = 4,
    /// Query refused
    Refused = 5,
    /// Zero-knowledge proof invalid
    ZkProofInvalid = 100,
    /// Access denied
    AccessDenied = 101,
    /// Privacy violation
    PrivacyViolation = 102,
}

impl ZdnsResponseCode {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ZdnsResponseCode::NoError => "No error",
            ZdnsResponseCode::FormatError => "Format error",
            ZdnsResponseCode::ServerFailure => "Server failure",
            ZdnsResponseCode::NameError => "Name error",
            ZdnsResponseCode::NotImplemented => "Not implemented",
            ZdnsResponseCode::Refused => "Query refused",
            ZdnsResponseCode::ZkProofInvalid => "Zero-knowledge proof invalid",
            ZdnsResponseCode::AccessDenied => "Access denied",
            ZdnsResponseCode::PrivacyViolation => "Privacy violation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zdns_record_type_conversion() {
        assert_eq!(ZdnsRecordType::A.as_str(), "A");
        assert_eq!(ZdnsRecordType::from_str("A"), Some(ZdnsRecordType::A));
        assert_eq!(ZdnsRecordType::from_str("UNKNOWN"), None);
    }

    #[test]
    fn test_zdns_response_code_description() {
        assert_eq!(ZdnsResponseCode::NoError.description(), "No error");
        assert_eq!(ZdnsResponseCode::ZkProofInvalid.description(), "Zero-knowledge proof invalid");
    }

    #[test]
    fn test_zdns_flags_default() {
        let flags = ZdnsFlags::default();
        assert!(!flags.qr);
        assert!(flags.rd);
        assert!(flags.zk); // Should default to zero-knowledge privacy
    }

    #[test]
    fn test_constants() {
        assert_eq!(ZHTP_VERSION, "1.0");
        assert_eq!(ZDNS_VERSION, "1.0");
        assert_eq!(DAO_FEE_PERCENTAGE, 200);
        assert_eq!(MIN_DAO_FEE, 5);
    }
}

// Additional types for storage and content management
/// Cached content structure for improved performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedContent {
    /// Content hash identifier
    pub content_hash: String,
    /// Actual content data
    pub content: Vec<u8>,
    /// Content metadata
    pub metadata: ContentMetadata,
    /// When content was cached (Unix timestamp)
    pub cached_at: u64,
    /// Number of times content was accessed
    pub access_count: u64,
}

/// Content search result for storage queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSearchResult {
    /// Unique content identifier
    pub content_id: String,
    /// Original filename
    pub filename: String,
    /// MIME type
    pub content_type: String,
    /// File size in bytes
    pub size: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Content description
    pub description: String,
    /// Associated tags
    pub tags: Vec<String>,
    /// Search relevance score (0.0-1.0)
    pub relevance_score: f64,
    /// Owner identity ID
    pub owner_id: String,
    /// Access level required
    pub access_level: String,
}

/// Storage search query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSearchQuery {
    /// Search keywords
    pub keywords: Vec<String>,
    /// Filter by content type
    pub content_type: Option<String>,
    /// Size range filter (min, max) in bytes
    pub size_range: Option<(u64, u64)>,
    /// Date range filter (start, end) as Unix timestamps
    pub date_range: Option<(u64, u64)>,
    /// Tag filters
    pub tags: Option<Vec<String>>,
}

// ServerContent moved to types/content.rs to avoid duplication
// Use: use crate::types::content::ServerContent;

/// Storage requirements for content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRequirements {
    /// Required replication factor
    pub replication: u32,
    /// Storage duration in days
    pub duration_days: u32,
    /// Geographic distribution requirements
    pub geographic_distribution: Vec<String>,
    /// Quality requirements
    pub quality_level: StorageQuality,
}

impl Default for StorageRequirements {
    fn default() -> Self {
        Self {
            replication: 3,
            duration_days: 30,
            geographic_distribution: Vec::new(),
            quality_level: StorageQuality::Standard,
        }
    }
}

/// Storage quality levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageQuality {
    /// Basic storage (lower redundancy)
    Basic,
    /// Standard storage (normal redundancy)
    Standard,
    /// Premium storage (high redundancy, fast access)
    Premium,
    /// Archive storage (high redundancy, slower access)
    Archive,
}
