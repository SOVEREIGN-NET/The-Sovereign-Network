//! Web4 Domain Registry Types and Structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use lib_proofs::ZeroKnowledgeProof;
use lib_identity::{ZhtpIdentity, IdentityId};

/// Web4 domain registration record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Domain name (e.g., "myapp.zhtp")
    pub domain: String,
    /// Owner's identity
    pub owner: IdentityId,
    /// Registration timestamp
    pub registered_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Domain ownership proof
    pub ownership_proof: ZeroKnowledgeProof,
    /// Content mappings (path -> content_hash)
    pub content_mappings: HashMap<String, String>,
    /// Domain metadata
    pub metadata: DomainMetadata,
    /// Transfer history
    pub transfer_history: Vec<DomainTransfer>,
}

/// Domain metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMetadata {
    /// Domain title/name
    pub title: String,
    /// Domain description
    pub description: String,
    /// Domain category
    pub category: String,
    /// Custom tags
    pub tags: Vec<String>,
    /// Is publicly discoverable
    pub public: bool,
    /// Economic settings
    pub economic_settings: DomainEconomicSettings,
}

/// Domain economic settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEconomicSettings {
    /// Registration fee paid
    pub registration_fee: f64,
    /// Renewal fee per year
    pub renewal_fee: f64,
    /// Transfer fee
    pub transfer_fee: f64,
    /// Content hosting budget
    pub hosting_budget: f64,
}

/// Domain transfer record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainTransfer {
    /// Previous owner
    pub from_owner: IdentityId,
    /// New owner
    pub to_owner: IdentityId,
    /// Transfer timestamp
    pub transferred_at: u64,
    /// Transfer proof
    pub transfer_proof: ZeroKnowledgeProof,
    /// Transfer fee paid
    pub fee_paid: f64,
}

/// Domain registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistrationRequest {
    /// Desired domain name
    pub domain: String,
    /// Owner identity
    pub owner: ZhtpIdentity,
    /// Registration duration in days
    pub duration_days: u64,
    /// Domain metadata
    pub metadata: DomainMetadata,
    /// Initial content mappings
    pub initial_content: HashMap<String, Vec<u8>>,
    /// Registration proof
    pub registration_proof: ZeroKnowledgeProof,
}

/// Domain registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistrationResponse {
    /// Registered domain
    pub domain: String,
    /// Registration successful
    pub success: bool,
    /// Registration hash/ID
    pub registration_id: String,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Registration fees
    pub fees_charged: f64,
    /// Error message if any
    pub error: Option<String>,
}

/// Domain lookup response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainLookupResponse {
    /// Domain found
    pub found: bool,
    /// Domain record if found
    pub record: Option<DomainRecord>,
    /// Current content mappings
    pub content_mappings: HashMap<String, String>,
    /// Domain owner info (public parts only)
    pub owner_info: Option<PublicOwnerInfo>,
}

/// Public owner information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOwnerInfo {
    /// Owner's public identity hash
    pub identity_hash: String,
    /// Registration date
    pub registered_at: u64,
    /// Is verified identity
    pub verified: bool,
    /// Public alias if any
    pub alias: Option<String>,
}

/// Content publishing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPublishRequest {
    /// Target domain
    pub domain: String,
    /// Content path
    pub path: String,
    /// Content data
    pub content: Vec<u8>,
    /// Content type
    pub content_type: String,
    /// Publisher identity
    pub publisher: ZhtpIdentity,
    /// Publishing proof (proves domain ownership)
    pub ownership_proof: ZeroKnowledgeProof,
    /// Content metadata
    pub metadata: ContentMetadata,
}

/// Content metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content title
    pub title: String,
    /// Content description
    pub description: String,
    /// Content version
    pub version: String,
    /// Content tags
    pub tags: Vec<String>,
    /// Is publicly accessible
    pub public: bool,
    /// Content license
    pub license: String,
}

/// Content publishing response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPublishResponse {
    /// Publishing successful
    pub success: bool,
    /// Content hash
    pub content_hash: String,
    /// Full ZHTP URL
    pub zhtp_url: String,
    /// Publishing timestamp
    pub published_at: u64,
    /// Storage fees charged
    pub storage_fees: f64,
    /// Error message if any
    pub error: Option<String>,
}

/// Web4 system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Statistics {
    /// Total registered domains
    pub total_domains: u64,
    /// Total content items
    pub total_content: u64,
    /// Total storage used (bytes)
    pub total_storage_bytes: u64,
    /// Active domains (with recent content updates)
    pub active_domains: u64,
    /// Economic statistics
    pub economic_stats: Web4EconomicStats,
}

/// Web4 economic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4EconomicStats {
    /// Total registration fees collected
    pub registration_fees: f64,
    /// Total storage fees collected
    pub storage_fees: f64,
    /// Total transfer fees collected
    pub transfer_fees: f64,
    /// Current network storage capacity
    pub storage_capacity_gb: f64,
    /// Storage utilization percentage
    pub storage_utilization: f64,
}