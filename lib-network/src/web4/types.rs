//! Web4 Domain Registry Types and Structures
//!
//! ## Versioning Model
//!
//! Web4 domains use a **versioned pointer** model:
//! - `DomainRecord` holds the current manifest CID and version number
//! - `Web4Manifest` is an immutable, content-addressed structure
//! - Each manifest links to its predecessor via `previous_manifest`
//! - Updates require atomic compare-and-swap on `expected_previous_manifest_cid`
//!
//! This ensures:
//! - Atomic, ordered updates (no concurrent overwrites)
//! - Cryptographically linked history
//! - Rollback via re-pointing to old manifest CID

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use lib_proofs::ZeroKnowledgeProof;
use lib_identity::{ZhtpIdentity, IdentityId};

/// Manifest reference entry in version history
/// CANONICAL: This is what appears in the manifest_index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRef {
    /// Version number (monotonically increasing)
    pub version: u64,
    /// CANONICAL: The Web4Manifest CID (runtime truth)
    /// Used for all domain resolution and runtime lookups
    pub web4_manifest_cid: String,
    /// AUDIT: The original DeployManifest CID (provenance)
    /// Stored for audit trail and signature verification
    #[serde(default)]
    pub deploy_manifest_cid: Option<String>,
    /// BLAKE3 hash of the build output
    pub build_hash: String,
    /// Deployment timestamp
    pub created_at: u64,
    /// Deployment message (optional)
    pub message: Option<String>,
}

/// Web4 domain registration record (versioned pointer)
///
/// CANONICAL ARCHITECTURE:
/// - current_web4_manifest_cid points to the RUNTIME truth (Web4Manifest)
/// - All resolution uses web4_manifest_cid exclusively
/// - deploy_manifest_cid is stored only in manifest_index for audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// Domain name (e.g., "myapp.zhtp")
    pub domain: String,
    /// Owner's identity
    pub owner: IdentityId,
    /// CANONICAL: Current Web4Manifest CID (runtime truth for resolution)
    /// This is the authoritative pointer used by all domain resolution logic
    pub current_web4_manifest_cid: String,
    /// Current version number (monotonically increasing)
    pub version: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Domain ownership proof
    pub ownership_proof: ZeroKnowledgeProof,
    /// Content mappings (path -> content_hash) - cached from current manifest
    pub content_mappings: HashMap<String, String>,
    /// Domain metadata
    pub metadata: DomainMetadata,
    /// Transfer history
    pub transfer_history: Vec<DomainTransfer>,
}

/// Web4 Manifest - Immutable, content-addressed deployment snapshot
///
/// Each deployment creates a new manifest with:
/// - Incremented version
/// - Link to previous manifest (for history chain)
/// - Build hash for integrity verification
/// - File mappings (path -> CID)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web4Manifest {
    /// Domain this manifest belongs to
    pub domain: String,
    /// Version number (must be previous.version + 1)
    pub version: u64,
    /// Previous manifest CID (required for version > 1)
    pub previous_manifest: Option<String>,
    /// BLAKE3 hash of the entire build output
    pub build_hash: String,
    /// File mappings (path -> content CID)
    pub files: HashMap<String, ManifestFile>,
    /// Creation timestamp
    pub created_at: u64,
    /// Creator identity (DID)
    pub created_by: String,
    /// Optional deployment message (like git commit message)
    pub message: Option<String>,
}

/// File entry in a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Content CID
    pub cid: String,
    /// File size in bytes
    pub size: u64,
    /// Content type (MIME)
    pub content_type: String,
    /// BLAKE3 hash of file content
    pub hash: String,
}

impl Web4Manifest {
    /// Compute the CID of this manifest (content-addressed identifier)
    pub fn compute_cid(&self) -> String {
        let canonical = serde_json::to_vec(self).unwrap_or_default();
        let hash = lib_crypto::hash_blake3(&canonical);
        format!("bafk{}", hex::encode(&hash[..16]))
    }

    /// Validate manifest chain integrity
    pub fn validate_chain(&self, previous: Option<&Web4Manifest>) -> Result<(), String> {
        if self.version == 1 {
            // First version must not have previous manifest
            if self.previous_manifest.is_some() {
                return Err("Version 1 manifest must not have previous_manifest".to_string());
            }
            if previous.is_some() {
                return Err("Version 1 should not have a previous manifest".to_string());
            }
            return Ok(());
        }

        // Version > 1 must have previous manifest
        let prev_cid = self.previous_manifest.as_ref()
            .ok_or("Version > 1 must have previous_manifest")?;

        // If we have the previous manifest, validate the link
        if let Some(prev) = previous {
            let expected_cid = prev.compute_cid();
            if prev_cid != &expected_cid {
                return Err(format!(
                    "previous_manifest mismatch: expected {}, got {}",
                    expected_cid, prev_cid
                ));
            }
            if self.version != prev.version + 1 {
                return Err(format!(
                    "Version must be previous + 1: expected {}, got {}",
                    prev.version + 1, self.version
                ));
            }
            if self.domain != prev.domain {
                return Err("Domain mismatch in manifest chain".to_string());
            }
        }

        Ok(())
    }
}

/// Domain update request (atomic compare-and-swap)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUpdateRequest {
    /// Domain to update
    pub domain: String,
    /// New manifest CID
    pub new_manifest_cid: String,
    /// Expected current manifest CID (for compare-and-swap)
    pub expected_previous_manifest_cid: String,
    /// Signature from domain owner
    pub signature: String,
    /// Request timestamp
    pub timestamp: u64,
}

/// Domain update response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUpdateResponse {
    /// Update successful
    pub success: bool,
    /// New version number
    pub new_version: u64,
    /// New manifest CID
    pub new_manifest_cid: String,
    /// Previous manifest CID
    pub previous_manifest_cid: String,
    /// Update timestamp
    pub updated_at: u64,
    /// Error message if failed
    pub error: Option<String>,
}

/// Domain version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVersionEntry {
    /// Version number
    pub version: u64,
    /// CANONICAL: Web4Manifest CID for this version
    /// This is what's used for runtime resolution
    pub web4_manifest_cid: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Creator DID
    pub created_by: String,
    /// Deployment message
    pub message: Option<String>,
    /// Build hash
    pub build_hash: String,
}

/// Domain history response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainHistoryResponse {
    /// Domain name
    pub domain: String,
    /// Current version
    pub current_version: u64,
    /// Version history (newest first)
    pub versions: Vec<DomainVersionEntry>,
    /// Total version count
    pub total_versions: u64,
}

/// Domain status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStatusResponse {
    /// Domain found
    pub found: bool,
    /// Domain name
    pub domain: String,
    /// Current version
    pub version: u64,
    /// CANONICAL: Current Web4Manifest CID (runtime truth)
    pub current_web4_manifest_cid: String,
    /// Owner DID
    pub owner_did: String,
    /// Last update timestamp
    pub updated_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Build hash of current version
    pub build_hash: String,
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
    /// CANONICAL: DeployManifest CID (if registering with pre-uploaded manifest)
    /// This will be converted to web4_manifest_cid during registration
    #[serde(default)]
    pub deploy_manifest_cid: Option<String>,
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