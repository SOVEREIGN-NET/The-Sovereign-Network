//! ZHTP Headers for Zero-Knowledge Web with Built-in Economic Incentives
//! 
//! Headers include standard HTTP-compatible fields plus Web4 extensions for
//! zero-knowledge proofs, DAO fees, post-quantum cryptography, and mesh networking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use lib_crypto::PostQuantumSignature;
use lib_storage::types::ContentHash;
use lib_proofs::ZeroKnowledgeProof;
use lib_economy::Priority;
use crate::types::ZHTP_VERSION;

/// ZHTP headers with Web4 extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpHeaders {
    // Standard HTTP-compatible headers
    /// Content type (MIME type)
    pub content_type: Option<String>,
    /// Content length in bytes
    pub content_length: Option<u64>,
    /// Content encoding (gzip, deflate, br, etc.)
    pub content_encoding: Option<String>,
    /// Cache control directives
    pub cache_control: Option<String>,
    /// Last modified timestamp
    pub last_modified: Option<u64>,
    /// ETag for content versioning
    pub etag: Option<String>,
    /// Accept types for content negotiation
    pub accept: Option<String>,
    /// Accept encoding for compression negotiation
    pub accept_encoding: Option<String>,
    /// Accept language for localization
    pub accept_language: Option<String>,
    /// User agent information
    pub user_agent: Option<String>,
    /// Referer information
    pub referer: Option<String>,
    /// Authorization header
    pub authorization: Option<String>,
    /// Host header
    pub host: Option<String>,
    /// Location header (for redirects)
    pub location: Option<String>,
    /// Access-Control-Allow-Origin header
    pub access_control_allow_origin: Option<String>,
    /// Server header
    pub server: Option<String>,
    /// Date header
    pub date: Option<u64>,
    /// Expires header
    pub expires: Option<u64>,
    /// Cookie header
    pub cookie: Option<String>,
    /// Set-Cookie header
    pub set_cookie: Option<String>,

    // Web4 Privacy and Zero-Knowledge Extensions
    /// Privacy level (0-100, 100 = maximum privacy)
    pub privacy_level: Option<u8>,
    /// Zero-knowledge proof of content validity
    pub zk_proof: Option<ZeroKnowledgeProof>,
    /// Zero-knowledge proof of identity authorization
    pub zk_identity_proof: Option<ZeroKnowledgeProof>,
    /// Zero-knowledge proof of access rights
    pub zk_access_proof: Option<ZeroKnowledgeProof>,
    /// Content hash for integrity verification
    pub content_hash: Option<ContentHash>,
    /// Access control requirements
    pub access_requirements: Option<Vec<String>>,
    /// Privacy metadata (encrypted)
    pub privacy_metadata: Option<Vec<u8>>,

    // Web4 Cryptographic Extensions
    /// Encryption algorithm used (CRYSTALS-Kyber, etc.)
    pub encryption: Option<String>,
    /// Key exchange algorithm
    pub key_exchange: Option<String>,
    /// Digital signature
    pub signature: Option<PostQuantumSignature>,
    /// Signature algorithm used
    pub signature_algorithm: Option<String>,
    /// Public key for verification
    pub public_key: Option<Vec<u8>>,
    /// Certificate chain
    pub certificate_chain: Option<Vec<Vec<u8>>>,

    // Web4 Economic Extensions
    /// Network operation fee (covers bandwidth, storage, compute)
    pub network_fee: Option<u64>,
    /// Mandatory DAO fee for Universal Basic Income and welfare (2% of transaction value)
    pub dao_fee: u64,
    /// Total transaction fees (network_fee + dao_fee)
    pub total_fees: u64,
    /// DAO fee payment proof (validates UBI contribution)
    pub dao_fee_proof: Option<[u8; 32]>,
    /// Transaction priority for network QoS
    pub priority: Option<Priority>,
    /// Economic transaction ID
    pub transaction_id: Option<String>,
    /// Fee tier for pricing
    pub fee_tier: Option<String>,
    /// UBI contribution tracking
    pub ubi_contribution: Option<u64>,
    /// Economic validation proof
    pub economic_proof: Option<Vec<u8>>,

    // Web4 Mesh Network Extensions
    /// Mesh routing path
    pub mesh_path: Option<Vec<String>>,
    /// Mesh hop count
    pub mesh_hops: Option<u16>,
    ///  flag
    pub isp_bypass: Option<bool>,
    /// Preferred mesh peers
    pub preferred_peers: Option<Vec<String>>,
    /// Network latency requirements
    pub latency_requirements: Option<u32>,
    /// Bandwidth requirements
    pub bandwidth_requirements: Option<u64>,
    /// Mesh quality metrics
    pub mesh_quality: Option<f64>,

    // Web4 Identity and Access Control
    /// Identity DID (Decentralized Identifier)
    pub identity_did: Option<String>,
    /// Identity proof type
    pub identity_proof_type: Option<String>,
    /// Access control policy ID
    pub access_policy_id: Option<String>,
    /// Required reputation score
    pub required_reputation: Option<u32>,
    /// Geographic restrictions
    pub geo_restrictions: Option<Vec<String>>,
    /// Time-based access constraints
    pub time_constraints: Option<String>,

    // Web4 Content and Storage Extensions
    /// Content distribution tier
    pub content_tier: Option<String>,
    /// Storage replication factor
    pub replication_factor: Option<u8>,
    /// Content expiration time
    pub expires_at: Option<u64>,
    /// Content version
    pub content_version: Option<String>,
    /// Storage encryption level
    pub storage_encryption: Option<String>,
    /// Content licensing information
    pub content_license: Option<String>,

    // Web4 Protocol Extensions
    /// ZHTP protocol version
    pub lib_version: Option<String>,
    /// Required protocol features
    pub required_features: Option<Vec<String>>,
    /// Protocol upgrade recommendations
    pub protocol_upgrade: Option<String>,
    /// Backward compatibility mode
    pub compatibility_mode: Option<String>,

    // Custom headers for extensibility
    /// Custom application-specific headers
    pub custom: HashMap<String, String>,
}

impl ZhtpHeaders {
    /// Create new headers with default values
    pub fn new() -> Self {
        Self {
            // Standard headers
            content_type: None,
            content_length: None,
            content_encoding: None,
            cache_control: None,
            last_modified: None,
            etag: None,
            accept: None,
            accept_encoding: None,
            accept_language: None,
            user_agent: None,
            referer: None,
            authorization: None,
            host: None,
            location: None,
            access_control_allow_origin: None,
            server: None,
            date: None,
            expires: None,
            cookie: None,
            set_cookie: None,

            // Privacy extensions
            privacy_level: Some(100), // Maximum privacy by default
            zk_proof: None,
            zk_identity_proof: None,
            zk_access_proof: None,
            content_hash: None,
            access_requirements: None,
            privacy_metadata: None,

            // Cryptographic extensions
            encryption: Some("CRYSTALS-Kyber".to_string()),
            key_exchange: Some("CRYSTALS-Kyber".to_string()),
            signature: None,
            signature_algorithm: Some("CRYSTALS-Dilithium".to_string()),
            public_key: None,
            certificate_chain: None,

            // Economic extensions
            network_fee: None,
            dao_fee: 0,
            total_fees: 0,
            dao_fee_proof: None,
            priority: Some(Priority::Normal),
            transaction_id: None,
            fee_tier: None,
            ubi_contribution: None,
            economic_proof: None,

            // Mesh network extensions
            mesh_path: None,
            mesh_hops: None,
            isp_bypass: Some(true), // Enable  by default
            preferred_peers: None,
            latency_requirements: None,
            bandwidth_requirements: None,
            mesh_quality: None,

            // Identity and access control
            identity_did: None,
            identity_proof_type: None,
            access_policy_id: None,
            required_reputation: None,
            geo_restrictions: None,
            time_constraints: None,

            // Content and storage
            content_tier: Some("hot".to_string()),
            replication_factor: Some(3),
            expires_at: None,
            content_version: None,
            storage_encryption: Some("AES-256-GCM".to_string()),
            content_license: None,

            // Protocol extensions
            lib_version: Some(ZHTP_VERSION.to_string()),
            required_features: None,
            protocol_upgrade: None,
            compatibility_mode: None,

            custom: HashMap::new(),
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Set content length
    pub fn with_content_length(mut self, length: u64) -> Self {
        self.content_length = Some(length);
        self
    }

    /// Set cache control
    pub fn with_cache_control(mut self, cache_control: String) -> Self {
        self.cache_control = Some(cache_control);
        self
    }

    /// Set privacy level (0-100)
    pub fn with_privacy_level(mut self, level: u8) -> Self {
        self.privacy_level = Some(level.min(100));
        self
    }

    /// Set zero-knowledge proof
    pub fn with_zk_proof(mut self, proof: ZeroKnowledgeProof) -> Self {
        self.zk_proof = Some(proof);
        self
    }

    /// Set content hash
    pub fn with_content_hash(mut self, hash: ContentHash) -> Self {
        self.content_hash = Some(hash);
        self
    }

    /// Set encryption algorithm
    pub fn with_encryption(mut self, algorithm: String) -> Self {
        self.encryption = Some(algorithm);
        self
    }

    /// Set DAO fee
    pub fn with_dao_fee(mut self, fee: u64, proof: [u8; 32]) -> Self {
        self.dao_fee = fee;
        self.dao_fee_proof = Some(proof);
        self
    }

    /// Set network fee
    pub fn with_network_fee(mut self, fee: u64) -> Self {
        self.network_fee = Some(fee);
        self.total_fees = self.dao_fee + fee;
        self
    }

    /// Set transaction priority
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Enable 
    pub fn with_isp_bypass(mut self, enable: bool) -> Self {
        self.isp_bypass = Some(enable);
        self
    }

    /// Set mesh routing path
    pub fn with_mesh_path(mut self, path: Vec<String>) -> Self {
        self.mesh_hops = Some(path.len() as u16);
        self.mesh_path = Some(path);
        self
    }

    /// Set identity DID
    pub fn with_identity_did(mut self, did: String) -> Self {
        self.identity_did = Some(did);
        self
    }

    /// Set access requirements
    pub fn with_access_requirements(mut self, requirements: Vec<String>) -> Self {
        self.access_requirements = Some(requirements);
        self
    }

    /// Set content tier
    pub fn with_content_tier(mut self, tier: String) -> Self {
        self.content_tier = Some(tier);
        self
    }

    /// Set replication factor
    pub fn with_replication_factor(mut self, factor: u8) -> Self {
        self.replication_factor = Some(factor);
        self
    }

    /// Add custom header
    pub fn with_custom_header(mut self, key: String, value: String) -> Self {
        self.custom.insert(key, value);
        self
    }

    /// Get header by name (case-insensitive)
    pub fn get(&self, name: &str) -> Option<String> {
        let name_lower = name.to_lowercase();
        match name_lower.as_str() {
            "content-type" => self.content_type.clone(),
            "content-length" => self.content_length.map(|v| v.to_string()),
            "content-encoding" => self.content_encoding.clone(),
            "cache-control" => self.cache_control.clone(),
            "privacy-level" => self.privacy_level.map(|v| v.to_string()),
            "encryption" => self.encryption.clone(),
            "dao-fee" => Some(self.dao_fee.to_string()),
            "total-fees" => Some(self.total_fees.to_string()),
            "isp-bypass" => self.isp_bypass.map(|v| v.to_string()),
            "lib-version" => self.lib_version.clone(),
            _ => self.custom.get(&name_lower).cloned(),
        }
    }

    /// Set header by name (case-insensitive)
    pub fn set(&mut self, name: &str, value: String) {
        let name_lower = name.to_lowercase();
        match name_lower.as_str() {
            "content-type" => self.content_type = Some(value),
            "content-length" => {
                if let Ok(length) = value.parse::<u64>() {
                    self.content_length = Some(length);
                }
            }
            "content-encoding" => self.content_encoding = Some(value),
            "cache-control" => self.cache_control = Some(value),
            "privacy-level" => {
                if let Ok(level) = value.parse::<u8>() {
                    self.privacy_level = Some(level.min(100));
                }
            }
            "encryption" => self.encryption = Some(value),
            "dao-fee" => {
                if let Ok(fee) = value.parse::<u64>() {
                    self.dao_fee = fee;
                }
            }
            "isp-bypass" => {
                if let Ok(bypass) = value.parse::<bool>() {
                    self.isp_bypass = Some(bypass);
                }
            }
            "lib-version" => self.lib_version = Some(value),
            _ => {
                self.custom.insert(name_lower, value);
            }
        }
    }

    /// Remove header by name (case-insensitive)
    pub fn remove(&mut self, name: &str) {
        let name_lower = name.to_lowercase();
        match name_lower.as_str() {
            "content-type" => self.content_type = None,
            "content-length" => self.content_length = None,
            "content-encoding" => self.content_encoding = None,
            "cache-control" => self.cache_control = None,
            "privacy-level" => self.privacy_level = Some(100), // Reset to default
            "encryption" => self.encryption = Some("CRYSTALS-Kyber".to_string()), // Reset to default
            "dao-fee" => self.dao_fee = 0,
            "isp-bypass" => self.isp_bypass = Some(true), // Reset to default
            "lib-version" => self.lib_version = Some(ZHTP_VERSION.to_string()), // Reset to default
            _ => {
                self.custom.remove(&name_lower);
            }
        }
    }

    /// Check if headers indicate zero-knowledge privacy is enabled
    pub fn has_zero_knowledge_privacy(&self) -> bool {
        self.privacy_level.unwrap_or(0) > 50 || self.zk_proof.is_some()
    }

    /// Check if headers indicate post-quantum cryptography is used
    pub fn has_post_quantum_crypto(&self) -> bool {
        self.encryption.as_ref().map_or(false, |enc| {
            enc.contains("Kyber") || enc.contains("Dilithium")
        }) || self.signature_algorithm.as_ref().map_or(false, |sig| {
            sig.contains("Dilithium")
        })
    }

    /// Check if DAO fee is properly set and validated
    pub fn has_valid_dao_fee(&self) -> bool {
        self.dao_fee > 0 && self.dao_fee_proof.is_some()
    }

    /// Check if  is enabled
    pub fn has_isp_bypass(&self) -> bool {
        self.isp_bypass.unwrap_or(false)
    }

    /// Get all header names
    pub fn header_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        
        // Add standard headers that have values
        if self.content_type.is_some() { names.push("content-type".to_string()); }
        if self.content_length.is_some() { names.push("content-length".to_string()); }
        if self.content_encoding.is_some() { names.push("content-encoding".to_string()); }
        if self.cache_control.is_some() { names.push("cache-control".to_string()); }
        if self.privacy_level.is_some() { names.push("privacy-level".to_string()); }
        if self.encryption.is_some() { names.push("encryption".to_string()); }
        if self.dao_fee > 0 { names.push("dao-fee".to_string()); }
        if self.total_fees > 0 { names.push("total-fees".to_string()); }
        if self.isp_bypass.is_some() { names.push("isp-bypass".to_string()); }
        if self.lib_version.is_some() { names.push("lib-version".to_string()); }
        
        // Add custom headers
        names.extend(self.custom.keys().cloned());
        
        names.sort();
        names
    }

    /// Iterate over all headers
    pub fn iter(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        
        // Add standard headers if present
        if let Some(ref value) = self.content_type { headers.push(("Content-Type".to_string(), value.clone())); }
        if let Some(value) = self.content_length { headers.push(("Content-Length".to_string(), value.to_string())); }
        if let Some(ref value) = self.content_encoding { headers.push(("Content-Encoding".to_string(), value.clone())); }
        if let Some(ref value) = self.cache_control { headers.push(("Cache-Control".to_string(), value.clone())); }
        if let Some(value) = self.last_modified { headers.push(("Last-Modified".to_string(), value.to_string())); }
        if let Some(ref value) = self.etag { headers.push(("ETag".to_string(), value.clone())); }
        if let Some(ref value) = self.accept { headers.push(("Accept".to_string(), value.clone())); }
        if let Some(ref value) = self.accept_encoding { headers.push(("Accept-Encoding".to_string(), value.clone())); }
        if let Some(ref value) = self.accept_language { headers.push(("Accept-Language".to_string(), value.clone())); }
        if let Some(ref value) = self.user_agent { headers.push(("User-Agent".to_string(), value.clone())); }
        if let Some(ref value) = self.host { headers.push(("Host".to_string(), value.clone())); }
        if let Some(ref value) = self.referer { headers.push(("Referer".to_string(), value.clone())); }
        if let Some(ref value) = self.authorization { headers.push(("Authorization".to_string(), value.clone())); }
        if let Some(ref value) = self.location { headers.push(("Location".to_string(), value.clone())); }
        if let Some(ref value) = self.access_control_allow_origin { headers.push(("Access-Control-Allow-Origin".to_string(), value.clone())); }
        if let Some(ref value) = self.server { headers.push(("Server".to_string(), value.clone())); }
        if let Some(value) = self.date { headers.push(("Date".to_string(), value.to_string())); }
        if let Some(value) = self.expires { headers.push(("Expires".to_string(), value.to_string())); }
        if let Some(ref value) = self.cookie { headers.push(("Cookie".to_string(), value.clone())); }
        if let Some(ref value) = self.set_cookie { headers.push(("Set-Cookie".to_string(), value.clone())); }
        
        // Add Web4 headers if present
        if let Some(value) = self.privacy_level { headers.push(("Privacy-Level".to_string(), value.to_string())); }
        if let Some(ref value) = self.encryption { headers.push(("Encryption".to_string(), value.clone())); }
        if let Some(ref value) = self.signature_algorithm { headers.push(("Signature-Algorithm".to_string(), value.clone())); }
        if let Some(ref value) = self.zk_proof { headers.push(("ZK-Proof".to_string(), format!("{:?}", value))); }
        if let Some(ref value) = self.identity_did { headers.push(("Identity-ID".to_string(), value.clone())); }
        if let Some(ref value) = self.access_policy_id { headers.push(("Access-Policy-ID".to_string(), value.clone())); }
        if let Some(ref value) = self.fee_tier { headers.push(("Fee-Tier".to_string(), format!("{:?}", value))); }
        if self.dao_fee > 0 { headers.push(("DAO-Fee".to_string(), self.dao_fee.to_string())); }
        if self.total_fees > 0 { headers.push(("Total-Fees".to_string(), self.total_fees.to_string())); }
        if let Some(value) = self.isp_bypass { headers.push(("ISP-Bypass".to_string(), value.to_string())); }
        if let Some(ref value) = self.lib_version { headers.push(("ZHTP-Version".to_string(), value.clone())); }
        
        // Add custom headers
        for (key, value) in &self.custom {
            headers.push((key.clone(), value.clone()));
        }
        
        headers
    }

    /// Check if a header exists (case-insensitive)
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

impl Default for ZhtpHeaders {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_headers_creation() {
        let headers = ZhtpHeaders::new();
        assert_eq!(headers.privacy_level, Some(100));
        assert_eq!(headers.encryption, Some("CRYSTALS-Kyber".to_string()));
        assert_eq!(headers.isp_bypass, Some(true));
    }

    #[test]
    fn test_headers_builder() {
        let headers = ZhtpHeaders::new()
            .with_content_type("text/html".to_string())
            .with_content_length(1024)
            .with_privacy_level(80)
            .with_dao_fee(50, [1u8; 32])
            .with_network_fee(25);

        assert_eq!(headers.content_type, Some("text/html".to_string()));
        assert_eq!(headers.content_length, Some(1024));
        assert_eq!(headers.privacy_level, Some(80));
        assert_eq!(headers.dao_fee, 50);
        assert_eq!(headers.total_fees, 75); // 50 + 25
    }

    #[test]
    fn test_header_get_set() {
        let mut headers = ZhtpHeaders::new();
        
        headers.set("content-type", "application/json".to_string());
        assert_eq!(headers.get("content-type"), Some("application/json".to_string()));
        assert_eq!(headers.get("Content-Type"), Some("application/json".to_string()));
        
        headers.set("custom-header", "custom-value".to_string());
        assert_eq!(headers.get("custom-header"), Some("custom-value".to_string()));
    }

    #[test]
    fn test_header_validation_methods() {
        let mut headers = ZhtpHeaders::new();
        
        assert!(headers.has_zero_knowledge_privacy()); // Default privacy level is 100
        assert!(headers.has_post_quantum_crypto()); // Default encryption is Kyber
        assert!(!headers.has_valid_dao_fee()); // No DAO fee set
        assert!(headers.has_isp_bypass()); // Default  is true
        
        headers.dao_fee = 50;
        headers.dao_fee_proof = Some([1u8; 32]);
        assert!(headers.has_valid_dao_fee());
    }

    #[test]
    fn test_header_names() {
        let headers = ZhtpHeaders::new()
            .with_content_type("text/plain".to_string())
            .with_custom_header("x-custom".to_string(), "value".to_string());
        
        let names = headers.header_names();
        assert!(names.contains(&"content-type".to_string()));
        assert!(names.contains(&"x-custom".to_string()));
        assert!(names.contains(&"lib-version".to_string()));
    }

    #[test]
    fn test_privacy_level_bounds() {
        let headers = ZhtpHeaders::new().with_privacy_level(150);
        assert_eq!(headers.privacy_level, Some(100)); // Should be capped at 100
    }
}
