//! ZHTP Request Implementation
//! 
//! Complete ZHTP request structure with automatic DAO fee calculation,
//! zero-knowledge proof integration, and post-quantum cryptography.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{ZhtpMethod, ZhtpHeaders, ZHTP_VERSION, MIN_DAO_FEE, DAO_FEE_PERCENTAGE};
use lib_identity::IdentityId;
use lib_proofs::ZeroKnowledgeProof;
use lib_economy::{EconomicModel, Priority};
use lib_crypto::hash_blake3;

/// ZHTP request with Web4 extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpRequest {
    /// Request method
    pub method: ZhtpMethod,
    /// Target URI
    pub uri: String,
    /// Protocol version
    pub version: String,
    /// Request headers
    pub headers: ZhtpHeaders,
    /// Request body
    pub body: Vec<u8>,
    /// Request timestamp
    pub timestamp: u64,
    /// Requester identity
    pub requester: Option<IdentityId>,
    /// Zero-knowledge proof of authorization
    pub auth_proof: Option<ZeroKnowledgeProof>,
}

impl ZhtpRequest {
    /// Create a new ZHTP request with automatic DAO fee calculation
    pub fn new(
        method: ZhtpMethod,
        uri: String,
        body: Vec<u8>,
        requester: Option<IdentityId>,
        priority: Priority,
        economic_model: &EconomicModel,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        // Fee Policy: Getters are FREE (rate-limited), Setters require DAO fee
        // GET/HEAD: 0 fee (100 requests per 30 seconds enforced by node)
        // POST/PUT/DELETE/PATCH: Standard DAO fee for UBI funding
        let (network_fee, dao_fee) = match method {
            ZhtpMethod::Get | ZhtpMethod::Head => {
                // Getters are free - rate limiting enforced server-side
                (0, 0)
            }
            _ => {
                // Setters require fees
                let request_value = crate::economics::utils::calculate_request_value(&method, &body, &uri);
                let tx_size = body.len() as u64 + uri.len() as u64;
                let (net_fee, dao_fee_calc, _total) = economic_model.calculate_fee(tx_size, request_value, priority);
                (net_fee, dao_fee_calc)
            }
        };
        
        // Generate DAO fee proof for UBI funding validation
        let dao_fee_proof = hash_blake3(&format!("dao_fee_{}_{}", dao_fee, timestamp).as_bytes());
        
        // Create headers with Web4 defaults
        let mut headers = ZhtpHeaders::new()
            .with_content_type("application/octet-stream".to_string())
            .with_content_length(body.len() as u64)
            .with_privacy_level(100) // Maximum privacy by default
            .with_encryption("CRYSTALS-Kyber".to_string())
            .with_dao_fee(dao_fee, dao_fee_proof)
            .with_network_fee(network_fee)
            .with_priority(priority);

        // Set method-specific headers
        match method {
            ZhtpMethod::Get | ZhtpMethod::Head => {
                headers = headers.with_cache_control("max-age=3600".to_string());
            }
            ZhtpMethod::Post | ZhtpMethod::Put | ZhtpMethod::Patch => {
                headers = headers.with_content_tier("hot".to_string())
                    .with_replication_factor(3);
            }
            _ => {}
        }

        Ok(ZhtpRequest {
            method,
            uri,
            version: ZHTP_VERSION.to_string(),
            headers,
            body,
            timestamp,
            requester,
            auth_proof: None, // Will be added by auth layer
        })
    }

    /// Create a new request with custom headers
    pub fn with_headers(
        method: ZhtpMethod,
        uri: String,
        body: Vec<u8>,
        headers: ZhtpHeaders,
        requester: Option<IdentityId>,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        Ok(ZhtpRequest {
            method,
            uri,
            version: ZHTP_VERSION.to_string(),
            headers,
            body,
            timestamp,
            requester,
            auth_proof: None,
        })
    }

    /// Create a simple GET request
    pub fn get(uri: String, requester: Option<IdentityId>) -> anyhow::Result<Self> {
        let economic_model = EconomicModel::new();
        Self::new(
            ZhtpMethod::Get,
            uri,
            vec![],
            requester,
            Priority::Normal,
            &economic_model,
        )
    }

    /// Create a POST request with content
    pub fn post(
        uri: String,
        body: Vec<u8>,
        content_type: String,
        requester: Option<IdentityId>,
    ) -> anyhow::Result<Self> {
        let economic_model = EconomicModel::new();
        let mut request = Self::new(
            ZhtpMethod::Post,
            uri,
            body,
            requester,
            Priority::Normal,
            &economic_model,
        )?;
        
        request.headers = request.headers.with_content_type(content_type);
        Ok(request)
    }

    /// Create a PUT request for updates
    pub fn put(
        uri: String,
        body: Vec<u8>,
        content_type: String,
        requester: Option<IdentityId>,
    ) -> anyhow::Result<Self> {
        let economic_model = EconomicModel::new();
        let mut request = Self::new(
            ZhtpMethod::Put,
            uri,
            body,
            requester,
            Priority::Normal,
            &economic_model,
        )?;
        
        request.headers = request.headers.with_content_type(content_type);
        Ok(request)
    }

    /// Create a DELETE request
    pub fn delete(uri: String, requester: Option<IdentityId>) -> anyhow::Result<Self> {
        let economic_model = EconomicModel::new();
        Self::new(
            ZhtpMethod::Delete,
            uri,
            vec![],
            requester,
            Priority::Normal,
            &economic_model,
        )
    }

    /// Create a VERIFY request for zero-knowledge proof validation
    pub fn verify(
        uri: String,
        proof: ZeroKnowledgeProof,
        requester: Option<IdentityId>,
    ) -> anyhow::Result<Self> {
        let economic_model = EconomicModel::new();
        let mut request = Self::new(
            ZhtpMethod::Verify,
            uri,
            vec![], // Proof is in headers, not body
            requester,
            Priority::High, // Verification has high priority
            &economic_model,
        )?;
        
        request.headers = request.headers.with_zk_proof(proof);
        Ok(request)
    }

    /// Validate ZHTP request includes mandatory DAO fee for UBI/welfare funding
    pub fn validate_dao_fee(&self, _economic_model: &EconomicModel) -> anyhow::Result<bool> {
        // Calculate expected DAO fee based on request value
        let request_value = crate::economics::utils::calculate_request_value(&self.method, &self.body, &self.uri);
        
        // Calculate expected DAO fee (2% of request value)
        let expected_dao_fee = (request_value * DAO_FEE_PERCENTAGE) / 10000; // 2.00%
        let expected_dao_fee = expected_dao_fee.max(MIN_DAO_FEE); // Minimum 5 tokens
        
        // Validate DAO fee was paid
        let dao_fee_valid = self.headers.dao_fee >= expected_dao_fee;
        
        // Validate DAO fee proof exists
        let proof_valid = self.headers.dao_fee_proof.is_some();
        
        if !dao_fee_valid {
            tracing::warn!(
                "ZHTP request rejected: insufficient DAO fee. Expected: {}, Provided: {}",
                expected_dao_fee, self.headers.dao_fee
            );
            return Ok(false);
        }
        
        if !proof_valid {
            tracing::warn!("ZHTP request rejected: missing DAO fee proof");
            return Ok(false);
        }
        
        tracing::info!(
            "ZHTP request validated: {} ZHTP DAO fee paid for UBI/welfare funding",
            self.headers.dao_fee
        );
        
        Ok(true)
    }

    /// Validate request size limits
    pub fn validate_size_limits(&self) -> anyhow::Result<bool> {
        if self.body.len() > crate::types::MAX_REQUEST_SIZE {
            tracing::warn!(
                "ZHTP request rejected: body too large. Size: {}, Max: {}",
                self.body.len(),
                crate::types::MAX_REQUEST_SIZE
            );
            return Ok(false);
        }

        // Estimate header size (simplified)
        let header_size = serde_json::to_string(&self.headers)?.len();
        if header_size > crate::types::MAX_HEADER_SIZE {
            tracing::warn!(
                "ZHTP request rejected: headers too large. Size: {}, Max: {}",
                header_size,
                crate::types::MAX_HEADER_SIZE
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate request timestamp (prevent replay attacks)
    pub fn validate_timestamp(&self, max_age_seconds: u64) -> anyhow::Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let age = now.saturating_sub(self.timestamp);
        
        if age > max_age_seconds {
            tracing::warn!(
                "ZHTP request rejected: timestamp too old. Age: {}s, Max: {}s",
                age, max_age_seconds
            );
            return Ok(false);
        }

        if self.timestamp > now + 300 { // Allow 5 minutes clock skew
            tracing::warn!(
                "ZHTP request rejected: timestamp in future. Skew: {}s",
                self.timestamp - now
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Add zero-knowledge proof of authorization
    pub fn with_auth_proof(mut self, proof: ZeroKnowledgeProof) -> Self {
        self.auth_proof = Some(proof);
        self
    }

    /// Add zero-knowledge identity proof
    pub fn with_identity_proof(mut self, proof: ZeroKnowledgeProof) -> Self {
        self.headers.zk_identity_proof = Some(proof);
        self
    }

    /// Set mesh routing preferences
    pub fn with_mesh_routing(mut self, preferred_peers: Vec<String>, bypass_isp: bool) -> Self {
        self.headers.preferred_peers = Some(preferred_peers);
        self.headers.isp_bypass = Some(bypass_isp);
        self
    }

    /// Set geographic restrictions
    pub fn with_geo_restrictions(mut self, restrictions: Vec<String>) -> Self {
        self.headers.geo_restrictions = Some(restrictions);
        self
    }

    /// Set custom header
    pub fn with_custom_header(mut self, name: String, value: String) -> Self {
        self.headers.custom.insert(name, value);
        self
    }

    /// Get request size in bytes
    pub fn size(&self) -> usize {
        self.body.len() + self.uri.len() + 
        serde_json::to_string(&self.headers).unwrap_or_default().len()
    }

    /// Check if request is safe (doesn't modify state)
    pub fn is_safe(&self) -> bool {
        self.method.is_safe()
    }

    /// Check if request is idempotent
    pub fn is_idempotent(&self) -> bool {
        self.method.is_idempotent()
    }

    /// Get expected response content type
    pub fn expected_response_type(&self) -> Option<String> {
        self.headers.accept.clone()
    }

    /// Check if request requires special permissions
    pub fn requires_special_permissions(&self) -> bool {
        self.method.requires_special_permissions() || 
        self.headers.access_requirements.is_some() ||
        self.headers.required_reputation.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let economic_model = EconomicModel::new();
        let request = ZhtpRequest::new(
            ZhtpMethod::Post,
            "/test".to_string(),
            b"test data".to_vec(),
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();

        assert_eq!(request.method, ZhtpMethod::Post);
        assert_eq!(request.uri, "/test");
        assert_eq!(request.version, ZHTP_VERSION);
        assert!(request.headers.dao_fee >= MIN_DAO_FEE);
    }

    #[test]
    fn test_convenience_constructors() {
        let get_req = ZhtpRequest::get("/api/test".to_string(), None).unwrap();
        assert_eq!(get_req.method, ZhtpMethod::Get);
        assert!(get_req.body.is_empty());

        let post_req = ZhtpRequest::post(
            "/api/create".to_string(),
            b"test data".to_vec(),
            "text/plain".to_string(),
            None,
        ).unwrap();
        assert_eq!(post_req.method, ZhtpMethod::Post);
        assert_eq!(post_req.body, b"test data");
        assert_eq!(post_req.headers.content_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_dao_fee_validation() {
        let economic_model = EconomicModel::new();
        let request = ZhtpRequest::new(
            ZhtpMethod::Post,
            "/test".to_string(),
            b"test content".to_vec(),
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();

        assert!(request.validate_dao_fee(&economic_model).unwrap());
    }

    #[test]
    fn test_size_validation() {
        let economic_model = EconomicModel::new();
        
        // Small request should pass
        let small_request = ZhtpRequest::new(
            ZhtpMethod::Get,
            "/test".to_string(),
            vec![0u8; 1024], // 1KB
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();
        assert!(small_request.validate_size_limits().unwrap());

        // Large request should fail
        let large_request = ZhtpRequest::new(
            ZhtpMethod::Post,
            "/test".to_string(),
            vec![0u8; crate::types::MAX_REQUEST_SIZE + 1], // Too large
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();
        assert!(!large_request.validate_size_limits().unwrap());
    }

    #[test]
    fn test_timestamp_validation() {
        let economic_model = EconomicModel::new();
        let request = ZhtpRequest::new(
            ZhtpMethod::Get,
            "/test".to_string(),
            vec![],
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();

        // Current timestamp should be valid
        assert!(request.validate_timestamp(300).unwrap()); // 5 minutes max age
    }

    #[test]
    fn test_request_value_calculation() {
        use crate::economics::utils::calculate_request_value;
        
        assert_eq!(
            calculate_request_value(&ZhtpMethod::Get, &[], "/test"),
            100 + ("/test".len() as u64 / 10)
        );
        
        assert_eq!(
            calculate_request_value(&ZhtpMethod::Post, b"data", "/test"),
            4 * 10 // 4 bytes * 10 tokens per byte
        );
    }

    #[test]
    fn test_request_properties() {
        let economic_model = EconomicModel::new();
        
        let get_req = ZhtpRequest::new(
            ZhtpMethod::Get,
            "/test".to_string(),
            vec![],
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();
        assert!(get_req.is_safe());
        assert!(get_req.is_idempotent());
        assert!(!get_req.requires_special_permissions());

        let post_req = ZhtpRequest::new(
            ZhtpMethod::Post,
            "/test".to_string(),
            vec![1, 2, 3],
            None,
            Priority::Normal,
            &economic_model,
        ).unwrap();
        assert!(!post_req.is_safe());
        assert!(!post_req.is_idempotent());
        assert!(post_req.requires_special_permissions());
    }
}
