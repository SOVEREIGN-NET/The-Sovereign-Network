//! ZHTP Response Implementation
//! 
//! Complete ZHTP response structure with zero-knowledge proof validation,
//! content integrity checks, and Web4 protocol extensions.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{ZhtpStatus, ZhtpHeaders, ZHTP_VERSION};
use lib_identity::IdentityId;
use lib_proofs::ZeroKnowledgeProof;
use crate::storage_stub::ContentHash;

/// ZHTP response with Web4 extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZhtpResponse {
    /// Protocol version
    pub version: String,
    /// Response status
    pub status: ZhtpStatus,
    /// Status message
    pub status_message: String,
    /// Response headers
    pub headers: ZhtpHeaders,
    /// Response body
    pub body: Vec<u8>,
    /// Response timestamp
    pub timestamp: u64,
    /// Server identity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<IdentityId>,
    /// Zero-knowledge proof of response validity
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_proof: Option<ZeroKnowledgeProof>,
}

impl ZhtpResponse {
    /// Create a successful ZHTP response
    pub fn success(body: Vec<u8>, server: Option<IdentityId>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let headers = ZhtpHeaders::new()
            .with_content_type("application/octet-stream".to_string())
            .with_content_length(body.len() as u64)
            .with_cache_control("max-age=3600".to_string())
            .with_privacy_level(100)
            .with_encryption("CRYSTALS-Kyber".to_string());
        
        ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status: ZhtpStatus::Ok,
            status_message: ZhtpStatus::Ok.reason_phrase().to_string(),
            headers,
            body,
            timestamp,
            server,
            validity_proof: None,
        }
    }

    /// Create a successful response with specific content type
    pub fn success_with_content_type(
        body: Vec<u8>,
        content_type: String,
        server: Option<IdentityId>,
    ) -> Self {
        let mut response = Self::success(body, server);
        response.headers = response.headers.with_content_type(content_type);
        response
    }

    /// Create a JSON response
    pub fn json<T: serde::Serialize>(
        data: &T,
        server: Option<IdentityId>,
    ) -> anyhow::Result<Self> {
        let body = serde_json::to_vec(data)?;
        Ok(Self::success_with_content_type(
            body,
            "application/json".to_string(),
            server,
        ))
    }

    /// Create a text response
    pub fn text(text: String, server: Option<IdentityId>) -> Self {
        Self::success_with_content_type(
            text.into_bytes(),
            "text/plain; charset=utf-8".to_string(),
            server,
        )
    }

    /// Create an HTML response
    pub fn html(html: String, server: Option<IdentityId>) -> Self {
        Self::success_with_content_type(
            html.into_bytes(),
            "text/html; charset=utf-8".to_string(),
            server,
        )
    }

    /// Create a binary response
    pub fn binary(data: Vec<u8>, content_type: String, server: Option<IdentityId>) -> Self {
        Self::success_with_content_type(data, content_type, server)
    }

    /// Create a created response (201)
    pub fn created(body: Vec<u8>, location: String, server: Option<IdentityId>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let headers = ZhtpHeaders::new()
            .with_content_type("application/octet-stream".to_string())
            .with_content_length(body.len() as u64)
            .with_custom_header("location".to_string(), location);
        
        ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status: ZhtpStatus::Created,
            status_message: ZhtpStatus::Created.reason_phrase().to_string(),
            headers,
            body,
            timestamp,
            server,
            validity_proof: None,
        }
    }

    /// Create an accepted response (202)
    pub fn accepted(message: String, server: Option<IdentityId>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let headers = ZhtpHeaders::new()
            .with_content_type("text/plain".to_string())
            .with_content_length(message.len() as u64);
        
        ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status: ZhtpStatus::Accepted,
            status_message: ZhtpStatus::Accepted.reason_phrase().to_string(),
            headers,
            body: message.into_bytes(),
            timestamp,
            server,
            validity_proof: None,
        }
    }

    /// Create a no content response (204)
    pub fn no_content(server: Option<IdentityId>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let headers = ZhtpHeaders::new().with_content_length(0);
        
        ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status: ZhtpStatus::NoContent,
            status_message: ZhtpStatus::NoContent.reason_phrase().to_string(),
            headers,
            body: vec![],
            timestamp,
            server,
            validity_proof: None,
        }
    }

    /// Create an error ZHTP response
    pub fn error(status: ZhtpStatus, message: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let headers = ZhtpHeaders::new()
            .with_content_type("text/plain; charset=utf-8".to_string())
            .with_content_length(message.len() as u64)
            .with_privacy_level(100);
        
        ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status,
            status_message: message.clone(),
            headers,
            body: message.into_bytes(),
            timestamp,
            server: None,
            validity_proof: None,
        }
    }

    /// Create an error response with JSON details
    pub fn error_json<T: serde::Serialize>(
        status: ZhtpStatus,
        error_data: &T,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let body = serde_json::to_vec(error_data)?;
        let headers = ZhtpHeaders::new()
            .with_content_type("application/json".to_string())
            .with_content_length(body.len() as u64);
        
        Ok(ZhtpResponse {
            version: ZHTP_VERSION.to_string(),
            status,
            status_message: status.reason_phrase().to_string(),
            headers,
            body,
            timestamp,
            server: None,
            validity_proof: None,
        })
    }

    /// Create common error responses
    pub fn bad_request(message: String) -> Self {
        Self::error(ZhtpStatus::BadRequest, message)
    }

    pub fn unauthorized(message: String) -> Self {
        Self::error(ZhtpStatus::Unauthorized, message)
    }

    pub fn forbidden(message: String) -> Self {
        Self::error(ZhtpStatus::Forbidden, message)
    }

    pub fn not_found(message: String) -> Self {
        Self::error(ZhtpStatus::NotFound, message)
    }

    pub fn method_not_allowed(message: String) -> Self {
        Self::error(ZhtpStatus::MethodNotAllowed, message)
    }

    pub fn internal_server_error(message: String) -> Self {
        Self::error(ZhtpStatus::InternalServerError, message)
    }

    pub fn not_implemented(message: String) -> Self {
        Self::error(ZhtpStatus::NotImplemented, message)
    }

    pub fn service_unavailable(message: String) -> Self {
        Self::error(ZhtpStatus::ServiceUnavailable, message)
    }

    /// Create Web4-specific error responses
    pub fn zk_proof_invalid(message: String) -> Self {
        Self::error(ZhtpStatus::ZkProofInvalid, message)
    }

    pub fn dao_fee_required(message: String) -> Self {
        Self::error(ZhtpStatus::DaoFeeRequired, message)
    }

    pub fn dao_fee_insufficient(required: u64, provided: u64) -> Self {
        Self::error(
            ZhtpStatus::DaoFeeInsufficient,
            format!("DAO fee insufficient. Required: {} SOV, Provided: {} SOV", required, provided),
        )
    }

    pub fn mesh_unavailable(message: String) -> Self {
        Self::error(ZhtpStatus::MeshUnavailable, message)
    }

    pub fn post_quantum_required(message: String) -> Self {
        Self::error(ZhtpStatus::PostQuantumRequired, message)
    }

    /// Add zero-knowledge proof of response validity
    pub fn with_validity_proof(mut self, proof: ZeroKnowledgeProof) -> Self {
        self.validity_proof = Some(proof);
        self
    }

    /// Add content hash for integrity verification
    pub fn with_content_hash(mut self, hash: ContentHash) -> Self {
        self.headers.content_hash = Some(hash);
        self
    }

    /// Add zero-knowledge proof to headers
    pub fn with_zk_proof(mut self, proof: ZeroKnowledgeProof) -> Self {
        self.headers.zk_proof = Some(proof);
        self
    }

    /// Set cache control headers
    pub fn with_cache_control(mut self, cache_control: String) -> Self {
        self.headers = self.headers.with_cache_control(cache_control);
        self
    }

    /// Set ETag for content versioning
    pub fn with_etag(mut self, etag: String) -> Self {
        self.headers.etag = Some(etag);
        self
    }

    /// Set last modified timestamp
    pub fn with_last_modified(mut self, timestamp: u64) -> Self {
        self.headers.last_modified = Some(timestamp);
        self
    }

    /// Add custom header
    pub fn with_custom_header(mut self, name: String, value: String) -> Self {
        self.headers.custom.insert(name, value);
        self
    }

    /// Set mesh routing information
    pub fn with_mesh_info(mut self, path: Vec<String>, quality: f64) -> Self {
        self.headers.mesh_path = Some(path);
        self.headers.mesh_quality = Some(quality);
        self
    }

    /// Check if response indicates success
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Check if response indicates client error
    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }

    /// Check if response indicates server error
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// Check if response indicates Web4-specific error
    pub fn is_web4_error(&self) -> bool {
        self.status.is_web4_error()
    }

    /// Get response size in bytes
    pub fn size(&self) -> usize {
        self.body.len() + 
        serde_json::to_string(&self.headers).unwrap_or_default().len() +
        self.status_message.len()
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&String> {
        self.headers.content_type.as_ref()
    }

    /// Get content length
    pub fn content_length(&self) -> Option<u64> {
        self.headers.content_length
    }

    /// Check if response has zero-knowledge privacy
    pub fn has_zero_knowledge_privacy(&self) -> bool {
        self.headers.has_zero_knowledge_privacy()
    }

    /// Check if response uses post-quantum cryptography
    pub fn has_post_quantum_crypto(&self) -> bool {
        self.headers.has_post_quantum_crypto()
    }

    /// Convert response body to string (if text-based)
    pub fn body_as_string(&self) -> anyhow::Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| anyhow::anyhow!("Response body is not valid UTF-8: {}", e))
    }

    /// Parse response body as JSON
    pub fn body_as_json<T: for<'de> serde::Deserialize<'de>>(&self) -> anyhow::Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| anyhow::anyhow!("Failed to parse response body as JSON: {}", e))
    }

    /// Validate response integrity
    pub fn validate_integrity(&self) -> anyhow::Result<bool> {
        // Check content length matches body size
        if let Some(declared_length) = self.headers.content_length {
            if declared_length != self.body.len() as u64 {
                tracing::warn!(
                    "Response content length mismatch: declared {}, actual {}",
                    declared_length,
                    self.body.len()
                );
                return Ok(false);
            }
        }

        // Validate content hash if present
        if let Some(content_hash) = &self.headers.content_hash {
            let calculated_hash = lib_crypto::hash_blake3(&self.body).to_vec();
            if calculated_hash != *content_hash {
                tracing::warn!("Response content hash mismatch");
                return Ok(false);
            }
        }

        // Validate timestamp is not too far in the future
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        if self.timestamp > now + 300 { // Allow 5 minutes clock skew
            tracing::warn!(
                "Response timestamp in future: {} > {}",
                self.timestamp,
                now
            );
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_response() {
        let response = ZhtpResponse::success(b"test data".to_vec(), None);
        assert_eq!(response.status, ZhtpStatus::Ok);
        assert_eq!(response.body, b"test data");
        assert!(response.is_success());
    }

    #[test]
    fn test_error_responses() {
        let bad_request = ZhtpResponse::bad_request("Invalid input".to_string());
        assert_eq!(bad_request.status, ZhtpStatus::BadRequest);
        assert!(bad_request.is_client_error());

        let server_error = ZhtpResponse::internal_server_error("Database error".to_string());
        assert_eq!(server_error.status, ZhtpStatus::InternalServerError);
        assert!(server_error.is_server_error());
    }

    #[test]
    fn test_web4_error_responses() {
        let zk_error = ZhtpResponse::zk_proof_invalid("Invalid proof".to_string());
        assert_eq!(zk_error.status, ZhtpStatus::ZkProofInvalid);
        assert!(zk_error.is_web4_error());

        let dao_error = ZhtpResponse::dao_fee_insufficient(100, 50);
        assert_eq!(dao_error.status, ZhtpStatus::DaoFeeInsufficient);
        assert!(dao_error.is_web4_error());
    }

    #[test]
    fn test_json_response() {
        let data = serde_json::json!({
            "message": "Hello, World!",
            "status": "success"
        });
        
        let response = ZhtpResponse::json(&data, None).unwrap();
        assert_eq!(response.content_type(), Some(&"application/json".to_string()));
        
        let parsed: serde_json::Value = response.body_as_json().unwrap();
        assert_eq!(parsed["message"], "Hello, World!");
    }

    #[test]
    fn test_convenience_responses() {
        let text_response = ZhtpResponse::text("Hello".to_string(), None);
        assert_eq!(text_response.content_type(), Some(&"text/plain; charset=utf-8".to_string()));
        assert_eq!(text_response.body_as_string().unwrap(), "Hello");

        let html_response = ZhtpResponse::html("<h1>Title</h1>".to_string(), None);
        assert_eq!(html_response.content_type(), Some(&"text/html; charset=utf-8".to_string()));

        let no_content = ZhtpResponse::no_content(None);
        assert_eq!(no_content.status, ZhtpStatus::NoContent);
        assert!(no_content.body.is_empty());
    }

    #[test]
    fn test_response_validation() {
        let mut response = ZhtpResponse::success(b"test".to_vec(), None);
        assert!(response.validate_integrity().unwrap());

        // Test content length mismatch
        response.headers.content_length = Some(100);
        assert!(!response.validate_integrity().unwrap());
    }

    #[test]
    fn test_response_properties() {
        let response = ZhtpResponse::success(b"test data".to_vec(), None);
        assert!(response.has_zero_knowledge_privacy());
        assert!(response.has_post_quantum_crypto());
        assert_eq!(response.size(), response.body.len() + response.status_message.len() + 
                   serde_json::to_string(&response.headers).unwrap().len());
    }

    #[test]
    fn test_response_builder_pattern() {
        let response = ZhtpResponse::success(b"data".to_vec(), None)
            .with_cache_control("no-cache".to_string())
            .with_etag("\"123456\"".to_string())
            .with_custom_header("x-custom".to_string(), "value".to_string());

        assert_eq!(response.headers.cache_control, Some("no-cache".to_string()));
        assert_eq!(response.headers.etag, Some("\"123456\"".to_string()));
        assert_eq!(response.headers.custom.get("x-custom"), Some(&"value".to_string()));
    }
}
