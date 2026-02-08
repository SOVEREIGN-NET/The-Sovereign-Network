//! Zero-Knowledge Proof HTTP Handler
//!
//! Implements 2 endpoints for ZK proof generation and verification.
//! Supports age verification, citizenship verification, and other privacy-preserving proofs.
//!
//! ## IMPORTANT SECURITY NOTICE
//!
//! **Current ZK Proof Implementation is NOT True Zero-Knowledge**
//!
//! The current implementation uses ZkRangeProof which stores plaintext values in proofs
//! and performs plaintext comparison during verification. This is a SIMULATION of zero-knowledge
//! proofs, not cryptographically sound zero-knowledge proofs.
//!
//! **Privacy Limitations:**
//! - Proofs contain plaintext credential values
//! - Verifiers can extract actual ages, not just range membership
//! - Not suitable for production privacy-critical applications
//!
//! **Roadmap:**
//! - Short-term: Use for testing and demonstration only
//! - Medium-term: Migrate to Bulletproofs for range proofs
//! - Long-term: Full Plonky2 circuit implementation
//!
//! For production use, credentials must be verified before proof generation.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_identity::IdentityManager;
use lib_proofs::ZkRangeProof;

use crate::session_manager::SessionManager;
use crate::api::middleware::RateLimiter;

/// Request to generate a zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProofRequest {
    /// Identity ID requesting the proof
    pub identity_id: String,
    /// Type of proof to generate
    pub proof_type: String,
    /// Credential data for proof generation
    pub credential_data: CredentialData,
}

/// Credential data for proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    /// Age (for age-based proofs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<u64>,
    /// Jurisdiction (for citizenship proofs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// Citizenship status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_verified_citizen: Option<bool>,
}

/// Response from proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateProofResponse {
    /// Status of the operation
    pub status: String,
    /// Generated proof
    pub proof: ProofData,
    /// Unix timestamp when proof expires
    pub valid_until: u64,
}

/// Proof data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    /// Proof bytes (base64-encoded)
    pub proof_data: String,
    /// Public inputs for verification
    pub public_inputs: Vec<String>,
    /// Type of proof
    pub proof_type: String,
    /// Unix timestamp when proof was generated
    pub generated_at: u64,
    /// Unix timestamp when proof expires
    pub valid_until: u64,
}

/// Request to verify a zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofRequest {
    /// Proof to verify
    pub proof: ProofData,
}

/// Response from proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyProofResponse {
    /// Status of the operation
    pub status: String,
    /// Whether the proof is valid
    pub valid: bool,
    /// Claim being proven
    pub claim: String,
    /// Unix timestamp of verification
    pub verified_at: u64,
}

/// ZKP HTTP Handler
pub struct ZkpHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
}

impl ZkpHandler {
    /// Create a new ZKP handler
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        session_manager: Arc<SessionManager>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            identity_manager,
            session_manager,
            rate_limiter,
        }
    }

    /// Handle: POST /api/v1/zkp/generate
    async fn handle_generate_proof(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_generate_proof(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.rate_limiter.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/zkp/verify
    async fn handle_verify_proof(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_verify_proof(
            &request.body,
            self.rate_limiter.clone(),
            &request,
        )
        .await
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ZkpHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        match (request.method.as_str(), request.uri.as_str()) {
            ("POST", "/api/v1/zkp/generate") => self.handle_generate_proof(request).await,
            ("POST", "/api/v1/zkp/verify") => self.handle_verify_proof(request).await,
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("ZKP endpoint not found: {} {}", request.method, request.uri),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/zkp")
    }

    fn priority(&self) -> u32 {
        100
    }
}

/// Handle proof generation
async fn handle_generate_proof(
    body: &[u8],
    identity_manager: Arc<RwLock<IdentityManager>>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Security: Validate request size
    const MAX_REQUEST_SIZE: usize = 10_000; // 10KB
    if body.len() > MAX_REQUEST_SIZE {
        return Err(anyhow::anyhow!("Request too large"));
    }

    // Security: Extract client IP for rate limiting
    let client_ip = extract_client_ip(request);

    // Security: Rate limit proof generation (10 requests per hour per IP)
    if let Err(response) = rate_limiter.check_rate_limit_aggressive(&client_ip, 10, 3600).await {
        return Ok(response);
    }

    // Parse request
    let req: GenerateProofRequest = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("Invalid request format"))?;

    // Security: Validate proof_type against allowlist
    const VALID_PROOF_TYPES: &[&str] = &[
        "age_over_18", "age_range",
        "citizenship_verified", "jurisdiction_membership"
    ];
    if !VALID_PROOF_TYPES.contains(&req.proof_type.as_str()) {
        return Err(anyhow::anyhow!("Invalid proof type"));
    }

    // Security: Extract and validate session token from Authorization header
    let session_token = request
        .headers
        .get("Authorization")
        .and_then(|auth| auth.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid Authorization header"))?;

    // Security: Validate session and get authenticated identity
    let user_agent = extract_user_agent(request);
    let session_token_obj = session_manager
        .validate_session(&session_token, &client_ip, &user_agent)
        .await
        .map_err(|e| anyhow::anyhow!("Invalid or expired session: {}", e))?;

    // Convert request identity_id string to IdentityId (Hash)
    let identity_id_bytes = hex::decode(&req.identity_id)
        .map_err(|_| anyhow::anyhow!("Invalid identity_id format"))?;
    if identity_id_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid identity_id length"));
    }
    let mut id_array = [0u8; 32];
    id_array.copy_from_slice(&identity_id_bytes);
    let identity_id = lib_crypto::Hash::from_bytes(&id_array);

    // Security: Verify authenticated identity matches requested identity
    if session_token_obj.identity_id != identity_id {
        return Err(anyhow::anyhow!("Identity mismatch - cannot generate proofs for other identities"));
    }

    // Verify identity exists and is active
    let manager = identity_manager.read().await;
    let _identity = manager
        .get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;

    // TODO: Add credential verification here
    // For production, verify that identity actually possesses the claimed credentials
    // Example: identity.get_credential("age")?.verify_signature()?;

    drop(manager);

    // Get current timestamp for proof generation and expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let valid_until = now + 86400; // 24 hours expiration

    // Generate proof based on type
    let (proof, _claim) = match req.proof_type.as_str() {
        "age_over_18" => {
            let age = req.credential_data.age
                .ok_or_else(|| anyhow::anyhow!("Missing age in credential_data"))?;

            // Generate range proof: age >= 18
            let range_proof = ZkRangeProof::generate_simple(age, 18, 150)?;

            // Convert to proof data
            let proof_bytes = serde_json::to_vec(&range_proof)?;

            // Security: Use opaque commitment instead of revealing range bounds
            let commitment = lib_crypto::hashing::hash_blake3(&[&age.to_le_bytes()[..], &identity_id.0[..]].concat());

            let proof_data = ProofData {
                proof_data: general_purpose::STANDARD.encode(&proof_bytes),
                public_inputs: vec![hex::encode(&commitment[..16])], // Opaque commitment, not range bounds
                proof_type: "age_over_18".to_string(),
                generated_at: now,
                valid_until,
            };

            (proof_data, "age_over_18")
        },
        "age_range" => {
            let age = req.credential_data.age
                .ok_or_else(|| anyhow::anyhow!("Missing age in credential_data"))?;

            // For alpha: support common ranges (18-25, 26-40, 41-65, 66+)
            let (min, max) = if age >= 18 && age <= 25 {
                (18, 25)
            } else if age >= 26 && age <= 40 {
                (26, 40)
            } else if age >= 41 && age <= 65 {
                (41, 65)
            } else {
                (66, 150)
            };

            let range_proof = ZkRangeProof::generate_simple(age, min, max)?;

            let proof_bytes = serde_json::to_vec(&range_proof)?;

            // Security: Use opaque bracket identifier instead of revealing bounds
            let bracket_hash = lib_crypto::hashing::hash_blake3(
                &[&min.to_le_bytes()[..], &max.to_le_bytes()[..]].concat()
            );

            let proof_data = ProofData {
                proof_data: general_purpose::STANDARD.encode(&proof_bytes),
                public_inputs: vec![hex::encode(&bracket_hash[..16])], // Opaque bracket ID
                proof_type: "age_range".to_string(),
                generated_at: now,
                valid_until,
            };

            (proof_data, "age_range")
        },
        "citizenship_verified" => {
            let is_verified = req.credential_data.is_verified_citizen
                .ok_or_else(|| anyhow::anyhow!("Missing is_verified_citizen in credential_data"))?;

            if !is_verified {
                return Err(anyhow::anyhow!("Cannot generate citizenship proof for unverified citizen"));
            }

            // Generate a simple proof (value=1 means verified, range [1,1])
            let range_proof = ZkRangeProof::generate_simple(1, 1, 1)?;

            let proof_bytes = serde_json::to_vec(&range_proof)?;

            // Security: Use opaque commitment
            let commitment = lib_crypto::hashing::hash_blake3(&identity_id.0);

            let proof_data = ProofData {
                proof_data: general_purpose::STANDARD.encode(&proof_bytes),
                public_inputs: vec![hex::encode(&commitment[..16])],
                proof_type: "citizenship_verified".to_string(),
                generated_at: now,
                valid_until,
            };

            (proof_data, "citizenship_verified")
        },
        "jurisdiction_membership" => {
            let jurisdiction = req.credential_data.jurisdiction
                .ok_or_else(|| anyhow::anyhow!("Missing jurisdiction in credential_data"))?;

            // Security: Use salted hash with identity-specific salt to prevent rainbow table attacks
            let salt = &identity_id.0; // Use identity as salt
            let salted_data = [jurisdiction.as_bytes(), salt].concat();
            let jurisdiction_hash = lib_crypto::hashing::hash_blake3(&salted_data);

            let jurisdiction_value = u64::from_le_bytes([
                jurisdiction_hash[0], jurisdiction_hash[1],
                jurisdiction_hash[2], jurisdiction_hash[3],
                jurisdiction_hash[4], jurisdiction_hash[5],
                jurisdiction_hash[6], jurisdiction_hash[7],
            ]);

            // Generate proof that user belongs to this jurisdiction
            let range_proof = ZkRangeProof::generate_simple(jurisdiction_value, jurisdiction_value, jurisdiction_value)?;

            let proof_bytes = serde_json::to_vec(&range_proof)?;
            let proof_data = ProofData {
                proof_data: general_purpose::STANDARD.encode(&proof_bytes),
                public_inputs: vec![hex::encode(&jurisdiction_hash[..16])], // Salted hash prevents reverse lookup
                proof_type: "jurisdiction_membership".to_string(),
                generated_at: now,
                valid_until,
            };

            (proof_data, "jurisdiction_membership")
        },
        _ => {
            return Err(anyhow::anyhow!("Unsupported proof type: {}", req.proof_type));
        }
    };

    let response = GenerateProofResponse {
        status: "success".to_string(),
        proof,
        valid_until,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

/// Handle proof verification
async fn handle_verify_proof(
    body: &[u8],
    rate_limiter: Arc<RateLimiter>,
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Security: Validate request size
    const MAX_REQUEST_SIZE: usize = 100_000; // 100KB (proofs can be larger)
    if body.len() > MAX_REQUEST_SIZE {
        return Err(anyhow::anyhow!("Request too large"));
    }

    // Security: Extract client IP for rate limiting
    let client_ip = extract_client_ip(request);

    // Security: Rate limit proof verification (100 requests per 15 min)
    // Verification is public but rate-limited to prevent abuse
    if let Err(response) = rate_limiter.check_rate_limit(&client_ip).await {
        return Ok(response);
    }

    // Parse request
    let req: VerifyProofRequest = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("Invalid request format"))?;

    // Security: Validate proof expiration
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if now > req.proof.valid_until {
        return Ok(ZhtpResponse::error(
            ZhtpStatus::BadRequest,
            "Proof has expired".to_string(),
        ));
    }

    // Security: Validate proof size before decoding
    const MAX_PROOF_SIZE: usize = 1024 * 1024; // 1MB
    if req.proof.proof_data.len() > MAX_PROOF_SIZE {
        return Err(anyhow::anyhow!("Proof data too large"));
    }

    // Decode proof data
    let proof_bytes = base64::decode(&req.proof.proof_data)
        .map_err(|_| anyhow::anyhow!("Invalid proof_data encoding"))?;

    if proof_bytes.len() > MAX_PROOF_SIZE {
        return Err(anyhow::anyhow!("Decoded proof too large"));
    }

    // Verify based on proof type
    let (valid, claim) = match req.proof.proof_type.as_str() {
        "age_over_18" | "age_range" | "citizenship_verified" | "jurisdiction_membership" => {
            // Deserialize range proof
            let range_proof: ZkRangeProof = serde_json::from_slice(&proof_bytes)
                .map_err(|_| anyhow::anyhow!("Invalid proof format"))?;

            // Verify the proof
            let is_valid = range_proof.verify()?;

            (is_valid, req.proof.proof_type.clone())
        },
        _ => {
            return Err(anyhow::anyhow!("Invalid proof type"));
        }
    };

    let verified_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let response = VerifyProofResponse {
        status: "success".to_string(),
        valid,
        claim,
        verified_at,
    };

    Ok(ZhtpResponse::success(
        serde_json::to_vec(&response)?,
        None,
    ))
}

// Helper functions

fn extract_client_ip(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("X-Real-IP")
        .or_else(|| {
            request.headers.get("X-Forwarded-For").and_then(|f| {
                f.split(',').next().map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_agent(request: &ZhtpRequest) -> String {
    request
        .headers
        .get("User-Agent")
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_proof_request_parsing() {
        let json = r#"{
            "identity_id": "0000000000000000000000000000000000000000000000000000000000000001",
            "proof_type": "age_over_18",
            "credential_data": {
                "age": 25
            }
        }"#;

        let req: GenerateProofRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.proof_type, "age_over_18");
        assert_eq!(req.credential_data.age, Some(25));
    }

    #[test]
    fn test_verify_proof_request_parsing() {
        let json = r#"{
            "proof": {
                "proof_data": "eyJwcm9vZiI6IltdIn0=",
                "public_inputs": ["a1b2c3d4"],
                "proof_type": "age_over_18",
                "generated_at": 1234567890,
                "valid_until": 1234654290
            }
        }"#;

        let req: VerifyProofRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.proof.proof_type, "age_over_18");
        assert_eq!(req.proof.public_inputs.len(), 1);
        assert_eq!(req.proof.generated_at, 1234567890);
        assert_eq!(req.proof.valid_until, 1234654290);
    }
}
