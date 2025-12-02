//! Zero-Knowledge Proof HTTP Handler
//!
//! Implements 2 endpoints for ZK proof generation and verification.
//! Supports age verification, citizenship verification, and other privacy-preserving proofs.

use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;

use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_identity::IdentityManager;
use lib_proofs::{ZkRangeProof, ZkProof};

use crate::session_manager::SessionManager;

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
}

impl ZkpHandler {
    /// Create a new ZKP handler
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        session_manager: Arc<SessionManager>,
    ) -> Self {
        Self {
            identity_manager,
            session_manager,
        }
    }

    /// Handle: POST /api/v1/zkp/generate
    async fn handle_generate_proof(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_generate_proof(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle: POST /api/v1/zkp/verify
    async fn handle_verify_proof(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        handle_verify_proof(
            &request.body,
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
    request: &ZhtpRequest,
) -> Result<ZhtpResponse> {
    // Parse request
    let req: GenerateProofRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Convert identity_id string to IdentityId (Hash)
    let identity_id_bytes = hex::decode(&req.identity_id)
        .map_err(|e| anyhow::anyhow!("Invalid identity_id format: {}", e))?;
    if identity_id_bytes.len() != 32 {
        return Err(anyhow::anyhow!("Invalid identity_id length"));
    }
    let mut id_array = [0u8; 32];
    id_array.copy_from_slice(&identity_id_bytes);
    let identity_id = lib_crypto::Hash::from_bytes(&id_array);

    // Verify identity exists
    let manager = identity_manager.read().await;
    let _identity = manager
        .get_identity(&identity_id)
        .ok_or_else(|| anyhow::anyhow!("Identity not found"))?;
    drop(manager);

    // Generate proof based on type
    let (proof, claim) = match req.proof_type.as_str() {
        "age_over_18" => {
            let age = req.credential_data.age
                .ok_or_else(|| anyhow::anyhow!("Missing age in credential_data"))?;

            // Generate range proof: age >= 18
            let range_proof = ZkRangeProof::generate_simple(age, 18, 150)?;

            // Convert to proof data
            let proof_bytes = serde_json::to_vec(&range_proof)?;
            let proof_data = ProofData {
                proof_data: base64::encode(&proof_bytes),
                public_inputs: vec![
                    range_proof.min_value.to_string(),
                    range_proof.max_value.to_string(),
                ],
                proof_type: "age_over_18".to_string(),
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
            let proof_data = ProofData {
                proof_data: base64::encode(&proof_bytes),
                public_inputs: vec![
                    range_proof.min_value.to_string(),
                    range_proof.max_value.to_string(),
                ],
                proof_type: "age_range".to_string(),
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
            let proof_data = ProofData {
                proof_data: base64::encode(&proof_bytes),
                public_inputs: vec!["verified".to_string()],
                proof_type: "citizenship_verified".to_string(),
            };

            (proof_data, "citizenship_verified")
        },
        "jurisdiction_membership" => {
            let jurisdiction = req.credential_data.jurisdiction
                .ok_or_else(|| anyhow::anyhow!("Missing jurisdiction in credential_data"))?;

            // Hash the jurisdiction to a proof value
            let jurisdiction_hash = lib_crypto::hashing::hash_blake3(jurisdiction.as_bytes());
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
                proof_data: base64::encode(&proof_bytes),
                public_inputs: vec![hex::encode(&jurisdiction_hash[..8])],
                proof_type: "jurisdiction_membership".to_string(),
            };

            (proof_data, "jurisdiction_membership")
        },
        _ => {
            return Err(anyhow::anyhow!("Unsupported proof type: {}", req.proof_type));
        }
    };

    // Set expiration (24 hours from now)
    let valid_until = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() + 86400;

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
) -> Result<ZhtpResponse> {
    // Parse request
    let req: VerifyProofRequest = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!("Invalid request body: {}", e)
    })?;

    // Decode proof data
    let proof_bytes = base64::decode(&req.proof.proof_data)
        .map_err(|e| anyhow::anyhow!("Invalid proof_data encoding: {}", e))?;

    // Verify based on proof type
    let (valid, claim) = match req.proof.proof_type.as_str() {
        "age_over_18" | "age_range" | "citizenship_verified" | "jurisdiction_membership" => {
            // Deserialize range proof
            let range_proof: ZkRangeProof = serde_json::from_slice(&proof_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid proof format: {}", e))?;

            // Verify the proof
            let is_valid = range_proof.verify()?;

            (is_valid, req.proof.proof_type.clone())
        },
        _ => {
            return Err(anyhow::anyhow!("Unsupported proof type: {}", req.proof.proof_type));
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
                "public_inputs": ["18", "150"],
                "proof_type": "age_over_18"
            }
        }"#;

        let req: VerifyProofRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.proof.proof_type, "age_over_18");
        assert_eq!(req.proof.public_inputs.len(), 2);
    }
}
