//! Crypto Utilities Handler
//!
//! Provides cryptographic utility endpoints for developers:
//! - Sign arbitrary messages with identity keys
//! - Verify signatures
//! - Generate new keypairs
//!
//! These are convenience APIs matching the old ZHTP implementation.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use base64::Engine;

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

// Crypto imports
use lib_crypto::KeyPair;

// Identity imports
use lib_identity::IdentityManager;

/// Crypto utilities handler for signing, verification, and key generation
pub struct CryptoHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl CryptoHandler {
    pub fn new(identity_manager: Arc<RwLock<IdentityManager>>) -> Self {
        Self { identity_manager }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for CryptoHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Crypto handler: {} {}", request.method, request.uri);

        let response = match (request.method, request.uri.as_str()) {
            // POST /api/v1/crypto/sign_message
            (ZhtpMethod::Post, "/api/v1/crypto/sign_message") => {
                self.handle_sign_message(request).await
            }
            // POST /api/v1/crypto/verify_signature
            (ZhtpMethod::Post, "/api/v1/crypto/verify_signature") => {
                self.handle_verify_signature(request).await
            }
            // POST /api/v1/crypto/generate_keypair
            (ZhtpMethod::Post, "/api/v1/crypto/generate_keypair") => {
                self.handle_generate_keypair(request).await
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Crypto endpoint not found".to_string(),
                ))
            }
        };

        match response {
            Ok(mut resp) => {
                // Add ZHTP headers
                resp.headers.set("X-Handler", "Crypto".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Crypto handler error: {}", e);
                Ok(create_error_response(
                    ZhtpStatus::InternalServerError,
                    format!("Crypto error: {}", e),
                ))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/crypto/")
    }

    fn priority(&self) -> u32 {
        100
    }
}

// Request/Response structures
#[derive(Deserialize)]
struct SignMessageRequest {
    identity_id: String,
    message: String, // Base64 or hex encoded
    encoding: Option<String>, // "base64", "hex", or "utf8" (default)
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String, // Hex encoded
    public_key: String, // Hex encoded (1312-byte Dilithium2 key)
    algorithm: String,
    message_hash: String,
}

#[derive(Deserialize)]
struct VerifySignatureRequest {
    signature: String, // Hex encoded
    public_key: String, // Hex encoded
    message: String, // Base64 or hex encoded
    encoding: Option<String>,
}

#[derive(Serialize)]
struct VerifySignatureResponse {
    valid: bool,
    algorithm: String,
    message_hash: String,
}

#[derive(Serialize)]
struct GenerateKeypairResponse {
    public_key: String, // Hex encoded Dilithium2 public key
    private_key: String, // Hex encoded Dilithium2 private key (SENSITIVE!)
    algorithm: String,
    warning: String,
}

impl CryptoHandler {
    /// Sign an arbitrary message with an identity's private key
    async fn handle_sign_message(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let sign_req: SignMessageRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;

        // Parse identity ID
        let identity_hash = hex::decode(&sign_req.identity_id)
            .map_err(|_| anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }

        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        let identity_id = lib_crypto::Hash::from_bytes(&identity_id_bytes);

        // Decode message based on encoding
        let encoding = sign_req.encoding.as_deref().unwrap_or("utf8");
        let message_bytes = match encoding {
            "base64" => {
                base64::engine::general_purpose::STANDARD.decode(&sign_req.message)
                    .map_err(|e| anyhow!("Invalid base64: {}", e))?
            }
            "hex" => {
                hex::decode(&sign_req.message)
                    .map_err(|e| anyhow!("Invalid hex: {}", e))?
            }
            "utf8" | _ => sign_req.message.as_bytes().to_vec(),
        };

        // Get identity and sign the message
        let identity_mgr = self.identity_manager.read().await;
        let identity = identity_mgr.get_identity(&identity_id)
            .ok_or_else(|| anyhow!("Identity not found"))?;

        // Get private key from identity (P1-7: private keys stored in identity)
        let private_key = identity.private_key.as_ref()
            .ok_or_else(|| anyhow!("Identity missing private key"))?;

        // Create keypair for signing
        let keypair = lib_crypto::KeyPair {
            private_key: private_key.clone(),
            public_key: identity.public_key.clone(),
        };

        // Get public key (clone it before dropping the lock)
        let public_key = identity.public_key.clone();

        drop(identity_mgr);

        // Sign the message using lib_crypto
        let signature = lib_crypto::sign_message(&keypair, &message_bytes)
            .map_err(|e| anyhow!("Failed to sign message: {}", e))?;

        // Calculate message hash for reference
        let message_hash = lib_crypto::hash_blake3(&message_bytes);

        let response = SignMessageResponse {
            signature: hex::encode(&signature.signature),
            public_key: hex::encode(&public_key.as_bytes()),
            algorithm: "Dilithium2".to_string(),
            message_hash: hex::encode(message_hash.as_slice()),
        };

        let json_response = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Verify a signature against a message and public key
    async fn handle_verify_signature(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let verify_req: VerifySignatureRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;

        // Decode signature and public key
        let signature_bytes = hex::decode(&verify_req.signature)
            .map_err(|e| anyhow!("Invalid signature hex: {}", e))?;
        let public_key_bytes = hex::decode(&verify_req.public_key)
            .map_err(|e| anyhow!("Invalid public key hex: {}", e))?;

        // Decode message
        let encoding = verify_req.encoding.as_deref().unwrap_or("utf8");
        let message_bytes = match encoding {
            "base64" => {
                base64::engine::general_purpose::STANDARD.decode(&verify_req.message)
                    .map_err(|e| anyhow!("Invalid base64: {}", e))?
            }
            "hex" => {
                hex::decode(&verify_req.message)
                    .map_err(|e| anyhow!("Invalid hex: {}", e))?
            }
            "utf8" | _ => verify_req.message.as_bytes().to_vec(),
        };

        // Verify signature using lib-crypto
        let valid = lib_crypto::verify_signature(&signature_bytes, &message_bytes, &public_key_bytes)
            .unwrap_or(false);

        let message_hash = lib_crypto::hash_blake3(&message_bytes);

        let response = VerifySignatureResponse {
            valid,
            algorithm: "Dilithium2".to_string(),
            message_hash: hex::encode(message_hash.as_slice()),
        };

        let json_response = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Generate a new Dilithium2 keypair
    async fn handle_generate_keypair(&self, _request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Generate new keypair
        let keypair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate keypair: {}", e))?;

        let response = GenerateKeypairResponse {
            public_key: hex::encode(&keypair.public_key.dilithium_pk),
            private_key: hex::encode(&keypair.private_key.dilithium_sk),
            algorithm: "Dilithium2".to_string(),
            warning: "NEVER share the private key! Store it securely. This key cannot be recovered if lost.".to_string(),
        };

        let json_response = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
}

// Helper function to create error responses
fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}
