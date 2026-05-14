//! User Credentials Handler
//!
//! Username + password authentication for public-zone access.
//!
//! Endpoints:
//!   POST /api/v1/auth/credentials/register — set username + password (requires existing DID)
//!   POST /api/v1/auth/credentials/signin   — username + password → session token
//!   POST /api/v1/auth/credentials/recover  — seed phrase → prove DID → new password

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_blockchain::{Blockchain, BlockchainQuery};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

use crate::session_manager::SessionManager;

pub struct CredentialsHandler {
    blockchain: Arc<RwLock<Blockchain>>,
    session_manager: Arc<SessionManager>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    did: String,
    username: String,
    password_hash: String,
    ownership_proof: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct SigninRequest {
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct RecoverRequest {
    username: String,
    new_password_hash: String,
    ownership_proof: String,
    timestamp: u64,
}

fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

fn error_resp(status: ZhtpStatus, msg: &str) -> ZhtpResponse {
    ZhtpResponse::error(status, msg.to_string())
}

impl CredentialsHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>, session_manager: Arc<SessionManager>) -> Self {
        Self {
            blockchain,
            session_manager,
        }
    }

    async fn handle_register(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: RegisterRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        if let Err(e) = lib_blockchain::transaction::credentials::validate_username(&req.username) {
            return Ok(error_resp(ZhtpStatus::BadRequest, &e));
        }

        if !req.password_hash.starts_with("$argon2") {
            return Ok(error_resp(
                ZhtpStatus::BadRequest,
                "password_hash must be an argon2id PHC string (hash client-side)",
            ));
        }

        if !req.did.starts_with("did:zhtp:") {
            return Ok(error_resp(ZhtpStatus::BadRequest, "Invalid DID format"));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(req.timestamp) > 300 {
            return Ok(error_resp(ZhtpStatus::BadRequest, "Timestamp expired"));
        }

        // Verify DID ownership
        let message = format!("REGISTER_CREDENTIAL:{}:{}", req.username, req.timestamp);
        if let Err(e) = self
            .verify_did_ownership(&req.did, &req.ownership_proof, &message)
            .await
        {
            return Ok(error_resp(ZhtpStatus::Unauthorized, &e));
        }

        // Check availability
        {
            let blockchain = self.blockchain.read().await;
            if !blockchain.query_identity_exists(&req.did) {
                return Ok(error_resp(
                    ZhtpStatus::NotFound,
                    "DID not found — register identity first",
                ));
            }
            if blockchain.credential_registry.contains_key(&req.username) {
                return Ok(error_resp(ZhtpStatus::Conflict, "Username already taken"));
            }
            if blockchain.did_to_username.contains_key(&req.did) {
                return Ok(error_resp(
                    ZhtpStatus::Conflict,
                    "DID already has registered credentials",
                ));
            }
        }

        // Submit transaction + cache warmup. Legacy endpoint emits an
        // Argon2idPhc record; opaque_record stays empty.
        let credential_data = lib_blockchain::transaction::RegisterCredentialData {
            username: req.username.clone(),
            owner_did: req.did.clone(),
            password_hash: req.password_hash.clone(),
            opaque_record: Vec::new(),
            auth_method: lib_blockchain::transaction::credentials::AuthMethod::Argon2idPhc,
        };

        let tx = self.build_system_tx(
            lib_blockchain::TransactionType::RegisterCredential,
            lib_blockchain::transaction::TransactionPayload::RegisterCredential(credential_data),
            format!("credential:register:{}", req.username).into_bytes(),
            now,
        );

        {
            let mut blockchain = self.blockchain.write().await;
            blockchain
                .add_system_transaction(tx)
                .map_err(|e| anyhow::anyhow!("Failed to submit credential tx: {}", e))?;

            // Cache warmup so signin works before block commit
            let height = blockchain.query_height();
            blockchain.credential_registry.insert(
                req.username.clone(),
                lib_blockchain::transaction::UserCredential {
                    username: req.username.clone(),
                    owner_did: req.did.clone(),
                    password_hash: req.password_hash,
                    registered_at_height: height,
                    registered_at: now,
                    password_changed_at_height: 0,
                    opaque_record: Vec::new(),
                    auth_method: lib_blockchain::transaction::credentials::AuthMethod::Argon2idPhc,
                },
            );
            blockchain
                .did_to_username
                .insert(req.did.clone(), req.username.clone());
        }

        info!(
            "Credential registered: '{}' for {}",
            req.username,
            &req.did[..20.min(req.did.len())]
        );

        create_json_response(json!({
            "status": "success",
            "username": req.username,
            "did": req.did,
            "message": "Credentials registered. Sign in with username and password."
        }))
    }

    async fn handle_signin(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: SigninRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        let credential = {
            let blockchain = self.blockchain.read().await;
            blockchain.credential_registry.get(&req.username).cloned()
        };

        let credential = match credential {
            Some(c) => c,
            None => {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                return Ok(error_resp(
                    ZhtpStatus::Unauthorized,
                    "Invalid username or password",
                ));
            }
        };

        if credential.password_hash != req.password_hash {
            return Ok(error_resp(
                ZhtpStatus::Unauthorized,
                "Invalid username or password",
            ));
        }

        let client_ip = request
            .headers
            .get("X-Real-IP")
            .unwrap_or_else(|| "unknown".to_string());
        let user_agent = request
            .headers
            .get("User-Agent")
            .unwrap_or_else(|| "unknown".to_string());

        let identity_hash = {
            let did_hex = credential
                .owner_did
                .strip_prefix("did:zhtp:")
                .unwrap_or(&credential.owner_did);
            let mut h = [0u8; 32];
            if let Ok(bytes) = hex::decode(did_hex) {
                let len = bytes.len().min(32);
                h[..len].copy_from_slice(&bytes[..len]);
            }
            lib_crypto::Hash(h)
        };

        let session_token = self
            .session_manager
            .create_password_session(identity_hash, &client_ip, &user_agent)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create session: {}", e))?;

        info!("Password signin: '{}' from {}", req.username, client_ip);

        create_json_response(json!({
            "status": "success",
            "session_token": session_token,
            "did": credential.owner_did,
            "username": credential.username,
            "access_zone": "public"
        }))
    }

    async fn handle_recover(&self, request: &ZhtpRequest) -> Result<ZhtpResponse> {
        let req: RecoverRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(req.timestamp) > 300 {
            return Ok(error_resp(ZhtpStatus::BadRequest, "Timestamp expired"));
        }

        let credential = {
            let blockchain = self.blockchain.read().await;
            blockchain.credential_registry.get(&req.username).cloned()
        };

        let credential = match credential {
            Some(c) => c,
            None => {
                return Ok(error_resp(ZhtpStatus::NotFound, "Username not found"));
            }
        };

        let message = format!("RECOVER_CREDENTIAL:{}:{}", req.username, req.timestamp);
        if let Err(e) = self
            .verify_did_ownership(&credential.owner_did, &req.ownership_proof, &message)
            .await
        {
            return Ok(error_resp(ZhtpStatus::Unauthorized, &e));
        }

        if !req.new_password_hash.starts_with("$argon2") {
            return Ok(error_resp(
                ZhtpStatus::BadRequest,
                "new_password_hash must be argon2id PHC string",
            ));
        }

        let update_data = lib_blockchain::transaction::UpdateCredentialPasswordData {
            username: req.username.clone(),
            owner_did: credential.owner_did.clone(),
            new_password_hash: req.new_password_hash.clone(),
        };

        let tx = self.build_system_tx(
            lib_blockchain::TransactionType::UpdateCredentialPassword,
            lib_blockchain::transaction::TransactionPayload::UpdateCredentialPassword(update_data),
            format!("credential:recover:{}", req.username).into_bytes(),
            now,
        );

        {
            let mut blockchain = self.blockchain.write().await;
            blockchain
                .add_system_transaction(tx)
                .map_err(|e| anyhow::anyhow!("Failed to submit password update tx: {}", e))?;

            let height = blockchain.query_height();
            if let Some(cred) = blockchain.credential_registry.get_mut(&req.username) {
                cred.password_hash = req.new_password_hash;
                cred.password_changed_at_height = height;
            }
        }

        info!("Password recovered for '{}'", req.username);

        create_json_response(json!({
            "status": "success",
            "username": req.username,
            "message": "Password updated successfully."
        }))
    }

    async fn verify_did_ownership(
        &self,
        did: &str,
        signature_hex: &str,
        message: &str,
    ) -> std::result::Result<(), String> {
        let blockchain = self.blockchain.read().await;
        let identity = blockchain
            .query_identity(did)
            .ok_or_else(|| "DID not found".to_string())?;

        let sig_bytes =
            hex::decode(signature_hex).map_err(|_| "Invalid signature hex".to_string())?;

        let pk_bytes = &identity.public_key;
        if pk_bytes.len() < 2592 {
            return Err("Public key too short for Dilithium5".to_string());
        }

        let pk: [u8; 2592] = pk_bytes[..2592]
            .try_into()
            .map_err(|_| "Failed to extract public key".to_string())?;

        match lib_crypto::verify_signature(message.as_bytes(), &sig_bytes, &pk) {
            Ok(true) => Ok(()),
            Ok(false) => Err("Signature verification failed".to_string()),
            Err(e) => Err(format!("Signature verification error: {}", e)),
        }
    }

    fn build_system_tx(
        &self,
        tx_type: lib_blockchain::TransactionType,
        payload: lib_blockchain::transaction::TransactionPayload,
        memo: Vec<u8>,
        timestamp: u64,
    ) -> lib_blockchain::Transaction {
        lib_blockchain::Transaction {
            version: 8,
            chain_id: 0x03,
            transaction_type: tx_type,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature: lib_blockchain::integration::crypto_integration::Signature {
                signature: Vec::new(),
                public_key: lib_blockchain::integration::crypto_integration::PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id: [0u8; 32],
                },
                algorithm:
                    lib_blockchain::integration::crypto_integration::SignatureAlgorithm::Dilithium5,
                timestamp,
            },
            memo,
            payload,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for CredentialsHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = request.uri.split('?').next().unwrap_or("").trim_end_matches('/');

        match (&request.method, path) {
            (ZhtpMethod::Post, "/api/v1/auth/credentials/register") => {
                Ok(self.handle_register(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/auth/credentials/signin") => {
                Ok(self.handle_signin(&request).await?)
            }
            (ZhtpMethod::Post, "/api/v1/auth/credentials/recover") => {
                Ok(self.handle_recover(&request).await?)
            }
            _ => Ok(error_resp(ZhtpStatus::NotFound, "Not found")),
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        let path = request.uri.split('?').next().unwrap_or("");
        path.starts_with("/api/v1/auth/credentials/")
    }
}
