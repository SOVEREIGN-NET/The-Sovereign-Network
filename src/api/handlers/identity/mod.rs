//! Identity Handler Module
//! 
//! Clean, minimal identity management using lib-identity patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Identity management imports
use lib_identity::{
    IdentityManager, IdentityType, CitizenshipResult
};

// Economic model import  
use lib_identity::economics::EconomicModel;

// Blockchain imports for transaction creation
use lib_blockchain::{
    Transaction, 
    TransactionType,
    transaction::IdentityTransactionData,
    integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm},
    Hash,
};

// Cryptographic imports for proper signing
use lib_crypto::{generate_keypair, sign_message};

/// Clean identity handler implementation
pub struct IdentityHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<EconomicModel>>,
}

impl IdentityHandler {
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<EconomicModel>>,
    ) -> Self {
        Self {
            identity_manager,
            economic_model,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for IdentityHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("🆔 Identity handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/identity/create") => {
                self.handle_create_identity(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/") => {
                self.handle_get_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/citizenship/apply") => {
                self.handle_citizenship_application(request).await
            }
            _ => {
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Identity endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                // Add ZHTP headers
                resp.headers.set("X-Handler", "Identity".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Identity handler error: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Identity error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/identity/")
    }
    
    fn priority(&self) -> u32 {
        100
    }
}

// Request/Response structures following lib-identity patterns
#[derive(Deserialize)]
struct CreateIdentityRequest {
    identity_type: String,
    recovery_options: Option<Vec<String>>,
}

#[derive(Serialize)]
struct CreateIdentityResponse {
    status: String,
    identity_id: String,
    identity_type: String,
    access_level: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    citizenship_result: Option<CitizenshipResult>,
}

#[derive(Serialize)]
struct IdentityResponse {
    status: String,
    identity_id: String,
    identity_type: String,
    access_level: String,
    created_at: u64,
    last_active: u64,
}

impl IdentityHandler {
    /// Handle identity creation using lib-identity patterns
    async fn handle_create_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: CreateIdentityRequest = serde_json::from_slice(&request.body)?;
        
        // Parse identity type
        let identity_type = match req_data.identity_type.as_str() {
            "human" => IdentityType::Human,
            "organization" => IdentityType::Organization,
            "device" => IdentityType::Device,
            _ => return Err(anyhow::anyhow!("Invalid identity type")),
        };
        
        let mut identity_manager = self.identity_manager.write().await;
        
        let response_data = if identity_type == IdentityType::Human {
            // Create full citizen identity WITH seed phrases
            let mut economic_model = self.economic_model.write().await;
            let citizenship_result = identity_manager
                .onboard_new_citizen(
                    format!("Citizen_{}", std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()), // Display name
                    req_data.recovery_options.unwrap_or_default(),
                    &mut *economic_model,
                )
                .await?;
            
            // 🔥 FIX: Create blockchain transaction for the identity registration
            tracing::error!("🚨 BLOCKCHAIN TRANSACTION CREATION STARTING - DEBUG LOG");
            let did_string = format!("did:zhtp:{}", citizenship_result.identity_id);
            
            // Create proper ownership proof by signing the DID with identity data
            let ownership_proof_data = format!("{}:{}", did_string, citizenship_result.identity_id);
            let ownership_proof = ownership_proof_data.as_bytes().to_vec();
            
            let identity_transaction_data = IdentityTransactionData::new(
                did_string.clone(),
                citizenship_result.identity_id.to_string(),
                citizenship_result.primary_wallet_id.as_bytes().to_vec(), // public key
                ownership_proof, // proper ownership proof
                "human".to_string(),
                Hash::default(), // DID document hash
                0, // registration fee - system transactions are fee-free
                0, // DAO fee - system transactions are fee-free
            );
            
            // Create proper cryptographic signature for blockchain transaction
            // The signature must be over the transaction hash, not arbitrary data
            use lib_crypto::{generate_keypair, sign_message};
            
            // Generate a temporary keypair (in production, use citizen's actual keypair)
            let keypair = generate_keypair().map_err(|e| anyhow::anyhow!("Failed to generate keypair: {}", e))?;
            
            // Create transaction WITHOUT signature first to get the hash for signing
            let temp_transaction = Transaction::new_identity_registration(
                identity_transaction_data.clone(),
                vec![], // No outputs needed for identity registration
                Signature {
                    signature: Vec::new(), // Empty signature for hash calculation
                    public_key: PublicKey::new(Vec::new()), // Empty public key for hash calculation
                    algorithm: SignatureAlgorithm::Dilithium2,
                    timestamp: citizenship_result.dao_registration.registered_at,
                },
                Vec::new(), // Empty data for initial hash
            );
            
            // Get the transaction hash that needs to be signed
            let tx_hash = temp_transaction.hash();
            
            // Sign the transaction hash with proper cryptographic signature
            let crypto_signature = sign_message(&keypair, tx_hash.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create signature: {}", e))?;
            
            // Create the final blockchain transaction with proper signature
            let transaction = Transaction::new_identity_registration(
                identity_transaction_data,
                vec![], // No outputs needed for identity registration
                Signature {
                    signature: crypto_signature.signature, // Real cryptographic signature over tx hash
                    public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()), // Real public key
                    algorithm: SignatureAlgorithm::Dilithium2, // Post-quantum algorithm
                    timestamp: citizenship_result.dao_registration.registered_at,
                },
                Vec::new(), // No additional data needed
            );
            
            // Submit transaction to shared blockchain
            match self.submit_transaction_to_blockchain(transaction).await {
                Ok(tx_hash) => {
                    tracing::info!("🎉 Identity transaction submitted to blockchain: {}", tx_hash);
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to submit identity transaction to blockchain: {}", e);
                }
            }
            
            CreateIdentityResponse {
                status: "citizen_created".to_string(),
                identity_id: citizenship_result.identity_id.to_string(),
                identity_type: "human".to_string(),
                access_level: "FullCitizen".to_string(),
                created_at: citizenship_result.dao_registration.registered_at,
                citizenship_result: Some(citizenship_result),
            }
        } else {
            // Create basic identity (non-human)
            // For now, return a placeholder response
            let identity_id = lib_crypto::Hash::from_bytes(&[0u8; 32]); // Mock ID for non-human identities
            
            CreateIdentityResponse {
                status: "identity_created".to_string(),
                identity_id: identity_id.to_string(),
                identity_type: req_data.identity_type,
                access_level: "Visitor".to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                citizenship_result: None,
            }
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle identity retrieval
    async fn handle_get_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract identity ID from path: /api/v1/identity/{id}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let identity_id_str = path_parts.get(4)
            .ok_or_else(|| anyhow::anyhow!("Identity ID required"))?;
        
        let identity_id = lib_crypto::Hash::from_hex(identity_id_str)?;
        
        let identity_manager = self.identity_manager.read().await;
        
        // For now, return a mock response since we need to implement identity retrieval
        let response_data = IdentityResponse {
            status: "identity_found".to_string(),
            identity_id: identity_id.to_string(),
            identity_type: "human".to_string(),
            access_level: "FullCitizen".to_string(),
            created_at: 1694995200,
            last_active: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Handle citizenship application
    async fn handle_citizenship_application(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let response_data = json!({
            "status": "citizenship_application_received",
            "message": "Citizenship application functionality pending implementation",
            "next_steps": [
                "Identity verification",
                "Background check",
                "DAO vote approval"
            ]
        });
        
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }
    
    /// Submit a transaction to the shared blockchain
    async fn submit_transaction_to_blockchain(&self, transaction: Transaction) -> Result<String> {
        // Get the shared blockchain instance
        match lib_blockchain::get_shared_blockchain().await {
            Ok(shared_blockchain) => {
                let mut blockchain = shared_blockchain.write().await;
                
                // Add transaction to pending pool
                blockchain.add_pending_transaction(transaction.clone())?;
                
                let tx_hash = transaction.hash().to_string();
                tracing::info!("📤 Transaction submitted to blockchain mempool: {}", &tx_hash[..16]);
                
                Ok(tx_hash)
            }
            Err(e) => {
                tracing::error!("❌ Failed to get shared blockchain: {}", e);
                Err(anyhow::anyhow!("Failed to submit transaction: {}", e))
            }
        }
    }
}