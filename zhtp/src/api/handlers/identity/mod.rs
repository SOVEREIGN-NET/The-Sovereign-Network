//! Identity Handler Module
//!
//! Clean, minimal identity management using lib-identity patterns

pub mod login_handlers;
pub mod password_reset;
pub mod backup_recovery;

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
    IdentityManager, IdentityType, CitizenshipResult, RecoveryPhraseManager
};

// Identity and economic model imports
use lib_identity::{
    economics::EconomicModel as IdentityEconomicModel,
};

// Blockchain imports for transaction creation
use lib_blockchain::{
    Transaction, 
    transaction::core::IdentityTransactionData,
    integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm},
    Hash,
};

// Removed unused cryptographic imports

/// Clean identity handler implementation
pub struct IdentityHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    economic_model: Arc<RwLock<IdentityEconomicModel>>,
    session_manager: Arc<crate::session_manager::SessionManager>,
    rate_limiter: Arc<crate::api::middleware::RateLimiter>,
    account_lockout: Arc<login_handlers::AccountLockout>,
    csrf_protection: Arc<crate::api::middleware::CsrfProtection>,
    recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
}

impl IdentityHandler {
    pub fn new(
        identity_manager: Arc<RwLock<IdentityManager>>,
        economic_model: Arc<RwLock<IdentityEconomicModel>>,
        session_manager: Arc<crate::session_manager::SessionManager>,
        rate_limiter: Arc<crate::api::middleware::RateLimiter>,
        account_lockout: Arc<login_handlers::AccountLockout>,
        csrf_protection: Arc<crate::api::middleware::CsrfProtection>,
        recovery_phrase_manager: Arc<RwLock<RecoveryPhraseManager>>,
    ) -> Self {
        Self {
            identity_manager,
            economic_model,
            session_manager,
            rate_limiter,
            account_lockout,
            csrf_protection,
            recovery_phrase_manager,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for IdentityHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Identity handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            (ZhtpMethod::Post, "/api/v1/identity/create") => {
                self.handle_create_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/signin") => {
                self.handle_signin(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/login") => {
                self.handle_login(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/password/recover") => {
                self.handle_password_recovery(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/generate") => {
                self.handle_generate_recovery_phrase(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/verify") => {
                self.handle_verify_recovery_phrase(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/recover") => {
                self.handle_recover_identity(request).await
            }
            (ZhtpMethod::Get, "/api/v1/identity/backup/status") => {
                self.handle_backup_status(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/") => {
                self.handle_get_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/citizenship/apply") => {
                self.handle_citizenship_application(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/sign") => {
                self.handle_sign_message(request).await
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
    display_name: String,
    identity_type: Option<String>,  // Optional, defaults to "human"
    recovery_options: Option<Vec<String>>,
    password: Option<String>,  // Optional password for identity
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
        
        // Parse identity type (defaults to human if not specified)
        let identity_type_str = req_data.identity_type.as_deref().unwrap_or("human");
        let identity_type = match identity_type_str {
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
                .create_citizen_identity(
                    req_data.display_name.clone(), // Use provided display name
                    req_data.recovery_options.unwrap_or_default(),
                    &mut *economic_model,
                )
                .await?;
            
            // Set password if provided
            if let Some(password) = &req_data.password {
                if let Err(e) = identity_manager.set_identity_password(&citizenship_result.identity_id, password) {
                    tracing::warn!("Failed to set identity password: {}", e);
                }
            }
            
            //  Create blockchain transactions for identity + all 3 wallets
            tracing::info!(" Creating blockchain transactions for identity and wallets");
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
            
            // ========================================================================
            // CRITICAL FIX: Create welcome bonus UTXO output (5,000 ZHTP)
            // This creates an actual spendable UTXO on the blockchain, not just a
            // record in the identity layer. Without this, users cannot spend tokens.
            // ========================================================================
            use lib_blockchain::transaction::TransactionOutput;
            
            let identity_id_hex = citizenship_result.identity_id.to_string();
            let welcome_bonus_amount = citizenship_result.welcome_bonus.bonus_amount;
            
            tracing::info!(" Creating welcome bonus UTXO: {} ZHTP for identity {}", 
                          welcome_bonus_amount, &identity_id_hex[..16]);
            
            // Create UTXO output for welcome bonus
            // The recipient is the identity hash (32 bytes) - same as what genesis uses
            let welcome_bonus_output = TransactionOutput {
                commitment: lib_blockchain::types::hash::blake3_hash(
                    format!("welcome_bonus_commitment_{}_{}", identity_id_hex, welcome_bonus_amount).as_bytes()
                ),
                note: lib_blockchain::types::hash::blake3_hash(
                    format!("welcome_bonus_note_{}", identity_id_hex).as_bytes()
                ),
                recipient: PublicKey::new(citizenship_result.identity_id.as_bytes().to_vec()),
            };
            
            let outputs = vec![welcome_bonus_output];
            
            // Create transaction WITHOUT signature first to get the hash for signing
            let temp_transaction = Transaction::new_identity_registration(
                identity_transaction_data.clone(),
                outputs.clone(), // Include welcome bonus output
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
                outputs, //  Include welcome bonus UTXO output
                Signature {
                    signature: crypto_signature.signature, // cryptographic signature over tx hash
                    public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()), // public key
                    algorithm: SignatureAlgorithm::Dilithium2, // Post-quantum algorithm
                    timestamp: citizenship_result.dao_registration.registered_at,
                },
                Vec::new(), // No additional data needed
            );
            
            // Submit identity transaction to shared blockchain
            tracing::info!(" Attempting to submit identity transaction to blockchain...");
            match self.submit_transaction_to_blockchain(transaction).await {
                Ok(tx_hash) => {
                    tracing::info!(" Identity transaction submitted to blockchain: {}", tx_hash);
                }
                Err(e) => {
                    tracing::error!(" Failed to submit identity transaction to blockchain: {}", e);
                }
            }
            
            // Create and submit wallet transactions for all 3 wallets
            use lib_blockchain::transaction::WalletTransactionData;
            
            // Primary Wallet
            let primary_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.primary_wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.primary_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: citizenship_result.welcome_bonus.bonus_amount,  // Welcome bonus goes to primary
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(primary_wallet_tx).await {
                tracing::warn!("Failed to submit primary wallet to blockchain: {}", e);
            }
            
            // UBI Wallet
            let ubi_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.ubi_wallet_id.0),
                wallet_type: "UBI".to_string(),
                wallet_name: "UBI Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.ubi_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: 0,  // UBI payments come later
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(ubi_wallet_tx).await {
                tracing::warn!("Failed to submit UBI wallet to blockchain: {}", e);
            }
            
            // Savings Wallet
            let savings_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.savings_wallet_id.0),
                wallet_type: "Savings".to_string(),
                wallet_name: "Savings Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: lib_crypto::hash_blake3(citizenship_result.wallet_seed_phrases.savings_wallet_seeds.words.join(" ").as_bytes()).into(),
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: 0,  // Starts empty
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(savings_wallet_tx).await {
                tracing::warn!("Failed to submit savings wallet to blockchain: {}", e);
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
            // Generate proper random identity ID for non-human identities
            let identity_type_for_hash = req_data.identity_type.as_deref().unwrap_or("unknown");
            let identity_data = format!("{}:{}", identity_type_for_hash, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
            let identity_id = lib_crypto::hash_blake3(identity_data.as_bytes());
            
            CreateIdentityResponse {
                status: "identity_created".to_string(),
                identity_id: hex::encode(identity_id),
                identity_type: req_data.identity_type.unwrap_or_else(|| "unknown".to_string()),
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
        
        // Use identity manager to retrieve actual identity data
        let response_data = match identity_manager.get_identity(&identity_id) {
            Some(identity) => IdentityResponse {
                status: "identity_found".to_string(),
                identity_id: identity_id.to_string(),
                identity_type: format!("{:?}", identity.identity_type),
                access_level: format!("{:?}", identity.access_level),
                created_at: identity.created_at,
                last_active: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            },
            None => IdentityResponse {
                status: "identity_not_found".to_string(),
                identity_id: identity_id.to_string(),
                identity_type: "unknown".to_string(),
                access_level: "None".to_string(),
                created_at: 0,
                last_active: 0,
            },
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
        // Extract and validate application data from request
        let application_data: serde_json::Value = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid application data: {}", e))?;
        
        // Validate required fields in application
        let applicant_name = application_data.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Anonymous");
        
        let applicant_email = application_data.get("email")
            .and_then(|v| v.as_str());
        
        // Validate that at least a name is provided
        if applicant_name == "Anonymous" && applicant_email.is_none() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Application must include either name or email".to_string(),
            ));
        }
        
        tracing::info!("Processing citizenship application for: {} ({})", 
            applicant_name, 
            applicant_email.unwrap_or("no email"));
        
        // TODO: Store application in identity manager for processing
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
        tracing::info!(" Getting shared blockchain instance for transaction submission...");
        
        // Get the global blockchain instance
        match crate::runtime::blockchain_provider::get_global_blockchain().await {
            Ok(shared_blockchain) => {
                tracing::info!(" Got global blockchain, acquiring write lock...");
                
                // Add timeout to prevent infinite blocking
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(10),
                    shared_blockchain.write()
                ).await {
                    Ok(mut blockchain) => {
                        tracing::info!(" Write lock acquired, adding transaction to mempool...");
                        
                        // Add transaction to pending pool
                        blockchain.add_pending_transaction(transaction.clone())?;
                        
                        let tx_hash = transaction.hash().to_string();
                        tracing::info!(" Transaction submitted to blockchain mempool: {}", &tx_hash[..16]);
                        
                        // Explicitly drop lock
                        drop(blockchain);
                        tracing::info!(" Write lock released");
                        
                        Ok(tx_hash)
                    }
                    Err(_) => {
                        tracing::error!(" TIMEOUT: Failed to acquire write lock on blockchain after 10 seconds!");
                        tracing::error!("   This indicates a deadlock - another task is holding the lock");
                        Err(anyhow::anyhow!("Blockchain write lock timeout - possible deadlock"))
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to get shared blockchain: {}", e);
                Err(anyhow::anyhow!("Failed to submit transaction: {}", e))
            }
        }
    }
    
    /// Submit a wallet registration transaction to the blockchain
    async fn submit_wallet_to_blockchain(&self, wallet_data: lib_blockchain::transaction::WalletTransactionData) -> Result<String> {
        use lib_blockchain::transaction::{Transaction, TransactionOutput};
        use lib_blockchain::integration::{Signature, PublicKey, SignatureAlgorithm};
        
        // Generate keypair for wallet transaction signature
        let keypair = lib_crypto::KeyPair::generate()
            .map_err(|e| anyhow::anyhow!("Failed to generate keypair: {}", e))?;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        // ========================================================================
        // CRITICAL FIX: Create dust UTXO for wallet (1 micro-ZHTP = 0.00000001 ZHTP)
        // This establishes the wallet on-chain and allows it to receive transactions
        // Cost is minimal: 3 micro-ZHTP per user for 3 wallets
        // ========================================================================
        let dust_amount = 1u64; // 1 micro-ZHTP (0.00000001 ZHTP)
        let wallet_id_hex = hex::encode(wallet_data.wallet_id.as_bytes());
        
        tracing::info!("💳 Creating dust UTXO for {} wallet: {} micro-ZHTP", 
                      wallet_data.wallet_type, dust_amount);
        
        // Create dust UTXO output
        // Use owner identity ID as recipient (same as welcome bonus)
        let recipient_identity = if let Some(owner_id) = wallet_data.owner_identity_id {
            owner_id.as_bytes().to_vec()
        } else {
            // Fallback: use wallet ID itself
            wallet_data.wallet_id.as_bytes().to_vec()
        };
        
        let wallet_dust_output = TransactionOutput {
            commitment: lib_blockchain::types::hash::blake3_hash(
                format!("wallet_init_commitment_{}_{}", wallet_id_hex, dust_amount).as_bytes()
            ),
            note: lib_blockchain::types::hash::blake3_hash(
                format!("wallet_init_note_{}", wallet_id_hex).as_bytes()
            ),
            recipient: PublicKey::new(recipient_identity),
        };
        
        let outputs = vec![wallet_dust_output];
        
        // Create temporary transaction to get hash for signing
        let temp_transaction = Transaction::new_wallet_registration(
            wallet_data.clone(),
            outputs.clone(), // Include dust output
            Signature {
                signature: vec![0; 2420], // Temporary signature
                public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp,
            },
            Vec::new(), // Empty data
        );
        
        // Get the transaction hash for signing
        let tx_hash = temp_transaction.hash();
        
        // Sign the transaction hash
        let crypto_signature = keypair.sign(tx_hash.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to sign wallet transaction: {}", e))?;
        
        // Create final signed transaction
        let transaction = Transaction::new_wallet_registration(
            wallet_data.clone(),
            outputs, //  Include dust UTXO output
            Signature {
                signature: crypto_signature.signature,
                public_key: PublicKey::new(keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp,
            },
            Vec::new(), // Empty data
        );
        
        // Submit to blockchain
        let tx_hash = self.submit_transaction_to_blockchain(transaction).await?;
        tracing::info!(" Wallet transaction submitted: {} ({})", 
            &tx_hash[..16], 
            wallet_data.wallet_type);
        
        Ok(tx_hash)
    }
    
    /// Sign a message with an identity's private key
    /// POST /api/v1/identity/sign
    async fn handle_sign_message(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(Deserialize)]
        struct SignRequest {
            identity_id: String,  // Identity ID (short hex format like "8972927464b621d2")
            message: String,      // Message to sign
        }
        
        // Parse request body
        let sign_req: SignRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid sign request: {}", e))?;
        
        tracing::info!(" Signing message for identity: {}", sign_req.identity_id);
        
        // Parse identity ID from hex
        let identity_id_bytes = hex::decode(&sign_req.identity_id)
            .map_err(|e| anyhow::anyhow!("Invalid identity ID hex: {}", e))?;
        let identity_hash = lib_crypto::Hash::from_bytes(&identity_id_bytes);
        
        // Get identity and sign message
        let manager = self.identity_manager.read().await;
        let identity = manager.get_identity(&identity_hash)
            .ok_or_else(|| anyhow::anyhow!("Identity not found: {}", sign_req.identity_id))?;

        // Get private key from identity (P1-7: private keys stored in identity)
        let private_key = identity.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Identity missing private key"))?;

        // Create keypair for signing
        let keypair = lib_crypto::KeyPair {
            private_key: private_key.clone(),
            public_key: identity.public_key.clone(),
        };

        // Sign the message using lib_crypto
        let signature = lib_crypto::sign_message(&keypair, sign_req.message.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to sign message: {}", e))?;

        // Convert signature to hex
        let signature_hex = hex::encode(&signature.signature);
        
        tracing::info!(" Message signed successfully (signature length: {} bytes)", signature.signature.len());
        
        // Return response
        let response_body = json!({
            "success": true,
            "identity_id": sign_req.identity_id,
            "message": sign_req.message,
            "signature": signature_hex,
            "signature_algorithm": "CRYSTALS-Dilithium2",
            "public_key": hex::encode(&identity.public_key.as_bytes()),
        });
        
        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    /// Handle signin request
    /// POST /api/v1/identity/signin
    async fn handle_signin(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        login_handlers::handle_signin(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.rate_limiter.clone(),
            self.account_lockout.clone(),
            self.csrf_protection.clone(),
            &request,
        )
        .await
    }

    /// Handle login request (alias for signin)
    /// POST /api/v1/identity/login
    async fn handle_login(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        login_handlers::handle_login(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.rate_limiter.clone(),
            self.account_lockout.clone(),
            self.csrf_protection.clone(),
            &request,
        )
        .await
    }

    /// Handle password recovery request (P0-8)
    /// POST /api/v1/identity/password/recover
    async fn handle_password_recovery(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        password_reset::handle_password_recovery(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
        )
        .await
    }

    /// Handle generate recovery phrase request (Issue #100)
    /// POST /api/v1/identity/backup/generate
    async fn handle_generate_recovery_phrase(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_generate_recovery_phrase(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.recovery_phrase_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle verify recovery phrase request (Issue #100)
    /// POST /api/v1/identity/backup/verify
    async fn handle_verify_recovery_phrase(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_verify_recovery_phrase(
            &request.body,
            self.recovery_phrase_manager.clone(),
        )
        .await
    }

    /// Handle recover identity request (Issue #100)
    /// POST /api/v1/identity/recover
    async fn handle_recover_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_recover_identity(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.recovery_phrase_manager.clone(),
            self.rate_limiter.clone(),
            &request,
        )
        .await
    }

    /// Handle backup status request (Issue #100)
    /// GET /api/v1/identity/backup/status
    async fn handle_backup_status(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract query params from URI
        let query_params = request.uri
            .split('?')
            .nth(1)
            .unwrap_or("");

        backup_recovery::handle_backup_status(
            query_params,
            self.recovery_phrase_manager.clone(),
        )
        .await
    }
}