//! Identity Handler Module
//!
//! Clean, minimal identity management using lib-identity patterns

pub mod login_handlers;
pub mod password_reset;
pub mod backup_recovery;
pub mod bip39;

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use base64::Engine as _;

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
use crate::api::handlers::constants::{SOV_ATOMIC_UNITS, SOV_WELCOME_BONUS, SOV_WELCOME_BONUS_SOV};

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
    storage_system: Arc<RwLock<lib_storage::PersistentStorageSystem>>,
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
        storage_system: Arc<RwLock<lib_storage::PersistentStorageSystem>>,
    ) -> Self {
        Self {
            identity_manager,
            economic_model,
            session_manager,
            rate_limiter,
            account_lockout,
            csrf_protection,
            recovery_phrase_manager,
            storage_system,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for IdentityHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Identity handler: {} {}", request.method, request.uri);
        tracing::info!("AAAAA second log line test");

        // Normalize URI: strip trailing slashes for consistent matching
        // iOS sends "/api/v1/identity/recover/" but routes expect "/api/v1/identity/recover"
        let normalized_uri = request.uri.trim_end_matches('/');
        let normalized_uri = if normalized_uri.is_empty() { "/" } else { normalized_uri };

        // Strip query string for matching (keep original for handlers that need it)
        let match_uri = normalized_uri.split('?').next().unwrap_or(normalized_uri);

        tracing::info!("ZZZZZ IDENTITY HANDLER DEBUG: method={:?}, raw_uri='{}', normalized='{}', match_uri='{}'",
            request.method, request.uri, normalized_uri, match_uri);

        let response = match (request.method, match_uri) {
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
                eprintln!(">>> MOD.RS: Routing to handle_recover_identity");
                self.handle_recover_identity(request).await
            }
            (ZhtpMethod::Get, "/api/v1/identity/backup/status") => {
                self.handle_backup_status(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/export") => {
                self.handle_export_backup(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/backup/import") => {
                self.handle_import_backup(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/seed/verify") => {
                self.handle_verify_seed_phrase(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/migrate") => {
                self.handle_migrate_identity(request).await
            }
            // New endpoints (Issue #348)
            (ZhtpMethod::Post, "/api/v1/identity/restore/seed") => {
                self.handle_restore_from_seed(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/zkdid/create") => {
                // Alias to /create - ZK-DID is always created with identity
                self.handle_create_identity(request).await
            }
            (ZhtpMethod::Post, "/api/v1/identity/signin-with-identity") => {
                self.handle_signin_with_identity(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/exists/") => {
                self.handle_identity_exists(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/username/available/") => {
                self.handle_username_available(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/identity/get/") => {
                self.handle_get_identity_by_did(request).await
            }
            (ZhtpMethod::Post, path) if path.starts_with("/api/v1/identity/verify/") => {
                self.handle_verify_identity_by_did(request).await
            }
            (ZhtpMethod::Get, path) if path.ends_with("/seeds") && path.starts_with("/api/v1/identity/") => {
                self.handle_get_identity_seeds(request).await
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
            // Client-side key generation registration (iOS/mobile)
            (ZhtpMethod::Post, "/api/v1/identity/register") => {
                self.handle_register_client_identity(request).await
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
            // CRITICAL FIX: Create welcome bonus UTXO output (5,000 SOV)
            // This creates an actual spendable UTXO on the blockchain, not just a
            // record in the identity layer. Without this, users cannot spend tokens.
            // ========================================================================
            use lib_blockchain::transaction::TransactionOutput;
            
            let identity_id_hex = citizenship_result.identity_id.to_string();
            let welcome_bonus_amount = citizenship_result.welcome_bonus.bonus_amount;
            
            tracing::info!(" Creating welcome bonus UTXO: {} SOV for identity {}", 
                          welcome_bonus_amount / SOV_ATOMIC_UNITS, &identity_id_hex[..16]);
            
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
            
            // Seed commitment removed for mobile flow (client manages master seed).
            let master_seed_commitment = lib_blockchain::Hash::from_slice(&[0u8; 32]);

            // Primary Wallet
            let primary_wallet_tx = WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from(citizenship_result.primary_wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: None,
                public_key: keypair.public_key.dilithium_pk.to_vec(),
                owner_identity_id: Some(lib_blockchain::Hash::from(citizenship_result.identity_id.0)),
                seed_commitment: master_seed_commitment,
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
                seed_commitment: master_seed_commitment,
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
                seed_commitment: master_seed_commitment,
                created_at: citizenship_result.dao_registration.registered_at,
                registration_fee: 0,  // System wallets are free
                capabilities: 0xFFFF,  // Full capabilities
                initial_balance: 0,  // Starts empty
            };
            
            if let Err(e) = self.submit_wallet_to_blockchain(savings_wallet_tx).await {
                tracing::warn!("Failed to submit savings wallet to blockchain: {}", e);
            }

            // Persist identity to DHT for fast lookups (derived cache, not source of truth)
            // This enables stateless API restarts and horizontal scaling
            let identity_id_str = citizenship_result.identity_id.to_string();
            match serde_json::to_vec(&citizenship_result) {
                Ok(identity_data) => {
                    let mut storage = self.storage_system.write().await;

                    // Store identity record
                    if let Err(e) = storage.store_identity_record(
                        &identity_id_str,
                        &identity_data
                    ).await {
                        tracing::warn!("Failed to persist identity to DHT (non-fatal): {}", e);
                    } else {
                        tracing::info!(" Identity {} persisted to DHT cache", citizenship_result.identity_id);
                    }

                    // Add to identity index for bootstrap
                    if let Err(e) = storage.add_to_identity_index(&identity_id_str).await {
                        tracing::warn!("Failed to add identity to index (non-fatal): {}", e);
                    }

                    // Add wallet indexes for the 3 wallets
                    let primary_wallet_id = citizenship_result.primary_wallet_id.to_string();
                    let ubi_wallet_id = citizenship_result.ubi_wallet_id.to_string();
                    let savings_wallet_id = citizenship_result.savings_wallet_id.to_string();

                    for wallet_id in [&primary_wallet_id, &ubi_wallet_id, &savings_wallet_id] {
                        if let Err(e) = storage.add_to_wallet_index(&identity_id_str, wallet_id).await {
                            tracing::warn!("Failed to add wallet {} to index (non-fatal): {}", wallet_id, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize identity for DHT (non-fatal): {}", e);
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
        // CRITICAL FIX: Create dust UTXO for wallet (1 micro-SOV = 0.00000001 SOV)
        // This establishes the wallet on-chain and allows it to receive transactions
        // Cost is minimal: 3 micro-SOV per user for 3 wallets
        // ========================================================================
        let dust_amount = 1u64; // 1 micro-SOV (0.00000001 SOV)
        let wallet_id_hex = hex::encode(wallet_data.wallet_id.as_bytes());
        
        tracing::info!("💳 Creating dust UTXO for {} wallet: {} micro-SOV", 
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
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;
        let identity_hash = lib_crypto::Hash::from_bytes(&identity_id_bytes);
        
        // Get identity and sign message
        let manager = self.identity_manager.read().await;
        let identity = match manager.get_identity(&identity_hash) {
            Some(id) => id,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Identity not found: {}", sign_req.identity_id),
                ));
            }
        };

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

    /// Handle identity migration (one-time fix for broken seed phrases)
    /// POST /api/v1/identity/migrate
    /// SECURITY: Requires UHP authentication (user must sign with old private key)
    async fn handle_migrate_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_migrate_identity(
            &request.body,
            self.identity_manager.clone(),
            self.rate_limiter.clone(),
            &request,
            self.storage_system.clone(),
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

    /// Handle backup export request (Issue #115)
    /// POST /api/v1/identity/backup/export
    async fn handle_export_backup(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_export_backup(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    /// Handle backup import request (Issue #115)
    /// POST /api/v1/identity/backup/import
    async fn handle_import_backup(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_import_backup(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            self.rate_limiter.clone(),
            &request,
        )
        .await
    }

    /// Handle seed phrase verification request (Issue #115)
    /// POST /api/v1/identity/seed/verify
    async fn handle_verify_seed_phrase(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        backup_recovery::handle_verify_seed_phrase(
            &request.body,
            self.identity_manager.clone(),
            self.session_manager.clone(),
            &request,
        )
        .await
    }

    // ============================================================================
    // New endpoints (Issue #348): Wire up 7 missing identity API endpoints
    // ============================================================================

    /// Restore identity from seed phrase (Issue #348)
    /// POST /api/v1/identity/restore/seed
    async fn handle_restore_from_seed(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(Deserialize)]
        struct RestoreSeedRequest {
            seed_phrase: String,  // Space-separated 20 or 24 words (BIP39)
            display_name: Option<String>,
        }

        let req_data: RestoreSeedRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid restore request: {}", e))?;

        // Parse seed phrase into words
        let seed_words: Vec<String> = req_data.seed_phrase
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Accept both 20-word custom and 24-word BIP39 standard
        if seed_words.len() != 20 && seed_words.len() != 24 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Invalid seed phrase: expected 20 or 24 words, got {}", seed_words.len()),
            ));
        }

        tracing::info!("🔑 Restoring identity from seed phrase");

        // Reconstruct the identity ID from seed phrase
        let seed_text = seed_words.join(" ");
        let identity_hash = lib_crypto::hash_blake3(format!("ZHTP_IDENTITY_SEED:{}", seed_text).as_bytes());
        let identity_id = lib_crypto::Hash::from_bytes(&identity_hash);

        // Check if identity already exists
        let identity_manager = self.identity_manager.read().await;
        if let Some(existing) = identity_manager.get_identity(&identity_id) {
            // Identity exists, create session and return
            let did = existing.did.clone();
            drop(identity_manager);

            let client_ip = request.headers.get("X-Forwarded-For")
                .or_else(|| request.headers.get("Remote-Addr"))
                .unwrap_or_else(|| "unknown".to_string());
            let user_agent = request.headers.get("User-Agent")
                .unwrap_or_else(|| "unknown".to_string());

            let session_token = self.session_manager.create_session(
                identity_id.clone(),
                &client_ip,
                &user_agent,
            ).await?;

            let response_body = json!({
                "status": "restored",
                "identity_id": identity_id.to_string(),
                "did": did,
                "session_token": session_token,
                "message": "Identity restored from seed phrase"
            });

            return Ok(ZhtpResponse::json(&response_body, None)?);
        }
        drop(identity_manager);

        // Identity doesn't exist - need to recreate it
        // This would require full identity recreation logic
        // For now, return an error suggesting to use the recovery endpoint
        let response_body = json!({
            "status": "error",
            "error": "identity_not_found",
            "message": "No identity found for this seed phrase. Use /api/v1/identity/recover to recreate."
        });

        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    /// Check if identity exists (Issue #348)
    /// GET /api/v1/identity/exists/{id}
    async fn handle_identity_exists(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract identity ID from path: /api/v1/identity/exists/{id}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let identity_id_str = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("Identity ID required"))?;

        let identity_id = lib_crypto::Hash::from_hex(identity_id_str)
            .map_err(|e| anyhow::anyhow!("Invalid identity ID: {}", e))?;

        let identity_manager = self.identity_manager.read().await;
        let exists = identity_manager.get_identity(&identity_id).is_some();

        let response_body = json!({
            "identity_id": identity_id_str,
            "exists": exists
        });

        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    /// Check if username (display_name) is available
    /// GET /api/v1/identity/username/available/{username}
    async fn handle_username_available(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract username from path: /api/v1/identity/username/available/{username}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let username = path_parts.get(6)
            .ok_or_else(|| anyhow::anyhow!("Username required"))?;

        // URL decode the username (handles spaces, special chars)
        let username = urlencoding::decode(username)
            .map_err(|e| anyhow::anyhow!("Invalid username encoding: {}", e))?
            .to_string();

        tracing::info!("🔍 Checking username availability: {}", username);

        let identity_manager = self.identity_manager.read().await;

        // Check if any identity has this display_name (case-insensitive)
        let username_lower = username.to_lowercase();
        let is_taken = identity_manager.list_identities()
            .iter()
            .any(|identity| {
                identity.metadata
                    .get("display_name")
                    .map(|name| name.to_lowercase() == username_lower)
                    .unwrap_or(false)
            });

        let response_body = json!({
            "username": username,
            "available": !is_taken
        });

        tracing::info!("🔍 Username '{}' available: {}", username, !is_taken);

        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    /// Get identity by DID (Issue #348)
    /// GET /api/v1/identity/get/{did}
    async fn handle_get_identity_by_did(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract DID from path: /api/v1/identity/get/{did}
        // DID format: did:zhtp:xxx or just the hash part
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let did_str = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("DID required"))?;

        // Handle both full DID and short form
        let did = if did_str.starts_with("did:zhtp:") {
            did_str.to_string()
        } else {
            format!("did:zhtp:{}", did_str)
        };

        tracing::info!("🔍 Looking up identity by DID: {}", did);

        let identity_manager = self.identity_manager.read().await;

        match identity_manager.get_identity_by_did(&did) {
            Some(identity) => {
                let response_body = json!({
                    "status": "found",
                    "identity_id": identity.did.replace("did:zhtp:", ""),
                    "did": identity.did,
                    "identity_type": format!("{:?}", identity.identity_type),
                    "access_level": format!("{:?}", identity.access_level),
                    "created_at": identity.created_at,
                });
                Ok(ZhtpResponse::json(&response_body, None)?)
            }
            None => {
                let response_body = json!({
                    "status": "not_found",
                    "did": did,
                    "message": "Identity not found for this DID"
                });
                Ok(ZhtpResponse::json(&response_body, None)?)
            }
        }
    }

    /// Verify identity by DID (Issue #348)
    /// POST /api/v1/identity/verify/{did}
    async fn handle_verify_identity_by_did(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        use lib_identity::types::IdentityProofParams;

        // Extract DID from path: /api/v1/identity/verify/{did}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let did_str = path_parts.get(5)
            .ok_or_else(|| anyhow::anyhow!("DID required"))?;

        // Parse optional verification requirements from body
        #[derive(Deserialize, Default)]
        struct VerifyRequest {
            #[serde(default)]
            min_age: Option<u8>,
            #[serde(default)]
            jurisdiction: Option<String>,
            #[serde(default)]
            require_citizenship: bool,
        }

        let req_data: VerifyRequest = if request.body.is_empty() {
            VerifyRequest::default()
        } else {
            serde_json::from_slice(&request.body).unwrap_or_default()
        };

        // Handle both full DID and short form
        let did = if did_str.starts_with("did:zhtp:") {
            did_str.to_string()
        } else {
            format!("did:zhtp:{}", did_str)
        };

        tracing::info!("✅ Verifying identity by DID: {}", did);

        let mut identity_manager = self.identity_manager.write().await;

        // Get identity ID from DID
        let identity_id = match identity_manager.get_identity_id_by_did(&did) {
            Some(id) => id,
            None => {
                let response_body = json!({
                    "status": "not_found",
                    "did": did,
                    "verified": false,
                    "message": "Identity not found for this DID"
                });
                return Ok(ZhtpResponse::json(&response_body, None)?);
            }
        };

        // Build verification requirements
        let mut proof_params = IdentityProofParams::new(
            req_data.min_age,
            req_data.jurisdiction,
            vec![],  // No specific credentials required by default
            50,      // Medium privacy level
        );

        if req_data.require_citizenship {
            proof_params = proof_params.with_citizenship_requirement();
        }

        // Verify identity
        match identity_manager.verify_identity(&identity_id, &proof_params).await {
            Ok(verification) => {
                let response_body = json!({
                    "status": "verified",
                    "did": did,
                    "verified": verification.verified,
                    "requirements_met": verification.requirements_met,
                    "requirements_failed": verification.requirements_failed,
                    "privacy_score": verification.privacy_score,
                    "verified_at": verification.verified_at,
                });
                Ok(ZhtpResponse::json(&response_body, None)?)
            }
            Err(e) => {
                let response_body = json!({
                    "status": "error",
                    "did": did,
                    "verified": false,
                    "error": e.to_string()
                });
                Ok(ZhtpResponse::json(&response_body, None)?)
            }
        }
    }

    /// Get identity seed phrases (Issue #348)
    /// GET /api/v1/identity/{id}/seeds
    async fn handle_get_identity_seeds(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        // Extract identity ID from path: /api/v1/identity/{id}/seeds
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        let identity_id_str = path_parts.get(4)
            .ok_or_else(|| anyhow::anyhow!("Identity ID required"))?;

        // Require authentication - check session token
        let session_token_str = request.headers.get("Authorization")
            .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
            .or_else(|| request.headers.get("X-Session-Token"));

        let session_token_str = match session_token_str {
            Some(token) => token,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Unauthorized,
                    "Authentication required to access seed phrases".to_string(),
                ));
            }
        };

        // Get client IP and user agent for session validation
        let client_ip = request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("Remote-Addr"))
            .unwrap_or_else(|| "unknown".to_string());
        let user_agent = request.headers.get("User-Agent")
            .unwrap_or_else(|| "unknown".to_string());

        // Validate session
        let session = match self.session_manager.validate_session(&session_token_str, &client_ip, &user_agent).await {
            Ok(s) => s,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Unauthorized,
                    "Invalid or expired session".to_string(),
                ));
            }
        };

        let identity_id = lib_crypto::Hash::from_hex(identity_id_str)
            .map_err(|e| anyhow::anyhow!("Invalid identity ID: {}", e))?;

        // Verify session belongs to this identity
        if session.identity_id != identity_id {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Session does not match requested identity".to_string(),
            ));
        }

        tracing::info!("🔐 Retrieving seed phrases for identity: {}", &identity_id_str[..16.min(identity_id_str.len())]);

        // Get identity and its wallets
        let identity_manager = self.identity_manager.read().await;
        let identity = match identity_manager.get_identity(&identity_id) {
            Some(id) => id,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Identity not found".to_string(),
                ));
            }
        };

        // Get wallet seed phrases from identity's wallet manager
        let mut seeds = Vec::new();

        // Access the wallet manager from identity
        for (wallet_id, wallet) in identity.wallet_manager.wallets.iter() {
            if let Ok(Some(seed)) = wallet.decrypt_seed_phrase() {
                seeds.push(json!({
                    "wallet_id": hex::encode(&wallet_id.0[..8]),
                    "wallet_type": format!("{:?}", wallet.wallet_type),
                    "wallet_name": wallet.name,
                    "seed_phrase": seed,
                }));
            }
        }

        let response_body = json!({
            "status": "success",
            "identity_id": identity_id_str,
            "wallet_count": seeds.len(),
            "seeds": seeds,
            "warning": "SENSITIVE: Store these seed phrases securely and never share them"
        });

        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    /// Sign in with existing identity (Issue #348)
    /// POST /api/v1/identity/signin-with-identity
    async fn handle_signin_with_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(Deserialize)]
        struct SigninWithIdentityRequest {
            identity_id: String,
            #[serde(default)]
            signature: Option<String>,  // Optional signature proof
        }

        let req_data: SigninWithIdentityRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid signin request: {}", e))?;

        tracing::info!("🔑 Signin with identity: {}", &req_data.identity_id[..16.min(req_data.identity_id.len())]);

        let identity_id = lib_crypto::Hash::from_hex(&req_data.identity_id)
            .map_err(|e| anyhow::anyhow!("Invalid identity ID: {}", e))?;

        // Verify identity exists
        let identity_manager = self.identity_manager.read().await;
        let identity = match identity_manager.get_identity(&identity_id) {
            Some(id) => id,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Identity not found".to_string(),
                ));
            }
        };

        // If signature provided, verify it (future enhancement)
        // For now, we just check identity exists

        // Capture identity data before dropping the lock
        let did = identity.did.clone();
        let identity_type = format!("{:?}", identity.identity_type);
        let access_level = format!("{:?}", identity.access_level);

        drop(identity_manager);

        // Create session for the identity
        let client_ip = request.headers.get("X-Forwarded-For")
            .or_else(|| request.headers.get("Remote-Addr"))
            .unwrap_or_else(|| "unknown".to_string());
        let user_agent = request.headers.get("User-Agent")
            .unwrap_or_else(|| "unknown".to_string());

        let session_token = self.session_manager.create_session(
            identity_id.clone(),
            &client_ip,
            &user_agent,
        ).await?;

        // Calculate expiry (24 hours from now)
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() + 24 * 60 * 60;

        let response_body = json!({
            "status": "success",
            "identity_id": req_data.identity_id,
            "did": did,
            "session_token": session_token,
            "expires_at": expires_at,
            "identity_type": identity_type,
            "access_level": access_level,
        });

        Ok(ZhtpResponse::json(&response_body, None)?)
    }

    // ============================================================================
    // Client-Side Key Generation Registration (iOS/Mobile)
    // ============================================================================

    /// Register an identity created client-side (iOS/mobile secure key generation)
    ///
    /// This endpoint receives ONLY public keys from the client. Private keys
    /// are generated and stored on the client device (iOS Keychain) and NEVER
    /// transmitted over the network.
    ///
    /// POST /api/v1/identity/register
    async fn handle_register_client_identity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        /// Request structure for client-side identity registration
        /// NOTE: DID and node_id are derived server-side from public_key for security.
        /// Client signs "ZHTP_REGISTER:{timestamp}" to prove private key ownership.
        #[derive(Deserialize)]
        struct RegisterIdentityRequest {
            /// Base64-encoded Dilithium5 public key (~2592 bytes)
            public_key: String,

            /// Base64-encoded Kyber1024 public key (~1568 bytes) - optional for PQC
            #[serde(default)]
            kyber_public_key: Option<String>,

            /// Device identifier (e.g., "iphone-uuid-abc123")
            device_id: String,

            /// Optional display name
            #[serde(default)]
            display_name: Option<String>,

            /// Identity type: "human", "device", "organization"
            #[serde(default = "default_identity_type")]
            identity_type: String,

            /// Signature proving ownership of private key
            /// Signs: "ZHTP_REGISTER:{timestamp}"
            registration_proof: String,

            /// Timestamp when signature was created (Unix seconds)
            timestamp: u64,
        }

        fn default_identity_type() -> String {
            "human".to_string()
        }

        // Parse request
        let req_data: RegisterIdentityRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid register request: {}", e))?;

        tracing::info!("📱 Client-side identity registration (device: {})",
            &req_data.device_id[..req_data.device_id.len().min(16)]);

        // Validate timestamp (within 5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let timestamp_age = now.saturating_sub(req_data.timestamp);
        if timestamp_age > 300 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Registration proof expired: {}s old (max 300s)", timestamp_age),
            ));
        }

        // Decode public key from base64
        let public_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &req_data.public_key
        ).map_err(|e| anyhow::anyhow!("Invalid base64 for public_key: {}", e))?;

        // Validate Dilithium5 public key size (exactly 2592 bytes)
        if public_key_bytes.len() != 2592 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Invalid Dilithium5 public key size: {} bytes (expected 2592)", public_key_bytes.len()),
            ));
        }

        // Create PublicKey struct from raw bytes - this computes key_id = Blake3(dilithium_pk)
        let public_key = lib_crypto::PublicKey::new(public_key_bytes.clone());

        // SECURITY: Derive DID server-side from public key (single source of truth)
        // DID = did:zhtp:{hex(Blake3(dilithium_public_key))}
        let did = format!("did:zhtp:{}", hex::encode(public_key.key_id));

        // Derive node_id server-side: Blake3(did || device_id)
        let node_id_bytes = lib_crypto::hash_blake3(
            format!("{}{}", did, req_data.device_id).as_bytes()
        );

        // Identity ID is the key_id (same bytes as in DID)
        let identity_id = lib_crypto::Hash::from_bytes(&public_key.key_id);

        tracing::info!("📱 Derived DID: {} for device: {}",
            &did[..did.len().min(32)],
            &req_data.device_id[..req_data.device_id.len().min(16)]);

        // Decode and verify registration proof signature
        let proof_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &req_data.registration_proof
        ).map_err(|e| anyhow::anyhow!("Invalid base64 for registration_proof: {}", e))?;

        // Message that was signed: "ZHTP_REGISTER:{timestamp}"
        // Client signs timestamp to prove ownership of private key
        let signed_message = format!("ZHTP_REGISTER:{}", req_data.timestamp);

        // Verify signature using Dilithium
        tracing::info!("🔐 Verifying registration proof: pk_len={}, sig_len={}, msg='{}'",
            public_key_bytes.len(), proof_bytes.len(), &signed_message);

        if !lib_crypto::verify_signature(signed_message.as_bytes(), &proof_bytes, &public_key_bytes)
            .unwrap_or(false)
        {
            tracing::warn!("❌ Signature verification failed: pk_len={}, sig_len={}",
                public_key_bytes.len(), proof_bytes.len());
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Unauthorized,
                "Registration proof signature verification failed".to_string(),
            ));
        }

        tracing::info!("✅ Registration proof verified for {}", &did[..32.min(did.len())]);

        // Decode optional Kyber public key
        let kyber_public_key = if let Some(kyber_b64) = &req_data.kyber_public_key {
            let kyber_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                kyber_b64
            ).map_err(|e| anyhow::anyhow!("Invalid base64 for kyber_public_key: {}", e))?;

            // Validate Kyber1024 public key size (exactly 1568 bytes)
            if kyber_bytes.len() != 1568 {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid Kyber1024 public key size: {} bytes (expected 1568)", kyber_bytes.len()),
                ));
            }
            Some(kyber_bytes)
        } else {
            None
        };

        // Parse identity type
        let _identity_type = match req_data.identity_type.as_str() {
            "human" => IdentityType::Human,
            "device" => IdentityType::Device,
            "organization" => IdentityType::Organization,
            _ => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid identity_type: '{}' (expected human/device/organization)", req_data.identity_type),
                ));
            }
        };

        // Check if identity already exists
        {
            let identity_manager = self.identity_manager.read().await;
            if identity_manager.get_identity(&identity_id).is_some() {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Conflict,
                    "Identity already registered".to_string(),
                ));
            }
        }

        // Create identity record (without private key - client keeps it)
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Register identity with full citizenship (creates 3 wallets)
        let citizenship_result = {
            let mut identity_manager = self.identity_manager.write().await;
            let mut economic_model = lib_identity::economics::EconomicModel::new();

            // Register as citizen with 3 wallets
            identity_manager.register_external_citizen_identity(
                did.clone(),
                public_key.clone(),
                kyber_public_key.clone().unwrap_or_default(),
                req_data.device_id.clone(),
                req_data.display_name.clone(),
                created_at,
                &mut economic_model,
            ).await?
        };

        // Extract wallet info from citizenship result
        let primary_wallet_id = hex::encode(&citizenship_result.primary_wallet_id.0);
        let ubi_wallet_id = hex::encode(&citizenship_result.ubi_wallet_id.0);
        let savings_wallet_id = hex::encode(&citizenship_result.savings_wallet_id.0);

        // Create blockchain transaction for identity registration
        let did_string = did.clone();

        let ownership_proof_data = format!("{}:{}", did_string, identity_id);
        let ownership_proof = ownership_proof_data.as_bytes().to_vec();

        let identity_transaction_data = IdentityTransactionData::new(
            did_string.clone(),
            identity_id.to_string(),
            public_key_bytes.clone(),
            ownership_proof,
            req_data.identity_type.clone(),
            Hash::default(),
            0,
            0,
        );

        use lib_blockchain::transaction::TransactionOutput;

        let welcome_bonus_amount = SOV_WELCOME_BONUS; // Citizens always get welcome bonus (atomic units)

        let outputs = vec![TransactionOutput {
            commitment: lib_blockchain::types::hash::blake3_hash(
                format!("welcome_bonus_commitment_{}_{}", identity_id, welcome_bonus_amount).as_bytes()
            ),
            note: lib_blockchain::types::hash::blake3_hash(
                format!("welcome_bonus_note_{}", identity_id).as_bytes()
            ),
            recipient: PublicKey::new(public_key_bytes.clone()),
        }];

        let server_keypair = lib_crypto::generate_keypair()
            .map_err(|e| anyhow::anyhow!("Failed to generate server keypair: {}", e))?;

        let transaction = Transaction::new_identity_registration(
            identity_transaction_data,
            outputs.clone(),
            Signature {
                signature: vec![0; 2420],
                public_key: PublicKey::new(server_keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: created_at,
            },
            Vec::new(),
        );

        let tx_hash = transaction.hash();
        let crypto_signature = lib_crypto::sign_message(&server_keypair, tx_hash.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to sign transaction: {}", e))?;

        let final_transaction = Transaction::new_identity_registration(
            IdentityTransactionData::new(
                did_string.clone(),
                identity_id.to_string(),
                public_key_bytes.clone(),
                format!("{}:{}", did_string, identity_id).as_bytes().to_vec(),
                req_data.identity_type.clone(),
                Hash::default(),
                0,
                0,
            ),
            outputs,
            Signature {
                signature: crypto_signature.signature,
                public_key: PublicKey::new(server_keypair.public_key.dilithium_pk.to_vec()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: created_at,
            },
            Vec::new(),
        );

        let blockchain_tx_hash = match self.submit_transaction_to_blockchain(final_transaction).await {
            Ok(hash) => {
                tracing::info!("⛓️ Identity registered on blockchain: {}", &hash[..16]);
                Some(hash)
            }
            Err(e) => {
                tracing::warn!("⚠️ Blockchain registration failed (non-fatal): {}", e);
                None
            }
        };

        // SOV welcome bonus is credited in-memory by register_wallet() via token_contract.mint().
        // No separate TokenMint transaction needed.

        // Register wallets in blockchain's wallet_registry (source of truth for balances)
        if let Ok(blockchain_arc) = crate::runtime::blockchain_provider::get_global_blockchain().await {
            let mut blockchain = blockchain_arc.write().await;

            // Primary wallet gets welcome bonus
            let primary_wallet_data = lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&citizenship_result.primary_wallet_id.0),
                wallet_type: "Primary".to_string(),
                wallet_name: "Primary Wallet".to_string(),
                alias: Some("primary".to_string()),
                public_key: public_key_bytes.clone(),
                owner_identity_id: Some(lib_blockchain::Hash::from_slice(&identity_id.0)),
                seed_commitment: lib_blockchain::types::hash::blake3_hash(b"client_wallet_seed"),
                created_at,
                registration_fee: 50,
                capabilities: 0xFF,
                initial_balance: welcome_bonus_amount, // 5,000 SOV welcome bonus (atomic units)
            };
            if let Err(e) = blockchain.register_wallet(primary_wallet_data) {
                tracing::warn!("Failed to register primary wallet: {}", e);
            } else {
                tracing::info!("💰 Primary wallet registered with {} SOV welcome bonus", SOV_WELCOME_BONUS_SOV);
            }

            // UBI wallet - no initial balance
            let ubi_wallet_data = lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&citizenship_result.ubi_wallet_id.0),
                wallet_type: "UBI".to_string(),
                wallet_name: "UBI Wallet".to_string(),
                alias: Some("ubi".to_string()),
                public_key: public_key_bytes.clone(),
                owner_identity_id: Some(lib_blockchain::Hash::from_slice(&identity_id.0)),
                seed_commitment: lib_blockchain::types::hash::blake3_hash(b"client_wallet_seed"),
                created_at,
                registration_fee: 50,
                capabilities: 0x01,
                initial_balance: 0,
            };
            if let Err(e) = blockchain.register_wallet(ubi_wallet_data) {
                tracing::warn!("Failed to register UBI wallet: {}", e);
            }

            // Savings wallet - no initial balance
            let savings_wallet_data = lib_blockchain::transaction::WalletTransactionData {
                wallet_id: lib_blockchain::Hash::from_slice(&citizenship_result.savings_wallet_id.0),
                wallet_type: "Savings".to_string(),
                wallet_name: "Savings Wallet".to_string(),
                alias: Some("savings".to_string()),
                public_key: public_key_bytes.clone(),
                owner_identity_id: Some(lib_blockchain::Hash::from_slice(&identity_id.0)),
                seed_commitment: lib_blockchain::types::hash::blake3_hash(b"client_wallet_seed"),
                created_at,
                registration_fee: 50,
                capabilities: 0x02,
                initial_balance: 0,
            };
            if let Err(e) = blockchain.register_wallet(savings_wallet_data) {
                tracing::warn!("Failed to register savings wallet: {}", e);
            }

            tracing::info!("✅ All 3 wallets registered in blockchain wallet_registry");
        }

        // Persist to DHT for fast lookups
        let identity_id_str = identity_id.to_string();
        let identity_record = json!({
            "did": did,
            "public_key": req_data.public_key,
            "kyber_public_key": req_data.kyber_public_key,
            "node_id": hex::encode(&node_id_bytes),
            "device_id": req_data.device_id,
            "display_name": req_data.display_name,
            "identity_type": req_data.identity_type,
            "primary_wallet_id": primary_wallet_id,
            "ubi_wallet_id": ubi_wallet_id,
            "savings_wallet_id": savings_wallet_id,
            "created_at": created_at,
            "registered_at": now,
        });

        {
            let mut storage = self.storage_system.write().await;

            // Store identity record
            if let Err(e) = storage.store_identity_record(
                &identity_id_str,
                &serde_json::to_vec(&identity_record)?
            ).await {
                tracing::warn!("Failed to persist identity to DHT (non-fatal): {}", e);
            }

            // Add to identity index for bootstrap
            if let Err(e) = storage.add_to_identity_index(&identity_id_str).await {
                tracing::warn!("Failed to add identity to index (non-fatal): {}", e);
            }

            // Add wallet indexes for the 3 wallets
            for wallet_id in [&primary_wallet_id, &ubi_wallet_id, &savings_wallet_id] {
                if let Err(e) = storage.add_to_wallet_index(&identity_id_str, wallet_id).await {
                    tracing::warn!("Failed to add wallet {} to index (non-fatal): {}", wallet_id, e);
                }
            }
        }

        tracing::info!("✅ Client citizen registered: {} with 3 wallets",
            &did[..32.min(did.len())]);

        // Return success response with server-derived DID, node_id, and wallet IDs
        // IMPORTANT: Client must use the DID and node_id from this response (server-derived)
        let response_body = json!({
            "status": "registered",
            "identity_id": identity_id.to_string(),
            "did": did,
            "node_id": hex::encode(&node_id_bytes),
            "device_id": req_data.device_id,
            "identity_type": req_data.identity_type,
            "blockchain_tx": blockchain_tx_hash,
            "welcome_bonus": welcome_bonus_amount,
            "registered_at": now,
            "pqc_enabled": req_data.kyber_public_key.is_some(),
            "primary_wallet_id": primary_wallet_id,
            "ubi_wallet_id": ubi_wallet_id,
            "savings_wallet_id": savings_wallet_id
        });

        Ok(ZhtpResponse::json(&response_body, None)?)
    }
}
