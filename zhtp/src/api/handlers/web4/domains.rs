//! Web4 Domain Management API Endpoints

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_network::web4::{DomainRegistrationRequest, DomainMetadata, DomainEconomicSettings, DomainLookupResponse, PublicOwnerInfo};
use lib_identity::ZhtpIdentity;
use lib_proofs::ZeroKnowledgeProof;
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn};
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use crate::web4_manifest::{DeployManifest, ensure_canonical_file_list, compute_root_hash, manifest_unsigned_bytes};

use super::Web4Handler;
use std::collections::HashMap;

/// Domain registration request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiDomainRegistrationRequest {
    /// Domain to register
    pub domain: String,
    /// Registration duration in days
    pub duration_days: u64,
    /// Domain title
    pub title: String,
    /// Domain description
    pub description: String,
    /// Domain category
    pub category: String,
    /// Domain tags
    pub tags: Vec<String>,
    /// Is publicly discoverable
    pub public: bool,
    /// Initial content (path -> base64 encoded content)
    pub initial_content: std::collections::HashMap<String, String>,
    /// Owner identity (serialized)
    pub owner_identity: String,
    /// Registration proof (serialized)
    pub registration_proof: String,
}

/// Manifest-based domain registration request (used by CLI deploy)
/// This is a simpler format where content has already been uploaded
/// and the deploy_manifest_cid references the uploaded DeployManifest
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestDomainRegistrationRequest {
    /// Domain to register
    pub domain: String,
    /// CANONICAL: CID of the uploaded DeployManifest
    /// This will be converted to web4_manifest_cid during registration
    #[serde(alias = "manifest_cid")]  // Backwards compatibility
    pub deploy_manifest_cid: String,
    /// Owner DID (did:zhtp:hex format)
    pub owner: String,
    /// Optional declared fee amount in SOV tokens (minimum 10 SOV)
    #[serde(default)]
    pub fee: Option<u64>,
    /// Canonical on-chain SOV fee payment transaction (hex-encoded bincode Transaction)
    #[serde(default)]
    pub fee_payment_tx: Option<String>,
}

/// Simple domain registration request (for easier testing)
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleDomainRegistrationRequest {
    /// Domain to register
    pub domain: String,
    /// Owner name/identifier (DID format: did:zhtp:hex or raw hex)
    pub owner: String,
    /// Content mappings (path -> content object)
    pub content_mappings: std::collections::HashMap<String, ContentMapping>,
    /// Metadata (optional)
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Cryptographic signature proving ownership (hex encoded)
    /// Signs: domain|timestamp|fee_amount
    pub signature: String,
    /// Request timestamp (Unix seconds) - for replay protection
    pub timestamp: u64,
    /// Fee amount in SOV tokens (fixed: 10 SOV for domain registration)
    #[serde(default)]
    pub fee: Option<u64>,
    /// Canonical on-chain SOV fee payment transaction (hex-encoded bincode Transaction)
    /// Must be a TokenTransfer from owner's Primary wallet to DAO treasury wallet.
    #[serde(default)]
    pub fee_payment_tx: Option<String>,
}

/// Content mapping for simple registration
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentMapping {
    /// Actual content (will be hashed)
    pub content: String,
    /// Content type
    pub content_type: String,
}

/// Domain transfer request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiDomainTransferRequest {
    /// Domain to transfer
    pub domain: String,
    /// Current owner identity
    pub from_owner: String,
    /// New owner identity
    pub to_owner: String,
    /// Transfer proof
    pub transfer_proof: String,
}

/// Domain release request from API
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiDomainReleaseRequest {
    /// Domain to release
    pub domain: String,
    /// Owner identity
    pub owner_identity: String,
}

impl Web4Handler {
    /// Register a domain using simplified format (for easy testing/deployment)
    /// Supports both manifest-based (from CLI deploy) and content-based formats
    pub async fn register_domain_simple(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!("Processing Web4 domain registration request");

        // Try manifest-based request first (simpler format from CLI deploy)
        if let Ok(manifest_request) = serde_json::from_slice::<ManifestDomainRegistrationRequest>(&request_body) {
            return self.register_domain_from_manifest(manifest_request).await;
        }

        // Fall back to simple request with inline content
        info!("Processing simple Web4 domain registration request");

        // Parse simple request
        let simple_request: SimpleDomainRegistrationRequest = serde_json::from_slice(&request_body)
            .map_err(|e| anyhow!("Invalid domain registration request: {}", e))?;

        info!(" Registering domain: {}", simple_request.domain);
        info!(" Owner: {}", simple_request.owner);
        info!(" Content paths: {}", simple_request.content_mappings.len());

        // BOUNDARY CODE: Accept DID as-is, use proper DID resolution
        // DID is the public contract - do not fabricate internal IdentityIds
        let owner_did = if simple_request.owner.starts_with("did:zhtp:") {
            simple_request.owner.clone()
        } else {
            // Support raw hex for backward compat, but convert to DID
            format!("did:zhtp:{}", simple_request.owner)
        };

        // Look up owner identity using boundary-safe DID API
        // This is the correct layer: accept DID, use get_identity_by_did()
        let identity_mgr = self.identity_manager.read().await;
        let owner_identity = identity_mgr.get_identity_by_did(&owner_did)
            .ok_or_else(|| anyhow!(
                "Owner identity not found: {}. Please register this identity first using /api/v1/identity/create",
                owner_did
            ))?
            .clone();

        // DEBUG: Check wallet state right after retrieval
        info!("  WALLET DEBUG (after IdentityManager retrieval):");
        info!("    Wallet count: {}", owner_identity.wallet_manager.wallets.len());
        for (id, w) in &owner_identity.wallet_manager.wallets {
            info!("    - Wallet: {} (type: {:?})", hex::encode(&id.0[..8]), w.wallet_type);
        }

        drop(identity_mgr);
        info!(" Using identity: {} (Display name: {})",
            owner_did,
            owner_identity.metadata.get("display_name").map(|s| s.as_str()).unwrap_or("no name")
        );

        // Domain registration fee: fixed 10 SOV
        const DOMAIN_REGISTRATION_FEE_SOV: u64 = 10;

        // Fee is fixed; if the client provides it explicitly, it must match.
        let user_provided_fee = simple_request.fee.unwrap_or(DOMAIN_REGISTRATION_FEE_SOV);
        if user_provided_fee != DOMAIN_REGISTRATION_FEE_SOV {
            return Err(anyhow!(
                "Invalid fee: provided {} SOV, required exactly {} SOV for domain registration",
                user_provided_fee, DOMAIN_REGISTRATION_FEE_SOV
            ));
        }

        info!(" Domain registration fee: {} SOV", DOMAIN_REGISTRATION_FEE_SOV);

        let registration_fee_sov = DOMAIN_REGISTRATION_FEE_SOV;

        // ========== SECURITY: SIGNATURE VERIFICATION ==========
        // Verify that the request was signed by the owner's private key
        info!(" Verifying signature for authorization...");
        
        // Check timestamp is recent (within 5 minutes)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();
        
        let time_diff = if current_time > simple_request.timestamp {
            current_time - simple_request.timestamp
        } else {
            simple_request.timestamp - current_time
        };
        
        if time_diff > 300 { // 5 minutes = 300 seconds
            return Err(anyhow!(
                "Request expired. Timestamp difference: {} seconds (max 300). Current: {}, Request: {}",
                time_diff, current_time, simple_request.timestamp
            ));
        }
        
        // Create the message that should have been signed
        // Format: domain|timestamp|fee_amount (fee in SOV)
        let signed_message = format!("{}|{}|{}",
            simple_request.domain,
            simple_request.timestamp,
            user_provided_fee
        );
        
        // Decode the signature from hex
        let signature_bytes = hex::decode(&simple_request.signature)
            .map_err(|e| anyhow!("Invalid signature hex encoding: {}", e))?;
        
        // DEBUG: Log verification inputs
        info!(" DEBUG SIGNATURE VERIFICATION:");
        info!("   Message: {}", signed_message);
        info!("   Signature length: {} bytes", signature_bytes.len());
        info!("   Public key length: {} bytes", owner_identity.public_key.size());
        info!("   Expected public key length: 1312 (Dilithium2)");
        
        // Verify signature using owner's public key
        let is_valid = lib_crypto::verify_signature(
            signed_message.as_bytes(),
            &signature_bytes,
            &owner_identity.public_key.as_bytes()
        ).map_err(|e| anyhow!("Signature verification error: {}", e))?;
        
        info!(" DEBUG: Signature verification result: {}", is_valid);
        
        if !is_valid {
            error!(" AUTHORIZATION DENIED: Invalid signature for identity {}", owner_did);
            return Err(anyhow!(
                "Authorization denied: Invalid signature. You must sign the request with the private key for identity {}",
                owner_did
            ));
        }
        
        info!(" Signature verified successfully - owner authenticated");
        // ========== END SIGNATURE VERIFICATION ==========
        
        info!(" Registration fee: {} SOV (domain: {})",
            registration_fee_sov, simple_request.domain);

        // ========================================================================
        // SOV TOKEN PAYMENT FOR DOMAIN REGISTRATION
        // ========================================================================
        // Domain registration costs 10 SOV, paid via SOV token contract transfer
        // to the network treasury

        info!("💳 Processing SOV token payment for domain registration ({} SOV)", registration_fee_sov);

        // Resolve owner's Primary wallet for SOV balance lookup
        let owner_identity_hash = lib_blockchain::Hash::from_slice(&owner_identity.id.0);

        // Get SOV token contract and check balance
        let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();

        // Ensure SOV token contract exists (auto-migration for older blockchain data)
        {
            let mut blockchain = self.blockchain.write().await;
            if !blockchain.token_contracts.contains_key(&sov_token_id) {
                let sov_token = lib_blockchain::contracts::TokenContract::new_sov_native();
                blockchain.token_contracts.insert(sov_token_id, sov_token);
                info!("🪙 SOV token contract auto-initialized during domain registration");
            }
        }

        // Check SOV balance
        {
            let blockchain = self.blockchain.read().await;

            let owner_wallet_id = blockchain.wallet_registry.values()
                .find(|wallet| wallet.owner_identity_id.as_ref() == Some(&owner_identity_hash) && wallet.wallet_type == "Primary")
                .map(|wallet| wallet.wallet_id)
                .ok_or_else(|| anyhow!("Primary wallet not found for identity"))?;

            let owner_wallet_key = lib_blockchain::integration::crypto_integration::PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: owner_wallet_id.into(),
            };

            // Check if SOV token contract exists
            let sov_token = blockchain.token_contracts.get(&sov_token_id)
                .ok_or_else(|| anyhow!("SOV token contract not initialized. Network may still be bootstrapping."))?;

            // Check user's SOV balance
            let user_sov_balance = sov_token.balance_of(&owner_wallet_key);

            info!(" User SOV balance: {} SOV (need {} SOV)", user_sov_balance, registration_fee_sov);

            if user_sov_balance < registration_fee_sov {
                return Err(anyhow!(
                    "Insufficient SOV balance. Required: {} SOV, Available: {} SOV. \
                    You need SOV tokens to register domains.",
                    registration_fee_sov, user_sov_balance
                ));
            }
        }

        let fee_payment_tx_raw = simple_request
            .fee_payment_tx
            .as_deref()
            .ok_or_else(|| anyhow!(
                "fee_payment_tx is required. Submit a signed canonical TokenTransfer \
                 from owner Primary wallet to DAO treasury wallet for {} SOV.",
                registration_fee_sov
            ))?;
        let fee_tx_hash_hex = self
            .validate_and_submit_domain_fee_tx(&owner_identity, registration_fee_sov, fee_payment_tx_raw)
            .await?;

        info!(" Domain registration payment complete!");
        info!("   Fee paid: {} SOV", registration_fee_sov);
        info!("   Transaction ref: {}", fee_tx_hash_hex);

        // Prepare content mappings WITH RICH METADATA for storage
        let mut initial_content = HashMap::new();
        let mut content_hash_map = HashMap::new();
        let mut content_metadata_map = HashMap::new();  // NEW: Store rich metadata per route
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        
        for (path, mapping) in simple_request.content_mappings {
            // Decode base64 content to raw bytes for DHT storage
            let content_bytes = match general_purpose::STANDARD.decode(&mapping.content) {
                Ok(decoded) => {
                    info!("   Decoded base64 content for path: {}", path);
                    decoded
                }
                Err(e) => {
                    error!("   Failed to decode base64 content for path {}: {}", path, e);
                    // Fallback to treating as literal string (for backward compatibility)
                    mapping.content.as_bytes().to_vec()
                }
            };
            let content_hash = lib_crypto::hash_blake3(&content_bytes);
            let content_hash_hex = hex::encode(&content_hash[..8]); // Use first 8 bytes for shorter hash
            let content_hash_full = lib_crypto::Hash::from_bytes(&content_hash[..32]);
            
            info!("   Path: {} ({} bytes)", path, content_bytes.len());
            info!("     Hash: {}", content_hash_hex);
            info!("     Type: {}", mapping.content_type);
            
            // CREATE RICH METADATA for each content item
            let content_metadata = lib_storage::ContentMetadata {
                hash: content_hash_full.clone(),
                content_hash: content_hash_full.clone(),
                owner: owner_identity.clone(),
                size: content_bytes.len() as u64,
                content_type: mapping.content_type.clone(),
                filename: path.clone(),
                description: format!("Content for {}{}", simple_request.domain, path),
                checksum: content_hash_full.clone(),
                
                // Storage config optimized for Web4 content
                tier: lib_storage::StorageTier::Hot,  // Fast access for websites
                encryption: lib_storage::EncryptionLevel::None,  // Public by default
                access_pattern: lib_storage::AccessPattern::Frequent,
                replication_factor: 5,  // High availability for websites
                total_chunks: (content_bytes.len() / 65536 + 1) as u32,
                is_encrypted: false,
                is_compressed: false,
                
                // Public access for Web4 content
                access_control: vec![lib_storage::AccessLevel::Public],
                tags: vec![
                    "web4".to_string(),
                    simple_request.domain.clone(),
                    path.clone(),
                ],
                
                // Economics: 1 year Web4 hosting
                cost_per_day: 10,  // 10 SOV per day for web content
                created_at: current_time,
                last_accessed: current_time,
                access_count: 0,
                expires_at: Some(current_time + (365 * 86400)), // 1 year expiry
            };
            
            initial_content.insert(path.clone(), content_bytes);
            content_hash_map.insert(path.clone(), content_hash_hex);
            content_metadata_map.insert(path, content_metadata);  // Store metadata!
        }

        // Create domain metadata
        let metadata = DomainMetadata {
            title: simple_request.metadata.as_ref()
                .and_then(|m| m.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or(&simple_request.domain)
                .to_string(),
            description: simple_request.metadata.as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("Web4 website")
                .to_string(),
            category: "general".to_string(),
            tags: simple_request.metadata.as_ref()
                .and_then(|m| m.get("tags"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            public: true,
            economic_settings: DomainEconomicSettings {
                registration_fee: 10.0,
                renewal_fee: 5.0,
                transfer_fee: 2.0,
                hosting_budget: 100.0,
            },
        };

        // Register domain using domain registry
        let registration_result = self.domain_registry.register_domain_with_content(
            simple_request.domain.clone(),
            owner_identity.clone(),  // Clone since we need it later for wallet operations
            initial_content,
            metadata,
        ).await;

        let registration_response = registration_result
            .map_err(|e| anyhow!("Domain registration failed: {}", e))?;

        let total_fees = registration_response.fees_charged;
        info!(" Domain {} registered with {} SOV fees", simple_request.domain, total_fees);

        // Get the ACTUAL content mappings from domain registry (with correct DHT hashes)
        let actual_content_mappings = match self.name_resolver.resolve(&simple_request.domain).await {
            Ok(record) => record.content_mappings,
            Err(_) => content_hash_map.clone(),
        };

        info!(" Retrieved actual content mappings from DHT:");
        for (path, hash) in &actual_content_mappings {
            info!("   {} -> {}", path, hash);
        }

        // ========================================================================
        // NOTE: Domain registration fees are paid via canonical SOV TokenTransfer above.
        // Contract deployment handled separately from fee payment
        // ========================================================================
        let domain_tx_hash = Some(fee_tx_hash_hex);
        info!(" Web4 domain registration transaction completed: {:?}", domain_tx_hash);

        // Register content ownership with wallet using ACTUAL owner identity
        let wallet_manager_lock = self.wallet_content_manager.write().await;
        
        // Get primary wallet from owner's identity
        if let Some(primary_wallet) = owner_identity.wallet_manager.wallets.values().next() {
            let wallet_id = primary_wallet.id.clone();
            drop(wallet_manager_lock); // Release lock before async operations
            
            let mut wallet_manager = self.wallet_content_manager.write().await;
            
            // Register ownership for each content item in the domain
            for (path, metadata) in &content_metadata_map {
                if let Err(e) = wallet_manager.register_content_ownership(
                    metadata.content_hash.clone(),
                    wallet_id.clone(),
                    metadata,
                    0, // No purchase price for domain registration uploads
                ) {
                    error!("Failed to register content ownership for {}: {}", path, e);
                }
            }
            
            info!(" Registered {} content items to wallet {} for identity {}", 
                content_metadata_map.len(), wallet_id, owner_did);
        } else {
            drop(wallet_manager_lock);
            error!(" No wallet found for owner identity {}, content ownership not registered", owner_did);
        }

        // Create response
        let mut response = serde_json::json!({
            "success": true,
            "domain": simple_request.domain,
            "owner": simple_request.owner,
            "content_mappings": actual_content_mappings,  // Use actual DHT hashes from lookup
            "fees_charged": registration_response.fees_charged,
            "registered_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "message": "Domain registered successfully on Web4 blockchain"
        });

        // Add blockchain transaction hash if deployment succeeded
        if let Some(tx_hash) = domain_tx_hash {
            response["blockchain_transaction"] = serde_json::json!(tx_hash);
            response["contract_deployed"] = serde_json::json!(true);
        }

        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

        info!(" Domain {} registered successfully with {} SOV fees", simple_request.domain, total_fees);

        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// Register a domain using DeployManifest CID (from CLI deploy command)
    /// This is a simplified flow where content has already been uploaded
    async fn register_domain_from_manifest(&self, request: ManifestDomainRegistrationRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Processing manifest-based domain registration");
        info!(" Domain: {}", request.domain);
        info!(" DeployManifest CID: {}", request.deploy_manifest_cid);
        info!(" Owner: {}", request.owner);

        let manifest = self
            .load_and_verify_manifest(&request.domain, &request.deploy_manifest_cid)
            .await
            .map_err(|e| anyhow!("Manifest verification failed: {}", e))?;

        // BOUNDARY CODE: Accept DID as-is, use proper DID resolution
        let owner_did = if request.owner.starts_with("did:zhtp:") {
            request.owner.clone()
        } else {
            format!("did:zhtp:{}", request.owner)
        };

        // Look up owner identity using boundary-safe DID API
        let identity_mgr = self.identity_manager.read().await;
        let owner_identity = identity_mgr.get_identity_by_did(&owner_did)
            .ok_or_else(|| anyhow!(
                "Owner identity not found: {}. Register identity first.",
                owner_did
            ))?
            .clone();
        drop(identity_mgr);
        info!(" Verified owner identity: {}", owner_did);

        if owner_identity.did != manifest.author_did {
            return Err(anyhow!(
                "Manifest author DID does not match owner identity ({} != {})",
                manifest.author_did,
                owner_identity.did
            ));
        }

        const DOMAIN_REGISTRATION_FEE_SOV: u64 = 10;
        let user_provided_fee = request.fee.unwrap_or(DOMAIN_REGISTRATION_FEE_SOV);
        if user_provided_fee != DOMAIN_REGISTRATION_FEE_SOV {
            return Err(anyhow!(
                "Invalid fee: provided {} SOV, required exactly {} SOV for domain registration",
                user_provided_fee, DOMAIN_REGISTRATION_FEE_SOV
            ));
        }
        let fee_payment_tx_raw = request
            .fee_payment_tx
            .as_deref()
            .ok_or_else(|| anyhow!(
                "fee_payment_tx is required. Submit a signed canonical TokenTransfer \
                 from owner Primary wallet to DAO treasury wallet for {} SOV.",
                DOMAIN_REGISTRATION_FEE_SOV
            ))?;
        let fee_tx_hash_hex = self
            .validate_and_submit_domain_fee_tx(&owner_identity, DOMAIN_REGISTRATION_FEE_SOV, fee_payment_tx_raw)
            .await?;
        info!(" Manifest domain registration fee tx accepted: {}", fee_tx_hash_hex);

        // Register domain using manifest CID
        info!("Registering domain from manifest: {}", request.domain);

        // Create domain metadata
        let metadata = DomainMetadata {
            title: request.domain.clone(),
            description: format!("Domain registered via DeployManifest {}", request.deploy_manifest_cid),
            category: "website".to_string(),
            tags: vec!["web4".to_string(), "manifest".to_string()],
            public: true,
            economic_settings: DomainEconomicSettings {
                registration_fee: 10.0,
                renewal_fee: 5.0,
                transfer_fee: 2.0,
                hosting_budget: 100.0,
            },
        };

        // Create registration proof (simplified for manifest-based registration)
        let registration_proof = ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            lib_crypto::hash_blake3(&[
                owner_identity.id.0.as_slice(),
                request.domain.as_bytes(),
            ].concat()).to_vec(),
            owner_identity.id.0.to_vec(),
            owner_identity.id.0.to_vec(),
            None,
        );

        // Create domain registration request with deploy_manifest_cid
        // This will be converted to web4_manifest_cid during registration
        let domain_request = DomainRegistrationRequest {
            domain: request.domain.clone(),
            owner: owner_identity.clone(),
            duration_days: 365, // Default 1 year
            metadata,
            initial_content: HashMap::new(), // Content already uploaded via manifest
            registration_proof,
            deploy_manifest_cid: Some(request.deploy_manifest_cid.clone()),
        };

        // Register domain
        let registration_result = self.domain_registry.register_domain(domain_request).await
            .map_err(|e| anyhow!("Failed to register domain: {}", e))?;

        info!(" Domain {} registered with DeployManifest {}", request.domain, request.deploy_manifest_cid);

        let response = serde_json::json!({
            "status": "success",
            "domain": request.domain,
            "deploy_manifest_cid": request.deploy_manifest_cid,
            "owner": owner_did,
            "registration_id": registration_result.registration_id,
            "fees_charged": DOMAIN_REGISTRATION_FEE_SOV,
            "fee_payment_tx_hash": fee_tx_hash_hex,
            "message": "Domain registered successfully"
        });

        Ok(ZhtpResponse::success_with_content_type(
            serde_json::to_vec(&response)?,
            "application/json".to_string(),
            None,
        ))
    }

    /// Validates and submits a domain registration fee payment transaction.
    ///
    /// This function ensures the provided fee transaction is a properly signed canonical
    /// `TokenTransfer` from the owner's Primary wallet to the DAO treasury for the required
    /// SOV amount. It performs the following validations:
    ///
    /// * Transaction type must be `TokenTransfer`
    /// * Chain ID must be 0x03 (mainnet)
    /// * Token must be SOV (the canonical token)
    /// * Transfer amount must exactly match the required registration fee
    /// * Sender must be the owner's Primary wallet
    /// * Signature must match the Primary wallet's public key
    /// * Recipient must be the DAO treasury wallet
    ///
    /// If the transaction passes all validations and is not already confirmed or pending,
    /// it will be submitted to the blockchain's pending transaction pool.
    ///
    /// # Arguments
    ///
    /// * `owner_identity` - The identity of the domain owner
    /// * `registration_fee_sov` - The required registration fee in SOV
    /// * `fee_payment_tx_raw` - Hex-encoded serialized transaction
    ///
    /// # Returns
    ///
    /// Returns the transaction hash as a hex string on success, or an error if validation fails.
    async fn validate_and_submit_domain_fee_tx(
        &self,
        owner_identity: &ZhtpIdentity,
        registration_fee_sov: u64,
        fee_payment_tx_raw: &str,
    ) -> anyhow::Result<String> {
        let fee_payment_tx_bytes = hex::decode(fee_payment_tx_raw)
            .map_err(|_| anyhow!("Invalid fee_payment_tx hex encoding"))?;
        let fee_payment_tx: lib_blockchain::transaction::Transaction =
            bincode::deserialize(&fee_payment_tx_bytes)
                .map_err(|e| anyhow!("Invalid fee_payment_tx payload: {}", e))?;

        let fee_transfer = fee_payment_tx
            .token_transfer_data
            .as_ref()
            .ok_or_else(|| anyhow!("fee_payment_tx missing token_transfer_data"))?;
        if fee_payment_tx.transaction_type != lib_blockchain::TransactionType::TokenTransfer {
            return Err(anyhow!(
                "fee_payment_tx must use TransactionType::TokenTransfer"
            ));
        }
        if fee_payment_tx.chain_id != 0x03 {
            return Err(anyhow!(
                "fee_payment_tx must use chain_id 0x03, got {}",
                fee_payment_tx.chain_id
            ));
        }
        let is_sov = fee_transfer.token_id == lib_blockchain::contracts::utils::generate_lib_token_id()
            || fee_transfer.token_id == [0u8; 32];
        if !is_sov {
            return Err(anyhow!("fee_payment_tx must transfer SOV token"));
        }
        if fee_transfer.amount != registration_fee_sov as u128 {
            return Err(anyhow!(
                "fee_payment_tx amount mismatch: expected {} SOV, got {}",
                registration_fee_sov, fee_transfer.amount
            ));
        }

        let fee_tx_hash = fee_payment_tx.hash();
        let fee_tx_hash_hex = hex::encode(fee_tx_hash.as_bytes());

        let owner_identity_hash = lib_blockchain::Hash::from_slice(&owner_identity.id.0);
        {
            let blockchain = self.blockchain.read().await;
            let owner_wallet = blockchain.wallet_registry.values()
                .find(|wallet| wallet.owner_identity_id.as_ref() == Some(&owner_identity_hash) && wallet.wallet_type == "Primary")
                .ok_or_else(|| anyhow!("Primary wallet not found for identity"))?;
            if fee_transfer.from != owner_wallet.wallet_id.as_array() {
                return Err(anyhow!("fee_payment_tx sender wallet does not match owner Primary wallet"));
            }

            let owner_wallet_pubkey = lib_blockchain::integration::crypto_integration::PublicKey::new(
                owner_wallet.public_key.clone()
            );
            if fee_payment_tx.signature.public_key.key_id != owner_wallet_pubkey.key_id {
                return Err(anyhow!("fee_payment_tx signature does not match owner Primary wallet public key"));
            }

            let treasury_wallet_id = blockchain.get_dao_treasury_wallet_id()
                .ok_or_else(|| anyhow!("DAO treasury wallet is not configured"))?;
            let treasury_wallet_bytes = hex::decode(treasury_wallet_id)
                .map_err(|_| anyhow!("DAO treasury wallet id is malformed"))?;
            if treasury_wallet_bytes.len() != 32 {
                return Err(anyhow!("DAO treasury wallet id must be 32 bytes"));
            }
            let mut treasury_wallet = [0u8; 32];
            treasury_wallet.copy_from_slice(&treasury_wallet_bytes);
            if fee_transfer.to != treasury_wallet {
                return Err(anyhow!("fee_payment_tx recipient must be the DAO treasury wallet"));
            }

            let already_confirmed = blockchain.blocks.iter().any(|block| {
                block.transactions.iter().any(|tx| tx.hash() == fee_tx_hash)
            });
            let already_pending = blockchain.pending_transactions.iter().any(|tx| tx.hash() == fee_tx_hash);

            if !already_confirmed && !already_pending {
                drop(blockchain);
                let mut blockchain = self.blockchain.write().await;
                blockchain.add_pending_transaction(fee_payment_tx)
                    .map_err(|e| anyhow!("Failed to submit fee_payment_tx to mempool: {}", e))?;
            }
        }

        Ok(fee_tx_hash_hex)
    }

    /// Register a new Web4 domain
    pub async fn register_domain(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!("Processing Web4 domain registration request");

        // Parse request
        let api_request: ApiDomainRegistrationRequest = serde_json::from_slice(&request_body)
            .map_err(|e| anyhow!("Invalid domain registration request: {}", e))?;

        // Deserialize owner identity
        let owner_identity = self.deserialize_identity(&api_request.owner_identity)
            .map_err(|e| anyhow!("Invalid owner identity: {}", e))?;

        // Deserialize registration proof
        let registration_proof = self.deserialize_proof(&api_request.registration_proof)
            .map_err(|e| anyhow!("Invalid registration proof: {}", e))?;

        // Decode initial content from base64
        let mut initial_content = std::collections::HashMap::new();
        for (path, encoded_content) in api_request.initial_content {
            // Decode base64 content to raw bytes for DHT storage
            let content = match general_purpose::STANDARD.decode(&encoded_content) {
                Ok(decoded) => {
                    info!("Decoded base64 content for path: {}", path);
                    decoded
                }
                Err(e) => {
                    error!("Failed to decode base64 content for path {}: {}", path, e);
                    // Fallback to treating as literal string (for backward compatibility)
                    encoded_content.as_bytes().to_vec()
                }
            };
            initial_content.insert(path, content);
        }

        // Create domain metadata
        let metadata = DomainMetadata {
            title: api_request.title,
            description: api_request.description,
            category: api_request.category,
            tags: api_request.tags,
            public: api_request.public,
            economic_settings: DomainEconomicSettings {
                registration_fee: 10.0, // Will be calculated properly
                renewal_fee: 5.0,
                transfer_fee: 2.0,
                hosting_budget: 100.0,
            },
        };

        // Create registration request
        let registration_request = DomainRegistrationRequest {
            domain: api_request.domain.clone(),
            owner: owner_identity,
            duration_days: api_request.duration_days,
            metadata,
            initial_content,
            registration_proof,
            deploy_manifest_cid: None, // Auto-generate for non-manifest registration
        };

        // Process registration
        
        match self.domain_registry.register_domain(registration_request).await {
            Ok(response) => {
                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                info!(" Domain {} registered successfully", api_request.domain);
                
                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to register domain {}: {}", api_request.domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Domain registration failed: {}", e),
                ))
            }
        }
    }

    /// Get domain information
    pub async fn get_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract domain from path: /api/v1/web4/domains/{domain}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 6 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid domain lookup path".to_string(),
            ));
        }

        let domain = path_parts[5]; // ["", "api", "v1", "web4", "domains", "hello-world.zhtp"]
        info!(" Looking up Web4 domain: {}", domain);

        
        match self.name_resolver.resolve(domain).await {
            Ok(record) => {
                let owner_info = PublicOwnerInfo {
                    identity_hash: hex::encode(&record.owner.0[..16]),
                    registered_at: record.registered_at,
                    verified: true,
                    alias: None,
                };

                let response = DomainLookupResponse {
                    found: true,
                    record: None,
                    content_mappings: record.content_mappings,
                    owner_info: Some(owner_info),
                };

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to lookup domain {}: {}", domain, e);
                let response = DomainLookupResponse {
                    found: false,
                    record: None,
                    content_mappings: HashMap::new(),
                    owner_info: None,
                };
                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    /// List domains for an owner
    /// GET /api/v1/web4/domains?owner={did}
    pub async fn list_domains(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let owner = request
            .uri
            .splitn(2, '?')
            .nth(1)
            .and_then(|query| {
                query.split('&').find_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let value = parts.next()?;
                    if key == "owner" { Some(value) } else { None }
                })
            });
        let _owner = match owner {
            Some(value) if !value.is_empty() => value,
            _ => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Missing owner query parameter".to_string(),
                ));
            }
        };

        // NOTE: list_domains_by_owner requires iterating all persisted domains, which is not
        // yet implemented in the DomainRegistry. This endpoint is reserved for future use.
        // For now, we return a not-implemented error rather than silently returning empty results,
        // which would confuse API clients expecting functional behavior.
        return Err(anyhow!(
            "The list_domains_by_owner endpoint is not yet implemented. \
             This feature requires registry support for domain enumeration by owner. \
             Please use domain lookup endpoints for specific domains or track deployments \
             in your application state."
        ));
    }

    /// Transfer domain to new owner
    pub async fn transfer_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!(" Processing Web4 domain transfer request");

        // Parse request
        let api_request: ApiDomainTransferRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid domain transfer request: {}", e))?;

        // Deserialize owner identities
        let from_owner = self.deserialize_identity(&api_request.from_owner)
            .map_err(|e| anyhow!("Invalid from_owner identity: {}", e))?;
        let to_owner = self.deserialize_identity(&api_request.to_owner)
            .map_err(|e| anyhow!("Invalid to_owner identity: {}", e))?;

        // Create transfer proof (simplified for now)
        let transfer_proof = lib_proofs::ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            lib_crypto::hash_blake3(&[
                from_owner.id.0.as_slice(),
                to_owner.id.0.as_slice(),
                api_request.domain.as_bytes(),
            ].concat()).to_vec(),
            from_owner.id.0.to_vec(),
            to_owner.id.0.to_vec(),
            None,
        );

        match self.domain_registry.transfer_domain(
            &api_request.domain,
            &from_owner,
            &to_owner,
            transfer_proof,
        ).await {
            Ok(success) => {
                let response = serde_json::json!({
                    "success": success,
                    "domain": api_request.domain,
                    "transferred_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                });

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                if success {
                    info!(" Domain {} transferred successfully", api_request.domain);
                }

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to transfer domain {}: {}", api_request.domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Domain transfer failed: {}", e),
                ))
            }
        }
    }

    /// Release/delete domain
    pub async fn release_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("🗑️ Processing Web4 domain release request");

        // Parse request
        let api_request: ApiDomainReleaseRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid domain release request: {}", e))?;

        // BOUNDARY: Accept owner_identity from request and look it up in identity manager
        // This verifies the identity exists in the system
        let normalized_did = if api_request.owner_identity.starts_with("did:zhtp:") {
            api_request.owner_identity.clone()
        } else {
            format!("did:zhtp:{}", api_request.owner_identity)
        };

        let identity_mgr = self.identity_manager.read().await;
        let owner_identity = identity_mgr.get_identity_by_did(&normalized_did)
            .ok_or_else(|| anyhow!(
                "Owner identity not found: {}. Identity must be registered first.",
                normalized_did
            ))?
            .clone();
        drop(identity_mgr);

        info!(" Verified owner identity for domain release: {}", normalized_did);

        match self.domain_registry.release_domain(&api_request.domain, &owner_identity).await {
            Ok(success) => {
                let response = serde_json::json!({
                    "success": success,
                    "domain": api_request.domain,
                    "released_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                });

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                if success {
                    info!(" Domain {} released successfully", api_request.domain);
                }

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to release domain {}: {}", api_request.domain, e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Domain release failed: {}", e),
                ))
            }
        }
    }

    /// Deserialize identity from string (for compatibility with older code)
    /// DEPRECATED: Use identity manager lookup instead
    pub fn deserialize_identity(&self, _identity_str: &str) -> Result<ZhtpIdentity, String> {
        // This is a fallback for legacy code - should use identity manager lookup instead
        // Creates a placeholder human identity (should not be used for ownership verification)
        ZhtpIdentity::new_unified(
            lib_identity::types::IdentityType::Human,
            None,
            None,
            "placeholder-user",
            None,
        ).map_err(|e| format!("Failed to create identity: {}", e))
    }

    /// Deserialize zero-knowledge proof from string (simplified for now)
    pub fn deserialize_proof(&self, proof_str: &str) -> Result<ZeroKnowledgeProof, String> {
        // In production, this would properly deserialize from JSON/base64
        // For now, create a simple proof from the string
        Ok(ZeroKnowledgeProof::new(
            "Plonky2".to_string(),
            proof_str.as_bytes().to_vec(),
            proof_str.as_bytes().to_vec(),
            proof_str.as_bytes().to_vec(),
            None,
        ))
    }

    // ============================================================================
    // deploy_web4_contract() function REMOVED
    // 
    // This function previously created improper "system transactions" with:
    // - Empty inputs (bypasses UTXO validation)
    // - Zero fees (no economic cost = spam risk)
    // - Mock signatures (hash pretending to be Dilithium2 signature)
    // - chain_id=0x03 (explicit validation bypass flag)
    //
    // This was architecturally wrong for user-initiated actions. System transactions
    // should ONLY be used for protocol-level actions:
    // - Genesis block (one-time network bootstrap at height 0)
    // - Block rewards (validator mining compensation)
    // - UBI distributions (scheduled protocol distributions)
    //
    // Web4 contract deployment is now handled as an OUTPUT in the proper
    // UTXO-based payment transaction above, with:
    // - Real UTXO inputs (proves ownership)
    // - Real fees (economic spam protection)
    // - Real Dilithium2 signatures (cryptographic proof)
    // - Full on-chain validation (security)
    // ============================================================================

    // ============================================================================
    // Domain Versioning API (Addendum Phase 5)
    // ============================================================================

    /// Get domain status with version info
    /// GET /api/v1/web4/domains/status/{domain}
    pub async fn get_domain_status(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract domain from path: /api/v1/web4/domains/status/{domain}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 7 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid domain status path".to_string(),
            ));
        }

        let domain = path_parts[6];
        info!(" Getting status for domain: {}", domain);


        match self.domain_registry.get_domain_status(domain).await {
            Ok(status) => {
                // MIGRATION: Include both old and new field names for backwards compatibility with CLI
                let response = serde_json::json!({
                    "found": status.found,
                    "domain": status.domain,
                    "version": status.version,
                    "current_web4_manifest_cid": status.current_web4_manifest_cid,
                    "current_manifest_cid": status.current_web4_manifest_cid,  // Backwards compat for CLI
                    "owner_did": status.owner_did,
                    "updated_at": status.updated_at,
                    "expires_at": status.expires_at,
                    "build_hash": status.build_hash,
                });

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to get domain status: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get domain status: {}", e),
                ))
            }
        }
    }

    /// Get domain version history
    /// GET /api/v1/web4/domains/history/{domain}
    pub async fn get_domain_history(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Extract domain from path: /api/v1/web4/domains/history/{domain}
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 7 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid domain history path".to_string(),
            ));
        }

        // Extract domain and remove any query parameters
        let domain_with_query = path_parts[6];
        let domain = domain_with_query.split('?').next().unwrap_or(domain_with_query);

        // Parse optional limit from query string
        let limit = request.uri
            .split("limit=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(50);

        info!(" Getting history for domain: {} (limit: {})", domain, limit);


        match self.domain_registry.get_domain_history(domain, limit).await {
            Ok(history) => {
                let response_json = serde_json::to_vec(&history)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to get domain history: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    format!("Domain not found: {}", e),
                ))
            }
        }
    }

    /// Update domain with new manifest (atomic compare-and-swap)
    /// POST /api/v1/web4/domains/update
    pub async fn update_domain_version(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!(" Processing domain update request");

        // Parse update request
        let update_request: lib_network::web4::DomainUpdateRequest =
            serde_json::from_slice(&request.body)
                .map_err(|e| anyhow!("Invalid domain update request: {}", e))?;

        info!(
            " Updating domain {} (expected CID: {}...)",
            update_request.domain,
            &update_request.expected_previous_manifest_cid[..16.min(update_request.expected_previous_manifest_cid.len())]
        );

        let status = self.domain_registry
            .get_domain_status(&update_request.domain)
            .await
            .map_err(|e| anyhow!("Failed to fetch domain status: {}", e))?;

        let owner_did = if status.owner_did.is_empty() {
            return Err(anyhow!("Domain owner not found"));
        } else {
            &status.owner_did
        };

        if update_request.signature.is_empty() {
            return Err(anyhow!("Update signature missing"));
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();
        let time_diff = if current_time > update_request.timestamp {
            current_time - update_request.timestamp
        } else {
            update_request.timestamp - current_time
        };
        if time_diff > 300 {
            return Err(anyhow!(
                "Update request expired. Timestamp difference: {} seconds (max 300). Current: {}, Request: {}",
                time_diff, current_time, update_request.timestamp
            ));
        }

        let signed_message = format!(
            "{}|{}|{}|{}",
            update_request.domain,
            update_request.expected_previous_manifest_cid,
            update_request.new_manifest_cid,
            update_request.timestamp
        );
        let signature_bytes = hex::decode(&update_request.signature)
            .map_err(|e| anyhow!("Invalid update signature hex encoding: {}", e))?;

        let identity_mgr = self.identity_manager.read().await;
        let owner_identity = identity_mgr
            .get_identity_by_did(owner_did)
            .ok_or_else(|| anyhow!("Owner identity not found: {}", owner_did))?;

        let is_valid = lib_crypto::verify_signature(
            signed_message.as_bytes(),
            &signature_bytes,
            &owner_identity.public_key.as_bytes(),
        )
        .map_err(|e| anyhow!("Signature verification error: {}", e))?;

        if !is_valid {
            return Err(anyhow!("Invalid update signature"));
        }

        let manifest = self
            .load_and_verify_manifest(&update_request.domain, &update_request.new_manifest_cid)
            .await
            .map_err(|e| anyhow!("Manifest verification failed: {}", e))?;

        // CANONICALIZE: convert the CLI DeployManifest (provenance) into a canonical Web4Manifest
        // and store its CID as the runtime-truth pointer.
        let mut manifest_files = std::collections::HashMap::new();
        for entry in &manifest.files {
            manifest_files.insert(
                entry.path.clone(),
                lib_network::web4::ManifestFile {
                    cid: entry.hash.clone(),
                    size: entry.size,
                    content_type: entry.mime_type.clone(),
                    hash: entry.hash.clone(),
                },
            );
        }

        let new_version = status.version.saturating_add(1);
        let previous_manifest = if status.version == 0 {
            None
        } else {
            Some(status.current_web4_manifest_cid.clone())
        };

        let web4_manifest = lib_network::web4::Web4Manifest {
            domain: update_request.domain.clone(),
            version: new_version,
            previous_manifest,
            build_hash: hex::encode(manifest.root_hash),
            files: manifest_files,
            created_at: current_time,
            created_by: manifest.author_did.clone(),
            message: Some(format!(
                "Domain {} updated with {} files",
                update_request.domain,
                manifest.files.len()
            )),
        };

        let canonical_web4_manifest_cid = self
            .domain_registry
            .store_manifest(web4_manifest)
            .await
            .map_err(|e| anyhow!("Failed to store canonical Web4Manifest: {}", e))?;

        let mut canonical_update_request = update_request.clone();
        canonical_update_request.new_manifest_cid = canonical_web4_manifest_cid;

        match self.domain_registry.update_domain(canonical_update_request).await {
            Ok(response) => {
                if response.success {
                    let version = response.new_version;
                    let cid_preview = &response.new_manifest_cid[..16.min(response.new_manifest_cid.len())];
                    info!(
                        " Domain updated to v{} (CID: {}...)",
                        version,
                        cid_preview
                    );
                } else {
                    warn!(
                        " Domain update failed: {}",
                        response.error.as_deref().unwrap_or("Unknown error")
                    );
                }

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to update domain: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Domain update failed: {}", e),
                ))
            }
        }
    }

    async fn load_and_verify_manifest(&self, domain: &str, manifest_cid: &str) -> anyhow::Result<DeployManifest> {
        let manifest_bytes = self.domain_registry.get_content_by_cid(manifest_cid)
            .await
            .map_err(|e| anyhow!("Failed to fetch manifest: {}", e))?
            .ok_or_else(|| anyhow!("Manifest content not found for CID {}", manifest_cid))?;
        let manifest: DeployManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| anyhow!("Invalid manifest JSON: {}", e))?;

        if manifest.domain != domain {
            return Err(anyhow!(
                "Manifest domain mismatch: expected {}, got {}",
                domain,
                manifest.domain
            ));
        }

        ensure_canonical_file_list(&manifest.files)?;
        let computed_hash = compute_root_hash(&manifest.files);
        if computed_hash != manifest.root_hash {
            return Err(anyhow!("Manifest root hash mismatch"));
        }

        if manifest.signature.is_empty() {
            return Err(anyhow!("Manifest signature missing"));
        }

        let unsigned_bytes = manifest_unsigned_bytes(&manifest)?;
        let signature_bytes = general_purpose::STANDARD
            .decode(&manifest.signature)
            .map_err(|e| anyhow!("Invalid manifest signature encoding: {}", e))?;

        let identity_mgr = self.identity_manager.read().await;
        let author_identity = identity_mgr
            .get_identity_by_did(&manifest.author_did)
            .ok_or_else(|| anyhow!("Author identity not found: {}", manifest.author_did))?;

        let is_valid = lib_crypto::verify_signature(
            &unsigned_bytes,
            &signature_bytes,
            &author_identity.public_key.dilithium_pk,
        ).map_err(|e| anyhow!("Signature verification error: {}", e))?;

        if !is_valid {
            return Err(anyhow!("Invalid manifest signature"));
        }

        Ok(manifest)
    }

    /// Resolve domain to current manifest
    /// POST /api/v1/web4/domains/resolve
    pub async fn resolve_domain_manifest(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct ResolveRequest {
            domain: String,
            version: Option<u64>,
        }

        let resolve_req: ResolveRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid resolve request: {}", e))?;

        info!("🔍 resolve_domain_manifest: Resolving '{}' (version: {:?})", resolve_req.domain, resolve_req.version);


        // Get domain status
        let status = self.domain_registry.get_domain_status(&resolve_req.domain).await
            .map_err(|e| anyhow!("Domain not found: {}", e))?;

        info!("🔍 resolve_domain_manifest: status.found={} for '{}'", status.found, resolve_req.domain);

        if !status.found {
            warn!("❌ resolve_domain_manifest: Domain '{}' NOT FOUND in registry", resolve_req.domain);
            return Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Domain not found: {}", resolve_req.domain),
            ));
        }

        // If specific version requested, look up that manifest
        // CANONICAL: Always use web4_manifest_cid for resolution
        let web4_manifest_cid = if let Some(version) = resolve_req.version {
            let history = self.domain_registry.get_domain_history(&resolve_req.domain, 1000).await
                .map_err(|e| anyhow!("Failed to get history: {}", e))?;

            history.versions.iter()
                .find(|v| v.version == version)
                .map(|v| v.web4_manifest_cid.clone())
                .unwrap_or_else(|| "manifest-not-found".to_string())
        } else {
            status.current_web4_manifest_cid.clone()
        };

        // Debug: load manifest details to log what will be served
        if let Ok(Some(manifest)) = self.domain_registry.get_manifest(&resolve_req.domain, &web4_manifest_cid).await {
            let manifest_cid_computed = manifest.compute_cid();
            let files_count = manifest.files.len();
            info!(
                domain = %manifest.domain,
                version = manifest.version,
                previous_manifest = manifest.previous_manifest.as_deref().unwrap_or("none"),
                build_hash = %manifest.build_hash,
                files = files_count,
                manifest_cid = %manifest_cid_computed,
                requested_cid = %web4_manifest_cid,
                "resolve_domain_manifest: serving manifest"
            );
        }

        let response = serde_json::json!({
            "domain": resolve_req.domain,
            "version": resolve_req.version.unwrap_or(status.version),
            "web4_manifest_cid": web4_manifest_cid,
            "owner_did": status.owner_did,
            "updated_at": status.updated_at,
        });

        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// Rollback domain to previous version
    /// POST /api/v1/web4/domains/{domain}/rollback
    pub async fn rollback_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        #[derive(Deserialize)]
        struct RollbackRequest {
            to_version: u64,
            signature: Option<String>,
        }

        // Extract domain from path
        let path_parts: Vec<&str> = request.uri.split('/').collect();
        if path_parts.len() < 7 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Invalid rollback path".to_string(),
            ));
        }

        let domain = path_parts[5]; // /api/v1/web4/domains/{domain}/rollback

        let rollback_req: RollbackRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid rollback request: {}", e))?;

        info!(" Rolling back domain {} to version {}", domain, rollback_req.to_version);

        // TODO: Verify signature matches domain owner
        let owner_did = request.headers.get("x-owner-did")
            .unwrap_or_else(|| "anonymous".to_string());


        match self.domain_registry.rollback_domain(domain, rollback_req.to_version, &owner_did).await {
            Ok(response) => {
                if response.success {
                    info!(
                        " Domain {} rolled back to v{} (new version: v{})",
                        domain,
                        rollback_req.to_version,
                        response.new_version
                    );
                }

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to rollback domain: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Rollback failed: {}", e),
                ))
            }
        }
    }

    /// Admin: migrate legacy domain records to the latest format
    pub async fn migrate_domains(&self, _request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Running domain migration");

        match self.domain_registry.migrate_domains().await {
            Ok(count) => {
                let response = serde_json::json!({
                    "success": true,
                    "migrated": count,
                });

                let response_json = serde_json::to_vec(&response)
                    .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

                Ok(ZhtpResponse::success_with_content_type(
                    response_json,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Domain migration failed: {}", e);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Domain migration failed: {}", e),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use lib_blockchain::contracts::TokenContract;
    use lib_blockchain::contracts::utils::generate_lib_token_id;
    use lib_blockchain::integration::crypto_integration::{PublicKey as BcPublicKey, Signature as BcSignature, SignatureAlgorithm as BcSignatureAlgorithm};
    use lib_blockchain::transaction::{TokenTransferData, Transaction, WalletTransactionData};
    use lib_identity::IdentityManager;
    use lib_identity::types::IdentityType;
    use lib_network::storage_stub::UnifiedStorage;
    use lib_network::web4::{ContentPublisher, DomainRegistry};
    use serde_json::json;
    use std::collections::HashMap as StdHashMap;
    use std::sync::{Arc, RwLock as StdRwLock};
    use tokio::sync::RwLock;

    #[derive(Clone, Default)]
    struct TestStorage {
        domains: Arc<StdRwLock<StdHashMap<String, Vec<u8>>>>,
        manifests: Arc<StdRwLock<StdHashMap<String, Vec<u8>>>>,
    }

    #[async_trait]
    impl UnifiedStorage for TestStorage {
        async fn store_domain_record(&self, domain: &str, data: Vec<u8>) -> anyhow::Result<()> {
            self.domains.write().unwrap().insert(domain.to_string(), data);
            Ok(())
        }

        async fn load_domain_record(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.domains.read().unwrap().get(domain).cloned())
        }

        async fn delete_domain_record(&self, domain: &str) -> anyhow::Result<()> {
            self.domains.write().unwrap().remove(domain);
            Ok(())
        }

        async fn list_domain_records(&self) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
            Ok(self
                .domains
                .read()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }

        async fn store_manifest(&self, domain: &str, manifest_data: Vec<u8>) -> anyhow::Result<()> {
            self.manifests
                .write()
                .unwrap()
                .insert(domain.to_string(), manifest_data);
            Ok(())
        }

        async fn load_manifest(&self, domain: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.manifests.read().unwrap().get(domain).cloned())
        }

        fn is_stub(&self) -> bool {
            false
        }
    }

    fn wallet_data(
        wallet_id: [u8; 32],
        wallet_type: &str,
        owner_identity_id: Option<lib_blockchain::Hash>,
        public_key: Vec<u8>,
    ) -> WalletTransactionData {
        WalletTransactionData {
            wallet_id: lib_blockchain::Hash::new(wallet_id),
            wallet_type: wallet_type.to_string(),
            wallet_name: format!("{}-wallet", wallet_type),
            alias: None,
            public_key,
            owner_identity_id,
            seed_commitment: lib_blockchain::Hash::zero(),
            created_at: 1_700_000_000,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        }
    }

    fn fee_payment_tx(
        signer: BcPublicKey,
        signer_private: lib_crypto::PrivateKey,
        from_wallet: [u8; 32],
        to_wallet: [u8; 32],
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction::new_token_transfer_with_chain_id(
            0x03,
            TokenTransferData {
                token_id: generate_lib_token_id(),
                from: from_wallet,
                to: to_wallet,
                amount: amount as u128,
                nonce,
            },
            BcSignature {
                signature: vec![],
                public_key: signer.clone(),
                algorithm: BcSignatureAlgorithm::Dilithium5,
                timestamp: 0,
            },
            Vec::new(),
        );
        // Mempool stateful validator currently enforces minimum fee for non-system txs,
        // including TokenTransfer in this path.
        tx.fee = 1_000;

        let keypair = lib_crypto::KeyPair {
            public_key: signer,
            private_key: signer_private,
        };
        let sign = |tx: &mut Transaction| {
            let signing_hash = tx.signing_hash();
            let sig = lib_crypto::sign_message(&keypair, signing_hash.as_bytes())
                .expect("fee tx should sign");
            tx.signature.signature = sig.signature;
            tx.signature.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be valid")
                .as_secs();
        };
        sign(&mut tx);

        // Ensure fee meets current minimum based on signed transaction size.
        let min_fee = lib_blockchain::transaction::creation::utils::calculate_minimum_fee(tx.size());
        if tx.fee < min_fee {
            tx.fee = min_fee;
            sign(&mut tx);
        }
        tx
    }

    async fn setup_handler() -> anyhow::Result<(Web4Handler, lib_identity::ZhtpIdentity, [u8; 32], [u8; 32], lib_crypto::PrivateKey)> {
        let storage: Arc<dyn UnifiedStorage> = Arc::new(TestStorage::default());
        let registry = Arc::new(DomainRegistry::new(storage.clone()).await?);
        let publisher = Arc::new(ContentPublisher::new(registry.clone(), storage.clone()));

        let owner_identity = lib_identity::ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "domain-fee-test-owner",
            None,
        )?;

        let mut identity_manager = IdentityManager::new();
        identity_manager.add_identity(owner_identity.clone());
        let identity_manager = Arc::new(RwLock::new(identity_manager));

        let mut blockchain = lib_blockchain::Blockchain::new()?;
        let owner_wallet_id = [0x11u8; 32];
        let treasury_wallet_id = [0x22u8; 32];
        let owner_identity_hash = lib_blockchain::Hash::from_slice(&owner_identity.id.0);

        // Set wallet public key deterministically for fee tx signer check.
        let owner_wallet_pk = owner_identity.public_key.dilithium_pk.clone();
        blockchain.wallet_registry.insert(
            hex::encode(owner_wallet_id),
            wallet_data(
                owner_wallet_id,
                "Primary",
                Some(owner_identity_hash),
                owner_wallet_pk.clone(),
            ),
        );
        blockchain.wallet_registry.insert(
            hex::encode(treasury_wallet_id),
            wallet_data(treasury_wallet_id, "Treasury", None, vec![8u8; 32]),
        );
        blockchain.set_dao_treasury_wallet(hex::encode(treasury_wallet_id))?;

        // Ensure owner has enough SOV for the pre-validation balance check.
        let mut sov = TokenContract::new_sov_native();
        let owner_wallet_key = BcPublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: owner_wallet_id,
        };
        sov.mint(&owner_wallet_key, 100).unwrap();
        blockchain.token_contracts.insert(generate_lib_token_id(), sov);

        let blockchain = Arc::new(RwLock::new(blockchain));
        let owner_private = owner_identity.private_key.clone().expect("test identity should include private key");
        let handler = Web4Handler::new_with_registry(
            registry,
            publisher,
            identity_manager,
            blockchain,
        )
        .await?;

        Ok((handler, owner_identity, owner_wallet_id, treasury_wallet_id, owner_private))
    }

    fn sign_simple_registration(identity: &lib_identity::ZhtpIdentity, domain: &str, timestamp: u64, fee: u64) -> String {
        let message = format!("{}|{}|{}", domain, timestamp, fee);
        let keypair = lib_crypto::KeyPair {
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone().expect("test identity must have private key"),
        };
        let sig = lib_crypto::sign_message(&keypair, message.as_bytes())
            .expect("signature should be generated");
        hex::encode(sig.signature)
    }

    fn simple_registration_request(
        owner_identity: &lib_identity::ZhtpIdentity,
        domain: &str,
        html_content: &str,
        fee_payment_tx: &Transaction,
    ) -> anyhow::Result<serde_json::Value> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(json!({
            "domain": domain,
            "owner": owner_identity.did,
            "content_mappings": {
                "/": {
                    "content": base64::engine::general_purpose::STANDARD.encode(html_content),
                    "content_type": "text/html"
                }
            },
            "signature": sign_simple_registration(owner_identity, domain, timestamp, 10),
            "timestamp": timestamp,
            "fee": 10,
            "fee_payment_tx": hex::encode(bincode::serialize(fee_payment_tx)?)
        }))
    }
    #[tokio::test]
    async fn register_domain_accepts_valid_fee_payment_tx() -> anyhow::Result<()> {
        let (handler, owner_identity, owner_wallet_id, treasury_wallet_id, owner_private) = setup_handler().await?;
        let fee_signer = BcPublicKey::new(owner_identity.public_key.dilithium_pk.clone());
        let tx = fee_payment_tx(fee_signer, owner_private, owner_wallet_id, treasury_wallet_id, 10, 0);
        let tx_hash_hex = hex::encode(tx.hash().as_bytes());
        let request =
            simple_registration_request(&owner_identity, "valid-fee.zhtp", "<html>ok</html>", &tx)?;

        let response = handler.register_domain_simple(serde_json::to_vec(&request)?).await?;
        assert_eq!(response.status, ZhtpStatus::Ok);
        let body: serde_json::Value = serde_json::from_slice(&response.body)?;
        assert_eq!(body["success"], serde_json::Value::Bool(true));
        assert_eq!(body["blockchain_transaction"], serde_json::Value::String(tx_hash_hex.clone()));

        let blockchain = handler.blockchain.read().await;
        let found_in_mempool = blockchain
            .pending_transactions
            .iter()
            .any(|pending| hex::encode(pending.hash().as_bytes()) == tx_hash_hex);
        assert!(found_in_mempool, "fee tx should be submitted to mempool");

        Ok(())
    }

    #[tokio::test]
    async fn register_domain_rejects_invalid_fee_payment_tx_amount() -> anyhow::Result<()> {
        let (handler, owner_identity, owner_wallet_id, treasury_wallet_id, owner_private) = setup_handler().await?;
        let fee_signer = BcPublicKey::new(owner_identity.public_key.dilithium_pk.clone());
        let tx = fee_payment_tx(fee_signer, owner_private, owner_wallet_id, treasury_wallet_id, 9, 0);
        let request = simple_registration_request(
            &owner_identity,
            "invalid-fee.zhtp",
            "<html>bad</html>",
            &tx,
        )?;

        let result = handler.register_domain_simple(serde_json::to_vec(&request)?).await;
        assert!(result.is_err(), "invalid fee tx amount should be rejected");
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("amount mismatch"), "unexpected error: {}", err);

        Ok(())
    }
}
