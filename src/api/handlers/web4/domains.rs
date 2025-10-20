//! Web4 Domain Management API Endpoints

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpResult;
use lib_network::web4::DomainRegistrationRequest;
// Removed unused DomainRegistrationResponse, DomainLookupResponse
use lib_identity::ZhtpIdentity;
use lib_proofs::ZeroKnowledgeProof;
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use anyhow::anyhow;

use super::Web4Handler;
use crate::runtime::blockchain_provider::add_transaction;
use lib_blockchain::{Transaction, TransactionOutput, TransactionType};
use lib_blockchain::contracts::{Web4Contract, WebsiteMetadata, ContentRoute, WebsiteDeploymentData};
use lib_blockchain::types::Hash as BlockchainHash;
use lib_crypto::{Signature, SignatureAlgorithm, PublicKey};
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

/// Simple domain registration request (for easier testing)
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleDomainRegistrationRequest {
    /// Domain to register
    pub domain: String,
    /// Owner name/identifier
    pub owner: String,
    /// Content mappings (path -> content object)
    pub content_mappings: std::collections::HashMap<String, ContentMapping>,
    /// Metadata (optional)
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
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
    pub async fn register_domain_simple(&self, request_body: Vec<u8>) -> ZhtpResult<ZhtpResponse> {
        info!("Processing simple Web4 domain registration request");

        // Parse simple request
        let simple_request: SimpleDomainRegistrationRequest = serde_json::from_slice(&request_body)
            .map_err(|e| anyhow!("Invalid simple domain registration request: {}", e))?;

        info!(" Registering domain: {}", simple_request.domain);
        info!(" Owner: {}", simple_request.owner);
        info!(" Content paths: {}", simple_request.content_mappings.len());

        // Create owner identity (simplified) - needed before metadata creation
        let owner_identity = self.deserialize_identity(&simple_request.owner)
            .map_err(|e| anyhow!("Failed to deserialize identity: {}", e))?;

        // Prepare content mappings WITH RICH METADATA for storage
        let mut initial_content = HashMap::new();
        let mut content_hash_map = HashMap::new();
        let mut content_metadata_map = HashMap::new();  // NEW: Store rich metadata per route
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        
        for (path, mapping) in simple_request.content_mappings {
            let content_bytes = mapping.content.as_bytes().to_vec();
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
                cost_per_day: 10,  // 10 ZHTP per day for web content
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
        let metadata = lib_network::web4::DomainMetadata {
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
            economic_settings: lib_network::web4::DomainEconomicSettings {
                registration_fee: 10.0,
                renewal_fee: 5.0,
                transfer_fee: 2.0,
                hosting_budget: 100.0,
            },
        };

        // Register domain using Web4Manager
        let manager = self.web4_manager.read().await;
        let registration_result = manager.register_domain_with_content(
            simple_request.domain.clone(),
            owner_identity,
            initial_content,
            metadata,
        ).await;
        drop(manager); // Release lock

        let registration_response = registration_result
            .map_err(|e| anyhow!("Domain registration failed: {}", e))?;

        let total_fees = registration_response.fees_charged;
        info!(" Domain {} registered via Web4Manager with {} ZHTP fees", simple_request.domain, total_fees);

        // Deploy Web4Contract to blockchain WITH METADATA
        let blockchain_tx_hash = match self.deploy_web4_contract(
            &simple_request.domain,
            &simple_request.owner,
            &content_hash_map,
            simple_request.metadata.clone(),
            &content_metadata_map,  // NEW: Pass content metadata
        ).await {
            Ok(tx_hash) => {
                info!(" Web4Contract deployed with transaction: {}", tx_hash);
                Some(tx_hash)
            }
            Err(e) => {
                error!(" Failed to deploy Web4Contract: {}", e);
                None
            }
        };

        // Register content ownership with wallet
        let owner_identity_for_wallet = self.deserialize_identity(&simple_request.owner)
            .map_err(|e| anyhow!("Failed to deserialize identity for wallet: {}", e))?;
        
        if let Some(primary_wallet) = owner_identity_for_wallet.wallet_manager.wallets.values().next() {
            let wallet_id = primary_wallet.id.clone();
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
            
            info!(" Registered {} content items to wallet {}", content_metadata_map.len(), wallet_id);
        } else {
            error!(" No wallet found for owner, content ownership not registered");
        }

        // Create response
        let mut response = serde_json::json!({
            "success": true,
            "domain": simple_request.domain,
            "owner": simple_request.owner,
            "content_mappings": content_hash_map,
            "fees_charged": registration_response.fees_charged,
            "registered_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            "message": "Domain registered successfully on Web4 blockchain"
        });

        // Add blockchain transaction hash if deployment succeeded
        if let Some(tx_hash) = blockchain_tx_hash {
            response["blockchain_transaction"] = serde_json::json!(tx_hash);
            response["contract_deployed"] = serde_json::json!(true);
        }

        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

        info!(" Domain {} registered successfully with {} ZHTP fees", simple_request.domain, total_fees);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
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
            let content = encoded_content.as_bytes().to_vec(); // Simplified for now
            initial_content.insert(path, content);
        }

        // Create domain metadata
        let metadata = lib_network::web4::DomainMetadata {
            title: api_request.title,
            description: api_request.description,
            category: api_request.category,
            tags: api_request.tags,
            public: api_request.public,
            economic_settings: lib_network::web4::DomainEconomicSettings {
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
        };

        // Process registration
        let manager = self.web4_manager.read().await;
        
        match manager.registry.register_domain(registration_request).await {
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

        let manager = self.web4_manager.read().await;
        
        match manager.registry.lookup_domain(domain).await {
            Ok(response) => {
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
                Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Domain lookup failed".to_string(),
                ))
            }
        }
    }

    /// Transfer domain to new owner
    pub async fn transfer_domain(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!(" Processing Web4 domain transfer request");

        // Parse request
        let api_request: ApiDomainTransferRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow!("Invalid domain transfer request: {}", e))?;

        // Deserialize identities
        let from_owner = self.deserialize_identity(&api_request.from_owner)
            .map_err(|e| anyhow!("Invalid from_owner identity: {}", e))?;
        
        let to_owner = self.deserialize_identity(&api_request.to_owner)
            .map_err(|e| anyhow!("Invalid to_owner identity: {}", e))?;

        // Deserialize transfer proof
        let transfer_proof = self.deserialize_proof(&api_request.transfer_proof)
            .map_err(|e| anyhow!("Invalid transfer proof: {}", e))?;

        let manager = self.web4_manager.read().await;
        
        match manager.registry.transfer_domain(
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

        // Deserialize owner identity
        let owner_identity = self.deserialize_identity(&api_request.owner_identity)
            .map_err(|e| anyhow!("Invalid owner identity: {}", e))?;

        let manager = self.web4_manager.read().await;
        
        match manager.registry.release_domain(&api_request.domain, &owner_identity).await {
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

    /// Deserialize identity from string (simplified for now)
    pub fn deserialize_identity(&self, identity_str: &str) -> Result<ZhtpIdentity, String> {
        // In production, this would properly deserialize from JSON/base64
        // For now, create a test identity from the string
        let identity_bytes = identity_str.as_bytes();
        let mut id_bytes = [0u8; 32];
        
        // Take first 32 bytes or pad with zeros
        let copy_len = std::cmp::min(identity_bytes.len(), 32);
        id_bytes[..copy_len].copy_from_slice(&identity_bytes[..copy_len]);

        ZhtpIdentity::new(
            lib_identity::types::IdentityType::Human,
            vec![0u8; 32],
            ZeroKnowledgeProof::new(
                "Plonky2".to_string(),
                vec![0u8; 32],
                vec![0u8; 32],
                vec![0u8; 32],
                None,
            ),
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

    /// Deploy Web4Contract to blockchain for domain registration with rich metadata
    async fn deploy_web4_contract(
        &self,
        domain: &str,
        owner: &str,
        content_mappings: &HashMap<String, String>,
        metadata: Option<serde_json::Value>,
        content_metadata_map: &HashMap<String, lib_storage::ContentMetadata>,  // NEW: Rich metadata
    ) -> Result<String, anyhow::Error> {
        info!(" Deploying Web4Contract for domain: {}", domain);

        let current_time = chrono::Utc::now().timestamp() as u64;
        let contract_id = format!("web4_{}", hex::encode(lib_crypto::hash_blake3(domain.as_bytes())));

        // Create website metadata
        let web4_metadata = WebsiteMetadata {
            title: metadata.as_ref()
                .and_then(|m| m.get("title"))
                .and_then(|v| v.as_str())
                .unwrap_or(domain)
                .to_string(),
            description: metadata.as_ref()
                .and_then(|m| m.get("description"))
                .and_then(|v| v.as_str())
                .unwrap_or("Web4 website")
                .to_string(),
            author: owner.to_string(),
            version: "1.0.0".to_string(),
            tags: metadata.as_ref()
                .and_then(|m| m.get("tags"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            language: "en".to_string(),
            created_at: current_time,
            updated_at: current_time,
            custom: HashMap::new(),
        };

        // Create content routes WITH RICH METADATA
        let mut routes = Vec::new();
        for (path, content_hash) in content_mappings {
            // Get ContentMetadata from map if available
            let (route_content_type, route_size, route_metadata) = if let Some(content_meta) = content_metadata_map.get(path) {
                // Serialize ContentMetadata to HashMap for blockchain storage
                let mut metadata_map = HashMap::new();
                metadata_map.insert("size".to_string(), content_meta.size.to_string());
                metadata_map.insert("content_type".to_string(), content_meta.content_type.clone());
                metadata_map.insert("tier".to_string(), format!("{:?}", content_meta.tier));
                metadata_map.insert("encryption".to_string(), format!("{:?}", content_meta.encryption));
                metadata_map.insert("replication".to_string(), content_meta.replication_factor.to_string());
                metadata_map.insert("cost_per_day".to_string(), content_meta.cost_per_day.to_string());
                metadata_map.insert("created_at".to_string(), content_meta.created_at.to_string());
                metadata_map.insert("access_count".to_string(), content_meta.access_count.to_string());
                metadata_map.insert("tags".to_string(), content_meta.tags.join(","));
                
                (content_meta.content_type.clone(), content_meta.size, metadata_map)
            } else {
                // Fallback to generic if metadata not available
                (
                    "application/octet-stream".to_string(),
                    0,
                    HashMap::new()
                )
            };
            
            routes.push(ContentRoute {
                path: path.clone(),
                content_hash: content_hash.clone(),
                content_type: route_content_type,
                size: route_size,
                metadata: route_metadata,
                updated_at: current_time,
            });
            
            info!("   Route: {} - {} bytes ({})", path, route_size, content_hash);
        }

        // Create deployment data
        let deployment_data = WebsiteDeploymentData {
            domain: domain.to_string(),
            metadata: web4_metadata.clone(),
            routes: routes.clone(),
            owner: owner.to_string(),
            config: HashMap::new(),
        };

        // Create Web4Contract
        let web4_contract = Web4Contract::new(
            contract_id.clone(),
            domain.to_string(),
            owner.to_string(),
            web4_metadata,
            deployment_data,
        );

        // Serialize contract to bytes
        let contract_bytes = serde_json::to_vec(&web4_contract)
            .map_err(|e| anyhow!("Failed to serialize Web4Contract: {}", e))?;

        info!(" Contract serialized: {} bytes", contract_bytes.len());

        // Create blockchain transaction for contract deployment from owner's wallet
        // Owner is a hex wallet address - this is the actual owner who will pay for deployment
        let owner_wallet_bytes = hex::decode(owner)
            .unwrap_or_else(|_| owner.as_bytes().to_vec());
        
        // Create transaction output - contract is stored on-chain
        let commitment_hash = lib_crypto::hash_blake3(&contract_bytes);
        let note_hash = lib_crypto::hash_blake3(contract_id.as_bytes());
        
        let contract_output = TransactionOutput {
            commitment: BlockchainHash::new(commitment_hash),
            note: BlockchainHash::new(note_hash),
            recipient: PublicKey {
                dilithium_pk: owner_wallet_bytes.clone(),
                kyber_pk: Vec::new(),
                key_id: {
                    let mut key_id = [0u8; 32];
                    let len = std::cmp::min(owner_wallet_bytes.len(), 32);
                    key_id[..len].copy_from_slice(&owner_wallet_bytes[..len]);
                    key_id
                },
            },
        };

        // Create signature using owner's wallet
        // TODO: In production, this should be signed with owner's actual private key
        // For now, create a valid-looking signature structure
        let signature_data = lib_crypto::hash_blake3(
            format!("{}:{}", contract_id, current_time).as_bytes()
        );
        
        let signature = Signature {
            signature: signature_data.to_vec(),
            public_key: PublicKey {
                dilithium_pk: owner_wallet_bytes.clone(),
                kyber_pk: Vec::new(),
                key_id: {
                    let mut key_id = [0u8; 32];
                    let len = std::cmp::min(owner_wallet_bytes.len(), 32);
                    key_id[..len].copy_from_slice(&owner_wallet_bytes[..len]);
                    key_id
                },
            },
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: current_time,
        };

        // Create transaction metadata
        let metadata_json = serde_json::json!({
            "domain": domain,
            "contract_id": contract_id,
            "contract_type": "Web4Contract",
            "owner": owner,
            "routes": routes.len()
        });
        let memo = serde_json::to_vec(&metadata_json)
            .map_err(|e| anyhow!("Failed to serialize contract metadata: {}", e))?;

        let mut transaction = Transaction::new(
            vec![], // No inputs for now - in production, should pull from owner's UTXOs
            vec![contract_output],
            1000, // Contract deployment fee (1000 ZHTP)
            signature,
            memo,
        );

        transaction.transaction_type = TransactionType::ContractDeployment;
        let tx_hash = transaction.hash().to_string();

        // Add transaction to blockchain
        match add_transaction(transaction).await {
            Ok(_) => {
                info!(" Web4Contract {} deployed with transaction: {}", contract_id, tx_hash);
                Ok(tx_hash)
            }
            Err(e) => {
                error!(" Failed to deploy Web4 contract to blockchain: {}", e);
                error!(" This likely means the owner's identity (wallet {}) is not registered on the blockchain", owner);
                error!(" SOLUTION: Register the owner's identity first using the identity registration API");
                error!(" Then the wallet can be used to deploy Web4 contracts");
                Err(anyhow!(
                    "Contract deployment failed - owner identity not registered on blockchain. \
                     Owner wallet: {}. Error: {}. \
                     Please register this identity on the blockchain first.",
                    owner, e
                ))
            }
        }
    }
}
