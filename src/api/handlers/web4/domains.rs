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

        // Prepare content mappings for storage
        let mut initial_content = HashMap::new();
        let mut content_hash_map = HashMap::new();
        
        for (path, mapping) in simple_request.content_mappings {
            let content_bytes = mapping.content.as_bytes().to_vec();
            let content_hash = lib_crypto::hash_blake3(&content_bytes);
            let content_hash_hex = hex::encode(&content_hash[..8]); // Use first 8 bytes for shorter hash
            
            info!("   Path: {} ({} bytes)", path, content_bytes.len());
            info!("     Hash: {}", content_hash_hex);
            info!("     Type: {}", mapping.content_type);
            
            initial_content.insert(path.clone(), content_bytes);
            content_hash_map.insert(path, content_hash_hex);
        }

        // Create owner identity (simplified)
        let owner_identity = self.deserialize_identity(&simple_request.owner)
            .map_err(|e| anyhow!("Failed to deserialize identity: {}", e))?;

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

        // Deploy Web4Contract to blockchain
        let blockchain_tx_hash = match self.deploy_web4_contract(
            &simple_request.domain,
            &simple_request.owner,
            &content_hash_map,
            simple_request.metadata.clone(),
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

    /// Deploy Web4Contract to blockchain for domain registration
    async fn deploy_web4_contract(
        &self,
        domain: &str,
        owner: &str,
        content_mappings: &HashMap<String, String>,
        metadata: Option<serde_json::Value>,
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

        // Create content routes
        let mut routes = Vec::new();
        for (path, content_hash) in content_mappings {
            routes.push(ContentRoute {
                path: path.clone(),
                content_hash: content_hash.clone(),
                content_type: "application/octet-stream".to_string(), // Default, would be set properly
                size: 0, // Would be set from actual content
                metadata: HashMap::new(),
                updated_at: current_time,
            });
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

        // Create blockchain transaction for contract deployment
        // System transactions have EMPTY inputs to bypass identity verification
        let contract_output = TransactionOutput {
            commitment: BlockchainHash::from_slice(&contract_bytes),
            note: BlockchainHash::from_slice(contract_id.as_bytes()),
            recipient: PublicKey::new(owner.as_bytes().to_vec()),
        };

        let signature = Signature {
            signature: contract_id.as_bytes().to_vec(),
            public_key: PublicKey::new(b"WEB4_CONTRACT_DEPLOYER________".to_vec()),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: current_time,
        };

        let mut transaction = Transaction::new(
            vec![], // Empty inputs = system transaction (bypasses identity verification)
            vec![contract_output],
            1000, // Contract deployment fee
            signature,
            format!("Web4Contract deployment: {}", domain).as_bytes().to_vec(),
        );

        transaction.transaction_type = TransactionType::ContractDeployment;
        let tx_hash = transaction.hash().to_string();

        // Add transaction to blockchain
        add_transaction(transaction).await
            .map_err(|e| anyhow!("Failed to add contract transaction: {}", e))?;

        info!(" Web4Contract {} deployed with transaction: {}", contract_id, tx_hash);
        Ok(tx_hash)
    }
}
