use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use chrono;

use lib_protocols::{
    zhtp::{ZhtpResult, ZhtpRequestHandler},
    types::{ZhtpRequest, ZhtpResponse, ZhtpMethod, ZhtpStatus},
};
use crate::runtime::blockchain_provider::get_global_blockchain;
use lib_blockchain::Blockchain;
use lib_crypto::Hash;

/// Request payload for validator registration
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterValidatorRequest {
    /// Validator identity DID or hash
    pub identity_id: String,
    /// Initial stake amount (REQUIRED)
    pub stake: u64,
    /// Storage capacity provided in bytes (OPTIONAL - validators can be pure consensus nodes)
    #[serde(default)]
    pub storage_provided: u64,
    /// Commission rate in basis points (e.g., 500 = 5%)
    pub commission_rate: u16,
    /// Network endpoints for validator communication
    pub endpoints: Vec<String>,
    /// Consensus public key (hex encoded)
    pub consensus_key: String,
    /// Registration fee
    pub registration_fee: u64,
}

/// Request payload for updating validator information
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateValidatorRequest {
    /// New stake amount (optional)
    pub stake: Option<u64>,
    /// New storage capacity (optional)
    pub storage_provided: Option<u64>,
    /// New commission rate (optional)
    pub commission_rate: Option<u16>,
    /// New endpoints (optional)
    pub endpoints: Option<Vec<String>>,
    /// Update fee
    pub update_fee: u64,
}

/// Response for validator information
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorInfo {
    /// Validator identity hash
    pub identity_hash: String,
    /// Current stake amount
    pub stake: u64,
    /// Storage capacity provided
    pub storage_provided: u64,
    /// Commission rate in basis points
    pub commission_rate: u16,
    /// Network endpoints
    pub endpoints: Vec<String>,
    /// Consensus public key
    pub consensus_key: String,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Validator status (active, suspended, etc.)
    pub status: String,
}

/// Response for a single validator
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorResponse {
    /// Validator identifier
    pub id: String,
    /// Identity hash
    pub identity_hash: String,
    /// Staked amount
    pub stake: u64,
    /// Commission rate (0-100)
    pub commission_rate: u16,
    /// Network endpoints
    pub endpoints: Vec<String>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Validator status
    pub status: String,
}

/// Response for listing validators
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorListResponse {
    /// List of validators
    pub validators: Vec<ValidatorInfo>,
    /// Total number of validators
    pub total_count: usize,
    /// Current page (for pagination)
    pub page: usize,
    /// Page size
    pub page_size: usize,
}

/// Validator API handler
#[derive(Clone)]
pub struct ValidatorHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl ValidatorHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self { blockchain }
    }

    // REMOVED: register_validator() function - Security vulnerability
    // This allowed anyone to register as a validator without:
    // - Authentication
    // - Proof of stake (actual locked funds)
    // - Identity ownership verification
    // - Signature validation
    // Validator registration must go through proper governance channels only.

    /// Get list of all validators
    pub async fn get_validators(&self, page: Option<usize>, page_size: Option<usize>) -> ZhtpResult<ZhtpResponse> {
        info!("Retrieving validator list");
        
        let blockchain = get_global_blockchain().await?;
        let blockchain_guard = blockchain.read().await;
        
        // Get all validators from registry
        let all_validators = blockchain_guard.get_all_validators();
        
        // Apply pagination
        let page = page.unwrap_or(1);
        let page_size = page_size.unwrap_or(50).min(100); // Max 100 per page
        let start_idx = (page - 1) * page_size;
        let end_idx = (start_idx + page_size).min(all_validators.len());
        
        // Convert validator data to response format
        let validators: Vec<ValidatorInfo> = all_validators
            .iter()
            .skip(start_idx)
            .take(end_idx - start_idx)
            .map(|(id, validator)| ValidatorInfo {
                identity_hash: id.clone(), // Use the ID directly as it's the hex string
                stake: validator.stake,
                storage_provided: validator.storage_provided,
                commission_rate: validator.commission_rate as u16, // Convert u8 to u16
                endpoints: vec![validator.network_address.clone()], // Convert String to Vec<String>
                consensus_key: hex::encode(&validator.consensus_key),
                registered_at: validator.registered_at,
                updated_at: validator.last_activity, // Use last_activity instead of updated_at
                status: format!("{:?}", validator.status),
            })
            .collect();
        
        let response = ValidatorListResponse {
            validators,
            total_count: all_validators.len(),
            page,
            page_size,
        };
        
        info!("Retrieved {} validators (page {}/{})", response.validators.len(), page, (all_validators.len() + page_size - 1) / page_size);
        let json_response = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get specific validator by ID
    pub async fn get_validator(&self, validator_id: String) -> ZhtpResult<ZhtpResponse> {
        info!("Getting validator: {}", validator_id);

        let blockchain = self.blockchain.clone();
        let blockchain_guard = blockchain.read().await;

        // Parse validator ID
        let identity_hash = match hex::decode(&validator_id) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes);
                Hash(hash_bytes)
            }
            Ok(_) => return Err(anyhow::anyhow!("Invalid hex for validator_id: must be 32 bytes")),
            Err(e) => return Err(anyhow::anyhow!("Invalid hex for validator_id: {}", e)),
        };

        // Get validator from blockchain
        match blockchain_guard.get_validator(&hex::encode(&identity_hash.0)) {
            Some(validator) => {
                let validator_response = ValidatorResponse {
                    id: validator.identity_id.clone(),
                    identity_hash: hex::encode(&identity_hash.0),
                    stake: validator.stake,
                    commission_rate: validator.commission_rate as u16, // Convert u8 to u16
                    endpoints: vec![validator.network_address.clone()], // Convert String to Vec<String>
                    registered_at: validator.registered_at,
                    updated_at: validator.last_activity, // Use last_activity instead of updated_at
                    status: format!("{:?}", validator.status),
                };
                
                let json_response = serde_json::to_vec(&validator_response)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            None => {
                warn!("Validator not found: {}", hex::encode(&identity_hash.0));
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Validator not found".to_string(),
                ))
            }
        }
    }

    /// Update validator information
    pub async fn update_validator(&self, validator_id: String, request: UpdateValidatorRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Updating validator: {}", validator_id);

        let blockchain = self.blockchain.clone();
        let mut blockchain_guard = blockchain.write().await;

        // Parse validator ID
        let identity_hash = match hex::decode(&validator_id) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes);
                Hash(hash_bytes)
            }
            Ok(_) => return Err(anyhow::anyhow!("Invalid hex for validator_id: must be 32 bytes")),
            Err(e) => return Err(anyhow::anyhow!("Invalid hex for validator_id: {}", e)),
        };

        // Check if validator exists and get current info
        let identity_id_str = hex::encode(&identity_hash.0);
        let existing_validator = blockchain_guard.get_validator(&identity_id_str)
            .ok_or_else(|| anyhow::anyhow!("Validator not found"))?;

        // Create updated ValidatorInfo with existing values as defaults
        let updated_info = lib_blockchain::blockchain::ValidatorInfo {
            identity_id: identity_id_str.clone(),
            stake: request.stake.unwrap_or(existing_validator.stake),
            storage_provided: request.storage_provided.unwrap_or(existing_validator.storage_provided),
            consensus_key: existing_validator.consensus_key.clone(), // Keep existing consensus key
            network_address: request.endpoints
                .as_ref()
                .and_then(|eps| eps.get(0))
                .cloned()
                .unwrap_or_else(|| existing_validator.network_address.clone()),
            commission_rate: request.commission_rate
                .map(|rate| (rate.min(100) as u8))
                .unwrap_or(existing_validator.commission_rate),
            status: existing_validator.status.clone(),
            registered_at: existing_validator.registered_at,
            last_activity: chrono::Utc::now().timestamp() as u64, // Update activity time
            blocks_validated: existing_validator.blocks_validated,
            slash_count: existing_validator.slash_count,
        };

        // Update validator through blockchain
        match blockchain_guard.update_validator(&identity_id_str, updated_info) {
            Ok(tx_hash) => {
                info!(" Validator updated successfully: {}", hex::encode(tx_hash));
                let response = serde_json::json!({
                    "transaction_hash": hex::encode(tx_hash),
                    "validator_id": hex::encode(&identity_hash.0),
                    "message": "Validator updated successfully"
                });
                let json_response = serde_json::to_vec(&response)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to update validator: {}", e);
                Err(anyhow::anyhow!("Update failed: {}", e))
            }
        }
    }

    /// Unregister a validator
    pub async fn unregister_validator(&self, validator_id: String) -> ZhtpResult<ZhtpResponse> {
        info!("Unregistering validator: {}", validator_id);

        let blockchain = self.blockchain.clone();
        let mut blockchain_guard = blockchain.write().await;

        // Parse validator ID
        let identity_hash = match hex::decode(&validator_id) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&bytes);
                Hash(hash_bytes)
            }
            Ok(_) => return Err(anyhow::anyhow!("Invalid hex for validator_id: must be 32 bytes")),
            Err(e) => return Err(anyhow::anyhow!("Invalid hex for validator_id: {}", e)),
        };

        // Check if validator exists
        let identity_id_str = hex::encode(&identity_hash.0);
        if blockchain_guard.get_validator(&identity_id_str).is_none() {
            return Err(anyhow::anyhow!("Validator not found"));
        }

        // Unregister validator through blockchain
        match blockchain_guard.unregister_validator(&identity_id_str) {
            Ok(tx_hash) => {
                info!(" Validator unregistered successfully: {}", hex::encode(tx_hash));
                let response = serde_json::json!({
                    "transaction_hash": hex::encode(tx_hash),
                    "validator_id": hex::encode(&identity_hash.0),
                    "message": "Validator unregistered successfully"
                });
                let json_response = serde_json::to_vec(&response)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => {
                error!("Failed to unregister validator: {}", e);
                Err(anyhow::anyhow!("Unregister failed: {}", e))
            }
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ValidatorHandler {
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/validator")
    }
    
    fn priority(&self) -> u32 {
        90
    }

    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("Validator handler: {} {}", request.method, request.uri);
        
        match (request.method, request.uri.as_str()) {
            // REMOVED: Insecure validator registration endpoint
            // Validators should only be added through genesis or proper staking governance
            // (ZhtpMethod::Post, "/api/v1/validator/register") => { ... }
            
            (ZhtpMethod::Get, "/api/v1/validators") => {
                self.handle_get_validators(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/validator/") => {
                self.handle_get_validator(request).await
            }
            (ZhtpMethod::Put, path) if path.starts_with("/api/v1/validator/") => {
                self.handle_update_validator(request).await
            }
            (ZhtpMethod::Delete, path) if path.starts_with("/api/v1/validator/") => {
                self.handle_unregister_validator(request).await
            }
            _ => {
                warn!("Validator handler: unsupported route {} {}", request.method, request.uri);
                Err(anyhow::anyhow!("Validator endpoint not found"))
            }
        }
    }
}

impl ValidatorHandler {
    // REMOVED: handle_register_validator() - insecure endpoint
    // Validators must be registered through genesis or governance only
    
    /// Handle GET /api/v1/validators
    async fn handle_get_validators(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Parse query parameters
        let query_params = Self::parse_query_params(&request.uri);
        let page = query_params.get("page").and_then(|p| p.parse().ok());
        let page_size = query_params.get("page_size").and_then(|p| p.parse().ok());
        
        self.get_validators(page, page_size).await
    }
    
    /// Handle GET /api/v1/validator/{id}
    async fn handle_get_validator(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let validator_id = Self::extract_path_param(&request.uri, "/api/v1/validator/");
        
        self.get_validator(validator_id).await
    }
    
    /// Handle PUT /api/v1/validator/{id}
    async fn handle_update_validator(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let validator_id = Self::extract_path_param(&request.uri, "/api/v1/validator/");
        
        let update_request: UpdateValidatorRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;
        
        self.update_validator(validator_id, update_request).await
    }
    
    /// Handle DELETE /api/v1/validator/{id}
    async fn handle_unregister_validator(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let validator_id = Self::extract_path_param(&request.uri, "/api/v1/validator/");
        
        self.unregister_validator(validator_id).await
    }
    
    /// Helper function to extract path parameter from URI
    fn extract_path_param(uri: &str, prefix: &str) -> String {
        uri.strip_prefix(prefix)
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
            .to_string()
    }
    
    /// Helper function to parse query parameters from URI
    fn parse_query_params(uri: &str) -> std::collections::HashMap<String, String> {
        let mut params = std::collections::HashMap::new();
        
        if let Some(query_part) = uri.split('?').nth(1) {
            for param in query_part.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    params.insert(
                        key.to_string(),
                        urlencoding::decode(value).unwrap_or(std::borrow::Cow::Borrowed(value)).to_string(),
                    );
                }
            }
        }
        
        params
    }
}