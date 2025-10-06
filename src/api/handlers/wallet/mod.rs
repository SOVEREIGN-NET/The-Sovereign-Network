//! Wallet Handler Module
//! 
//! Complete wallet management using real MultiWalletManager and lib-economy patterns

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ZHTP protocol imports
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Import actual wallet system components
use lib_economy::wallets::{
    multi_wallet::{MultiWalletManager, WalletType},
    // Removed unused CrossWalletTransaction, WalletBalance
};
use lib_identity::{IdentityManager, identity::ZhtpIdentity as Identity};
use lib_crypto::Hash;

/// Helper function to create JSON responses correctly
fn create_json_response(data: serde_json::Value) -> Result<ZhtpResponse> {
    let json_response = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        json_response,
        "application/json".to_string(),
        None,
    ))
}

fn create_error_response(status: ZhtpStatus, message: String) -> ZhtpResponse {
    ZhtpResponse::error(status, message)
}

/// Complete wallet handler using real MultiWalletManager
pub struct WalletHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl WalletHandler {
    pub fn new(identity_manager: Arc<RwLock<IdentityManager>>) -> Self {
        Self {
            identity_manager,
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for WalletHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Wallet handler: {} {}", request.method, request.uri);
        
        let response = match (request.method, request.uri.as_str()) {
            // GET /api/v1/wallet/list/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/list/") => {
                let identity_id = path.strip_prefix("/api/v1/wallet/list/").unwrap_or("");
                self.handle_list_wallets(identity_id).await
            }
            // GET /api/v1/wallet/balance/{wallet_type}/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/balance/") => {
                let path_parts: Vec<&str> = path.strip_prefix("/api/v1/wallet/balance/").unwrap_or("").split('/').collect();
                if path_parts.len() >= 2 {
                    self.handle_get_balance(path_parts[0], path_parts[1]).await
                } else {
                    Ok(create_error_response(ZhtpStatus::BadRequest, "Invalid balance path".to_string()))
                }
            }
            // GET /api/v1/wallet/statistics/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/statistics/") => {
                let identity_id = path.strip_prefix("/api/v1/wallet/statistics/").unwrap_or("");
                self.handle_get_statistics(identity_id).await
            }
            // POST /api/v1/wallet/transfer/cross-wallet
            (ZhtpMethod::Post, "/api/v1/wallet/transfer/cross-wallet") => {
                self.handle_cross_wallet_transfer(request).await
            }
            // POST /api/v1/wallet/staking/stake
            (ZhtpMethod::Post, "/api/v1/wallet/staking/stake") => {
                self.handle_stake_tokens(request).await
            }
            // POST /api/v1/wallet/staking/unstake
            (ZhtpMethod::Post, "/api/v1/wallet/staking/unstake") => {
                self.handle_unstake_tokens(request).await
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Wallet endpoint not found".to_string(),
                ))
            }
        };
        
        match response {
            Ok(mut resp) => {
                // Add ZHTP headers
                resp.headers.set("X-Handler", "Wallet".to_string());
                resp.headers.set("X-Protocol", "ZHTP/1.0".to_string());
                Ok(resp)
            }
            Err(e) => {
                tracing::error!("Wallet handler error: {}", e);
                Ok(create_error_response(
                    ZhtpStatus::InternalServerError,
                    format!("Wallet error: {}", e),
                ))
            }
        }
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/wallet/")
    }
    
    fn priority(&self) -> u32 {
        100
    }
}

// Request/Response structures
#[derive(Serialize)]
struct WalletInfo {
    wallet_type: String,
    wallet_id: String,
    available_balance: u64,
    staked_balance: u64,
    pending_rewards: u64,
    total_balance: u64,
    permissions: WalletPermissionsInfo,
    created_at: u64,
    description: String,
}

#[derive(Serialize)]
struct WalletPermissionsInfo {
    can_transfer_external: bool,
    can_vote: bool,
    can_stake: bool,
    can_receive_rewards: bool,
    daily_transaction_limit: u64,
    requires_multisig_threshold: Option<u64>,
}

#[derive(Deserialize)]
struct CrossWalletTransferRequest {
    identity_id: String,
    from_wallet: String,
    to_wallet: String,
    amount: u64,
    purpose: Option<String>,
}

#[derive(Deserialize)]
struct StakingRequest {
    identity_id: String,
    amount: u64,
}

impl WalletHandler {
    /// List all wallets for an identity
    async fn handle_list_wallets(&self, identity_id: &str) -> Result<ZhtpResponse> {
        // Parse identity ID from hex string
        let identity_hash = hex::decode(identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                let error_response = json!({
                    "status": "identity_not_found",
                    "identity_id": identity_id,
                    "total_wallets": 0,
                    "total_balance": 0,
                    "wallets": []
                });
                let json_response = serde_json::to_vec(&error_response)?;
                return Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ));
            }
        };

        // Get wallets from the identity's wallet manager (created during identity registration)
        let wallet_summaries = identity.list_wallets();
        
        // Convert wallet summaries to API response format
        let mut wallets = Vec::new();
        for summary in wallet_summaries.iter() {
            // Get full wallet details to access staked_balance and pending_rewards
            let (staked_balance, pending_rewards) = if let Some(wallet) = identity.wallet_manager.get_wallet(&summary.id) {
                (wallet.staked_balance, wallet.pending_rewards)
            } else {
                (0, 0)
            };

            let wallet_info = WalletInfo {
                wallet_type: format!("{:?}", summary.wallet_type),
                wallet_id: self.generate_wallet_id(&summary.wallet_type, identity_id),
                available_balance: summary.balance.saturating_sub(staked_balance),
                staked_balance,
                pending_rewards,
                total_balance: summary.balance + pending_rewards,
                permissions: WalletPermissionsInfo {
                    can_transfer_external: true,
                    can_vote: summary.wallet_type == lib_identity::wallets::WalletType::Primary,
                    can_stake: true,
                    can_receive_rewards: true,
                    daily_transaction_limit: 1_000_000,
                    requires_multisig_threshold: None,
                },
                created_at: summary.created_at,
                description: format!("{:?} wallet for identity", summary.wallet_type),
            };
            wallets.push(wallet_info);
        }

        let total_balance = identity.get_total_balance();

        let response_data = json!({
            "status": "success",
            "identity_id": identity_id,
            "total_wallets": wallets.len(),
            "total_balance": total_balance,
            "wallets": wallets
        });
        let json_response = serde_json::to_vec(&response_data)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Get specific wallet balance
    async fn handle_get_balance(&self, wallet_type_str: &str, identity_id: &str) -> Result<ZhtpResponse> {
        // Parse wallet type
        let wallet_type = match self.parse_wallet_type(wallet_type_str) {
            Some(wt) => wt,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid wallet type: {}", wallet_type_str),
                ));
            }
        };

        // Parse identity ID
        let identity_hash = hex::decode(identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                let error_response = json!({
                    "status": "identity_not_found",
                    "wallet_type": wallet_type_str,
                    "identity_id": identity_id,
                    "balance": null
                });
                let json_response = serde_json::to_vec(&error_response)?;
                return Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ));
            }
        };

        // Create multi-wallet manager
        let wallet_manager = match MultiWalletManager::new(identity.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to create wallet manager: {}", e),
                ));
            }
        };

        // Get specific wallet balance
        match wallet_manager.wallets.get(&wallet_type) {
            Some(wallet) => {
                let response_data = json!({
                    "status": "success",
                    "wallet_type": wallet_type_str,
                    "identity_id": identity_id,
                    "balance": {
                        "available_balance": wallet.available_balance,
                        "staked_balance": wallet.staked_balance,
                        "pending_rewards": wallet.pending_rewards,
                        "total_balance": wallet.total_balance()
                    },
                    "permissions": self.convert_permissions(
                        wallet_manager.wallet_permissions.get(&wallet_type).unwrap()
                    ),
                    "created_at": wallet_manager.wallet_created_at.get(&wallet_type).unwrap_or(&0)
                });
                let json_response = serde_json::to_vec(&response_data)?;
                Ok(ZhtpResponse::success_with_content_type(
                    json_response,
                    "application/json".to_string(),
                    None,
                ))
            },
            None => {
                create_json_response(json!({
                    "status": "wallet_not_found",
                    "wallet_type": wallet_type_str,
                    "identity_id": identity_id,
                    "message": format!("Wallet type {} not found for identity", wallet_type_str)
                }))
            }
        }
    }

    /// Get comprehensive wallet statistics
    async fn handle_get_statistics(&self, identity_id: &str) -> Result<ZhtpResponse> {
        // Parse identity ID
        let identity_hash = hex::decode(identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                return create_json_response(json!({
                    "status": "identity_not_found",
                    "identity_id": identity_id,
                    "statistics": null
                }));
            }
        };

        // Create multi-wallet manager
        let wallet_manager = match MultiWalletManager::new(identity.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to create wallet manager: {}", e),
                ));
            }
        };

        // Get comprehensive statistics using the actual function
        let statistics = match wallet_manager.get_multi_wallet_statistics().await {
            Ok(stats) => serde_json::to_value(stats)?,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to get wallet statistics: {}", e),
                ));
            }
        };

        create_json_response(json!({
            "status": "success",
            "identity_id": identity_id,
            "statistics": statistics
        }))
    }

    /// Handle cross-wallet transfer
    async fn handle_cross_wallet_transfer(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: CrossWalletTransferRequest = serde_json::from_slice(&request.body)?;
        
        // Parse wallet types
        let from_wallet_type = match self.parse_wallet_type(&req_data.from_wallet) {
            Some(wt) => wt,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid from_wallet type: {}", req_data.from_wallet),
                ));
            }
        };
        
        let to_wallet_type = match self.parse_wallet_type(&req_data.to_wallet) {
            Some(wt) => wt,
            None => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid to_wallet type: {}", req_data.to_wallet),
                ));
            }
        };

        // Parse identity ID
        let identity_hash = hex::decode(&req_data.identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                return create_json_response(json!({
                    "status": "identity_not_found",
                    "identity_id": req_data.identity_id,
                    "transaction": null
                }));
            }
        };

        // Create multi-wallet manager
        let mut wallet_manager = match MultiWalletManager::new(identity.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to create wallet manager: {}", e),
                ));
            }
        };

        // Perform the actual transfer using the real function
        let purpose = req_data.purpose.unwrap_or_else(|| 
            format!("Transfer from {:?} to {:?}", from_wallet_type, to_wallet_type)
        );

        match wallet_manager.transfer_between_wallets(
            from_wallet_type.clone(),
            to_wallet_type.clone(),
            req_data.amount,
            purpose.clone(),
        ).await {
            Ok(transaction_id) => {
                create_json_response(json!({
                    "status": "success",
                    "identity_id": req_data.identity_id,
                    "transaction": {
                        "transaction_id": hex::encode(transaction_id),
                        "from_wallet": format!("{:?}", from_wallet_type),
                        "to_wallet": format!("{:?}", to_wallet_type),
                        "amount": req_data.amount,
                        "purpose": purpose,
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    },
                    "updated_balances": {
                        "from_balance": wallet_manager.wallets.get(&from_wallet_type)
                            .map(|w| w.available_balance).unwrap_or(0),
                        "to_balance": wallet_manager.wallets.get(&to_wallet_type)
                            .map(|w| w.available_balance).unwrap_or(0)
                    }
                }))
            },
            Err(e) => {
                create_json_response(json!({
                    "status": "transfer_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string(),
                    "transaction": null
                }))
            }
        }
    }

    /// Handle staking tokens
    async fn handle_stake_tokens(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: StakingRequest = serde_json::from_slice(&request.body)?;
        
        // Parse identity ID
        let identity_hash = hex::decode(&req_data.identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                return create_json_response(json!({
                    "status": "identity_not_found",
                    "identity_id": req_data.identity_id,
                    "staking_result": null
                }));
            }
        };

        // Create multi-wallet manager
        let mut wallet_manager = match MultiWalletManager::new(identity.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to create wallet manager: {}", e),
                ));
            }
        };

        // Create staking wallet if it doesn't exist
        if !wallet_manager.wallets.contains_key(&WalletType::Staking) {
            if let Err(e) = wallet_manager.create_specialized_wallet(WalletType::Staking).await {
                return create_json_response(json!({
                    "status": "staking_wallet_creation_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string()
                }));
            }
        }

        // Transfer from Primary to Staking wallet
        match wallet_manager.transfer_between_wallets(
            WalletType::Primary,
            WalletType::Staking,
            req_data.amount,
            "Staking tokens".to_string(),
        ).await {
            Ok(transaction_id) => {
                // Also perform actual staking operation on the staking wallet
                if let Some(staking_wallet) = wallet_manager.wallets.get_mut(&WalletType::Staking) {
                    let _ = staking_wallet.stake_tokens(req_data.amount);
                }

                create_json_response(json!({
                    "status": "success",
                    "identity_id": req_data.identity_id,
                    "staking_result": {
                        "transaction_id": hex::encode(transaction_id),
                        "amount_staked": req_data.amount,
                        "primary_balance": wallet_manager.wallets.get(&WalletType::Primary)
                            .map(|w| w.available_balance).unwrap_or(0),
                        "staked_balance": wallet_manager.wallets.get(&WalletType::Staking)
                            .map(|w| w.staked_balance).unwrap_or(0),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    }
                }))
            },
            Err(e) => {
                create_json_response(json!({
                    "status": "staking_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string()
                }))
            }
        }
    }

    /// Handle unstaking tokens
    async fn handle_unstake_tokens(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req_data: StakingRequest = serde_json::from_slice(&request.body)?;
        
        // Parse identity ID
        let identity_hash = hex::decode(&req_data.identity_id)
            .map_err(|_| anyhow::anyhow!("Invalid identity ID format"))?;
        
        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }
        
        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);
        
        // Get the identity
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                return create_json_response(json!({
                    "status": "identity_not_found",
                    "identity_id": req_data.identity_id,
                    "unstaking_result": null
                }));
            }
        };

        // Create multi-wallet manager
        let mut wallet_manager = match MultiWalletManager::new(identity.clone()).await {
            Ok(manager) => manager,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("Failed to create wallet manager: {}", e),
                ));
            }
        };

        // Check if staking wallet exists
        if !wallet_manager.wallets.contains_key(&WalletType::Staking) {
            return create_json_response(json!({
                "status": "staking_wallet_not_found",
                "identity_id": req_data.identity_id,
                "message": "No staking wallet found for this identity"
            }));
        }

        // Perform unstaking on the staking wallet first
        if let Some(staking_wallet) = wallet_manager.wallets.get_mut(&WalletType::Staking) {
            if let Err(e) = staking_wallet.unstake_tokens(req_data.amount) {
                return create_json_response(json!({
                    "status": "unstaking_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string()
                }));
            }
        }

        // Transfer from Staking to Primary wallet
        match wallet_manager.transfer_between_wallets(
            WalletType::Staking,
            WalletType::Primary,
            req_data.amount,
            "Unstaking tokens".to_string(),
        ).await {
            Ok(transaction_id) => {
                create_json_response(json!({
                    "status": "success",
                    "identity_id": req_data.identity_id,
                    "unstaking_result": {
                        "transaction_id": hex::encode(transaction_id),
                        "amount_unstaked": req_data.amount,
                        "primary_balance": wallet_manager.wallets.get(&WalletType::Primary)
                            .map(|w| w.available_balance).unwrap_or(0),
                        "staked_balance": wallet_manager.wallets.get(&WalletType::Staking)
                            .map(|w| w.staked_balance).unwrap_or(0),
                        "timestamp": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    }
                }))
            },
            Err(e) => {
                create_json_response(json!({
                    "status": "unstaking_transfer_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string()
                }))
            }
        }
    }

    // Helper functions

    /// Get identity by ID from the identity manager
    async fn get_identity_by_id(&self, identity_id: &[u8; 32]) -> Option<Identity> {
        // Convert bytes to Hash for identity lookup
        let identity_hash = Hash(*identity_id);
        
        // Look up in identity manager
        let identity_manager = self.identity_manager.read().await;
        identity_manager.get_identity(&identity_hash).cloned()
    }

    /// Parse wallet type string to WalletType enum
    fn parse_wallet_type(&self, wallet_type_str: &str) -> Option<WalletType> {
        match wallet_type_str.to_lowercase().as_str() {
            "primary" => Some(WalletType::Primary),
            "ispbypassrewards" | "isp_bypass_rewards" => Some(WalletType::IspBypassRewards),
            "meshdiscoveryrewards" | "mesh_discovery_rewards" => Some(WalletType::MeshDiscoveryRewards),
            "staking" => Some(WalletType::Staking),
            "governance" => Some(WalletType::Governance),
            "ubidistribution" | "ubi_distribution" | "ubi" => Some(WalletType::UbiDistribution),
            "infrastructure" => Some(WalletType::Infrastructure),
            "bridge" => Some(WalletType::Bridge),
            "smartcontract" | "smart_contract" => Some(WalletType::SmartContract),
            "privacy" => Some(WalletType::Privacy),
            _ => None,
        }
    }

    /// Generate wallet ID based on wallet type and identity
    fn generate_wallet_id(&self, wallet_type: &lib_identity::wallets::WalletType, identity_id: &str) -> String {
        match wallet_type {
            lib_identity::wallets::WalletType::Primary => format!("wallet_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Standard => format!("standard_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::UBI => format!("ubi_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Savings => format!("savings_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Business => format!("business_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Stealth => format!("stealth_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::NonProfitDAO => format!("nonprofit_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::ForProfitDAO => format!("forprofit_{}", &identity_id[..12]),
        }
    }

    /// Convert wallet permissions to API format
    fn convert_permissions(&self, permissions: &lib_economy::wallets::multi_wallet::WalletPermissions) -> WalletPermissionsInfo {
        WalletPermissionsInfo {
            can_transfer_external: permissions.can_transfer_external,
            can_vote: permissions.can_vote,
            can_stake: permissions.can_stake,
            can_receive_rewards: permissions.can_receive_rewards,
            daily_transaction_limit: permissions.daily_transaction_limit,
            requires_multisig_threshold: permissions.requires_multisig_threshold,
        }
    }
}