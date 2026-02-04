//! Wallet Handler Module
//! 
//! Complete wallet management using MultiWalletManager and lib-economy patterns

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
use lib_blockchain::Blockchain;

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

/// Complete wallet handler using MultiWalletManager
pub struct WalletHandler {
    identity_manager: Arc<RwLock<IdentityManager>>,
    blockchain: Arc<RwLock<Blockchain>>,
}

impl WalletHandler {
    pub fn new(identity_manager: Arc<RwLock<IdentityManager>>) -> Self {
        // Get blockchain from global provider
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });
        
        Self {
            identity_manager,
            blockchain,
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
            // GET /api/v1/wallet/transactions/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/transactions/") => {
                let identity_id = path.strip_prefix("/api/v1/wallet/transactions/").unwrap_or("");
                self.handle_get_transactions(identity_id).await
            }
            // POST /api/v1/wallet/send
            (ZhtpMethod::Post, "/api/v1/wallet/send") => {
                self.handle_simple_send(request).await
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

#[derive(Serialize, Deserialize)]
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

#[derive(Deserialize)]
struct SimpleSendRequest {
    from_identity: String,
    to_address: String,
    amount: u64,
    memo: Option<String>,
}

#[derive(Serialize)]
struct TransactionHistoryResponse {
    identity_id: String,
    total_transactions: usize,
    transactions: Vec<TransactionRecord>,
}

#[derive(Serialize)]
struct TransactionRecord {
    tx_hash: String,
    tx_type: String,
    amount: u64,
    fee: u64,
    from_wallet: Option<String>,
    to_address: Option<String>,
    timestamp: u64,
    block_height: Option<u64>,
    status: String, // "confirmed", "pending", "failed"
    memo: Option<String>,
}

impl WalletHandler {
    /// List all wallets for an identity
    async fn handle_list_wallets(&self, identity_id: &str) -> Result<ZhtpResponse> {
        // Parse identity ID from hex string
        let identity_hash = hex::decode(identity_id)
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;
        
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

        // Get blockchain wallet registry balances (UBI distributions go here)
        let blockchain_balances: std::collections::HashMap<String, u64> = {
            let blockchain = self.blockchain.read().await;
            blockchain.wallet_registry.iter()
                .map(|(id, data)| (id.clone(), data.initial_balance))
                .collect()
        };

        // Convert wallet summaries to API response format, merging blockchain balances
        let mut wallets = Vec::new();
        let mut total_balance_adjusted = 0u64;
        for summary in wallet_summaries.iter() {
            // Get full wallet details to access staked_balance and pending_rewards
            let (staked_balance, pending_rewards) = if let Some(wallet) = identity.wallet_manager.get_wallet(&summary.id) {
                (wallet.staked_balance, wallet.pending_rewards)
            } else {
                (0, 0)
            };

            // Check blockchain registry for potentially higher balance (UBI accumulates there)
            let wallet_id_hex = hex::encode(summary.id.0);
            let blockchain_balance = blockchain_balances.get(&wallet_id_hex).copied().unwrap_or(0);
            let effective_balance = std::cmp::max(summary.balance, blockchain_balance);

            let wallet_info = WalletInfo {
                wallet_type: format!("{:?}", summary.wallet_type),
                wallet_id: wallet_id_hex.clone(),  // Full 64-char hex wallet_id for transfers
                available_balance: effective_balance.saturating_sub(staked_balance),
                staked_balance,
                pending_rewards,
                total_balance: effective_balance + pending_rewards,
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
            total_balance_adjusted += effective_balance + pending_rewards;
            wallets.push(wallet_info);
        }

        let total_balance = total_balance_adjusted;

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
        // Parse wallet type to lib_identity::wallets::WalletType
        let wallet_type = match wallet_type_str.to_lowercase().as_str() {
            "primary" => lib_identity::wallets::WalletType::Primary,
            "standard" => lib_identity::wallets::WalletType::Standard,
            "ubi" | "ubidistribution" | "ubi_distribution" => lib_identity::wallets::WalletType::UBI,
            "savings" => lib_identity::wallets::WalletType::Savings,
            "business" => lib_identity::wallets::WalletType::Business,
            "stealth" | "privacy" => lib_identity::wallets::WalletType::Stealth,
            "nonprofitdao" | "nonprofit" => lib_identity::wallets::WalletType::NonProfitDAO,
            "forprofitdao" | "forprofit" => lib_identity::wallets::WalletType::ForProfitDAO,
            _ => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid wallet type: {}", wallet_type_str),
                ));
            }
        };

        // Parse identity ID
        let identity_hash = hex::decode(identity_id)
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;

        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }

        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);

        // Get the identity from stored state
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

        // Get wallet summaries from identity's wallet_manager
        let wallet_summaries = identity.wallet_manager.list_wallets();

        // Find the specific wallet type
        match wallet_summaries.iter().find(|w| w.wallet_type == wallet_type) {
            Some(summary) => {
                // Get full wallet details from identity's wallet_manager
                let (mut available_balance, mut staked_balance, mut pending_rewards, created_at) =
                    if let Some(wallet) = identity.wallet_manager.get_wallet(&summary.id) {
                        (
                            wallet.balance.saturating_sub(wallet.staked_balance),
                            wallet.staked_balance,
                            wallet.pending_rewards,
                            wallet.created_at,
                        )
                    } else {
                        (summary.balance, 0, 0, summary.created_at)
                    };

                // Check blockchain's wallet_registry for the authoritative balance using direct wallet_id lookup
                let blockchain = self.blockchain.read().await;
                let wallet_id_hex = hex::encode(summary.id.0);
                if let Some(wallet_data) = blockchain.wallet_registry.get(&wallet_id_hex) {
                    // Use max of identity balance and blockchain balance (UBI accumulates in blockchain)
                    let blockchain_balance = wallet_data.initial_balance;
                    if blockchain_balance > available_balance {
                        tracing::debug!(
                            "Using blockchain balance for wallet {}: {} > {} (identity)",
                            &wallet_id_hex[..16], blockchain_balance, available_balance
                        );
                        available_balance = blockchain_balance;
                    }
                }
                drop(blockchain);

                let total_balance = available_balance + staked_balance + pending_rewards;

                let response_data = json!({
                    "status": "success",
                    "wallet_type": wallet_type_str,
                    "identity_id": identity_id,
                    "balance": {
                        "available_balance": available_balance,
                        "staked_balance": staked_balance,
                        "pending_rewards": pending_rewards,
                        "total_balance": total_balance
                    },
                    "permissions": {
                        "can_transfer_external": true,
                        "can_vote": wallet_type == lib_identity::wallets::WalletType::Primary,
                        "can_stake": true,
                        "can_receive_rewards": true,
                        "daily_transaction_limit": 1_000_000,
                        "requires_multisig_threshold": null
                    },
                    "created_at": created_at
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
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;

        if identity_hash.len() != 32 {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }

        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);

        // Get the identity from stored state
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

        // Use the identity's existing wallet_manager (populated during registration)
        // Do NOT create a new MultiWalletManager which would lose stored balances
        let wallet_summaries = identity.wallet_manager.list_wallets();
        let total_balance = identity.get_total_balance();

        // Build wallet statistics from stored wallet_manager
        let mut wallet_stats = serde_json::Map::new();
        for summary in wallet_summaries.iter() {
            let (staked_balance, pending_rewards) =
                if let Some(wallet) = identity.wallet_manager.get_wallet(&summary.id) {
                    (wallet.staked_balance, wallet.pending_rewards)
                } else {
                    (0, 0)
                };

            let wallet_stat = json!({
                "available_balance": summary.balance.saturating_sub(staked_balance),
                "staked_balance": staked_balance,
                "pending_rewards": pending_rewards,
                "total_balance": summary.balance + pending_rewards,
                "transaction_count": 0,
                "description": format!("{:?} wallet", summary.wallet_type),
                "created_at": summary.created_at
            });
            wallet_stats.insert(format!("{:?}", summary.wallet_type), wallet_stat);
        }

        let statistics = json!({
            "identity": {
                "node_id": hex::encode(identity.id.clone()),
                "public_key": hex::encode(&identity.public_key.dilithium_pk),
                "identity_type": format!("{:?}", identity.identity_type)
            },
            "total_balance": total_balance,
            "wallet_count": wallet_summaries.len(),
            "wallet_statistics": wallet_stats,
            "cross_wallet_transactions": 0,
            "blockchain_context": {
                "current_height": 0,
                "is_synced": true,
                "peer_count": 0
            }
        });

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
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;

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

        // Perform the actual transfer using the function
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
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;
        
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
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;
        
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

    /// Get transaction history for an identity
    async fn handle_get_transactions(&self, identity_id: &str) -> Result<ZhtpResponse> {
        // Parse identity ID
        let identity_hash = hex::decode(identity_id)
            .map_err(|e| anyhow::anyhow!("Invalid hex for identity_id: {}", e))?;
        
        if identity_hash.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }

        // Get blockchain
        let blockchain = self.blockchain.read().await;
        
        // Collect all transactions involving this identity
        let mut transactions = Vec::new();
        
        // Search through all blocks for transactions
        for block in &blockchain.blocks {
            for tx in &block.transactions {
                // Check if transaction involves this identity
                let mut involves_identity = false;
                
                // Check identity_data
                if let Some(ref identity_data) = tx.identity_data {
                    if identity_data.did.contains(identity_id) {
                        involves_identity = true;
                    }
                }
                
                // Check wallet_data
                if let Some(ref wallet_data) = tx.wallet_data {
                    if let Some(ref owner_id) = wallet_data.owner_identity_id {
                        if hex::encode(owner_id.as_bytes()).contains(identity_id) {
                            involves_identity = true;
                        }
                    }
                }
                
                if involves_identity {
                    let tx_hash = tx.hash();
                    // Calculate total output amount (for display purposes)
                    let output_count = tx.outputs.len() as u64;
                    transactions.push(TransactionRecord {
                        tx_hash: hex::encode(tx_hash.as_bytes()),
                        tx_type: format!("{:?}", tx.transaction_type),
                        amount: output_count, // ZK system hides amounts, show output count
                        fee: tx.fee,
                        from_wallet: None, // Could be enhanced
                        to_address: None, // Could be enhanced
                        timestamp: block.timestamp(),
                        block_height: Some(block.height()),
                        status: "confirmed".to_string(),
                        memo: if tx.memo.is_empty() { None } else { Some(hex::encode(&tx.memo)) },
                    });
                }
            }
        }
        
        // Also check pending transactions
        for tx in &blockchain.pending_transactions {
            let mut involves_identity = false;
            
            if let Some(ref identity_data) = tx.identity_data {
                if identity_data.did.contains(identity_id) {
                    involves_identity = true;
                }
            }
            
            if let Some(ref wallet_data) = tx.wallet_data {
                if let Some(ref owner_id) = wallet_data.owner_identity_id {
                    if hex::encode(owner_id.as_bytes()).contains(identity_id) {
                        involves_identity = true;
                    }
                }
            }
            
            if involves_identity {
                let tx_hash = tx.hash();
                let output_count = tx.outputs.len() as u64;
                transactions.push(TransactionRecord {
                    tx_hash: hex::encode(tx_hash.as_bytes()),
                    tx_type: format!("{:?}", tx.transaction_type),
                    amount: output_count,
                    fee: tx.fee,
                    from_wallet: None,
                    to_address: None,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    block_height: None,
                    status: "pending".to_string(),
                    memo: if tx.memo.is_empty() { None } else { Some(hex::encode(&tx.memo)) },
                });
            }
        }
        
        drop(blockchain);
        
        // Sort by timestamp (newest first)
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        let response = TransactionHistoryResponse {
            identity_id: identity_id.to_string(),
            total_transactions: transactions.len(),
            transactions,
        };
        
        let json_response = serde_json::to_vec(&response)?;
        Ok(ZhtpResponse::success_with_content_type(
            json_response,
            "application/json".to_string(),
            None,
        ))
    }

    /// Handle simple payment (matching old ZHTP API)
    async fn handle_simple_send(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let send_req: SimpleSendRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        // Parse identity ID
        let identity_hash = hex::decode(&send_req.from_identity)
            .map_err(|e| anyhow::anyhow!("Invalid hex for from_identity: {}", e))?;
        
        if identity_hash.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Identity ID must be 32 bytes".to_string(),
            ));
        }

        let mut identity_id_bytes = [0u8; 32];
        identity_id_bytes.copy_from_slice(&identity_hash);

        // Parse recipient address (validate format)
        let _to_address_bytes = hex::decode(&send_req.to_address)
            .map_err(|e| anyhow::anyhow!("Invalid hex for to_address: {}", e))?;

        // Get identity and primary wallet
        let identity = match self.get_identity_by_id(&identity_id_bytes).await {
            Some(identity) => identity,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    "Identity not found".to_string(),
                ));
            }
        };

        // Get primary wallet from wallet list
        let wallets = identity.wallet_manager.list_wallets();
        let primary_wallet = wallets.iter()
            .find(|w| w.wallet_type == lib_identity::wallets::WalletType::Primary)
            .ok_or_else(|| anyhow::anyhow!("No primary wallet found"))?;

        // Check balance
        if primary_wallet.balance < send_req.amount {
            return Ok(create_error_response(
                ZhtpStatus::PaymentRequired,
                format!("Insufficient balance. Available: {}, Required: {}", 
                    primary_wallet.balance, send_req.amount),
            ));
        }

        // Create transaction using cross-wallet transfer logic
        // This is a simplified wrapper around the existing functionality
        let cross_wallet_req = CrossWalletTransferRequest {
            identity_id: send_req.from_identity.clone(),
            from_wallet: "primary".to_string(),
            to_wallet: send_req.to_address.clone(),
            amount: send_req.amount,
            purpose: send_req.memo,
        };

        let request_body = serde_json::to_vec(&cross_wallet_req)?;
        let modified_request = ZhtpRequest {
            version: request.version,
            method: ZhtpMethod::Post,
            uri: "/api/v1/wallet/transfer/cross-wallet".to_string(),
            headers: request.headers,
            body: request_body,
            timestamp: request.timestamp,
            requester: request.requester,
            auth_proof: request.auth_proof,
        };

        // Reuse existing cross-wallet transfer logic
        self.handle_cross_wallet_transfer(modified_request).await
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