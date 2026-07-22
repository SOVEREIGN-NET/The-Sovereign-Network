//! Wallet Handler Module
//!
//! Complete wallet management using MultiWalletManager and lib-economy patterns

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

// Import actual wallet system components
use lib_blockchain::{Blockchain, BlockchainQuery};
use lib_crypto::Hash;
use lib_economy::wallets::{
    multi_wallet::{MultiWalletManager, WalletType},
    // Removed unused CrossWalletTransaction, WalletBalance
};
use lib_identity::{identity::ZhtpIdentity as Identity, IdentityManager};


// Access control imports
use crate::api::principal::{
    extract_principal_from_request, identity_id_matches_caller, parse_identity_id_bytes,
};
use lib_access_control::{AccessDomain, AccessOperation, SecurityPrincipal};

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

    /// Extract a SecurityPrincipal from an incoming request.
    fn extract_principal(&self, request: &ZhtpRequest) -> SecurityPrincipal {
        extract_principal_from_request(request)
    }

    fn parse_identity_id_or_bad_request(
        identity_id: &str,
    ) -> std::result::Result<[u8; 32], ZhtpResponse> {
        parse_identity_id_bytes(identity_id)
            .map_err(|msg| create_error_response(ZhtpStatus::BadRequest, msg))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for WalletHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        tracing::info!("Wallet handler: {} {}", request.method, request.uri);

        // Access zone gate: password sessions cannot access wallet endpoints
        if crate::session_manager::is_request_password_session(&request).await {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Wallet access requires key authentication (mobile app or seed phrase recovery)".to_string(),
            ));
        }

        let response = match (request.method, request.uri.as_str()) {
            // GET /api/v1/wallet/list/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/list/") => {
                let identity_id = path.strip_prefix("/api/v1/wallet/list/").unwrap_or("");
                self.handle_list_wallets(identity_id, &request).await
            }
            // GET /api/v1/wallet/balance/{wallet_type}/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/balance/") => {
                let rest = path.strip_prefix("/api/v1/wallet/balance/").unwrap_or("");
                if let Some((wallet_type, identity_id)) = rest.split_once('/') {
                    self.handle_get_balance(wallet_type, identity_id, &request)
                        .await
                } else {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Invalid balance path".to_string(),
                    ))
                }
            }
            // GET /api/v1/wallet/statistics/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/statistics/") => {
                let identity_id = path
                    .strip_prefix("/api/v1/wallet/statistics/")
                    .unwrap_or("");
                self.handle_get_statistics(identity_id, &request).await
            }
            // GET /api/v1/wallet/transactions/{identity_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/wallet/transactions/") => {
                let identity_id = path
                    .strip_prefix("/api/v1/wallet/transactions/")
                    .unwrap_or("");
                self.handle_get_transactions(identity_id, &request).await
            }
            // POST /api/v1/wallet/send
            (ZhtpMethod::Post, "/api/v1/wallet/send") => self.handle_simple_send(request).await,
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
            // POST /api/v1/wallet/provision — ops-only post-reset wallet restore
            // (GENESIS-3 Phase 7). Not for end-user onboarding; identity/register
            // remains the normal path.
            (ZhtpMethod::Post, "/api/v1/wallet/provision") => {
                self.handle_provision_wallet(request).await
            }
            // POST /api/v1/wallet/mint-sov — REMOVED: minting is Treasury Kernel
            // only, never via API endpoint.
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                "Wallet endpoint not found".to_string(),
            )),
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
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    available_balance: u128,
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    staked_balance: u128,
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    pending_rewards: u128,
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    total_balance: u128,
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
    amount: u128,
    purpose: Option<String>,
}

#[derive(Deserialize)]
struct StakingRequest {
    identity_id: String,
    amount: u128,
}

#[derive(Deserialize)]
struct SimpleSendRequest {
    from_identity: String,
    to_address: String,
    amount: u128,
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
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    amount: u128,
    #[serde(serialize_with = "crate::api::handlers::token::u128_as_string::serialize")]
    fee: u128,
    from_wallet: Option<String>,
    to_address: Option<String>,
    timestamp: u64,
    block_height: Option<u64>,
    status: String, // "confirmed", "pending", "failed"
    memo: Option<String>,
}

impl WalletHandler {
    /// List all wallets for an identity
    async fn handle_list_wallets(
        &self,
        identity_id: &str,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let identity_hash = Hash(identity_id_bytes);

        // TODO: Gate cross-identity wallet list once mobile app is updated.
        // For now, return full data to maintain backward compatibility.

        // The in-memory identity_manager is an optional fast-path for the rich
        // Identity object (it carries the WalletManager with staked/pending
        // detail). It is NOT rebuilt from chain on restart and only holds
        // identities that registered/handshook live on THIS node — so a miss
        // here is normal and MUST NOT hide on-chain wallets. The authoritative
        // source is blockchain.wallet_registry; fall through to it whenever
        // the in-memory manager has nothing for this identity.
        let identity_opt = self.get_identity_by_id(&identity_id_bytes).await;

        // Get wallets from the identity's wallet manager (created during identity
        // registration). If absent (identity not in the in-memory manager) or
        // empty (e.g. after restart / sled wipe + seed recovery), fall back to
        // scanning blockchain.wallet_registry for wallets owned by this identity.
        let wallet_summaries = identity_opt
            .as_ref()
            .map(|identity| identity.list_wallets())
            .unwrap_or_default();

        let sov_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();

        let mut wallets = Vec::new();
        let mut total_balance_adjusted = 0u128;

        if wallet_summaries.is_empty() {
            // Fallback: surface wallets from the on-chain registry that belong to this identity.
            let blockchain = self.blockchain.read().await;
            for (wallet_id_hex, wallet_data) in blockchain.wallet_registry_snapshot() {
                let owned = wallet_data
                    .owner_identity_id
                    .map(|owner| owner.as_bytes() == identity_id_bytes.as_slice())
                    .unwrap_or(false);
                if !owned {
                    continue;
                }
                // Mirror the main path at line 393: read SOV balance sled-first
                // via blockchain.token_balance() rather than the in-memory
                // TokenContract.balances HashMap. The executor writes SOV
                // debits/credits to the sled `token_balances` tree, and the
                // post-apply sync to in-memory can miss entries when the
                // identity_manager has no live entry for this DID (the path
                // this fallback exists for in the first place). Reading sled
                // here guarantees the mobile wallet displays the post-debit
                // balance immediately after a domain registration fee_payment_tx
                // commits.
                let effective_balance = hex::decode(&wallet_id_hex)
                    .ok()
                    .filter(|b| b.len() == 32)
                    .map(|bytes| {
                        let mut key_id = [0u8; 32];
                        key_id.copy_from_slice(&bytes);
                        blockchain.token_balance(&sov_token_id, &key_id).unwrap_or(0)
                    })
                    .unwrap_or(0);
                let wallet_info = WalletInfo {
                    wallet_type: wallet_data.wallet_type.clone(),
                    wallet_id: wallet_id_hex.clone(),
                    available_balance: effective_balance,
                    staked_balance: 0,
                    pending_rewards: 0,
                    total_balance: effective_balance,
                    permissions: WalletPermissionsInfo {
                        can_transfer_external: true,
                        can_vote: wallet_data.wallet_type == "Primary",
                        can_stake: true,
                        can_receive_rewards: true,
                        daily_transaction_limit: 1_000_000,
                        requires_multisig_threshold: None,
                    },
                    created_at: wallet_data.created_at,
                    description: format!("{} wallet (recovered)", wallet_data.wallet_type),
                };
                total_balance_adjusted += effective_balance;
                wallets.push(wallet_info);
            }
            let response_data = json!({
                "status": "success",
                "identity_id": identity_id,
                "total_wallets": wallets.len(),
                "total_balance": total_balance_adjusted.to_string(),
                "wallets": wallets
            });
            let json_response = serde_json::to_vec(&response_data)?;
            return Ok(ZhtpResponse::success_with_content_type(
                json_response,
                "application/json".to_string(),
                None,
            ));
        }

        // Reached only when wallet_summaries is non-empty, which implies the
        // in-memory identity was present (summaries were derived from it).
        let identity = match identity_opt {
            Some(identity) => identity,
            None => unreachable!("non-empty wallet_summaries implies identity present"),
        };

        for summary in wallet_summaries.iter() {
            // Get full wallet details to access staked_balance and pending_rewards
            let (staked_balance, pending_rewards) =
                if let Some(wallet) = identity.wallet_manager.get_wallet(&summary.id) {
                    (wallet.staked_balance, wallet.pending_rewards)
                } else {
                    (0, 0)
                };

            // Read SOV balance from in-memory token_contracts (authoritative).
            // After each block commit, the executor path syncs in-memory from SledStore
            // for all touched addresses, so in-memory is always current.
            let wallet_id_hex = hex::encode(summary.id.0);
            let effective_balance = {
                let blockchain = self.blockchain.read().await;
                let wallet_id_bytes_opt =
                    hex::decode(&wallet_id_hex).ok().filter(|b| b.len() == 32);
                // #2637: token_balance() is sled-first and keyed by key_id. Also
                // fixes a latent bug — the old synthetic PublicKey (zeroed
                // dilithium/kyber) never matched balance_of's full-field key
                // equality, so this path always returned 0.
                wallet_id_bytes_opt
                    .as_ref()
                    .map(|bytes| {
                        let mut key_id = [0u8; 32];
                        key_id.copy_from_slice(bytes);
                        blockchain.token_balance(&sov_token_id, &key_id).unwrap_or(0)
                    })
                    .unwrap_or(0)
            };

            let wallet_info = WalletInfo {
                wallet_type: format!("{:?}", summary.wallet_type),
                wallet_id: wallet_id_hex.clone(), // Full 64-char hex wallet_id for transfers
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
            "total_balance": total_balance.to_string(),
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
    async fn handle_get_balance(
        &self,
        wallet_type_str: &str,
        identity_id: &str,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        // Parse wallet type to lib_identity::wallets::WalletType
        let wallet_type = match wallet_type_str.to_lowercase().as_str() {
            "primary" => lib_identity::wallets::WalletType::Primary,
            "standard" => lib_identity::wallets::WalletType::Standard,
            "ubi" | "ubidistribution" | "ubi_distribution" => {
                lib_identity::wallets::WalletType::UBI
            }
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

        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let identity_hash = Hash(identity_id_bytes);

        // TODO: Gate cross-identity balance once mobile app is updated.
        // For now, return full data to maintain backward compatibility.

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
        match wallet_summaries
            .iter()
            .find(|w| w.wallet_type == wallet_type)
        {
            Some(summary) => {
                // Get full wallet details from identity's wallet_manager
                let (mut available_balance, staked_balance, pending_rewards, created_at) =
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

                // Prefer SOV token contract balance (live balance) for this wallet.
                let blockchain = self.blockchain.read().await;
                let wallet_id_hex = hex::encode(summary.id.0);
                if let Some(wallet_data) = blockchain.wallet_transaction_data(&wallet_id_hex) {
                    // #2637: sled-first SOV balance. Gate on the contract existing
                    // (preserves the prior "only override if SOV token present"
                    // behavior), then read via token_balance() keyed by key_id —
                    // the wallet_id for the 32-byte path (the SOV balance key the
                    // executor uses), else the wallet public key's key_id. Also
                    // fixes the synthetic-PublicKey balance_of bug that returned 0.
                    let native_token_id = lib_blockchain::contracts::utils::generate_lib_token_id();
                    if blockchain.get_token_contract(&native_token_id).is_some() {
                        let addr: [u8; 32] = match hex::decode(&wallet_id_hex)
                            .ok()
                            .filter(|b| b.len() == 32)
                        {
                            Some(bytes) => {
                                let mut key_id = [0u8; 32];
                                key_id.copy_from_slice(&bytes);
                                key_id
                            }
                            None => lib_blockchain::integration::crypto_integration::PublicKey::new(
                                wallet_data.public_key.as_slice().try_into().unwrap_or([0u8; 2592]),
                            )
                            .key_id,
                        };
                        let token_balance =
                            blockchain.token_balance(&native_token_id, &addr).unwrap_or(0);
                        if token_balance != available_balance {
                            tracing::debug!(
                                "Using SOV token balance for wallet {}: {} (was {})",
                                &wallet_id_hex[..16],
                                token_balance,
                                available_balance
                            );
                            available_balance = token_balance;
                        }
                    }
                }
                drop(blockchain);

                let total_balance = available_balance + staked_balance + pending_rewards;

                let response_data = json!({
                    "status": "success",
                    "wallet_type": wallet_type_str,
                    "identity_id": identity_id,
                    "balance": {
                        "available_balance": available_balance.to_string(),
                        "staked_balance": staked_balance.to_string(),
                        "pending_rewards": pending_rewards.to_string(),
                        "total_balance": total_balance.to_string()
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
            }
            None => create_json_response(json!({
                "status": "wallet_not_found",
                "wallet_type": wallet_type_str,
                "identity_id": identity_id,
                "message": format!("Wallet type {} not found for identity", wallet_type_str)
            })),
        }
    }

    /// Get comprehensive wallet statistics
    async fn handle_get_statistics(
        &self,
        identity_id: &str,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let identity_hash = Hash(identity_id_bytes);

        // TODO: Gate cross-identity statistics once mobile app is updated.
        // For now, return full data to maintain backward compatibility.

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
                "available_balance": summary.balance.saturating_sub(staked_balance).to_string(),
                "staked_balance": staked_balance.to_string(),
                "pending_rewards": pending_rewards.to_string(),
                "total_balance": (summary.balance + pending_rewards).to_string(),
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
            "total_balance": total_balance.to_string(),
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
        let principal = self.extract_principal(&request);
        let req_data: CrossWalletTransferRequest = serde_json::from_slice(&request.body)?;

        if !identity_id_matches_caller(&req_data.identity_id, &principal.did)
            && principal.role != lib_access_control::Role::Council
        {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Cannot transfer from an identity you don't own".to_string(),
            ));
        }

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

        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(&req_data.identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

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
        let purpose = req_data.purpose.unwrap_or_else(|| {
            format!(
                "Transfer from {:?} to {:?}",
                from_wallet_type, to_wallet_type
            )
        });

        match wallet_manager
            .transfer_between_wallets(
                from_wallet_type.clone(),
                to_wallet_type.clone(),
                req_data.amount,
                purpose.clone(),
            )
            .await
        {
            Ok(transaction_id) => create_json_response(json!({
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
            })),
            Err(e) => create_json_response(json!({
                "status": "transfer_failed",
                "identity_id": req_data.identity_id,
                "error": e.to_string(),
                "transaction": null
            })),
        }
    }

    /// Handle staking tokens
    async fn handle_stake_tokens(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = self.extract_principal(&request);
        let req_data: StakingRequest = serde_json::from_slice(&request.body)?;

        if !identity_id_matches_caller(&req_data.identity_id, &principal.did)
            && principal.role != lib_access_control::Role::Council
        {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Cannot stake from an identity you don't own".to_string(),
            ));
        }

        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(&req_data.identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

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
            if let Err(e) = wallet_manager
                .create_specialized_wallet(WalletType::Staking)
                .await
            {
                return create_json_response(json!({
                    "status": "staking_wallet_creation_failed",
                    "identity_id": req_data.identity_id,
                    "error": e.to_string()
                }));
            }
        }

        // Transfer from Primary to Staking wallet
        match wallet_manager
            .transfer_between_wallets(
                WalletType::Primary,
                WalletType::Staking,
                req_data.amount,
                "Staking tokens".to_string(),
            )
            .await
        {
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
            }
            Err(e) => create_json_response(json!({
                "status": "staking_failed",
                "identity_id": req_data.identity_id,
                "error": e.to_string()
            })),
        }
    }

    /// Handle unstaking tokens
    async fn handle_unstake_tokens(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = self.extract_principal(&request);
        let req_data: StakingRequest = serde_json::from_slice(&request.body)?;

        if !identity_id_matches_caller(&req_data.identity_id, &principal.did)
            && principal.role != lib_access_control::Role::Council
        {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Cannot unstake from an identity you don't own".to_string(),
            ));
        }

        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(&req_data.identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

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
        match wallet_manager
            .transfer_between_wallets(
                WalletType::Staking,
                WalletType::Primary,
                req_data.amount,
                "Unstaking tokens".to_string(),
            )
            .await
        {
            Ok(transaction_id) => create_json_response(json!({
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
            })),
            Err(e) => create_json_response(json!({
                "status": "unstaking_transfer_failed",
                "identity_id": req_data.identity_id,
                "error": e.to_string()
            })),
        }
    }

    // Helper functions

    /// Get identity by ID from the identity manager, with chain-backed hydrate.
    ///
    /// The in-memory IdentityManager is only populated on the node that handled
    /// registration (or a live handshake). Other validators still have the DID
    /// in sled / wallet_registry after block apply — hydrate a read-only view
    /// for wallet balance/list when the manager misses. Never overwrites an
    /// existing manager entry (avoids the wallet-ownership migration bug that
    /// forced full startup backfill to stay disabled).
    async fn get_identity_by_id(&self, identity_id: &[u8; 32]) -> Option<Identity> {
        let identity_hash = Hash(*identity_id);

        {
            let identity_manager = self.identity_manager.read().await;
            if let Some(identity) = identity_manager.get_identity(&identity_hash).cloned() {
                return Some(identity);
            }
        }

        self.hydrate_identity_from_chain(identity_id).await
    }

    /// Reconstruct a single identity + owned wallets from chain snapshots.
    async fn hydrate_identity_from_chain(&self, identity_id: &[u8; 32]) -> Option<Identity> {
        let identity_hash = Hash(*identity_id);
        let owner_hex = hex::encode(identity_id);

        let blockchain = self.blockchain.read().await;
        let identity_registry = blockchain.identity_registry_snapshot();
        let wallet_registry = blockchain.wallet_registry_snapshot();
        drop(blockchain);

        let identity_data = identity_registry.values().find(|data| {
            lib_identity::did::parse_did_to_identity_id(&data.did)
                .map(|id| id.as_bytes() == identity_id.as_slice())
                .unwrap_or(false)
        })?;

        let identity_type = match identity_data.identity_type.to_ascii_lowercase().as_str() {
            "human" => lib_identity::IdentityType::Human,
            "device" => lib_identity::IdentityType::Device,
            "organization" => lib_identity::IdentityType::Organization,
            "agent" => lib_identity::IdentityType::Agent,
            "contract" => lib_identity::IdentityType::Contract,
            _ => lib_identity::IdentityType::Human,
        };
        if matches!(identity_type, lib_identity::IdentityType::Device) {
            return None;
        }

        let public_key = lib_crypto::PublicKey::new(
            identity_data
                .public_key
                .as_slice()
                .try_into()
                .unwrap_or([0u8; 2592]),
        );
        let display_name = if identity_data.display_name.is_empty() {
            None
        } else {
            Some(identity_data.display_name.clone())
        };
        let mut identity = lib_identity::ZhtpIdentity::new_external(
            identity_data.did.clone(),
            public_key,
            identity_type,
            identity_data
                .did
                .trim_start_matches("did:zhtp:")
                .to_string(),
            display_name,
            identity_data.created_at,
        )
        .ok()?;
        identity.did_document_hash = Some(lib_crypto::Hash::from_bytes(
            identity_data.did_document_hash.as_bytes(),
        ));
        identity.wallet_manager.wallets.clear();
        identity.wallet_manager.total_balance = 0;

        for wallet_data in wallet_registry.values() {
            let owned = wallet_data
                .owner_identity_id
                .map(|owner| hex::encode(owner.as_bytes()) == owner_hex)
                .unwrap_or(false);
            if !owned {
                continue;
            }
            let wallet_type = match wallet_data.wallet_type.to_ascii_lowercase().as_str() {
                "primary" => lib_identity::wallets::WalletType::Primary,
                "ubi" => lib_identity::wallets::WalletType::UBI,
                "savings" => lib_identity::wallets::WalletType::Savings,
                "business" => lib_identity::wallets::WalletType::Business,
                "stealth" => lib_identity::wallets::WalletType::Stealth,
                "dao" | "nonprofitdao" | "non_profit_dao" | "non-profit-dao" => {
                    lib_identity::wallets::WalletType::NonProfitDAO
                }
                "forprofitdao" | "for_profit_dao" | "for-profit-dao" => {
                    lib_identity::wallets::WalletType::ForProfitDAO
                }
                "standard" => lib_identity::wallets::WalletType::Standard,
                _ => lib_identity::wallets::WalletType::Primary,
            };
            if let Ok(wallet_id) = identity.wallet_manager.add_restored_wallet(
                &hex::encode(wallet_data.wallet_id.as_bytes()),
                wallet_type,
                wallet_data.created_at,
            ) {
                if let Some(wallet) = identity.wallet_manager.get_wallet_mut(&wallet_id) {
                    wallet.name = wallet_data.wallet_name.clone();
                    wallet.alias = wallet_data.alias.clone();
                    wallet.public_key = wallet_data.public_key.clone();
                    wallet.seed_commitment =
                        Some(hex::encode(wallet_data.seed_commitment.as_bytes()));
                    wallet.balance = wallet_data.initial_balance;
                }
            }
        }

        // Cache only if still missing — never overwrite live registration state.
        {
            let mut identity_manager = self.identity_manager.write().await;
            if identity_manager.get_identity(&identity_hash).is_none() {
                identity_manager.add_identity(identity.clone());
            } else if let Some(existing) = identity_manager.get_identity(&identity_hash).cloned() {
                return Some(existing);
            }
        }

        Some(identity)
    }

    /// Parse wallet type string to WalletType enum
    fn parse_wallet_type(&self, wallet_type_str: &str) -> Option<WalletType> {
        match wallet_type_str.to_lowercase().as_str() {
            "primary" => Some(WalletType::Primary),
            "ispbypassrewards" | "isp_bypass_rewards" => Some(WalletType::IspBypassRewards),
            "meshdiscoveryrewards" | "mesh_discovery_rewards" => {
                Some(WalletType::MeshDiscoveryRewards)
            }
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

    fn infer_transaction_amount(tx: &lib_blockchain::transaction::Transaction) -> u128 {
        if let Some(data) = tx.token_transfer_data() {
            return data.amount;
        }
        if let Some(data) = tx.token_mint_data() {
            return data.amount;
        }
        if let Some(data) = tx.dao_execution_data() {
            return data.amount.unwrap_or(tx.outputs.len() as u64) as u128;
        }
        tx.outputs.len() as u128
    }

    fn canonical_key_id_from_public_key_bytes(public_key: &[u8]) -> Option<[u8; 32]> {
        if public_key.is_empty() {
            return None;
        }
        if public_key.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(public_key);
            return Some(id);
        }
        Some(
            lib_blockchain::integration::crypto_integration::PublicKey::new(
                public_key.try_into().unwrap_or([0u8; 2592])
            ).key_id,
        )
    }

    fn tx_involves_identity(
        tx: &lib_blockchain::transaction::Transaction,
        tracked_key_ids: &HashSet<[u8; 32]>,
        identity_id_bytes: &[u8; 32],
        identity_id_hex: &str,
        identity_did: &str,
    ) -> bool {
        if tracked_key_ids.contains(&tx.signature.public_key.key_id) {
            return true;
        }

        if tx
            .outputs
            .iter()
            .any(|output| tracked_key_ids.contains(&output.recipient.key_id))
        {
            return true;
        }

        if let Some(data) = tx.identity_data() {
            if data.did == identity_did {
                return true;
            }
            if data.owned_wallets.iter().any(|wallet_id| {
                if let Ok(bytes) = hex::decode(wallet_id) {
                    if bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        return tracked_key_ids.contains(&id);
                    }
                }
                false
            }) {
                return true;
            }
        }

        if let Some(data) = tx.wallet_data() {
            if data
                .owner_identity_id
                .as_ref()
                .is_some_and(|owner| owner.as_bytes() == identity_id_bytes)
            {
                return true;
            }
            if tracked_key_ids.contains(&data.wallet_id.as_array()) {
                return true;
            }
            if let Some(id) = Self::canonical_key_id_from_public_key_bytes(&data.public_key) {
                if tracked_key_ids.contains(&id) {
                    return true;
                }
            }
        }

        if let Some(data) = tx.dao_proposal_data() {
            if data.proposer == identity_did || data.proposer == identity_id_hex {
                return true;
            }
        }

        if let Some(data) = tx.dao_vote_data() {
            if data.voter == identity_did || data.voter == identity_id_hex {
                return true;
            }
        }

        if let Some(data) = tx.dao_execution_data() {
            if data.executor == identity_did || data.executor == identity_id_hex {
                return true;
            }
            if let Some(recipient) = &data.recipient {
                if recipient == identity_did || recipient == identity_id_hex {
                    return true;
                }
            }
        }

        if let Some(data) = tx.ubi_claim_data() {
            if data.claimant_identity == identity_did || data.claimant_identity == identity_id_hex {
                return true;
            }
            if tracked_key_ids.contains(&data.recipient_wallet.key_id) {
                return true;
            }
        }

        if let Some(data) = tx.profit_declaration_data() {
            if data.declarant_identity == identity_did || data.declarant_identity == identity_id_hex
            {
                return true;
            }
            if tracked_key_ids.contains(&data.nonprofit_treasury.key_id)
                || tracked_key_ids.contains(&data.forprofit_treasury.key_id)
            {
                return true;
            }
        }

        if let Some(data) = tx.token_transfer_data() {
            if tracked_key_ids.contains(&data.from) || tracked_key_ids.contains(&data.to) {
                return true;
            }
        }

        if let Some(data) = tx.token_mint_data() {
            if tracked_key_ids.contains(&data.to) {
                return true;
            }
        }

        if let Some(data) = tx.governance_config_data() {
            if tracked_key_ids.contains(&data.caller) {
                return true;
            }
        }

        if let Some(data) = tx.bonding_curve_deploy_data() {
            if tracked_key_ids.contains(&data.creator) {
                return true;
            }
        }

        if let Some(data) = tx.bonding_curve_buy_data() {
            if tracked_key_ids.contains(&data.buyer) {
                return true;
            }
        }

        if let Some(data) = tx.bonding_curve_sell_data() {
            if tracked_key_ids.contains(&data.seller) {
                return true;
            }
        }

        if let Some(data) = tx.bonding_curve_graduate_data() {
            if tracked_key_ids.contains(&data.graduator) {
                return true;
            }
        }

        false
    }

    fn tx_to_record(
        tx: &lib_blockchain::transaction::Transaction,
        status: &str,
        timestamp: u64,
        block_height: Option<u64>,
    ) -> TransactionRecord {
        let tx_hash = tx.hash();
        let amount = Self::infer_transaction_amount(tx);
        let from_wallet = tx.token_transfer_data().map(|d| hex::encode(d.from));
        let to_address = tx
            .token_transfer_data()
            .map(|d| hex::encode(d.to))
            .or_else(|| tx.token_mint_data().map(|d| hex::encode(d.to)));

        TransactionRecord {
            tx_hash: hex::encode(tx_hash.as_bytes()),
            tx_type: format!("{:?}", tx.transaction_type),
            amount,
            fee: tx.fee as u128,
            from_wallet,
            to_address,
            timestamp,
            block_height,
            status: status.to_string(),
            memo: if tx.memo.is_empty() {
                None
            } else {
                Some(hex::encode(&tx.memo))
            },
        }
    }

    /// Get transaction history for an identity
    async fn handle_get_transactions(
        &self,
        identity_id: &str,
        request: &ZhtpRequest,
    ) -> Result<ZhtpResponse> {
        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(identity_id) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };
        let identity_hash = Hash(identity_id_bytes);

        // Graph-traversal guard: WalletGraph / Read
        // TODO: Gate cross-identity transaction history once mobile app is updated.
        // For now, return full data to maintain backward compatibility.

        // The in-memory identity_manager is an optional fast-path only; a miss
        // must not hide on-chain transaction history. Fall through to the
        // blockchain wallet_registry + block scan regardless.
        let identity_opt = self.get_identity_by_id(&identity_id_bytes).await;

        let identity_did = identity_opt
            .as_ref()
            .map(|identity| identity.did.clone())
            .unwrap_or_else(|| format!("did:zhtp:{}", identity_id));
        let mut tracked_key_ids: HashSet<[u8; 32]> = HashSet::new();
        // The URL identity id is itself a tracked key id (DID == key_id form).
        tracked_key_ids.insert(identity_id_bytes);
        if let Some(ref identity) = identity_opt {
            tracked_key_ids.insert(identity.public_key.key_id);
            for wallet in identity.list_wallets() {
                tracked_key_ids.insert(wallet.id.0);
            }
        }

        // Get blockchain
        let blockchain = self.blockchain.read().await;

        // Include any wallet registry entries linked to this identity that may
        // not be present in the in-memory identity wallet manager.
        for (wallet_id_hex, wallet_data) in blockchain.wallet_registry_snapshot() {
            if wallet_data
                .owner_identity_id
                .as_ref()
                .is_some_and(|owner| owner.as_bytes() == identity_id_bytes)
            {
                if let Ok(bytes) = hex::decode(wallet_id_hex) {
                    if bytes.len() == 32 {
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        tracked_key_ids.insert(id);
                    }
                }
                if let Some(id) =
                    Self::canonical_key_id_from_public_key_bytes(&wallet_data.public_key)
                {
                    tracked_key_ids.insert(id);
                }
            }
        }

        // Collect all transactions involving this identity (confirmed + pending).
        // Use a map keyed by hash to avoid duplicate records.
        let mut tx_by_hash: HashMap<String, TransactionRecord> = HashMap::new();

        // Search through all blocks for transactions
        // #2636: iter_blocks() (full chain) — query_blocks() saw only the window.
        for block in blockchain.iter_blocks() {
            for tx in &block.transactions {
                if Self::tx_involves_identity(
                    tx,
                    &tracked_key_ids,
                    &identity_id_bytes,
                    identity_id,
                    &identity_did,
                ) {
                    let record = Self::tx_to_record(
                        tx,
                        "confirmed",
                        block.timestamp(),
                        Some(block.height()),
                    );
                    tx_by_hash.insert(record.tx_hash.clone(), record);
                }
            }
        }

        // Also check pending transactions
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pending = blockchain.query_pending_transactions();
        for tx in &pending {
            if Self::tx_involves_identity(
                tx,
                &tracked_key_ids,
                &identity_id_bytes,
                identity_id,
                &identity_did,
            ) {
                let ts = if tx.signature.timestamp > 0 {
                    tx.signature.timestamp
                } else {
                    now
                };
                let record = Self::tx_to_record(tx, "pending", ts, None);
                tx_by_hash.entry(record.tx_hash.clone()).or_insert(record);
            }
        }

        drop(blockchain);

        let mut transactions: Vec<TransactionRecord> = tx_by_hash.into_values().collect();

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
        let principal = self.extract_principal(&request);
        let send_req: SimpleSendRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request body: {}", e))?;

        if !identity_id_matches_caller(&send_req.from_identity, &principal.did)
            && principal.role != lib_access_control::Role::Council
        {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Cannot send from an identity you don't own".to_string(),
            ));
        }

        let identity_id_bytes = match Self::parse_identity_id_or_bad_request(&send_req.from_identity) {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

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
        let primary_wallet = wallets
            .iter()
            .find(|w| w.wallet_type == lib_identity::wallets::WalletType::Primary)
            .ok_or_else(|| anyhow::anyhow!("No primary wallet found"))?;

        // Check balance
        if primary_wallet.balance < send_req.amount {
            return Ok(create_error_response(
                ZhtpStatus::PaymentRequired,
                format!(
                    "Insufficient balance. Available: {}, Required: {}",
                    primary_wallet.balance, send_req.amount
                ),
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
    #[allow(dead_code)]
    fn generate_wallet_id(
        &self,
        wallet_type: &lib_identity::wallets::WalletType,
        identity_id: &str,
    ) -> String {
        match wallet_type {
            lib_identity::wallets::WalletType::Primary => format!("wallet_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Standard => {
                format!("standard_{}", &identity_id[..12])
            }
            lib_identity::wallets::WalletType::UBI => format!("ubi_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Savings => format!("savings_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::Business => {
                format!("business_{}", &identity_id[..12])
            }
            lib_identity::wallets::WalletType::Stealth => format!("stealth_{}", &identity_id[..12]),
            lib_identity::wallets::WalletType::NonProfitDAO => {
                format!("nonprofit_{}", &identity_id[..12])
            }
            lib_identity::wallets::WalletType::ForProfitDAO => {
                format!("forprofit_{}", &identity_id[..12])
            }
        }
    }

    /// Convert wallet permissions to API format
    #[allow(dead_code)]
    fn convert_permissions(
        &self,
        permissions: &lib_economy::wallets::multi_wallet::WalletPermissions,
    ) -> WalletPermissionsInfo {
        WalletPermissionsInfo {
            can_transfer_external: permissions.can_transfer_external,
            can_vote: permissions.can_vote,
            can_stake: permissions.can_stake,
            can_receive_rewards: permissions.can_receive_rewards,
            daily_transaction_limit: permissions.daily_transaction_limit,
            requires_multisig_threshold: permissions.requires_multisig_threshold,
        }
    }

    /// Provision a wallet for an existing identity.
    ///
    /// Registers a wallet in the blockchain wallet_registry with the given ID and
    /// owner. If `welcome_bonus` is true, mints the SOV welcome bonus. The wallet
    /// registration transaction is included in the next block, persisting the wallet
    /// on-chain.
    ///
    /// Used for:
    /// - Restoring wallets lost during testnet resets
    /// - Provisioning wallets for observed-only identities
    async fn handle_provision_wallet(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let principal = self.extract_principal(&request);
        if principal.role != lib_access_control::Role::Council
            && principal.role != lib_access_control::Role::System
        {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Wallet provisioning requires council authorization".to_string(),
            ));
        }

        #[derive(serde::Deserialize)]
        struct ProvisionRequest {
            wallet_id: String,
            owner_identity_id: String,
            wallet_type: String,
            #[serde(default)]
            welcome_bonus: bool,
            /// Optional dilithium public key hex (2592 bytes). If omitted, looked up
            /// from the on-chain identity registry.
            #[serde(default)]
            public_key: Option<String>,
        }

        let req: ProvisionRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("invalid provision request: {}", e))?;

        // Parse wallet_id
        let wallet_id_bytes = hex::decode(&req.wallet_id)
            .map_err(|_| anyhow::anyhow!("invalid wallet_id hex"))?;
        if wallet_id_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "wallet_id must be 32 bytes".to_string(),
            ));
        }
        let mut wallet_id_arr = [0u8; 32];
        wallet_id_arr.copy_from_slice(&wallet_id_bytes);

        // Parse owner identity ID
        let owner_hex = req.owner_identity_id
            .strip_prefix("did:zhtp:")
            .unwrap_or(&req.owner_identity_id);
        let owner_bytes = hex::decode(owner_hex)
            .map_err(|_| anyhow::anyhow!("invalid owner_identity_id hex"))?;
        if owner_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "owner_identity_id must be 32 bytes".to_string(),
            ));
        }
        let mut owner_arr = [0u8; 32];
        owner_arr.copy_from_slice(&owner_bytes);

        // Resolve public key: explicit or from identity registry
        let public_key_bytes = if let Some(pk_hex) = &req.public_key {
            hex::decode(pk_hex).map_err(|_| anyhow::anyhow!("invalid public_key hex"))?
        } else {
            // Look up from identity registry
            let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
                .await
                .map_err(|e| anyhow::anyhow!("blockchain unavailable: {}", e))?;
            let blockchain = blockchain_arc.read().await;
            let did = format!("did:zhtp:{}", owner_hex);
            // #2639: sled-first dilithium key (consensus-pinned), in-mem pending
            // fallback. Fail CLOSED when the owner's on-chain key is missing or
            // refused (e.g. consensus-pin mismatch): provisioning a wallet with a
            // placeholder zero key would create an unusable, on-chain-invalid wallet.
            match blockchain.identity_public_key(&did) {
                Some(pk) => pk,
                None => {
                    return Ok(create_error_response(
                        ZhtpStatus::NotFound,
                        format!(
                            "Owner identity {} has no usable on-chain public key; register the identity first",
                            did
                        ),
                    ));
                }
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let public_key_for_wallet = public_key_bytes.clone();

        let welcome_bonus_amount: u128 = if req.welcome_bonus {
            lib_types::sov::atoms(5000)
        } else {
            0
        };

        let wallet_data = lib_blockchain::transaction::WalletTransactionData {
            wallet_id: lib_blockchain::Hash::from_slice(&wallet_id_arr),
            wallet_type: req.wallet_type.clone(),
            wallet_name: format!("{} Wallet (provisioned)", req.wallet_type),
            alias: Some(req.wallet_type.to_lowercase()),
            public_key: public_key_for_wallet,
            owner_identity_id: Some(lib_blockchain::Hash::from_slice(&owner_arr)),
            seed_commitment: lib_blockchain::types::hash::blake3_hash(b"provisioned_wallet"),
            created_at: now,
            registration_fee: 0,
            capabilities: if req.wallet_type == "Primary" { 0xFF } else { 0x01 },
            initial_balance: 0,
        };

        // Register on blockchain — creates system transaction for block inclusion
        let blockchain_arc = crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("blockchain unavailable: {}", e))?;
        {
            let mut blockchain = blockchain_arc.write().await;

            // If the owner identity is not in the identity_registry, register it
            // via a system transaction so it persists in blocks on all nodes.
            let did = format!("did:zhtp:{}", owner_hex);
            if !blockchain.query_identity_exists(&did) {
                let identity_data = lib_blockchain::transaction::IdentityTransactionData {
                    did: did.clone(),
                    display_name: String::new(),
                    public_key: public_key_bytes.clone(),
                    ownership_proof: vec![],
                    identity_type: "human".to_string(),
                    did_document_hash: lib_blockchain::types::hash::blake3_hash(
                        format!("provisioned_identity_{}", owner_hex).as_bytes(),
                    ),
                    created_at: now,
                    registration_fee: 0,
                    dao_fee: 0,
                    controlled_nodes: vec![],
                    owned_wallets: vec![],
                    kyber_public_key: vec![],
                };

                // Create IdentityRegistration system transaction for block persistence
                let identity_tx = lib_blockchain::transaction::Transaction::new_identity_registration(
                    identity_data.clone(),
                    vec![],
                    lib_blockchain::integration::crypto_integration::Signature {
                        signature: Vec::new(),
                        public_key: lib_blockchain::integration::crypto_integration::PublicKey::new(
                            public_key_bytes.as_slice().try_into().unwrap_or([0u8; 2592]),
                        ),
                        algorithm: lib_blockchain::integration::crypto_integration::SignatureAlgorithm::DEFAULT,
                        timestamp: now,
                    },
                    format!("Provisioned identity {}", &did[..40.min(did.len())]).into_bytes(),
                );
                if let Err(e) = blockchain.add_system_transaction(identity_tx, lib_blockchain::SystemOriginator::IdentityProvisioning) {
                    tracing::warn!("Failed to submit identity tx: {}", e);
                }
                // Cache warmup: identity must be visible immediately for QUIC handshake
                // validation. The system transaction above ensures it persists in blocks,
                // but won't be committed until the next block. This in-memory insert
                // bridges the gap until block commit. Note: identity_blocks height will
                // be the current chain height (not the future block height where the tx
                // lands), but this is acceptable for the handshake check.
                blockchain.insert_identity_shadow(did.clone(), identity_data);
                let current_height = blockchain.get_height();
                blockchain.identity_blocks.insert(did.clone(), current_height);
                tracing::info!(
                    "📝 Identity registered: {} (system tx + in-memory)",
                    &did[..40.min(did.len())],
                );
            }

            match blockchain.register_wallet(wallet_data) {
                Ok(tx_hash) => {
                    if req.welcome_bonus && welcome_bonus_amount > 0 {
                        let memo = format!(
                            "WELCOME_BONUS_V1:{}",
                            hex::encode(wallet_id_arr)
                        )
                        .into_bytes();
                        if let Ok(mint_tx) = crate::runtime::token_utils::build_sov_mint_tx(
                            &wallet_id_arr,
                            welcome_bonus_amount,
                            memo,
                        )
                        .await
                        {
                            if let Err(e) = blockchain.add_system_transaction(
                                mint_tx,
                                lib_blockchain::SystemOriginator::TreasuryWalletBootstrap,
                            ) {
                                tracing::warn!(
                                    "Failed to queue welcome bonus TokenMint: {}",
                                    e
                                );
                            }
                        } else {
                            tracing::warn!("Failed to build welcome bonus TokenMint");
                        }
                    }
                    tracing::info!(
                        "✅ Wallet provisioned: {} (type={}, owner={}, bonus={})",
                        &req.wallet_id[..16.min(req.wallet_id.len())],
                        req.wallet_type,
                        &owner_hex[..16.min(owner_hex.len())],
                        req.welcome_bonus,
                    );
                    create_json_response(serde_json::json!({
                        "status": "success",
                        "wallet_id": req.wallet_id,
                        "owner_identity_id": req.owner_identity_id,
                        "wallet_type": req.wallet_type,
                        "welcome_bonus": welcome_bonus_amount.to_string(),
                        "tx_hash": hex::encode(tx_hash.as_bytes()),
                    }))
                }
                Err(e) => {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        format!("Wallet provision failed: {}", e),
                    ))
                }
            }
        }
    }
}
