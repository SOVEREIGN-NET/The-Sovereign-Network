//! Token Handler Module
//!
//! Mutation API for custom token mint, transfer, burn, and nonce lookup.
//! Read/discovery paths were deprecated in SA-8 — use `/api/v1/assets/*` instead.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

// Blockchain imports
use lib_blockchain::transaction::Transaction;
use lib_blockchain::{Blockchain, BlockchainQuery};

/// Helper function to create JSON responses
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

/// SA-8: legacy `/api/v1/token` read/create routes return 410 Gone with successor pointer.
fn token_deprecated_gone(successor: &str) -> ZhtpResponse {
    create_error_response(
        ZhtpStatus::Gone,
        format!(
            "This /api/v1/token endpoint is deprecated (SA-8). Use {successor} instead."
        ),
    )
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to mint tokens (client must provide signed tx)
#[derive(Debug, Deserialize)]
pub struct MintTokenRequest {
    pub signed_tx: String,
}

/// Request to transfer tokens (client must provide signed tx)
#[derive(Debug, Deserialize)]
pub struct TransferTokenRequest {
    pub signed_tx: String,
}

/// Request to burn tokens (client must provide signed tx)
#[derive(Debug, Deserialize)]
pub struct BurnTokenRequest {
    pub signed_tx: String,
}

/// Serialize u128 as string to avoid JSON number overflow (u128 > Number.MAX_SAFE_INTEGER).
pub mod u128_as_string {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
}
pub mod option_u128_as_string {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(n) => s.serialize_str(&n.to_string()),
            None => s.serialize_none(),
        }
    }
}

// ============================================================================
// Token Handler
// ============================================================================

/// Token operations handler (mutation + nonce; reads deprecated → `/api/v1/assets/*`).
pub struct TokenHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl TokenHandler {
    pub fn new() -> Self {
        // Get blockchain from global provider
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });

        Self { blockchain }
    }

    /// POST /api/v1/token/mint - Mint tokens (creator only)
    async fn handle_mint_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let mint_req: MintTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let tx = match self.decode_signed_tx_raw(&mint_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
            }
        };

        if tx.transaction_type != lib_blockchain::TransactionType::TokenMint {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token mint requires TransactionType::TokenMint".to_string(),
            ));
        }

        let mint = match tx.token_mint_data() {
            Some(m) => m,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "TokenMint missing token_mint_data".to_string(),
                ));
            }
        };
        let token_id = mint.token_id;
        let to = mint.to;
        let amount = mint.amount;

        if let Err(e) = self.submit_to_mempool(tx).await {
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        info!("Mint submitted for token {}", hex::encode(token_id));

        create_json_response(json!({
            "success": true,
            "token_id": hex::encode(token_id),
            "to": format!("0x{}", hex::encode(to)),
            "amount_minted": amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/transfer - Transfer tokens
    ///
    /// The `to` field can be:
    /// - 32 bytes: wallet_id OR key_id (DID suffix) - resolved via wallet_registry then identity_registry
    /// - 2592 bytes: full Dilithium5 public key (used directly)
    ///
    /// Resolution order for 32-byte values:
    /// 1. Try wallet_registry[to] - direct wallet lookup
    /// 2. If not found, try identity_registry[to] - DID key_id lookup
    /// 3. Fail if neither found or ambiguous
    async fn handle_transfer_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let transfer_req: TransferTokenRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("[token/transfer] invalid request: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request: {}", e),
                ));
            }
        };

        let tx = match self.decode_signed_tx_raw(&transfer_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::error!("[token/transfer] decode failed: {}", e);
                return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
            }
        };

        // Canonical path: TokenTransfer only.
        let (recipient_hex, token_id_hex, amount) =
            if tx.transaction_type == lib_blockchain::TransactionType::TokenTransfer {
                match tx.token_transfer_data() {
                    Some(d) => (hex::encode(d.to), hex::encode(d.token_id), d.amount),
                    None => {
                        tracing::error!(
                            "[token/transfer] TokenTransfer payload missing (version={})",
                            tx.version
                        );
                        return Ok(create_error_response(
                            ZhtpStatus::BadRequest,
                            "TokenTransfer missing data".to_string(),
                        ));
                    }
                }
            } else {
                tracing::error!(
                    "[token/transfer] wrong tx type: {:?} (expected TokenTransfer)",
                    tx.transaction_type
                );
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!(
                        "Token transfer requires TransactionType::TokenTransfer, got {:?}",
                        tx.transaction_type
                    ),
                ));
            };

        let is_sov = token_id_hex
            == hex::encode(lib_blockchain::contracts::utils::generate_lib_token_id())
            || token_id_hex == "0000000000000000000000000000000000000000000000000000000000000000";

        // Recipient validation: log findings but don't reject — the token contract
        // will handle balance for any valid key_id.
        let blockchain = self.blockchain.read().await;
        let in_wallet = blockchain.query_wallet_exists(&recipient_hex);
        let in_identity = if is_sov {
            false
        } else {
            let did_key = format!("did:zhtp:{}", recipient_hex);
            blockchain.query_identity_exists(&did_key)
        };
        drop(blockchain);

        if !in_wallet && !in_identity {
            tracing::warn!(
                "[token/transfer] recipient unknown: to={} in_wallet={} in_identity={}",
                &recipient_hex[..8.min(recipient_hex.len())],
                in_wallet,
                in_identity,
            );
        }

        if let Err(e) = self.submit_to_mempool(tx).await {
            tracing::error!("[token/transfer] mempool rejected: to={} amount={} err={}", &recipient_hex[..8.min(recipient_hex.len())], amount, e);
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        tracing::info!(
            "[token/transfer] accepted: token={} to={} amount={}",
            if is_sov { "SOV" } else { &token_id_hex[..8.min(token_id_hex.len())] },
            &recipient_hex[..8.min(recipient_hex.len())],
            amount,
        );
        create_json_response(json!({
            "success": true,
            "token_id": token_id_hex,
            "to": recipient_hex,
            "amount": amount.to_string(),
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/burn - Burn tokens (caller burns own balance)
    async fn handle_burn_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let burn_req: BurnTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let tx = match self.decode_signed_tx_raw(&burn_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
            }
        };
        let _ = tx;
        Ok(create_error_response(
            ZhtpStatus::BadRequest,
            "Token burn via ContractExecution is disabled; use canonical typed token mutation transactions".to_string(),
        ))
    }

    /// GET /api/v1/token/nonce/{token_id}/{address} - Get expected nonce for transfer replay protection
    async fn handle_get_nonce(
        &self,
        token_id_hex: &str,
        address_hex: &str,
    ) -> Result<ZhtpResponse> {
        let token_id_bytes = match hex::decode(token_id_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Invalid token_id hex".to_string(),
                ))
            }
        };
        if token_id_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "token_id must be 32 bytes (64 hex chars)".to_string(),
            ));
        }
        let mut token_id = [0u8; 32];
        token_id.copy_from_slice(&token_id_bytes);

        let address_bytes = match hex::decode(address_hex) {
            Ok(b) => b,
            Err(_) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Invalid address hex".to_string(),
                ))
            }
        };
        if address_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Address must be 32 bytes (64 hex chars)".to_string(),
            ));
        }
        let mut address = [0u8; 32];
        address.copy_from_slice(&address_bytes);

        let blockchain = self.blockchain.read().await;
        let nonce = match blockchain.token_nonce(&token_id, &address) {
            Ok(n) => n,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::InternalServerError,
                    format!("nonce lookup failed: {e}"),
                ));
            }
        };

        create_json_response(json!({
            "token_id": token_id_hex,
            "address": address_hex,
            "nonce": nonce
        }))
    }

    fn decode_signed_tx_raw(&self, signed_tx: &str) -> Result<Transaction> {
        let tx_bytes =
            hex::decode(signed_tx).map_err(|_| anyhow::anyhow!("Invalid signed_tx hex"))?;
        lib_blockchain::transaction::decode_client_transaction(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signed_tx payload: {}", e))
    }

    async fn submit_to_mempool(&self, tx: Transaction) -> Result<()> {
        let tx_type = tx.transaction_type;
        let mut blockchain = self.blockchain.write().await;
        blockchain
            .add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit transaction to mempool: {}", e))?;
        tracing::debug!("submit_to_mempool: type={:?} accepted", tx_type);
        Ok(())
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for TokenHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Token handler: {} {}", request.method, request.uri);

        // Access zone gate: password sessions cannot access token/balance endpoints
        if crate::session_manager::is_request_password_session(&request).await {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Token access requires key authentication (mobile app or seed phrase recovery)".to_string(),
            ));
        }

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/token/create — deprecated (SA-8)
            (ZhtpMethod::Post, "/api/v1/token/create") => {
                Ok(token_deprecated_gone("POST /api/v1/assets/launch"))
            }
            // POST /api/v1/token/mint
            (ZhtpMethod::Post, "/api/v1/token/mint") => self.handle_mint_token(request).await,
            // POST /api/v1/token/transfer
            (ZhtpMethod::Post, "/api/v1/token/transfer") => {
                self.handle_transfer_token(request).await
            }
            // POST /api/v1/token/burn
            (ZhtpMethod::Post, "/api/v1/token/burn") => self.handle_burn_token(request).await,
            // GET /api/v1/token/list — deprecated (SA-8)
            (ZhtpMethod::Get, "/api/v1/token/list") => {
                Ok(token_deprecated_gone("GET /api/v1/assets"))
            }
            // GET /api/v1/token/symbol/available/{symbol} — deprecated (SA-8)
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/symbol/available/") => {
                let symbol = path
                    .strip_prefix("/api/v1/token/symbol/available/")
                    .unwrap_or("");
                if symbol.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Symbol required".to_string(),
                    ))
                } else {
                    Ok(token_deprecated_gone(&format!(
                        "GET /api/v1/assets/symbol/available/{symbol}"
                    )))
                }
            }
            // GET /api/v1/token/balances/{address} — deprecated (SA-8)
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/balances/") => {
                let address = path.strip_prefix("/api/v1/token/balances/").unwrap_or("");
                if address.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Address required".to_string(),
                    ))
                } else {
                    Ok(token_deprecated_gone(
                        "GET /api/v1/assets then GET /api/v1/assets/{asset_id}/balances/{address}",
                    ))
                }
            }
            // GET /api/v1/token/nonce/{token_id}/{address}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/nonce/") => {
                let suffix = path.strip_prefix("/api/v1/token/nonce/").unwrap_or("");
                let mut parts = suffix.split('/');
                let token_id = parts.next().unwrap_or("");
                let address = parts.next().unwrap_or("");
                if token_id.is_empty() || address.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "token_id and address required".to_string(),
                    ))
                } else {
                    self.handle_get_nonce(token_id, address).await
                }
            }
            // GET /api/v1/token/{id} — deprecated (SA-8)
            (ZhtpMethod::Get, path)
                if path.starts_with("/api/v1/token/") && !path.contains("/balance") =>
            {
                let token_id = path.strip_prefix("/api/v1/token/").unwrap_or("");
                if token_id.is_empty() || token_id == "list" {
                    Ok(token_deprecated_gone("GET /api/v1/assets"))
                } else {
                    Ok(token_deprecated_gone(&format!(
                        "GET /api/v1/assets/{token_id}"
                    )))
                }
            }
            // GET /api/v1/token/{id}/balance/{address} — deprecated (SA-8)
            (ZhtpMethod::Get, path) if path.contains("/balance/") => {
                let parts: Vec<&str> = path.split('/').collect();
                if parts.len() >= 7 {
                    let token_id = parts[4];
                    let address = parts.get(6).unwrap_or(&"");
                    Ok(token_deprecated_gone(&format!(
                        "GET /api/v1/assets/{token_id}/balances/{address}"
                    )))
                } else {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Invalid balance path format".to_string(),
                    ))
                }
            }
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                format!(
                    "Token endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
        };

        response.map_err(|e| {
            warn!("Token handler error: {}", e);
            anyhow::anyhow!("Token handler error: {}", e)
        })
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/token")
    }
}

impl Default for TokenHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_balance_path_parsing() {
        // /api/v1/token/{id}/balance/{address}
        // parts: ["", "api", "v1", "token", "{id}", "balance", "{address}"]
        let path = "/api/v1/token/abc123/balance/def456";
        let parts: Vec<&str> = path.split('/').collect();

        assert!(parts.len() >= 7);
        assert_eq!(parts[4], "abc123");
        assert_eq!(parts[6], "def456");
    }

    #[test]
    fn test_balance_path_malformed_rejected() {
        let path = "/api/v1/token/abc123/balance";
        let parts: Vec<&str> = path.split('/').collect();
        assert!(parts.len() < 7);
    }

    #[test]
    fn token_deprecated_gone_uses_410_status() {
        let resp = super::token_deprecated_gone("GET /api/v1/assets");
        assert_eq!(resp.status, lib_protocols::types::ZhtpStatus::Gone);
        assert!(resp.status_message.contains("/api/v1/assets"));
    }
}