//! Token Handler Module
//!
//! Complete token management API for custom token creation, minting, and transfer.
//! Enables users to create their own tokens on the ZHTP blockchain.

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn, debug};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Blockchain imports
use lib_blockchain::Blockchain;
use lib_blockchain::transaction::{TokenCreationPayloadV1, Transaction};
use lib_blockchain::contracts::utils::generate_custom_token_id;
use lib_blockchain::types::transaction_type::TransactionType;
use lib_crypto::types::keys::PublicKey;

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

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to submit a signed token transaction
#[derive(Debug, Deserialize)]
pub struct SubmitTokenTransactionRequest {
    /// Hex-encoded bincode Transaction
    pub signed_tx: String,
}

/// Request to create a new token (client must provide signed tx)
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub signed_tx: String,
}

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

/// Token info response
#[derive(Debug, Serialize)]
pub struct TokenInfoResponse {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub max_supply: Option<u64>,
    pub creator: String,
    pub is_deflationary: bool,
    pub created_at_block: Option<u64>,
}

/// Token list item
#[derive(Debug, Serialize)]
pub struct TokenListItem {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub total_supply: u64,
}

// ============================================================================
// Token Handler
// ============================================================================

/// Token operations handler
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

    /// POST /api/v1/token/create - Create a new custom token
    async fn handle_create_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        tracing::warn!("[FLOW] token/create: ENTER body_len={}", request.body.len());
        let create_req: CreateTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let tx = match self.decode_signed_tx_raw(&create_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!("[FLOW] token/create: decode_signed_tx FAILED: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };
        tracing::warn!(
            "[FLOW] token/create decoded tx: size={}, memo_len={}, fee={}, inputs={}, outputs={}",
            tx.size(),
            tx.memo.len(),
            tx.fee,
            tx.inputs.len(),
            tx.outputs.len()
        );

        if tx.transaction_type != TransactionType::TokenCreation {
            let reason = if tx.transaction_type == TransactionType::ContractExecution {
                "Deprecated token create transaction type. Use canonical TokenCreation transaction".to_string()
            } else {
                format!(
                    "Invalid transaction type for token/create: expected TokenCreation, got {:?}",
                    tx.transaction_type
                )
            };
            tracing::warn!("[FLOW] token/create: invalid tx type: {}", reason);
            return Ok(create_error_response(ZhtpStatus::BadRequest, reason));
        }

        let payload = match TokenCreationPayloadV1::decode_memo(&tx.memo) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("[FLOW] token/create: payload decode FAILED: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid token creation payload: {}", e),
                ));
            }
        };
        let (creator_allocation, treasury_allocation) = payload.split_initial_supply();
        let TokenCreationPayloadV1 {
            name,
            symbol,
            initial_supply,
            decimals,
            treasury_allocation_bps,
            treasury_recipient,
        } = payload;
        let treasury_recipient_hex = hex::encode(treasury_recipient);
        tracing::warn!(
            "[FLOW] token/create params: name='{}' symbol='{}' supply={} decimals={} treasury_bps={} treasury={}",
            name,
            symbol,
            initial_supply,
            decimals,
            treasury_allocation_bps,
            treasury_recipient_hex
        );

        if name.is_empty() || symbol.is_empty() {
            tracing::warn!("[FLOW] token/create: name/symbol empty");
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Name and symbol are required".to_string(),
            ));
        }

        if symbol.len() > 10 {
            tracing::warn!("[FLOW] token/create: symbol too long len={}", symbol.len());
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Symbol must be 10 characters or less".to_string(),
            ));
        }

        let token_id = generate_custom_token_id(&name, &symbol);
        tracing::warn!("[FLOW] token/create token_id={}", hex::encode(token_id));

        // Check if token already exists (duplicate name+symbol)
        {
            let blockchain = self.blockchain.read().await;
            if blockchain.get_token_contract(&token_id).is_some() {
                tracing::warn!("[FLOW] token/create: DUPLICATE token_id={}", hex::encode(token_id));
                return Ok(create_error_response(
                    ZhtpStatus::Conflict,
                    format!("Token with name '{}' and symbol '{}' already exists", name, symbol),
                ));
            }
        }

        if let Err(e) = self.submit_to_mempool(tx).await {
            tracing::warn!("[FLOW] token/create submit_to_mempool FAILED: {}", e);
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                e.to_string(),
            ));
        }
        tracing::warn!("[FLOW] token/create: submit_to_mempool OK");

        info!("Token creation submitted: {} ({})", name, symbol);

        create_json_response(json!({
            "success": true,
            "token_id": hex::encode(token_id),
            "name": name,
            "symbol": symbol,
            "initial_supply": initial_supply,
            "decimals": decimals,
            "treasury_allocation_bps": treasury_allocation_bps,
            "treasury_recipient": treasury_recipient_hex,
            "creator_allocation": creator_allocation,
            "treasury_allocation": treasury_allocation,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/mint - Mint tokens (creator only)
    async fn handle_mint_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let mint_req: MintTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let tx = match self.decode_signed_tx_raw(&mint_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };

        if tx.transaction_type != lib_blockchain::TransactionType::TokenMint {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token mint requires TransactionType::TokenMint".to_string(),
            ));
        }

        let mint = match tx.token_mint_data.as_ref() {
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
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                e.to_string(),
            ));
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
        tracing::info!("[TRANSFER] START handle_transfer_token, body_len={}", request.body.len());

        let transfer_req: TransferTokenRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("[TRANSFER] FAIL: invalid JSON request: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request: {}", e),
                ));
            }
        };

        tracing::info!("[TRANSFER] signed_tx hex len={}", transfer_req.signed_tx.len());

        let tx = match self.decode_signed_tx_raw(&transfer_req.signed_tx) {
            Ok(parsed) => {
                tracing::info!(
                    "[TRANSFER] decoded tx OK: type={:?}, version={}, chain_id={}",
                    parsed.transaction_type, parsed.version, parsed.chain_id
                );
                parsed
            }
            Err(e) => {
                tracing::error!("[TRANSFER] FAIL: decode_signed_tx_raw: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };

        // Canonical path: TokenTransfer only.
        let (recipient_hex, token_id_hex, amount) = if tx.transaction_type == lib_blockchain::TransactionType::TokenTransfer {
            // Native TokenTransfer path
            match tx.token_transfer_data.as_ref() {
                Some(d) => (hex::encode(d.to), hex::encode(d.token_id), d.amount),
                None => {
                    tracing::error!("[TRANSFER] FAIL: TokenTransfer but token_transfer_data is None");
                    return Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "TokenTransfer missing data".to_string(),
                    ));
                }
            }
        } else {
            tracing::error!(
                "[TRANSFER] FAIL: wrong tx type: {:?} (expected TokenTransfer)",
                tx.transaction_type
            );
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token transfer requires TransactionType::TokenTransfer, got {:?}", tx.transaction_type),
            ));
        };
        tracing::info!(
            "[TRANSFER] to={}, token_id={}, amount={}",
            &recipient_hex[..16.min(recipient_hex.len())],
            &token_id_hex[..16.min(token_id_hex.len())],
            amount
        );

        let is_sov = token_id_hex == hex::encode(lib_blockchain::contracts::utils::generate_lib_token_id())
            || token_id_hex == "0000000000000000000000000000000000000000000000000000000000000000";

        // Recipient validation: check wallet_registry, identity_registry, and
        // identity_manager. Log findings but don't reject — the token contract
        // will create a balance entry for any valid public key, similar to how
        // Bitcoin allows sends to any address.
        let blockchain = self.blockchain.read().await;
        let in_wallet = blockchain.wallet_registry.contains_key(&recipient_hex);
        let in_identity = if is_sov {
            false
        } else {
            let did_key = format!("did:zhtp:{}", recipient_hex);
            blockchain.identity_registry.contains_key(&did_key)
        };
        drop(blockchain);

        tracing::info!(
            "[TRANSFER] recipient check: wallet_registry={}, identity_registry={} (did={})",
            in_wallet, in_identity, if is_sov { "<wallet_id>" } else { "did:zhtp:..." }
        );

        if !in_wallet && !in_identity {
            tracing::warn!(
                "[TRANSFER] recipient not in wallet_registry or identity_registry: {} — proceeding anyway",
                &recipient_hex[..16.min(recipient_hex.len())]
            );
        }

        if let Err(e) = self.submit_to_mempool(tx).await {
            tracing::error!("[TRANSFER] FAIL: mempool submission: {}", e);
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                e.to_string(),
            ));
        }

        tracing::info!(
            "[TRANSFER] SUCCESS: submitted to mempool, to={}, amount={}",
            &recipient_hex[..16.min(recipient_hex.len())], amount
        );
        create_json_response(json!({
            "success": true,
            "token_id": token_id_hex,
            "to": recipient_hex,
            "amount": amount,
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
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };
        let _ = tx;
        Ok(create_error_response(
            ZhtpStatus::BadRequest,
            "Token burn via ContractExecution is disabled; use canonical typed token mutation transactions".to_string(),
        ))
    }

    /// GET /api/v1/token/{id} - Get token info
    async fn handle_get_token_info(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;

        if token_id.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token ID must be 32 bytes".to_string()
            ));
        }

        let token_id_array: [u8; 32] = token_id.try_into().unwrap();

        let blockchain = self.blockchain.read().await;

        let token = blockchain.get_token_contract(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let created_at = blockchain.contract_blocks.get(&token_id_array).copied();

        let response = TokenInfoResponse {
            token_id: token_id_hex.to_string(),
            name: token.name.clone(),
            symbol: token.symbol.clone(),
            decimals: token.decimals,
            total_supply: token.total_supply,
            max_supply: if token.max_supply == u64::MAX { None } else { Some(token.max_supply) },
            creator: format!("0x{}", hex::encode(&token.creator.key_id)),
            is_deflationary: token.is_deflationary,
            created_at_block: created_at,
        };

        create_json_response(serde_json::to_value(response)?)
    }

    /// GET /api/v1/token/{id}/balance/{address} - Get token balance
    async fn handle_get_balance(&self, token_id_hex: &str, address: &str) -> Result<ZhtpResponse> {
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;

        if token_id.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token ID must be 32 bytes".to_string()
            ));
        }

        let token_id_array: [u8; 32] = token_id.try_into().unwrap();

        let is_sov = token_id_array == [0u8; 32]
            || token_id_array == lib_blockchain::contracts::utils::generate_lib_token_id();

        let blockchain = self.blockchain.read().await;

        let token = blockchain.get_token_contract(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let balance = if is_sov {
            let wallet_id = self.resolve_wallet_id_for_sov(address, &blockchain)
                .ok_or_else(|| anyhow::anyhow!("SOV balance lookup requires a valid wallet_id"))?;
            // When BlockExecutor is active it writes to the token_balances Sled tree.
            // The in-memory token_contracts is NOT updated after executor-path transfers,
            // so we must read from Sled to get the post-transfer balance.
            if let Some(store) = blockchain.get_store() {
                let storage_token_id = lib_blockchain::storage::TokenId(token_id_array);
                let addr = lib_blockchain::storage::Address::new(wallet_id);
                store.get_token_balance(&storage_token_id, &addr).unwrap_or(0) as u64
            } else {
                let wallet_key = PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: wallet_id,
                };
                token.balance_of(&wallet_key)
            }
        } else {
            let pubkey = self.identity_to_pubkey(address)?;
            let target_key_id = pubkey.key_id;
            token.balances.iter()
                .find(|(pk, _)| pk.key_id == target_key_id)
                .map(|(_, bal)| *bal)
                .unwrap_or(0)
        };

        create_json_response(json!({
            "token_id": token_id_hex,
            "address": address,
            "balance": balance,
            "symbol": token.symbol.clone()
        }))
    }

    /// GET /api/v1/token/list - List all tokens
    async fn handle_list_tokens(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;

        let tokens: Vec<TokenListItem> = blockchain.token_contracts
            .iter()
            .map(|(id, token)| TokenListItem {
                token_id: hex::encode(id),
                name: token.name.clone(),
                symbol: token.symbol.clone(),
                total_supply: token.total_supply,
            })
            .collect();

        let count = tokens.len();

        create_json_response(json!({
            "tokens": tokens,
            "count": count
        }))
    }

    /// GET /api/v1/token/nonce/{token_id}/{address} - Get expected nonce for transfer replay protection
    async fn handle_get_nonce(&self, token_id_hex: &str, address_hex: &str) -> Result<ZhtpResponse> {
        let token_id_bytes = match hex::decode(token_id_hex) {
            Ok(b) => b,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid token_id hex".to_string()
            )),
        };
        if token_id_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "token_id must be 32 bytes (64 hex chars)".to_string()
            ));
        }
        let mut token_id = [0u8; 32];
        token_id.copy_from_slice(&token_id_bytes);

        let address_bytes = match hex::decode(address_hex) {
            Ok(b) => b,
            Err(_) => return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Invalid address hex".to_string()
            )),
        };
        if address_bytes.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Address must be 32 bytes (64 hex chars)".to_string()
            ));
        }
        let mut address = [0u8; 32];
        address.copy_from_slice(&address_bytes);

        let blockchain = self.blockchain.read().await;
        let nonce = blockchain.get_token_nonce(&token_id, &address);

        create_json_response(json!({
            "token_id": token_id_hex,
            "address": address_hex,
            "nonce": nonce
        }))
    }

    /// GET /api/v1/token/symbol/available/{symbol} - Check if symbol is available
    async fn handle_check_symbol_available(&self, symbol: &str) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        let symbol_upper = symbol.to_uppercase();

        // Check if any existing token uses this symbol (case-insensitive)
        let existing_token = blockchain.token_contracts
            .values()
            .find(|token| token.symbol.to_uppercase() == symbol_upper);

        match existing_token {
            Some(token) => {
                create_json_response(json!({
                    "symbol": symbol,
                    "available": false,
                    "reason": format!("Symbol already used by token '{}'", token.name),
                    "existing_token": {
                        "token_id": hex::encode(token.token_id),
                        "name": token.name.clone(),
                        "symbol": token.symbol.clone()
                    }
                }))
            }
            None => {
                create_json_response(json!({
                    "symbol": symbol,
                    "available": true
                }))
            }
        }
    }

    /// GET /api/v1/token/balances/{address} - Get all token balances for an address
    async fn handle_get_balances_for_address(&self, address: &str) -> Result<ZhtpResponse> {
        use lib_blockchain::contracts::utils::generate_lib_token_id;

        let blockchain = self.blockchain.read().await;
        let target_key_id = if let Some(wallet) = blockchain.wallet_registry.get(address) {
            let wallet_pk = PublicKey::new(wallet.public_key.clone());
            wallet_pk.key_id
        } else {
            let pubkey = self.identity_to_pubkey(address)?;
            pubkey.key_id
        };
        let sov_wallet_id = self.resolve_wallet_id_for_sov(address, &blockchain);

        debug!(
            "token/balances: address={}, target_key_id={}, token_count={}",
            address,
            hex::encode(&target_key_id),
            blockchain.token_contracts.len()
        );

        let native_token_id = generate_lib_token_id();
        let native_token_id_hex = hex::encode(native_token_id);
        let mut balances = Vec::new();

        // Collect balances from all token contracts
        for (token_id, token) in &blockchain.token_contracts {
            let balance = if *token_id == native_token_id {
                if let Some(wallet_id) = sov_wallet_id {
                    // Prefer Sled tree when executor is active (canonical post-transfer balance)
                    if let Some(store) = blockchain.get_store() {
                        let storage_token_id = lib_blockchain::storage::TokenId(*token_id);
                        let addr = lib_blockchain::storage::Address::new(wallet_id);
                        store.get_token_balance(&storage_token_id, &addr).unwrap_or(0) as u64
                    } else {
                        let wallet_key = PublicKey {
                            dilithium_pk: vec![],
                            kyber_pk: vec![],
                            key_id: wallet_id,
                        };
                        token.balance_of(&wallet_key)
                    }
                } else {
                    0
                }
            } else {
                token.balances.iter()
                    .find(|(pk, _)| pk.key_id == target_key_id)
                    .map(|(_, bal)| *bal)
                    .unwrap_or(0)
            };

            debug!(
                "token/balances: token={} ({}) balance_count={} found_balance={}",
                token.name,
                token.symbol,
                token.balances.len(),
                balance
            );

            if balance > 0 {
                let is_creator = token.creator.key_id == target_key_id;
                balances.push(json!({
                    "token_id": hex::encode(token_id),
                    "name": token.name.clone(),
                    "symbol": token.symbol.clone(),
                    "decimals": token.decimals,
                    "balance": balance,
                    "is_creator": is_creator
                }));
            }
        }

        // Always include native SOV entry (even if balance is 0) so clients get the token_id.
        let has_sov = balances.iter().any(|b| {
            b.get("token_id").and_then(|v| v.as_str()) == Some(&native_token_id_hex)
        });
        if !has_sov {
            let (name, symbol, decimals) = blockchain
                .token_contracts
                .get(&native_token_id)
                .map(|t| (t.name.clone(), t.symbol.clone(), t.decimals))
                .unwrap_or_else(|| ("Sovereign".to_string(), "SOV".to_string(), 8));

            balances.insert(0, json!({
                "token_id": native_token_id_hex,
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "balance": 0,
                "is_creator": false
            }));
        }

        create_json_response(json!({
            "address": address,
            "balances": balances,
            "count": balances.len()
        }))
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Convert identity string to PublicKey
    fn identity_to_pubkey(&self, identity: &str) -> Result<PublicKey> {
        // Handle different identity formats
        let key_bytes = if identity.starts_with("did:zhtp:") {
            let hex_part = identity.strip_prefix("did:zhtp:").unwrap_or(identity);
            hex::decode(hex_part)
                .map_err(|_| anyhow::anyhow!("Invalid DID format"))?
        } else if identity.starts_with("0x") {
            hex::decode(&identity[2..])
                .map_err(|_| anyhow::anyhow!("Invalid hex address"))?
        } else {
            hex::decode(identity)
                .map_err(|_| anyhow::anyhow!("Invalid identity format"))?
        };

        if key_bytes.len() == 32 {
            let mut key_id_array = [0u8; 32];
            key_id_array.copy_from_slice(&key_bytes);
            return Ok(PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: key_id_array,
            });
        }

        Ok(PublicKey::new(key_bytes))
    }

    /// Resolve a wallet_id for SOV balance lookups/transfers.
    ///
    /// Accepts:
    /// - wallet_id hex (preferred)
    /// - DID/identity hex (maps to Primary wallet if found)
    fn resolve_wallet_id_for_sov(
        &self,
        address: &str,
        blockchain: &Blockchain,
    ) -> Option<[u8; 32]> {
        let hex_part = if address.starts_with("did:zhtp:") {
            address.strip_prefix("did:zhtp:").unwrap_or(address)
        } else if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        let bytes = hex::decode(hex_part).ok()?;
        if bytes.len() != 32 {
            return None;
        }

        // If this is already a wallet_id, accept it.
        let wallet_id_hex = hex::encode(&bytes);
        if blockchain.wallet_registry.contains_key(&wallet_id_hex) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }

        // Otherwise treat it as identity_id and try to find the Primary wallet.
        let identity_hash = lib_blockchain::Hash::from_slice(&bytes);
        let primary_wallet = blockchain.wallet_registry.values().find(|wallet| {
            wallet.owner_identity_id.as_ref() == Some(&identity_hash)
                && wallet.wallet_type == "Primary"
        })?;
        Some(primary_wallet.wallet_id.as_array())
    }

    fn decode_signed_tx_raw(&self, signed_tx: &str) -> Result<Transaction> {
        tracing::warn!("[FLOW] decode_signed_tx_raw: len={}", signed_tx.len());
        let tx_bytes = hex::decode(signed_tx)
            .map_err(|_| anyhow::anyhow!("Invalid signed_tx hex"))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signed_tx payload: {}", e))?;
        Ok(tx)
    }

    async fn submit_to_mempool(&self, tx: Transaction) -> Result<()> {
        tracing::warn!(
            "[FLOW] token/create submit_to_mempool: tx_hash={}, size={}, fee={}",
            hex::encode(tx.hash().as_bytes()),
            tx.size(),
            tx.fee
        );
        let mut blockchain = self.blockchain.write().await;
        blockchain.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit transaction to mempool: {}", e))?;
        tracing::warn!("[FLOW] token/create submit_to_mempool: ok");
        Ok(())
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for TokenHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Token handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/token/create
            (ZhtpMethod::Post, "/api/v1/token/create") => {
                self.handle_create_token(request).await
            }
            // POST /api/v1/token/mint
            (ZhtpMethod::Post, "/api/v1/token/mint") => {
                self.handle_mint_token(request).await
            }
            // POST /api/v1/token/transfer
            (ZhtpMethod::Post, "/api/v1/token/transfer") => {
                self.handle_transfer_token(request).await
            }
            // POST /api/v1/token/burn
            (ZhtpMethod::Post, "/api/v1/token/burn") => {
                self.handle_burn_token(request).await
            }
            // GET /api/v1/token/list
            (ZhtpMethod::Get, "/api/v1/token/list") => {
                self.handle_list_tokens().await
            }
            // GET /api/v1/token/symbol/available/{symbol} - Check if symbol is available
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/symbol/available/") => {
                let symbol = path.strip_prefix("/api/v1/token/symbol/available/").unwrap_or("");
                if symbol.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Symbol required".to_string()
                    ))
                } else {
                    self.handle_check_symbol_available(symbol).await
                }
            }
            // GET /api/v1/token/balances/{address} - Get all token balances for an address
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/balances/") => {
                let address = path.strip_prefix("/api/v1/token/balances/").unwrap_or("");
                if address.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Address required".to_string()
                    ))
                } else {
                    self.handle_get_balances_for_address(address).await
                }
            }
            // GET /api/v1/token/nonce/{token_id}/{address} - Get expected nonce for replay protection
            // NOTE: Must be above the generic /api/v1/token/{id} matcher to avoid shadowing
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/nonce/") => {
                let suffix = path.strip_prefix("/api/v1/token/nonce/").unwrap_or("");
                let mut parts = suffix.split('/');
                let token_id = parts.next().unwrap_or("");
                let address = parts.next().unwrap_or("");
                if token_id.is_empty() || address.is_empty() {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "token_id and address required".to_string()
                    ))
                } else {
                    self.handle_get_nonce(token_id, address).await
                }
            }
            // GET /api/v1/token/{id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/") && !path.contains("/balance") => {
                let token_id = path.strip_prefix("/api/v1/token/").unwrap_or("");
                if token_id.is_empty() || token_id == "list" {
                    self.handle_list_tokens().await
                } else {
                    self.handle_get_token_info(token_id).await
                }
            }
            // GET /api/v1/token/{id}/balance/{address}
            (ZhtpMethod::Get, path) if path.contains("/balance/") => {
                let parts: Vec<&str> = path.split('/').collect();
                // /api/v1/token/{id}/balance/{address}
                // 0   1  2     3     4       5      6
                if parts.len() >= 7 {
                    let token_id = parts[4];
                    let address = parts.get(6).unwrap_or(&"");
                    self.handle_get_balance(token_id, address).await
                } else {
                    Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Invalid balance path format".to_string()
                    ))
                }
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    format!("Token endpoint not found: {} {}", request.method, request.uri)
                ))
            }
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
    use super::*;
    use lib_crypto::types::keys::PublicKey;

    // Helper to parse identity without needing full handler
    fn parse_identity(identity: &str) -> Result<PublicKey> {
        let key_bytes = if identity.starts_with("did:zhtp:") {
            let hex_part = identity.strip_prefix("did:zhtp:").unwrap_or(identity);
            hex::decode(hex_part)
                .map_err(|_| anyhow::anyhow!("Invalid DID format"))?
        } else if identity.starts_with("0x") {
            hex::decode(&identity[2..])
                .map_err(|_| anyhow::anyhow!("Invalid hex address"))?
        } else {
            hex::decode(identity)
                .map_err(|_| anyhow::anyhow!("Invalid identity format"))?
        };

        if key_bytes.len() == 32 {
            let mut key_id_array = [0u8; 32];
            key_id_array.copy_from_slice(&key_bytes);
            return Ok(PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: key_id_array,
            });
        }

        Ok(PublicKey::new(key_bytes))
    }

    #[test]
    fn test_identity_to_pubkey_did_format() {
        let did = "did:zhtp:0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_identity(did);
        assert!(result.is_ok());
        let pk = result.unwrap();
        assert_eq!(pk.key_id[0], 0x01);
        assert_eq!(pk.key_id[31], 0x32);
    }

    #[test]
    fn test_identity_to_pubkey_hex_format() {
        let hex_addr = "0x0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_identity(hex_addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_to_pubkey_raw_hex() {
        let raw_hex = "0102030405060708091011121314151617181920212223242526272829303132";
        let result = parse_identity(raw_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_to_pubkey_invalid() {
        let invalid = "not-valid-hex";
        let result = parse_identity(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance_path_parsing() {
        // /api/v1/token/{id}/balance/{address}
        // parts: ["", "api", "v1", "token", "{id}", "balance", "{address}"]
        // indices:  0     1     2      3       4        5          6
        let path = "/api/v1/token/abc123/balance/def456";
        let parts: Vec<&str> = path.split('/').collect();

        assert!(parts.len() >= 7);
        assert_eq!(parts[4], "abc123");
        assert_eq!(parts[6], "def456");
    }

    #[test]
    fn test_balance_path_malformed_rejected() {
        // Missing address should fail length check
        let path = "/api/v1/token/abc123/balance";
        let parts: Vec<&str> = path.split('/').collect();

        // parts: ["", "api", "v1", "token", "abc123", "balance"]
        // This has 6 elements, not 7
        assert!(parts.len() < 7);
    }
}
