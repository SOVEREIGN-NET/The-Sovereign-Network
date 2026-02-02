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
use lib_blockchain::transaction::Transaction;
use lib_blockchain::contracts::utils::generate_custom_token_id;
use lib_blockchain::types::ContractCall;
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

        let (tx, call) = match self.decode_signed_tx(&create_req.signed_tx) {
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
        if let Err(e) = self.ensure_token_call(&call, "create_custom_token") {
            tracing::warn!("[FLOW] token/create: ensure_token_call FAILED: {}", e);
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        // Extract params for response - must match CreateTokenParams struct from lib-client
        #[derive(serde::Deserialize)]
        struct CreateTokenParams {
            name: String,
            symbol: String,
            initial_supply: u64,
            decimals: u8,
        }
        let params: CreateTokenParams = match bincode::deserialize(&call.params) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("[FLOW] token/create: params deserialize FAILED: {}", e);
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid token create params: {}", e),
                ));
            }
        };
        let CreateTokenParams { name, symbol, initial_supply, decimals } = params;
        tracing::warn!(
            "[FLOW] token/create params: name='{}' symbol='{}' supply={} decimals={}",
            name,
            symbol,
            initial_supply,
            decimals
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
            if blockchain.token_contracts.contains_key(&token_id) {
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
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/mint - Mint tokens (creator only)
    async fn handle_mint_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let mint_req: MintTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let (tx, call) = match self.decode_signed_tx(&mint_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };
        if let Err(e) = self.ensure_token_call(&call, "mint") {
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        // Must match MintParams from lib-client
        #[derive(serde::Deserialize)]
        struct MintParams {
            token_id: [u8; 32],
            to: Vec<u8>,
            amount: u64,
        }
        let params: MintParams = match bincode::deserialize(&call.params) {
            Ok(p) => p,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid mint params: {}", e),
                ));
            }
        };
        let MintParams { token_id, to, amount } = params;

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
            "to": format!("0x{}", hex::encode(&to)),
            "amount_minted": amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/transfer - Transfer tokens
    async fn handle_transfer_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let transfer_req: TransferTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let (tx, call) = match self.decode_signed_tx(&transfer_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };
        if let Err(e) = self.ensure_token_call(&call, "transfer") {
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        // Must match TransferParams from lib-client
        #[derive(serde::Deserialize)]
        struct TransferParams {
            token_id: [u8; 32],
            to: Vec<u8>,
            amount: u64,
        }
        let params: TransferParams = match bincode::deserialize(&call.params) {
            Ok(p) => p,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid transfer params: {}", e),
                ));
            }
        };
        let TransferParams { token_id, to, amount } = params;

        if let Err(e) = self.submit_to_mempool(tx).await {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                e.to_string(),
            ));
        }

        info!("Transfer submitted for token {}", hex::encode(token_id));

        create_json_response(json!({
            "success": true,
            "token_id": hex::encode(token_id),
            "to": format!("0x{}", hex::encode(&to)),
            "amount": amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/token/burn - Burn tokens (caller burns own balance)
    async fn handle_burn_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let burn_req: BurnTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let (tx, call) = match self.decode_signed_tx(&burn_req.signed_tx) {
            Ok(parsed) => parsed,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    e.to_string(),
                ));
            }
        };
        if let Err(e) = self.ensure_token_call(&call, "burn") {
            return Ok(create_error_response(ZhtpStatus::BadRequest, e.to_string()));
        }

        // Must match BurnParams from lib-client
        #[derive(serde::Deserialize)]
        struct BurnParams {
            token_id: [u8; 32],
            amount: u64,
        }
        let params: BurnParams = match bincode::deserialize(&call.params) {
            Ok(p) => p,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Invalid burn params: {}", e),
                ));
            }
        };
        let BurnParams { token_id, amount } = params;

        if let Err(e) = self.submit_to_mempool(tx).await {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                e.to_string(),
            ));
        }

        info!("Burn submitted for token {}", hex::encode(token_id));

        create_json_response(json!({
            "success": true,
            "token_id": hex::encode(token_id),
            "amount": amount,
            "tx_status": "submitted_to_mempool"
        }))
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

        let pubkey = self.identity_to_pubkey(address)?;
        let target_key_id = pubkey.key_id;

        let blockchain = self.blockchain.read().await;

        let token = blockchain.get_token_contract(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // Look up balance by key_id (not full PublicKey comparison)
        let balance = token.balances.iter()
            .find(|(pk, _)| pk.key_id == target_key_id)
            .map(|(_, bal)| *bal)
            .unwrap_or(0);

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
        let pubkey = self.identity_to_pubkey(address)?;
        let target_key_id = pubkey.key_id;
        let blockchain = self.blockchain.read().await;

        debug!(
            "token/balances: address={}, target_key_id={}, token_count={}",
            address,
            hex::encode(&target_key_id),
            blockchain.token_contracts.len()
        );

        let mut balances = Vec::new();

        for (token_id, token) in &blockchain.token_contracts {
            // Look up balance by key_id (not full PublicKey comparison)
            // This handles the case where the stored PublicKey has full keys
            // but the query only has key_id
            let balance = token.balances.iter()
                .find(|(pk, _)| pk.key_id == target_key_id)
                .map(|(_, bal)| *bal)
                .unwrap_or(0);

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

    fn decode_signed_tx(&self, signed_tx: &str) -> Result<(Transaction, ContractCall)> {
        tracing::warn!("[FLOW] decode_signed_tx: len={}", signed_tx.len());
        let tx_bytes = hex::decode(signed_tx)
            .map_err(|_| anyhow::anyhow!("Invalid signed_tx hex"))?;
        tracing::warn!("[FLOW] decode_signed_tx: hex decoded len={}, first 20 bytes={:02x?}",
            tx_bytes.len(),
            &tx_bytes[..20.min(tx_bytes.len())]);
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid signed_tx payload: {}", e))?;

        let call = self.extract_contract_call(&tx)?;
        Ok((tx, call))
    }

    fn extract_contract_call(&self, tx: &Transaction) -> Result<ContractCall> {
        tracing::warn!(
            "[FLOW] extract_contract_call: type={:?}, memo_len={}",
            tx.transaction_type,
            tx.memo.len()
        );
        if tx.transaction_type != lib_blockchain::TransactionType::ContractExecution {
            return Err(anyhow::anyhow!("Transaction type must be ContractExecution"));
        }
        if tx.memo.len() <= 4 || &tx.memo[0..4] != b"ZHTP" {
            return Err(anyhow::anyhow!("Transaction memo is missing contract call marker"));
        }

        let call_data = &tx.memo[4..];
        let (call, _sig): (ContractCall, lib_crypto::types::signatures::Signature) =
            bincode::deserialize(call_data)
                .map_err(|e| anyhow::anyhow!("Invalid contract call data: {}", e))?;

        Ok(call)
    }

    fn ensure_token_call(&self, call: &ContractCall, expected_method: &str) -> Result<()> {
        tracing::warn!(
            "[FLOW] ensure_token_call: contract_type={:?} method={} expected={}",
            call.contract_type,
            call.method,
            expected_method
        );
        if call.contract_type != lib_blockchain::types::ContractType::Token {
            return Err(anyhow::anyhow!("Transaction is not a token contract call"));
        }
        if call.method != expected_method {
            return Err(anyhow::anyhow!("Expected token method '{}'", expected_method));
        }
        // NOTE: We don't check call.permissions.requires_caller() because:
        // - Authorization is done via tx.signature.public_key (the canonical sender)
        // - The signature cryptographically proves the caller's identity
        // - CallPermissions::Public is valid - the signature IS the authorization
        call.validate().map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
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
