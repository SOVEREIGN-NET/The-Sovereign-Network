//! Token Handler Module
//!
//! Complete token management API for custom token creation, minting, and transfer.
//! Enables users to create their own tokens on the ZHTP blockchain.

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

// ZHTP protocol imports
use lib_protocols::zhtp::ZhtpRequestHandler;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

// Blockchain imports
use lib_blockchain::Blockchain;
use lib_blockchain::contracts::TokenContract;
use lib_blockchain::transaction::{Transaction, TransactionOutput};
use lib_blockchain::types::{TransactionType, Hash};
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

/// Request to create a new token
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub symbol: String,
    pub initial_supply: u64,
    #[serde(default = "default_decimals")]
    pub decimals: u8,
    pub max_supply: Option<u64>,
    // NOTE: creator_identity removed - now derived from authenticated session (request.requester)
}

fn default_decimals() -> u8 { 8 }

/// Request to mint tokens
#[derive(Debug, Deserialize)]
pub struct MintTokenRequest {
    pub token_id: String,
    pub amount: u64,
    pub to: String,
    // NOTE: creator_identity removed - authorization now verified via authenticated session (request.requester)
}

/// Request to transfer tokens
#[derive(Debug, Deserialize)]
pub struct TransferTokenRequest {
    pub token_id: String,
    // NOTE: `from` removed - source is now the authenticated caller (request.requester)
    pub to: String,
    pub amount: u64,
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
        let create_req: CreateTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        info!("Creating token: {} ({})", create_req.name, create_req.symbol);

        // Validate inputs
        if create_req.name.is_empty() || create_req.symbol.is_empty() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Name and symbol are required".to_string()
            ));
        }

        if create_req.symbol.len() > 10 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Symbol must be 10 characters or less".to_string()
            ));
        }

        // SECURITY FIX: Use authenticated session identity, not user-supplied value
        let requester_hash = match &request.requester {
            Some(hash) => hash,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Authentication required to create tokens".to_string()
                ));
            }
        };

        // Convert requester hash to hex string for identity lookup
        let requester_hex = hex::encode(requester_hash.as_bytes());

        // Create creator public key from authenticated session identity
        let creator_pubkey = self.identity_to_pubkey(&requester_hex)?;

        // Create the token contract
        let token = TokenContract::new_custom(
            create_req.name.clone(),
            create_req.symbol.clone(),
            create_req.initial_supply,
            creator_pubkey.clone(),
        );

        let token_id = token.token_id;
        let token_id_hex = hex::encode(token_id);

        // Create deployment transaction
        let tx = self.create_token_deployment_tx(&token, &creator_pubkey)?;
        let tx_hash = tx.hash();

        // Register token and add transaction to blockchain
        {
            let mut blockchain = self.blockchain.write().await;

            // Check if token already exists
            if blockchain.get_token_contract(&token_id).is_some() {
                return Ok(create_error_response(
                    ZhtpStatus::Conflict,
                    format!("Token with symbol {} already exists", create_req.symbol)
                ));
            }

            // Register the token contract
            let height = blockchain.height;
            blockchain.register_token_contract(token_id, token, height);

            // Add transaction to pending pool
            if let Err(e) = blockchain.add_pending_transaction(tx) {
                warn!("Failed to add token creation tx to pending pool: {}", e);
            }
        }

        info!("Token created: {} ({}) with ID {}", create_req.name, create_req.symbol, token_id_hex);

        create_json_response(json!({
            "success": true,
            "token_id": token_id_hex,
            "name": create_req.name,
            "symbol": create_req.symbol,
            "total_supply": create_req.initial_supply,
            "creator": requester_hex,
            "tx_hash": hex::encode(tx_hash.as_bytes())
        }))
    }

    /// POST /api/v1/token/mint - Mint tokens (creator only)
    async fn handle_mint_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let mint_req: MintTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&mint_req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;

        if token_id.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token ID must be 32 bytes".to_string()
            ));
        }

        let token_id_array: [u8; 32] = token_id.try_into().unwrap();

        // SECURITY FIX: Verify caller is authenticated
        let requester_hash = match &request.requester {
            Some(hash) => hash,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Authentication required to mint tokens".to_string()
                ));
            }
        };

        // Convert requester hash to hex string for identity lookup
        let requester_hex = hex::encode(requester_hash.as_bytes());

        // Get recipient public key
        let to_pubkey = self.identity_to_pubkey(&mint_req.to)?;

        // SECURITY FIX: Use authenticated session identity for creator verification
        let caller_pubkey = self.identity_to_pubkey(&requester_hex)?;

        let mut blockchain = self.blockchain.write().await;

        // Get token contract
        let token = blockchain.get_token_contract_mut(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // SECURITY FIX: Verify authenticated caller is the token creator
        if token.creator != caller_pubkey {
            return Ok(create_error_response(
                ZhtpStatus::Forbidden,
                "Only the token creator can mint".to_string()
            ));
        }

        // Mint tokens
        match token.mint(&to_pubkey, mint_req.amount) {
            Ok(_) => {
                let new_supply = token.total_supply;
                info!("Minted {} tokens to {}", mint_req.amount, mint_req.to);

                create_json_response(json!({
                    "success": true,
                    "amount_minted": mint_req.amount,
                    "to": mint_req.to,
                    "new_total_supply": new_supply
                }))
            }
            Err(e) => {
                Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Mint failed: {}", e)
                ))
            }
        }
    }

    /// POST /api/v1/token/transfer - Transfer tokens
    async fn handle_transfer_token(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let transfer_req: TransferTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // SECURITY FIX: Require authentication - the authenticated caller is the sender
        let requester_hash = match &request.requester {
            Some(hash) => hash,
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::Unauthorized,
                    "Authentication required for transfers".to_string()
                ));
            }
        };

        // Convert requester hash to hex string for identity lookup
        let requester_hex = hex::encode(requester_hash.as_bytes());

        let token_id = hex::decode(&transfer_req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;

        if token_id.len() != 32 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Token ID must be 32 bytes".to_string()
            ));
        }

        let token_id_array: [u8; 32] = token_id.try_into().unwrap();

        // SECURITY FIX: Use authenticated session identity as sender, not user-supplied value
        // This prevents unauthorized transfers from other accounts
        let from_pubkey = self.identity_to_pubkey(&requester_hex)?;
        let to_pubkey = self.identity_to_pubkey(&transfer_req.to)?;

        let mut blockchain = self.blockchain.write().await;

        // Get token contract
        let token = blockchain.get_token_contract_mut(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // Check balance
        let from_balance = token.balance_of(&from_pubkey);
        if from_balance < transfer_req.amount {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Insufficient balance: have {}, need {}", from_balance, transfer_req.amount)
            ));
        }

        // Perform transfer
        let new_from_balance = from_balance - transfer_req.amount;
        let to_balance = token.balance_of(&to_pubkey);
        let new_to_balance = to_balance + transfer_req.amount;

        token.balances.insert(from_pubkey.clone(), new_from_balance);
        token.balances.insert(to_pubkey.clone(), new_to_balance);

        info!("Transferred {} tokens from {} to {}",
            transfer_req.amount, requester_hex, transfer_req.to);

        create_json_response(json!({
            "success": true,
            "amount": transfer_req.amount,
            "from": requester_hex,
            "to": transfer_req.to,
            "from_balance": new_from_balance,
            "to_balance": new_to_balance
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

        let blockchain = self.blockchain.read().await;

        let token = blockchain.get_token_contract(&token_id_array)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let balance = token.balance_of(&pubkey);

        create_json_response(json!({
            "token_id": token_id_hex,
            "address": address,
            "balance": balance,
            "symbol": token.symbol
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

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Convert identity string to PublicKey
    fn identity_to_pubkey(&self, identity: &str) -> Result<PublicKey> {
        // Handle different identity formats
        let key_id = if identity.starts_with("did:zhtp:") {
            // Extract key_id from DID
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

        if key_id.len() != 32 {
            return Err(anyhow::anyhow!("Identity must be 32 bytes"));
        }

        let mut key_id_array = [0u8; 32];
        key_id_array.copy_from_slice(&key_id);

        Ok(PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: key_id_array,
        })
    }

    /// Create a token deployment transaction
    fn create_token_deployment_tx(&self, token: &TokenContract, creator: &PublicKey) -> Result<Transaction> {
        // Serialize token contract
        let token_bytes = bincode::serialize(token)?;

        // Create transaction output with serialized token
        let output = TransactionOutput {
            commitment: Hash::new(lib_crypto::hash_blake3(&token_bytes)),
            note: Hash::new(token.token_id),
            recipient: creator.clone(),
        };

        // Create the transaction
        let tx = Transaction {
            version: 1,
            chain_id: 0x03, // testnet
            transaction_type: TransactionType::ContractDeployment,
            inputs: vec![], // System transaction
            outputs: vec![output],
            fee: 0,
            signature: lib_crypto::types::signatures::Signature {
                signature: vec![],
                public_key: creator.clone(),
                algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            memo: format!("Token deployment: {} ({})", token.name, token.symbol).into_bytes(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };

        Ok(tx)
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
            // GET /api/v1/token/list
            (ZhtpMethod::Get, "/api/v1/token/list") => {
                self.handle_list_tokens().await
            }
            // GET /api/v1/token/{id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/token/") && !path.contains("/balance/") => {
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
                // 0   1  2     3     4       5
                if parts.len() >= 6 {
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
