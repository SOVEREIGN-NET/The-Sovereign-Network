//! NFT API handler — create collections, mint, transfer, burn, query.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use lib_blockchain::Blockchain;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};

fn json_ok(data: serde_json::Value) -> Result<ZhtpResponse> {
    let bytes = serde_json::to_vec(&data)?;
    Ok(ZhtpResponse::success_with_content_type(
        bytes,
        "application/json".to_string(),
        None,
    ))
}

fn err(status: ZhtpStatus, msg: String) -> ZhtpResponse {
    ZhtpResponse::error(status, msg)
}

pub struct NftHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl NftHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Self {
        Self { blockchain }
    }

    /// GET /api/v1/nft/collections
    async fn handle_list_collections(&self) -> Result<ZhtpResponse> {
        let bc = self.blockchain.read().await;
        let collections: Vec<serde_json::Value> = bc
            .nft_collections
            .values()
            .map(|c| {
                json!({
                    "collection_id": hex::encode(c.collection_id),
                    "name": c.name,
                    "symbol": c.symbol,
                    "creator_did": c.creator_did,
                    "total_supply": c.total_supply(),
                    "total_minted": c.total_minted,
                    "max_supply": c.max_supply,
                    "created_at": c.created_at,
                })
            })
            .collect();
        json_ok(json!({ "collections": collections, "count": collections.len() }))
    }

    /// GET /api/v1/nft/collection/{id}
    async fn handle_get_collection(&self, collection_id_hex: &str) -> Result<ZhtpResponse> {
        let id = match hex::decode(collection_id_hex) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid collection_id hex".into())),
        };
        if id.len() != 32 {
            return Ok(err(ZhtpStatus::BadRequest, "collection_id must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id);

        let bc = self.blockchain.read().await;
        match bc.nft_collections.get(&arr) {
            Some(c) => {
                let tokens: Vec<serde_json::Value> = c
                    .all_tokens()
                    .map(|(id, owner, meta)| {
                        json!({
                            "token_id": id,
                            "owner": hex::encode(owner),
                            "name": meta.map(|m| m.name.as_str()).unwrap_or(""),
                            "image_cid": meta.map(|m| m.image_cid.as_str()).unwrap_or(""),
                        })
                    })
                    .collect();
                json_ok(json!({
                    "collection_id": collection_id_hex,
                    "name": c.name,
                    "symbol": c.symbol,
                    "creator_did": c.creator_did,
                    "total_supply": c.total_supply(),
                    "total_minted": c.total_minted,
                    "max_supply": c.max_supply,
                    "created_at": c.created_at,
                    "tokens": tokens,
                }))
            }
            None => Ok(err(ZhtpStatus::NotFound, "Collection not found".into())),
        }
    }

    /// GET /api/v1/nft/{collection}/{token_id}
    async fn handle_get_token(
        &self,
        collection_id_hex: &str,
        token_id_str: &str,
    ) -> Result<ZhtpResponse> {
        let id = match hex::decode(collection_id_hex) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid collection_id hex".into())),
        };
        if id.len() != 32 {
            return Ok(err(ZhtpStatus::BadRequest, "collection_id must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id);

        let token_id: u64 = match token_id_str.parse() {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid token_id".into())),
        };

        let bc = self.blockchain.read().await;
        match bc.nft_collections.get(&arr) {
            Some(c) => {
                let owner = c.owner_of(token_id);
                let meta = c.metadata_of(token_id);
                if owner.is_none() {
                    return Ok(err(ZhtpStatus::NotFound, "Token not found".into()));
                }
                json_ok(json!({
                    "collection_id": collection_id_hex,
                    "collection_name": c.name,
                    "token_id": token_id,
                    "owner": hex::encode(owner.unwrap()),
                    "metadata": meta.map(|m| json!({
                        "name": m.name,
                        "description": m.description,
                        "image_cid": m.image_cid,
                        "attributes": m.attributes,
                        "creator_did": m.creator_did,
                        "created_at": m.created_at,
                    })),
                }))
            }
            None => Ok(err(ZhtpStatus::NotFound, "Collection not found".into())),
        }
    }

    /// GET /api/v1/nft/owned/{wallet_id}
    async fn handle_get_owned(&self, wallet_id_hex: &str) -> Result<ZhtpResponse> {
        let id = match hex::decode(wallet_id_hex) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid wallet_id hex".into())),
        };
        if id.len() != 32 {
            return Ok(err(ZhtpStatus::BadRequest, "wallet_id must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id);

        let bc = self.blockchain.read().await;
        let mut owned: Vec<serde_json::Value> = Vec::new();
        for (col_id, collection) in &bc.nft_collections {
            for token_id in collection.tokens_of(&arr) {
                let meta = collection.metadata_of(token_id);
                owned.push(json!({
                    "collection_id": hex::encode(col_id),
                    "collection_name": collection.name,
                    "token_id": token_id,
                    "name": meta.map(|m| m.name.as_str()).unwrap_or(""),
                    "image_cid": meta.map(|m| m.image_cid.as_str()).unwrap_or(""),
                }));
            }
        }
        json_ok(json!({ "wallet_id": wallet_id_hex, "owned": owned, "count": owned.len() }))
    }

    /// POST /api/v1/nft/collection/create
    async fn handle_create_collection(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }
        let body: Req = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid request: {}", e))),
        };

        let tx_bytes = match hex::decode(&body.signed_tx) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid hex".into())),
        };
        let tx: lib_blockchain::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid transaction: {}", e))),
        };

        if tx.transaction_type != lib_blockchain::types::transaction_type::TransactionType::NftCreateCollection {
            return Ok(err(ZhtpStatus::BadRequest, "Expected NftCreateCollection tx".into()));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("submit failed: {}", e))?;

        info!("NFT collection creation submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }

    /// POST /api/v1/nft/mint
    async fn handle_mint(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }
        let body: Req = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid request: {}", e))),
        };

        let tx_bytes = match hex::decode(&body.signed_tx) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid hex".into())),
        };
        let tx: lib_blockchain::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid transaction: {}", e))),
        };

        if tx.transaction_type != lib_blockchain::types::transaction_type::TransactionType::NftMint {
            return Ok(err(ZhtpStatus::BadRequest, "Expected NftMint tx".into()));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("submit failed: {}", e))?;

        info!("NFT mint submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }

    /// POST /api/v1/nft/transfer
    async fn handle_transfer(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }
        let body: Req = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid request: {}", e))),
        };

        let tx_bytes = match hex::decode(&body.signed_tx) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid hex".into())),
        };
        let tx: lib_blockchain::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid transaction: {}", e))),
        };

        if tx.transaction_type != lib_blockchain::types::transaction_type::TransactionType::NftTransfer {
            return Ok(err(ZhtpStatus::BadRequest, "Expected NftTransfer tx".into()));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("submit failed: {}", e))?;

        info!("NFT transfer submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }

    /// POST /api/v1/nft/burn
    async fn handle_burn(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(serde::Deserialize)]
        struct Req {
            signed_tx: String,
        }
        let body: Req = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid request: {}", e))),
        };

        let tx_bytes = match hex::decode(&body.signed_tx) {
            Ok(v) => v,
            Err(_) => return Ok(err(ZhtpStatus::BadRequest, "invalid hex".into())),
        };
        let tx: lib_blockchain::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
            Ok(v) => v,
            Err(e) => return Ok(err(ZhtpStatus::BadRequest, format!("invalid transaction: {}", e))),
        };

        if tx.transaction_type != lib_blockchain::types::transaction_type::TransactionType::NftBurn {
            return Ok(err(ZhtpStatus::BadRequest, "Expected NftBurn tx".into()));
        }

        let tx_hash = hex::encode(tx.hash().as_bytes());
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("submit failed: {}", e))?;

        info!("NFT burn submitted: {}", tx_hash);
        json_ok(json!({ "success": true, "tx_hash": tx_hash }))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for NftHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        info!("NFT handler: {} {}", request.method, request.uri);

        let result = match (request.method.clone(), request.uri.as_str()) {
            (ZhtpMethod::Get, "/api/v1/nft/collections") => {
                self.handle_list_collections().await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/nft/owned/") => {
                let wallet_id = path.strip_prefix("/api/v1/nft/owned/").unwrap_or("");
                self.handle_get_owned(wallet_id).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/nft/collection/") => {
                let id = path.strip_prefix("/api/v1/nft/collection/").unwrap_or("");
                self.handle_get_collection(id).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/nft/") => {
                // /api/v1/nft/{collection_id}/{token_id}
                let parts: Vec<&str> = path
                    .strip_prefix("/api/v1/nft/")
                    .unwrap_or("")
                    .split('/')
                    .collect();
                if parts.len() == 2 {
                    self.handle_get_token(parts[0], parts[1]).await
                } else {
                    Ok(err(ZhtpStatus::BadRequest, "Expected /api/v1/nft/{collection}/{token_id}".into()))
                }
            }
            (ZhtpMethod::Post, "/api/v1/nft/collection/create") => {
                self.handle_create_collection(request).await
            }
            (ZhtpMethod::Post, "/api/v1/nft/mint") => {
                self.handle_mint(request).await
            }
            (ZhtpMethod::Post, "/api/v1/nft/transfer") => {
                self.handle_transfer(request).await
            }
            (ZhtpMethod::Post, "/api/v1/nft/burn") => {
                self.handle_burn(request).await
            }
            _ => Ok(err(
                ZhtpStatus::NotFound,
                format!("NFT endpoint not found: {} {}", request.method, request.uri),
            )),
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!("NFT handler error: {}", e);
                Ok(err(ZhtpStatus::InternalServerError, format!("NFT error: {}", e)))
            }
        }
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/nft")
    }

    fn priority(&self) -> u32 {
        100
    }
}
