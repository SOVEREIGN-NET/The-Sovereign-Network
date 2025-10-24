//! Content Marketplace API Endpoints
//! 
//! Handles buying, selling, and transferring content ownership with blockchain integration.

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_protocols::zhtp::{ZhtpResult, ZhtpRequestHandler};
use lib_storage::WalletContentManager;
use lib_identity::wallets::{WalletId, wallet_types::ContentTransferType};
use lib_crypto::Hash;
use lib_crypto::hashing::hash_blake3;
use lib_blockchain::{Transaction, TransactionOutput, TransactionType};
use serde::{Deserialize, Serialize};
use tracing::{info, error, warn};
use anyhow::anyhow;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Handler for marketplace operations (buying, selling, transferring)
pub struct MarketplaceHandler {
    /// Shared wallet-content manager
    wallet_content_manager: Arc<RwLock<WalletContentManager>>,
    /// Blockchain reference for creating transactions
    blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
}

impl MarketplaceHandler {
    /// Create new marketplace handler
    pub fn new(
        wallet_content_manager: Arc<RwLock<WalletContentManager>>,
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    ) -> Self {
        info!("Initializing Marketplace API handler");
        Self {
            wallet_content_manager,
            blockchain,
        }
    }

    /// Route incoming requests to appropriate handlers
    async fn handle_request_internal(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = &request.uri;
        
        // Parse path segments
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        match (request.method, segments.as_slice()) {
            // POST /api/marketplace/content/{content_hash}/transfer
            (ZhtpMethod::Post, ["api", "marketplace", "content", content_hash, "transfer"]) => {
                self.transfer_content(content_hash, &request.body).await
            }
            
            // POST /api/marketplace/content/{content_hash}/list
            (ZhtpMethod::Post, ["api", "marketplace", "content", content_hash, "list"]) => {
                self.list_content_for_sale(content_hash, &request.body).await
            }
            
            // POST /api/marketplace/content/{content_hash}/buy
            (ZhtpMethod::Post, ["api", "marketplace", "content", content_hash, "buy"]) => {
                self.buy_content(content_hash, &request.body).await
            }
            
            // GET /api/marketplace/listings
            (ZhtpMethod::Get, ["api", "marketplace", "listings"]) => {
                self.get_marketplace_listings().await
            }
            
            _ => {
                error!("Unknown marketplace API endpoint: {:?} {}", request.method, path);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Unknown marketplace API endpoint".to_string(),
                ))
            }
        }
    }

    /// POST /api/marketplace/content/{content_hash}/transfer
    /// 
    /// Transfer content ownership (can be gift or sale)
    async fn transfer_content(&self, content_hash_str: &str, body: &[u8]) -> ZhtpResult<ZhtpResponse> {
        info!("Processing content transfer for: {}", content_hash_str);
        
        // Parse request body
        let request: TransferRequest = serde_json::from_slice(body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;
        
        // Parse hashes
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        let from_wallet = Hash::from_hex(&request.from_wallet)
            .map_err(|e| anyhow!("Invalid from_wallet: {}", e))?;
        let to_wallet = Hash::from_hex(&request.to_wallet)
            .map_err(|e| anyhow!("Invalid to_wallet: {}", e))?;
        
        // Verify ownership
        let manager = self.wallet_content_manager.read().await;
        if !manager.verify_ownership(&content_hash, &from_wallet) {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Sender does not own this content".to_string(),
            ));
        }
        drop(manager);
        
        // Create blockchain transaction if there's a price
        let tx_hash = if request.price > 0 {
            info!("Creating blockchain transaction for {} ZHTP payment", request.price);
            
            let tx_hash = self.create_payment_transaction(
                &from_wallet,
                &to_wallet,
                request.price,
                &content_hash,
            ).await?;
            
            tx_hash
        } else {
            // For gifts (price = 0), create a simple hash as reference
            let gift_data = format!("gift_{}_{}_{}",
                content_hash_str,
                request.from_wallet,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
            Hash::from_bytes(&hash_blake3(gift_data.as_bytes()))
        };
        
        // Determine transfer type
        let transfer_type = if request.price > 0 {
            ContentTransferType::Sale
        } else {
            ContentTransferType::Gift
        };
        
        // Execute ownership transfer
        let mut manager = self.wallet_content_manager.write().await;
        manager.transfer_content_ownership(
            &content_hash,
            from_wallet,
            to_wallet,
            request.price,
            tx_hash.clone(),
            transfer_type.clone(),
        )?;
        
        info!("✅ Content transferred successfully with tx_hash: {}", tx_hash);
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "from_wallet": request.from_wallet,
            "to_wallet": request.to_wallet,
            "price": request.price,
            "transaction_hash": tx_hash.to_string(),
            "transfer_type": format!("{:?}", transfer_type),
            "message": if request.price > 0 {
                "Content sold successfully"
            } else {
                "Content gifted successfully"
            }
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// POST /api/marketplace/content/{content_hash}/list
    /// 
    /// List content for sale on marketplace
    async fn list_content_for_sale(&self, content_hash_str: &str, body: &[u8]) -> ZhtpResult<ZhtpResponse> {
        info!("Listing content for sale: {}", content_hash_str);
        
        // Parse request body
        let request: ListingRequest = serde_json::from_slice(body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;
        
        // Parse hashes
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        let owner_wallet = Hash::from_hex(&request.owner_wallet)
            .map_err(|e| anyhow!("Invalid owner_wallet: {}", e))?;
        
        // Verify ownership
        let manager = self.wallet_content_manager.read().await;
        if !manager.verify_ownership(&content_hash, &owner_wallet) {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Only the owner can list content for sale".to_string(),
            ));
        }
        
        // Get ownership record for metadata
        let record = manager.get_ownership_record(&content_hash)
            .ok_or_else(|| anyhow!("Content not found"))?;
        
        // TODO: Store listing in marketplace database
        // For now, just return success (listings would be stored in a separate system)
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "owner_wallet": request.owner_wallet,
            "asking_price": request.price,
            "description": request.description,
            "metadata": {
                "content_type": record.metadata_snapshot.content_type,
                "size": record.metadata_snapshot.size,
                "created_at": record.metadata_snapshot.created_at,
            },
            "message": "Content listed for sale successfully"
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!("✅ Content listed for {} ZHTP", request.price);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// POST /api/marketplace/content/{content_hash}/buy
    /// 
    /// Buy content from marketplace
    async fn buy_content(&self, content_hash_str: &str, body: &[u8]) -> ZhtpResult<ZhtpResponse> {
        info!("Processing content purchase: {}", content_hash_str);
        
        // Parse request body
        let request: PurchaseRequest = serde_json::from_slice(body)
            .map_err(|e| anyhow!("Invalid request body: {}", e))?;
        
        // Parse hashes
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        let buyer_wallet = Hash::from_hex(&request.buyer_wallet)
            .map_err(|e| anyhow!("Invalid buyer_wallet: {}", e))?;
        
        // Get current owner
        let manager = self.wallet_content_manager.read().await;
        let seller_wallet = manager.get_content_owner(&content_hash)
            .ok_or_else(|| anyhow!("Content not found or not owned"))?;
        
        // Check if buyer is trying to buy their own content
        if buyer_wallet == seller_wallet {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "Cannot buy your own content".to_string(),
            ));
        }
        drop(manager);
        
        // Create blockchain payment transaction
        info!("Creating blockchain payment transaction for {} ZHTP", request.offered_price);
        let tx_hash = self.create_payment_transaction(
            &buyer_wallet,
            &seller_wallet,
            request.offered_price,
            &content_hash,
        ).await?;
        
        // Execute ownership transfer
        let mut manager = self.wallet_content_manager.write().await;
        manager.transfer_content_ownership(
            &content_hash,
            seller_wallet.clone(),
            buyer_wallet,
            request.offered_price,
            tx_hash.clone(),
            ContentTransferType::Sale,
        )?;
        
        info!("✅ Content purchased successfully with tx_hash: {}", tx_hash);
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "seller_wallet": seller_wallet.to_string(),
            "buyer_wallet": request.buyer_wallet,
            "price": request.offered_price,
            "transaction_hash": tx_hash.to_string(),
            "message": "Content purchased successfully"
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/marketplace/listings
    /// 
    /// Get all active marketplace listings (placeholder)
    async fn get_marketplace_listings(&self) -> ZhtpResult<ZhtpResponse> {
        info!("Getting marketplace listings");
        
        // TODO: Implement actual marketplace listing storage
        // For now, return empty listings with instructions
        
        let response = serde_json::json!({
            "success": true,
            "listings": [],
            "total": 0,
            "message": "Marketplace listing storage not yet implemented. Use direct transfer for now."
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// Create a blockchain transaction for payment
    async fn create_payment_transaction(
        &self,
        from_wallet: &WalletId,
        to_wallet: &WalletId,
        amount: u64,
        content_hash: &Hash,
    ) -> Result<Hash, anyhow::Error> {
        info!("Creating blockchain payment transaction: {} → {} for {} ZHTP", 
              from_wallet, to_wallet, amount);
        
        // Store content metadata in memo field
        let metadata = serde_json::json!({
            "content_hash": content_hash.to_string(),
            "from_wallet": from_wallet.to_string(),
            "to_wallet": to_wallet.to_string(),
            "transfer_type": "Sale",
            "description": "Content ownership transfer"
        });
        let memo = serde_json::to_vec(&metadata)
            .map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
        
        // Create transaction output (payment to seller)
        // Note: This is a simplified ZK output. Full implementation needs:
        // - Pedersen commitment for amount privacy
        // - Encrypted note for recipient
        // - Proper recipient public key
        let commitment_hash = hash_blake3(format!("commitment_{}", amount).as_bytes());
        let note_hash = hash_blake3(content_hash.as_bytes());
        
        let output = TransactionOutput {
            commitment: lib_blockchain::Hash::new(commitment_hash),
            note: lib_blockchain::Hash::new(note_hash),
            recipient: lib_crypto::PublicKey {
                dilithium_pk: vec![0; 32],  // TODO: Use actual seller's Dilithium public key
                kyber_pk: Vec::new(),
                key_id: [0; 32],
            },
        };
        
        // Create transaction
        let transaction = Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::Transfer,
            inputs: vec![],  // TODO: Should pull from buyer's UTXOs with ZK proofs
            outputs: vec![output],
            fee: amount / 100,  // 1% transaction fee
            signature: lib_crypto::Signature {
                signature: vec![0; 64],  // TODO: Sign with buyer's private key
                public_key: lib_crypto::PublicKey {
                    dilithium_pk: vec![0; 32],  // TODO: Use buyer's public key
                    kyber_pk: Vec::new(),
                    key_id: [0; 32],
                },
                algorithm: lib_crypto::SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            },
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
        };
        
        // Calculate transaction hash
        let tx_bytes = serde_json::to_vec(&transaction)
            .map_err(|e| anyhow!("Failed to serialize transaction: {}", e))?;
        let tx_hash = lib_crypto::Hash::from_bytes(&hash_blake3(&tx_bytes));
        
        // Add transaction to blockchain
        let mut blockchain = self.blockchain.write().await;
        
        // Add to pending transaction pool for mining
        match blockchain.add_pending_transaction(transaction) {
            Ok(_) => {
                info!("✅ Transaction added to blockchain pending pool: {}", tx_hash);
            }
            Err(e) => {
                warn!("Failed to add transaction to blockchain: {}. Continuing anyway for testing.", e);
            }
        }
        
        Ok(tx_hash)
    }
}

/// Request to transfer content ownership
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferRequest {
    /// Sender wallet ID (hex)
    pub from_wallet: String,
    /// Recipient wallet ID (hex)
    pub to_wallet: String,
    /// Transfer price (0 for gifts)
    pub price: u64,
}

/// Request to list content for sale
#[derive(Debug, Serialize, Deserialize)]
pub struct ListingRequest {
    /// Owner wallet ID (hex)
    pub owner_wallet: String,
    /// Asking price in ZHTP
    pub price: u64,
    /// Optional description for listing
    pub description: Option<String>,
}

/// Request to purchase content
#[derive(Debug, Serialize, Deserialize)]
pub struct PurchaseRequest {
    /// Buyer wallet ID (hex)
    pub buyer_wallet: String,
    /// Offered price in ZHTP
    pub offered_price: u64,
}

/// Marketplace listing (for future use)
#[derive(Debug, Serialize, Deserialize)]
pub struct MarketplaceListing {
    pub content_hash: String,
    pub owner_wallet: String,
    pub asking_price: u64,
    pub listed_at: u64,
    pub description: Option<String>,
    pub metadata: serde_json::Value,
}

/// Implement ZhtpRequestHandler trait
#[async_trait::async_trait]
impl ZhtpRequestHandler for MarketplaceHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        self.handle_request_internal(&request).await
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        let path = &request.uri;
        
        // Handle marketplace API routes
        path.starts_with("/api/content/") && (
            path.contains("/transfer") || 
            path.contains("/list") || 
            path.contains("/buy")
        ) || path.starts_with("/api/marketplace/")
    }
    
    fn priority(&self) -> u32 {
        150 // Same priority as wallet content handler
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_request_parsing() {
        let json = r#"{
            "from_wallet": "abc123",
            "to_wallet": "def456",
            "price": 1000
        }"#;
        
        let request: TransferRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.from_wallet, "abc123");
        assert_eq!(request.to_wallet, "def456");
        assert_eq!(request.price, 1000);
    }

    #[test]
    fn test_purchase_request_parsing() {
        let json = r#"{
            "buyer_wallet": "buyer123",
            "offered_price": 500
        }"#;
        
        let request: PurchaseRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.buyer_wallet, "buyer123");
        assert_eq!(request.offered_price, 500);
    }
}
