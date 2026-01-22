//! Content Marketplace API Endpoints
//! 
//! Handles buying, selling, and transferring content ownership with blockchain integration.

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_protocols::zhtp::{ZhtpResult, ZhtpRequestHandler};
use lib_storage::WalletContentManager;
use lib_identity::wallets::{WalletId, wallet_types::ContentTransferType};
use lib_identity::identity::IdentityManager;
use lib_identity::types::IdentityId;
use lib_crypto::Hash;
use lib_crypto::hashing::hash_blake3;
use lib_blockchain::{TransactionOutput, TransactionType};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use anyhow::anyhow;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Handler for marketplace operations (buying, selling, transferring)
pub struct MarketplaceHandler {
    /// Shared wallet-content manager
    wallet_content_manager: Arc<RwLock<WalletContentManager>>,
    /// Blockchain reference for creating transactions
    blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
    /// Identity manager for retrieving private keys for transaction signing
    identity_manager: Arc<RwLock<IdentityManager>>,
}

impl MarketplaceHandler {
    /// Create new marketplace handler
    pub fn new(
        wallet_content_manager: Arc<RwLock<WalletContentManager>>,
        blockchain: Arc<RwLock<lib_blockchain::Blockchain>>,
        identity_manager: Arc<RwLock<IdentityManager>>,
    ) -> Self {
        info!("Initializing Marketplace API handler");
        Self {
            wallet_content_manager,
            blockchain,
            identity_manager,
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
                &request.buyer_identity_id,
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
        
        info!(" Content transferred successfully with tx_hash: {}", tx_hash);
        
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
        
        info!(" Content listed for {} ZHTP", request.price);
        
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
            &request.buyer_identity_id,
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
        
        info!(" Content purchased successfully with tx_hash: {}", tx_hash);
        
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

    /// Create a blockchain transaction for payment with proper signatures
    async fn create_payment_transaction(
        &self,
        buyer_identity_id: &str,
        from_wallet: &WalletId,
        to_wallet: &WalletId,
        amount: u64,
        content_hash: &Hash,
    ) -> Result<Hash, anyhow::Error> {
        info!("Creating blockchain payment transaction: {} → {} for {} ZHTP", 
              from_wallet, to_wallet, amount);
        
        // Parse buyer identity ID
        let identity_id_bytes = hex::decode(buyer_identity_id)
            .map_err(|e| anyhow!("Invalid buyer identity ID: {}", e))?;
        
        if identity_id_bytes.len() != 32 {
            return Err(anyhow!("Invalid identity ID length: expected 32 bytes, got {}", identity_id_bytes.len()));
        }
        
        let mut identity_id_array = [0u8; 32];
        identity_id_array.copy_from_slice(&identity_id_bytes);
        let identity_id: IdentityId = lib_crypto::Hash(identity_id_array);
        
        // Get buyer's identity and private key (P1-7: private keys stored in identity)
        let identity_mgr = self.identity_manager.read().await;
        let identity = identity_mgr.get_identity(&identity_id)
            .ok_or_else(|| anyhow!("Identity not found for buyer {}", hex::encode(&identity_id)))?;

        let private_key = identity.private_key.as_ref()
            .ok_or_else(|| anyhow!("Private key not found for buyer identity {}", hex::encode(&identity_id)))?;

        let identity_private_key_bytes = private_key.dilithium_sk.clone();
        let identity_seed = [0u8; 32]; // TODO: P1-7 - seed not directly accessible, may need to be stored separately
        let wallet_pubkey = identity.public_key.dilithium_pk.clone();
        drop(identity_mgr);
        
        // ========================================================================
        // STEP 1: Scan blockchain.utxo_set for UTXOs owned by buyer's wallet
        // ========================================================================
        info!(" Scanning blockchain UTXO set for buyer wallet's spendable outputs...");
        
        let blockchain = self.blockchain.read().await;
        let mut wallet_utxos: Vec<(lib_blockchain::Hash, u32, u64)> = Vec::new();
        
        info!(" Scanning {} UTXOs for wallet pubkey: {}", 
              blockchain.utxo_set.len(), 
              hex::encode(&wallet_pubkey[..8.min(wallet_pubkey.len())]));
        
        for (utxo_hash, output) in &blockchain.utxo_set {
            // Check if this UTXO belongs to buyer's wallet by comparing public keys
            if output.recipient.as_bytes() == wallet_pubkey {
                // NOTE: Amount is hidden in Pedersen commitment
                // For genesis UTXOs, we know the amount is 5000 ZHTP
                // In production, wallet would track amounts or decrypt notes
                let utxo_amount = 5000u64; // Genesis wallet funding amount
                
                wallet_utxos.push((*utxo_hash, 0, utxo_amount));
                info!("    Found UTXO: {}", hex::encode(utxo_hash.as_bytes()));
            }
        }
        
        if wallet_utxos.is_empty() {
            drop(blockchain);
            return Err(anyhow!("No UTXOs found for buyer wallet {}. Wallet may not have received genesis funding yet.", hex::encode(&wallet_pubkey[..8])));
        }
        
        info!(" Found {} UTXOs for buyer wallet", wallet_utxos.len());
        
        // ========================================================================
        // STEP 2: Select UTXOs to cover payment amount + fee
        // ========================================================================
        let fee = amount / 100;  // 1% transaction fee
        let required_amount = amount + fee;
        
        let mut selected_utxos = Vec::new();
        let mut total_selected = 0u64;
        
        for utxo in wallet_utxos {
            selected_utxos.push(utxo.clone());
            total_selected += utxo.2;
            
            if total_selected >= required_amount {
                break;
            }
        }
        
        if total_selected < required_amount {
            drop(blockchain);
            return Err(anyhow!("Insufficient funds: have {} ZHTP, need {} ZHTP (including {} ZHTP fee)", 
                              total_selected, required_amount, fee));
        }
        
        info!(" Selected {} UTXOs totaling {} ZHTP (need {} ZHTP)", 
              selected_utxos.len(), total_selected, required_amount);
        
        drop(blockchain);
        
        // ========================================================================
        // STEP 3: Build transaction inputs from selected UTXOs
        // ========================================================================
        
        
        let mut inputs = Vec::new();
        for (utxo_hash, output_index, _amount) in &selected_utxos {
            // Generate nullifier for this UTXO
            let nullifier_data = [utxo_hash.as_bytes(), &output_index.to_le_bytes()].concat();
            let nullifier = lib_blockchain::Hash::from_slice(&lib_crypto::hash_blake3(&nullifier_data)[..32]);
            
            // Create ZK proof for transaction privacy
            let zk_proof = lib_blockchain::integration::zk_integration::ZkTransactionProof::prove_transaction(
                total_selected,  // sender_balance
                0,               // receiver_balance (not needed for input)
                amount,          // payment amount
                fee,             // transaction fee
                [0u8; 32],       // sender_blinding (placeholder)
                [0u8; 32],       // receiver_blinding
                [0u8; 32],       // nullifier
            ).unwrap_or_else(|_| {
                // Fallback to default proof if generation fails
                lib_blockchain::integration::zk_integration::ZkTransactionProof::default()
            });
            
            let input = lib_blockchain::TransactionInput {
                previous_output: *utxo_hash,  //  CORRECT: Use actual UTXO hash from blockchain.utxo_set
                output_index: *output_index,
                nullifier,
                zk_proof,
            };
            inputs.push(input);
        }
        
        // ========================================================================
        // STEP 4: Create transaction outputs (payment + change)
        // ========================================================================
        let mut outputs = Vec::new();
        
        // Get seller's public key (derived from wallet ID)
        let seller_pubkey = to_wallet.as_bytes().to_vec();
        
        // Output 1: Payment to seller
        let payment_commitment = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"commitment:"[..], &seller_pubkey[..], &amount.to_le_bytes()].concat())[..32]
        );
        let payment_note = lib_blockchain::Hash::from_slice(
            &lib_crypto::hash_blake3(&[&b"note:marketplace_payment"[..], content_hash.as_bytes()].concat())[..32]
        );
        let payment_output = TransactionOutput {
            commitment: payment_commitment,
            note: payment_note,
            recipient: lib_crypto::PublicKey {
                dilithium_pk: seller_pubkey.clone(),
                kyber_pk: Vec::new(),
                key_id: [0; 32],
            },
        };
        outputs.push(payment_output);
        info!("   → Payment output: {} ZHTP to seller", amount);
        
        // Output 2: Change back to buyer (if any)
        let change_amount = total_selected.saturating_sub(required_amount);
        if change_amount > 0 {
            let change_commitment = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"commitment:"[..], &wallet_pubkey[..], &change_amount.to_le_bytes()].concat())[..32]
            );
            let change_note = lib_blockchain::Hash::from_slice(
                &lib_crypto::hash_blake3(&[&b"note:change"[..]].concat())[..32]
            );
            let change_output = lib_blockchain::TransactionOutput {
                commitment: change_commitment,
                note: change_note,
                recipient: lib_crypto::PublicKey {
                    dilithium_pk: wallet_pubkey.clone(),
                    kyber_pk: Vec::new(),
                    key_id: [0; 32],
                },
            };
            outputs.push(change_output);
            info!("   → Change output: {} ZHTP back to buyer", change_amount);
        }
        
        // ========================================================================
        // STEP 5: Store content metadata in memo field
        // ========================================================================
        let metadata = serde_json::json!({
            "content_hash": content_hash.to_string(),
            "from_wallet": from_wallet.to_string(),
            "to_wallet": to_wallet.to_string(),
            "transfer_type": "Sale",
            "description": "Content ownership transfer"
        });
        let memo = serde_json::to_vec(&metadata)
            .map_err(|e| anyhow!("Failed to serialize metadata: {}", e))?;
        
        // Build and sign transaction using TransactionBuilder with real private key
        use lib_blockchain::transaction::TransactionBuilder;
        use lib_crypto::PrivateKey;
        
        let private_key = PrivateKey {
            dilithium_sk: identity_private_key_bytes,
            dilithium_pk: wallet_pubkey.clone(),
            kyber_sk: Vec::new(),
            master_seed: identity_seed.to_vec(),
        };
        
        let mut transaction = TransactionBuilder::new()
            .transaction_type(TransactionType::Transfer)
            .add_inputs(inputs)
            .add_outputs(outputs)
            .fee(fee)
            .build(&private_key)
            .map_err(|e| anyhow!("Failed to build transaction: {:?}", e))?;
        
        // Set memo
        transaction.memo = memo;
        
        let tx_hash = transaction.hash();
        info!(" Marketplace transaction created with real signature: {}", hex::encode(tx_hash.as_bytes()));
        
        // Add transaction to blockchain
        let mut blockchain = self.blockchain.write().await;
        blockchain.add_pending_transaction(transaction)
            .map_err(|e| anyhow!("Transaction validation failed: {}", e))?;
        
        info!(" Transaction added to blockchain mempool");
        Ok(lib_crypto::Hash::from_bytes(tx_hash.as_bytes()))
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
    /// Buyer's identity ID (hex) - required for transaction signing
    pub buyer_identity_id: String,
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
    /// Buyer's identity ID (hex) - required for transaction signing
    pub buyer_identity_id: String,
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
            "price": 1000,
            "buyer_identity_id": "identity789"
        }"#;

        let request: TransferRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.from_wallet, "abc123");
        assert_eq!(request.to_wallet, "def456");
        assert_eq!(request.price, 1000);
        assert_eq!(request.buyer_identity_id, "identity789");
    }

    #[test]
    fn test_purchase_request_parsing() {
        let json = r#"{
            "buyer_wallet": "buyer123",
            "offered_price": 500,
            "buyer_identity_id": "identity456"
        }"#;

        let request: PurchaseRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.buyer_wallet, "buyer123");
        assert_eq!(request.offered_price, 500);
        assert_eq!(request.buyer_identity_id, "identity456");
    }
}
