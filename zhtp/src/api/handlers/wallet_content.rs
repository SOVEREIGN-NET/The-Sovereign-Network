//! Wallet Content Ownership API Endpoints
//! 
//! This module provides REST API endpoints for querying and managing
//! wallet-owned content in the SOVEREIGN_NET ecosystem.

use lib_protocols::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpResult, ZhtpRequestHandler};
use lib_storage::WalletContentManager;
use lib_crypto::Hash;
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use anyhow::anyhow;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Handler for wallet content ownership operations
pub struct WalletContentHandler {
    /// Shared wallet-content manager
    wallet_content_manager: Arc<RwLock<WalletContentManager>>,
}

impl WalletContentHandler {
    /// Create new wallet content handler
    pub fn new(wallet_content_manager: Arc<RwLock<WalletContentManager>>) -> Self {
        info!("Initializing Wallet Content API handler");
        Self {
            wallet_content_manager,
        }
    }

    /// Route incoming requests to appropriate handlers
    pub async fn handle_request_internal(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let path = &request.uri;
        
        // Parse path segments
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        match (request.method.as_str(), segments.as_slice()) {
            // GET /api/wallet/{wallet_id}/content
            ("GET", ["api", "wallet", wallet_id, "content"]) => {
                self.get_wallet_content(wallet_id).await
            }
            
            // GET /api/wallet/{wallet_id}/content/statistics
            ("GET", ["api", "wallet", wallet_id, "content", "statistics"]) => {
                self.get_wallet_content_statistics(wallet_id).await
            }
            
            // GET /api/content/{content_hash}/ownership
            ("GET", ["api", "content", content_hash, "ownership"]) => {
                self.get_content_ownership(content_hash).await
            }
            
            // GET /api/content/{content_hash}/transfers
            ("GET", ["api", "content", content_hash, "transfers"]) => {
                self.get_content_transfer_history(content_hash).await
            }
            
            // GET /api/content/{content_hash}/verify-ownership/{wallet_id}
            ("GET", ["api", "content", content_hash, "verify-ownership", wallet_id]) => {
                self.verify_content_ownership(content_hash, wallet_id).await
            }
            
            _ => {
                error!("Unknown wallet content API endpoint: {} {}", request.method, path);
                Ok(ZhtpResponse::error(
                    ZhtpStatus::NotFound,
                    "Unknown wallet content API endpoint".to_string(),
                ))
            }
        }
    }

    /// GET /api/wallet/{wallet_id}/content
    /// 
    /// Returns list of all content hashes owned by the wallet
    async fn get_wallet_content(&self, wallet_id_str: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Getting content list for wallet: {}", wallet_id_str);
        
        // Parse wallet ID (hex string)
        let wallet_id = Hash::from_hex(wallet_id_str)
            .map_err(|e| anyhow!("Invalid wallet ID: {}", e))?;
        
        // Get wallet content
        let manager = self.wallet_content_manager.read().await;
        let content_list = manager.get_wallet_content(&wallet_id);
        
        // Get detailed info for each content item
        let mut content_items = Vec::new();
        for content_hash in content_list {
            if let Some(record) = manager.get_ownership_record(&content_hash) {
                content_items.push(serde_json::json!({
                    "content_hash": content_hash.to_string(),
                    "acquired_at": record.acquired_at,
                    "purchase_price": record.purchase_price,
                    "previous_owner": record.previous_owner.as_ref().map(|id| id.to_string()),
                    "metadata": {
                        "content_type": record.metadata_snapshot.content_type,
                        "size": record.metadata_snapshot.size,
                        "description": record.metadata_snapshot.description,
                        "tags": record.metadata_snapshot.tags,
                        "created_at": record.metadata_snapshot.created_at,
                    },
                    "transfer_count": record.transfer_history.len(),
                }));
            }
        }
        
        let response = serde_json::json!({
            "success": true,
            "wallet_id": wallet_id_str,
            "total_items": content_items.len(),
            "content": content_items,
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!(" Found {} content items for wallet {}", content_items.len(), wallet_id_str);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/wallet/{wallet_id}/content/statistics
    /// 
    /// Returns statistics about wallet's owned content
    async fn get_wallet_content_statistics(&self, wallet_id_str: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Getting content statistics for wallet: {}", wallet_id_str);
        
        // Parse wallet ID (hex string)
        let wallet_id = Hash::from_hex(wallet_id_str)
            .map_err(|e| anyhow!("Invalid wallet ID: {}", e))?;
        
        // Get statistics
        let manager = self.wallet_content_manager.read().await;
        let stats = manager.get_wallet_content_statistics(&wallet_id);
        
        let response = serde_json::json!({
            "success": true,
            "wallet_id": wallet_id_str,
            "statistics": {
                "total_items": stats.total_items,
                "total_storage_bytes": stats.total_storage_bytes,
                "total_storage_mb": (stats.total_storage_bytes as f64) / (1024.0 * 1024.0),
                "total_value": stats.total_value,
                "content_by_type": stats.content_types,
            },
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!(" Wallet {} owns {} items ({} bytes, {} SOV value)", 
              wallet_id_str, stats.total_items, stats.total_storage_bytes, stats.total_value);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/content/{content_hash}/ownership
    /// 
    /// Returns ownership information for specific content
    async fn get_content_ownership(&self, content_hash_str: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Getting ownership info for content: {}", content_hash_str);
        
        // Parse content hash
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        
        // Get ownership record
        let manager = self.wallet_content_manager.read().await;
        let record = manager.get_ownership_record(&content_hash)
            .ok_or_else(|| anyhow!("Content not found or not owned"))?;
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "ownership": {
                "owner_wallet_id": record.owner_wallet_id.to_string(),
                "previous_owner": record.previous_owner.as_ref().map(|id| id.to_string()),
                "purchase_price": record.purchase_price,
                "acquired_at": record.acquired_at,
                "transfer_count": record.transfer_history.len(),
            },
            "metadata": {
                "content_type": record.metadata_snapshot.content_type,
                "size": record.metadata_snapshot.size,
                "description": record.metadata_snapshot.description,
                "tags": record.metadata_snapshot.tags,
                "created_at": record.metadata_snapshot.created_at,
            },
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!(" Content owned by wallet {}", record.owner_wallet_id);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/content/{content_hash}/transfers
    /// 
    /// Returns full transfer history for content
    async fn get_content_transfer_history(&self, content_hash_str: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Getting transfer history for content: {}", content_hash_str);
        
        // Parse content hash
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        
        // Get transfer history
        let manager = self.wallet_content_manager.read().await;
        let transfers = manager.get_content_transfer_history(&content_hash);
        
        let transfer_list: Vec<_> = transfers.iter().map(|transfer| {
            serde_json::json!({
                "from_wallet": transfer.from_wallet.to_string(),
                "to_wallet": transfer.to_wallet.to_string(),
                "price": transfer.price,
                "timestamp": transfer.timestamp,
                "transaction_hash": transfer.tx_hash.to_string(),
                "transfer_type": format!("{:?}", transfer.transfer_type),
            })
        }).collect();
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "transfer_count": transfer_list.len(),
            "transfers": transfer_list,
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!(" Found {} transfers for content", transfer_list.len());
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/content/{content_hash}/verify-ownership/{wallet_id}
    /// 
    /// Verifies if a wallet owns specific content
    async fn verify_content_ownership(&self, content_hash_str: &str, wallet_id_str: &str) -> ZhtpResult<ZhtpResponse> {
        info!("Verifying ownership of {} by wallet {}", content_hash_str, wallet_id_str);
        
        // Parse IDs
        let content_hash = Hash::from_hex(content_hash_str)
            .map_err(|e| anyhow!("Invalid content hash: {}", e))?;
        let wallet_id = Hash::from_hex(wallet_id_str)
            .map_err(|e| anyhow!("Invalid wallet ID: {}", e))?;
        
        // Verify ownership
        let manager = self.wallet_content_manager.read().await;
        let is_owner = manager.verify_ownership(&content_hash, &wallet_id);
        
        let response = serde_json::json!({
            "success": true,
            "content_hash": content_hash_str,
            "wallet_id": wallet_id_str,
            "is_owner": is_owner,
        });
        
        let response_json = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        
        info!(" Ownership verification: {}", is_owner);
        
        Ok(ZhtpResponse::success_with_content_type(
            response_json,
            "application/json".to_string(),
            None,
        ))
    }
}

/// Response format for wallet content list
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletContentResponse {
    pub success: bool,
    pub wallet_id: String,
    pub total_items: usize,
    pub content: Vec<ContentItem>,
}

/// Individual content item in response
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentItem {
    pub content_hash: String,
    pub acquired_at: u64,
    pub purchase_price: u64,
    pub previous_owner: Option<String>,
    pub metadata: ContentMetadataResponse,
    pub transfer_count: usize,
}

/// Content metadata in response
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentMetadataResponse {
    pub content_type: String,
    pub size: u64,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: u64,
}

/// Response format for wallet content statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletContentStatisticsResponse {
    pub success: bool,
    pub wallet_id: String,
    pub statistics: StatisticsData,
}

/// Statistics data
#[derive(Debug, Serialize, Deserialize)]
pub struct StatisticsData {
    pub total_items: usize,
    pub total_storage_bytes: u64,
    pub total_storage_mb: f64,
    pub total_value: u64,
    pub content_by_type: std::collections::HashMap<String, usize>,
}

/// Implement ZhtpRequestHandler trait for integration with ZHTP router
#[async_trait::async_trait]
impl ZhtpRequestHandler for WalletContentHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        self.handle_request_internal(&request).await
    }
    
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        let path = &request.uri;
        
        // Handle wallet content API routes
        path.starts_with("/api/wallet/") && path.contains("/content") ||
        path.starts_with("/api/content/") && (
            path.contains("/ownership") || 
            path.contains("/transfers") || 
            path.contains("/verify-ownership")
        )
    }
    
    fn priority(&self) -> u32 {
        150 // Higher priority than default (100)
    }
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_path_parsing() {
        let path = "/api/wallet/wallet_123/content";
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        assert_eq!(segments, vec!["api", "wallet", "wallet_123", "content"]);
    }
}
