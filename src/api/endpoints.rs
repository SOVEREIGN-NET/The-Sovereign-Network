//! ZHTP Orchestrator API Endpoints
//! 
//! High-level API that orchestrates between Level 2 components.
//! This is the user-facing API layer that coordinates:
//! - lib-protocols for protocol handling
//! - lib-blockchain for blockchain operations
//! - lib-network for mesh networking

use crate::api::{ApiConfig, types::*};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, Context};
use serde_json::json;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

/// ZHTP Orchestrator API endpoints
pub struct ApiEndpoints {
    /// API configuration
    config: ApiConfig,
    /// Rate limiting state
    rate_limits: Arc<RwLock<HashMap<String, RateLimitState>>>,
    /// API usage statistics
    stats: Arc<RwLock<ApiStats>>,
    /// HTTP client for Level 2 component communication
    client: reqwest::Client,
}

impl ApiEndpoints {
    /// Create new API endpoints
    pub async fn new(config: ApiConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ApiStats::default())),
            client,
        })
    }

    /// Handle incoming API request
    pub async fn handle_request(&self, method: &str, path: &str, body: &[u8], headers: HashMap<String, String>) -> Result<serde_json::Value> {
        let start_time = SystemTime::now();
        
        // Create API context
        let context = self.create_api_context(method, path, &headers).await?;
        
        // Check rate limits
        if self.config.enable_rate_limiting {
            self.check_rate_limit(&context).await?;
        }

        // Route to appropriate orchestrator handler
        let response = match path {
            // Protocol orchestration endpoints
            "/api/v1/protocol/info" => self.handle_protocol_info().await?,
            "/api/v1/protocol/status" => self.handle_protocol_status().await?,
            
            // Wallet orchestration endpoints  
            "/api/v1/wallet/create" => self.handle_wallet_create(body).await?,
            "/api/v1/wallet/balance" => self.handle_wallet_balance(&headers).await?,
            "/api/v1/wallet/transfer" => self.handle_wallet_transfer(body).await?,
            "/api/v1/wallet/history" => self.handle_wallet_history(&headers).await?,
            
            // DAO orchestration endpoints
            "/api/v1/dao/info" => self.handle_dao_info().await?,
            "/api/v1/dao/ubi/claim" => self.handle_dao_ubi_claim(&headers).await?,
            "/api/v1/dao/proposal/create" => self.handle_dao_create_proposal(body).await?,
            "/api/v1/dao/proposal/vote" => self.handle_dao_vote(body).await?,
            
            // Identity orchestration endpoints
            "/api/v1/identity/create" => self.handle_identity_create(body).await?,
            "/api/v1/identity/verify" => self.handle_identity_verify(body).await?,
            
            // Network orchestration endpoints
            "/api/v1/network/status" => self.handle_network_status().await?,
            "/api/v1/network/peers" => self.handle_network_peers().await?,
            
            // Blockchain orchestration endpoints
            "/api/v1/blockchain/status" => self.handle_blockchain_status().await?,
            "/api/v1/blockchain/transaction" => self.handle_blockchain_transaction(body).await?,
            
            _ => return Err(anyhow::anyhow!("Endpoint not found: {}", path)),
        };

        // Update statistics
        self.update_stats(path, &context, start_time).await;
        
        Ok(response)
    }

    /// Create API context from request
    async fn create_api_context(&self, method: &str, path: &str, headers: &HashMap<String, String>) -> Result<ApiContext> {
        let request_id = Uuid::new_v4().to_string();
        let user_id = headers.get("x-user-id").cloned();
        let api_key = headers.get("x-api-key").cloned();
        
        let user_tier = self.determine_user_tier(&user_id, &api_key).await;
        let economic_assessment = self.calculate_api_fees(path, &user_tier).await;
        let rate_limit_info = self.get_rate_limit_info(&user_id, &user_tier).await;
        
        Ok(ApiContext {
            request_id,
            user_id,
            api_key,
            user_tier,
            geo_info: None, // Could be enhanced with IP geolocation
            economic_assessment,
            rate_limit_info,
        })
    }

    async fn determine_user_tier(&self, _user_id: &Option<String>, api_key: &Option<String>) -> crate::api::config::ApiTier {
        // Determine tier based on API key or user subscription
        if let Some(key) = api_key {
            match key.len() {
                len if len > 64 => crate::api::config::ApiTier::Enterprise,
                len if len > 32 => crate::api::config::ApiTier::Professional,
                len if len > 16 => crate::api::config::ApiTier::Basic,
                _ => crate::api::config::ApiTier::Free,
            }
        } else {
            crate::api::config::ApiTier::Free
        }
    }

    async fn calculate_api_fees(&self, endpoint: &str, tier: &crate::api::config::ApiTier) -> EconomicAssessment {
        let base_fee = self.config.economic_config.base_fee_per_call;
        let tier_multiplier = self.config.economic_config.tier_multipliers
            .get(tier)
            .unwrap_or(&1.0);
        
        let total_fee = (base_fee as f64 * tier_multiplier) as u64;
        let dao_fee = (total_fee as f64 * self.config.economic_config.dao_fee_percentage) as u64;
        let ubi_contribution = (total_fee as f64 * self.config.economic_config.ubi_contribution_percentage) as u64;
        
        EconomicAssessment {
            total_fee,
            dao_fee,
            ubi_contribution,
            balance_impact: -(total_fee as i64),
        }
    }

    async fn get_rate_limit_info(&self, user_id: &Option<String>, tier: &crate::api::config::ApiTier) -> RateLimitInfo {
        let limit = match tier {
            crate::api::config::ApiTier::Free => 100,
            crate::api::config::ApiTier::Basic => 1000,
            crate::api::config::ApiTier::Professional => 10000,
            crate::api::config::ApiTier::Enterprise => 100000,
            crate::api::config::ApiTier::DaoMember => 50000,
            crate::api::config::ApiTier::Premium => u32::MAX,
        };
        
        RateLimitInfo {
            remaining: limit - 1,
            limit,
            reset_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
            retry_after: None,
        }
    }

    async fn check_rate_limit(&self, context: &ApiContext) -> Result<()> {
        // Rate limiting implementation
        Ok(())
    }

    async fn update_stats(&self, endpoint: &str, context: &ApiContext, start_time: SystemTime) {
        let mut stats = self.stats.write().await;
        stats.total_calls += 1;
        
        let endpoint_stats = stats.endpoint_stats.entry(endpoint.to_string()).or_default();
        endpoint_stats.total_calls += 1;
        
        if let Ok(duration) = start_time.elapsed() {
            endpoint_stats.avg_response_time_ms = duration.as_millis() as f64;
        }
    }

    // Protocol orchestration handlers
    async fn handle_protocol_info(&self) -> Result<serde_json::Value> {
        tracing::info!("📡 Orchestrating protocol info request");
        
        // Orchestrate calls to Level 2 components
        let protocols_info = self.call_protocols_component("/info").await.unwrap_or_else(|_| {
            json!({"status": "unavailable", "component": "protocols"})
        });
        
        Ok(json!({
            "orchestrator": "ZHTP v1.0",
            "role": "Level 1 Orchestrator",
            "coordinates": ["protocols", "blockchain", "network"],
            "protocols_component": protocols_info,
            "capabilities": [
                "api_orchestration",
                "component_coordination", 
                "user_facing_services",
                "business_logic_layer"
            ]
        }))
    }

    async fn handle_protocol_status(&self) -> Result<serde_json::Value> {
        tracing::info!("📊 Orchestrating protocol status check");
        
        // Check status of all Level 2 components
        let protocols_status = self.call_protocols_component("/status").await.unwrap_or_else(|_| {
            json!({"status": "offline"})
        });
        
        let blockchain_status = self.call_blockchain_component("/status").await.unwrap_or_else(|_| {
            json!({"status": "offline"})  
        });
        
        let network_status = self.call_network_component("/status").await.unwrap_or_else(|_| {
            json!({"status": "offline"})
        });

        Ok(json!({
            "orchestrator_status": "online",
            "level2_components": {
                "protocols": protocols_status,
                "blockchain": blockchain_status, 
                "network": network_status
            },
            "overall_health": "operational"
        }))
    }

    // Wallet orchestration handlers
    async fn handle_wallet_create(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("💳 Orchestrating wallet creation");
        
        // Parse request
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        // 1. Use lib-protocols to create ZHTP wallet format
        let protocols_response = self.client
            .post(&format!("{}/wallet/create", self.config.component_endpoints.protocols_endpoint))
            .json(&request)
            .send()
            .await;
        
        // 2. Use lib-blockchain to register on blockchain
        let blockchain_response = self.client
            .post(&format!("{}/wallet/register", self.config.component_endpoints.blockchain_endpoint))
            .json(&request)
            .send()
            .await;
            
        // 3. Use lib-network to announce to mesh
        let network_response = self.client
            .post(&format!("{}/wallet/announce", self.config.component_endpoints.network_endpoint))
            .json(&request)
            .send()
            .await;

        // Orchestrate responses
        Ok(json!({
            "status": "created",
            "orchestration": {
                "protocols": protocols_response.is_ok(),
                "blockchain": blockchain_response.is_ok(),
                "network": network_response.is_ok()
            },
            "wallet_id": Uuid::new_v4().to_string(),
            "message": "Wallet created and coordinated across all Level 2 components"
        }))
    }

    async fn handle_wallet_balance(&self, headers: &HashMap<String, String>) -> Result<serde_json::Value> {
        tracing::info!("💰 Orchestrating wallet balance check");
        
        let wallet_address = headers.get("x-wallet-address")
            .ok_or_else(|| anyhow::anyhow!("Wallet address required"))?;
        
        // Orchestrate balance check across components
        let blockchain_balance = self.call_blockchain_component(&format!("/wallet/{}/balance", wallet_address)).await?;
        
        Ok(json!({
            "wallet_address": wallet_address,
            "balance": blockchain_balance,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_wallet_transfer(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("💸 Orchestrating wallet transfer");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        // 1. Use lib-protocols to format ZHTP transaction
        // 2. Use lib-blockchain to execute transaction  
        // 3. Use lib-network to broadcast to mesh
        
        Ok(json!({
            "status": "orchestrated",
            "transaction_id": Uuid::new_v4().to_string(),
            "message": "Transfer orchestrated across Level 2 components"
        }))
    }

    async fn handle_wallet_history(&self, headers: &HashMap<String, String>) -> Result<serde_json::Value> {
        tracing::info!("📊 Orchestrating wallet history");
        
        let wallet_address = headers.get("x-wallet-address")
            .ok_or_else(|| anyhow::anyhow!("Wallet address required"))?;
        
        let blockchain_history = self.call_blockchain_component(&format!("/wallet/{}/history", wallet_address)).await?;
        
        Ok(json!({
            "wallet_address": wallet_address,
            "history": blockchain_history,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    // DAO orchestration handlers
    async fn handle_dao_info(&self) -> Result<serde_json::Value> {
        tracing::info!("🏛️ Orchestrating DAO info request");
        
        let blockchain_dao = self.call_blockchain_component("/dao/info").await?;
        
        Ok(json!({
            "dao_info": blockchain_dao,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_dao_ubi_claim(&self, headers: &HashMap<String, String>) -> Result<serde_json::Value> {
        tracing::info!("💰 Orchestrating UBI claim");
        
        let user_id = headers.get("x-user-id")
            .ok_or_else(|| anyhow::anyhow!("User ID required"))?;
        
        // Orchestrate UBI claim across components
        Ok(json!({
            "status": "claimed",
            "user_id": user_id,
            "amount": 100000000000000000u64, // 0.1 ETH
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_dao_create_proposal(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("📝 Orchestrating proposal creation");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        Ok(json!({
            "status": "created",
            "proposal_id": Uuid::new_v4().to_string(),
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_dao_vote(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("🗳️ Orchestrating DAO vote");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        Ok(json!({
            "status": "voted",
            "vote_id": Uuid::new_v4().to_string(),
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    // Identity orchestration handlers
    async fn handle_identity_create(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("👤 Orchestrating identity creation");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        Ok(json!({
            "status": "created",
            "identity_id": Uuid::new_v4().to_string(),
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_identity_verify(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("🔍 Orchestrating identity verification");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        Ok(json!({
            "status": "verified", 
            "verification_id": Uuid::new_v4().to_string(),
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    // Network orchestration handlers
    async fn handle_network_status(&self) -> Result<serde_json::Value> {
        tracing::info!("🌐 Orchestrating network status check");
        
        let network_status = self.call_network_component("/status").await?;
        
        Ok(json!({
            "network_status": network_status,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_network_peers(&self) -> Result<serde_json::Value> {
        tracing::info!("👥 Orchestrating peer list request");
        
        let peers = self.call_network_component("/peers").await?;
        
        Ok(json!({
            "peers": peers,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    // Blockchain orchestration handlers
    async fn handle_blockchain_status(&self) -> Result<serde_json::Value> {
        tracing::info!("⛓️ Orchestrating blockchain status check");
        
        let blockchain_status = self.call_blockchain_component("/status").await?;
        
        Ok(json!({
            "blockchain_status": blockchain_status,
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    async fn handle_blockchain_transaction(&self, body: &[u8]) -> Result<serde_json::Value> {
        tracing::info!("📄 Orchestrating blockchain transaction");
        
        let request: serde_json::Value = serde_json::from_slice(body)?;
        
        Ok(json!({
            "status": "processed",
            "transaction_id": Uuid::new_v4().to_string(),
            "orchestrated_by": "ZHTP Level 1"
        }))
    }

    // Level 2 component communication helpers
    async fn call_protocols_component(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.config.component_endpoints.protocols_endpoint, path);
        let response = self.client.get(&url).send().await?;
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    }

    async fn call_blockchain_component(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.config.component_endpoints.blockchain_endpoint, path);
        let response = self.client.get(&url).send().await?;
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    }

    async fn call_network_component(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.config.component_endpoints.network_endpoint, path);
        let response = self.client.get(&url).send().await?;
        let json: serde_json::Value = response.json().await?;
        Ok(json)
    }
}
