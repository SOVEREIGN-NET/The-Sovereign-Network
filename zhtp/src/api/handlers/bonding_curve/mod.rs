//! Bonding Curve API Handlers
//!
//! Clean separation of concerns:
//! - CurveHandler → ERC-20 style primitives + bonding curve lifecycle
//! - SwapHandler → AMM operations (post-graduation)
//! - ValuationHandler → Read-only price aggregation
//!
//! # Architecture
//! ```text
//! TokenHandler ────────────────────────────────► ERC-20 primitives
//!      │
//!      ▼
//! CurveHandler ──► Deploy/Buy/Sell/Curve Stats
//!      │
//!      ▼ (Graduation)
//! SwapHandler ───► AMM swaps, liquidity ops
//!      │
//!      ▼ (Price queries)
//! ValuationHandler ──► Unified price endpoint with confidence
//! ```

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
use lib_blockchain::contracts::bonding_curve::{
    BondingCurveToken, Phase, CurveType, Threshold, Valuation, PriceSource, ConfidenceLevel,
};
use lib_blockchain::integration::crypto_integration::PublicKey;

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

/// Deploy a new bonding curve token
#[derive(Debug, Deserialize)]
pub struct DeployCurveTokenRequest {
    /// Token name
    pub name: String,
    /// Token symbol (max 10 chars)
    pub symbol: String,
    /// Curve type configuration
    pub curve_type: CurveTypeRequest,
    /// Graduation threshold
    pub threshold: ThresholdRequest,
    /// Whether selling is enabled during curve phase
    pub sell_enabled: bool,
}

/// Curve type request (JSON-friendly)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CurveTypeRequest {
    Linear { base_price: u64, slope: u64 },
    Exponential { base_price: u64, growth_rate_bps: u64 },
    Sigmoid { max_price: u64, midpoint_supply: u64, steepness: u64 },
}

impl From<CurveTypeRequest> for CurveType {
    fn from(req: CurveTypeRequest) -> Self {
        match req {
            CurveTypeRequest::Linear { base_price, slope } => {
                CurveType::Linear { base_price, slope }
            }
            CurveTypeRequest::Exponential { base_price, growth_rate_bps } => {
                CurveType::Exponential { base_price, growth_rate_bps }
            }
            CurveTypeRequest::Sigmoid { max_price, midpoint_supply, steepness } => {
                CurveType::Sigmoid { max_price, midpoint_supply, steepness }
            }
        }
    }
}

/// Threshold request (JSON-friendly)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ThresholdRequest {
    ReserveAmount { min_reserve: u64 },
    SupplyAmount { min_supply: u64 },
    TimeAndReserve { min_time_seconds: u64, min_reserve: u64 },
    TimeAndSupply { min_time_seconds: u64, min_supply: u64 },
}

impl From<ThresholdRequest> for Threshold {
    fn from(req: ThresholdRequest) -> Self {
        match req {
            ThresholdRequest::ReserveAmount { min_reserve } => {
                Threshold::ReserveAmount(min_reserve)
            }
            ThresholdRequest::SupplyAmount { min_supply } => {
                Threshold::SupplyAmount(min_supply)
            }
            ThresholdRequest::TimeAndReserve { min_time_seconds, min_reserve } => {
                Threshold::TimeAndReserve { min_time_seconds, min_reserve }
            }
            ThresholdRequest::TimeAndSupply { min_time_seconds, min_supply } => {
                Threshold::TimeAndSupply { min_time_seconds, min_supply }
            }
        }
    }
}

/// Buy tokens from curve request
#[derive(Debug, Deserialize)]
pub struct BuyTokensRequest {
    /// Token ID (hex)
    pub token_id: String,
    /// Amount of stablecoin to spend (atomic units)
    pub stable_amount: u64,
}

/// Sell tokens to curve request
#[derive(Debug, Deserialize)]
pub struct SellTokensRequest {
    /// Token ID (hex)
    pub token_id: String,
    /// Amount of tokens to sell (atomic units)
    pub token_amount: u64,
}

/// AMM swap request
#[derive(Debug, Deserialize)]
pub struct SwapRequest {
    /// Token ID (hex)
    pub token_id: String,
    /// Pool ID (hex)
    pub pool_id: String,
    /// Amount in (atomic units)
    pub amount_in: u64,
    /// Minimum amount out (slippage protection)
    pub min_amount_out: u64,
    /// True if swapping token for SOV, false for SOV to token
    pub token_to_sov: bool,
}

/// Add liquidity request
#[derive(Debug, Deserialize)]
pub struct AddLiquidityRequest {
    /// Token ID (hex)
    pub token_id: String,
    /// Pool ID (hex)
    pub pool_id: String,
    /// Token amount to add
    pub token_amount: u64,
    /// SOV amount to add
    pub sov_amount: u64,
}

/// Remove liquidity request
#[derive(Debug, Deserialize)]
pub struct RemoveLiquidityRequest {
    /// Token ID (hex)
    pub token_id: String,
    /// Pool ID (hex)
    pub pool_id: String,
    /// LP tokens to burn
    pub lp_amount: u64,
}

/// Price query parameters
#[derive(Debug, Deserialize, Default)]
pub struct PriceQueryParams {
    /// Price type: "spot" or "twap" (default: twap)
    #[serde(default)]
    pub price_type: Option<String>,
}

/// Token valuation response
#[derive(Debug, Serialize)]
pub struct ValuationResponse {
    pub token_id: String,
    pub price_usd_cents: u64,
    pub source: String,
    pub confidence_level: String,
    pub phase: String,
}

/// Curve token info response
#[derive(Debug, Serialize)]
pub struct CurveTokenInfoResponse {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub phase: String,
    pub total_supply: u64,
    pub reserve_balance: u64,
    pub current_price: u64,
    pub curve_type: String,
    pub sell_enabled: bool,
    pub can_graduate: bool,
    pub graduation_progress_percent: u8,
    pub creator: String,
    pub deployed_at: u64,
}

/// Swap response
#[derive(Debug, Serialize)]
pub struct SwapResponse {
    pub token_id: String,
    pub pool_id: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub price_impact_bps: u64,
    pub tx_status: String,
}

/// Liquidity response
#[derive(Debug, Serialize)]
pub struct LiquidityResponse {
    pub token_id: String,
    pub pool_id: String,
    pub token_amount: u64,
    pub sov_amount: u64,
    pub lp_tokens_minted: u64,
    pub tx_status: String,
}

// ============================================================================
// CurveHandler - Bonding Curve Lifecycle
// ============================================================================

/// Bonding curve lifecycle handler
/// 
/// Handles: deploy, buy, sell, graduation, curve stats
/// Does NOT handle: AMM swaps (use SwapHandler), pricing queries (use ValuationHandler)
pub struct CurveHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl CurveHandler {
    pub fn new() -> Self {
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });

        Self { blockchain }
    }

    /// POST /api/v1/curve/deploy - Deploy new bonding curve token
    async fn handle_deploy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let deploy_req: DeployCurveTokenRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Validate
        if deploy_req.name.is_empty() || deploy_req.symbol.is_empty() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Name and symbol required".to_string(),
            ));
        }

        if deploy_req.symbol.len() > 10 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Symbol max 10 characters".to_string(),
            ));
        }

        // Get creator from requester (must be authenticated)
        let creator = self.get_requester_key(&request)?;

        // Generate token ID deterministically
        let token_id = self.generate_token_id(&deploy_req.name, &deploy_req.symbol, &creator.key_id);

        // Check if already exists
        {
            let blockchain = self.blockchain.read().await;
            if blockchain.bonding_curve_registry.contains(&token_id) {
                return Ok(create_error_response(
                    ZhtpStatus::Conflict,
                    "Token with this name and symbol already exists".to_string(),
                ));
            }
        }

        // Deploy token
        let curve_type: CurveType = deploy_req.curve_type.into();
        let threshold: Threshold = deploy_req.threshold.into();

        let token = BondingCurveToken::deploy(
            token_id,
            deploy_req.name.clone(),
            deploy_req.symbol.clone(),
            curve_type,
            threshold,
            deploy_req.sell_enabled,
            creator,
            self.get_current_block().await?,
            self.get_current_timestamp().await?,
        ).map_err(|e| anyhow::anyhow!("Deploy failed: {}", e))?;

        // Register in blockchain
        {
            let mut blockchain = self.blockchain.write().await;
            blockchain.bonding_curve_registry.register(token.clone())
                .map_err(|e| anyhow::anyhow!("Registration failed: {}", e))?;
        }

        info!("Bonding curve token deployed: {} ({}) - id={}", 
            deploy_req.name, deploy_req.symbol, hex::encode(&token_id[..8]));

        create_json_response(json!({
            "success": true,
            "token_id": hex::encode(token_id),
            "name": deploy_req.name,
            "symbol": deploy_req.symbol,
            "phase": "curve",
            "tx_status": "confirmed"
        }))
    }

    /// POST /api/v1/curve/buy - Buy tokens from curve
    async fn handle_buy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let buy_req: BuyTokensRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&buy_req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let buyer = self.get_requester_key(&request)?;
        let block_height = self.get_current_block().await?;
        let timestamp = self.get_current_timestamp().await?;

        let mut blockchain = self.blockchain.write().await;
        
        let token = blockchain.bonding_curve_registry.get_mut(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // Execute buy (contract enforces phase == Curve)
        let (token_amount, _event) = token.buy(
            buyer,
            buy_req.stable_amount,
            block_height,
            timestamp,
        ).map_err(|e| anyhow::anyhow!("Buy failed: {}", e))?;

        drop(blockchain);

        create_json_response(json!({
            "success": true,
            "token_id": buy_req.token_id,
            "stable_paid": buy_req.stable_amount,
            "tokens_received": token_amount,
            "tx_status": "confirmed"
        }))
    }

    /// POST /api/v1/curve/sell - Sell tokens back to curve
    async fn handle_sell(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let sell_req: SellTokensRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&sell_req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let seller = self.get_requester_key(&request)?;
        let block_height = self.get_current_block().await?;
        let timestamp = self.get_current_timestamp().await?;

        let mut blockchain = self.blockchain.write().await;
        
        let token = blockchain.bonding_curve_registry.get_mut(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // Execute sell (contract enforces phase == Curve and sell_enabled)
        let (stable_amount, _event) = token.sell(
            seller,
            sell_req.token_amount,
            block_height,
            timestamp,
        ).map_err(|e| anyhow::anyhow!("Sell failed: {}", e))?;

        drop(blockchain);

        create_json_response(json!({
            "success": true,
            "token_id": sell_req.token_id,
            "tokens_sold": sell_req.token_amount,
            "stable_received": stable_amount,
            "tx_status": "confirmed"
        }))
    }

    /// GET /api/v1/curve/{id} - Get curve token info
    async fn handle_get_token(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let timestamp = self.get_current_timestamp().await?;
        let stats = token.get_stats(timestamp);

        let response = CurveTokenInfoResponse {
            token_id: token_id_hex.to_string(),
            name: token.name.clone(),
            symbol: token.symbol.clone(),
            decimals: token.decimals,
            phase: token.phase.to_string(),
            total_supply: token.total_supply,
            reserve_balance: token.reserve_balance,
            current_price: token.current_price(),
            curve_type: token.curve_type.name().to_string(),
            sell_enabled: token.sell_enabled,
            can_graduate: stats.can_graduate,
            graduation_progress_percent: stats.graduation_progress_percent,
            creator: hex::encode(&token.creator.key_id[..8]),
            deployed_at: token.deployed_at_timestamp,
        };

        create_json_response(serde_json::to_value(response)?)
    }

    /// GET /api/v1/curve/{id}/stats - Get detailed curve statistics
    async fn handle_get_stats(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let timestamp = self.get_current_timestamp().await?;
        let stats = token.get_stats(timestamp);

        create_json_response(json!({
            "token_id": token_id_hex,
            "phase": token.phase.to_string(),
            "total_supply": stats.total_supply,
            "reserve_balance": stats.reserve_balance,
            "current_price": stats.current_price,
            "elapsed_seconds": stats.elapsed_seconds,
            "graduation_progress_percent": stats.graduation_progress_percent,
            "can_graduate": stats.can_graduate,
            "threshold_description": token.threshold.description(),
        }))
    }

    /// GET /api/v1/curve/list - List all curve tokens
    async fn handle_list(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        let registry = &blockchain.bonding_curve_registry;

        let tokens: Vec<serde_json::Value> = registry.get_all()
            .iter()
            .map(|t| {
                json!({
                    "token_id": hex::encode(t.token_id),
                    "name": t.name,
                    "symbol": t.symbol,
                    "phase": t.phase.to_string(),
                    "total_supply": t.total_supply,
                    "current_price": t.current_price(),
                })
            })
            .collect();

        let stats = registry.stats();

        create_json_response(json!({
            "tokens": tokens,
            "count": tokens.len(),
            "stats": {
                "total_deployed": stats.total_deployed,
                "in_curve_phase": stats.in_curve_phase,
                "graduated_pending_amm": stats.graduated_pending_amm,
                "active_in_amm": stats.active_in_amm,
            }
        }))
    }

    /// GET /api/v1/curve/list/{phase} - List tokens by phase
    async fn handle_list_by_phase(&self, phase_str: &str) -> Result<ZhtpResponse> {
        let phase = match phase_str {
            "curve" => Phase::Curve,
            "graduated" => Phase::Graduated,
            "amm" => Phase::AMM,
            _ => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Invalid phase. Use: curve, graduated, amm".to_string(),
                ));
            }
        };

        let blockchain = self.blockchain.read().await;
        let registry = &blockchain.bonding_curve_registry;

        let tokens: Vec<serde_json::Value> = registry.get_by_phase(phase)
            .iter()
            .map(|t| {
                json!({
                    "token_id": hex::encode(t.token_id),
                    "name": t.name,
                    "symbol": t.symbol,
                    "total_supply": t.total_supply,
                    "current_price": t.current_price(),
                })
            })
            .collect();

        create_json_response(json!({
            "phase": phase_str,
            "tokens": tokens,
            "count": tokens.len(),
        }))
    }

    /// GET /api/v1/curve/ready-to-graduate - List tokens that can graduate
    async fn handle_ready_to_graduate(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        let registry = &blockchain.bonding_curve_registry;
        let timestamp = self.get_current_timestamp().await?;

        let tokens: Vec<serde_json::Value> = registry.get_ready_to_graduate(timestamp)
            .iter()
            .map(|t| {
                json!({
                    "token_id": hex::encode(t.token_id),
                    "name": t.name,
                    "symbol": t.symbol,
                    "reserve_balance": t.reserve_balance,
                    "total_supply": t.total_supply,
                })
            })
            .collect();

        create_json_response(json!({
            "tokens": tokens,
            "count": tokens.len(),
        }))
    }

    // Helper methods
    fn get_requester_key(&self, request: &ZhtpRequest) -> Result<PublicKey> {
        match &request.requester {
            Some(hash) => {
                let bytes = hash.as_bytes();
                let mut key_id = [0u8; 32];
                key_id.copy_from_slice(bytes);
                Ok(PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id,
                })
            }
            None => Err(anyhow::anyhow!("Authentication required")),
        }
    }

    fn generate_token_id(&self, name: &str, symbol: &str, creator: &[u8; 32]) -> [u8; 32] {
        use lib_crypto::hash_blake3;
        let input = format!("{}:{}:{}", name, symbol, hex::encode(creator));
        hash_blake3(input.as_bytes())
    }

    async fn get_current_block(&self) -> Result<u64> {
        let blockchain = self.blockchain.read().await;
        Ok(blockchain.height)
    }

    async fn get_current_timestamp(&self) -> Result<u64> {
        use std::time::{SystemTime, UNIX_EPOCH};
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs())
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for CurveHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Curve handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/curve/deploy
            (ZhtpMethod::Post, "/api/v1/curve/deploy") => {
                self.handle_deploy(request).await
            }
            // POST /api/v1/curve/buy
            (ZhtpMethod::Post, "/api/v1/curve/buy") => {
                self.handle_buy(request).await
            }
            // POST /api/v1/curve/sell
            (ZhtpMethod::Post, "/api/v1/curve/sell") => {
                self.handle_sell(request).await
            }
            // GET /api/v1/curve/list
            (ZhtpMethod::Get, "/api/v1/curve/list") => {
                self.handle_list().await
            }
            // GET /api/v1/curve/ready-to-graduate
            (ZhtpMethod::Get, "/api/v1/curve/ready-to-graduate") => {
                self.handle_ready_to_graduate().await
            }
            // GET /api/v1/curve/list/{phase}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/curve/list/") => {
                let phase = path.strip_prefix("/api/v1/curve/list/").unwrap_or("");
                self.handle_list_by_phase(phase).await
            }
            // GET /api/v1/curve/{id}/stats
            (ZhtpMethod::Get, path) if path.ends_with("/stats") => {
                let prefix = "/api/v1/curve/";
                let suffix = "/stats";
                let token_id = path.strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(suffix))
                    .unwrap_or("");
                self.handle_get_stats(token_id).await
            }
            // GET /api/v1/curve/{id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/curve/") => {
                let token_id = path.strip_prefix("/api/v1/curve/").unwrap_or("");
                self.handle_get_token(token_id).await
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    format!("Curve endpoint not found: {} {}", request.method, request.uri)
                ))
            }
        };

        response.map_err(|e| {
            warn!("Curve handler error: {}", e);
            anyhow::anyhow!("Curve handler error: {}", e)
        })
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/curve")
    }
}

impl Default for CurveHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SwapHandler - AMM Operations (Post-Graduation)
// ============================================================================

/// AMM swap and liquidity handler
///
/// Handles: swaps, add/remove liquidity
/// Only works with tokens in AMM phase
pub struct SwapHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl SwapHandler {
    pub fn new() -> Self {
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });

        Self { blockchain }
    }

    /// POST /api/v1/swap - Execute AMM swap
    async fn handle_swap(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let swap_req: SwapRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&swap_req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        // Verify token is in AMM phase
        if !token.phase.is_amm_active() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in AMM phase (current: {})", token.phase),
            ));
        }

        // Verify pool ID matches
        match token.amm_pool_id {
            Some(expected) => {
                let provided = hex::decode(&swap_req.pool_id)
                    .map_err(|_| anyhow::anyhow!("Invalid pool_id hex"))?;
                let provided: [u8; 32] = provided.try_into()
                    .map_err(|_| anyhow::anyhow!("Pool ID must be 32 bytes"))?;
                if expected != provided {
                    return Ok(create_error_response(
                        ZhtpStatus::BadRequest,
                        "Pool ID mismatch".to_string(),
                    ));
                }
            }
            None => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    "Token has no AMM pool".to_string(),
                ));
            }
        }

        // Get the AMM pool for real quote
        let pool_id = token.amm_pool_id.unwrap();
        let pool = blockchain.amm_pools.get(&pool_id)
            .ok_or_else(|| anyhow::anyhow!("AMM pool not found in storage"))?;
        
        // Get quote from actual AMM pool (read-only, doesn't modify state)
        // Convert min_amount_out: 0 means no slippage protection
        let min_out = if swap_req.min_amount_out > 0 {
            Some(swap_req.min_amount_out)
        } else {
            None
        };
        
        let (amount_out, price_impact_bps) = if swap_req.token_to_sov {
            // Token -> SOV
            let result = pool.simulate_token_to_sov(swap_req.amount_in, min_out)?;
            (result.amount_out, result.price_impact_bps)
        } else {
            // SOV -> Token
            let result = pool.simulate_sov_to_token(swap_req.amount_in, min_out)?;
            (result.amount_out, result.price_impact_bps)
        };

        drop(blockchain);

        info!("Swap quote: token={}, amount_in={}, amount_out={}, token_to_sov={}",
            swap_req.token_id, swap_req.amount_in, amount_out, swap_req.token_to_sov);

        create_json_response(json!({
            "success": true,
            "token_id": swap_req.token_id,
            "pool_id": swap_req.pool_id,
            "amount_in": swap_req.amount_in,
            "amount_out": amount_out,
            "min_amount_out": swap_req.min_amount_out,
            "price_impact_bps": price_impact_bps,
            "tx_status": "ready_for_execution"
        }))
    }

    /// POST /api/v1/swap/liquidity/add - Add liquidity to AMM pool
    async fn handle_add_liquidity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: AddLiquidityRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        if !token.phase.is_amm_active() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in AMM phase (current: {})", token.phase),
            ));
        }

        drop(blockchain);

        // Mock LP calculation (simplified sqrt approximation)
        let product = req.token_amount as u128 * req.sov_amount as u128;
        let lp_tokens = integer_sqrt(product) as u64;

        info!("Add liquidity: token={}, token_amount={}, sov_amount={}, lp={}",
            req.token_id, req.token_amount, req.sov_amount, lp_tokens);

        create_json_response(json!({
            "success": true,
            "token_id": req.token_id,
            "pool_id": req.pool_id,
            "token_amount": req.token_amount,
            "sov_amount": req.sov_amount,
            "lp_tokens_minted": lp_tokens,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/swap/liquidity/remove - Remove liquidity from AMM pool
    async fn handle_remove_liquidity(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: RemoveLiquidityRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let token_id = hex::decode(&req.token_id)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        if !token.phase.is_amm_active() {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in AMM phase (current: {})", token.phase),
            ));
        }

        drop(blockchain);

        // Mock amounts (would calculate from LP tokens in production)
        let token_amount = req.lp_amount * 2;
        let sov_amount = req.lp_amount * 3;

        info!("Remove liquidity: token={}, lp_burned={}, token_out={}, sov_out={}",
            req.token_id, req.lp_amount, token_amount, sov_amount);

        create_json_response(json!({
            "success": true,
            "token_id": req.token_id,
            "pool_id": req.pool_id,
            "lp_tokens_burned": req.lp_amount,
            "token_amount_received": token_amount,
            "sov_amount_received": sov_amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// GET /api/v1/swap/pools/{token_id} - Get pool info for a token
    async fn handle_get_pool(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;
        
        let token = blockchain.bonding_curve_registry.get(&token_id)
            .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

        let pool_info = match token.amm_pool_id {
            Some(pool_id) => {
                // Get real pool data from storage
                match blockchain.amm_pools.get(&pool_id) {
                    Some(pool) => {
                        let state = pool.state();
                        json!({
                            "exists": true,
                            "pool_id": hex::encode(pool_id),
                            "token_id": token_id_hex,
                            "token_symbol": token.symbol,
                            "phase": token.phase.to_string(),
                            "total_liquidity_token": state.token_reserve,
                            "total_liquidity_sov": state.sov_reserve,
                            "lp_token_supply": 0, // LP tracking not yet implemented
                            "fee_bps": state.fee_bps,
                            "k": state.k.to_string(),
                            "initialized": state.initialized,
                        })
                    }
                    None => {
                        json!({
                            "exists": false,
                            "pool_id": hex::encode(pool_id),
                            "token_id": token_id_hex,
                            "phase": token.phase.to_string(),
                            "message": "Pool ID registered but pool data not found in storage",
                        })
                    }
                }
            }
            None => {
                json!({
                    "exists": false,
                    "token_id": token_id_hex,
                    "phase": token.phase.to_string(),
                    "message": "Token has not migrated to AMM yet",
                })
            }
        };

        create_json_response(pool_info)
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for SwapHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Swap handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/swap
            (ZhtpMethod::Post, "/api/v1/swap") => {
                self.handle_swap(request).await
            }
            // POST /api/v1/swap/liquidity/add
            (ZhtpMethod::Post, "/api/v1/swap/liquidity/add") => {
                self.handle_add_liquidity(request).await
            }
            // POST /api/v1/swap/liquidity/remove
            (ZhtpMethod::Post, "/api/v1/swap/liquidity/remove") => {
                self.handle_remove_liquidity(request).await
            }
            // GET /api/v1/swap/pools/{token_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/swap/pools/") => {
                let token_id = path.strip_prefix("/api/v1/swap/pools/").unwrap_or("");
                self.handle_get_pool(token_id).await
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    format!("Swap endpoint not found: {} {}", request.method, request.uri)
                ))
            }
        };

        response.map_err(|e| {
            warn!("Swap handler error: {}", e);
            anyhow::anyhow!("Swap handler error: {}", e)
        })
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/swap")
    }
}

impl Default for SwapHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ValuationHandler - Read-Only Price Aggregation
// ============================================================================

/// Valuation handler - read-only price queries
///
/// Provides unified price endpoint with confidence levels
/// No state mutation, pure aggregation
pub struct ValuationHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl ValuationHandler {
    pub fn new() -> Self {
        let blockchain = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::runtime::blockchain_provider::get_global_blockchain()
                    .await
                    .expect("Global blockchain must be initialized")
            })
        });

        Self { blockchain }
    }

    /// GET /api/v1/price/{token_id}?type=spot|twap
    /// 
    /// Returns price with source and confidence level
    /// Default type is twap (safer)
    async fn handle_price(&self, token_id_hex: &str, _query: &str) -> Result<ZhtpResponse> {
        // For now, default to twap. Full query parsing can be added later.
        let price_type = "twap";

        // SOV special case
        if token_id_hex == "sov" || token_id_hex == "SOV" {
            return self.get_sov_price(&price_type).await;
        }

        // Regular token
        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        // Try bonding curve first
        if let Some(token) = blockchain.bonding_curve_registry.get(&token_id) {
            let valuation = self.get_curve_valuation(token, price_type)?;
            return create_json_response(json!({
                "token_id": token_id_hex,
                "price_usd_cents": valuation.price_usd_cents,
                "source": valuation.source.name(),
                "confidence_level": valuation.confidence.name(),
                "phase": token.phase.to_string(),
            }));
        }

        // Try regular token
        if let Some(token) = blockchain.get_token_contract(&token_id) {
            // Regular tokens don't have built-in pricing
            let _ = token;  // Silence unused warning for now
            return create_json_response(json!({
                "token_id": token_id_hex,
                "price_usd_cents": 0,
                "source": "none",
                "confidence_level": "none",
                "message": "No pricing available for this token type",
            }));
        }

        Err(anyhow::anyhow!("Token not found"))
    }

    /// GET /api/v1/valuation/{token_id}
    ///
    /// Full valuation with value calculation
    async fn handle_valuation(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        if token_id_hex == "sov" || token_id_hex == "SOV" {
            return self.get_sov_valuation().await;
        }

        let token_id = hex::decode(token_id_hex)
            .map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id.try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        if let Some(token) = blockchain.bonding_curve_registry.get(&token_id) {
            let price = token.current_price();
            let (source, confidence) = match token.phase {
                Phase::Curve => (PriceSource::BondingCurve, ConfidenceLevel::DeterministicCurve),
                Phase::AMM => (PriceSource::AMM_TWAP, ConfidenceLevel::TwapLiquiditySufficient),
                _ => (PriceSource::BondingCurve, ConfidenceLevel::DeterministicCurve),
            };

            return create_json_response(json!({
                "token_id": token_id_hex,
                "name": token.name,
                "symbol": token.symbol,
                "price_usd_cents": price,
                "total_supply": token.total_supply,
                "market_cap_usd_cents": (token.total_supply as u128 * price as u128 / 100_000_000) as u64,
                "source": source.name(),
                "confidence_level": confidence.name(),
                "phase": token.phase.to_string(),
            }));
        }

        Err(anyhow::anyhow!("Token not found"))
    }

    /// GET /api/v1/valuation/batch
    ///
    /// Batch valuation for multiple tokens
    async fn handle_batch_valuation(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        #[derive(Deserialize)]
        struct BatchRequest {
            token_ids: Vec<String>,
        }

        let req: BatchRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        let blockchain = self.blockchain.read().await;
        let mut valuations = Vec::new();

        for token_id_hex in req.token_ids {
            let valuation = if token_id_hex == "sov" || token_id_hex == "SOV" {
                let srv = self.get_srv_from_treasury().await;
                json!({
                    "token_id": "sov",
                    "price_usd_cents": srv,
                    "source": "srv",
                    "confidence_level": "deterministic_curve",
                })
            } else if let Ok(token_id) = hex::decode(&token_id_hex) {
                if let Ok(arr) = token_id.try_into() as Result<[u8; 32], _> {
                    if let Some(token) = blockchain.bonding_curve_registry.get(&arr) {
                        let price = token.current_price();
                        json!({
                            "token_id": token_id_hex,
                            "price_usd_cents": price,
                            "source": "bonding_curve",
                            "confidence_level": "deterministic_curve",
                            "phase": token.phase.to_string(),
                        })
                    } else {
                        json!({
                            "token_id": token_id_hex,
                            "error": "Token not found",
                        })
                    }
                } else {
                    json!({
                        "token_id": token_id_hex,
                        "error": "Invalid token ID",
                    })
                }
            } else {
                json!({
                    "token_id": token_id_hex,
                    "error": "Invalid hex",
                })
            };
            valuations.push(valuation);
        }

        create_json_response(json!({
            "valuations": valuations,
            "count": valuations.len(),
        }))
    }

    // Helper methods
    async fn get_sov_price(&self, price_type: &str) -> Result<ZhtpResponse> {
        // Query Treasury Kernel for SRV
        let srv = self.get_srv_from_treasury().await;

        create_json_response(json!({
            "token_id": "sov",
            "price_usd_cents": srv,
            "source": "srv",
            "confidence_level": "deterministic_curve",
            "price_type_requested": price_type,
        }))
    }

    async fn get_sov_valuation(&self) -> Result<ZhtpResponse> {
        let srv = self.get_srv_from_treasury().await;
        
        // Get supply from Treasury Kernel
        let blockchain = self.blockchain.read().await;
        let supply = self.get_circulating_supply_from_treasury(&blockchain).await;
        drop(blockchain);

        create_json_response(json!({
            "token_id": "sov",
            "name": "Sovereign",
            "symbol": "SOV",
            "price_usd_cents": srv,
            "circulating_supply": supply,
            "market_cap_usd_cents": (supply as u128 * srv as u128 / 100_000_000) as u64,
            "source": "srv",
            "confidence_level": "deterministic_curve",
            "phase": "sov",
        }))
    }

    /// Get SRV from Treasury Kernel
    /// Returns SRV in cents (8 decimal precision stored, converted to cents for API)
    async fn get_srv_from_treasury(&self) -> u64 {
        let blockchain = self.blockchain.read().await;
        
        if let Some(kernel) = blockchain.treasury_kernel.as_ref() {
            // SRV is stored with 8 decimals, convert to cents (2 decimals)
            // SRVState.current_srv has 8 decimal precision
            let srv_8dec = kernel.srv_state().current_srv;
            // Convert: value * 100 / 100_000_000 = value / 1_000_000
            srv_8dec / 1_000_000
        } else {
            // Fallback to genesis SRV if kernel not initialized
            2180000u64 // $0.0218
        }
    }

    /// Get circulating supply from Treasury Kernel
    async fn get_circulating_supply_from_treasury(&self, blockchain: &Blockchain) -> u64 {
        if let Some(kernel) = blockchain.treasury_kernel.as_ref() {
            kernel.srv_state().circulating_supply_sov
        } else {
            // Fallback to genesis supply
            50_000_000_000_000_000u64 // 50M SOV with 8 decimals
        }
    }

    fn get_curve_valuation(&self, token: &BondingCurveToken, price_type: &str) -> Result<Valuation> {
        match token.phase {
            Phase::Curve => {
                // Curve phase: always use curve pricing
                Ok(Valuation {
                    price_usd_cents: token.current_price(),
                    value_usd_cents: 0,
                    source: PriceSource::BondingCurve,
                    confidence: ConfidenceLevel::DeterministicCurve,
                })
            }
            Phase::AMM => {
                // AMM phase: use requested type (default twap)
                let source = if price_type == "spot" {
                    PriceSource::AMM_Spot
                } else {
                    PriceSource::AMM_TWAP
                };
                let confidence = if price_type == "spot" {
                    ConfidenceLevel::TwapLowLiquidity // Spot is less reliable
                } else {
                    ConfidenceLevel::TwapLiquiditySufficient
                };
                
                // In production, query actual AMM
                Ok(Valuation {
                    price_usd_cents: token.current_price(), // Mock: would be AMM price
                    value_usd_cents: 0,
                    source,
                    confidence,
                })
            }
            Phase::Graduated => {
                Ok(Valuation {
                    price_usd_cents: 0,
                    value_usd_cents: 0,
                    source: PriceSource::BondingCurve,
                    confidence: ConfidenceLevel::None,
                })
            }
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ValuationHandler {
    async fn handle_request(&self, request: ZhtpRequest) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Valuation handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // GET /api/v1/valuation/batch
            (ZhtpMethod::Post, "/api/v1/valuation/batch") => {
                self.handle_batch_valuation(request).await
            }
            // GET /api/v1/valuation/{token_id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/valuation/") => {
                let token_id = path.strip_prefix("/api/v1/valuation/").unwrap_or("");
                self.handle_valuation(token_id).await
            }
            // GET /api/v1/price/{token_id} (with optional query params)
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/price/") => {
                let rest = path.strip_prefix("/api/v1/price/").unwrap_or("");
                let parts: Vec<&str> = rest.split('?').collect();
                let token_id = parts[0];
                let query = parts.get(1).unwrap_or(&"");
                self.handle_price(token_id, query).await
            }
            _ => {
                Ok(create_error_response(
                    ZhtpStatus::NotFound,
                    format!("Valuation endpoint not found: {} {}", request.method, request.uri)
                ))
            }
        };

        response.map_err(|e| {
            warn!("Valuation handler error: {}", e);
            anyhow::anyhow!("Valuation handler error: {}", e)
        })
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/price") || request.uri.starts_with("/api/v1/valuation")
    }
}

impl Default for ValuationHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Integer square root using Newton's method
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::contracts::bonding_curve::{BondingCurveToken, Phase};
    use lib_crypto::Hash;
    use lib_protocols::types::{ZhtpMethod, ZhtpRequest};

    fn test_pubkey(seed: u8) -> PublicKey {
        PublicKey::new(vec![seed; 1312])
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(1000000), 1000);
    }

    #[test]
    fn test_curve_type_conversion() {
        let req = CurveTypeRequest::Linear { base_price: 100, slope: 10 };
        let curve: CurveType = req.into();
        assert_eq!(curve.name(), "linear");
    }

    #[test]
    fn test_threshold_conversion() {
        let req = ThresholdRequest::ReserveAmount { min_reserve: 1_000_000 };
        let threshold: Threshold = req.into();
        assert!(threshold.is_met(1_000_000, 0, 0));
        assert!(!threshold.is_met(999_999, 0, 0));
    }

    #[tokio::test]
    async fn buy_handler_does_not_auto_graduate_token() {
        let mut blockchain = Blockchain::new().expect("blockchain");
        let token_id = [0x33u8; 32];
        let creator = test_pubkey(7);
        let mut token = BondingCurveToken::deploy(
            token_id,
            "Curve Test".to_string(),
            "CTEST".to_string(),
            CurveType::Linear {
                base_price: 100_000_000,
                slope: 1,
            },
            Threshold::ReserveAmount(1),
            true,
            creator,
            0,
            1_700_000_000,
        )
        .expect("deploy token");
        token.reserve_balance = 0;
        blockchain
            .bonding_curve_registry
            .register(token)
            .expect("register token");

        let handler = CurveHandler {
            blockchain: Arc::new(RwLock::new(blockchain)),
        };

        let req_body = serde_json::to_vec(&serde_json::json!({
            "token_id": hex::encode(token_id),
            "stable_amount": 1,
        }))
        .expect("serialize request");

        let request = ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/curve/buy".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::new(),
            body: req_body,
            timestamp: 1_700_000_100,
            requester: Some(Hash::from_bytes(&[9u8; 32])),
            auth_proof: None,
        };

        let response = handler.handle_buy(request).await.expect("buy response");
        let json: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
        assert!(
            json.get("auto_graduated").is_none(),
            "buy response must not expose runtime auto-graduation"
        );

        let guard = handler.blockchain.read().await;
        let stored = guard
            .bonding_curve_registry
            .get(&token_id)
            .expect("stored token");
        assert_eq!(
            stored.phase,
            Phase::Curve,
            "buy path must not mutate phase to graduated/amm"
        );
    }
}
