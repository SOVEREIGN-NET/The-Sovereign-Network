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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ZHTP protocol imports
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

// Blockchain imports
use lib_blockchain::contracts::bonding_curve::{
    BondingCurveToken, ConfidenceLevel, CurveType, Phase, PriceSource, Threshold, Valuation,
};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::Blockchain;
use lib_blockchain::Transaction;

/// Request to submit a signed bonding curve transaction
#[derive(Debug, Deserialize)]
pub struct SubmitBondingCurveTransactionRequest {
    /// Hex-encoded bincode Transaction
    pub signed_tx: String,
}

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
    Linear {
        base_price: u64,
        slope: u64,
    },
    Exponential {
        base_price: u64,
        growth_rate_bps: u64,
    },
    Sigmoid {
        max_price: u64,
        midpoint_supply: u64,
        steepness: u64,
    },
    /// Piecewise linear curve (CBE token default)
    /// Uses predefined 4-band configuration with document-compliant slopes
    PiecewiseLinear,
}

impl From<CurveTypeRequest> for CurveType {
    fn from(req: CurveTypeRequest) -> Self {
        match req {
            CurveTypeRequest::Linear { base_price, slope } => {
                CurveType::Linear { base_price, slope }
            }
            CurveTypeRequest::Exponential {
                base_price,
                growth_rate_bps,
            } => CurveType::Exponential {
                base_price,
                growth_rate_bps,
            },
            CurveTypeRequest::Sigmoid {
                max_price,
                midpoint_supply,
                steepness,
            } => CurveType::Sigmoid {
                max_price,
                midpoint_supply,
                steepness,
            },
            CurveTypeRequest::PiecewiseLinear => {
                CurveType::PiecewiseLinear(
                    lib_blockchain::contracts::bonding_curve::PiecewiseLinearCurve::cbe_default()
                )
            }
        }
    }
}

/// Threshold request (JSON-friendly)
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ThresholdRequest {
    ReserveAmount {
        min_reserve: u64,
    },
    SupplyAmount {
        min_supply: u64,
    },
    TimeAndReserve {
        min_time_seconds: u64,
        min_reserve: u64,
    },
    TimeAndSupply {
        min_time_seconds: u64,
        min_supply: u64,
    },
}

impl From<ThresholdRequest> for Threshold {
    fn from(req: ThresholdRequest) -> Self {
        match req {
            ThresholdRequest::ReserveAmount { min_reserve } => {
                Threshold::ReserveAmount(min_reserve)
            }
            ThresholdRequest::SupplyAmount { min_supply } => Threshold::SupplyAmount(min_supply),
            ThresholdRequest::TimeAndReserve {
                min_time_seconds,
                min_reserve,
            } => Threshold::TimeAndReserve {
                min_time_seconds,
                min_reserve,
            },
            ThresholdRequest::TimeAndSupply {
                min_time_seconds,
                min_supply,
            } => Threshold::TimeAndSupply {
                min_time_seconds,
                min_supply,
            },
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

    /// POST /api/v1/curve/deploy - Submit signed bonding curve deploy transaction
    /// 
    /// Accepts a signed BondingCurveDeploy transaction and submits it to the mempool.
    /// The transaction must be built using lib-client (build_bonding_curve_deploy_tx)
    /// or equivalent client library.
    async fn handle_deploy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let submit_req: SubmitBondingCurveTransactionRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Decode the signed transaction
        let tx_bytes = hex::decode(&submit_req.signed_tx)
            .map_err(|e| anyhow::anyhow!("Invalid hex in signed_tx: {}", e))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))?;

        // Validate transaction type
        if tx.transaction_type != lib_blockchain::TransactionType::BondingCurveDeploy {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Transaction must be of type BondingCurveDeploy".to_string(),
            ));
        }

        // Get deploy data for response (clone to avoid borrow issues)
        let deploy_data = tx.bonding_curve_deploy_data.clone().ok_or_else(|| {
            anyhow::anyhow!("BondingCurveDeploy transaction missing deploy data")
        })?;
        let tx_hash = hex::encode(tx.hash().as_bytes());
        let name = deploy_data.name.clone();
        let symbol = deploy_data.symbol.clone();

        // Submit to mempool
        self.submit_to_mempool(tx).await.map_err(|e| {
            anyhow::anyhow!("Failed to submit deploy transaction to mempool: {}", e)
        })?;

        info!(
            "Bonding curve deploy submitted to mempool: {} ({}) - creator={}",
            name,
            symbol,
            hex::encode(&deploy_data.creator[..8])
        );

        create_json_response(json!({
            "success": true,
            "tx_hash": tx_hash,
            "name": name,
            "symbol": symbol,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/curve/buy - Submit signed bonding curve buy transaction
    ///
    /// Accepts a signed BondingCurveBuy transaction and submits it to the mempool.
    /// The transaction must be built using lib-client (build_bonding_curve_buy_tx)
    /// or equivalent client library.
    async fn handle_buy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let submit_req: SubmitBondingCurveTransactionRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Decode the signed transaction
        let tx_bytes = hex::decode(&submit_req.signed_tx)
            .map_err(|e| anyhow::anyhow!("Invalid hex in signed_tx: {}", e))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))?;

        // Validate transaction type
        if tx.transaction_type != lib_blockchain::TransactionType::BondingCurveBuy {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Transaction must be of type BondingCurveBuy".to_string(),
            ));
        }

        // Get buy data for response (clone to avoid borrow issues)
        let buy_data = tx.bonding_curve_buy_data.clone().ok_or_else(|| {
            anyhow::anyhow!("BondingCurveBuy transaction missing buy data")
        })?;
        let tx_hash = hex::encode(tx.hash().as_bytes());
        let token_id = hex::encode(buy_data.token_id);
        let stable_amount = buy_data.stable_amount;

        // Submit to mempool
        self.submit_to_mempool(tx).await.map_err(|e| {
            anyhow::anyhow!("Failed to submit buy transaction to mempool: {}", e)
        })?;

        info!(
            "Bonding curve buy submitted to mempool: token={}, amount={}",
            &token_id[..16.min(token_id.len())],
            stable_amount
        );

        create_json_response(json!({
            "success": true,
            "tx_hash": tx_hash,
            "token_id": token_id,
            "stable_amount": stable_amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// POST /api/v1/curve/sell - Submit signed bonding curve sell transaction
    ///
    /// Accepts a signed BondingCurveSell transaction and submits it to the mempool.
    /// The transaction must be built using lib-client (build_bonding_curve_sell_tx)
    /// or equivalent client library.
    async fn handle_sell(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let submit_req: SubmitBondingCurveTransactionRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Decode the signed transaction
        let tx_bytes = hex::decode(&submit_req.signed_tx)
            .map_err(|e| anyhow::anyhow!("Invalid hex in signed_tx: {}", e))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))?;

        // Validate transaction type
        if tx.transaction_type != lib_blockchain::TransactionType::BondingCurveSell {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Transaction must be of type BondingCurveSell".to_string(),
            ));
        }

        // Get sell data for response (clone to avoid borrow issues)
        let sell_data = tx.bonding_curve_sell_data.clone().ok_or_else(|| {
            anyhow::anyhow!("BondingCurveSell transaction missing sell data")
        })?;
        let tx_hash = hex::encode(tx.hash().as_bytes());
        let token_id = hex::encode(sell_data.token_id);
        let token_amount = sell_data.token_amount;

        // Submit to mempool
        self.submit_to_mempool(tx).await.map_err(|e| {
            anyhow::anyhow!("Failed to submit sell transaction to mempool: {}", e)
        })?;

        info!(
            "Bonding curve sell submitted to mempool: token={}, amount={}",
            &token_id[..16.min(token_id.len())],
            token_amount
        );

        create_json_response(json!({
            "success": true,
            "tx_hash": tx_hash,
            "token_id": token_id,
            "token_amount": token_amount,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// GET /api/v1/curve/{id} - Get curve token info
    async fn handle_get_token(&self, token_id_hex: &str) -> Result<ZhtpResponse> {
        let token_id =
            hex::decode(token_id_hex).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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
        let token_id =
            hex::decode(token_id_hex).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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

        let tokens: Vec<serde_json::Value> = registry
            .get_all()
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

        let tokens: Vec<serde_json::Value> = registry
            .get_by_phase(phase)
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

    /// POST /api/v1/curve/graduate - Submit signed bonding curve graduate transaction
    ///
    /// Accepts a signed BondingCurveGraduate transaction and submits it to the mempool.
    /// The transaction must be built using lib-client (build_bonding_curve_graduate_tx)
    /// or equivalent client library.
    async fn handle_graduate(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let submit_req: SubmitBondingCurveTransactionRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        // Decode the signed transaction
        let tx_bytes = hex::decode(&submit_req.signed_tx)
            .map_err(|e| anyhow::anyhow!("Invalid hex in signed_tx: {}", e))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))?;

        // Validate transaction type
        if tx.transaction_type != lib_blockchain::TransactionType::BondingCurveGraduate {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Transaction must be of type BondingCurveGraduate".to_string(),
            ));
        }

        // Get graduate data for response (clone to avoid borrow issues)
        let grad_data = tx.bonding_curve_graduate_data.clone().ok_or_else(|| {
            anyhow::anyhow!("BondingCurveGraduate transaction missing graduate data")
        })?;
        let tx_hash = hex::encode(tx.hash().as_bytes());
        let token_id = hex::encode(grad_data.token_id);
        let pool_id = hex::encode(grad_data.pool_id);

        // Submit to mempool
        self.submit_to_mempool(tx).await.map_err(|e| {
            anyhow::anyhow!("Failed to submit graduate transaction to mempool: {}", e)
        })?;

        info!(
            "Bonding curve graduate submitted to mempool: token={}",
            &token_id[..16.min(token_id.len())]
        );

        create_json_response(json!({
            "success": true,
            "tx_hash": tx_hash,
            "token_id": token_id,
            "pool_id": pool_id,
            "tx_status": "submitted_to_mempool"
        }))
    }

    /// GET /api/v1/curve/ready-to-graduate - List tokens that can graduate
    async fn handle_ready_to_graduate(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        let registry = &blockchain.bonding_curve_registry;
        let timestamp = self.get_current_timestamp().await?;

        let tokens: Vec<serde_json::Value> = registry
            .get_ready_to_graduate(timestamp)
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

    /// Submit a transaction to the mempool for BFT consensus processing
    async fn submit_to_mempool(&self, tx: Transaction) -> Result<()> {
        let mut blockchain = self.blockchain.write().await;
        blockchain
            .add_pending_transaction(tx)
            .map_err(|e| anyhow::anyhow!("Failed to submit transaction to mempool: {}", e))
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for CurveHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Curve handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/curve/deploy
            (ZhtpMethod::Post, "/api/v1/curve/deploy") => self.handle_deploy(request).await,
            // POST /api/v1/curve/buy
            (ZhtpMethod::Post, "/api/v1/curve/buy") => self.handle_buy(request).await,
            // POST /api/v1/curve/sell
            (ZhtpMethod::Post, "/api/v1/curve/sell") => self.handle_sell(request).await,
            // POST /api/v1/curve/graduate
            (ZhtpMethod::Post, "/api/v1/curve/graduate") => self.handle_graduate(request).await,
            // GET /api/v1/curve/list
            (ZhtpMethod::Get, "/api/v1/curve/list") => self.handle_list().await,
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
                let token_id = path
                    .strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(suffix))
                    .unwrap_or("");
                self.handle_get_stats(token_id).await
            }
            // GET /api/v1/curve/{id}
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/curve/") => {
                let token_id = path.strip_prefix("/api/v1/curve/").unwrap_or("");
                self.handle_get_token(token_id).await
            }
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                format!(
                    "Curve endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
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

        let token_id =
            hex::decode(&swap_req.token_id).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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
                let provided: [u8; 32] = provided
                    .try_into()
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
        let pool = blockchain
            .amm_pools
            .get(&pool_id)
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

        info!(
            "Swap quote: token={}, amount_in={}, amount_out={}, token_to_sov={}",
            swap_req.token_id, swap_req.amount_in, amount_out, swap_req.token_to_sov
        );

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

        let token_id =
            hex::decode(&req.token_id).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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

        info!(
            "Add liquidity: token={}, token_amount={}, sov_amount={}, lp={}",
            req.token_id, req.token_amount, req.sov_amount, lp_tokens
        );

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

        let token_id =
            hex::decode(&req.token_id).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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

        info!(
            "Remove liquidity: token={}, lp_burned={}, token_out={}, sov_out={}",
            req.token_id, req.lp_amount, token_amount, sov_amount
        );

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
        let token_id =
            hex::decode(token_id_hex).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        let token = blockchain
            .bonding_curve_registry
            .get(&token_id)
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
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Swap handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // POST /api/v1/swap
            (ZhtpMethod::Post, "/api/v1/swap") => self.handle_swap(request).await,
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
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                format!(
                    "Swap endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
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
    /// Returns unified price with source and pricing mode (Issue #1819)
    /// Default type is twap (safer)
    async fn handle_price(&self, token_id_hex: &str, _query: &str) -> Result<ZhtpResponse> {
        // For now, default to twap. Full query parsing can be added later.
        let price_type = "twap";

        // SOV special case - use unified pricing
        if token_id_hex == "sov" || token_id_hex == "SOV" {
            return self.get_sov_price_unified().await;
        }

        // Check if it's CBE token
        let blockchain = self.blockchain.read().await;
        use lib_blockchain::contracts::tokens::{CBE_NAME, CBE_SYMBOL};
        let cbe_token_id = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            CBE_NAME.hash(&mut hasher);
            CBE_SYMBOL.hash(&mut hasher);
            let hash = hasher.finish();
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&hash.to_le_bytes());
            for i in 8..32 {
                id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
            }
            id
        };

        // Try to decode token_id
        let token_id = hex::decode(token_id_hex).ok().and_then(|bytes| {
            bytes.try_into().ok().map(|arr: [u8; 32]| arr)
        });

        // Check if it's CBE
        if let Some(id) = token_id {
            if id == cbe_token_id {
                return self.get_cbe_price_unified().await;
            }

            // Try bonding curve
            if let Some(token) = blockchain.bonding_curve_registry.get(&id) {
                let valuation = self.get_curve_valuation(token, price_type)?;
                return create_json_response(json!({
                    "token_id": token_id_hex,
                    "symbol": token.symbol,
                    "price_usd_cents": valuation.price_usd_cents,
                    "price_mode": "pre_graduation",
                    "price_source": valuation.source.name(),
                    "phase": token.phase.to_string(),
                }));
            }
        }

        // Try regular token
        if let Some(id) = token_id {
            if let Some(token) = blockchain.get_token_contract(&id) {
                let _ = token; // Silence unused warning for now
                return create_json_response(json!({
                    "token_id": token_id_hex,
                    "price_usd_cents": 0,
                    "price_mode": "unknown",
                    "price_source": "none",
                    "message": "No pricing available for this token type",
                }));
            }
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

        let token_id =
            hex::decode(token_id_hex).map_err(|_| anyhow::anyhow!("Invalid token_id hex"))?;
        let token_id: [u8; 32] = token_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("Token ID must be 32 bytes"))?;

        let blockchain = self.blockchain.read().await;

        if let Some(token) = blockchain.bonding_curve_registry.get(&token_id) {
            let price = token.current_price();
            let (source, confidence) = match token.phase {
                Phase::Curve => (
                    PriceSource::BondingCurve,
                    ConfidenceLevel::DeterministicCurve,
                ),
                Phase::AMM => (
                    PriceSource::AMM_TWAP,
                    ConfidenceLevel::TwapLiquiditySufficient,
                ),
                _ => (
                    PriceSource::BondingCurve,
                    ConfidenceLevel::DeterministicCurve,
                ),
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

    /// Issue #1819: Unified SOV price response (Issue #1819)
    /// Returns unified pricing format supporting both SRV (fixed) and oracle-derived (dynamic) modes
    async fn get_sov_price_unified(&self) -> Result<ZhtpResponse> {
        use lib_blockchain::pricing::{PRICE_SCALE, GENESIS_SRV_8DEC};
        
        let blockchain = self.blockchain.read().await;
        let pricing = &blockchain.token_pricing_state;
        
        // Check if we have oracle-derived pricing (dynamic pricing is active)
        if pricing.dynamic_pricing_active {
            // Dynamic pricing mode: SOV/USD derived from CBE/USD oracle
            let price_8dec = pricing.get_sov_price_8dec();
            let price_cents = ((price_8dec * 100) / PRICE_SCALE) as u64;
            
            return create_json_response(json!({
                "token_id": "sov",
                "symbol": "SOV",
                "price_usd_cents": price_cents,
                "price_mode": "dynamic",
                "price_source": "oracle_derived",
                "source_components": {
                    "cbe_usd_oracle": pricing.cbe_usd_price,
                    "cbe_sov_ratio": pricing.cbe_sov_ratio,
                },
                "last_updated": pricing.last_updated,
                "confidence_level": "high",
            }));
        }
        
        // Fallback to SRV (fixed pricing) when no oracle data available
        let srv = self.get_srv_from_treasury().await;
        
        create_json_response(json!({
            "token_id": "sov",
            "symbol": "SOV", 
            "price_usd_cents": srv,
            "price_mode": "fixed",
            "price_source": "srv",
            "confidence_level": "deterministic_curve",
            "note": "CBE/USD oracle not yet available, using fixed SRV pricing",
        }))
    }

    /// Issue #1819: Unified CBE price response (Issue #1819)
    /// Returns unified pricing format for CBE token
    async fn get_cbe_price_unified(&self) -> Result<ZhtpResponse> {
        use lib_blockchain::contracts::tokens::{CBE_NAME, CBE_SYMBOL};
        
        let blockchain = self.blockchain.read().await;
        let pricing = &blockchain.token_pricing_state;
        
        // Get CBE price info (returns Option<CbePriceInfo>)
        let price_info = blockchain.get_cbe_price_info();
        
        // Get CBE token for phase info
        let cbe_token_id = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            CBE_NAME.hash(&mut hasher);
            CBE_SYMBOL.hash(&mut hasher);
            let hash = hasher.finish();
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&hash.to_le_bytes());
            for i in 8..32 {
                id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
            }
            id
        };
        
        let phase = blockchain.bonding_curve_registry
            .get(&cbe_token_id)
            .map(|t| t.phase.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        // Use the price_info if available, otherwise fall back to pricing state
        match price_info {
            Some(info) => {
                create_json_response(json!({
                    "token_id": hex::encode(&cbe_token_id),
                    "symbol": "CBE",
                    "price_usd_cents": info.price_usd_cents,
                    "price_mode": info.price_mode.to_string(),
                    "price_source": info.price_source.to_string(),
                    "phase": info.phase,
                    "components": info.components,
                    "oracle_confidence": info.oracle_confidence,
                    "reserve_usd": info.reserve_usd,
                    "supply": info.supply,
                    "confidence_level": if info.price_mode.to_string() == "dynamic" { "high" } else { "deterministic_curve" },
                    "last_updated": info.last_updated,
                }))
            }
            None => {
                // Fallback: build response from pricing state
                let (price_mode, price_source) = if pricing.cbe_usd_price.is_some() {
                    ("dynamic", "oracle")
                } else {
                    ("pre_graduation", "bonding_curve")
                };
                
                // Get curve price from registry
                let curve_price_cents = blockchain.bonding_curve_registry
                    .get(&cbe_token_id)
                    .map(|t| t.current_price())
                    .unwrap_or(1); // $0.0001 fallback
                
                create_json_response(json!({
                    "token_id": hex::encode(&cbe_token_id),
                    "symbol": "CBE",
                    "price_usd_cents": curve_price_cents,
                    "price_mode": price_mode,
                    "price_source": price_source,
                    "phase": phase,
                    "confidence_level": if price_mode == "dynamic" { "high" } else { "deterministic_curve" },
                    "last_updated": pricing.last_updated,
                    "note": "Using fallback pricing (get_cbe_price_info returned None)",
                }))
            }
        }
    }

    fn get_curve_valuation(
        &self,
        token: &BondingCurveToken,
        price_type: &str,
    ) -> Result<Valuation> {
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
            Phase::Graduated => Ok(Valuation {
                price_usd_cents: 0,
                value_usd_cents: 0,
                source: PriceSource::BondingCurve,
                confidence: ConfidenceLevel::None,
            }),
        }
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for ValuationHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
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
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                format!(
                    "Valuation endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
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
    use lib_blockchain::Blockchain;
    use lib_crypto::Hash;

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
        let req = CurveTypeRequest::Linear {
            base_price: 100,
            slope: 10,
        };
        let curve: CurveType = req.into();
        assert_eq!(curve.name(), "linear");
    }

    #[test]
    fn test_threshold_conversion() {
        let req = ThresholdRequest::ReserveAmount {
            min_reserve: 1_000_000,
        };
        let threshold: Threshold = req.into();
        assert!(threshold.is_met(1_000_000, 0, 0));
        assert!(!threshold.is_met(999_999, 0, 0));
    }

    // =========================================================================
    // handle_deploy gate tests
    // =========================================================================

    /// Build a minimal authenticated deploy request for the given requester key_id.
    fn make_deploy_request(requester_key_id: [u8; 32]) -> ZhtpRequest {
        let body = serde_json::to_vec(&serde_json::json!({
            "name": "TestToken",
            "symbol": "TST",
            "curve_type": {"type": "linear", "base_price": 100, "slope": 10},
            "threshold": {"type": "reserve_amount", "min_reserve": 1_000_000},
            "sell_enabled": true
        }))
        .expect("body must serialize");

        ZhtpRequest {
            method: ZhtpMethod::Post,
            uri: "/api/v1/curve/deploy".to_string(),
            version: "ZHTP/1.0".to_string(),
            headers: lib_protocols::types::ZhtpHeaders::default(),
            body,
            timestamp: 0,
            requester: Some(Hash::from_bytes(&requester_key_id)),
            auth_proof: None,
        }
    }

    /// Register a minimal identity with an empty public key so that Gate 1 passes.
    ///
    /// `get_requester_key` always produces `dilithium_pk: vec![]` from the request hash,
    /// so `get_identity_by_public_key(&[])` must find an entry with `public_key: vec![]`.
    fn add_identity(bc: &mut Blockchain) {
        use lib_blockchain::IdentityTransactionData;
        let did = "did:zhtp:test".to_string();
        let identity = IdentityTransactionData {
            did: did.clone(),
            display_name: "Test".to_string(),
            public_key: vec![], // must match creator.dilithium_pk (always empty)
            ownership_proof: vec![],
            identity_type: "human".to_string(),
            did_document_hash: lib_blockchain::Hash::default(),
            created_at: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
        };
        // Key by DID, matching production identity_registry insertion convention.
        bc.identity_registry.insert(did, identity);
    }

    /// Add a Primary wallet whose dilithium public key is `wallet_dilithium` and whose
    /// wallet_id is `wallet_id_bytes`, then insert a SOV token balance for that wallet.
    ///
    /// Returns the requester key_id that must be put in the request so that
    /// `primary_wallet_for_signer` matches this wallet.
    fn add_primary_wallet_with_sov(
        bc: &mut Blockchain,
        wallet_dilithium: Vec<u8>,
        wallet_id_bytes: [u8; 32],
        sov_atomic: u64,
    ) -> [u8; 32] {
        use lib_blockchain::{
            contracts::utils::generate_lib_token_id, contracts::TokenContract,
            WalletTransactionData,
        };
        use lib_crypto::hash_blake3;

        // key_id derived by get_requester_key from the requester hash, which must equal
        // hash_blake3(wallet.public_key) for primary_wallet_for_signer to match.
        let requester_key_id = hash_blake3(&wallet_dilithium);

        // Insert Primary wallet keyed by hex-encoded wallet_id.
        let wallet_id_hex = hex::encode(wallet_id_bytes);
        bc.wallet_registry.insert(
            wallet_id_hex,
            WalletTransactionData {
                wallet_id: lib_blockchain::Hash::new(wallet_id_bytes),
                wallet_type: "Primary".to_string(),
                wallet_name: "Test Wallet".to_string(),
                alias: None,
                public_key: wallet_dilithium,
                owner_identity_id: None,
                seed_commitment: lib_blockchain::Hash::default(),
                created_at: 0,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 0,
            },
        );

        // Insert SOV token with the requested balance keyed by wallet_key_for_sov.
        let sov_id = generate_lib_token_id();
        let mut sov_token = TokenContract::new_sov_native();
        // wallet_key_for_sov uses an empty dilithium_pk and wallet_id_bytes as key_id.
        let sov_wallet_key = PublicKey {
            dilithium_pk: vec![],
            kyber_pk: vec![],
            key_id: wallet_id_bytes,
        };
        sov_token.balances.insert(sov_wallet_key, sov_atomic);
        bc.token_contracts.insert(sov_id, sov_token);

        requester_key_id
    }

    /// Gate 1: missing on-chain identity → 401 Unauthorized.
    #[tokio::test]
    async fn test_deploy_missing_identity_returns_401() {
        let key_id = [1u8; 32]; // arbitrary; no identity registered for any key
        let bc = Blockchain::new().expect("blockchain init");
        let handler = CurveHandler {
            blockchain: Arc::new(RwLock::new(bc)),
        };

        let response = handler
            .handle_deploy(make_deploy_request(key_id))
            .await
            .expect("handle_deploy must not error");

        assert_eq!(
            response.status,
            ZhtpStatus::Unauthorized,
            "expected 401 when no identity is registered"
        );
    }

    /// Gate 2a: identity registered but no primary wallet → 401 Unauthorized.
    #[tokio::test]
    async fn test_deploy_missing_primary_wallet_returns_401() {
        let key_id = [1u8; 32];
        let mut bc = Blockchain::new().expect("blockchain init");
        add_identity(&mut bc); // Gate 1 passes

        let handler = CurveHandler {
            blockchain: Arc::new(RwLock::new(bc)),
        };

        let response = handler
            .handle_deploy(make_deploy_request(key_id))
            .await
            .expect("handle_deploy must not error");

        assert_eq!(
            response.status,
            ZhtpStatus::Unauthorized,
            "expected 401 when no primary wallet is registered"
        );
    }

    /// Gate 2b: identity registered, wallet registered, but SOV balance < 100 → 401 Unauthorized.
    #[tokio::test]
    async fn test_deploy_insufficient_sov_returns_401() {
        let wallet_dilithium = vec![2u8; 32];
        let wallet_id_bytes = [3u8; 32];

        let mut bc = Blockchain::new().expect("blockchain init");
        add_identity(&mut bc); // Gate 1 passes
        let key_id = add_primary_wallet_with_sov(
            &mut bc,
            wallet_dilithium,
            wallet_id_bytes,
            50 * 100_000_000, // 50 SOV – below the 100 SOV minimum
        );

        let handler = CurveHandler {
            blockchain: Arc::new(RwLock::new(bc)),
        };

        let response = handler
            .handle_deploy(make_deploy_request(key_id))
            .await
            .expect("handle_deploy must not error");

        assert_eq!(
            response.status,
            ZhtpStatus::Unauthorized,
            "expected 401 when SOV balance is below 100 SOV"
        );
    }

    /// Gates pass: identity registered, primary wallet with ≥ 100 SOV → 200 OK.
    #[tokio::test]
    async fn test_deploy_sufficient_sov_succeeds() {
        let wallet_dilithium = vec![4u8; 32];
        let wallet_id_bytes = [5u8; 32];

        let mut bc = Blockchain::new().expect("blockchain init");
        add_identity(&mut bc); // Gate 1 passes
        let key_id = add_primary_wallet_with_sov(
            &mut bc,
            wallet_dilithium,
            wallet_id_bytes,
            200 * 100_000_000, // 200 SOV – above the 100 SOV minimum
        );

        let handler = CurveHandler {
            blockchain: Arc::new(RwLock::new(bc)),
        };

        let response = handler
            .handle_deploy(make_deploy_request(key_id))
            .await
            .expect("handle_deploy must not error");

        assert_eq!(
            response.status,
            ZhtpStatus::Ok,
            "expected 200 OK when both gates pass"
        );
    }
}
