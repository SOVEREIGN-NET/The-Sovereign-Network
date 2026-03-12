//! Issue #1850: REST API Endpoints for Bonding Curve
//!
//! Base Path: `/api/v1/bonding-curve`
//!
//! ## Endpoints
//!
//! ### State & Price
//! - `GET /state` - Current curve state (supply, reserve, phase)
//! - `GET /price` - Current CBE/SOV price  
//! - `GET /bands` - Supply band configuration
//!
//! ### Quotes
//! - `POST /quote-buy` - Quote CBE for SOV input
//! - `POST /quote-sell` - Quote SOV for CBE input
//!
//! ### Transactions
//! - `POST /buy` - Execute buy transaction
//! - `POST /sell` - Execute sell transaction
//!
//! ### History & AMM
//! - `GET /history` - Transaction history
//! - `GET /amm` - AMM pool state (post-graduation)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

use lib_blockchain::contracts::bonding_curve::{BondingCurveToken, Phase, PiecewiseLinearCurve};
use lib_blockchain::contracts::bonding_curve::token::{RESERVE_SPLIT_NUMERATOR, RESERVE_SPLIT_DENOMINATOR};
use lib_blockchain::integration::crypto_integration::PublicKey;
use lib_blockchain::Blockchain;

use super::{create_error_response, create_json_response};

// ============================================================================
// Request/Response Types
// ============================================================================

/// Quote buy request
#[derive(Debug, Deserialize)]
pub struct QuoteBuyRequest {
    /// Amount of SOV to spend (atomic units)
    pub sov_amount: u64,
}

/// Quote sell request  
#[derive(Debug, Deserialize)]
pub struct QuoteSellRequest {
    /// Amount of CBE tokens to sell (atomic units)
    pub cbe_amount: u64,
}

/// Execute buy request
#[derive(Debug, Deserialize)]
pub struct ExecuteBuyRequest {
    /// Amount of SOV to spend (atomic units)
    pub sov_amount: u64,
    /// Minimum CBE to receive (slippage protection)
    pub min_cbe_out: Option<u64>,
}

/// Execute sell request
#[derive(Debug, Deserialize)]
pub struct ExecuteSellRequest {
    /// Amount of CBE tokens to sell (atomic units)
    pub cbe_amount: u64,
    /// Minimum SOV to receive (slippage protection)
    pub min_sov_out: Option<u64>,
}

/// Quote buy response
#[derive(Debug, Serialize)]
pub struct QuoteBuyResponse {
    pub sov_input: u64,
    pub cbe_output: u64,
    pub to_reserve: u64,
    pub to_treasury: u64,
    pub price: f64,
    pub price_8dec: u64,
}

/// Quote sell response
#[derive(Debug, Serialize)]
pub struct QuoteSellResponse {
    pub cbe_input: u64,
    pub sov_output: u64,
    pub price: f64,
    pub price_8dec: u64,
}

/// Curve state response
#[derive(Debug, Serialize)]
pub struct CurveStateResponse {
    pub token_id: String,
    pub name: String,
    pub symbol: String,
    pub phase: String,
    pub total_supply: u64,
    pub reserve_balance: u64,
    pub treasury_balance: u64,
    pub current_price: f64,
    pub current_price_8dec: u64,
    pub current_band: u32,
}

/// Price response
#[derive(Debug, Serialize)]
pub struct PriceResponse {
    pub cbe_sov_price: f64,
    pub cbe_sov_price_8dec: u64,
    pub current_band: u32,
    pub phase: String,
}

/// Supply band info
#[derive(Debug, Serialize)]
pub struct SupplyBand {
    pub band_number: u32,
    pub min_supply: u64,
    pub max_supply: u64,
    pub base_price: u64,
    pub slope: u64,
}

/// Bands response
#[derive(Debug, Serialize)]
pub struct BandsResponse {
    pub curve_type: String,
    pub bands: Vec<SupplyBand>,
}

/// Transaction history entry
#[derive(Debug, Serialize)]
pub struct TransactionHistoryEntry {
    pub tx_type: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub sov_amount: u64,
    pub cbe_amount: u64,
    pub price: u64,
}

/// History response
#[derive(Debug, Serialize)]
pub struct HistoryResponse {
    pub transactions: Vec<TransactionHistoryEntry>,
    pub total_count: usize,
}

/// AMM pool state response
#[derive(Debug, Serialize)]
pub struct AmmPoolStateResponse {
    pub exists: bool,
    pub pool_id: Option<String>,
    pub phase: String,
    pub sov_reserve: u64,
    pub cbe_reserve: u64,
    pub k: String,
    pub fee_bps: u16,
    pub current_price: f64,
}

// ============================================================================
// BondingCurveApiHandler
// ============================================================================

/// Issue #1850: Bonding Curve REST API Handler
///
/// Handles all `/api/v1/bonding-curve/*` endpoints
pub struct BondingCurveApiHandler {
    blockchain: Arc<RwLock<Blockchain>>,
}

impl BondingCurveApiHandler {
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

    // ========================================================================
    // GET /api/v1/bonding-curve/state
    // ========================================================================

    /// Get current curve state (supply, reserve, phase)
    async fn handle_state(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        // Get CBE token - first one in registry (primary token)
        let cbe_token = self.get_cbe_token(&blockchain).await?;
        
        let current_band = self.get_current_band(cbe_token.total_supply);
        
        let response = CurveStateResponse {
            token_id: hex::encode(cbe_token.token_id),
            name: cbe_token.name.clone(),
            symbol: cbe_token.symbol.clone(),
            phase: cbe_token.phase.to_string(),
            total_supply: cbe_token.total_supply,
            reserve_balance: cbe_token.reserve_balance,
            treasury_balance: cbe_token.treasury_balance,
            current_price: cbe_token.current_price() as f64 / 100_000_000.0,
            current_price_8dec: cbe_token.current_price(),
            current_band,
        };
        
        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // GET /api/v1/bonding-curve/price
    // ========================================================================

    /// Get current CBE/SOV price
    async fn handle_price(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        let cbe_token = self.get_cbe_token(&blockchain).await?;
        let current_band = self.get_current_band(cbe_token.total_supply);
        let price_8dec = cbe_token.current_price();
        
        let response = PriceResponse {
            cbe_sov_price: price_8dec as f64 / 100_000_000.0,
            cbe_sov_price_8dec: price_8dec,
            current_band,
            phase: cbe_token.phase.to_string(),
        };
        
        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // GET /api/v1/bonding-curve/bands
    // ========================================================================

    /// Get supply band configuration
    async fn handle_bands(&self) -> Result<ZhtpResponse> {
        let curve = PiecewiseLinearCurve::cbe_default();
        let bands = curve
            .bands
            .iter()
            .enumerate()
            .map(|(idx, band)| SupplyBand {
                band_number: (idx + 1) as u32,
                min_supply: band.start_supply,
                max_supply: band.end_supply,
                base_price: band.base_offset.max(0) as u64,
                slope: band.slope,
            })
            .collect();

        let response = BandsResponse {
            curve_type: "PiecewiseLinear".to_string(),
            bands,
        };

        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // POST /api/v1/bonding-curve/quote-buy
    // ========================================================================

    /// Quote CBE for SOV input
    async fn handle_quote_buy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: QuoteBuyRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if req.sov_amount == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "sov_amount must be greater than 0".to_string(),
            ));
        }

        let blockchain = self.blockchain.read().await;
        let cbe_token = self.get_cbe_token(&blockchain).await?;

        // Verify token is in Curve phase
        if cbe_token.phase != Phase::Curve {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in Curve phase (current: {:?})", cbe_token.phase),
            ));
        }

        // Calculate 40/60 split (RESERVE_SPLIT_NUMERATOR/DENOMINATOR = 2/5) using u128 to prevent overflow
        let to_reserve = (req.sov_amount as u128 * RESERVE_SPLIT_NUMERATOR as u128 / RESERVE_SPLIT_DENOMINATOR as u128) as u64;
        let to_treasury = req.sov_amount - to_reserve;

        // Calculate CBE output using the contract's integer math
        let cbe_output = match cbe_token.calculate_buy(req.sov_amount) {
            Ok(amount) => amount,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Unable to quote buy: {}", e),
                ));
            }
        };

        let price_8dec = cbe_token.current_price();
        let response = QuoteBuyResponse {
            sov_input: req.sov_amount,
            cbe_output,
            to_reserve,
            to_treasury,
            price: price_8dec as f64 / 100_000_000.0,
            price_8dec,
        };

        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // POST /api/v1/bonding-curve/quote-sell
    // ========================================================================

    /// Quote SOV for CBE input
    async fn handle_quote_sell(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: QuoteSellRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if req.cbe_amount == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "cbe_amount must be greater than 0".to_string(),
            ));
        }

        let blockchain = self.blockchain.read().await;
        let cbe_token = self.get_cbe_token(&blockchain).await?;

        // Verify token is in Curve phase
        if cbe_token.phase != Phase::Curve {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in Curve phase (current: {:?})", cbe_token.phase),
            ));
        }

        // Verify selling is enabled
        if !cbe_token.sell_enabled {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "Selling is not enabled for this token".to_string(),
            ));
        }

        // Calculate SOV output using the contract's integer math (also checks reserve)
        let sov_output = match cbe_token.calculate_sell(req.cbe_amount) {
            Ok(amount) => amount,
            Err(e) => {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Unable to quote sell: {}", e),
                ));
            }
        };

        let price_8dec = cbe_token.current_price();
        let response = QuoteSellResponse {
            cbe_input: req.cbe_amount,
            sov_output,
            price: price_8dec as f64 / 100_000_000.0,
            price_8dec,
        };

        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // POST /api/v1/bonding-curve/buy
    // ========================================================================

    /// Execute buy transaction
    async fn handle_buy(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: ExecuteBuyRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if req.sov_amount == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "sov_amount must be greater than 0".to_string(),
            ));
        }

        let buyer = self.get_requester_key(&request)?;
        let block_height = self.get_current_block().await?;
        let timestamp = self.get_current_timestamp().await?;

        let mut blockchain = self.blockchain.write().await;

        // Get oracle price for graduation check
        let current_epoch = blockchain.oracle_state.epoch_id(timestamp);
        let epoch_duration = blockchain.oracle_state.config.epoch_duration_secs;
        let oracle_price_data = blockchain
            .oracle_state
            .latest_finalized_price_at_or_before(current_epoch)
            .map(|fp| {
                let price_ts = (fp.epoch_id + 1).saturating_mul(epoch_duration);
                (fp.sov_usd_price as u64, price_ts)
            });

        let token_id = self.get_cbe_token_id(&blockchain).await?;
        let token = blockchain
            .bonding_curve_registry
            .get_mut(&token_id)
            .ok_or_else(|| anyhow::anyhow!("CBE token not found"))?;

        // Verify token is in Curve phase
        if token.phase != Phase::Curve {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in Curve phase (current: {:?})", token.phase),
            ));
        }

        // Execute buy
        let (cbe_amount, _event) = token
            .buy(buyer, req.sov_amount, block_height, timestamp)
            .map_err(|e| anyhow::anyhow!("Buy failed: {}", e))?;

        // Enforce slippage protection
        if let Some(min_out) = req.min_cbe_out {
            if cbe_amount < min_out {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Slippage: received {} CBE but minimum is {}", cbe_amount, min_out),
                ));
            }
        }

        // Check graduation with oracle; if ready, graduate immediately
        if let Some((sov_usd_price, price_ts)) = oracle_price_data {
            let can_graduate = token.check_graduation_with_oracle(sov_usd_price, price_ts, block_height, timestamp);
            if can_graduate {
                if let Err(e) = token.graduate(timestamp, block_height) {
                    warn!("Graduation check passed but graduate() failed: {}", e);
                }
            }
        }

        drop(blockchain);

        create_json_response(json!({
            "success": true,
            "sov_spent": req.sov_amount,
            "cbe_received": cbe_amount,
            "tx_status": "confirmed"
        }))
    }

    // ========================================================================
    // POST /api/v1/bonding-curve/sell
    // ========================================================================

    /// Execute sell transaction
    async fn handle_sell(&self, request: ZhtpRequest) -> Result<ZhtpResponse> {
        let req: ExecuteSellRequest = serde_json::from_slice(&request.body)
            .map_err(|e| anyhow::anyhow!("Invalid request: {}", e))?;

        if req.cbe_amount == 0 {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                "cbe_amount must be greater than 0".to_string(),
            ));
        }

        let seller = self.get_requester_key(&request)?;
        let block_height = self.get_current_block().await?;
        let timestamp = self.get_current_timestamp().await?;

        let mut blockchain = self.blockchain.write().await;

        let token_id = self.get_cbe_token_id(&blockchain).await?;
        let token = blockchain
            .bonding_curve_registry
            .get_mut(&token_id)
            .ok_or_else(|| anyhow::anyhow!("CBE token not found"))?;

        // Verify token is in Curve phase
        if token.phase != Phase::Curve {
            return Ok(create_error_response(
                ZhtpStatus::BadRequest,
                format!("Token not in Curve phase (current: {:?})", token.phase),
            ));
        }

        // Execute sell
        let (sov_amount, _event) = token
            .sell(seller, req.cbe_amount, block_height, timestamp)
            .map_err(|e| anyhow::anyhow!("Sell failed: {}", e))?;

        // Enforce slippage protection
        if let Some(min_out) = req.min_sov_out {
            if sov_amount < min_out {
                return Ok(create_error_response(
                    ZhtpStatus::BadRequest,
                    format!("Slippage: received {} SOV but minimum is {}", sov_amount, min_out),
                ));
            }
        }

        drop(blockchain);

        create_json_response(json!({
            "success": true,
            "cbe_sold": req.cbe_amount,
            "sov_received": sov_amount,
            "tx_status": "confirmed"
        }))
    }

    // ========================================================================
    // GET /api/v1/bonding-curve/history
    // ========================================================================

    /// Get transaction history
    async fn handle_history(&self) -> Result<ZhtpResponse> {
        // For now, return empty history (would need event indexing)
        // In production, this would query the event indexer
        let response = HistoryResponse {
            transactions: vec![],
            total_count: 0,
        };
        
        create_json_response(serde_json::to_value(response)?)
    }

    // ========================================================================
    // GET /api/v1/bonding-curve/amm
    // ========================================================================

    /// Get AMM pool state (post-graduation)
    async fn handle_amm(&self) -> Result<ZhtpResponse> {
        let blockchain = self.blockchain.read().await;
        
        let cbe_token = match self.get_cbe_token(&blockchain).await {
            Ok(t) => t,
            Err(_) => {
                return create_json_response(json!({
                    "exists": false,
                    "message": "CBE token not found"
                }))
            }
        };

        match cbe_token.phase {
            Phase::AMM => {
                // Token has graduated to AMM
                if let Some(pool_id) = cbe_token.amm_pool_id {
                    // Get pool from blockchain storage
                    match blockchain.amm_pools.get(&pool_id) {
                        Some(pool) => {
                            let state = pool.state();
                            let price = if state.token_reserve > 0 {
                                state.sov_reserve as f64 / state.token_reserve as f64
                            } else {
                                0.0
                            };
                            
                            let response = AmmPoolStateResponse {
                                exists: true,
                                pool_id: Some(hex::encode(pool_id)),
                                phase: "AMM".to_string(),
                                sov_reserve: state.sov_reserve,
                                cbe_reserve: state.token_reserve,
                                k: state.k.to_string(),
                                fee_bps: state.fee_bps,
                                current_price: price,
                            };
                            create_json_response(serde_json::to_value(response)?)
                        }
                        None => {
                            create_json_response(json!({
                                "exists": false,
                                "phase": "AMM",
                                "message": "Pool ID registered but pool data not found"
                            }))
                        }
                    }
                } else {
                    create_json_response(json!({
                        "exists": false,
                        "phase": "AMM",
                        "message": "AMM pool ID not set"
                    }))
                }
            }
            Phase::Graduated => {
                create_json_response(json!({
                    "exists": false,
                    "phase": "Graduated",
                    "message": "Token graduated but AMM pool not yet created"
                }))
            }
            Phase::Curve => {
                create_json_response(json!({
                    "exists": false,
                    "phase": "Curve",
                    "message": "Token still in bonding curve phase"
                }))
            }
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Get CBE token from registry
    async fn get_cbe_token<'a>(&self, blockchain: &'a Blockchain) -> Result<&'a BondingCurveToken> {
        let cbe_symbol = lib_blockchain::contracts::tokens::CBE_SYMBOL;
        
        blockchain
            .bonding_curve_registry
            .get_all()
            .into_iter()
            .find(|t| t.symbol == cbe_symbol)
            .ok_or_else(|| anyhow::anyhow!("CBE token not found in registry"))
    }

    /// Get CBE token ID
    async fn get_cbe_token_id(&self, blockchain: &Blockchain) -> Result<[u8; 32]> {
        let token = self.get_cbe_token(blockchain).await?;
        Ok(token.token_id)
    }

    /// Get current supply band for CBE
    fn get_current_band(&self, supply: u64) -> u32 {
        let curve = PiecewiseLinearCurve::cbe_default();
        u32::try_from(curve.band_index_for_supply(supply) + 1).unwrap_or(u32::MAX)
    }

    /// Get requester public key from authenticated request
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
impl ZhtpRequestHandler for BondingCurveApiHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        info!("Bonding Curve API handler: {} {}", request.method, request.uri);

        let response = match (request.method.clone(), request.uri.as_str()) {
            // State & Price
            (ZhtpMethod::Get, "/api/v1/bonding-curve/state") => self.handle_state().await,
            (ZhtpMethod::Get, "/api/v1/bonding-curve/price") => self.handle_price().await,
            (ZhtpMethod::Get, "/api/v1/bonding-curve/bands") => self.handle_bands().await,
            
            // Quotes
            (ZhtpMethod::Post, "/api/v1/bonding-curve/quote-buy") => {
                self.handle_quote_buy(request).await
            }
            (ZhtpMethod::Post, "/api/v1/bonding-curve/quote-sell") => {
                self.handle_quote_sell(request).await
            }
            
            // Transactions
            (ZhtpMethod::Post, "/api/v1/bonding-curve/buy") => self.handle_buy(request).await,
            (ZhtpMethod::Post, "/api/v1/bonding-curve/sell") => self.handle_sell(request).await,
            
            // History & AMM
            (ZhtpMethod::Get, "/api/v1/bonding-curve/history") => self.handle_history().await,
            (ZhtpMethod::Get, "/api/v1/bonding-curve/amm") => self.handle_amm().await,
            
            _ => Ok(create_error_response(
                ZhtpStatus::NotFound,
                format!(
                    "Bonding curve API endpoint not found: {} {}",
                    request.method, request.uri
                ),
            )),
        };

        response.map_err(|e| {
            warn!("Bonding curve API handler error: {}", e);
            anyhow::anyhow!("Bonding curve API handler error: {}", e)
        })
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/bonding-curve")
    }
}

impl Default for BondingCurveApiHandler {
    fn default() -> Self {
        Self::new()
    }
}
