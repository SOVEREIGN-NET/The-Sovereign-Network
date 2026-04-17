//! Oracle API Handler
//!
//! ORACLE-R9: Hardened API/Runtime Write Boundaries
//!
//! All state mutations MUST go through governance-gated canonical paths.
//! Direct state mutations via API are disabled in strict spec mode.
//!
//! Read Endpoints (always available):
//!   GET /api/v1/oracle/price              — latest price for SOV/USD or CBE/USD
//!   GET /api/v1/oracle/variation          — variation metrics for SOV/USD or CBE/USD
//!   GET /api/v1/oracle/status             — committee state, epoch, last finalized height
//!   GET /api/v1/oracle/config             — all operating parameters
//!   GET /api/v1/oracle/protocol           — protocol version and activation status
//!   GET /api/v1/oracle/pending-updates    — pending committee/config updates
//!   GET /api/v1/oracle/slashing-events    — last 100 oracle slash events
//!   GET /api/v1/oracle/banned-validators  — currently banned validator key_ids
//!   GET /api/v1/oracle/attestations/{epoch_id} — attestation status for epoch
//!   
//! Governance Path Endpoints (canonical write path):
//!   POST /api/v1/oracle/committee/propose — submit DAO proposal for committee change
//!   POST /api/v1/oracle/config/propose    — submit DAO proposal for config change
//!   POST /api/v1/oracle/updates/cancel    — submit DAO proposal to cancel pending updates
//!
//! Deprecated/Restricted Endpoints:
//!   POST /api/v1/oracle/attest            — DISABLED in strict spec mode
//!                                           Use transaction-based attestation instead

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::oracle::{OracleSlashReason, ORACLE_PRICE_SCALE};
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{debug, warn};

pub struct OracleHandler {
    is_testnet: bool,
}

#[derive(Debug, Clone, Copy)]
enum OraclePair {
    SovUsd,
    CbeUsd,
}

impl OraclePair {
    fn as_str(self) -> &'static str {
        match self {
            OraclePair::SovUsd => "SOV/USD",
            OraclePair::CbeUsd => "CBE/USD",
        }
    }
}

impl OracleHandler {
    pub fn new() -> Self {
        Self {
            is_testnet: std::env::var("ZHTP_NETWORK")
                .map(|v| v == "testnet" || v == "dev")
                .unwrap_or(false),
        }
    }

    async fn get_blockchain(&self) -> Result<Arc<RwLock<lib_blockchain::Blockchain>>> {
        crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to access blockchain: {}", e))
    }

    /// Parse hex string to [u8; 32]
    fn parse_hex_32(&self, value: &str, field_name: &str) -> Result<[u8; 32]> {
        let hex_str = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow::anyhow!("Invalid {} hex: {}", field_name, e))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "{} must be exactly 32 bytes (64 hex chars)",
                field_name
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_query_params(uri: &str) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let query = match uri.split_once('?') {
            Some((_, q)) => q,
            None => return out,
        };
        for kv in query.split('&') {
            if kv.is_empty() {
                continue;
            }
            let (k, v) = match kv.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => (kv.trim(), ""),
            };
            if !k.is_empty() {
                let decoded_k = urlencoding::decode(k)
                    .unwrap_or_else(|_| k.into())
                    .to_ascii_lowercase();
                let decoded_v = urlencoding::decode(v)
                    .unwrap_or_else(|_| v.into())
                    .to_ascii_uppercase();
                out.insert(decoded_k, decoded_v);
            }
        }
        out
    }

    fn parse_pair_from_uri(&self, uri: &str) -> Result<OraclePair> {
        let q = Self::parse_query_params(uri);
        if let Some(pair) = q.get("pair") {
            return match pair.as_str() {
                "SOV/USD" | "SOV_USD" => Ok(OraclePair::SovUsd),
                "CBE/USD" | "CBE_USD" => Ok(OraclePair::CbeUsd),
                _ => Err(anyhow::anyhow!(
                    "Unsupported pair '{}'. Supported: SOV/USD, CBE/USD",
                    pair
                )),
            };
        }

        let base = q.get("base").map(String::as_str).unwrap_or("SOV");
        let quote = q.get("quote").map(String::as_str).unwrap_or("USD");
        match (base, quote) {
            ("SOV", "USD") => Ok(OraclePair::SovUsd),
            ("CBE", "USD") => Ok(OraclePair::CbeUsd),
            _ => Err(anyhow::anyhow!(
                "Unsupported base/quote '{} / {}'. Supported: SOV/USD, CBE/USD",
                base,
                quote
            )),
        }
    }

    fn parse_period_secs_from_uri(&self, uri: &str) -> Result<u64> {
        let q = Self::parse_query_params(uri);
        let period = q.get("period").map(String::as_str).unwrap_or("24h");
        match period {
            "1H" => Ok(3600),
            "24H" => Ok(24 * 3600),
            "7D" => Ok(7 * 24 * 3600),
            _ => Err(anyhow::anyhow!(
                "Unsupported period '{}'. Supported: 1h, 24h, 7d",
                period
            )),
        }
    }

    fn price_f64_from_atomic(price_atomic: u128) -> f64 {
        price_atomic as f64 / ORACLE_PRICE_SCALE as f64
    }
}

#[async_trait::async_trait]
impl ZhtpRequestHandler for OracleHandler {
    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/oracle")
    }

    async fn handle_request(&self, request: ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Strip trailing slash and query string before routing.
        let uri = request.uri.trim_end_matches('/');
        let uri_no_query = uri.splitn(2, '?').next().unwrap_or(uri);
        let path_parts: Vec<&str> = uri_no_query.trim_start_matches('/').split('/').collect();

        match (request.method.clone(), path_parts.as_slice()) {
            // Existing read endpoints
            (ZhtpMethod::Get, ["api", "v1", "oracle", "price"]) => {
                self.handle_get_price(&request).await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "variation"]) => {
                self.handle_get_variation(&request).await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "status"]) => self.handle_get_status().await,
            (ZhtpMethod::Get, ["api", "v1", "oracle", "config"]) => self.handle_get_config().await,

            // ORACLE-14: New read endpoints
            (ZhtpMethod::Get, ["api", "v1", "oracle", "protocol"]) => {
                self.handle_get_protocol().await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "pending-updates"]) => {
                self.handle_get_pending_updates().await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "slashing-events"]) => {
                self.handle_get_slashing_events().await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "banned-validators"]) => {
                self.handle_get_banned_validators().await
            }
            (ZhtpMethod::Get, ["api", "v1", "oracle", "attestations", epoch_str]) => {
                self.handle_get_attestations(epoch_str).await
            }

            // ORACLE-14: New write endpoints (governance proposals)
            (ZhtpMethod::Post, ["api", "v1", "oracle", "committee", "propose"]) => {
                self.handle_propose_committee(&request).await
            }
            (ZhtpMethod::Post, ["api", "v1", "oracle", "config", "propose"]) => {
                self.handle_propose_config(&request).await
            }
            (ZhtpMethod::Post, ["api", "v1", "oracle", "updates", "cancel"]) => {
                self.handle_cancel_update(&request).await
            }

            // ORACLE-14: Testnet-only attestation endpoint
            (ZhtpMethod::Post, ["api", "v1", "oracle", "attest"]) => {
                self.handle_manual_attest(&request).await
            }

            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Oracle endpoint not found: {}", uri_no_query),
            )),
        }
    }

    fn priority(&self) -> u32 {
        100
    }
}

// ============================================================================
// Request/Response Types for ORACLE-14
// ============================================================================

#[derive(Debug, Deserialize)]
struct ProposeCommitteeRequest {
    new_members: Vec<String>, // hex-encoded key_ids
    /// Optional: hex-encoded dilithium_pk for each member, same order as new_members.
    /// Required for bootstrap so attestation signature verification can resolve signers.
    #[serde(default)]
    signing_pubkeys: Vec<String>,
    #[allow(dead_code)] // reserved for future epoch-scheduled updates
    activate_at_epoch: u64,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProposeConfigRequest {
    epoch_duration_secs: Option<u64>,
    max_source_age_secs: Option<u64>,
    max_deviation_bps: Option<u32>,
    max_price_staleness_epochs: Option<u64>,
    activate_at_epoch: u64,
    _reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CancelUpdateRequest {
    cancel_committee_update: bool,
    cancel_config_update: bool,
    _reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManualAttestRequest {
    epoch_id: u64,
    sov_usd_price_atomic: String, // u128 as string
}

// ============================================================================
// Handler Implementations
// ============================================================================

impl OracleHandler {
    /// GET /api/v1/oracle/price
    ///
    /// Returns the latest finalized SOV/USD price, or 404 if no price has finalized yet.
    async fn handle_get_price(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let pair = match self.parse_pair_from_uri(&request.uri) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string()));
            }
        };

        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle price API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        // Use block timestamp for epoch derivation (Oracle Spec v1 §4.1)
        // Wall clock MUST NOT be used to determine epoch_id.
        let block_timestamp = bc.last_committed_timestamp();
        let current_epoch = bc.oracle_state.epoch_id(block_timestamp);

        match pair {
            OraclePair::SovUsd => {
                let latest = bc
                    .oracle_state
                    .latest_finalized_price_at_or_before(current_epoch);
                match latest {
                    Some(finalized) => {
                        let epochs_since = current_epoch.saturating_sub(finalized.epoch_id);
                        let max_staleness = bc.oracle_state.config.max_price_staleness_epochs;
                        let is_fresh = epochs_since <= max_staleness;
                        let current_block = bc.get_height();
                        let pricing_mode = bc.onramp_state.oracle_mode(current_block);
                        let pricing_mode_str = match pricing_mode {
                            lib_blockchain::onramp::OraclePricingMode::LiveDerived => "Mode B (Live Derived)",
                            lib_blockchain::onramp::OraclePricingMode::GenesisReference => "Mode A (Genesis Reference)",
                        };
                        let cbe_usd_price_atomic = finalized.cbe_usd_price;
                        let body = json!({
                            "pair": pair.as_str(),
                            "source": "oracle_finalized",
                            "pricing_mode": pricing_mode_str,
                            "epoch_id": finalized.epoch_id,
                            "price_atomic": finalized.sov_usd_price.to_string(),
                            "price": Self::price_f64_from_atomic(finalized.sov_usd_price),
                            "cbe_usd_price_atomic": cbe_usd_price_atomic.map(|p| p.to_string()),
                            "cbe_usd_price": cbe_usd_price_atomic.map(Self::price_f64_from_atomic),
                            "oracle_price_scale": ORACLE_PRICE_SCALE.to_string(),
                            "current_epoch": current_epoch,
                            "epochs_since_finalization": epochs_since,
                            "is_fresh": is_fresh,
                            "max_price_staleness_epochs": max_staleness,
                        });
                        let bytes = match serde_json::to_vec(&body) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("Oracle price API: failed to serialize response: {}", e);
                                return Ok(ZhtpResponse::error(
                                    ZhtpStatus::InternalServerError,
                                    "Failed to serialize oracle price response".to_string(),
                                ));
                            }
                        };
                        Ok(ZhtpResponse::success_with_content_type(
                            bytes,
                            "application/json".to_string(),
                            None,
                        ))
                    }
                    None => Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        "No finalized oracle price yet — oracle committee has not reached consensus".to_string(),
                    )),
                }
            }
            OraclePair::CbeUsd => {
                let cbe_symbol = lib_blockchain::contracts::tokens::CBE_SYMBOL;
                // Prefer bonding curve token (has live price); fall back to regular token contract.
                let bonding_token = bc
                    .bonding_curve_registry
                    .get_all()
                    .into_iter()
                    .find(|t| t.symbol == cbe_symbol);

                let body = if let Some(token) = bonding_token {
                    let price_atomic = token.current_price() as u128;
                    let s_c = if let Some(store) = bc.get_store() {
                        store.get_cbe_economic_state()
                            .map(|e| e.s_c)
                            .unwrap_or(0)
                    } else { 0 };
                    let econ = if let Some(store) = bc.get_store() {
                        store.get_cbe_economic_state().ok()
                    } else { None };
                    let floor_price = if s_c > 0 {
                        let reserve = econ.as_ref().map(|e| e.reserve_balance).unwrap_or(0);
                        Some(lib_blockchain::contracts::bonding_curve::canonical::floor_price(
                            &econ.clone().unwrap_or_default()
                        ))
                    } else { None };

                    // Determine current band (0-4) from supply
                    let current_band = lib_blockchain::contracts::bonding_curve::canonical::BANDS
                        .iter()
                        .position(|b| s_c >= b.start_supply && s_c < b.end_supply)
                        .unwrap_or(0);
                    let band = &lib_blockchain::contracts::bonding_curve::canonical::BANDS[current_band];
                    let band_progress = if band.end_supply > band.start_supply {
                        ((s_c.saturating_sub(band.start_supply)) as f64
                            / (band.end_supply - band.start_supply) as f64 * 100.0) as u8
                    } else { 0 };

                    let graduation_threshold = lib_blockchain::contracts::bonding_curve::canonical::GRAD_THRESHOLD;
                    let reserve_balance = econ.as_ref().map(|e| e.reserve_balance).unwrap_or(0);
                    let graduation_progress = if graduation_threshold > 0 {
                        (reserve_balance as f64 / graduation_threshold as f64 * 100.0).min(100.0)
                    } else { 0.0 };

                    json!({
                        "pair": pair.as_str(),
                        "source": "bonding_curve",
                        "token_id": hex::encode(token.token_id),
                        "phase": format!("{:?}", token.phase),
                        // Prices
                        "price_atomic": price_atomic.to_string(),
                        "price": Self::price_f64_from_atomic(price_atomic),
                        "price_scale": ORACLE_PRICE_SCALE.to_string(),
                        "floor_price_atomic": floor_price.map(|f| f.to_string()),
                        "cbe_sov_price": price_atomic as f64 / lib_types::TOKEN_SCALE_18 as f64,
                        // Supply
                        "circulating_supply": s_c.to_string(),
                        "total_supply_ceiling": lib_blockchain::contracts::bonding_curve::canonical::MAX_SUPPLY.to_string(),
                        "genesis_treasury_allocation": econ.as_ref().map(|e| e.genesis_treasury_allocation.to_string()),
                        // Band info
                        "current_band": current_band,
                        "band_count": 5,
                        "band_progress_pct": band_progress,
                        // Graduation
                        "graduation_progress_pct": graduation_progress,
                        "graduated": econ.as_ref().map(|e| e.graduated).unwrap_or(false),
                        // Pools
                        "reserve_balance": reserve_balance.to_string(),
                        "sov_treasury_cbe_balance": econ.as_ref().map(|e| e.sov_treasury_cbe_balance.to_string()),
                        "liquidity_pool_balance": econ.as_ref().map(|e| e.liquidity_pool.balance.to_string()),
                        // SOVRN audit
                        "sovrn_total_supply": econ.as_ref().map(|e| e.sovrn_total_supply.to_string()),
                        // Debt
                        "debt_state": econ.as_ref().map(|e| format!("{:?}", e.debt_state)),
                        "outstanding_pre_backed": econ.as_ref().map(|e| e.outstanding_pre_backed.to_string()),
                        // Epoch
                        "current_epoch": current_epoch,
                    })
                } else if let Some(token) =
                    bc.token_contracts.values().find(|t| t.symbol == cbe_symbol)
                {
                    // CBE exists as a standard token contract without a bonding curve price.
                    json!({
                        "pair": pair.as_str(),
                        "source": "token_contract",
                        "token_id": hex::encode(token.token_id),
                        "name": token.name,
                        "symbol": token.symbol,
                        "total_supply": token.total_supply,
                        "price": null,
                        "current_epoch": current_epoch,
                    })
                } else {
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        "CBE token not found".to_string(),
                    ));
                };

                let bytes = match serde_json::to_vec(&body) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Oracle price API: failed to serialize CBE response: {}", e);
                        return Ok(ZhtpResponse::error(
                            ZhtpStatus::InternalServerError,
                            "Failed to serialize CBE price response".to_string(),
                        ));
                    }
                };
                Ok(ZhtpResponse::success_with_content_type(
                    bytes,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    async fn handle_get_variation(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let pair = match self.parse_pair_from_uri(&request.uri) {
            Ok(p) => p,
            Err(e) => {
                return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string()));
            }
        };
        let period_secs = match self.parse_period_secs_from_uri(&request.uri) {
            Ok(p) => p,
            Err(e) => return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string())),
        };

        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle variation API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };
        let bc = bc_arc.read().await;
        let block_timestamp = bc.last_committed_timestamp();
        let current_epoch = bc.oracle_state.epoch_id(block_timestamp);

        match pair {
            OraclePair::SovUsd => {
                let epoch_duration = bc.oracle_state.config.epoch_duration_secs.max(1);
                let epochs_span = period_secs.saturating_add(epoch_duration - 1) / epoch_duration;
                let start_epoch = current_epoch.saturating_sub(epochs_span);

                let latest = match bc
                    .oracle_state
                    .latest_finalized_price_at_or_before(current_epoch)
                {
                    Some(p) => p,
                    None => {
                        return Ok(ZhtpResponse::error(
                            ZhtpStatus::NotFound,
                            "No finalized SOV/USD oracle price available".to_string(),
                        ));
                    }
                };
                let reference = match bc
                    .oracle_state
                    .latest_finalized_price_at_or_before(start_epoch)
                {
                    Some(p) => p,
                    None => latest,
                };

                let mut prices: Vec<f64> = bc
                    .oracle_state
                    .all_finalized_prices()
                    .iter()
                    .filter(|(epoch, _)| **epoch >= start_epoch && **epoch <= current_epoch)
                    .map(|(_, p)| Self::price_f64_from_atomic(p.sov_usd_price))
                    .collect();
                if prices.is_empty() {
                    prices.push(Self::price_f64_from_atomic(latest.sov_usd_price));
                }
                let high = prices.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                let low = prices.iter().cloned().fold(f64::INFINITY, f64::min);
                let mean = prices.iter().sum::<f64>() / prices.len() as f64;
                let variance =
                    prices.iter().map(|p| (p - mean).powi(2)).sum::<f64>() / prices.len() as f64;
                let stdev = variance.sqrt();

                let latest_price = Self::price_f64_from_atomic(latest.sov_usd_price);
                let reference_price = Self::price_f64_from_atomic(reference.sov_usd_price);
                let abs_change = latest_price - reference_price;
                let pct_change = if reference_price > 0.0 {
                    (abs_change / reference_price) * 100.0
                } else {
                    0.0
                };

                let body = json!({
                    "pair": pair.as_str(),
                    "source": "oracle_finalized",
                    "period_secs": period_secs,
                    "period_start_epoch": start_epoch,
                    "period_end_epoch": current_epoch,
                    "latest_price": latest_price,
                    "reference_price": reference_price,
                    "absolute_change": abs_change,
                    "percent_change": pct_change,
                    "high": high,
                    "low": low,
                    "mean": mean,
                    "stdev": stdev,
                    "sample_count": prices.len(),
                });
                let bytes = match serde_json::to_vec(&body) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(
                            "Oracle variation API: failed to serialize SOV response: {}",
                            e
                        );
                        return Ok(ZhtpResponse::error(
                            ZhtpStatus::InternalServerError,
                            "Failed to serialize SOV variation response".to_string(),
                        ));
                    }
                };
                Ok(ZhtpResponse::success_with_content_type(
                    bytes,
                    "application/json".to_string(),
                    None,
                ))
            }
            OraclePair::CbeUsd => {
                let cbe_symbol = lib_blockchain::contracts::tokens::CBE_SYMBOL;
                let bonding_token = bc
                    .bonding_curve_registry
                    .get_all()
                    .into_iter()
                    .find(|t| t.symbol == cbe_symbol);

                let body = if let Some(token) = bonding_token {
                    let current_price_atomic = token.current_price() as u128;
                    let lib_blockchain::contracts::bonding_curve::types::CurveType::PiecewiseLinear(
                        curve,
                    ) = &token.curve_type;
                    let base_price_atomic = curve.price_at(0) as u128;
                    let current_price = Self::price_f64_from_atomic(current_price_atomic);
                    let base_price = Self::price_f64_from_atomic(base_price_atomic);
                    let abs_change = current_price - base_price;
                    let pct_change = if base_price > 0.0 {
                        (abs_change / base_price) * 100.0
                    } else {
                        0.0
                    };
                    let current_block = bc.latest_block().map(|b| b.header.height).unwrap_or(0);
                    let stats = token.get_stats(block_timestamp, current_block);
                    json!({
                        "pair": pair.as_str(),
                        "source": "bonding_curve_model",
                        "note": "CBE variation is computed against curve baseline; no historical per-period oracle series exists yet",
                        "period_secs": period_secs,
                        "token_id": hex::encode(token.token_id),
                        "phase": format!("{:?}", token.phase),
                        "current_price": current_price,
                        "base_price": base_price,
                        "absolute_change_since_base": abs_change,
                        "percent_change_since_base": pct_change,
                        "reserve_balance": token.reserve_balance,
                        "total_supply": token.total_supply,
                        "graduation_progress_percent": stats.graduation_progress_percent,
                        "can_graduate": stats.can_graduate,
                    })
                } else if let Some(token) =
                    bc.token_contracts.values().find(|t| t.symbol == cbe_symbol)
                {
                    // CBE exists as a standard token contract; no bonding curve variation data.
                    json!({
                        "pair": pair.as_str(),
                        "source": "token_contract",
                        "note": "CBE is a standard token contract without a bonding curve; variation data is not available",
                        "period_secs": period_secs,
                        "token_id": hex::encode(token.token_id),
                        "name": token.name,
                        "symbol": token.symbol,
                        "total_supply": token.total_supply,
                        "current_price": null,
                        "base_price": null,
                        "absolute_change_since_base": null,
                        "percent_change_since_base": null,
                        "current_epoch": current_epoch,
                    })
                } else {
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::NotFound,
                        "CBE token not found".to_string(),
                    ));
                };

                let bytes = match serde_json::to_vec(&body) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(
                            "Oracle variation API: failed to serialize CBE response: {}",
                            e
                        );
                        return Ok(ZhtpResponse::error(
                            ZhtpStatus::InternalServerError,
                            "Failed to serialize CBE variation response".to_string(),
                        ));
                    }
                };
                Ok(ZhtpResponse::success_with_content_type(
                    bytes,
                    "application/json".to_string(),
                    None,
                ))
            }
        }
    }

    /// GET /api/v1/oracle/status
    async fn handle_get_status(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle status API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        // Use block timestamp for epoch derivation (Oracle Spec v1 §4.1)
        // Wall clock MUST NOT be used to determine epoch_id.
        let block_timestamp = bc.last_committed_timestamp();
        let current_epoch = bc.oracle_state.epoch_id(block_timestamp);
        let committee = bc.oracle_state.committee.members();
        let finalized_count = bc.oracle_state.finalized_prices_len();
        let threshold = bc.oracle_state.committee.threshold();

        let current_block = bc.get_height();
        let pricing_mode = bc.onramp_state.oracle_mode(current_block);
        let pricing_mode_str = match pricing_mode {
            lib_blockchain::onramp::OraclePricingMode::LiveDerived => "Mode B (Live Derived)",
            lib_blockchain::onramp::OraclePricingMode::GenesisReference => {
                "Mode A (Genesis Reference)"
            }
        };
        let cbe_usd_vwap = bc.onramp_state.cbe_usd_vwap(current_block);
        // Count trades in the VWAP window for status reporting.
        let window_start = current_block.saturating_sub(lib_blockchain::onramp::VWAP_WINDOW_BLOCKS);
        let onramp_window_trade_count = bc
            .onramp_state
            .trades
            .iter()
            .filter(|t| t.block_height >= window_start)
            .count();
        let onramp_window_usdc_volume: u128 = bc
            .onramp_state
            .trades
            .iter()
            .filter(|t| t.block_height >= window_start)
            .map(|t| t.usdc_amount)
            .sum();

        let latest_price = bc
            .oracle_state
            .latest_finalized_price_at_or_before(current_epoch)
            .map(|p| {
                let price_usd = p.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64;
                let epochs_since = current_epoch.saturating_sub(p.epoch_id);
                let max_staleness = bc.oracle_state.config.max_price_staleness_epochs;
                json!({
                    "epoch_id": p.epoch_id,
                    "sov_usd_price_atomic": p.sov_usd_price.to_string(),
                    "sov_usd_price": price_usd,
                    "cbe_usd_price_atomic": p.cbe_usd_price.map(|v| v.to_string()),
                    "cbe_usd_price": p.cbe_usd_price.map(Self::price_f64_from_atomic),
                    "epochs_since_finalization": epochs_since,
                    "is_fresh": epochs_since <= max_staleness,
                })
            });

        let body = json!({
            "current_epoch": current_epoch,
            "epoch_duration_secs": bc.oracle_state.config.epoch_duration_secs,
            "committee_size": committee.len(),
            "committee_threshold": threshold,
            "committee_members": committee.iter().map(hex::encode).collect::<Vec<_>>(),
            "finalized_prices_count": finalized_count,
            "latest_finalized_price": latest_price,
            "oracle_price_scale": ORACLE_PRICE_SCALE.to_string(),
            "max_price_staleness_epochs": bc.oracle_state.config.max_price_staleness_epochs,
            "pricing_mode": pricing_mode_str,
            "onramp_vwap_cbe_usd_atomic": cbe_usd_vwap.map(|v| v.to_string()),
            "onramp_vwap_cbe_usd": cbe_usd_vwap.map(Self::price_f64_from_atomic),
            "onramp_window_trade_count": onramp_window_trade_count,
            "onramp_window_usdc_volume_atomic": onramp_window_usdc_volume.to_string(),
            "onramp_min_trades_required": lib_blockchain::onramp::MIN_TRADES,
            "onramp_min_volume_usdc_atomic": lib_blockchain::onramp::MIN_VOLUME_USDC.to_string(),
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!("Oracle status API: failed to serialize response: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize oracle status response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/config
    ///
    /// Returns all operating parameters of the oracle: epoch cadence, price scale,
    /// deviation limits, staleness limits, committee membership and threshold,
    /// and any pending governance updates scheduled for future epochs.
    async fn handle_get_config(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle config API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        let cfg = &bc.oracle_state.config;
        let committee = bc.oracle_state.committee.members();
        let threshold = bc.oracle_state.committee.threshold();

        let pending_committee = bc.oracle_state.committee.pending_update().map(|u| {
            let n = u.members.len() as u64;
            let new_threshold = (2 * n) / 3 + 1;
            json!({
                "activate_at_epoch": u.activate_at_epoch,
                "new_members": u.members.iter().map(hex::encode).collect::<Vec<_>>(),
                "new_size": u.members.len(),
                "new_threshold": new_threshold,
            })
        });

        let pending_config = bc.oracle_state.pending_config_update.as_ref().map(|u| {
            json!({
                "activate_at_epoch": u.activate_at_epoch,
                "epoch_duration_secs": u.config.epoch_duration_secs,
                "max_source_age_secs": u.config.max_source_age_secs,
                "max_deviation_bps": u.config.max_deviation_bps,
                "max_price_staleness_epochs": u.config.max_price_staleness_epochs(),
                "price_scale": u.config.price_scale(),
            })
        });

        let body = json!({
            "epoch_duration_secs": cfg.epoch_duration_secs,
            "max_source_age_secs": cfg.max_source_age_secs,
            "max_deviation_bps": cfg.max_deviation_bps,
            "max_deviation_pct": cfg.max_deviation_bps as f64 / 100.0,
            "max_price_staleness_epochs": cfg.max_price_staleness_epochs(),
            "price_scale": cfg.price_scale().to_string(),
            "committee_size": committee.len(),
            "committee_threshold": threshold,
            "committee_members": committee.iter().map(hex::encode).collect::<Vec<_>>(),
            "pending_committee_update": pending_committee,
            "pending_config_update": pending_config,
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!("Oracle config API: failed to serialize response: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize oracle config response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/protocol
    ///
    /// Returns the current oracle protocol version and any pending protocol upgrade.
    async fn handle_get_protocol(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle protocol API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        let protocol_config = &bc.oracle_state.protocol_config;

        let current_version = protocol_config.current_version();
        let feature_flags = bc.oracle_state.feature_flags();

        let pending_upgrade = protocol_config.pending_activation().map(|p| {
            json!({
                "target_version": p.target_version.as_u16(),
                "activate_at_height": p.activate_at_height,
                "scheduled_at_height": p.scheduled_at_height,
                "source_proposal_id": p.source_proposal_id.map(|id| hex::encode(id)),
            })
        });

        let body = json!({
            "current_version": current_version.as_u16(),
            "version_name": if current_version.is_strict_spec() { "v1_strict_spec" } else { "v0_legacy" },
            "activated_at_height": protocol_config.activated_at_height(),
            "is_strict_spec_active": current_version.is_strict_spec(),
            "feature_flags": {
                "canonical_attestation_path": feature_flags.canonical_attestation_path,
                "strict_cbe_graduation_formula": feature_flags.strict_cbe_graduation_formula,
                "normalized_epoch_tracking": feature_flags.normalized_epoch_tracking,
                "on_chain_producer_policy": feature_flags.on_chain_producer_policy,
                "aligned_slashing_semantics": feature_flags.aligned_slashing_semantics,
                "hardened_write_boundaries": feature_flags.hardened_write_boundaries,
                "shadow_mode_parity": feature_flags.shadow_mode_parity,
            },
            "pending_upgrade": pending_upgrade,
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!("Oracle protocol API: failed to serialize response: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize oracle protocol response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/pending-updates
    ///
    /// Returns current pending committee and config updates with activation epoch,
    /// scheduled epoch, expiry, and source proposal ID.
    async fn handle_get_pending_updates(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle pending-updates API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        let block_timestamp = bc.last_committed_timestamp();
        let current_epoch = bc.oracle_state.epoch_id(block_timestamp);
        let _config = &bc.oracle_state.config;

        // Return only fields that are actually tracked in oracle state
        let pending_committee = bc.oracle_state.committee.pending_update().map(|u| {
            let n = u.members.len() as u64;
            let new_threshold = (2 * n) / 3 + 1;
            json!({
                "activate_at_epoch": u.activate_at_epoch,
                "new_member_count": u.members.len(),
                "new_members": u.members.iter().map(hex::encode).collect::<Vec<_>>(),
                "new_threshold": new_threshold,
            })
        });

        let pending_config = bc.oracle_state.pending_config_update.as_ref().map(|u| {
            json!({
                "activate_at_epoch": u.activate_at_epoch,
                "epoch_duration_secs": u.config.epoch_duration_secs,
                "max_source_age_secs": u.config.max_source_age_secs,
                "max_deviation_bps": u.config.max_deviation_bps,
                "max_price_staleness_epochs": u.config.max_price_staleness_epochs(),
            })
        });

        let body = json!({
            "current_epoch": current_epoch,
            "pending_committee_update": pending_committee,
            "pending_config_update": pending_config,
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Oracle pending-updates API: failed to serialize response: {}",
                    e
                );
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/slashing-events
    ///
    /// Returns last 100 oracle slash events.
    async fn handle_get_slashing_events(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle slashing-events API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;

        // Get last 100 events (or fewer if less exist)
        let events: Vec<_> = bc
            .oracle_slash_events
            .iter()
            .rev()
            .take(100)
            .map(|e| {
                let reason_str = match e.reason {
                    OracleSlashReason::ConflictingAttestation => "conflicting_attestation",
                    OracleSlashReason::WrongEpoch => "wrong_epoch",
                    OracleSlashReason::DeviationBand => "deviation_band",
                };
                json!({
                    "validator_key_id": hex::encode(e.validator_key_id),
                    "reason": reason_str,
                    "epoch_id": e.epoch_id,
                    "slash_amount": e.slash_amount,
                    "slashed_at_height": e.slashed_at_height,
                })
            })
            .collect();

        let body = json!({
            "events": events,
            "total_events": bc.oracle_slash_events.len(),
            "banned_validator_count": bc.oracle_banned_validators.len(),
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Oracle slashing-events API: failed to serialize response: {}",
                    e
                );
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/banned-validators
    ///
    /// Returns all currently banned validator key_ids.
    async fn handle_get_banned_validators(&self) -> ZhtpResult<ZhtpResponse> {
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle banned-validators API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;

        let banned: Vec<_> = bc
            .oracle_banned_validators
            .iter()
            .map(hex::encode)
            .collect();

        let body = json!({
            "banned": banned,
            "count": banned.len(),
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Oracle banned-validators API: failed to serialize response: {}",
                    e
                );
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// GET /api/v1/oracle/attestations/{epoch_id}
    ///
    /// Returns attestation status for a given epoch.
    async fn handle_get_attestations(&self, epoch_str: &str) -> ZhtpResult<ZhtpResponse> {
        let epoch_id: u64 = match epoch_str.parse() {
            Ok(e) => e,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid epoch_id - must be a positive integer".to_string(),
                ));
            }
        };

        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle attestations API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        let committee_size = bc.oracle_state.committee.members().len();
        let threshold = bc.oracle_state.committee.threshold();

        // Check if epoch is finalized
        let finalized = bc.oracle_state.finalized_price(epoch_id);

        // Get current epoch to calculate attestations needed
        let block_timestamp = bc.last_committed_timestamp();
        let current_epoch = bc.oracle_state.epoch_id(block_timestamp);

        // Per-epoch attestation tracking is not yet implemented.
        // We can only report whether the epoch is finalized or not.
        let is_finalized = finalized.is_some();

        let body = json!({
            "epoch_id": epoch_id,
            "current_epoch": current_epoch,
            "committee_size": committee_size,
            "threshold": threshold,
            "finalized": is_finalized,
            "note": "Per-epoch attestation tracking is not yet implemented",
            "finalized_price": finalized.map(|p| {
                let price_usd = p.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64;
                json!({
                    "sov_usd_price": price_usd,
                    "sov_usd_price_atomic": p.sov_usd_price.to_string(),
                })
            }),
        });

        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Oracle attestations API: failed to serialize response: {}",
                    e
                );
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    "Failed to serialize response".to_string(),
                ));
            }
        };
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }

    /// POST /api/v1/oracle/committee/propose
    ///
    /// Submits a DAO proposal for oracle committee change.
    /// Note: Full implementation requires governance transaction creation.
    async fn handle_propose_committee(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let req: ProposeCommitteeRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request body: {}", e),
                ));
            }
        };

        // Validate new_members
        if req.new_members.is_empty() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "new_members cannot be empty".to_string(),
            ));
        }

        let mut member_ids = Vec::new();
        for member_hex in &req.new_members {
            match self.parse_hex_32(member_hex, "member") {
                Ok(id) => member_ids.push(id),
                Err(e) => {
                    return Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string()));
                }
            }
        }

        // Bootstrap path: directly set the committee when it is currently empty.
        // Once populated, modifications must go through DAO governance.
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let mut bc = bc_arc.write().await;

        let reason = req
            .reason
            .unwrap_or_else(|| "Bootstrap oracle committee".to_string());

        // Parse signing public keys (hex) and pair with member key_ids.
        let members_with_pubkeys: Vec<([u8; 32], Vec<u8>)> = member_ids
            .iter()
            .enumerate()
            .map(|(i, &key_id)| {
                let pk = req
                    .signing_pubkeys
                    .get(i)
                    .and_then(|hex_str| hex::decode(hex_str).ok())
                    .unwrap_or_default();
                (key_id, pk)
            })
            .collect();

        match bc.bootstrap_oracle_committee(members_with_pubkeys) {
            Ok(()) => {
                // Persist immediately so the change survives restart before next block.
                let dat_path = std::path::Path::new("./data/testnet/blockchain.dat");
                if let Err(e) = bc.save_to_file(dat_path) {
                    warn!(
                        "Oracle bootstrap: failed to persist blockchain after committee update: {}",
                        e
                    );
                }
                let threshold = bc.oracle_state.committee.threshold();
                let members_hex: Vec<String> = bc
                    .oracle_state
                    .committee
                    .members()
                    .iter()
                    .map(hex::encode)
                    .collect();
                debug!(
                    "Oracle committee bootstrapped: {} members, reason={}",
                    members_hex.len(),
                    reason
                );
                let body = serde_json::json!({
                    "status": "success",
                    "committee_members": members_hex,
                    "committee_size": members_hex.len(),
                    "threshold": threshold,
                    "reason": reason,
                });
                Ok(ZhtpResponse::success_with_content_type(
                    serde_json::to_vec(&body).unwrap_or_default(),
                    "application/json".to_string(),
                    None,
                ))
            }
            Err(e) => Ok(ZhtpResponse::error(ZhtpStatus::BadRequest, e.to_string())),
        }
    }

    /// POST /api/v1/oracle/config/propose
    ///
    /// Submits a DAO proposal for oracle config change.
    async fn handle_propose_config(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let req: ProposeConfigRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request body: {}", e),
                ));
            }
        };

        // Build proposed config (start with current, apply changes)
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        let bc = bc_arc.read().await;
        let current_config = &bc.oracle_state.config;

        // Build proposed config by modifying current config fields
        let mut proposed_config = current_config.clone();
        if let Some(epoch_duration) = req.epoch_duration_secs {
            proposed_config.epoch_duration_secs = epoch_duration;
        }
        if let Some(max_source_age) = req.max_source_age_secs {
            proposed_config.max_source_age_secs = max_source_age;
        }
        if let Some(max_deviation) = req.max_deviation_bps {
            proposed_config.max_deviation_bps = max_deviation;
        }
        if let Some(max_staleness) = req.max_price_staleness_epochs {
            proposed_config.max_price_staleness_epochs = max_staleness;
        }

        // Validate the proposed config (ORACLE-15)
        if let Err(e) = proposed_config.validate() {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                format!("Invalid oracle config: {}", e),
            ));
        }

        // DAO proposal creation for oracle config updates is not yet implemented.
        debug!(
            "Oracle config proposal received but governance submission is not implemented; \
             requested activate_at_epoch={}",
            req.activate_at_epoch
        );

        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "DAO proposal creation for oracle config updates is not yet implemented".to_string(),
        ))
    }

    /// POST /api/v1/oracle/updates/cancel
    ///
    /// Submits a DAO proposal to cancel pending oracle updates.
    async fn handle_cancel_update(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        let req: CancelUpdateRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request body: {}", e),
                ));
            }
        };

        if !req.cancel_committee_update && !req.cancel_config_update {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                "At least one of cancel_committee_update or cancel_config_update must be true"
                    .to_string(),
            ));
        }

        // DAO proposal creation for oracle update cancellation is not yet implemented.
        warn!(
            "Oracle cancel update proposal requested but DAO governance submission is not implemented yet: \
             committee_cancel={}, config_cancel={}",
            req.cancel_committee_update,
            req.cancel_config_update
        );

        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Oracle update cancellation via DAO governance is not implemented yet".to_string(),
        ))
    }

    /// POST /api/v1/oracle/attest
    ///
    /// Manually submit an oracle attestation (testnet only).
    /// Disabled on mainnet and in strict spec mode.
    ///
    /// ORACLE-R9: In strict spec mode, attestations MUST go through the canonical
    /// transaction path. Direct API submission is disabled to prevent non-canonical
    /// state mutations.
    async fn handle_manual_attest(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
        // Check blockchain for strict spec mode
        let bc_arc = match self.get_blockchain().await {
            Ok(bc) => bc,
            Err(e) => {
                warn!("Oracle attest API: {}", e);
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    e.to_string(),
                ));
            }
        };

        // ORACLE-R9: Strict spec mode disables direct attestation API
        {
            let bc = bc_arc.read().await;
            if bc.oracle_state.is_strict_spec_active() {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::Forbidden,
                    "Direct attestation API is disabled in strict spec mode. \
                     Use transaction-based attestation submission."
                        .to_string(),
                ));
            }
        }

        // Check if on testnet
        if !self.is_testnet {
            return Ok(ZhtpResponse::error(
                ZhtpStatus::Forbidden,
                "Manual attestation is only available on testnet".to_string(),
            ));
        }

        let req: ManualAttestRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    format!("Invalid request body: {}", e),
                ));
            }
        };

        // Parse price from string
        let sov_usd_price: u128 = match req.sov_usd_price_atomic.parse() {
            Ok(p) => p,
            Err(_) => {
                return Ok(ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "Invalid sov_usd_price_atomic - must be a valid u128".to_string(),
                ));
            }
        };

        // Manual attestation submission is not yet implemented.
        debug!(
            "Manual attestation received (NOT IMPLEMENTED): epoch_id={}, price={}",
            req.epoch_id, sov_usd_price
        );

        Ok(ZhtpResponse::error(
            ZhtpStatus::NotImplemented,
            "Manual attestation submission is not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{OracleHandler, OraclePair};

    #[test]
    fn parses_supported_pairs() {
        let h = OracleHandler::new();
        assert!(matches!(
            h.parse_pair_from_uri("/api/v1/oracle/price?base=SOV&quote=USD")
                .unwrap(),
            OraclePair::SovUsd
        ));
        assert!(matches!(
            h.parse_pair_from_uri("/api/v1/oracle/price?pair=CBE_USD")
                .unwrap(),
            OraclePair::CbeUsd
        ));
    }

    #[test]
    fn parses_supported_periods() {
        let h = OracleHandler::new();
        assert_eq!(
            h.parse_period_secs_from_uri("/api/v1/oracle/variation?period=1h")
                .unwrap(),
            3600
        );
        assert_eq!(
            h.parse_period_secs_from_uri("/api/v1/oracle/variation?period=24h")
                .unwrap(),
            24 * 3600
        );
        assert_eq!(
            h.parse_period_secs_from_uri("/api/v1/oracle/variation?period=7d")
                .unwrap(),
            7 * 24 * 3600
        );
    }
}
