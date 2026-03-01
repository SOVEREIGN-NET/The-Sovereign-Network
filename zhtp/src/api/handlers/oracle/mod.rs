//! Oracle API Handler
//!
//! Endpoints:
//!   GET /api/v1/oracle/price   — latest finalized SOV/USD price
//!   GET /api/v1/oracle/status  — committee state, epoch, last finalized height
//!   GET /api/v1/oracle/config  — all operating parameters (epoch cadence, thresholds, deviation limits)

use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::oracle::ORACLE_PRICE_SCALE;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::warn;

pub struct OracleHandler;

impl OracleHandler {
    pub fn new() -> Self {
        Self
    }

    async fn get_blockchain(
        &self,
    ) -> Result<Arc<RwLock<lib_blockchain::Blockchain>>> {
        crate::runtime::blockchain_provider::get_global_blockchain()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to access blockchain: {}", e))
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

        match path_parts.as_slice() {
            ["api", "v1", "oracle", "price"] => self.handle_get_price().await,
            ["api", "v1", "oracle", "status"] => self.handle_get_status().await,
            ["api", "v1", "oracle", "config"] => self.handle_get_config().await,
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

impl OracleHandler {
    /// GET /api/v1/oracle/price
    ///
    /// Returns the latest finalized SOV/USD price, or 404 if no price has finalized yet.
    async fn handle_get_price(&self) -> ZhtpResult<ZhtpResponse> {
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

        let latest = bc
            .oracle_state
            .latest_finalized_price_at_or_before(current_epoch);

        match latest {
            Some(finalized) => {
                let price_usd = finalized.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64;
                
                // ORACLE-5: Include staleness metadata
                let epochs_since = current_epoch.saturating_sub(finalized.epoch_id);
                let max_staleness = bc.oracle_state.config.max_price_staleness_epochs;
                let is_fresh = epochs_since <= max_staleness;
                
                // u128 fields are serialized as strings — serde_json cannot represent
                // integers beyond u64::MAX and will return an error otherwise.
                let body = json!({
                    "epoch_id": finalized.epoch_id,
                    "sov_usd_price_atomic": finalized.sov_usd_price.to_string(),
                    "sov_usd_price": price_usd,
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
}
