//! Oracle API Handler
//!
//! Endpoints:
//!   GET /api/v1/oracle/price   — latest finalized SOV/USD price
//!   GET /api/v1/oracle/status  — committee state, epoch, last finalized height

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let uri = request.uri.trim_end_matches('/').to_string();
        let path_parts: Vec<&str> = uri.trim_start_matches('/').split('/').collect();

        match path_parts.as_slice() {
            ["api", "v1", "oracle", "price"] => self.handle_get_price().await,
            ["api", "v1", "oracle", "status"] => self.handle_get_status().await,
            _ => Ok(ZhtpResponse::error(
                ZhtpStatus::NotFound,
                format!("Oracle endpoint not found: {}", uri),
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_epoch = bc.oracle_state.epoch_id(now);

        let latest = bc
            .oracle_state
            .latest_finalized_price_at_or_before(current_epoch);

        match latest {
            Some(finalized) => {
                let price_usd = finalized.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64;
                let body = json!({
                    "epoch_id": finalized.epoch_id,
                    "sov_usd_price_atomic": finalized.sov_usd_price,
                    "sov_usd_price": price_usd,
                    "oracle_price_scale": ORACLE_PRICE_SCALE,
                });
                let bytes = serde_json::to_vec(&body).unwrap_or_default();
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_epoch = bc.oracle_state.epoch_id(now);
        let committee = bc.oracle_state.committee.members();
        let finalized_count = bc.oracle_state.finalized_prices_len();
        let threshold = bc.oracle_state.committee.threshold();

        let latest_price = bc
            .oracle_state
            .latest_finalized_price_at_or_before(current_epoch)
            .map(|p| json!({
                "epoch_id": p.epoch_id,
                "sov_usd_price_atomic": p.sov_usd_price,
                "sov_usd_price": p.sov_usd_price as f64 / ORACLE_PRICE_SCALE as f64,
            }));

        let body = json!({
            "current_epoch": current_epoch,
            "epoch_duration_secs": bc.oracle_state.config.epoch_duration_secs,
            "committee_size": committee.len(),
            "committee_threshold": threshold,
            "committee_members": committee.iter().map(hex::encode).collect::<Vec<_>>(),
            "finalized_prices_count": finalized_count,
            "latest_finalized_price": latest_price,
            "oracle_price_scale": ORACLE_PRICE_SCALE,
        });

        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        Ok(ZhtpResponse::success_with_content_type(
            bytes,
            "application/json".to_string(),
            None,
        ))
    }
}
