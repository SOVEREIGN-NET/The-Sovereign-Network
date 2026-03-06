//! Oracle API Handler
//!
//! Endpoints:
//!   GET /api/v1/oracle/price              — latest finalized SOV/USD price
//!   GET /api/v1/oracle/status             — committee state, epoch, last finalized height
//!   GET /api/v1/oracle/config             — all operating parameters
//!   GET /api/v1/oracle/pending-updates    — pending committee/config updates
//!   GET /api/v1/oracle/slashing-events    — last 100 oracle slash events
//!   GET /api/v1/oracle/banned-validators  — currently banned validator key_ids
//!   GET /api/v1/oracle/attestations/{epoch_id} — attestation status for epoch
//!   
//!   POST /api/v1/oracle/committee/propose — submit DAO proposal for committee change
//!   POST /api/v1/oracle/config/propose    — submit DAO proposal for config change
//!   POST /api/v1/oracle/updates/cancel    — submit DAO proposal to cancel pending updates
//!   POST /api/v1/oracle/attest            — submit oracle attestation (testnet only)

use std::sync::Arc;

use anyhow::Result;
use lib_blockchain::oracle::{ORACLE_PRICE_SCALE, OracleSlashReason};
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};
use lib_protocols::zhtp::{ZhtpRequestHandler, ZhtpResult};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{warn, debug};

pub struct OracleHandler {
    is_testnet: bool,
}

impl OracleHandler {
    pub fn new() -> Self {
        Self {
            is_testnet: std::env::var("ZHTP_NETWORK")
                .map(|v| v == "testnet" || v == "dev")
                .unwrap_or(false),
        }
    }

    async fn get_blockchain(
        &self,
    ) -> Result<Arc<RwLock<lib_blockchain::Blockchain>>> {
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
            (ZhtpMethod::Get, ["api", "v1", "oracle", "price"]) => self.handle_get_price().await,
            (ZhtpMethod::Get, ["api", "v1", "oracle", "status"]) => self.handle_get_status().await,
            (ZhtpMethod::Get, ["api", "v1", "oracle", "config"]) => self.handle_get_config().await,
            
            // ORACLE-14: New read endpoints
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
                warn!("Oracle pending-updates API: failed to serialize response: {}", e);
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
        let events: Vec<_> = bc.oracle_slash_events
            .iter()
            .rev()
            .take(100)
            .map(|e| {
                let reason_str = match e.reason {
                    OracleSlashReason::ConflictingAttestation => "conflicting_attestation",
                    OracleSlashReason::WrongEpoch => "wrong_epoch",
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
                warn!("Oracle slashing-events API: failed to serialize response: {}", e);
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
        
        let banned: Vec<_> = bc.oracle_banned_validators
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
                warn!("Oracle banned-validators API: failed to serialize response: {}", e);
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
                warn!("Oracle attestations API: failed to serialize response: {}", e);
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
                    return Ok(ZhtpResponse::error(
                        ZhtpStatus::BadRequest,
                        e.to_string(),
                    ));
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

        let reason = req.reason.unwrap_or_else(|| "Bootstrap oracle committee".to_string());

        // Parse signing public keys (hex) and pair with member key_ids.
        let members_with_pubkeys: Vec<([u8; 32], Vec<u8>)> = member_ids
            .iter()
            .enumerate()
            .map(|(i, &key_id)| {
                let pk = req.signing_pubkeys.get(i)
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
                    warn!("Oracle bootstrap: failed to persist blockchain after committee update: {}", e);
                }
                let threshold = bc.oracle_state.committee.threshold();
                let members_hex: Vec<String> = bc.oracle_state.committee.members()
                    .iter()
                    .map(hex::encode)
                    .collect();
                debug!("Oracle committee bootstrapped: {} members, reason={}", members_hex.len(), reason);
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
            Err(e) => Ok(ZhtpResponse::error(
                ZhtpStatus::BadRequest,
                e.to_string(),
            )),
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
                "At least one of cancel_committee_update or cancel_config_update must be true".to_string(),
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
    /// Disabled on mainnet.
    async fn handle_manual_attest(&self, request: &ZhtpRequest) -> ZhtpResult<ZhtpResponse> {
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
