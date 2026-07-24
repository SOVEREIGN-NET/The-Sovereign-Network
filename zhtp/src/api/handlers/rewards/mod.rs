//! BUBL rewards endpoints.
//!
//! Hybrid reward settlement (N2): spend-delegate attestation via signed
//! `RewardClaim` txs. Eligibility reads consensus trees; executor enforces
//! policy at commit. No request-body signing (see `notifications/mod.rs`).
//!
//! ## Configuration
//!
//! Activated via `rewards_activation.toml` (written by `zhtp-cli node configure-rewards`
//! or copied across validators). **Ops posture:** place the toml on every validator
//! (enables read endpoints); mount the hot delegate keystore on **one** validator only
//! (enables claim POSTs). Read endpoints need only `asset_id` in the file; claims
//! additionally require a local keystore whose `key_id` matches on-chain
//! `spend_delegate_key_id` with positive delegate balance. Without the toml, every
//! endpoint returns 503.
//!
//! ## Storage (N4 / Q6)
//!
//! Eligibility, streak, history, and lifetime counters are read exclusively from
//! on-chain consensus trees and committed `RewardClaim` blocks. Node-local
//! `rewards.sled` is retired — delete any legacy file on upgrade (see
//! `scripts/effective-reset-testnet.sh`).

use anyhow::{anyhow, Result};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};


use lib_blockchain::blockchain::rewards::RewardHistoryEntry;
use lib_blockchain::transaction::reward_claim::{
    checkin_amount_for_day, RewardEventKind, REWARD_CHECKIN_BASE_ATOMS,
    REWARD_STREAK_BONUS_CAP_DAYS, REWARD_STREAK_BONUS_PER_DAY_ATOMS,
};
use lib_blockchain::Blockchain;
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::keys::{PrivateKey, PublicKey};
use lib_identity::ZhtpIdentity;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

use crate::keyfile_names::{KeystorePrivateKey, USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME};

mod settlement;

// ── Constants ────────────────────────────────────────────────────────

/// 18-decimal atom multiplier.
const ATOM_18: u128 = 1_000_000_000_000_000_000;

/// Weekly cap on new-partner rewards (fallback when policy omits cap).
const WEEKLY_PARTNER_CAP: u32 = 5;

const HISTORY_DEFAULT_LIMIT: usize = 50;
const HISTORY_MAX_LIMIT: usize = 200;
const MAX_DID_LEN: usize = 256;

// ── Request / response shapes ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ClaimRequest {
    did: String,
    event: String,
}

#[derive(Debug, Deserialize)]
struct ConversationRequest {
    did: String,
    peer_did: String,
}

// ── Handler ──────────────────────────────────────────────────────────

pub struct RewardsHandler {
    blockchain: Arc<RwLock<Blockchain>>,
    /// On-chain asset id from `rewards_activation.toml` (enables read endpoints).
    configured_asset_id: Option<[u8; 32]>,
    /// None when delegate keystore is unset, unfunded, or chain validation failed.
    /// POST claim endpoints return 503; GET may still serve reads when configured.
    treasury: Option<TreasuryConfig>,
}

#[derive(Clone)]
struct TreasuryConfig {
    keypair: Arc<KeyPair>,
    /// Sovereign asset id (launch tx hash post-reset, legacy token_id pre-migration).
    rewards_asset_id: [u8; 32],
    signer_key_id: [u8; 32],
}

impl RewardsHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Result<Self> {
        // Startup-time lookup: resolve on-chain spend delegate under a non-async
        // borrow of the blockchain (RewardsHandler::new is sync). The
        // blockchain Arc is shared; at startup no API traffic is yet
        // dispatched, so `blocking_read` here is uncontended. Wrapped in
        // `block_in_place` so the runtime can park the worker.
        let (configured_asset_id, treasury) = tokio::task::block_in_place(|| {
            let bc = blockchain.blocking_read();
            let configured_asset_id = crate::rewards_activation::configured_asset_id_from_file();
            let treasury = load_treasury(&bc);
            (configured_asset_id, treasury)
        });

        match (&configured_asset_id, &treasury) {
            (Some(id), Some(_)) => {
                info!(
                    "Rewards: spend delegate loaded for asset {} — /api/v1/rewards/* active",
                    hex::encode(&id[..8])
                );
            }
            (Some(id), None) => {
                info!(
                    "Rewards: activation present for asset {} but delegate signer not loaded — reads only",
                    hex::encode(&id[..8])
                );
            }
            (None, _) => {
                info!(
                    "Rewards: no rewards_activation.toml — /api/v1/rewards/* will return 503"
                );
            }
        }

        Ok(Self {
            blockchain,
            configured_asset_id,
            treasury,
        })
    }

    // ── helpers ──────────────────────────────────────────────────────

    fn unavailable() -> ZhtpResponse {
        ZhtpResponse::error(
            ZhtpStatus::ServiceUnavailable,
            "rewards endpoint not configured on this node".to_string(),
        )
    }

    fn bad(msg: impl Into<String>) -> ZhtpResponse {
        ZhtpResponse::error(ZhtpStatus::BadRequest, msg.into())
    }

    fn ok_json(data: serde_json::Value) -> ZhtpResponse {
        match serde_json::to_vec(&data) {
            Ok(bytes) => ZhtpResponse::success_with_content_type(
                bytes,
                "application/json".to_string(),
                None,
            ),
            Err(e) => ZhtpResponse::error(
                ZhtpStatus::InternalServerError,
                format!("response serialize failed: {}", e),
            ),
        }
    }

    fn validate_did(did: &str) -> Result<[u8; 32], String> {
        if did.is_empty() {
            return Err("did is required".to_string());
        }
        if did.len() > MAX_DID_LEN {
            return Err(format!("did exceeds max length {}", MAX_DID_LEN));
        }
        let hex_part = did
            .strip_prefix("did:zhtp:")
            .ok_or_else(|| "did must start with 'did:zhtp:'".to_string())?;
        if hex_part.len() != 64 {
            return Err("did body must be 64 hex chars (32 bytes)".to_string());
        }
        let bytes = hex::decode(hex_part).map_err(|_| "did body is not valid hex".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn utc_date() -> String {
        Utc::now().date_naive().format("%Y-%m-%d").to_string()
    }

    fn utc_day_ordinal() -> i32 {
        // Days since CE (1=Jan 1, year 1). Sufficient for streak math.
        Utc::now().date_naive().num_days_from_ce()
    }

    fn iso_week() -> String {
        let now = Utc::now();
        let iso = now.iso_week();
        format!("{}-W{:02}", iso.year(), iso.week())
    }

    fn next_utc_midnight_secs() -> u64 {
        let now = Utc::now();
        let tomorrow = now.date_naive().succ_opt().unwrap_or(now.date_naive());
        tomorrow
            .and_hms_opt(0, 0, 0)
            .map(|dt| dt.and_utc().timestamp() as u64)
            .unwrap_or(Self::now_secs())
    }

    fn rewards_asset_id(&self) -> Option<[u8; 32]> {
        self.treasury
            .as_ref()
            .map(|t| t.rewards_asset_id)
            .or(self.configured_asset_id)
    }

    fn require_rewards_asset_id(&self) -> Result<[u8; 32], ZhtpResponse> {
        self.rewards_asset_id()
            .ok_or_else(Self::unavailable)
    }

    // ── handlers ─────────────────────────────────────────────────────

    async fn handle_claim(&self, request: ZhtpRequest) -> ZhtpResponse {
        if self.treasury.is_none() {
            return Self::unavailable();
        }
        let req: ClaimRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => return Self::bad(format!("invalid request body: {}", e)),
        };
        let key_id = match Self::validate_did(&req.did) {
            Ok(k) => k,
            Err(msg) => return Self::bad(msg),
        };
        let spec = match req.event.as_str() {
            "welcome" => settlement::ClaimSpec::welcome(),
            "daily_checkin" => settlement::ClaimSpec::daily_checkin(),
            "active_session" => settlement::ClaimSpec::active_session(),
            other => return Self::bad(format!("unknown event type: '{}'", other)),
        };
        self.execute_claim(&req.did, key_id, spec).await
    }

    fn claim_ineligible_response(
        spec: &settlement::ClaimSpec,
        reason: &str,
        partners_this_week: Option<u32>,
    ) -> ZhtpResponse {
        let mut body = json!({
            "awarded": false,
            "amount": "0",
            "reason": reason,
        });
        if let Some(obj) = body.as_object_mut() {
            if matches!(
                spec.event,
                RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession
            ) {
                obj.insert(
                    "next_eligible_at".into(),
                    json!(Self::next_utc_midnight_secs()),
                );
            }
            if let (RewardEventKind::NewPartner, Some(count)) = (spec.event, partners_this_week) {
                obj.insert("partners_this_week".into(), json!(count));
            }
        }
        Self::ok_json(body)
    }

    fn claim_awarded_response(
        spec: &settlement::ClaimSpec,
        submitted: &settlement::SubmittedClaim,
    ) -> ZhtpResponse {
        let plan = &submitted.plan;
        let mut body = json!({
            "awarded": true,
            "submitted": true,
            "amount": plan.amount.to_string(),
            "amount_display": (plan.amount / ATOM_18).to_string(),
            "event": spec.event_label,
            "tx_hash": submitted.tx_hash,
        });
        if let Some(obj) = body.as_object_mut() {
            if let Some(day) = plan.streak_day {
                obj.insert("streak_day".into(), json!(day));
            }
            if matches!(
                spec.event,
                RewardEventKind::DailyCheckin | RewardEventKind::ActiveSession
            ) {
                obj.insert(
                    "next_eligible_at".into(),
                    json!(Self::next_utc_midnight_secs()),
                );
            }
            if let Some(count) = plan.partners_this_week {
                obj.insert("partners_this_week".into(), json!(count.saturating_add(1)));
            }
            if let Some(cap) = plan.weekly_cap {
                obj.insert("weekly_cap".into(), json!(cap));
            }
        }
        Self::ok_json(body)
    }

    async fn execute_claim(
        &self,
        did: &str,
        key_id: [u8; 32],
        spec: settlement::ClaimSpec,
    ) -> ZhtpResponse {
        let treasury = match self.treasury.as_ref() {
            Some(t) => t,
            None => return Self::unavailable(),
        };

        match settlement::run_claim_flow(&self.blockchain, treasury, did, key_id, &spec).await {
            Ok(submitted) => Self::claim_awarded_response(&spec, &submitted),
            Err(settlement::ClaimFlowError::Ineligible { reason })
            | Err(settlement::ClaimFlowError::Unavailable(reason))
                if reason == "owner_did_not_registered" =>
            {
                ZhtpResponse::error(
                    ZhtpStatus::BadRequest,
                    "identity must be registered on-chain before claiming rewards".to_string(),
                )
            }
            Err(settlement::ClaimFlowError::InsufficientRewardLiquidity { have, need }) => {
                Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "InsufficientRewardLiquidity",
                    "have": have.to_string(),
                    "need": need.to_string(),
                }))
            }
            Err(settlement::ClaimFlowError::Ineligible { reason }) => {
                let partners_this_week = if spec.event == RewardEventKind::NewPartner {
                    let week = Self::iso_week();
                    let bc = self.blockchain.read().await;
                    Some(bc.reward_partners_this_week(
                        &treasury.rewards_asset_id,
                        &week,
                        did,
                    ))
                } else {
                    None
                };
                Self::claim_ineligible_response(&spec, &reason, partners_this_week)
            }
            Err(settlement::ClaimFlowError::Unavailable(reason)) => ZhtpResponse::error(
                ZhtpStatus::ServiceUnavailable,
                format!("rewards claim unavailable: {reason}"),
            ),
            Err(settlement::ClaimFlowError::SubmitFailed(e)) => ZhtpResponse::error(
                ZhtpStatus::InternalServerError,
                format!("reward claim submit failed: {e}"),
            ),
        }
    }

    async fn handle_conversation(&self, request: ZhtpRequest) -> ZhtpResponse {
        if self.treasury.is_none() {
            return Self::unavailable();
        }
        let req: ConversationRequest = match serde_json::from_slice(&request.body) {
            Ok(r) => r,
            Err(e) => return Self::bad(format!("invalid request body: {}", e)),
        };
        if req.did == req.peer_did {
            return Self::bad("peer_did must differ from did");
        }
        let key_id = match Self::validate_did(&req.did) {
            Ok(k) => k,
            Err(msg) => return Self::bad(msg),
        };
        if let Err(msg) = Self::validate_did(&req.peer_did) {
            return Self::bad(format!("peer_did invalid: {}", msg));
        }

        self.execute_claim(
            &req.did,
            key_id,
            settlement::ClaimSpec::new_partner(req.peer_did),
        )
        .await
    }

    async fn handle_balance(&self, did: &str) -> ZhtpResponse {
        let key_id = match Self::validate_did(did) {
            Ok(k) => k,
            Err(msg) => return Self::bad(msg),
        };
        let token_id = match self.require_rewards_asset_id() {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        let bc = self.blockchain.read().await;
        let stats = bc.reward_lifetime_stats(&token_id, did);

        // Spendable balance is on-chain under the holder's key_id.
        let (spendable_balance, asset_id_hex) = match &self.treasury {
            Some(treasury) => {
                let balance = bc
                    .token_balance(&treasury.rewards_asset_id, &key_id)
                    .unwrap_or(0);
                (
                    balance,
                    Some(hex::encode(treasury.rewards_asset_id)),
                )
            }
            None => (0, None),
        };

        let mut body = json!({
            "did": did,
            "total_earned": stats.total_earned.to_string(),
            "total_earned_display": (stats.total_earned / ATOM_18).to_string(),
            "spendable_balance": spendable_balance.to_string(),
            "spendable_balance_display": (spendable_balance / ATOM_18).to_string(),
            "counts": {
                "welcome_claimed": stats.welcome_claimed,
                "checkin_count": stats.checkin_count,
                "session_count": stats.session_count,
                "partner_count": stats.partner_count,
                "current_streak": stats.current_streak,
                "longest_streak": stats.longest_streak,
            },
        });
        if let Some(asset_id) = asset_id_hex {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("asset_id".into(), json!(asset_id));
            }
        }
        Self::ok_json(body)
    }

    async fn handle_status(&self, did: &str) -> ZhtpResponse {
        if let Err(msg) = Self::validate_did(did) {
            return Self::bad(msg);
        }

        let token_id = match self.require_rewards_asset_id() {
            Ok(id) => id,
            Err(resp) => return resp,
        };

        let now = Self::now_secs();
        let date = Self::utc_date();
        let week = Self::iso_week();
        let next_midnight = Self::next_utc_midnight_secs();
        let today_ord = Self::utc_day_ordinal();

        let bc = self.blockchain.read().await;

        // Settlement requires a hot treasury keystore, a rewards module or
        // legacy token contract, AND a resolvable rewards policy (so amounts
        // are non-zero and plan_reward_claim will not fail closed).
        let claims_settleable = self.treasury.is_some()
            && (bc.get_rewards_module_state(&token_id).is_some()
                || bc.get_token_contract(&token_id).is_some())
            && bc
                .reward_expected_amount(&token_id, RewardEventKind::Welcome, 1)
                .is_some_and(|amt| amt > 0);

        let welcome_available =
            claims_settleable && !bc.reward_welcome_claimed(&token_id, did);
        let checkin_done =
            bc.reward_daily_claimed(&token_id, &date, did, RewardEventKind::DailyCheckin);
        let streak = bc.reward_streak(&token_id, did);
        let next_streak = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else if streak.last_day == today_ord {
            streak.current_streak.max(1)
        } else {
            1
        };
        let checkin_amount = bc
            .reward_checkin_amount_for_streak(&token_id, next_streak)
            .unwrap_or(0);
        let welcome_amount = bc
            .reward_expected_amount(&token_id, RewardEventKind::Welcome, 1)
            .unwrap_or(0);
        let session_amount = bc
            .reward_expected_amount(&token_id, RewardEventKind::ActiveSession, 1)
            .unwrap_or(0);
        let partner_amount = bc
            .reward_expected_amount(&token_id, RewardEventKind::NewPartner, 1)
            .unwrap_or(0);

        let session_done =
            bc.reward_daily_claimed(&token_id, &date, did, RewardEventKind::ActiveSession);
        let partners_this_week = bc.reward_partners_this_week(&token_id, &week, did);
        let policy_cap = bc.reward_weekly_partner_cap(&token_id);
        let weekly_cap = if policy_cap > 0 { policy_cap } else { WEEKLY_PARTNER_CAP };

        Self::ok_json(json!({
            "did": did,
            "now": now,
            "claimable": {
                "welcome": {
                    "available": welcome_available,
                    "amount_display": (welcome_amount / ATOM_18).to_string(),
                },
                "daily_checkin": {
                    "available": claims_settleable && !checkin_done,
                    "amount_display": (checkin_amount / ATOM_18).to_string(),
                    "next_streak_day": next_streak,
                    "next_eligible_at": if checkin_done { Some(next_midnight) } else { None },
                },
                "active_session": {
                    "available": claims_settleable && !session_done,
                    "amount_display": (session_amount / ATOM_18).to_string(),
                    "next_eligible_at": if session_done { Some(next_midnight) } else { None },
                },
                "new_partner": {
                    "partners_this_week": partners_this_week,
                    "weekly_cap": weekly_cap,
                    "remaining": weekly_cap.saturating_sub(partners_this_week),
                    "amount_display_per_partner": (partner_amount / ATOM_18).to_string(),
                },
            },
            "current_streak": streak.current_streak,
            "longest_streak": streak.longest_streak,
        }))
    }

    /// Cursor format: `"<at_secs>:<seq>"`. We order events newest-first
    /// by `(at DESC, seq DESC)` and the cursor describes the *last item
    /// of the previous page*. The next page starts strictly **after** it
    /// in reverse order — i.e. events with `(at, seq) <
    /// (cursor_at, cursor_seq)` in lexicographic terms.
    ///
    /// Storing `seq` inside the event (added in the same change as this
    /// pagination fix) lets us tiebreak same-second events deterministically.
    fn parse_cursor(s: &str) -> Option<(u64, u64)> {
        let (a, b) = s.split_once(':')?;
        Some((a.parse().ok()?, b.parse().ok()?))
    }

    async fn handle_history(
        &self,
        did: &str,
        limit: usize,
        cursor: Option<(u64, u64)>,
    ) -> ZhtpResponse {
        // READS don't need the treasury keystore — see `handle_balance`.
        if let Err(msg) = Self::validate_did(did) {
            return Self::bad(msg);
        }
        let limit = limit.min(HISTORY_MAX_LIMIT);

        let token_id = match self.require_rewards_asset_id() {
            Ok(id) => id,
            Err(resp) => return resp,
        };
        let bc = self.blockchain.read().await;
        let cursor_seq = cursor.map(|c| c.1);
        let (page, has_more) = bc.reward_claim_history(&token_id, did, limit, cursor_seq);

        let next_cursor = if has_more {
            page.last().map(|e| format!("{}:{}", e.at, e.seq))
        } else {
            None
        };

        let events: Vec<serde_json::Value> = page
            .iter()
            .map(history_entry_json)
            .collect();

        Self::ok_json(json!({
            "did": did,
            "events": events,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }))
    }

    fn parse_did_from_path(uri: &str, prefix: &str) -> Option<String> {
        let after = uri.strip_prefix(prefix)?;
        let did = after.trim_end_matches('/');
        if did.is_empty() {
            None
        } else {
            // Mobile clients sometimes URL-encode the colons.
            Some(did.replace("%3A", ":").replace("%3a", ":"))
        }
    }

    fn parse_query<'a>(uri: &'a str, key: &str) -> Option<&'a str> {
        let q = uri.split_once('?')?.1;
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key {
                    return Some(v);
                }
            }
        }
        None
    }
}

fn history_entry_json(e: &RewardHistoryEntry) -> serde_json::Value {
    let mut meta = serde_json::Map::new();
    if let Some(d) = e.meta_streak_day {
        meta.insert("streak_day".into(), json!(d));
    }
    if let Some(p) = &e.meta_peer_did {
        meta.insert("peer_did".into(), json!(p));
    }
    let meta_json = if meta.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(meta))
    };
    json!({
        "at": e.at,
        "seq": e.seq,
        "event": e.event,
        "amount": e.amount.to_string(),
        "amount_display": (e.amount / ATOM_18).to_string(),
        "meta": meta_json,
        "tx_hash": e.tx_hash,
    })
}

// ── Trait impl ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl ZhtpRequestHandler for RewardsHandler {
    async fn handle_request(
        &self,
        request: ZhtpRequest,
    ) -> lib_protocols::zhtp::ZhtpResult<ZhtpResponse> {
        // Strip the optional trailing '/' for routing but keep the raw uri
        // available for path-parameter extraction.
        let uri_no_slash = request.uri.trim_end_matches('/').to_string();

        let resp = match (&request.method, uri_no_slash.as_str()) {
            (ZhtpMethod::Post, "/api/v1/rewards/claim") => self.handle_claim(request).await,
            (ZhtpMethod::Post, "/api/v1/rewards/conversation") => {
                self.handle_conversation(request).await
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/rewards/balance/") => {
                match Self::parse_did_from_path(&request.uri, "/api/v1/rewards/balance/") {
                    Some(did) => self.handle_balance(&did).await,
                    None => Self::bad("missing did in path"),
                }
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/rewards/status/") => {
                match Self::parse_did_from_path(&request.uri, "/api/v1/rewards/status/") {
                    Some(did) => self.handle_status(&did).await,
                    None => Self::bad("missing did in path"),
                }
            }
            (ZhtpMethod::Get, path) if path.starts_with("/api/v1/rewards/history/") => {
                let raw_uri = request.uri.clone();
                let did_segment = raw_uri
                    .strip_prefix("/api/v1/rewards/history/")
                    .unwrap_or("")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('/');
                if did_segment.is_empty() {
                    Self::bad("missing did in path")
                } else {
                    let did = did_segment.replace("%3A", ":").replace("%3a", ":");
                    let limit = Self::parse_query(&raw_uri, "limit")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(HISTORY_DEFAULT_LIMIT);
                    // Compound cursor "<at>:<seq>" — tiebreaks same-second
                    // events so adjacent pages can't drop or duplicate.
                    let cursor = Self::parse_query(&raw_uri, "cursor")
                        .and_then(|s| Self::parse_cursor(s));
                    self.handle_history(&did, limit, cursor).await
                }
            }
            _ => ZhtpResponse::error(
                ZhtpStatus::NotFound,
                "Unknown rewards endpoint".to_string(),
            ),
        };
        Ok(resp)
    }

    fn can_handle(&self, request: &ZhtpRequest) -> bool {
        request.uri.starts_with("/api/v1/rewards")
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Resolve the chain_id used to bind a TokenTransfer tx. Mirrors
/// `runtime::token_utils::chain_id_from_env` so reward txes ride the same
/// chain_id as every other server-built tx (testnet=0x02, mainnet=0x03).
pub(crate) fn chain_id_from_env() -> u8 {
    std::env::var("ZHTP_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0x03)
}

// ── Treasury loader ──────────────────────────────────────────────────

fn load_treasury(blockchain: &Blockchain) -> Option<TreasuryConfig> {
    let eligible = crate::rewards_activation::scan_chain_eligible_assets(blockchain);
    if !eligible.is_empty() {
        info!(
            "rewards: chain scan found {} asset(s) with rewards module + funded delegate",
            eligible.len()
        );
        for a in &eligible {
            info!(
                "rewards: eligible asset_id={} delegate={} balance={}",
                hex::encode(&a.asset_id[..8]),
                hex::encode(&a.spend_delegate_key_id[..8]),
                a.delegate_balance
            );
        }
    }

    let activation = crate::rewards_activation::resolve_activation()?;
    load_treasury_from_dir(
        blockchain,
        &activation.delegate_keystore_dir,
        activation.asset_id,
        activation.source,
    )
}

fn load_treasury_from_dir(
    blockchain: &Blockchain,
    path: &PathBuf,
    rewards_asset_id: [u8; 32],
    source: crate::rewards_activation::ActivationSource,
) -> Option<TreasuryConfig> {
    if !path.is_dir() {
        warn!(
            "rewards: keystore path '{}' is not a directory",
            path.display()
        );
        return None;
    }
    let identity_file = path.join(USER_IDENTITY_FILENAME);
    let priv_file = path.join(USER_PRIVATE_KEY_FILENAME);
    let keypair = match load_keypair(&identity_file, &priv_file) {
        Ok(k) => k,
        Err(e) => {
            warn!(
                "rewards: failed to load delegate keystore from {}: {}",
                path.display(),
                e
            );
            return None;
        }
    };
    let signer_key_id = keypair.public_key.key_id;

    if let Err(e) = crate::rewards_activation::validate_activation_against_chain(
        blockchain,
        &rewards_asset_id,
        &signer_key_id,
    ) {
        warn!("rewards: chain-native activation rejected: {e}");
        return None;
    }

    let balance = match blockchain.token_balance(&rewards_asset_id, &signer_key_id) {
        Ok(balance) => balance,
        Err(e) => {
            warn!(
                "rewards: token_balance lookup failed for token {}: {e}",
                hex::encode(&rewards_asset_id[..8]),
            );
            return None;
        }
    };
    if balance == 0 {
        warn!(
            "rewards: delegate keystore at {} holds 0 balance for token {}; endpoint disabled",
            path.display(),
            hex::encode(&rewards_asset_id[..8]),
        );
        return None;
    }
    let source_label = match source {
        crate::rewards_activation::ActivationSource::ConfigFile => "rewards_activation.toml",
    };
    info!(
        "rewards: signer loaded via {source_label} — token_id={} key_id={} balance={}",
        hex::encode(&rewards_asset_id[..8]),
        hex::encode(&signer_key_id[..8]),
        balance,
    );
    Some(TreasuryConfig {
        keypair: Arc::new(keypair),
        rewards_asset_id,
        signer_key_id,
    })
}

fn load_keypair(identity_file: &std::path::Path, priv_file: &std::path::Path) -> Result<KeyPair> {
    let identity_json = std::fs::read_to_string(identity_file)
        .map_err(|e| anyhow!("Failed to read {:?}: {}", identity_file, e))?;
    let priv_json = std::fs::read_to_string(priv_file)
        .map_err(|e| anyhow!("Failed to read {:?}: {}", priv_file, e))?;
    let stored: KeystorePrivateKey = serde_json::from_str(&priv_json)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
    let private_key = PrivateKey {
        dilithium_sk: stored.dilithium_sk,
        dilithium_pk: stored.dilithium_pk,
        kyber_sk: stored.kyber_sk,
        master_seed: stored.master_seed,
    };
    let identity = ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .map_err(|e| anyhow!("Failed to restore identity: {}", e))?;
    // Force `PublicKey` shape; the identity's public_key carries dilithium+kyber+key_id.
    let public_key: PublicKey = identity.public_key;
    Ok(KeyPair {
        public_key,
        private_key,
    })
}

fn decode_token_id(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("hex decode failed: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkin_amount_streak_schedule() {
        assert_eq!(checkin_amount_for_day(1), REWARD_CHECKIN_BASE_ATOMS);
        assert_eq!(
            checkin_amount_for_day(2),
            REWARD_CHECKIN_BASE_ATOMS + REWARD_STREAK_BONUS_PER_DAY_ATOMS
        );
        assert_eq!(
            checkin_amount_for_day(11),
            REWARD_CHECKIN_BASE_ATOMS
                + REWARD_STREAK_BONUS_PER_DAY_ATOMS * (REWARD_STREAK_BONUS_CAP_DAYS as u128)
        );
        assert_eq!(checkin_amount_for_day(99), checkin_amount_for_day(11));
    }

    #[test]
    fn validate_did_accepts_canonical() {
        assert!(RewardsHandler::validate_did(
            "did:zhtp:e0b9757663f55797ff06cdce1d0dc18329455b9a18d8e0b5bc05a8f10c969bf4"
        )
        .is_ok());
    }

    #[test]
    fn validate_did_rejects_bad() {
        for bad in &[
            "",
            "not-a-did",
            "did:other:abc",
            "did:zhtp:tooshort",
            "did:zhtp:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(
                RewardsHandler::validate_did(bad).is_err(),
                "expected rejection for {:?}",
                bad
            );
        }
    }

    #[test]
    fn iso_week_format_is_yyyy_w_nn() {
        let w = RewardsHandler::iso_week();
        let parts: Vec<&str> = w.splitn(2, "-W").collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<i32>().is_ok());
        assert_eq!(parts[1].len(), 2);
        assert!(parts[1].parse::<u8>().is_ok());
    }
}
