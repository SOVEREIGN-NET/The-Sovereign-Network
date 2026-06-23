//! BUBL rewards endpoints.
//!
//! Inline-mint reward distribution from the BUBL treasury identity to
//! end-user DIDs. Server-enforced caps; no body signing required (see
//! `notifications/mod.rs` for the same rationale).
//!
//! ## Configuration
//!
//! Activated by the `ZHTP_REWARDS_TREASURY_KEYSTORE` environment variable
//! pointing at a directory containing `user_identity.json` +
//! `user_private_key.json` for the treasury identity. Without that env
//! var the handler installs but every endpoint returns 503. Currently we
//! ship this with the keystore present **on g1 only**; the other
//! validators 503 so /rewards/* requests have a single source of truth
//! and the treasury key has exactly one exposure surface.
//!
//! ## Storage
//!
//! Sled DB under `node_data_dir()/rewards.sled`. Trees:
//! - `welcomed`         — set of DIDs that have claimed the one-shot
//!                        welcome bonus. value = unix-secs of claim.
//! - `checkins`         — `{utc_date_str}|{did}` → 1u8. Day-keyed dedup.
//! - `sessions`         — same shape, for active-session reward.
//! - `streak`           — did → bincode(StreakState).
//! - `partners`         — `{iso_week_str}|{did}|{peer_did}` → 1u8.
//!                        Compound key gives O(1) "have we counted this
//!                        peer this week" check.
//! - `partners_count`   — `{iso_week_str}|{did}` → u32-le count. Lets us
//!                        enforce the 5-per-week cap without iterating.
//! - `history`          — `{did}|{seq_u64_be}` → bincode(RewardEvent).
//!                        Iterating rev() yields newest first.
//! - `history_seq`      — `next` → u64-le. Monotonic counter for the
//!                        history tree's secondary key.
//! - `lifetime`         — did → bincode(LifetimeStats). Totals + counts
//!                        + longest streak so the balance endpoint
//!                        doesn't have to re-scan history every call.

use anyhow::{anyhow, Result};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use lib_blockchain::transaction::{Transaction, TokenTransferData};
use lib_blockchain::Blockchain;
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::keys::{PrivateKey, PublicKey};
use lib_crypto::Signature;
use lib_identity::ZhtpIdentity;
use lib_protocols::types::{ZhtpMethod, ZhtpRequest, ZhtpResponse, ZhtpStatus};
use lib_protocols::zhtp::ZhtpRequestHandler;

use crate::keyfile_names::{KeystorePrivateKey, USER_IDENTITY_FILENAME, USER_PRIVATE_KEY_FILENAME};

// ── Constants ────────────────────────────────────────────────────────

/// BUBL token id — derived deterministically from CBE-style name+symbol
/// hash at deploy time. Hard-coded here because rewards must keep
/// pointing at the same token across validator restarts and even across
/// today's testnet reset (the reset will preserve the deterministic id).
const BUBL_TOKEN_ID_HEX: &str =
    "f5aff42a31e17656ecab4b01cc2aea15025d813a3109c98b8f1a55378802f82d";

/// 18-decimal atom multiplier.
const ATOM_18: u128 = 1_000_000_000_000_000_000;

/// Welcome bonus — 100 BUBL, once per DID lifetime.
const REWARD_WELCOME: u128 = 100 * ATOM_18;
/// Base daily check-in reward — 10 BUBL plus streak bonus.
const REWARD_CHECKIN_BASE: u128 = 10 * ATOM_18;
/// Per-day streak bonus, capped at +10 BUBL.
const REWARD_STREAK_BONUS_PER_DAY: u128 = 1 * ATOM_18;
const REWARD_STREAK_BONUS_CAP_DAYS: u32 = 10;
/// Active-session reward — 2 BUBL, once per UTC day per DID.
const REWARD_ACTIVE_SESSION: u128 = 2 * ATOM_18;
/// New-conversation-partner reward — 20 BUBL per distinct peer per ISO week.
const REWARD_NEW_PARTNER: u128 = 20 * ATOM_18;
/// Weekly cap on new-partner rewards.
const WEEKLY_PARTNER_CAP: u32 = 5;

const HISTORY_DEFAULT_LIMIT: usize = 50;
const HISTORY_MAX_LIMIT: usize = 200;
const MAX_DID_LEN: usize = 256;

/// Sentinel value written into a reservation slot via `compare_and_swap`
/// before the mint, then either overwritten with the real marker on
/// success or removed on mint failure. Any non-empty byte is sufficient —
/// `compare_and_swap` distinguishes `None` from `Some(_)` only.
const SLOT_PENDING: &[u8] = b"P";

const TREE_WELCOMED: &str = "welcomed";
const TREE_CHECKINS: &str = "checkins";
const TREE_SESSIONS: &str = "sessions";
const TREE_STREAK: &str = "streak";
const TREE_PARTNERS: &str = "partners";
const TREE_PARTNERS_COUNT: &str = "partners_count";
const TREE_HISTORY: &str = "history";
const TREE_HISTORY_SEQ: &str = "history_seq";
const TREE_LIFETIME: &str = "lifetime";

const HISTORY_SEQ_KEY: &str = "next";
const SEPARATOR: u8 = 0x1f; // ASCII unit-separator — unlikely in any DID string

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

// ── Stored types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StreakState {
    /// UTC ordinal day (days since CE) of the last check-in.
    last_day: i32,
    current_streak: u32,
    longest_streak: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LifetimeStats {
    total_earned: u128,
    welcome_claimed: bool,
    checkin_count: u64,
    session_count: u64,
    partner_count: u64,
    current_streak: u32,
    longest_streak: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RewardEvent {
    at: u64,
    /// Monotonic per-server seq; used together with `at` as the pagination
    /// cursor so same-second events don't collide on the page boundary.
    #[serde(default)]
    seq: u64,
    event: String,
    amount: u128,
    tx_hash: String,
    /// streak_day for daily_checkin; peer_did for new_partner.
    meta_streak_day: Option<u32>,
    meta_peer_did: Option<String>,
}

// ── Handler ──────────────────────────────────────────────────────────

pub struct RewardsHandler {
    blockchain: Arc<RwLock<Blockchain>>,
    /// None when the treasury keystore env var is unset or load failed.
    /// All POST/GET endpoints return 503 in that case.
    treasury: Option<TreasuryConfig>,
    welcomed: sled::Tree,
    checkins: sled::Tree,
    sessions: sled::Tree,
    streak: sled::Tree,
    partners: sled::Tree,
    partners_count: sled::Tree,
    history: sled::Tree,
    history_seq: sled::Tree,
    lifetime: sled::Tree,
}

#[derive(Clone)]
struct TreasuryConfig {
    keypair: Arc<KeyPair>,
    bubl_token_id: [u8; 32],
    /// `keypair.public_key.key_id` — the combined-derivation key_id
    /// (`blake3(dilithium || kyber)`) the chain stores BUBL balances under
    /// for the creator allocation.
    signer_key_id: [u8; 32],
}

impl RewardsHandler {
    pub fn new(blockchain: Arc<RwLock<Blockchain>>) -> Result<Self> {
        let path = crate::node_data_dir().join("rewards.sled");
        let db = sled::open(&path)
            .map_err(|e| anyhow!("Failed to open rewards sled at {:?}: {}", path, e))?;
        let welcomed = db.open_tree(TREE_WELCOMED)?;
        let checkins = db.open_tree(TREE_CHECKINS)?;
        let sessions = db.open_tree(TREE_SESSIONS)?;
        let streak = db.open_tree(TREE_STREAK)?;
        let partners = db.open_tree(TREE_PARTNERS)?;
        let partners_count = db.open_tree(TREE_PARTNERS_COUNT)?;
        let history = db.open_tree(TREE_HISTORY)?;
        let history_seq = db.open_tree(TREE_HISTORY_SEQ)?;
        let lifetime = db.open_tree(TREE_LIFETIME)?;

        // Startup-time lookup: read the BUBL token contract under a non-async
        // borrow of the blockchain (RewardsHandler::new is sync). The
        // blockchain Arc is shared; at startup no API traffic is yet
        // dispatched, so `blocking_read` here is uncontended. Wrapped in
        // `block_in_place` so the runtime can park the worker.
        let treasury = tokio::task::block_in_place(|| {
            let bc = blockchain.blocking_read();
            load_treasury(&bc)
        });

        if treasury.is_some() {
            info!(
                "Rewards: signer keystore loaded with positive BUBL balance — endpoints active at {:?}",
                path
            );
        } else {
            info!(
                "Rewards: ZHTP_REWARDS_TREASURY_KEYSTORE unset, invalid, or holds 0 BUBL — /api/v1/rewards/* will return 503 on this node"
            );
        }

        Ok(Self {
            blockchain,
            treasury,
            welcomed,
            checkins,
            sessions,
            streak,
            partners,
            partners_count,
            history,
            history_seq,
            lifetime,
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

    fn day_compound_key(date: &str, did: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(date.len() + 1 + did.len());
        k.extend_from_slice(date.as_bytes());
        k.push(SEPARATOR);
        k.extend_from_slice(did.as_bytes());
        k
    }

    fn partner_compound_key(week: &str, did: &str, peer_did: &str) -> Vec<u8> {
        let mut k =
            Vec::with_capacity(week.len() + 1 + did.len() + 1 + peer_did.len());
        k.extend_from_slice(week.as_bytes());
        k.push(SEPARATOR);
        k.extend_from_slice(did.as_bytes());
        k.push(SEPARATOR);
        k.extend_from_slice(peer_did.as_bytes());
        k
    }

    fn partners_count_key(week: &str, did: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(week.len() + 1 + did.len());
        k.extend_from_slice(week.as_bytes());
        k.push(SEPARATOR);
        k.extend_from_slice(did.as_bytes());
        k
    }

    fn streak_bonus_for_day(streak_day: u32) -> u128 {
        let bonus_days = streak_day.saturating_sub(1).min(REWARD_STREAK_BONUS_CAP_DAYS);
        REWARD_STREAK_BONUS_PER_DAY * (bonus_days as u128)
    }

    fn checkin_amount_for_day(streak_day: u32) -> u128 {
        REWARD_CHECKIN_BASE + Self::streak_bonus_for_day(streak_day)
    }

    // ── core operations ──────────────────────────────────────────────

    /// Reserve the next history sequence number atomically.
    fn next_history_seq(&self) -> Result<u64> {
        let updated = self
            .history_seq
            .update_and_fetch(HISTORY_SEQ_KEY, |old: Option<&[u8]>| {
                let prev = old
                    .and_then(|b| b.try_into().ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(0);
                Some(prev.saturating_add(1).to_le_bytes().to_vec())
            })?
            .ok_or_else(|| anyhow!("history_seq update returned None"))?;
        let arr: [u8; 8] = updated
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("history_seq value not 8 bytes"))?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Append an event to history + bump lifetime stats. Best-effort
    /// (errors logged, not propagated to caller — the BUBL has already
    /// been minted by this point so user-facing UX shouldn't break for a
    /// sled hiccup).
    fn record_event(
        &self,
        did: &str,
        mut event: RewardEvent,
        update_lifetime: impl FnOnce(&mut LifetimeStats),
    ) {
        let seq = match self.next_history_seq() {
            Ok(s) => s,
            Err(e) => {
                warn!("rewards: history seq alloc failed: {}", e);
                return;
            }
        };
        event.seq = seq;
        let mut key = Vec::with_capacity(did.len() + 1 + 8);
        key.extend_from_slice(did.as_bytes());
        key.push(SEPARATOR);
        key.extend_from_slice(&seq.to_be_bytes());
        match bincode::serialize(&event) {
            Ok(bytes) => {
                if let Err(e) = self.history.insert(&key, bytes) {
                    warn!("rewards: history insert failed: {}", e);
                }
            }
            Err(e) => warn!("rewards: history serialize failed: {}", e),
        }

        // Update lifetime stats.
        let mut stats = self.load_lifetime(did);
        stats.total_earned = stats.total_earned.saturating_add(event.amount);
        update_lifetime(&mut stats);
        if let Ok(bytes) = bincode::serialize(&stats) {
            let _ = self.lifetime.insert(did.as_bytes(), bytes);
        }
    }

    fn load_lifetime(&self, did: &str) -> LifetimeStats {
        match self.lifetime.get(did.as_bytes()) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
            _ => LifetimeStats::default(),
        }
    }

    fn load_streak(&self, did: &str) -> StreakState {
        match self.streak.get(did.as_bytes()) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes).unwrap_or_default(),
            _ => StreakState::default(),
        }
    }

    fn save_streak(&self, did: &str, state: &StreakState) -> Result<()> {
        let bytes = bincode::serialize(state)?;
        self.streak.insert(did.as_bytes(), bytes)?;
        Ok(())
    }

    fn count_partners_this_week(&self, did: &str) -> u32 {
        let week = Self::iso_week();
        let key = Self::partners_count_key(&week, did);
        self.partners_count
            .get(&key)
            .ok()
            .flatten()
            .and_then(|v| v.as_ref().try_into().ok().map(u32::from_le_bytes))
            .unwrap_or(0)
    }

    /// Build, sign, and submit a TokenTransfer from the BUBL creator
    /// (= the loaded rewards keystore) → recipient. Returns the tx hash hex
    /// on success.
    ///
    /// The keystore configured via `ZHTP_REWARDS_TREASURY_KEYSTORE` MUST be
    /// the keypair that signed the original BUBL `TokenCreation` transaction.
    /// At deploy time TokenCreation credits the creator's `creator_allocation`
    /// to the creator's full `PublicKey`, so a normal TokenTransfer signed by
    /// the same keypair can debit it. The "treasury" 20 % allocation is
    /// minted to `PublicKey { dilithium_pk: [0; 2592], kyber_pk: [0; 1568],
    /// key_id: treasury_recipient }` (an unsignable address — see
    /// `lib-blockchain/src/blockchain/contracts.rs:688-692`) and is therefore
    /// inaccessible by design. Rewards are funded out of the creator share.
    async fn mint_to_user(&self, recipient_key_id: [u8; 32], amount: u128) -> Result<String> {
        let treasury = self
            .treasury
            .as_ref()
            .ok_or_else(|| anyhow!("rewards treasury not configured"))?;

        // Chain enforces strict per-(token, from) nonce equality via
        // `is_nonce_current` (`blockchain.rs:2262-2290`). Read the expected
        // nonce inside the same read-lock window we hold for submission. The
        // write-lock during `add_pending_transaction` below serialises
        // concurrent claims so this read-then-use is safe.
        let nonce = {
            let bc = self.blockchain.read().await;
            bc.get_token_nonce(&treasury.bubl_token_id, &treasury.signer_key_id)
        };

        let data = TokenTransferData {
            token_id: treasury.bubl_token_id,
            from: treasury.signer_key_id,
            to: recipient_key_id,
            amount,
            nonce,
        };

        let mut tx = Transaction::new_token_transfer_with_chain_id(
            chain_id_from_env(),
            data,
            Signature::default(),
            b"bubl:reward:v1".to_vec(),
        );
        let sig = treasury
            .keypair
            .sign(tx.signing_hash().as_bytes())
            .map_err(|e| anyhow!("rewards sign failed: {}", e))?;
        // No PublicKey mutation: `data.from = signer_key_id =
        // keypair.public_key.key_id`, kyber_pk is the keystore's real kyber,
        // and the key_id binding check at `validation.rs:1170-1192` expects
        // `blake3(dilithium || kyber)` when kyber is non-zero — which is how
        // `KeyPair::new` derives `public_key.key_id` in the first place. The
        // `balance_of(&sender_pk)` lookup at `contracts.rs:374` then matches
        // the creator-allocation entry written by `TokenCreation`.
        tx.signature = sig;

        let tx_hash = hex::encode(tx.hash().as_bytes());
        let mut bc = self.blockchain.write().await;
        bc.add_pending_transaction(tx)
            .map_err(|e| anyhow!("Failed to submit reward tx: {}", e))?;
        Ok(tx_hash)
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
        match req.event.as_str() {
            "welcome" => self.do_welcome(&req.did, key_id).await,
            "daily_checkin" => self.do_daily_checkin(&req.did, key_id).await,
            "active_session" => self.do_active_session(&req.did, key_id).await,
            other => Self::bad(format!("unknown event type: '{}'", other)),
        }
    }

    async fn do_welcome(&self, did: &str, key_id: [u8; 32]) -> ZhtpResponse {
        // Atomically reserve the welcome slot BEFORE minting. The previous
        // `get` → mint → `insert` sequence let two concurrent claims both
        // pass the check and double-mint. CAS the slot from `None` to a
        // pending sentinel; rivals see Some(_) and bail with
        // `welcome_already_claimed`. If the mint fails afterwards we
        // release the slot so retries succeed.
        match self.welcomed.compare_and_swap(
            did.as_bytes(),
            None::<&[u8]>,
            Some(SLOT_PENDING),
        ) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "welcome_already_claimed",
                }));
            }
            Err(e) => {
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("welcome reservation failed: {}", e),
                );
            }
        }
        let tx_hash = match self.mint_to_user(key_id, REWARD_WELCOME).await {
            Ok(h) => h,
            Err(e) => {
                // Release the pending slot so the next attempt can retry.
                let _ = self.welcomed.remove(did.as_bytes());
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("mint failed: {}", e),
                );
            }
        };
        let now = Self::now_secs();
        let _ = self.welcomed.insert(did.as_bytes(), &now.to_le_bytes());

        let event = RewardEvent { seq: 0, // filled by record_event below
            at: now,
            event: "welcome".into(),
            amount: REWARD_WELCOME,
            tx_hash: tx_hash.clone(),
            meta_streak_day: None,
            meta_peer_did: None,
        };
        self.record_event(did, event, |s| s.welcome_claimed = true);

        Self::ok_json(json!({
            "awarded": true,
            "amount": REWARD_WELCOME.to_string(),
            "amount_display": (REWARD_WELCOME / ATOM_18).to_string(),
            "event": "welcome",
            "tx_hash": tx_hash,
        }))
    }

    async fn do_daily_checkin(&self, did: &str, key_id: [u8; 32]) -> ZhtpResponse {
        let date = Self::utc_date();
        let key = Self::day_compound_key(&date, did);

        // CAS-reserve today's slot before doing any work. See `do_welcome`
        // for rationale — same race fix.
        match self
            .checkins
            .compare_and_swap(&key, None::<&[u8]>, Some(SLOT_PENDING))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "checkin_already_claimed_today",
                    "next_eligible_at": Self::next_utc_midnight_secs(),
                }));
            }
            Err(e) => {
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("checkin reservation failed: {}", e),
                );
            }
        }

        // Compute streak: consecutive if last_day == today-1, else reset to 1.
        let today_ord = Self::utc_day_ordinal();
        let mut streak = self.load_streak(did);
        let next_streak = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else {
            1
        };
        let amount = Self::checkin_amount_for_day(next_streak);

        let tx_hash = match self.mint_to_user(key_id, amount).await {
            Ok(h) => h,
            Err(e) => {
                let _ = self.checkins.remove(&key);
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("mint failed: {}", e),
                );
            }
        };

        // Promote the pending slot to a permanent marker.
        let _ = self.checkins.insert(&key, &[1u8]);

        // Update streak state.
        streak.last_day = today_ord;
        streak.current_streak = next_streak;
        if next_streak > streak.longest_streak {
            streak.longest_streak = next_streak;
        }
        let _ = self.save_streak(did, &streak);

        let now = Self::now_secs();
        let event = RewardEvent { seq: 0, // filled by record_event below
            at: now,
            event: "daily_checkin".into(),
            amount,
            tx_hash: tx_hash.clone(),
            meta_streak_day: Some(next_streak),
            meta_peer_did: None,
        };
        let streak_snapshot = next_streak;
        let longest_snapshot = streak.longest_streak;
        self.record_event(did, event, move |s| {
            s.checkin_count = s.checkin_count.saturating_add(1);
            s.current_streak = streak_snapshot;
            s.longest_streak = longest_snapshot;
        });

        Self::ok_json(json!({
            "awarded": true,
            "amount": amount.to_string(),
            "amount_display": (amount / ATOM_18).to_string(),
            "event": "daily_checkin",
            "streak_day": next_streak,
            "tx_hash": tx_hash,
            "next_eligible_at": Self::next_utc_midnight_secs(),
        }))
    }

    async fn do_active_session(&self, did: &str, key_id: [u8; 32]) -> ZhtpResponse {
        let date = Self::utc_date();
        let key = Self::day_compound_key(&date, did);

        // CAS-reserve today's slot (see `do_welcome` for the race rationale).
        match self
            .sessions
            .compare_and_swap(&key, None::<&[u8]>, Some(SLOT_PENDING))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "session_already_claimed_today",
                    "next_eligible_at": Self::next_utc_midnight_secs(),
                }));
            }
            Err(e) => {
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("session reservation failed: {}", e),
                );
            }
        }

        let tx_hash = match self.mint_to_user(key_id, REWARD_ACTIVE_SESSION).await {
            Ok(h) => h,
            Err(e) => {
                let _ = self.sessions.remove(&key);
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("mint failed: {}", e),
                );
            }
        };
        let _ = self.sessions.insert(&key, &[1u8]);

        let now = Self::now_secs();
        let event = RewardEvent { seq: 0, // filled by record_event below
            at: now,
            event: "active_session".into(),
            amount: REWARD_ACTIVE_SESSION,
            tx_hash: tx_hash.clone(),
            meta_streak_day: None,
            meta_peer_did: None,
        };
        self.record_event(did, event, |s| {
            s.session_count = s.session_count.saturating_add(1);
        });

        Self::ok_json(json!({
            "awarded": true,
            "amount": REWARD_ACTIVE_SESSION.to_string(),
            "amount_display": (REWARD_ACTIVE_SESSION / ATOM_18).to_string(),
            "event": "active_session",
            "tx_hash": tx_hash,
            "next_eligible_at": Self::next_utc_midnight_secs(),
        }))
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

        let week = Self::iso_week();
        let already_key = Self::partner_compound_key(&week, &req.did, &req.peer_did);
        let count_key = Self::partners_count_key(&week, &req.did);

        // Atomically reserve the (week, did, peer) slot. Same-peer twice in
        // the same week gets rejected here. Concurrent requests for two
        // different peers will both pass this gate — the count CAS below
        // handles the weekly cap.
        match self
            .partners
            .compare_and_swap(&already_key, None::<&[u8]>, Some(SLOT_PENDING))
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "partner_already_counted_this_week",
                    "partners_this_week": self.count_partners_this_week(&req.did),
                }));
            }
            Err(e) => {
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("partner reservation failed: {}", e),
                );
            }
        }

        // Spin-CAS the weekly count to enforce the cap atomically.
        // `update_and_fetch` would also work but conflates "no change"
        // with "delete" via its `Option` return.
        let new_count = loop {
            let current_iv = match self.partners_count.get(&count_key) {
                Ok(v) => v,
                Err(e) => {
                    let _ = self.partners.remove(&already_key);
                    return ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        format!("partner count read failed: {}", e),
                    );
                }
            };
            let current = current_iv
                .as_ref()
                .and_then(|v| <[u8; 4]>::try_from(v.as_ref()).ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0);
            if current >= WEEKLY_PARTNER_CAP {
                let _ = self.partners.remove(&already_key);
                return Self::ok_json(json!({
                    "awarded": false,
                    "amount": "0",
                    "reason": "weekly_partner_cap_reached",
                    "partners_this_week": WEEKLY_PARTNER_CAP,
                }));
            }
            let next = current.saturating_add(1);
            match self.partners_count.compare_and_swap(
                &count_key,
                current_iv.as_deref(),
                Some(&next.to_le_bytes()),
            ) {
                Ok(Ok(())) => break next,
                Ok(Err(_)) => continue, // racer mutated count; retry
                Err(e) => {
                    let _ = self.partners.remove(&already_key);
                    return ZhtpResponse::error(
                        ZhtpStatus::InternalServerError,
                        format!("partner count CAS failed: {}", e),
                    );
                }
            }
        };

        let tx_hash = match self.mint_to_user(key_id, REWARD_NEW_PARTNER).await {
            Ok(h) => h,
            Err(e) => {
                // Roll back both the slot reservation and the count.
                let _ = self.partners.remove(&already_key);
                let _ = self
                    .partners_count
                    .insert(&count_key, &new_count.saturating_sub(1).to_le_bytes());
                return ZhtpResponse::error(
                    ZhtpStatus::InternalServerError,
                    format!("mint failed: {}", e),
                );
            }
        };

        // Promote the pending reservation to a permanent marker.
        let _ = self.partners.insert(&already_key, &[1u8]);

        let now = Self::now_secs();
        let event = RewardEvent { seq: 0, // filled by record_event below
            at: now,
            event: "new_partner".into(),
            amount: REWARD_NEW_PARTNER,
            tx_hash: tx_hash.clone(),
            meta_streak_day: None,
            meta_peer_did: Some(req.peer_did.clone()),
        };
        self.record_event(&req.did, event, |s| {
            s.partner_count = s.partner_count.saturating_add(1);
        });

        Self::ok_json(json!({
            "awarded": true,
            "amount": REWARD_NEW_PARTNER.to_string(),
            "amount_display": (REWARD_NEW_PARTNER / ATOM_18).to_string(),
            "event": "new_partner",
            "partners_this_week": new_count,
            "tx_hash": tx_hash,
        }))
    }

    async fn handle_balance(&self, did: &str) -> ZhtpResponse {
        // READS don't need the treasury keystore — only mints/claims do.
        // The 503 here was wrong: it told every non-treasury node "rewards
        // endpoint not configured", even though local sled has whatever
        // counters this node has accumulated. Returning the local state
        // (zeros for nodes that haven't processed claims) is at least
        // an honest answer; the proper architectural fix is to read the
        // canonical BUBL balance from the on-chain token contract and
        // move reward-event state on-chain too.
        if let Err(msg) = Self::validate_did(did) {
            return Self::bad(msg);
        }
        let stats = self.load_lifetime(did);
        Self::ok_json(json!({
            "did": did,
            "total_earned": stats.total_earned.to_string(),
            "total_earned_display": (stats.total_earned / ATOM_18).to_string(),
            "counts": {
                "welcome_claimed": stats.welcome_claimed,
                "checkin_count": stats.checkin_count,
                "session_count": stats.session_count,
                "partner_count": stats.partner_count,
                "current_streak": stats.current_streak,
                "longest_streak": stats.longest_streak,
            },
        }))
    }

    async fn handle_status(&self, did: &str) -> ZhtpResponse {
        // READS don't need the treasury keystore — see `handle_balance`.
        if let Err(msg) = Self::validate_did(did) {
            return Self::bad(msg);
        }

        let now = Self::now_secs();
        let date = Self::utc_date();
        let next_midnight = Self::next_utc_midnight_secs();

        let welcome_available = !matches!(self.welcomed.get(did.as_bytes()), Ok(Some(_)));

        let checkin_done = matches!(
            self.checkins.get(&Self::day_compound_key(&date, did)),
            Ok(Some(_))
        );
        let streak = self.load_streak(did);
        let today_ord = Self::utc_day_ordinal();
        let next_streak = if streak.last_day == today_ord - 1 {
            streak.current_streak.saturating_add(1)
        } else if streak.last_day == today_ord {
            // already checked in today — show what TODAY's value was
            streak.current_streak.max(1)
        } else {
            1
        };
        let checkin_amount = Self::checkin_amount_for_day(next_streak);

        let session_done = matches!(
            self.sessions.get(&Self::day_compound_key(&date, did)),
            Ok(Some(_))
        );

        let partners_this_week = self.count_partners_this_week(did);

        Self::ok_json(json!({
            "did": did,
            "now": now,
            "claimable": {
                "welcome": {
                    "available": welcome_available,
                    "amount_display": (REWARD_WELCOME / ATOM_18).to_string(),
                },
                "daily_checkin": {
                    "available": !checkin_done,
                    "amount_display": (checkin_amount / ATOM_18).to_string(),
                    "next_streak_day": next_streak,
                    "next_eligible_at": if checkin_done { Some(next_midnight) } else { None },
                },
                "active_session": {
                    "available": !session_done,
                    "amount_display": (REWARD_ACTIVE_SESSION / ATOM_18).to_string(),
                    "next_eligible_at": if session_done { Some(next_midnight) } else { None },
                },
                "new_partner": {
                    "partners_this_week": partners_this_week,
                    "weekly_cap": WEEKLY_PARTNER_CAP,
                    "remaining": WEEKLY_PARTNER_CAP.saturating_sub(partners_this_week),
                    "amount_display_per_partner": (REWARD_NEW_PARTNER / ATOM_18).to_string(),
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

        let mut prefix = did.as_bytes().to_vec();
        prefix.push(SEPARATOR);

        // History keys are `<did>|<seq_be8>` and seq is allocated
        // monotonically by `next_history_seq`, so reverse range iteration
        // already yields events newest-first by seq. The page we want is
        // the first `limit` events strictly below the cursor's seq —
        // bound the range with an exclusive upper key built from the
        // cursor so sled skips the newer entries instead of us loading
        // and discarding them.
        let cseq = cursor.map(|c| c.1).unwrap_or(u64::MAX);
        let mut upper = prefix.clone();
        upper.extend_from_slice(&cseq.to_be_bytes());

        let mut page: Vec<RewardEvent> = Vec::with_capacity(limit);
        let mut has_more = false;
        for kv in self.history.range(prefix.clone()..upper).rev() {
            let (_k, v) = match kv {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let event = match bincode::deserialize::<RewardEvent>(&v) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if page.len() == limit {
                has_more = true;
                break;
            }
            page.push(event);
        }

        let next_cursor = if has_more {
            page.last().map(|e| format!("{}:{}", e.at, e.seq))
        } else {
            None
        };

        let events: Vec<serde_json::Value> = page
            .iter()
            .map(|e| {
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
            })
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
fn chain_id_from_env() -> u8 {
    std::env::var("ZHTP_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0x03)
}

// ── Treasury loader ──────────────────────────────────────────────────

fn load_treasury(blockchain: &Blockchain) -> Option<TreasuryConfig> {
    let dir = std::env::var("ZHTP_REWARDS_TREASURY_KEYSTORE").ok()?;
    let path = PathBuf::from(&dir);
    if !path.is_dir() {
        warn!(
            "rewards: ZHTP_REWARDS_TREASURY_KEYSTORE='{}' is not a directory",
            dir
        );
        return None;
    }
    let identity_file = path.join(USER_IDENTITY_FILENAME);
    let priv_file = path.join(USER_PRIVATE_KEY_FILENAME);
    let keypair = match load_keypair(&identity_file, &priv_file) {
        Ok(k) => k,
        Err(e) => {
            warn!(
                "rewards: failed to load treasury keystore from {}: {}",
                dir, e
            );
            return None;
        }
    };
    let bubl_token_id = match decode_token_id(BUBL_TOKEN_ID_HEX) {
        Ok(id) => id,
        Err(e) => {
            warn!("rewards: invalid BUBL token id constant: {}", e);
            return None;
        }
    };
    let signer_key_id = keypair.public_key.key_id;

    // Verify the keystore actually holds spendable BUBL. The BUBL token
    // contract minted the 20 % "treasury" share to an unsignable PublicKey
    // (zero dilithium + zero kyber) by design — see
    // `lib-blockchain/src/blockchain/contracts.rs:688-692`. Only the BUBL
    // creator (the entity that signed the original TokenCreation tx) holds
    // a real PublicKey-backed BUBL balance and can debit it via
    // TokenTransfer. If the loaded keystore lacks a positive balance, refuse
    // to enable rewards rather than queue txes that will fail on every
    // future replay.
    if blockchain.get_token_contract(&bubl_token_id).is_none() {
        warn!(
            "rewards: BUBL token contract {} not found on chain; \
             rewards endpoint disabled",
            hex::encode(&bubl_token_id[..4]),
        );
        return None;
    }
    let balance = blockchain
        .token_balance(&bubl_token_id, &signer_key_id)
        .unwrap_or(0);
    if balance == 0 {
        warn!(
            "rewards: keystore at {} holds 0 BUBL for signer key_id={}. \
             This keystore is NOT the BUBL creator and cannot fund rewards. \
             Point ZHTP_REWARDS_TREASURY_KEYSTORE at the keystore that \
             signed the BUBL TokenCreation. Rewards endpoint disabled.",
            dir,
            hex::encode(&signer_key_id[..8]),
        );
        return None;
    }
    info!(
        "rewards: signer loaded — key_id={} BUBL balance={} ({} BUBL)",
        hex::encode(&signer_key_id[..8]),
        balance,
        balance / ATOM_18,
    );
    Some(TreasuryConfig {
        keypair: Arc::new(keypair),
        bubl_token_id,
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
        // Day 1: base only.
        assert_eq!(
            RewardsHandler::checkin_amount_for_day(1),
            REWARD_CHECKIN_BASE
        );
        // Day 2: base + 1 bonus day.
        assert_eq!(
            RewardsHandler::checkin_amount_for_day(2),
            REWARD_CHECKIN_BASE + REWARD_STREAK_BONUS_PER_DAY
        );
        // Day 11: capped at +10.
        assert_eq!(
            RewardsHandler::checkin_amount_for_day(11),
            REWARD_CHECKIN_BASE
                + REWARD_STREAK_BONUS_PER_DAY * (REWARD_STREAK_BONUS_CAP_DAYS as u128)
        );
        // Day 99: still capped at +10.
        assert_eq!(
            RewardsHandler::checkin_amount_for_day(99),
            RewardsHandler::checkin_amount_for_day(11)
        );
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
