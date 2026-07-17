//! BUBL reward claim transaction payload and canonical reward constants.
//!
//! Reward eligibility is enforced on-chain at the executor; validators submit
//! signed `RewardClaim` transactions instead of bare `TokenTransfer`s.

use chrono::Datelike;
use serde::{Deserialize, Serialize};

/// 18-decimal atom multiplier for BUBL.
pub const BUBL_ATOM_18: u128 = 1_000_000_000_000_000_000;

/// Welcome bonus — 100 BUBL, once per DID lifetime.
pub const REWARD_WELCOME_ATOMS: u128 = 100 * BUBL_ATOM_18;
/// Base daily check-in reward — 10 BUBL plus streak bonus.
pub const REWARD_CHECKIN_BASE_ATOMS: u128 = 10 * BUBL_ATOM_18;
/// Per-day streak bonus, capped at +10 BUBL.
pub const REWARD_STREAK_BONUS_PER_DAY_ATOMS: u128 = 1 * BUBL_ATOM_18;
pub const REWARD_STREAK_BONUS_CAP_DAYS: u32 = 10;
/// Active-session reward — 2 BUBL, once per UTC day per DID.
pub const REWARD_ACTIVE_SESSION_ATOMS: u128 = 2 * BUBL_ATOM_18;
/// New-conversation-partner reward — 20 BUBL per distinct peer per ISO week.
pub const REWARD_NEW_PARTNER_ATOMS: u128 = 20 * BUBL_ATOM_18;
/// Weekly cap on new-partner rewards.
pub const WEEKLY_PARTNER_CAP: u32 = 5;

/// Memo tag for reward claim transactions.
pub const REWARD_CLAIM_MEMO: &[u8] = b"bubl:reward:claim:v1";

/// Reward event kinds — explicit `repr(u8)` for stable bincode layout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RewardEventKind {
    Welcome = 0,
    DailyCheckin = 1,
    ActiveSession = 2,
    NewPartner = 3,
}

impl RewardEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::DailyCheckin => "daily_checkin",
            Self::ActiveSession => "active_session",
            Self::NewPartner => "new_partner",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "welcome" => Some(Self::Welcome),
            "daily_checkin" => Some(Self::DailyCheckin),
            "active_session" => Some(Self::ActiveSession),
            "new_partner" => Some(Self::NewPartner),
            _ => None,
        }
    }
}

/// On-chain streak state for daily check-in rewards.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RewardStreakRecord {
    /// UTC ordinal day (days since CE) of the last check-in.
    pub last_day: i32,
    pub current_streak: u32,
    pub longest_streak: u32,
}

/// Payload for `TransactionType::RewardClaim`.
///
/// Signed by the BUBL `TokenCreation` creator (or future authorized delegate).
/// Amount must match the canonical schedule for `event` at execution time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardClaimData {
    pub event: RewardEventKind,
    /// Beneficiary DID — must exist in the identity registry.
    pub owner_did: String,
    /// Recipient wallet key_id (hex suffix of `did:zhtp:{hex}`).
    pub recipient_key_id: [u8; 32],
    /// BUBL token id (`generate_custom_token_id("Bubble","BUBL")`).
    pub token_id: [u8; 32],
    /// Treasury spender key_id (BUBL creator allocation).
    pub from: [u8; 32],
    /// Claim amount in 18-decimal atoms — validated against event + streak.
    pub amount: u128,
    /// Per-(token, from) transfer nonce.
    pub nonce: u64,
    /// Required when `event == NewPartner`.
    pub peer_did: Option<String>,
}

pub fn streak_bonus_for_day(streak_day: u32) -> u128 {
    let bonus_days = streak_day.saturating_sub(1).min(REWARD_STREAK_BONUS_CAP_DAYS);
    REWARD_STREAK_BONUS_PER_DAY_ATOMS * (bonus_days as u128)
}

pub fn checkin_amount_for_day(streak_day: u32) -> u128 {
    REWARD_CHECKIN_BASE_ATOMS + streak_bonus_for_day(streak_day)
}

pub fn expected_amount_for_event(event: RewardEventKind, streak_day: u32) -> u128 {
    use crate::rewards_policy::{expected_amount_for_trigger, legacy_bubl_policy, RewardsPolicyEvent};
    let policy = legacy_bubl_policy();
    let policy_event = reward_event_to_policy_event(event);
    expected_amount_for_trigger(&policy, policy_event, streak_day)
        .expect("legacy BUBL policy must define all reward events")
}

pub fn reward_event_to_policy_event(event: RewardEventKind) -> crate::rewards_policy::RewardsPolicyEvent {
    use crate::rewards_policy::RewardsPolicyEvent;
    match event {
        RewardEventKind::Welcome => RewardsPolicyEvent::Welcome,
        RewardEventKind::DailyCheckin => RewardsPolicyEvent::DailyCheckin,
        RewardEventKind::ActiveSession => RewardsPolicyEvent::ActiveSession,
        RewardEventKind::NewPartner => RewardsPolicyEvent::NewPartner,
    }
}

/// Whether `owner_did` is registered in durable identity storage.
///
/// Shared by mempool admission, stateful validation, and the executor so a
/// `RewardClaim` cannot be finalized unless the beneficiary identity exists.
pub fn owner_identity_registered_on_store(
    store: &dyn crate::storage::BlockchainStore,
    owner_did: &str,
) -> Result<bool, String> {
    let did_hash = crate::storage::did_to_hash(owner_did);
    store
        .get_identity(&did_hash)
        .map(|opt| opt.is_some())
        .map_err(|e| format!("identity lookup failed: {e}"))
}

/// Reject when the beneficiary DID is absent from chain state.
pub fn validate_owner_identity_registered(
    store: &dyn crate::storage::BlockchainStore,
    owner_did: &str,
) -> Result<(), String> {
    if !owner_identity_registered_on_store(store, owner_did)? {
        return Err("owner DID not registered".to_string());
    }
    Ok(())
}

/// Parse `did:zhtp:{64-hex}` → 32-byte key_id.
pub fn key_id_from_did(did: &str) -> Option<[u8; 32]> {
    const MAX_DID_LEN: usize = 256;
    if did.is_empty() || did.len() > MAX_DID_LEN {
        return None;
    }
    let hex_part = did.strip_prefix("did:zhtp:")?;
    if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(hex_part).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Convert a unix-second timestamp for chrono without silent `as i64` wrap (#2873).
fn chrono_datetime_from_unix_ts(ts: u64) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let ts_i = i64::try_from(ts).map_err(|_| {
        format!("timestamp {ts} exceeds i64 range")
    })?;
    chrono::DateTime::from_timestamp(ts_i, 0).ok_or_else(|| {
        format!("timestamp {ts} is outside chrono representable range")
    })
}

/// UTC date string `YYYY-MM-DD` from unix timestamp.
///
/// Rejects out-of-range values instead of wrapping via `as i64` (which maps
/// `u64::MAX` to `-1` → 1969-12-31).
pub fn utc_date_from_ts(ts: u64) -> Result<String, String> {
    Ok(chrono_datetime_from_unix_ts(ts)?
        .date_naive()
        .format("%Y-%m-%d")
        .to_string())
}

/// UTC ordinal day (days since CE) from unix timestamp.
pub fn utc_day_ordinal_from_ts(ts: u64) -> Result<i32, String> {
    use chrono::Datelike;
    Ok(chrono_datetime_from_unix_ts(ts)?
        .date_naive()
        .num_days_from_ce())
}

/// ISO week key `YYYY-Www` from unix timestamp.
pub fn iso_week_from_ts(ts: u64) -> Result<String, String> {
    use chrono::Datelike;
    let dt = chrono_datetime_from_unix_ts(ts)?;
    let iso = dt.date_naive().iso_week();
    Ok(format!("{}-W{:02}", iso.year(), iso.week()))
}

pub const REWARD_KEY_SEP: u8 = 0x1f;

fn token_key_prefix(token_id: &[u8; 32]) -> String {
    hex::encode(token_id)
}

pub fn welcome_claim_key(token_id: &[u8; 32], did: &str) -> String {
    format!("{}|{}", token_key_prefix(token_id), did)
}

pub fn streak_key(token_id: &[u8; 32], did: &str) -> String {
    format!("{}|{}", token_key_prefix(token_id), did)
}

pub fn daily_claim_key(
    token_id: &[u8; 32],
    date: &str,
    did: &str,
    event: RewardEventKind,
) -> String {
    format!(
        "{}|{}|{}|{}",
        token_key_prefix(token_id),
        date,
        did,
        event.as_str()
    )
}

pub fn partner_claim_key(token_id: &[u8; 32], week: &str, did: &str, peer_did: &str) -> String {
    format!(
        "{}|{}|{}|{}",
        token_key_prefix(token_id),
        week,
        did,
        peer_did
    )
}

pub fn partner_count_key(token_id: &[u8; 32], week: &str, did: &str) -> String {
    format!("{}|{}|{}", token_key_prefix(token_id), week, did)
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
    }

    #[test]
    fn key_id_from_did_valid() {
        let did = "did:zhtp:e0b9757663f55797ff06cdce1d0dc18329455b9a18d8e0b5bc05a8f10c969bf4";
        assert!(key_id_from_did(did).is_some());
    }

    #[test]
    fn validate_owner_identity_registered_rejects_unknown_did() {
        use crate::storage::{BlockchainStore, SledStore};
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let store = SledStore::open(dir.path().join("identity_gate")).expect("sled");
        let store: &dyn BlockchainStore = &store;
        let did = "did:zhtp:adf4cea328c55797ff06cdce1d0dc18329455b9a18d8e0b5bc05a8f10c969bf4";
        let err = validate_owner_identity_registered(store, did).unwrap_err();
        assert_eq!(err, "owner DID not registered");
    }

    #[test]
    fn valid_timestamp_buckets() {
        // 2024-01-15 12:00:00 UTC
        let ts = 1_705_320_000u64;
        assert_eq!(utc_date_from_ts(ts).unwrap(), "2024-01-15");
        assert!(utc_day_ordinal_from_ts(ts).unwrap() > 0);
        let week = iso_week_from_ts(ts).unwrap();
        assert!(week.starts_with("2024-W"), "week={week}");
    }

    #[test]
    fn rejects_u64_max_without_wrapping_to_1969() {
        assert!(utc_date_from_ts(u64::MAX).is_err());
        assert!(utc_day_ordinal_from_ts(u64::MAX).is_err());
        assert!(iso_week_from_ts(u64::MAX).is_err());
    }
}
