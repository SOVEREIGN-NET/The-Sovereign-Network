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
    use crate::rewards_policy::{expected_amount_for_trigger, legacy_bubl_policy};
    let policy = legacy_bubl_policy();
    let policy_event = reward_event_to_policy_event(event);
    expected_amount_for_trigger(&policy, policy_event, streak_day).unwrap_or(0)
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

/// Canonical BUBL `token_id` for reward claims.
pub fn bubl_token_id() -> [u8; 32] {
    crate::contracts::utils::generate_custom_token_id("Bubble", "BUBL")
}

/// Normalize `did:zhtp:{hex}` to lowercase hex suffix for stable storage keys.
pub fn canonical_owner_did(did: &str) -> Option<String> {
    let key_id = key_id_from_did(did)?;
    Some(format!("did:zhtp:{}", hex::encode(key_id)))
}

/// Parse `did:zhtp:{64-hex}` → 32-byte key_id (hex case-insensitive).
pub fn key_id_from_did(did: &str) -> Option<[u8; 32]> {
    const MAX_DID_LEN: usize = 256;
    if did.is_empty() || did.len() > MAX_DID_LEN {
        return None;
    }
    let hex_part = did.strip_prefix("did:zhtp:")?;
    if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let lower = hex_part.to_ascii_lowercase();
    let bytes = hex::decode(&lower).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// UTC date string `YYYY-MM-DD` from unix timestamp.
pub fn utc_date_from_ts(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.date_naive().format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".to_string())
}

/// UTC ordinal day (days since CE) from unix timestamp.
pub fn utc_day_ordinal_from_ts(ts: u64) -> i32 {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.date_naive().num_days_from_ce())
        .unwrap_or(0)
}

/// ISO week key `YYYY-Www` from unix timestamp.
pub fn iso_week_from_ts(ts: u64) -> String {
    use chrono::Datelike;
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| {
            let iso = dt.date_naive().iso_week();
            format!("{}-W{:02}", iso.year(), iso.week())
        })
        .unwrap_or_else(|| "1970-W01".to_string())
}

pub const REWARD_KEY_SEP: u8 = 0x1f;

pub fn daily_claim_key(date: &str, did: &str, event: RewardEventKind) -> String {
    format!("{}|{}|{}", date, did, event.as_str())
}

pub fn partner_claim_key(week: &str, did: &str, peer_did: &str) -> String {
    format!("{}|{}|{}", week, did, peer_did)
}

pub fn partner_count_key(week: &str, did: &str) -> String {
    format!("{}|{}", week, did)
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
    fn key_id_from_did_uppercase_hex_matches_lowercase() {
        let lower = "did:zhtp:e0b9757663f55797ff06cdce1d0dc18329455b9a18d8e0b5bc05a8f10c969bf4";
        let upper = "did:zhtp:E0B9757663F55797FF06CDCE1D0DC18329455B9A18D8E0B5BC05A8F10C969BF4";
        assert_eq!(key_id_from_did(lower), key_id_from_did(upper));
        assert_eq!(canonical_owner_did(lower), canonical_owner_did(upper));
    }

    #[test]
    fn expected_amount_matches_legacy_constants() {
        assert_eq!(expected_amount_for_event(RewardEventKind::Welcome, 1), REWARD_WELCOME_ATOMS);
        assert_eq!(
            expected_amount_for_event(RewardEventKind::NewPartner, 1),
            REWARD_NEW_PARTNER_ATOMS
        );
    }
}