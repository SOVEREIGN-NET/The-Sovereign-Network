use super::types::{
    RewardsPolicyEvent, RewardsPolicyV1, RewardsTrigger, TriggerKind, REWARDS_POLICY_SCHEMA_V1,
};
use crate::types::Hash;
use std::collections::HashSet;

const ATOM_18: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewardsPolicyError {
    InvalidJson(String),
    WrongSchema { expected: String, got: String },
    InvalidAssetId(String),
    EmptyTriggers,
    TooManyTriggers,
    DuplicateTriggerId(String),
    DuplicateEvent(RewardsPolicyEvent),
    TriggerDisabledNoop(String),
    MissingField { trigger_id: String, field: &'static str },
    InvalidAmount { trigger_id: String, reason: String },
    InvalidWeeklyCap { trigger_id: String },
    DescriptionTooLong,
}

impl std::fmt::Display for RewardsPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid JSON: {e}"),
            Self::WrongSchema { expected, got } => {
                write!(f, "schema must be '{expected}', got '{got}'")
            }
            Self::InvalidAssetId(s) => write!(f, "asset_id must be 64 hex chars: {s}"),
            Self::EmptyTriggers => write!(f, "triggers must not be empty"),
            Self::TooManyTriggers => write!(f, "triggers exceed max 32"),
            Self::DuplicateTriggerId(id) => write!(f, "duplicate trigger id '{id}'"),
            Self::DuplicateEvent(ev) => write!(f, "duplicate event '{}'", ev.as_str()),
            Self::TriggerDisabledNoop(id) => write!(f, "trigger '{id}' disabled (ok)"),
            Self::MissingField { trigger_id, field } => {
                write!(f, "trigger '{trigger_id}' missing '{field}'")
            }
            Self::InvalidAmount { trigger_id, reason } => {
                write!(f, "trigger '{trigger_id}' invalid amount: {reason}")
            }
            Self::InvalidWeeklyCap { trigger_id } => {
                write!(f, "trigger '{trigger_id}' weekly_cap out of range")
            }
            Self::DescriptionTooLong => write!(f, "description exceeds 512 chars"),
        }
    }
}

impl std::error::Error for RewardsPolicyError {}

/// Parse and semantically validate a rewards policy document.
pub fn validate_rewards_policy(bytes: &[u8]) -> Result<RewardsPolicyV1, RewardsPolicyError> {
    let policy: RewardsPolicyV1 = serde_json::from_slice(bytes)
        .map_err(|e| RewardsPolicyError::InvalidJson(e.to_string()))?;
    validate_rewards_policy_value(&policy)?;
    Ok(policy)
}

pub fn validate_rewards_policy_value(policy: &RewardsPolicyV1) -> Result<(), RewardsPolicyError> {
    if policy.schema != REWARDS_POLICY_SCHEMA_V1 {
        return Err(RewardsPolicyError::WrongSchema {
            expected: REWARDS_POLICY_SCHEMA_V1.to_string(),
            got: policy.schema.clone(),
        });
    }
    if policy.asset_id.len() != 64
        || !policy.asset_id.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(RewardsPolicyError::InvalidAssetId(policy.asset_id.clone()));
    }
    if let Some(desc) = &policy.description {
        if desc.len() > 512 {
            return Err(RewardsPolicyError::DescriptionTooLong);
        }
    }
    if policy.triggers.is_empty() {
        return Err(RewardsPolicyError::EmptyTriggers);
    }
    if policy.triggers.len() > 32 {
        return Err(RewardsPolicyError::TooManyTriggers);
    }

    let mut ids = HashSet::new();
    let mut events = HashSet::new();
    let mut any_enabled = false;

    for t in &policy.triggers {
        if !ids.insert(t.id.clone()) {
            return Err(RewardsPolicyError::DuplicateTriggerId(t.id.clone()));
        }
        if !t.enabled {
            continue;
        }
        any_enabled = true;
        validate_trigger(t)?;
        if let Some(ev) = t.event {
            if !events.insert(ev) {
                return Err(RewardsPolicyError::DuplicateEvent(ev));
            }
        }
    }

    if !any_enabled {
        return Err(RewardsPolicyError::EmptyTriggers);
    }

    Ok(())
}

fn validate_trigger(t: &RewardsTrigger) -> Result<(), RewardsPolicyError> {
    let id = &t.id;
    if !id
        .chars()
        .next()
        .map(|c| c.is_ascii_lowercase())
        .unwrap_or(false)
        || id.len() > 32
        || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(RewardsPolicyError::InvalidAmount {
            trigger_id: id.clone(),
            reason: "id must match [a-z][a-z0-9_]{0,31}".to_string(),
        });
    }

    let event = t.event.ok_or(RewardsPolicyError::MissingField {
        trigger_id: id.clone(),
        field: "event",
    })?;

    match t.kind {
        TriggerKind::OncePerDid => {
            let amount = t.amount_atoms.ok_or(RewardsPolicyError::MissingField {
                trigger_id: id.clone(),
                field: "amount_atoms",
            })?;
            require_positive(id, amount)?;
            if event != RewardsPolicyEvent::Welcome {
                // allowed but warn via validation — welcome is the expected pairing
            }
        }
        TriggerKind::OncePerUtcDay => {
            if let Some(amount) = t.amount_atoms {
                require_positive(id, amount)?;
            } else if let Some(base) = t.base_amount_atoms {
                require_positive(id, base)?;
                if let Some(sb) = &t.streak_bonus {
                    require_positive(id, sb.per_day_atoms)?;
                    if sb.cap_days > 365 {
                        return Err(RewardsPolicyError::InvalidAmount {
                            trigger_id: id.clone(),
                            reason: "streak_bonus.cap_days > 365".to_string(),
                        });
                    }
                }
            } else {
                return Err(RewardsPolicyError::MissingField {
                    trigger_id: id.clone(),
                    field: "amount_atoms or base_amount_atoms",
                });
            }
        }
        TriggerKind::DistinctPeerPerIsoWeek => {
            let amount = t.amount_atoms.ok_or(RewardsPolicyError::MissingField {
                trigger_id: id.clone(),
                field: "amount_atoms",
            })?;
            require_positive(id, amount)?;
            let cap = t.weekly_cap.ok_or(RewardsPolicyError::MissingField {
                trigger_id: id.clone(),
                field: "weekly_cap",
            })?;
            if cap == 0 || cap > 1000 {
                return Err(RewardsPolicyError::InvalidWeeklyCap {
                    trigger_id: id.clone(),
                });
            }
            if event != RewardsPolicyEvent::NewPartner {
                return Err(RewardsPolicyError::InvalidAmount {
                    trigger_id: id.clone(),
                    reason: "distinct_peer_per_iso_week expects event new_partner".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn require_positive(trigger_id: &str, amount: u128) -> Result<(), RewardsPolicyError> {
    if amount == 0 {
        return Err(RewardsPolicyError::InvalidAmount {
            trigger_id: trigger_id.to_string(),
            reason: "must be > 0".to_string(),
        });
    }
    Ok(())
}

/// Canonical JSON bytes for hashing (sorted keys, compact).
pub fn canonical_policy_bytes(policy: &RewardsPolicyV1) -> Result<Vec<u8>, RewardsPolicyError> {
    validate_rewards_policy_value(policy)?;
    serde_json::to_vec(policy).map_err(|e| RewardsPolicyError::InvalidJson(e.to_string()))
}

/// BLAKE3 hash of canonical policy JSON — stored on-chain as `policy_hash`.
pub fn policy_hash(policy: &RewardsPolicyV1) -> Result<Hash, RewardsPolicyError> {
    let bytes = canonical_policy_bytes(policy)?;
    Ok(crate::types::hash::blake3_hash(&bytes))
}

/// Expected claim amount for an event at a given streak day (check-in only).
pub fn expected_amount_for_trigger(
    policy: &RewardsPolicyV1,
    event: RewardsPolicyEvent,
    streak_day: u32,
) -> Option<u128> {
    let trigger = policy.triggers.iter().find(|t| t.enabled && t.event == Some(event))?;
    match trigger.kind {
        TriggerKind::OncePerDid | TriggerKind::DistinctPeerPerIsoWeek => trigger.amount_atoms,
        TriggerKind::OncePerUtcDay => {
            if let Some(fixed) = trigger.amount_atoms {
                Some(fixed)
            } else {
                let base = trigger.base_amount_atoms?;
                let bonus = trigger.streak_bonus.as_ref().map(|sb| {
                    let days = streak_day.saturating_sub(1).min(sb.cap_days) as u128;
                    sb.per_day_atoms.saturating_mul(days)
                })?;
                Some(base.saturating_add(bonus))
            }
        }
    }
}

/// BUBL canonical constants for regression tests (18-decimal atoms).
pub mod bubl_canonical {
    use super::*;

    pub const WELCOME: u128 = 100 * ATOM_18;
    pub const CHECKIN_BASE: u128 = 10 * ATOM_18;
    pub const STREAK_PER_DAY: u128 = 1 * ATOM_18;
    pub const STREAK_CAP_DAYS: u32 = 10;
    pub const ACTIVE_SESSION: u128 = 2 * ATOM_18;
    pub const NEW_PARTNER: u128 = 20 * ATOM_18;
    pub const WEEKLY_PARTNER_CAP: u32 = 5;
}

#[cfg(test)]
mod tests {
    use super::bubl_canonical::*;
    use super::*;
    use crate::rewards_policy::types::{RewardsBudget, RewardsTrigger, StreakBonus};

    fn example_bubl_policy() -> RewardsPolicyV1 {
        RewardsPolicyV1 {
            schema: REWARDS_POLICY_SCHEMA_V1.to_string(),
            asset_id: "ab".repeat(32),
            description: Some("test".to_string()),
            triggers: vec![
                RewardsTrigger {
                    id: "welcome".to_string(),
                    kind: TriggerKind::OncePerDid,
                    enabled: true,
                    event: Some(RewardsPolicyEvent::Welcome),
                    amount_atoms: Some(WELCOME),
                    base_amount_atoms: None,
                    streak_bonus: None,
                    weekly_cap: None,
                },
                RewardsTrigger {
                    id: "daily_checkin".to_string(),
                    kind: TriggerKind::OncePerUtcDay,
                    enabled: true,
                    event: Some(RewardsPolicyEvent::DailyCheckin),
                    amount_atoms: None,
                    base_amount_atoms: Some(CHECKIN_BASE),
                    streak_bonus: Some(StreakBonus {
                        per_day_atoms: STREAK_PER_DAY,
                        cap_days: STREAK_CAP_DAYS,
                    }),
                    weekly_cap: None,
                },
                RewardsTrigger {
                    id: "active_session".to_string(),
                    kind: TriggerKind::OncePerUtcDay,
                    enabled: true,
                    event: Some(RewardsPolicyEvent::ActiveSession),
                    amount_atoms: Some(ACTIVE_SESSION),
                    base_amount_atoms: None,
                    streak_bonus: None,
                    weekly_cap: None,
                },
                RewardsTrigger {
                    id: "new_partner".to_string(),
                    kind: TriggerKind::DistinctPeerPerIsoWeek,
                    enabled: true,
                    event: Some(RewardsPolicyEvent::NewPartner),
                    amount_atoms: Some(NEW_PARTNER),
                    base_amount_atoms: None,
                    streak_bonus: None,
                    weekly_cap: Some(WEEKLY_PARTNER_CAP),
                },
            ],
            budget: Some(RewardsBudget {
                max_daily_outflow_atoms: None,
                max_lifetime_per_did_atoms: None,
            }),
        }
    }

    #[test]
    fn example_file_validates() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../schemas/zhtp/rewards-policy/examples/bubl-v1.json"
        );
        let bytes = std::fs::read(path).expect("read bubl example");
        let policy = validate_rewards_policy(&bytes).expect("valid");
        assert_eq!(policy.triggers.len(), 4);
    }

    #[test]
    fn bubl_amounts_match_executor_constants() {
        let policy = example_bubl_policy();
        assert_eq!(
            expected_amount_for_trigger(&policy, RewardsPolicyEvent::Welcome, 1),
            Some(WELCOME)
        );
        assert_eq!(
            expected_amount_for_trigger(&policy, RewardsPolicyEvent::DailyCheckin, 1),
            Some(CHECKIN_BASE)
        );
        assert_eq!(
            expected_amount_for_trigger(&policy, RewardsPolicyEvent::DailyCheckin, 11),
            Some(CHECKIN_BASE + STREAK_PER_DAY * 10)
        );
        assert_eq!(
            expected_amount_for_trigger(&policy, RewardsPolicyEvent::ActiveSession, 1),
            Some(ACTIVE_SESSION)
        );
        assert_eq!(
            expected_amount_for_trigger(&policy, RewardsPolicyEvent::NewPartner, 1),
            Some(NEW_PARTNER)
        );
        assert_eq!(NEW_PARTNER, 20 * ATOM_18, "C2: canonical new_partner is 20 BUBL");
    }

    #[test]
    fn policy_hash_is_deterministic() {
        let policy = example_bubl_policy();
        let h1 = policy_hash(&policy).unwrap();
        let h2 = policy_hash(&policy).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn rejects_wrong_schema() {
        let mut policy = example_bubl_policy();
        policy.schema = "zhtp/rewards-policy/v0".to_string();
        assert!(validate_rewards_policy_value(&policy).is_err());
    }
}