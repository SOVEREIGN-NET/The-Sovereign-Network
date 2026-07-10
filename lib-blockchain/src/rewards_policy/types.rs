use serde::{Deserialize, Serialize};

pub const REWARDS_POLICY_SCHEMA_V1: &str = "zhtp/rewards-policy/v1";

/// Canonical event names — align with `RewardEventKind::from_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardsPolicyEvent {
    Welcome,
    DailyCheckin,
    ActiveSession,
    NewPartner,
}

impl RewardsPolicyEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::DailyCheckin => "daily_checkin",
            Self::ActiveSession => "active_session",
            Self::NewPartner => "new_partner",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    OncePerDid,
    OncePerUtcDay,
    DistinctPeerPerIsoWeek,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreakBonus {
    #[serde(with = "atoms_string")]
    pub per_day_atoms: u128,
    pub cap_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsTrigger {
    pub id: String,
    pub kind: TriggerKind,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<RewardsPolicyEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_atoms_string")]
    pub amount_atoms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_atoms_string")]
    pub base_amount_atoms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streak_bonus: Option<StreakBonus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_cap: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RewardsBudget {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_atoms_string")]
    pub max_daily_outflow_atoms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_atoms_string")]
    pub max_lifetime_per_did_atoms: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardsPolicyV1 {
    pub schema: String,
    pub asset_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub triggers: Vec<RewardsTrigger>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<RewardsBudget>,
}

mod atoms_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

mod optional_atoms_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.serialize_some(&v.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        opt.map(|s| s.parse::<u128>().map_err(serde::de::Error::custom))
            .transpose()
    }
}