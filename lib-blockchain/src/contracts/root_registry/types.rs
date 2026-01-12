//! Root registry types for on-chain domain authority graph.

use crate::integration::crypto_integration::{hash_data, PublicKey};
use serde::{Deserialize, Serialize};

pub type NameHash = [u8; 32];
pub type DaoId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationLevel {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameStatus {
    Active,
    SuspendedByParent,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservedReason {
    MetaGovernance,
    WelfareRoot,
    GovernanceAdded,
    HighRiskLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WelfareSector {
    Food,
    Health,
    Education,
    Housing,
    Energy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NameClass {
    Reserved { reason: ReservedReason },
    Commercial { min_verification: VerificationLevel },
    WelfareChild {
        sector: WelfareSector,
        zone_root_hash: NameHash,
    },
    DaoPrefixed { parent_hash: NameHash },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneController {
    /// Contract address that can issue under this zone
    pub controller: PublicKey,
    /// The zone root this controller manages (hash of zone root)
    pub scope: NameHash,
    /// Optional expiration (None = permanent until revoked)
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRecord {
    pub name_hash: NameHash,
    pub owner: PublicKey,
    pub controller: Option<PublicKey>,
    pub zone_controller: Option<ZoneController>,
    pub parent: Option<NameHash>,
    pub depth: u8,
    pub classification: NameClass,
    pub verification_level: VerificationLevel,
    pub governance_pointer: Option<DaoId>,
    pub status: NameStatus,
    pub expires_at: u64,
    pub grace_ends_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyDomainRecord {
    pub domain: String,
    pub owner: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredRecord {
    V1(LegacyDomainRecord),
    V2(NameRecord),
}

pub fn normalize_name(name: &str) -> String {
    name.trim().to_lowercase()
}

pub fn hash_name(name: &str) -> NameHash {
    let normalized = normalize_name(name);
    let hash = hash_data(normalized.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    out
}

pub fn is_zero_name_hash(name_hash: &NameHash) -> bool {
    name_hash.iter().all(|b| *b == 0)
}
