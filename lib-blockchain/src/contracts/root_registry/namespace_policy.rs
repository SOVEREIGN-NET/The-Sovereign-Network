//! Namespace policy enforcement for the root registry.

use std::collections::HashSet;
use super::types::{
    hash_name, normalize_name, NameClass, NameHash, ReservedReason, VerificationLevel,
    WelfareSector,
};

const IMMUTABLE_RESERVED: &[&str] = &[
    "food.dao.sov",
    "health.dao.sov",
    "edu.dao.sov",
    "housing.dao.sov",
    "energy.dao.sov",
    "dao.sov",
];

#[derive(Debug, Clone)]
pub struct NamespacePolicy {
    governance_added_reserved: HashSet<NameHash>,
}

impl NamespacePolicy {
    pub fn new() -> Self {
        Self {
            governance_added_reserved: HashSet::new(),
        }
    }

    pub fn add_reserved_namespace(&mut self, name_hash: NameHash) {
        self.governance_added_reserved.insert(name_hash);
    }

    pub fn is_reserved_hash(&self, name_hash: &NameHash) -> bool {
        self.governance_added_reserved.contains(name_hash)
            || immutable_reserved_hashes().contains(name_hash)
    }

    pub fn classify_name(&self, name: &str) -> NameClass {
        let normalized = normalize_name(name);

        if normalized == "dao.sov" {
            return NameClass::Reserved {
                reason: ReservedReason::MetaGovernance,
            };
        }

        if let Some(sector) = welfare_sector_from_root(&normalized) {
            return NameClass::Reserved {
                reason: ReservedReason::WelfareRoot,
            };
        }

        if self.governance_added_reserved.contains(&hash_name(&normalized)) {
            return NameClass::Reserved {
                reason: ReservedReason::GovernanceAdded,
            };
        }

        if let Some((sector, zone_root)) = welfare_child_info(&normalized) {
            return NameClass::WelfareChild {
                sector,
                zone_root_hash: zone_root,
            };
        }

        if let Some(parent_hash) = dao_prefixed_parent(&normalized) {
            return NameClass::DaoPrefixed { parent_hash };
        }

        NameClass::Commercial {
            min_verification: VerificationLevel::L0,
        }
    }
}

pub fn immutable_reserved_hashes() -> HashSet<NameHash> {
    IMMUTABLE_RESERVED
        .iter()
        .map(|name| hash_name(name))
        .collect()
}

fn welfare_sector_from_root(name: &str) -> Option<WelfareSector> {
    match name {
        "food.dao.sov" => Some(WelfareSector::Food),
        "health.dao.sov" => Some(WelfareSector::Health),
        "edu.dao.sov" => Some(WelfareSector::Education),
        "housing.dao.sov" => Some(WelfareSector::Housing),
        "energy.dao.sov" => Some(WelfareSector::Energy),
        _ => None,
    }
}

fn welfare_child_info(name: &str) -> Option<(WelfareSector, NameHash)> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 4 {
        return None;
    }

    let sector = match parts[parts.len() - 3] {
        "food" => WelfareSector::Food,
        "health" => WelfareSector::Health,
        "edu" => WelfareSector::Education,
        "housing" => WelfareSector::Housing,
        "energy" => WelfareSector::Energy,
        _ => return None,
    };

    if parts[parts.len() - 2] != "dao" || parts[parts.len() - 1] != "sov" {
        return None;
    }

    let zone_root = format!("{}.dao.sov", parts[parts.len() - 3]);
    Some((sector, hash_name(&zone_root)))
}

fn dao_prefixed_parent(name: &str) -> Option<NameHash> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    if parts[0] != "dao" || parts[2] != "sov" {
        return None;
    }
    let parent = format!("{}.sov", parts[1]);
    Some(hash_name(&parent))
}
