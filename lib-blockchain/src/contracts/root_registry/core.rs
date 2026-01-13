//! Root registry contract implementation (authoritative on-chain state).

use std::collections::HashMap;

use super::delegation_tree::DelegationTree;
use super::namespace_policy::NamespacePolicy;
use super::types::{
    hash_name, normalize_name, DaoId, LegacyDomainRecord, NameClass, NameHash,
    NameStatus, VerificationLevel, WelfareSector, ZoneController, PublicKey,
};

/// Simplified internal record for RootRegistry core operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreNameRecord {
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

/// Stored record variants for persistence
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreStoredRecord {
    V1(LegacyDomainRecord),
    V2(CoreNameRecord),
}

#[derive(Debug, Clone)]
pub struct RootRegistry {
    records: HashMap<NameHash, CoreStoredRecord>,
    delegation_tree: DelegationTree,
    policy: NamespacePolicy,
    welfare_sector_to_dao: HashMap<WelfareSector, DaoId>,
}

impl RootRegistry {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            delegation_tree: DelegationTree::new(),
            policy: NamespacePolicy::new(),
            welfare_sector_to_dao: HashMap::new(),
        }
    }

    pub fn get_record(&self, name_hash: &NameHash) -> Option<CoreNameRecord> {
        self.records.get(name_hash).map(|stored| self.load_record(stored))
    }

    pub fn register_commercial(
        &mut self,
        name: &str,
        owner: PublicKey,
        now: u64,
        expires_at: u64,
    ) -> Result<NameHash, String> {
        let normalized = normalize_name(name);
        let classification = self.policy.classify_name(&normalized);

        match classification {
            NameClass::Reserved { .. } => {
                return Err("Reserved namespaces cannot be registered via commercial path".to_string());
            }
            NameClass::WelfareChild { .. } => {
                return Err("Welfare namespaces cannot be registered via commercial path".to_string());
            }
            NameClass::DaoPrefixed { .. } => {
                // Phase 2 (Issue #657): dao.* names are VIRTUAL and cannot be registered
                // They are resolved at query time from the parent's governance_pointer
                return Err("dao.* names are virtual and cannot be registered. Use resolution to access governance.".to_string());
            }
            NameClass::Commercial { .. } => {}
        }

        self.insert_record(normalized, owner, classification, now, expires_at, None)
    }

    pub fn register_reserved_root(
        &mut self,
        name: &str,
        owner: PublicKey,
        now: u64,
        expires_at: u64,
        dao_id: Option<DaoId>,
    ) -> Result<NameHash, String> {
        let normalized = normalize_name(name);
        let classification = self.policy.classify_name(&normalized);

        match classification {
            NameClass::Reserved { .. } => {}
            _ => return Err("Name is not a reserved root".to_string()),
        }

        let name_hash = self.insert_record(normalized, owner, classification, now, expires_at, dao_id)?;

        if let Some(sector) = welfare_root_sector(name) {
            if let Some(dao_id) = dao_id {
                self.welfare_sector_to_dao.insert(sector, dao_id);
            }
        }

        Ok(name_hash)
    }

    pub fn set_zone_controller(
        &mut self,
        name_hash: &NameHash,
        controller: ZoneController,
        caller: &PublicKey,
    ) -> Result<(), String> {
        let record = self
            .get_record(name_hash)
            .ok_or_else(|| "Name record not found".to_string())?;

        if &record.owner != caller {
            return Err("Only owner can set zone controller".to_string());
        }

        if controller.scope != *name_hash {
            return Err("Zone controller scope must match name hash".to_string());
        }

        let mut updated = record.clone();
        updated.zone_controller = Some(controller);
        self.records.insert(*name_hash, CoreStoredRecord::V2(updated));
        Ok(())
    }

    pub fn register_under_zone_controller(
        &mut self,
        name: &str,
        owner: PublicKey,
        caller: &PublicKey,
        now: u64,
        expires_at: u64,
    ) -> Result<NameHash, String> {
        let normalized = normalize_name(name);
        let parent_hash = parent_hash(&normalized)
            .ok_or_else(|| "Zone registration requires a parent".to_string())?;
        let parent = self
            .get_record(&parent_hash)
            .ok_or_else(|| "Parent record not found".to_string())?;
        let controller = parent
            .zone_controller
            .as_ref()
            .ok_or_else(|| "Parent has no zone controller".to_string())?;

        if controller.scope != parent_hash {
            return Err("Zone controller scope mismatch".to_string());
        }

        if controller.controller != *caller {
            return Err("Caller is not authorized zone controller".to_string());
        }

        if let Some(expires_at_ctrl) = controller.expires_at {
            if now > expires_at_ctrl {
                return Err("Zone controller is expired".to_string());
            }
        }

        let classification = self.policy.classify_name(&normalized);
        self.insert_record(normalized, owner, classification, now, expires_at, parent.governance_pointer)
    }

    pub fn expire_name(&mut self, name_hash: &NameHash) -> Result<(), String> {
        let record = self
            .get_record(name_hash)
            .ok_or_else(|| "Name record not found".to_string())?;
        let mut updated = record.clone();
        updated.status = NameStatus::Expired { grace_ends: updated.expires_at + super::types::timing::EXPIRATION_GRACE_SECS };
        self.records.insert(*name_hash, CoreStoredRecord::V2(updated));
        self.suspend_children(name_hash);
        Ok(())
    }

    /// Link a welfare sector to its DAO
    /// Note: Requires integration with DAORegistry for governance verification
    pub fn link_welfare_sector_dao(
        &mut self,
        sector: WelfareSector,
        dao_id: DaoId,
    ) -> Result<(), String> {
        // TODO: Add governance verification when DAORegistry integration is complete
        self.welfare_sector_to_dao.insert(sector, dao_id);
        Ok(())
    }

    /// Get the DAO ID for a welfare sector
    pub fn get_welfare_sector_dao(&self, sector: &WelfareSector) -> Option<&DaoId> {
        self.welfare_sector_to_dao.get(sector)
    }

    fn suspend_children(&mut self, parent: &NameHash) {
        let children = self.delegation_tree.children_of(parent);
        for child in children {
            if let Some(mut record) = self.get_record(&child) {
                record.status = NameStatus::SuspendedByParent;
                self.records.insert(child, CoreStoredRecord::V2(record));
                self.suspend_children(&child);
            }
        }
    }

    fn insert_record(
        &mut self,
        normalized_name: String,
        owner: PublicKey,
        classification: NameClass,
        now: u64,
        expires_at: u64,
        governance_pointer: Option<DaoId>,
    ) -> Result<NameHash, String> {
        let name_hash = hash_name(&normalized_name);
        if self.records.contains_key(&name_hash) {
            return Err("Name already registered".to_string());
        }

        let parent_hash = parent_hash(&normalized_name);
        let depth = parent_hash.map(|_| 1u8).unwrap_or(0);

        let record = CoreNameRecord {
            name_hash,
            owner,
            controller: None,
            zone_controller: None,
            parent: parent_hash,
            depth,
            classification,
            verification_level: VerificationLevel::L0Unverified,
            governance_pointer,
            status: NameStatus::Active,
            expires_at,
            grace_ends_at: None,
        };

        if let Some(parent) = record.parent {
            self.delegation_tree.add_child(parent, name_hash);
        }

        self.records.insert(name_hash, CoreStoredRecord::V2(record));
        let _ = now;
        Ok(name_hash)
    }

    fn load_record(&self, stored: &CoreStoredRecord) -> CoreNameRecord {
        match stored {
            CoreStoredRecord::V2(record) => record.clone(),
            CoreStoredRecord::V1(legacy) => migrate_legacy_record(legacy),
        }
    }
}

impl Default for RootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn parent_hash(name: &str) -> Option<NameHash> {
    let mut parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    parts.remove(0);
    Some(hash_name(&parts.join(".")))
}

fn welfare_root_sector(name: &str) -> Option<WelfareSector> {
    match normalize_name(name).as_str() {
        "food.dao.sov" => Some(WelfareSector::Food),
        "health.dao.sov" => Some(WelfareSector::Health),
        "edu.dao.sov" => Some(WelfareSector::Education),
        "housing.dao.sov" => Some(WelfareSector::Housing),
        "energy.dao.sov" => Some(WelfareSector::Energy),
        _ => None,
    }
}

fn migrate_legacy_record(legacy: &LegacyDomainRecord) -> CoreNameRecord {
    let name_hash = hash_name(&legacy.domain);
    // Convert string owner to PublicKey (32-byte array)
    let mut owner = [0u8; 32];
    let owner_bytes = legacy.owner.as_bytes();
    let copy_len = owner_bytes.len().min(32);
    owner[..copy_len].copy_from_slice(&owner_bytes[..copy_len]);

    CoreNameRecord {
        name_hash,
        owner,
        controller: None,
        zone_controller: None,
        parent: None,
        depth: 0,
        classification: NameClass::Commercial {
            min_verification: VerificationLevel::L0Unverified,
        },
        verification_level: VerificationLevel::L0Unverified,
        governance_pointer: None,
        status: NameStatus::Active,
        expires_at: legacy.expires_at,
        grace_ends_at: None,
    }
}
