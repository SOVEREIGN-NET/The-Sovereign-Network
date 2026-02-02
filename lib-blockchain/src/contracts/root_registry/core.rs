//! Root registry contract implementation (authoritative on-chain state).
//!
//! [Phase 5] Implements verification requirements for .sov domain registration.
//! Root-level issuance requires identity-anchored proofs with graduated access
//! control based on domain classification.

use std::collections::HashMap;

use super::delegation_tree::DelegationTree;
use super::namespace_policy::NamespacePolicy;
use super::types::{
    hash_name, normalize_name, DaoId, LegacyDomainRecord, NameClass, NameHash,
    NameStatus, VerificationLevel, VerificationProof,
    WelfareSector, ZoneController, PublicKey,
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

    /// Register a commercial .sov domain with verification
    ///
    /// [Phase 5] Root-level .sov issuance requires identity-anchored proofs.
    /// Commercial roots require L2 (Verified Entity) minimum.
    ///
    /// # Arguments
    /// * `name` - Domain name to register (e.g., "shoes.sov")
    /// * `owner` - Owner's public key
    /// * `verification_level` - Claimed verification level of the registrant
    /// * `verification_proof` - ZK proof demonstrating claimed level
    /// * `now` - Current timestamp
    /// * `expires_at` - Expiration timestamp
    ///
    /// # Errors
    /// * Returns error if verification level is insufficient (L0 always rejected)
    /// * Returns error if verification proof is missing or invalid
    /// * Returns error for reserved, welfare, or dao-prefixed names
    ///
    /// # Invariants (Phase 5)
    /// * V1: .sov root issuance is impossible without verification
    /// * V2: Verification requirements are name-class dependent
    /// * V7: Missing verification fails loudly and deterministically
    pub fn register_commercial(
        &mut self,
        name: &str,
        owner: PublicKey,
        verification_level: VerificationLevel,
        verification_proof: Option<&VerificationProof>,
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

        // [Phase 5] Verify identity before registration
        // This is the critical security gate - must happen BEFORE any state changes
        self.policy
            .verify(&classification, verification_level, verification_proof, now, None)
            .map_err(|e| e.to_string())?;

        self.insert_record_with_verification(
            normalized,
            owner,
            classification,
            verification_level,
            now,
            expires_at,
            None,
        )
    }

    /// Register a commercial domain without verification (for testing/migration only)
    ///
    /// # WARNING
    /// This method bypasses Phase 5 verification requirements.
    /// It exists ONLY for:
    /// - Unit tests that don't need to test verification
    /// - Migration of legacy records
    /// - Internal use by other registration paths that handle verification themselves
    ///
    /// Production code should use `register_commercial()` which enforces verification.
    #[cfg(any(test, feature = "testing"))]
    pub fn register_commercial_unverified(
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

    /// Register a welfare subdomain from the WelfareIssuerAdapter (Issue #658)
    ///
    /// This is a privileged method that allows ratified sector DAOs to issue
    /// welfare subdomains. The caller must be the authorized WelfareIssuerAdapter.
    ///
    /// # Arguments
    /// * `sector` - The welfare sector (Food, Health, etc.)
    /// * `label` - The subdomain label (e.g., "farm" for "farm.food.dao.sov")
    /// * `owner` - The owner of the new subdomain
    /// * `verification_level` - The verification level of the owner
    /// * `expires_at` - When the subdomain expires
    /// * `caller_dao_id` - The DAO ID making the request (must be bound to sector)
    /// * `metadata_hash` - Hash of WelfareMetadata for this issuance
    ///
    /// # Returns
    /// * `Ok(NameHash)` - The hash of the newly registered name
    /// * `Err(String)` - If registration fails
    pub fn register_from_welfare_adapter(
        &mut self,
        sector: WelfareSector,
        label: &str,
        owner: PublicKey,
        verification_level: VerificationLevel,
        now: u64,
        expires_at: u64,
        caller_dao_id: DaoId,
        _metadata_hash: [u8; 32],
    ) -> Result<NameHash, String> {
        // Verify the caller DAO is authorized for this sector
        let authorized_dao = self
            .welfare_sector_to_dao
            .get(&sector)
            .ok_or_else(|| format!("No DAO registered for sector {:?}", sector))?;

        if *authorized_dao != caller_dao_id {
            return Err(format!(
                "DAO {:?} is not authorized for sector {:?}",
                &caller_dao_id[..8],
                sector
            ));
        }

        // Construct the full name (e.g., "farm.food.dao.sov")
        let full_name = format!("{}.{}", label, sector.dao_domain());
        let normalized = normalize_name(&full_name);

        // Verify it's classified as a welfare child
        let classification = self.policy.classify_name(&normalized);
        match &classification {
            NameClass::WelfareChild { sector: class_sector, .. } => {
                if class_sector != &sector {
                    return Err("Classification sector mismatch".to_string());
                }
            }
            _ => {
                return Err(format!(
                    "Name '{}' is not classified as welfare child",
                    full_name
                ));
            }
        }

        // Get the parent (sector root) hash
        let parent_name = sector.dao_domain();
        let parent_hash = hash_name(&normalize_name(&parent_name));

        // Verify parent exists and is active
        if let Some(parent_record) = self.get_record(&parent_hash) {
            if !matches!(parent_record.status, NameStatus::Active) {
                return Err("Parent welfare root is not active".to_string());
            }
        } else {
            return Err(format!("Parent welfare root '{}' not found", parent_name));
        }

        // Create the welfare subdomain record
        let name_hash = hash_name(&normalized);
        if self.records.contains_key(&name_hash) {
            return Err(format!("Welfare name '{}' already registered", full_name));
        }

        let record = CoreNameRecord {
            name_hash,
            owner,
            controller: None,
            zone_controller: None,
            parent: Some(parent_hash),
            depth: 3, // e.g., farm.food.dao.sov = 3 levels deep
            classification,
            verification_level,
            governance_pointer: Some(caller_dao_id),
            status: NameStatus::Active,
            expires_at,
            grace_ends_at: None,
        };

        // Register in delegation tree
        self.delegation_tree.add_child(parent_hash, name_hash);

        // Store the record
        self.records.insert(name_hash, CoreStoredRecord::V2(record));
        let _ = now;

        Ok(name_hash)
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

    /// Insert a record with verified verification level
    ///
    /// [Phase 5] This stores the verification level that was validated during registration.
    fn insert_record_with_verification(
        &mut self,
        normalized_name: String,
        owner: PublicKey,
        classification: NameClass,
        verification_level: VerificationLevel,
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
            verification_level, // [Phase 5] Store the verified level
            governance_pointer,
            status: NameStatus::Active,
            expires_at,
            grace_ends_at: None,
        };

        if let Some(parent) = record.parent {
            self.delegation_tree.add_child(parent, name_hash);
        }

        self.records.insert(name_hash, CoreStoredRecord::V2(record));
        Ok(name_hash)
    }

    /// Insert a record without verification (legacy/test support)
    ///
    /// # Warning
    /// This sets verification_level to L0. Only use for:
    /// - Legacy record migration
    /// - Tests that don't test verification
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
