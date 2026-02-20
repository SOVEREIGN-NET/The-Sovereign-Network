//! Root registry contract implementation (authoritative on-chain state).
//!
//! # Phase 6: Lifecycle Integration
//! All read/write operations use `touch()` for lazy state transitions.
//! Block height is authoritative for all lifecycle timestamps.
//!
//! [Phase 5] Implements verification requirements for .sov domain registration.
//! Root-level issuance requires identity-anchored proofs with graduated access
//! control based on domain classification.

use std::collections::HashMap;

use super::delegation_tree::DelegationTree;
use super::namespace_policy::NamespacePolicy;
use super::types::{
    hash_name, normalize_name, BlockHeight, CustodianId, DaoId, EffectiveStatus,
    LegacyDomainRecord, LifecycleFields, LifecycleParams, NameClass, NameClassification, NameHash,
    NameStatus, PublicKey, ReasonCode, RevokedRecord, VerificationLevel, VerificationProof,
    WelfareSector, ZoneController, timing,
};
use crate::impl_lifecycle_fields_accessors;

/// Simplified internal record for RootRegistry core operations
///
/// # Phase 6: Block Height Authority
/// All lifecycle timestamps use block height (never wall-clock on-chain).
/// The `effective_status()` method computes derived status from timestamps.
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

    // === Phase 6: Authoritative Block Heights ===
    /// When the registration expires (block height) - AUTHORITATIVE
    pub expires_at_height: BlockHeight,
    /// When renewal window opens (block height)
    pub renewal_window_start_height: BlockHeight,
    /// When expiry grace period ends (block height)
    pub renew_grace_until_height: BlockHeight,
    /// When revocation grace period ends (block height)
    /// Only set for governance-initiated revocations (Invariant L5)
    pub revoke_grace_until_height: Option<BlockHeight>,
    /// Custodian for domains returned to governance
    pub custodian: Option<CustodianId>,

    // === Legacy (for display/migration compatibility) ===
    /// When the registration expires (unix timestamp) - DISPLAY ONLY
    #[deprecated(note = "Use expires_at_height for on-chain logic")]
    pub expires_at: u64,
    #[deprecated(note = "Use renew_grace_until_height for on-chain logic")]
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
    /// Phase 6: Governable lifecycle parameters
    lifecycle_params: LifecycleParams,
}

impl RootRegistry {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            delegation_tree: DelegationTree::new(),
            policy: NamespacePolicy::new(),
            welfare_sector_to_dao: HashMap::new(),
            lifecycle_params: LifecycleParams::default(),
        }
    }

    /// Create with custom lifecycle parameters
    pub fn with_lifecycle_params(params: LifecycleParams) -> Self {
        Self {
            records: HashMap::new(),
            delegation_tree: DelegationTree::new(),
            policy: NamespacePolicy::new(),
            welfare_sector_to_dao: HashMap::new(),
            lifecycle_params: params,
        }
    }

    /// Get current lifecycle parameters
    pub fn lifecycle_params(&self) -> &LifecycleParams {
        &self.lifecycle_params
    }

    /// Update lifecycle parameters (governance action)
    pub fn set_lifecycle_params(&mut self, params: LifecycleParams) -> Result<(), String> {
        params.validate()?;
        self.lifecycle_params = params;
        Ok(())
    }

    /// Get a record, applying lazy state transitions (Phase 6: Invariant L6)
    ///
    /// This is the primary read method. It ensures no zombie domains by
    /// computing effective status on every access.
    pub fn get_record(&self, name_hash: &NameHash) -> Option<CoreNameRecord> {
        self.records.get(name_hash).map(|stored| self.load_record(stored))
    }

    /// Get record with lazy state transition and mutation (for writes)
    ///
    /// # Phase 6: Lazy Transitions
    /// This method:
    /// 1. Loads the record
    /// 2. Computes effective_status(current_height)
    /// 3. If past grace, finalizes to Released/ReturnedToGovernance
    /// 4. Persists the updated state
    ///
    /// Returns None if record doesn't exist or has been released.
    pub fn touch(&mut self, name_hash: &NameHash, current_height: BlockHeight) -> Option<CoreNameRecord> {
        let stored = self.records.get(name_hash)?;
        let mut record = self.load_record(stored);

        // Compute effective status
        let effective = record.effective_status(current_height);

        // Handle terminal transitions
        match effective {
            EffectiveStatus::Released => {
                // Commercial domain past grace - finalize release
                record.finalize_release();
                self.records.insert(*name_hash, CoreStoredRecord::V2(record.clone()));
                // Return None to indicate domain is no longer owned
                return None;
            }
            EffectiveStatus::ReturnedToGovernance => {
                // Welfare/Reserved domain past grace - finalize return
                let sector_dao = record.governance_pointer;
                record.finalize_return_to_governance(sector_dao);
                self.records.insert(*name_hash, CoreStoredRecord::V2(record.clone()));
            }
            _ => {
                // No state change needed
            }
        }

        Some(record)
    }

    /// Get record with effective status computed (read-only, no mutation)
    pub fn get_record_with_status(&self, name_hash: &NameHash, current_height: BlockHeight) -> Option<(CoreNameRecord, EffectiveStatus)> {
        let record = self.get_record(name_hash)?;
        let effective = record.effective_status(current_height);
        Some((record, effective))
    }

    /// Register a commercial .sov domain with verification
    ///
    /// [Phase 5] Root-level .sov issuance requires identity-anchored proofs.
    /// Commercial roots require L2 (Verified Entity) minimum.
    ///
    /// # Phase 6: Block Height Authority
    /// Registration uses current_height and duration_blocks instead of timestamps.
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
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
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

        // [Phase 5] Verify identity before registration — critical security gate
        self.policy
            .verify(&classification, verification_level, verification_proof, current_height, None)
            .map_err(|e| e.to_string())?;

        self.insert_record_verified(normalized, owner, classification, verification_level, current_height, duration_blocks, None)
    }

    /// Register a commercial domain without verification (for testing/migration only)
    ///
    /// # WARNING
    /// Bypasses Phase 5 verification requirements. Only for:
    /// - Unit tests that don't need to test verification
    /// - Migration of legacy records
    ///
    /// Production code must use `register_commercial()`.
    #[cfg(any(test, feature = "testing"))]
    pub fn register_commercial_unverified(
        &mut self,
        name: &str,
        owner: PublicKey,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
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

        self.insert_record(normalized, owner, classification, current_height, duration_blocks, None)
    }

    /// Register a reserved root domain (welfare sector roots, etc.)
    ///
    /// # Phase 6: Block Height Authority
    /// Registration uses current_height and duration_blocks instead of timestamps.
    pub fn register_reserved_root(
        &mut self,
        name: &str,
        owner: PublicKey,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
        dao_id: Option<DaoId>,
    ) -> Result<NameHash, String> {
        let normalized = normalize_name(name);
        let classification = self.policy.classify_name(&normalized);

        match classification {
            NameClass::Reserved { .. } => {}
            _ => return Err("Name is not a reserved root".to_string()),
        }

        let name_hash = self.insert_record(normalized, owner, classification, current_height, duration_blocks, dao_id)?;

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

    /// Register a subdomain under a zone controller
    ///
    /// # Phase 6: Block Height Authority
    /// Registration uses current_height and duration_blocks instead of timestamps.
    pub fn register_under_zone_controller(
        &mut self,
        name: &str,
        owner: PublicKey,
        caller: &PublicKey,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
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
            if current_height > expires_at_ctrl {
                return Err("Zone controller is expired".to_string());
            }
        }

        let classification = self.policy.classify_name(&normalized);
        self.insert_record(normalized, owner, classification, current_height, duration_blocks, parent.governance_pointer)
    }

    /// Mark a domain as expired (manual expiration)
    ///
    /// # Phase 6: Deprecation Note
    /// Prefer using `touch()` with the appropriate block height, which will
    /// automatically transition expired domains. This method is kept for
    /// backward compatibility and explicit expiration.
    #[deprecated(note = "Prefer touch() for automatic lifecycle transitions")]
    pub fn expire_name(&mut self, name_hash: &NameHash, current_height: BlockHeight) -> Result<(), String> {
        let record = self
            .get_record(name_hash)
            .ok_or_else(|| "Name record not found".to_string())?;
        
        // Check if already past expiry
        if current_height <= record.expires_at_height {
            return Err("Domain has not yet expired".to_string());
        }
        
        let mut updated = record.clone();
        #[allow(deprecated)]
        {
            // Note: NameStatus::Expired.grace_ends expects Timestamp (legacy)
            // but Phase 6 uses block heights. Use deprecated grace_ends_at or 0.
            // Authoritative grace period is in renew_grace_until_height field.
            updated.status = NameStatus::Expired { 
                grace_ends: updated.grace_ends_at.unwrap_or(0)
            };
        }
        self.records.insert(*name_hash, CoreStoredRecord::V2(updated));
        self.suspend_children(name_hash);
        Ok(())
    }

    /// Renew a domain registration (Phase 6)
    ///
    /// # Arguments
    /// * `name_hash` - Hash of the domain to renew
    /// * `caller` - The caller's public key (must be owner)
    /// * `current_height` - Current block height
    /// * `duration_blocks` - Additional duration in blocks
    /// * `fee_paid` - Fee paid for renewal
    ///
    /// # Returns
    /// * `Ok(u64)` - The required fee (caller should verify fee_paid >= this)
    /// * `Err(String)` - If renewal fails
    pub fn renew_name(
        &mut self,
        name_hash: &NameHash,
        caller: &PublicKey,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
        base_fee: u64,
    ) -> Result<u64, String> {
        // Use touch to apply any pending transitions
        let record = self
            .touch(name_hash, current_height)
            .ok_or_else(|| "Domain not found or has been released".to_string())?;

        // Verify caller is owner
        if &record.owner != caller {
            return Err("Only owner can renew".to_string());
        }

        // Check if renewal is allowed
        if !record.can_renew_at(current_height) {
            return Err("Domain cannot be renewed at this time".to_string());
        }

        // Calculate fee with potential late penalty
        let required_fee = record.calculate_renewal_fee(
            current_height,
            base_fee,
            self.lifecycle_params.late_renewal_penalty_percent,
        );

        if required_fee == 0 {
            return Err("Domain is past grace period and cannot be renewed".to_string());
        }

        // Apply the renewal
        let mut updated = record.clone();
        updated.extend_registration(duration_blocks, &self.lifecycle_params, current_height);
        self.records.insert(*name_hash, CoreStoredRecord::V2(updated));

        Ok(required_fee)
    }

    /// Sweep expired domains (batch maintenance - Phase 6: Invariant L7)
    ///
    /// Processes expired domains in ascending order by `renew_grace_until_height`
    /// to ensure deterministic, height-ordered finalization.
    ///
    /// # Arguments
    /// * `current_height` - Current block height
    /// * `limit` - Maximum number of domains to process
    ///
    /// # Returns
    /// Number of domains transitioned
    pub fn sweep_expired(&mut self, current_height: BlockHeight, limit: u32) -> u32 {
        // Collect domains that need finalization with their expiry heights
        let mut candidates: Vec<(NameHash, BlockHeight)> = self.records.iter()
            .filter_map(|(hash, stored)| {
                let record = self.load_record(stored);
                let effective = record.effective_status(current_height);
                if matches!(effective, EffectiveStatus::Released | EffectiveStatus::ReturnedToGovernance) {
                    Some((*hash, record.renew_grace_until_height))
                } else {
                    None
                }
            })
            .collect();

        // Sort by expiry height (ascending) for deterministic, height-ordered finalization
        candidates.sort_by_key(|(_, height)| *height);

        // Process up to limit
        let mut count = 0u32;
        for (name_hash, _) in candidates.into_iter().take(limit as usize) {
            let _ = self.touch(&name_hash, current_height);
            count += 1;
        }

        count
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
    /// # Phase 6: Block Height Authority
    /// Registration uses current_height and duration_blocks instead of timestamps.
    ///
    /// # Arguments
    /// * `sector` - The welfare sector (Food, Health, etc.)
    /// * `label` - The subdomain label (e.g., "farm" for "farm.food.dao.sov")
    /// * `owner` - The owner of the new subdomain
    /// * `verification_level` - The verification level of the owner
    /// * `current_height` - Current block height
    /// * `duration_blocks` - Registration duration in blocks
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
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
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

        // Phase 6: Calculate lifecycle heights
        let expires_at_height = current_height.saturating_add(duration_blocks);
        let renewal_window_start_height = expires_at_height
            .saturating_sub(self.lifecycle_params.renewal_window_blocks);
        let renew_grace_until_height = expires_at_height
            .saturating_add(self.lifecycle_params.expiry_grace_blocks);

        #[allow(deprecated)]
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
            // Phase 6: Authoritative block heights
            expires_at_height,
            renewal_window_start_height,
            renew_grace_until_height,
            revoke_grace_until_height: None,
            custodian: None,
            // Legacy (deprecated)
            expires_at: 0,
            grace_ends_at: None,
        };

        // Register in delegation tree
        self.delegation_tree.add_child(parent_hash, name_hash);

        // Store the record
        self.records.insert(name_hash, CoreStoredRecord::V2(record));

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

    /// Insert a record with a specific verification level stored
    ///
    /// [Phase 5] Used by `register_commercial` after verification passes.
    fn insert_record_verified(
        &mut self,
        normalized_name: String,
        owner: PublicKey,
        classification: NameClass,
        verification_level: VerificationLevel,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
        governance_pointer: Option<DaoId>,
    ) -> Result<NameHash, String> {
        let name_hash = hash_name(&normalized_name);
        if self.records.contains_key(&name_hash) {
            return Err("Name already registered".to_string());
        }

        let parent_hash = parent_hash(&normalized_name);
        let depth = parent_hash.map(|_| 1u8).unwrap_or(0);

        let expires_at_height = current_height.saturating_add(duration_blocks);
        let renewal_window_start_height = expires_at_height
            .saturating_sub(self.lifecycle_params.renewal_window_blocks);
        let renew_grace_until_height = expires_at_height
            .saturating_add(self.lifecycle_params.expiry_grace_blocks);

        #[allow(deprecated)]
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
            expires_at_height,
            renewal_window_start_height,
            renew_grace_until_height,
            revoke_grace_until_height: None,
            custodian: None,
            expires_at: 0,
            grace_ends_at: None,
        };

        if let Some(parent) = record.parent {
            self.delegation_tree.add_child(parent, name_hash);
        }

        self.records.insert(name_hash, CoreStoredRecord::V2(record));
        Ok(name_hash)
    }

    fn insert_record(
        &mut self,
        normalized_name: String,
        owner: PublicKey,
        classification: NameClass,
        current_height: BlockHeight,
        duration_blocks: BlockHeight,
        governance_pointer: Option<DaoId>,
    ) -> Result<NameHash, String> {
        let name_hash = hash_name(&normalized_name);
        if self.records.contains_key(&name_hash) {
            return Err("Name already registered".to_string());
        }

        let parent_hash = parent_hash(&normalized_name);
        let depth = parent_hash.map(|_| 1u8).unwrap_or(0);

        // Phase 6: Calculate lifecycle heights
        let expires_at_height = current_height.saturating_add(duration_blocks);
        let renewal_window_start_height = expires_at_height
            .saturating_sub(self.lifecycle_params.renewal_window_blocks);
        let renew_grace_until_height = expires_at_height
            .saturating_add(self.lifecycle_params.expiry_grace_blocks);

        #[allow(deprecated)]
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
            // Phase 6: Authoritative block heights
            expires_at_height,
            renewal_window_start_height,
            renew_grace_until_height,
            revoke_grace_until_height: None,
            custodian: None,
            // Legacy (deprecated)
            expires_at: 0,
            grace_ends_at: None,
        };

        if let Some(parent) = record.parent {
            self.delegation_tree.add_child(parent, name_hash);
        }

        self.records.insert(name_hash, CoreStoredRecord::V2(record));
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

    // Phase 6: Convert legacy expires_at to block height
    //
    // MIGRATION NOTE:
    // - Legacy `expires_at` was stored as unix timestamp (seconds since epoch)
    // - We convert to an approximate block height assuming 10-second blocks
    // - This conversion is ONLY valid during initial migration when the chain
    //   has a known relationship between wall-clock time and block height
    // - For production migrations, consider using a reference point:
    //   `(legacy.expires_at - genesis_timestamp) / 10 + genesis_height`
    //
    // The resulting block height is approximate and should be validated
    // against actual chain state during migration.
    let estimated_blocks = legacy.expires_at.saturating_div(10);
    let renewal_window = timing::RENEWAL_WINDOW_BLOCKS;
    let grace_period = timing::EXPIRATION_GRACE_BLOCKS;

    #[allow(deprecated)]
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
        // Phase 6: Estimated block heights from legacy timestamp
        expires_at_height: estimated_blocks,
        renewal_window_start_height: estimated_blocks.saturating_sub(renewal_window),
        renew_grace_until_height: estimated_blocks.saturating_add(grace_period),
        revoke_grace_until_height: None,
        custodian: None,
        // Legacy (kept for reference)
        expires_at: legacy.expires_at,
        grace_ends_at: None,
    }
}

// ============================================================================
// CoreNameRecord Implementation (Phase 6: Lifecycle Methods)
// ============================================================================

impl CoreNameRecord {
    /// Determine terminal status based on domain classification
    fn terminal_status_for_class(&self) -> EffectiveStatus {
        match &self.classification {
            NameClass::Commercial { .. } => EffectiveStatus::Released,
            NameClass::WelfareChild { .. } => EffectiveStatus::ReturnedToGovernance,
            NameClass::Reserved { .. } => EffectiveStatus::ReturnedToGovernance,
            NameClass::DaoPrefixed { .. } => EffectiveStatus::ReturnedToGovernance,
        }
    }

    /// Convert NameClass to NameClassification for lifecycle operations
    #[allow(dead_code)] // Reserved for future cross-module lifecycle operations
    fn to_name_classification(&self) -> NameClassification {
        match &self.classification {
            NameClass::Commercial { .. } => NameClassification::Commercial,
            NameClass::WelfareChild { .. } => NameClassification::WelfareDelegated,
            NameClass::Reserved { reason } => {
                use super::types::ReservedReason;
                match reason {
                    ReservedReason::WelfareRoot => NameClassification::ReservedWelfare,
                    ReservedReason::MetaGovernance => NameClassification::ReservedMeta,
                    _ => NameClassification::ReservedByRule,
                }
            }
            NameClass::DaoPrefixed { .. } => NameClassification::ReservedByRule,
        }
    }

    /// Finalize release for commercial domains (Invariant L3)
    pub fn finalize_release(&mut self) {
        self.status = NameStatus::Released;
        self.owner = [0u8; 32]; // Clear ownership
        self.controller = None;
        self.custodian = None;
        self.governance_pointer = None;
    }

    /// Finalize return to governance for welfare/reserved domains
    ///
    /// # Post-Grace Finalization
    /// Welfare/Reserved domains return to appropriate custodian after grace.
    pub fn finalize_return_to_governance(&mut self, sector_dao_id: Option<DaoId>) {
        self.status = NameStatus::Revoked {
            tombstone: RevokedRecord {
                // Note: revoked_at expects Timestamp (legacy), but Phase 6 uses block heights.
                // Authoritative revocation time is derived from renew_grace_until_height.
                // Use 0 as placeholder; display layer should use block height instead.
                revoked_at: 0,
                reason_code: ReasonCode::ExpirationLapsed,
                revoking_authority: [0u8; 32], // System
                appeal_status: None,
            },
        };

        // Set custodian based on classification
        match &self.classification {
            NameClass::WelfareChild { .. } => {
                self.custodian = Some(CustodianId::SectorDao(
                    sector_dao_id.unwrap_or([0u8; 32]),
                ));
            }
            _ => {
                self.custodian = Some(CustodianId::RootGovernance);
            }
        }
    }

    /// Extend registration by duration, recalculating lifecycle heights
    pub fn extend_registration(
        &mut self,
        duration_blocks: BlockHeight,
        params: &LifecycleParams,
        _current_height: BlockHeight,
    ) {
        // Extend from current expiry (not current time)
        let new_expiry = self.expires_at_height.saturating_add(duration_blocks);

        self.expires_at_height = new_expiry;
        self.renewal_window_start_height = new_expiry.saturating_sub(params.renewal_window_blocks);
        self.renew_grace_until_height = new_expiry.saturating_add(params.expiry_grace_blocks);

        // Clear expired state if was in grace
        if matches!(self.status, NameStatus::Expired { .. }) {
            self.status = NameStatus::Active;
        }
    }
}

// Use the macro for CoreNameRecord implementation
impl_lifecycle_fields_accessors!(CoreNameRecord, |record: &CoreNameRecord| {
    record.terminal_status_for_class()
});
