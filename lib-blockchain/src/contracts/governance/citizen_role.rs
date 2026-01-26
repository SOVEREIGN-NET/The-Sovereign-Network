//! Citizen Role Registry
//!
//! Defines the Citizen role and registry for Universal Basic Income (UBI) eligibility.
//! Per ADR-0017 and Issue #844 (Prep Phase):
//! - Citizen is a role that enables UBI claim eligibility
//! - Citizenship is gated by role verification (no direct UBI minting)
//! - All actual distribution is deferred to Treasury Kernel
//! - This module defines SCHEMA ONLY, not execution logic

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Citizen role - grants eligibility for UBI claims
///
/// # Design Principles
/// - Citizenship is verified at registration time
/// - Role is immutable once created (cannot change citizenship_epoch)
/// - Revocation is explicit and timestamped (for audit trail)
/// - No direct token transfer authority (Treasury Kernel owns minting)
///
/// # Integration with Treasury Kernel
/// When Treasury Kernel processes UBI distributions:
/// 1. Reads citizen_id from claim intent
/// 2. Looks up CitizenRole in registry
/// 3. Checks: role_type == "citizen" && revoked == false && citizenship_epoch <= current_epoch
/// 4. If valid: Kernel mints tokens to citizen_id
/// 5. If invalid: Kernel rejects claim with deterministic error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitizenRole {
    /// Unique citizen identifier (linked to identity proof)
    /// - 32 bytes to match blockchain address format
    /// - Deterministic from identity verification
    pub citizen_id: [u8; 32],

    /// Role type discriminator (always "citizen" for this struct)
    /// - Enables future role variants (e.g., "verified_citizen", "institutional_citizen")
    /// - Used for Role Registry queries: filter by role_type
    /// - Note: This is conceptual; could be enum in future versions
    pub role_type: u8, // 0 = "citizen", future: 1 = "verified", 2 = "institutional"

    /// Block epoch when citizen verification was completed
    /// - Determines earliest UBI claim eligibility
    /// - Used by Treasury Kernel: citizenship_epoch <= current_epoch required for payouts
    /// - Immutable after registration (no backdating)
    pub citizenship_epoch: u64,

    /// Block height when citizenship was first verified
    /// - Audit trail: when identity proof was accepted
    /// - Used for governance queries: "how long has this citizen been verified?"
    /// - Immutable after registration
    pub verified_at: u64,

    /// Revocation status
    /// - true = citizenship revoked (cannot claim UBI anymore)
    /// - false = citizenship active (can claim if other conditions met)
    /// - Can only transition false → true (never unrevoke)
    pub revoked: bool,

    /// Block epoch when revocation occurred (if revoked)
    /// - Some(epoch) = revoked at this epoch
    /// - None = not revoked
    /// - Used by Treasury Kernel: reject any claims with timestamp >= revoked_epoch
    pub revoked_epoch: Option<u64>,
}

impl CitizenRole {
    /// Create a new citizen role
    ///
    /// # Parameters
    /// - `citizen_id`: Verified identity hash
    /// - `citizenship_epoch`: When verification happened
    /// - `verified_at`: Block height of verification
    ///
    /// # Returns
    /// New CitizenRole with revoked = false, revoked_epoch = None
    pub fn new(citizen_id: [u8; 32], citizenship_epoch: u64, verified_at: u64) -> Self {
        CitizenRole {
            citizen_id,
            role_type: 0, // "citizen"
            citizenship_epoch,
            verified_at,
            revoked: false,
            revoked_epoch: None,
        }
    }

    /// Revoke this citizen (immutable - cannot be undone)
    ///
    /// # Parameters
    /// - `revoked_epoch`: Block epoch when revocation takes effect
    ///
    /// # Returns
    /// - Ok(()) if revocation succeeded
    /// - Err if already revoked
    pub fn revoke(&mut self, revoked_epoch: u64) -> Result<(), CitizenRoleError> {
        if self.revoked {
            return Err(CitizenRoleError::AlreadyRevoked);
        }
        self.revoked = true;
        self.revoked_epoch = Some(revoked_epoch);
        Ok(())
    }

    /// Check if this citizen is currently eligible for UBI (role-gating check only)
    ///
    /// # Parameters
    /// - `current_epoch`: Current block epoch
    ///
    /// # Returns
    /// true if: not revoked AND citizenship_epoch <= current_epoch
    ///
    /// # Note
    /// This checks role eligibility ONLY. Treasury Kernel performs additional checks:
    /// - Pool cap enforcement
    /// - Duplicate claim prevention
    /// - Economic parameter validation
    pub fn is_eligible_for_ubi(&self, current_epoch: u64) -> bool {
        !self.revoked && self.citizenship_epoch <= current_epoch
    }

    /// Get the role type name for queries and logging
    pub fn role_type_name(&self) -> &'static str {
        match self.role_type {
            0 => "citizen",
            1 => "verified_citizen",
            2 => "institutional_citizen",
            _ => "unknown",
        }
    }
}

/// Errors for citizen role operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CitizenRoleError {
    /// Citizen already exists with this ID
    AlreadyExists,

    /// Citizen not found in registry
    NotFound,

    /// Citizen already revoked (cannot revoke twice)
    AlreadyRevoked,

    /// Invalid epoch (e.g., citizenship_epoch in future)
    InvalidEpoch,

    /// Registry is full (max capacity reached)
    RegistryFull,
}

/// Citizen Role Registry - stores all verified citizens for UBI eligibility
///
/// # Design
/// - Immutable after registration (no updates, only create/revoke)
/// - Append-only (citizens can be revoked but never removed)
/// - Indexed by citizen_id for O(1) lookup
/// - Total ordering by citizenship_epoch for batch processing
///
/// # Integration with Treasury Kernel
/// Kernel reads from this registry during:
/// 1. UBI distribution at epoch boundaries
/// 2. Claim validation (is this citizen in registry?)
/// 3. Eligibility checks (not revoked? citizenship_epoch <= current_epoch?)
///
/// # Governance
/// Only authorized role (e.g., Identity Governor) can:
/// - Register new citizens
/// - Revoke existing citizens
/// Changes are recorded as governance events for audit trail
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CitizenRegistry {
    /// citizen_id -> CitizenRole (primary index)
    citizens: HashMap<[u8; 32], CitizenRole>,

    /// All citizens in insertion order (for iteration, auditing)
    citizen_list: Vec<[u8; 32]>,

    /// Monotonic counter: total citizens ever registered (including revoked)
    total_registered: u64,

    /// Count of currently active (not revoked) citizens
    active_count: u64,
}

impl CitizenRegistry {
    /// Create a new empty citizen registry
    pub fn new() -> Self {
        CitizenRegistry {
            citizens: HashMap::new(),
            citizen_list: Vec::new(),
            total_registered: 0,
            active_count: 0,
        }
    }

    /// Register a new citizen
    ///
    /// # Parameters
    /// - `role`: CitizenRole to register
    ///
    /// # Returns
    /// - Ok(()) if registration succeeded
    /// - Err if citizen already exists
    ///
    /// # Invariants
    /// - citizen_id must not already exist in registry
    /// - citizenship_epoch should not be in future (governance should validate)
    pub fn register(&mut self, role: CitizenRole) -> Result<(), CitizenRoleError> {
        if self.citizens.contains_key(&role.citizen_id) {
            return Err(CitizenRoleError::AlreadyExists);
        }

        self.citizen_list.push(role.citizen_id);
        self.citizens.insert(role.citizen_id, role);
        self.total_registered += 1;
        self.active_count += 1;

        Ok(())
    }

    /// Look up a citizen by ID
    ///
    /// # Returns
    /// - Some(&CitizenRole) if found
    /// - None if not found
    pub fn get(&self, citizen_id: &[u8; 32]) -> Option<&CitizenRole> {
        self.citizens.get(citizen_id)
    }

    /// Look up a citizen by ID (mutable)
    ///
    /// Used for revocation and other state changes
    fn get_mut(&mut self, citizen_id: &[u8; 32]) -> Option<&mut CitizenRole> {
        self.citizens.get_mut(citizen_id)
    }

    /// Revoke a citizen (immutable operation)
    ///
    /// # Parameters
    /// - `citizen_id`: Which citizen to revoke
    /// - `revoked_epoch`: When revocation takes effect
    ///
    /// # Returns
    /// - Ok(()) if revocation succeeded
    /// - Err if citizen not found or already revoked
    pub fn revoke(
        &mut self,
        citizen_id: &[u8; 32],
        revoked_epoch: u64,
    ) -> Result<(), CitizenRoleError> {
        let citizen = self
            .get_mut(citizen_id)
            .ok_or(CitizenRoleError::NotFound)?;

        citizen.revoke(revoked_epoch)?;
        self.active_count -= 1;

        Ok(())
    }

    /// Check if a citizen is eligible for UBI
    ///
    /// # Parameters
    /// - `citizen_id`: Which citizen to check
    /// - `current_epoch`: Current block epoch
    ///
    /// # Returns
    /// - Some(true) if eligible
    /// - Some(false) if found but not eligible
    /// - None if not found
    ///
    /// # Used by Treasury Kernel
    /// When processing UBI claims, Kernel calls this to gate access
    pub fn is_eligible_for_ubi(&self, citizen_id: &[u8; 32], current_epoch: u64) -> Option<bool> {
        self.get(citizen_id).map(|role| role.is_eligible_for_ubi(current_epoch))
    }

    /// Get all active citizens (for batch processing by Treasury Kernel)
    ///
    /// # Returns
    /// Vector of (citizen_id, role) for all non-revoked citizens
    pub fn get_active_citizens(&self) -> Vec<([u8; 32], &CitizenRole)> {
        self.citizen_list
            .iter()
            .filter_map(|id| {
                self.citizens.get(id).and_then(|role| {
                    if !role.revoked {
                        Some((*id, role))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Get registry statistics
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_registered: self.total_registered,
            active_count: self.active_count,
            revoked_count: self.total_registered.saturating_sub(self.active_count),
        }
    }
}

/// Statistics about the citizen registry
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RegistryStats {
    pub total_registered: u64,
    pub active_count: u64,
    pub revoked_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_citizen_role_creation() {
        let citizen_id = [1u8; 32];
        let role = CitizenRole::new(citizen_id, 100, 50);

        assert_eq!(role.citizen_id, citizen_id);
        assert_eq!(role.citizenship_epoch, 100);
        assert_eq!(role.verified_at, 50);
        assert!(!role.revoked);
        assert_eq!(role.revoked_epoch, None);
        assert_eq!(role.role_type_name(), "citizen");
    }

    #[test]
    fn test_citizen_eligibility() {
        let role = CitizenRole::new([1u8; 32], 100, 50);

        // Before citizenship epoch: not eligible
        assert!(!role.is_eligible_for_ubi(99));

        // At citizenship epoch: eligible
        assert!(role.is_eligible_for_ubi(100));

        // After citizenship epoch: eligible
        assert!(role.is_eligible_for_ubi(200));
    }

    #[test]
    fn test_citizen_revocation() {
        let mut role = CitizenRole::new([1u8; 32], 100, 50);

        // Before revocation: eligible
        assert!(!role.revoked);

        // Revoke at epoch 150
        role.revoke(150).expect("revocation should succeed");

        // After revocation: not eligible
        assert!(role.revoked);
        assert_eq!(role.revoked_epoch, Some(150));
        assert!(!role.is_eligible_for_ubi(160));
    }

    #[test]
    fn test_double_revocation_fails() {
        let mut role = CitizenRole::new([1u8; 32], 100, 50);
        role.revoke(150).expect("first revocation should succeed");

        let result = role.revoke(160);
        assert_eq!(result, Err(CitizenRoleError::AlreadyRevoked));
    }

    #[test]
    fn test_registry_registration() {
        let mut registry = CitizenRegistry::new();
        let citizen_id = [1u8; 32];
        let role = CitizenRole::new(citizen_id, 100, 50);

        registry.register(role).expect("registration should succeed");

        assert_eq!(registry.get(&citizen_id), Some(&role));
        assert_eq!(registry.stats().active_count, 1);
        assert_eq!(registry.stats().total_registered, 1);
    }

    #[test]
    fn test_registry_duplicate_registration_fails() {
        let mut registry = CitizenRegistry::new();
        let citizen_id = [1u8; 32];
        let role = CitizenRole::new(citizen_id, 100, 50);

        registry.register(role).expect("first registration should succeed");

        let result = registry.register(role);
        assert_eq!(result, Err(CitizenRoleError::AlreadyExists));
    }

    #[test]
    fn test_registry_revocation() {
        let mut registry = CitizenRegistry::new();
        let citizen_id = [1u8; 32];
        let role = CitizenRole::new(citizen_id, 100, 50);

        registry.register(role).expect("registration should succeed");
        assert_eq!(registry.stats().active_count, 1);

        registry
            .revoke(&citizen_id, 150)
            .expect("revocation should succeed");

        assert_eq!(registry.stats().active_count, 0);
        assert_eq!(registry.stats().total_registered, 1);
        assert_eq!(registry.stats().revoked_count, 1);
    }

    #[test]
    fn test_registry_eligibility_check() {
        let mut registry = CitizenRegistry::new();
        let citizen_id = [1u8; 32];
        let role = CitizenRole::new(citizen_id, 100, 50);

        registry.register(role).expect("registration should succeed");

        // Before citizenship epoch: not eligible
        assert_eq!(registry.is_eligible_for_ubi(&citizen_id, 99), Some(false));

        // After citizenship epoch: eligible
        assert_eq!(registry.is_eligible_for_ubi(&citizen_id, 100), Some(true));

        // Non-existent citizen: None
        assert_eq!(registry.is_eligible_for_ubi(&[2u8; 32], 100), None);
    }

    #[test]
    fn test_active_citizens_list() {
        let mut registry = CitizenRegistry::new();

        let role1 = CitizenRole::new([1u8; 32], 100, 50);
        let role2 = CitizenRole::new([2u8; 32], 100, 50);

        registry.register(role1).expect("registration should succeed");
        registry.register(role2).expect("registration should succeed");

        assert_eq!(registry.get_active_citizens().len(), 2);

        registry.revoke(&[1u8; 32], 150).expect("revocation should succeed");

        assert_eq!(registry.get_active_citizens().len(), 1);
        let active = registry.get_active_citizens();
        assert_eq!(active[0].0, [2u8; 32]);
    }
}
