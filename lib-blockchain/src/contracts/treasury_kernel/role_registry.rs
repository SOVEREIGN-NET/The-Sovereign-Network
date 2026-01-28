//! Role Registry - Immutable Entitlement Binding
//!
//! The Role Registry manages:
//! - Role definitions with compensation ceilings
//! - Assignments with snapshotted caps
//! - Prohibited role combinations
//!
//! # Key Invariants
//!
//! 1. **Snapshot Immutability**: Once an assignment is created, its snap_* fields
//!    NEVER change. Governance can update role caps, but only NEW assignments
//!    see the new values.
//!
//! 2. **No Retroactive Punishment**: Reducing a role's cap does NOT affect
//!    existing assignments. Workers keep their original entitlement.
//!
//! 3. **Prohibited Combinations**: Some roles cannot be held simultaneously
//!    (e.g., CEO and Auditor). These are enforced at assignment creation.
//!
//! # Consensus-Critical
//! Uses BTreeMap for deterministic iteration. All operations are pure functions
//! of their inputs.

use super::role_types::{
    Assignment, AssignmentError, AssignmentId, AssignmentStatus, IdentityId,
    RoleDefinition, RoleId, RoleRegistryError,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Role Registry - manages roles and assignments
///
/// # Storage
/// Uses BTreeMap for deterministic serialization (consensus-critical).
///
/// # Authorization
/// All mutation operations require governance authorization, verified via
/// the `authorized_admin` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRegistry {
    /// All role definitions (role_id -> definition)
    roles: BTreeMap<RoleId, RoleDefinition>,

    /// All assignments (assignment_id -> assignment)
    assignments: BTreeMap<AssignmentId, Assignment>,

    /// Index: person -> their assignment IDs
    assignments_by_person: BTreeMap<IdentityId, BTreeSet<AssignmentId>>,

    /// Index: role -> assignment IDs for that role
    assignments_by_role: BTreeMap<RoleId, BTreeSet<AssignmentId>>,

    /// Prohibited role combinations (unordered pairs)
    /// Stored as (min(a,b), max(a,b)) for canonical form
    prohibited_combinations: BTreeSet<(RoleId, RoleId)>,

    /// Authorized admin key_id (governance authority)
    authorized_admin: [u8; 32],

    /// Counter for generating unique assignment IDs
    next_assignment_counter: u64,
}

impl RoleRegistry {
    /// Create a new Role Registry
    ///
    /// # Arguments
    /// * `authorized_admin` - Governance authority key_id
    pub fn new(authorized_admin: [u8; 32]) -> Self {
        Self {
            roles: BTreeMap::new(),
            assignments: BTreeMap::new(),
            assignments_by_person: BTreeMap::new(),
            assignments_by_role: BTreeMap::new(),
            prohibited_combinations: BTreeSet::new(),
            authorized_admin,
            next_assignment_counter: 0,
        }
    }

    // ─── Authorization ──────────────────────────────────────────────────────

    /// Verify caller is authorized admin
    fn verify_admin(&self, caller: &[u8; 32]) -> Result<(), RoleRegistryError> {
        if caller != &self.authorized_admin {
            return Err(RoleRegistryError::Unauthorized);
        }
        Ok(())
    }

    // ─── Role Management ────────────────────────────────────────────────────

    /// Grant (create) a new role
    ///
    /// # Arguments
    /// * `role` - Role definition to add
    /// * `caller` - Must be authorized admin
    ///
    /// # Returns
    /// Ok(()) if successful
    pub fn grant_role(
        &mut self,
        role: RoleDefinition,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        if self.roles.contains_key(&role.role_id) {
            return Err(RoleRegistryError::RoleAlreadyExists(role.role_id));
        }

        self.roles.insert(role.role_id, role);
        Ok(())
    }

    /// Revoke (deactivate) a role
    ///
    /// Does NOT affect existing assignments - they keep their snapshots.
    /// Only prevents NEW assignments to this role.
    ///
    /// # Arguments
    /// * `role_id` - Role to revoke
    /// * `caller` - Must be authorized admin
    pub fn revoke_role(
        &mut self,
        role_id: &RoleId,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let role = self
            .roles
            .get_mut(role_id)
            .ok_or(RoleRegistryError::RoleNotFound(*role_id))?;

        role.is_active = false;

        // NOTE: Existing assignments are NOT affected
        // Their snap_* fields remain unchanged

        Ok(())
    }

    /// Update role caps - only affects NEW assignments
    ///
    /// # Arguments
    /// * `role_id` - Role to update
    /// * `new_annual_cap` - New annual cap
    /// * `new_lifetime_cap` - New lifetime cap (None to remove)
    /// * `new_per_epoch_cap` - New per-epoch cap
    /// * `caller` - Must be authorized admin
    ///
    /// # Important
    /// Existing assignments are NOT affected. Their snap_* fields remain unchanged.
    pub fn update_role_caps(
        &mut self,
        role_id: &RoleId,
        new_annual_cap: u64,
        new_lifetime_cap: Option<u64>,
        new_per_epoch_cap: u64,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let role = self
            .roles
            .get_mut(role_id)
            .ok_or(RoleRegistryError::RoleNotFound(*role_id))?;

        role.annual_cap = new_annual_cap;
        role.lifetime_cap = new_lifetime_cap;
        role.per_epoch_cap = new_per_epoch_cap;

        // NOTE: Existing assignments are NOT affected
        // Their snap_* fields remain unchanged

        Ok(())
    }

    /// Get a role definition
    pub fn get_role(&self, role_id: &RoleId) -> Option<&RoleDefinition> {
        self.roles.get(role_id)
    }

    /// Get all roles
    pub fn get_all_roles(&self) -> impl Iterator<Item = &RoleDefinition> {
        self.roles.values()
    }

    /// Get active roles only
    pub fn get_active_roles(&self) -> impl Iterator<Item = &RoleDefinition> {
        self.roles.values().filter(|r| r.is_active)
    }

    // ─── Prohibited Combinations ────────────────────────────────────────────

    /// Add a prohibited role combination
    ///
    /// Once added, no person can hold both roles simultaneously.
    ///
    /// # Arguments
    /// * `role_a` - First role
    /// * `role_b` - Second role
    /// * `caller` - Must be authorized admin
    pub fn add_prohibited_combination(
        &mut self,
        role_a: &RoleId,
        role_b: &RoleId,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        // Store in canonical form (min, max)
        let pair = if role_a < role_b {
            (*role_a, *role_b)
        } else {
            (*role_b, *role_a)
        };

        self.prohibited_combinations.insert(pair);
        Ok(())
    }

    /// Remove a prohibited combination
    pub fn remove_prohibited_combination(
        &mut self,
        role_a: &RoleId,
        role_b: &RoleId,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let pair = if role_a < role_b {
            (*role_a, *role_b)
        } else {
            (*role_b, *role_a)
        };

        self.prohibited_combinations.remove(&pair);
        Ok(())
    }

    /// Check if two roles are a prohibited combination
    pub fn is_prohibited_combination(&self, role_a: &RoleId, role_b: &RoleId) -> bool {
        let pair = if role_a < role_b {
            (*role_a, *role_b)
        } else {
            (*role_b, *role_a)
        };

        self.prohibited_combinations.contains(&pair)
    }

    // ─── Assignment Management ──────────────────────────────────────────────

    /// Generate unique assignment ID
    fn generate_assignment_id(&mut self, person_id: &IdentityId, role_id: &RoleId) -> AssignmentId {
        use blake3::Hasher;

        // Increment counter first to ensure same value is used in hash and ID
        self.next_assignment_counter += 1;
        let counter = self.next_assignment_counter;

        // Use Blake3 for deterministic, consensus-safe hashing
        let mut hasher = Hasher::new();
        hasher.update(person_id);
        hasher.update(role_id);
        hasher.update(&counter.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        let mut id = [0u8; 32];
        // First 8 bytes from Blake3 hash
        id[..8].copy_from_slice(&hash_bytes[..8]);
        // Next 8 bytes: counter for uniqueness
        id[8..16].copy_from_slice(&counter.to_le_bytes());
        // Next 8 bytes: prefix of person_id for traceability
        id[16..24].copy_from_slice(&person_id[..8]);
        // Last 8 bytes: prefix of role_id for traceability
        id[24..32].copy_from_slice(&role_id[..8]);
        id
    }

    /// Get active roles for a person
    pub fn get_active_roles_for_person(&self, person_id: &IdentityId) -> Vec<RoleId> {
        self.assignments_by_person
            .get(person_id)
            .map(|assignment_ids| {
                assignment_ids
                    .iter()
                    .filter_map(|aid| self.assignments.get(aid))
                    .filter(|a| a.status == AssignmentStatus::Active)
                    .map(|a| a.role_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Create a new assignment with snapshotted caps
    ///
    /// # Arguments
    /// * `person_id` - Person to assign
    /// * `role_id` - Role to assign
    /// * `current_epoch` - Current epoch
    /// * `current_year` - Current year
    /// * `caller` - Must be authorized admin
    ///
    /// # Returns
    /// The created assignment with snapshotted caps
    ///
    /// # Errors
    /// - RoleNotFound if role doesn't exist
    /// - RoleNotActive if role is deactivated
    /// - DuplicateAssignment if person already has this role
    /// - ProhibitedCombination if person has incompatible role
    pub fn create_assignment(
        &mut self,
        person_id: &IdentityId,
        role_id: &RoleId,
        current_epoch: u64,
        current_year: u64,
        caller: &[u8; 32],
    ) -> Result<Assignment, RoleRegistryError> {
        self.verify_admin(caller)?;

        // Get role definition and clone to avoid borrow conflicts
        let role = self
            .roles
            .get(role_id)
            .ok_or(RoleRegistryError::RoleNotFound(*role_id))?
            .clone();

        // Check role is active
        if !role.is_active {
            return Err(RoleRegistryError::RoleNotActive(*role_id));
        }

        // Check for duplicate assignment
        let existing_roles = self.get_active_roles_for_person(person_id);
        if existing_roles.contains(role_id) {
            return Err(RoleRegistryError::DuplicateAssignment {
                person_id: *person_id,
                role_id: *role_id,
            });
        }

        // Check prohibited combinations
        for existing_role in &existing_roles {
            if self.is_prohibited_combination(role_id, existing_role) {
                return Err(RoleRegistryError::ProhibitedCombination {
                    role_a: *role_id,
                    role_b: *existing_role,
                });
            }
        }

        // Create assignment with SNAPSHOTTED caps
        let assignment_id = self.generate_assignment_id(person_id, role_id);
        let assignment = Assignment::new(
            assignment_id,
            *person_id,
            &role,
            current_epoch,
            current_year,
        );

        // Insert into storage
        self.assignments.insert(assignment_id, assignment.clone());

        // Update indices
        self.assignments_by_person
            .entry(*person_id)
            .or_default()
            .insert(assignment_id);

        self.assignments_by_role
            .entry(*role_id)
            .or_default()
            .insert(assignment_id);

        Ok(assignment)
    }

    /// Get an assignment by ID
    pub fn get_assignment(&self, assignment_id: &AssignmentId) -> Option<&Assignment> {
        self.assignments.get(assignment_id)
    }

    /// Get mutable assignment by ID
    pub fn get_assignment_mut(&mut self, assignment_id: &AssignmentId) -> Option<&mut Assignment> {
        self.assignments.get_mut(assignment_id)
    }

    /// Get all assignments for a person
    pub fn get_assignments_for_person(&self, person_id: &IdentityId) -> Vec<&Assignment> {
        self.assignments_by_person
            .get(person_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.assignments.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record a payment to an assignment
    ///
    /// # Arguments
    /// * `assignment_id` - Assignment to pay
    /// * `amount` - Amount to pay
    /// * `current_epoch` - Current epoch
    /// * `current_year` - Current year
    ///
    /// # Returns
    /// Ok(()) if successful
    pub fn record_payment(
        &mut self,
        assignment_id: &AssignmentId,
        amount: u64,
        current_epoch: u64,
        current_year: u64,
    ) -> Result<(), RoleRegistryError> {
        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or(RoleRegistryError::AssignmentNotFound(*assignment_id))?;

        assignment.record_payment(amount, current_epoch, current_year)?;
        Ok(())
    }

    /// Suspend an assignment
    ///
    /// Preserves accrued entitlement - only pauses future payments.
    pub fn suspend_assignment(
        &mut self,
        assignment_id: &AssignmentId,
        current_epoch: u64,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or(RoleRegistryError::AssignmentNotFound(*assignment_id))?;

        assignment.suspend(current_epoch)?;
        Ok(())
    }

    /// Reactivate a suspended assignment
    pub fn reactivate_assignment(
        &mut self,
        assignment_id: &AssignmentId,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or(RoleRegistryError::AssignmentNotFound(*assignment_id))?;

        assignment.reactivate()?;
        Ok(())
    }

    /// Terminate an assignment permanently
    pub fn terminate_assignment(
        &mut self,
        assignment_id: &AssignmentId,
        current_epoch: u64,
        caller: &[u8; 32],
    ) -> Result<(), RoleRegistryError> {
        self.verify_admin(caller)?;

        let assignment = self
            .assignments
            .get_mut(assignment_id)
            .ok_or(RoleRegistryError::AssignmentNotFound(*assignment_id))?;

        assignment.terminate(current_epoch)?;
        Ok(())
    }

    // ─── Statistics ─────────────────────────────────────────────────────────

    /// Get total number of roles
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    /// Get total number of assignments
    pub fn assignment_count(&self) -> usize {
        self.assignments.len()
    }

    /// Get number of active assignments
    pub fn active_assignment_count(&self) -> usize {
        self.assignments
            .values()
            .filter(|a| a.status == AssignmentStatus::Active)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_key() -> [u8; 32] {
        [1u8; 32]
    }

    fn other_key() -> [u8; 32] {
        [2u8; 32]
    }

    fn alice_id() -> IdentityId {
        [10u8; 32]
    }

    fn bob_id() -> IdentityId {
        [11u8; 32]
    }

    fn engineer_role_id() -> RoleId {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(b"engineer");
        id
    }

    fn ceo_role_id() -> RoleId {
        let mut id = [0u8; 32];
        id[..3].copy_from_slice(b"ceo");
        id
    }

    fn auditor_role_id() -> RoleId {
        let mut id = [0u8; 32];
        id[..7].copy_from_slice(b"auditor");
        id
    }

    fn engineer_role() -> RoleDefinition {
        RoleDefinition::new(
            engineer_role_id(),
            "Engineer".to_string(),
            "Software Engineer".to_string(),
            100_000, // annual cap
            10_000,  // per epoch cap
            100,     // created at epoch
        )
    }

    fn ceo_role() -> RoleDefinition {
        RoleDefinition::new(
            ceo_role_id(),
            "CEO".to_string(),
            "Chief Executive Officer".to_string(),
            500_000, // annual cap
            50_000,  // per epoch cap
            100,
        )
    }

    fn auditor_role() -> RoleDefinition {
        RoleDefinition::new(
            auditor_role_id(),
            "Auditor".to_string(),
            "Financial Auditor".to_string(),
            150_000,
            15_000,
            100,
        )
    }

    #[test]
    fn test_grant_role() {
        let mut registry = RoleRegistry::new(admin_key());
        let role = engineer_role();

        assert!(registry.grant_role(role.clone(), &admin_key()).is_ok());
        assert!(registry.get_role(&engineer_role_id()).is_some());
    }

    #[test]
    fn test_grant_role_unauthorized() {
        let mut registry = RoleRegistry::new(admin_key());
        let role = engineer_role();

        let result = registry.grant_role(role, &other_key());
        assert!(matches!(result, Err(RoleRegistryError::Unauthorized)));
    }

    #[test]
    fn test_grant_role_duplicate() {
        let mut registry = RoleRegistry::new(admin_key());
        let role = engineer_role();

        registry.grant_role(role.clone(), &admin_key()).unwrap();
        let result = registry.grant_role(role, &admin_key());
        assert!(matches!(result, Err(RoleRegistryError::RoleAlreadyExists(_))));
    }

    #[test]
    fn test_revoke_role() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        assert!(registry.revoke_role(&engineer_role_id(), &admin_key()).is_ok());
        assert!(!registry.get_role(&engineer_role_id()).unwrap().is_active);
    }

    #[test]
    fn test_update_role_caps() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        registry
            .update_role_caps(&engineer_role_id(), 50_000, Some(200_000), 5_000, &admin_key())
            .unwrap();

        let role = registry.get_role(&engineer_role_id()).unwrap();
        assert_eq!(role.annual_cap, 50_000);
        assert_eq!(role.lifetime_cap, Some(200_000));
        assert_eq!(role.per_epoch_cap, 5_000);
    }

    #[test]
    fn test_create_assignment_snapshots_caps() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        let assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();

        // Verify caps are snapshotted
        assert_eq!(assignment.snap_annual_cap, 100_000);
        assert_eq!(assignment.snap_per_epoch_cap, 10_000);
    }

    #[test]
    fn test_reducing_role_cap_does_not_affect_existing_assignment() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // Create assignment - snapshots 100k
        let assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        let assignment_id = assignment.assignment_id;
        assert_eq!(assignment.snap_annual_cap, 100_000);

        // Governance reduces cap to 50k
        registry
            .update_role_caps(&engineer_role_id(), 50_000, None, 5_000, &admin_key())
            .unwrap();

        // Alice's assignment still has 100k cap
        let assignment = registry.get_assignment(&assignment_id).unwrap();
        assert_eq!(assignment.snap_annual_cap, 100_000); // NOT 50k
    }

    #[test]
    fn test_new_assignment_reflects_new_cap() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // Alice assigned at 100k
        let alice_assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();

        // Cap reduced to 50k
        registry
            .update_role_caps(&engineer_role_id(), 50_000, None, 5_000, &admin_key())
            .unwrap();

        // Bob assigned at 50k (new cap)
        let bob_assignment = registry
            .create_assignment(&bob_id(), &engineer_role_id(), 101, 2024, &admin_key())
            .unwrap();

        assert_eq!(alice_assignment.snap_annual_cap, 100_000);
        assert_eq!(bob_assignment.snap_annual_cap, 50_000);
    }

    #[test]
    fn test_prohibited_role_combinations_rejected() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(ceo_role(), &admin_key()).unwrap();
        registry.grant_role(auditor_role(), &admin_key()).unwrap();

        // Define CEO and Auditor as incompatible
        registry
            .add_prohibited_combination(&ceo_role_id(), &auditor_role_id(), &admin_key())
            .unwrap();

        // Alice is CEO
        registry
            .create_assignment(&alice_id(), &ceo_role_id(), 100, 2024, &admin_key())
            .unwrap();

        // Alice cannot also be Auditor
        let result =
            registry.create_assignment(&alice_id(), &auditor_role_id(), 100, 2024, &admin_key());

        assert!(matches!(
            result,
            Err(RoleRegistryError::ProhibitedCombination { .. })
        ));
    }

    #[test]
    fn test_suspension_does_not_change_accrued_entitlement() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // Create assignment, pay 50k over multiple epochs (10k per epoch cap)
        let assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        let assignment_id = assignment.assignment_id;

        // Pay 10k per epoch for 5 epochs = 50k total
        for epoch in 100..105 {
            registry.record_payment(&assignment_id, 10_000, epoch, 2024).unwrap();
        }

        // Suspend
        registry
            .suspend_assignment(&assignment_id, 106, &admin_key())
            .unwrap();

        // Accrued entitlement unchanged
        let assignment = registry.get_assignment(&assignment_id).unwrap();
        assert_eq!(assignment.total_paid, 50_000);
        assert_eq!(assignment.snap_annual_cap, 100_000); // Still 50k remaining
        assert_eq!(assignment.status, AssignmentStatus::Suspended);
    }

    #[test]
    fn test_duplicate_assignment_rejected() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // First assignment
        registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();

        // Duplicate rejected
        let result =
            registry.create_assignment(&alice_id(), &engineer_role_id(), 101, 2024, &admin_key());

        assert!(matches!(
            result,
            Err(RoleRegistryError::DuplicateAssignment { .. })
        ));
    }

    #[test]
    fn test_cannot_assign_to_inactive_role() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // Revoke role
        registry.revoke_role(&engineer_role_id(), &admin_key()).unwrap();

        // Cannot assign to inactive role
        let result =
            registry.create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key());

        assert!(matches!(result, Err(RoleRegistryError::RoleNotActive(_))));
    }

    #[test]
    fn test_assignment_lifecycle() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();

        // Create
        let assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        let assignment_id = assignment.assignment_id;

        // Pay
        registry.record_payment(&assignment_id, 10_000, 100, 2024).unwrap();

        // Suspend
        registry
            .suspend_assignment(&assignment_id, 101, &admin_key())
            .unwrap();

        // Reactivate
        registry
            .reactivate_assignment(&assignment_id, &admin_key())
            .unwrap();

        // Pay more
        registry.record_payment(&assignment_id, 10_000, 102, 2024).unwrap();

        // Terminate
        registry
            .terminate_assignment(&assignment_id, 103, &admin_key())
            .unwrap();

        let assignment = registry.get_assignment(&assignment_id).unwrap();
        assert_eq!(assignment.total_paid, 20_000);
        assert_eq!(assignment.status, AssignmentStatus::Terminated);
    }

    #[test]
    fn test_get_assignments_for_person() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();
        registry.grant_role(ceo_role(), &admin_key()).unwrap();

        registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        registry
            .create_assignment(&alice_id(), &ceo_role_id(), 100, 2024, &admin_key())
            .unwrap();

        let assignments = registry.get_assignments_for_person(&alice_id());
        assert_eq!(assignments.len(), 2);
    }

    #[test]
    fn test_get_active_roles_for_person() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();
        registry.grant_role(ceo_role(), &admin_key()).unwrap();

        let eng_assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        registry
            .create_assignment(&alice_id(), &ceo_role_id(), 100, 2024, &admin_key())
            .unwrap();

        // Suspend engineer assignment
        registry
            .suspend_assignment(&eng_assignment.assignment_id, 101, &admin_key())
            .unwrap();

        // Only CEO should be active
        let active_roles = registry.get_active_roles_for_person(&alice_id());
        assert_eq!(active_roles.len(), 1);
        assert_eq!(active_roles[0], ceo_role_id());
    }

    #[test]
    fn test_statistics() {
        let mut registry = RoleRegistry::new(admin_key());
        registry.grant_role(engineer_role(), &admin_key()).unwrap();
        registry.grant_role(ceo_role(), &admin_key()).unwrap();

        assert_eq!(registry.role_count(), 2);

        let assignment = registry
            .create_assignment(&alice_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();
        registry
            .create_assignment(&bob_id(), &engineer_role_id(), 100, 2024, &admin_key())
            .unwrap();

        assert_eq!(registry.assignment_count(), 2);
        assert_eq!(registry.active_assignment_count(), 2);

        registry
            .suspend_assignment(&assignment.assignment_id, 101, &admin_key())
            .unwrap();

        assert_eq!(registry.active_assignment_count(), 1);
    }
}
