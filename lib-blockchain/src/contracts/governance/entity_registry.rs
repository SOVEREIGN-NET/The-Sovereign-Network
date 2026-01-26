//! Entity Registry - DOC 01: Phase 0 Primitives & Fiduciary Mapping
//!
//! Defines the foundational on-chain entities for the SOV economic system.
//! This module establishes the immutable entity definitions and role assignments
//! that govern treasury isolation and fiduciary responsibilities.
//!
//! # Architecture
//!
//! ```text
//! CBE_TREASURY (For-Profit)
//! +-- Role: Operational execution layer
//! +-- Permissions: OPERATOR, PROFIT_DECLARER, TREASURY_SPENDER
//! +-- Constraint: Cannot directly receive nonprofit earnings
//!
//! NONPROFIT_TREASURY (Nonprofit)
//! +-- Role: Mission steward, holder of all nonprofit earnings
//! +-- Permissions: MISSION_CUSTODIAN, TREASURY_HOLDER
//! +-- Constraint: All outflows require DAO governance
//! ```
//!
//! # Core Invariants (Non-Negotiable)
//!
//! - **I1**: CBE_TREASURY != NONPROFIT_TREASURY (always distinct)
//! - **I2**: Exactly ONE CBE_TREASURY (singleton)
//! - **I3**: Exactly ONE NONPROFIT_TREASURY (singleton)
//! - **I4**: CBE cannot receive nonprofit earnings directly
//! - **I5**: Entity types and roles are immutable after initialization

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use crate::integration::crypto_integration::PublicKey;

/// Entity type classification
///
/// Determines the fundamental nature of an entity and its treasury isolation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// For-profit entity (CBE operational layer)
    /// - Can receive 80% of declared profits
    /// - Must pay 20% tribute before disbursements
    /// - Subject to Sunset contract restrictions
    ForProfit,

    /// Nonprofit entity (mission steward)
    /// - Receives 100% of nonprofit earnings
    /// - Receives 20% tribute from for-profit
    /// - Outflows require DAO governance
    Nonprofit,
}

impl EntityType {
    /// Returns human-readable name for the entity type
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::ForProfit => "for_profit",
            EntityType::Nonprofit => "nonprofit",
        }
    }
}

/// Roles that can be assigned to entities
///
/// These roles determine what operations an entity is authorized to perform.
/// Role assignments are immutable after initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Can execute operational spending from treasury
    Operator,

    /// Can declare profits (triggers tribute calculation)
    ProfitDeclarer,

    /// Can spend from treasury (subject to Sunset state)
    TreasurySpender,

    /// Governs mission strategy (nonprofit only)
    MissionCustodian,

    /// Holds funds in treasury (nonprofit only)
    TreasuryHolder,
}

impl Role {
    /// Returns human-readable name for the role
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Operator => "OPERATOR",
            Role::ProfitDeclarer => "PROFIT_DECLARER",
            Role::TreasurySpender => "TREASURY_SPENDER",
            Role::MissionCustodian => "MISSION_CUSTODIAN",
            Role::TreasuryHolder => "TREASURY_HOLDER",
        }
    }

    /// Returns roles valid for ForProfit entities
    pub fn for_profit_roles() -> HashSet<Role> {
        let mut roles = HashSet::new();
        roles.insert(Role::Operator);
        roles.insert(Role::ProfitDeclarer);
        roles.insert(Role::TreasurySpender);
        roles
    }

    /// Returns roles valid for Nonprofit entities
    pub fn nonprofit_roles() -> HashSet<Role> {
        let mut roles = HashSet::new();
        roles.insert(Role::MissionCustodian);
        roles.insert(Role::TreasuryHolder);
        roles
    }
}

/// Entity Registry Contract
///
/// Maintains the canonical mapping of addresses to entity types and roles.
/// Enforces singleton constraints and treasury isolation invariants.
///
/// # Immutability
///
/// Once initialized, the registry cannot be modified. This ensures that:
/// - Entity definitions remain stable across consensus
/// - Treasury isolation rules cannot be bypassed
/// - Fiduciary responsibilities are permanently encoded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRegistry {
    /// CBE (For-Profit) Treasury address - singleton
    cbe_treasury: PublicKey,

    /// Nonprofit Treasury address - singleton
    nonprofit_treasury: PublicKey,

    /// Entity type mapping: Address -> EntityType
    entity_types: HashMap<[u8; 32], EntityType>,

    /// Role assignments: Address -> Set<Role>
    roles: HashMap<[u8; 32], HashSet<Role>>,

    /// Initialization flag - once true, registry is immutable
    initialized: bool,
}

/// Error types for EntityRegistry operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityRegistryError {
    /// Attempted to initialize an already-initialized registry
    AlreadyInitialized,

    /// CBE and Nonprofit treasury addresses must be distinct
    TreasuriesNotDistinct,

    /// Address is zero (invalid)
    ZeroAddress,

    /// Entity not found in registry
    EntityNotFound,

    /// Role not valid for entity type
    InvalidRoleForEntityType,

    /// Registry not initialized
    NotInitialized,

    /// Attempted to modify immutable registry
    RegistryImmutable,
}

impl std::fmt::Display for EntityRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntityRegistryError::AlreadyInitialized =>
                write!(f, "Entity registry already initialized"),
            EntityRegistryError::TreasuriesNotDistinct =>
                write!(f, "CBE and Nonprofit treasury addresses must be distinct"),
            EntityRegistryError::ZeroAddress =>
                write!(f, "Address cannot be zero"),
            EntityRegistryError::EntityNotFound =>
                write!(f, "Entity not found in registry"),
            EntityRegistryError::InvalidRoleForEntityType =>
                write!(f, "Role not valid for this entity type"),
            EntityRegistryError::NotInitialized =>
                write!(f, "Registry not initialized"),
            EntityRegistryError::RegistryImmutable =>
                write!(f, "Registry is immutable after initialization"),
        }
    }
}

impl EntityRegistry {
    /// Internal helper to create a zero/placeholder public key.
    fn zero_public_key() -> PublicKey {
        PublicKey::new(vec![0u8; 32])
    }

    /// Create a new uninitialized EntityRegistry
    pub fn new() -> Self {
        Self {
            cbe_treasury: Self::zero_public_key(),
            nonprofit_treasury: Self::zero_public_key(),
            entity_types: HashMap::new(),
            roles: HashMap::new(),
            initialized: false,
        }
    }

    /// Initialize the registry with CBE and Nonprofit treasury addresses
    ///
    /// # Invariants Enforced
    ///
    /// - I1: cbe_treasury != nonprofit_treasury
    /// - I2: Exactly one CBE treasury
    /// - I3: Exactly one Nonprofit treasury
    /// - I4: All addresses are non-zero
    /// - I5: Registry becomes immutable after this call
    ///
    /// # Arguments
    ///
    /// * `cbe_treasury` - Address of the CBE (for-profit) treasury
    /// * `nonprofit_treasury` - Address of the Nonprofit treasury
    ///
    /// # Errors
    ///
    /// - `AlreadyInitialized` if called more than once
    /// - `TreasuriesNotDistinct` if addresses are equal
    /// - `ZeroAddress` if either address is zero
    pub fn init(
        &mut self,
        cbe_treasury: PublicKey,
        nonprofit_treasury: PublicKey,
    ) -> Result<(), EntityRegistryError> {
        // Check not already initialized
        if self.initialized {
            return Err(EntityRegistryError::AlreadyInitialized);
        }

        // Validate non-zero addresses
        if cbe_treasury.as_bytes().iter().all(|b| *b == 0) {
            return Err(EntityRegistryError::ZeroAddress);
        }
        if nonprofit_treasury.as_bytes().iter().all(|b| *b == 0) {
            return Err(EntityRegistryError::ZeroAddress);
        }

        // Invariant I1: Treasuries must be distinct
        if cbe_treasury.key_id == nonprofit_treasury.key_id {
            return Err(EntityRegistryError::TreasuriesNotDistinct);
        }

        // Set singleton treasuries
        self.cbe_treasury = cbe_treasury.clone();
        self.nonprofit_treasury = nonprofit_treasury.clone();

        // Register CBE as ForProfit with appropriate roles
        self.entity_types.insert(cbe_treasury.key_id, EntityType::ForProfit);
        let mut cbe_roles = HashSet::new();
        cbe_roles.insert(Role::Operator);
        cbe_roles.insert(Role::ProfitDeclarer);
        cbe_roles.insert(Role::TreasurySpender);
        self.roles.insert(cbe_treasury.key_id, cbe_roles);

        // Register Nonprofit with appropriate roles
        self.entity_types.insert(nonprofit_treasury.key_id, EntityType::Nonprofit);
        let mut nonprofit_roles = HashSet::new();
        nonprofit_roles.insert(Role::MissionCustodian);
        nonprofit_roles.insert(Role::TreasuryHolder);
        self.roles.insert(nonprofit_treasury.key_id, nonprofit_roles);

        // Lock the registry (immutable after init)
        self.initialized = true;

        Ok(())
    }

    /// Check if the registry is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the CBE (for-profit) treasury address
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if registry not initialized
    pub fn cbe_treasury(&self) -> Result<&PublicKey, EntityRegistryError> {
        if !self.initialized {
            return Err(EntityRegistryError::NotInitialized);
        }
        Ok(&self.cbe_treasury)
    }

    /// Get the Nonprofit treasury address
    ///
    /// # Errors
    ///
    /// - `NotInitialized` if registry not initialized
    pub fn nonprofit_treasury(&self) -> Result<&PublicKey, EntityRegistryError> {
        if !self.initialized {
            return Err(EntityRegistryError::NotInitialized);
        }
        Ok(&self.nonprofit_treasury)
    }

    /// Get the entity type for an address
    ///
    /// # Arguments
    ///
    /// * `address` - The address to look up
    ///
    /// # Returns
    ///
    /// - `Some(EntityType)` if address is registered
    /// - `None` if address is not registered
    pub fn get_entity_type(&self, address: &PublicKey) -> Option<EntityType> {
        self.entity_types.get(&address.key_id).copied()
    }

    /// Check if an address is the CBE treasury
    pub fn is_cbe_treasury(&self, address: &PublicKey) -> bool {
        self.initialized && address.key_id == self.cbe_treasury.key_id
    }

    /// Check if an address is the Nonprofit treasury
    pub fn is_nonprofit_treasury(&self, address: &PublicKey) -> bool {
        self.initialized && address.key_id == self.nonprofit_treasury.key_id
    }

    /// Check if an address has a specific role
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    /// * `role` - The role to check for
    ///
    /// # Returns
    ///
    /// - `true` if address has the role
    /// - `false` otherwise
    pub fn has_role(&self, address: &PublicKey, role: Role) -> bool {
        self.roles
            .get(&address.key_id)
            .map(|roles| roles.contains(&role))
            .unwrap_or(false)
    }

    /// Get all roles for an address
    ///
    /// # Arguments
    ///
    /// * `address` - The address to look up
    ///
    /// # Returns
    ///
    /// - Set of roles if address is registered
    /// - Empty set if address is not registered
    pub fn get_roles(&self, address: &PublicKey) -> HashSet<Role> {
        self.roles
            .get(&address.key_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Validate that a transfer respects treasury isolation rules
    ///
    /// # Invariant I4 Enforcement
    ///
    /// CBE cannot directly receive nonprofit earnings.
    /// This function validates that a transfer from `from` to `to`
    /// respects this constraint.
    ///
    /// # Arguments
    ///
    /// * `from` - Source address
    /// * `to` - Destination address
    /// * `is_nonprofit_earning` - Whether this transfer represents nonprofit earnings
    ///
    /// # Returns
    ///
    /// - `Ok(())` if transfer is valid
    /// - `Err(...)` if transfer violates treasury isolation
    pub fn validate_transfer(
        &self,
        from: &PublicKey,
        to: &PublicKey,
        is_nonprofit_earning: bool,
    ) -> Result<(), EntityRegistryError> {
        if !self.initialized {
            return Err(EntityRegistryError::NotInitialized);
        }

        // Invariant I4: CBE cannot receive nonprofit earnings
        if is_nonprofit_earning && self.is_cbe_treasury(to) {
            // Nonprofit earnings must go to Nonprofit treasury
            // This is a hard constraint - no exceptions
            return Err(EntityRegistryError::InvalidRoleForEntityType);
        }

        Ok(())
    }

    /// Validate the entire registry state
    ///
    /// Checks all invariants:
    /// - I1: Treasuries are distinct
    /// - I2: Exactly one CBE treasury
    /// - I3: Exactly one Nonprofit treasury
    /// - I5: Roles are valid for entity types
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all invariants hold
    /// - `Err(...)` with the first violation found
    pub fn validate(&self) -> Result<(), EntityRegistryError> {
        if !self.initialized {
            return Err(EntityRegistryError::NotInitialized);
        }

        // I1: Treasuries must be distinct
        if self.cbe_treasury.key_id == self.nonprofit_treasury.key_id {
            return Err(EntityRegistryError::TreasuriesNotDistinct);
        }

        // Validate role assignments match entity types
        for (key_id, entity_type) in &self.entity_types {
            if let Some(roles) = self.roles.get(key_id) {
                let valid_roles = match entity_type {
                    EntityType::ForProfit => Role::for_profit_roles(),
                    EntityType::Nonprofit => Role::nonprofit_roles(),
                };

                for role in roles {
                    if !valid_roles.contains(role) {
                        return Err(EntityRegistryError::InvalidRoleForEntityType);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for EntityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    // ========================================================================
    // INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_new_registry_not_initialized() {
        let registry = EntityRegistry::new();
        assert!(!registry.is_initialized());
    }

    #[test]
    fn test_init_success() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);

        let result = registry.init(cbe.clone(), nonprofit.clone());

        assert!(result.is_ok());
        assert!(registry.is_initialized());
        assert_eq!(registry.cbe_treasury().unwrap().key_id, cbe.key_id);
        assert_eq!(registry.nonprofit_treasury().unwrap().key_id, nonprofit.key_id);
    }

    #[test]
    fn test_init_rejects_duplicate_init() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);

        registry.init(cbe.clone(), nonprofit.clone()).unwrap();
        let result = registry.init(cbe, nonprofit);

        assert_eq!(result, Err(EntityRegistryError::AlreadyInitialized));
    }

    #[test]
    fn test_init_rejects_same_addresses() {
        let mut registry = EntityRegistry::new();
        let same_key = create_test_public_key(1);

        let result = registry.init(same_key.clone(), same_key);

        assert_eq!(result, Err(EntityRegistryError::TreasuriesNotDistinct));
    }

    #[test]
    fn test_init_rejects_zero_cbe_address() {
        let mut registry = EntityRegistry::new();
        let zero = PublicKey::new(vec![0u8; 32]);
        let nonprofit = create_test_public_key(2);

        let result = registry.init(zero, nonprofit);

        assert_eq!(result, Err(EntityRegistryError::ZeroAddress));
    }

    #[test]
    fn test_init_rejects_zero_nonprofit_address() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let zero = PublicKey::new(vec![0u8; 32]);

        let result = registry.init(cbe, zero);

        assert_eq!(result, Err(EntityRegistryError::ZeroAddress));
    }

    // ========================================================================
    // ENTITY TYPE TESTS
    // ========================================================================

    #[test]
    fn test_get_entity_type_cbe() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        assert_eq!(registry.get_entity_type(&cbe), Some(EntityType::ForProfit));
    }

    #[test]
    fn test_get_entity_type_nonprofit() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit.clone()).unwrap();

        assert_eq!(registry.get_entity_type(&nonprofit), Some(EntityType::Nonprofit));
    }

    #[test]
    fn test_get_entity_type_unknown() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let unknown = create_test_public_key(3);
        registry.init(cbe, nonprofit).unwrap();

        assert_eq!(registry.get_entity_type(&unknown), None);
    }

    // ========================================================================
    // ROLE TESTS
    // ========================================================================

    #[test]
    fn test_cbe_has_operator_role() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        assert!(registry.has_role(&cbe, Role::Operator));
    }

    #[test]
    fn test_cbe_has_profit_declarer_role() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        assert!(registry.has_role(&cbe, Role::ProfitDeclarer));
    }

    #[test]
    fn test_cbe_has_treasury_spender_role() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        assert!(registry.has_role(&cbe, Role::TreasurySpender));
    }

    #[test]
    fn test_cbe_does_not_have_nonprofit_roles() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        assert!(!registry.has_role(&cbe, Role::MissionCustodian));
        assert!(!registry.has_role(&cbe, Role::TreasuryHolder));
    }

    #[test]
    fn test_nonprofit_has_mission_custodian_role() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit.clone()).unwrap();

        assert!(registry.has_role(&nonprofit, Role::MissionCustodian));
    }

    #[test]
    fn test_nonprofit_has_treasury_holder_role() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit.clone()).unwrap();

        assert!(registry.has_role(&nonprofit, Role::TreasuryHolder));
    }

    #[test]
    fn test_nonprofit_does_not_have_forprofit_roles() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit.clone()).unwrap();

        assert!(!registry.has_role(&nonprofit, Role::Operator));
        assert!(!registry.has_role(&nonprofit, Role::ProfitDeclarer));
        assert!(!registry.has_role(&nonprofit, Role::TreasurySpender));
    }

    #[test]
    fn test_get_all_roles_cbe() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe.clone(), nonprofit).unwrap();

        let roles = registry.get_roles(&cbe);

        assert_eq!(roles.len(), 3);
        assert!(roles.contains(&Role::Operator));
        assert!(roles.contains(&Role::ProfitDeclarer));
        assert!(roles.contains(&Role::TreasurySpender));
    }

    #[test]
    fn test_get_all_roles_nonprofit() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit.clone()).unwrap();

        let roles = registry.get_roles(&nonprofit);

        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&Role::MissionCustodian));
        assert!(roles.contains(&Role::TreasuryHolder));
    }

    // ========================================================================
    // TREASURY ISOLATION TESTS (INVARIANT I4)
    // ========================================================================

    #[test]
    fn test_validate_transfer_nonprofit_earnings_to_nonprofit_allowed() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let external = create_test_public_key(3);
        registry.init(cbe, nonprofit.clone()).unwrap();

        // Nonprofit earnings to nonprofit treasury: allowed
        let result = registry.validate_transfer(&external, &nonprofit, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transfer_nonprofit_earnings_to_cbe_rejected() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let external = create_test_public_key(3);
        registry.init(cbe.clone(), nonprofit).unwrap();

        // Nonprofit earnings to CBE treasury: REJECTED (Invariant I4)
        let result = registry.validate_transfer(&external, &cbe, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_transfer_regular_transfer_to_cbe_allowed() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let external = create_test_public_key(3);
        registry.init(cbe.clone(), nonprofit).unwrap();

        // Non-nonprofit-earnings to CBE: allowed
        let result = registry.validate_transfer(&external, &cbe, false);
        assert!(result.is_ok());
    }

    // ========================================================================
    // VALIDATION TESTS
    // ========================================================================

    #[test]
    fn test_validate_initialized_registry_passes() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        registry.init(cbe, nonprofit).unwrap();

        let result = registry.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_uninitialized_registry_fails() {
        let registry = EntityRegistry::new();

        let result = registry.validate();
        assert_eq!(result, Err(EntityRegistryError::NotInitialized));
    }

    // ========================================================================
    // TREASURY LOOKUP TESTS
    // ========================================================================

    #[test]
    fn test_is_cbe_treasury() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let other = create_test_public_key(3);
        registry.init(cbe.clone(), nonprofit.clone()).unwrap();

        assert!(registry.is_cbe_treasury(&cbe));
        assert!(!registry.is_cbe_treasury(&nonprofit));
        assert!(!registry.is_cbe_treasury(&other));
    }

    #[test]
    fn test_is_nonprofit_treasury() {
        let mut registry = EntityRegistry::new();
        let cbe = create_test_public_key(1);
        let nonprofit = create_test_public_key(2);
        let other = create_test_public_key(3);
        registry.init(cbe.clone(), nonprofit.clone()).unwrap();

        assert!(!registry.is_nonprofit_treasury(&cbe));
        assert!(registry.is_nonprofit_treasury(&nonprofit));
        assert!(!registry.is_nonprofit_treasury(&other));
    }

    // ========================================================================
    // EDGE CASE TESTS
    // ========================================================================

    #[test]
    fn test_cbe_treasury_before_init_fails() {
        let registry = EntityRegistry::new();

        let result = registry.cbe_treasury();
        assert_eq!(result, Err(EntityRegistryError::NotInitialized));
    }

    #[test]
    fn test_nonprofit_treasury_before_init_fails() {
        let registry = EntityRegistry::new();

        let result = registry.nonprofit_treasury();
        assert_eq!(result, Err(EntityRegistryError::NotInitialized));
    }

    #[test]
    fn test_validate_transfer_before_init_fails() {
        let registry = EntityRegistry::new();
        let from = create_test_public_key(1);
        let to = create_test_public_key(2);

        let result = registry.validate_transfer(&from, &to, false);
        assert_eq!(result, Err(EntityRegistryError::NotInitialized));
    }
}
