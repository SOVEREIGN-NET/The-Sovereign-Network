//! Treasury Registry and coordination layer
//!
//! Provides canonical routing from SectorDao to TreasuryAddress.
//! Pure routing contract: zero economic logic, zero percentage math.
//! Phase 1: immutable after initialization.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::types::dao::SectorDao;

/// Treasury Registry: canonical mapping from sector to treasury address.
///
/// # Invariants (non-negotiable):
///
/// ## A1: Sector Uniqueness
/// There must be exactly one treasury per sector.
/// Each of the five sectors (healthcare, Education, Energy, Housing, Food)
/// must have a unique treasury address registered.
///
/// ## A2: Sector Immutability
/// A SovDaoTreasury instance is permanently bound to exactly one sector.
/// After initialization:
/// - healthcare treasury can only receive healthcare credits
/// - Education treasury can only receive Education credits
/// - (etc. for all 5 sectors)
///
/// ## A3: Canonical Mapping (Routing Invariant)
/// Registry.resolve(sector) must:
/// - Be deterministic (same input → same output at given chain state)
/// - Return the same address across all consensus nodes
/// - Not depend on node-local configuration
/// - Support wiring: fee_distributor calls registry.get_treasury(sector)
///
/// ## Immutability Enforcement (Phase 1):
/// The registry mapping is immutable after initialization.
/// Invariant: initialized == true → mapping cannot change
/// This is enforced in code, not by social contract.
///
/// # No Economic Logic
/// This contract must NEVER:
/// - Calculate percentages ("6%")
/// - Track balances
/// - Perform fee math
/// - Infer sector from caller
/// 
/// It is pure routing: SectorDao -> Address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryRegistry {
    // Immutable fields
    authorized_admin: PublicKey,
    authorized_fee_collector: PublicKey,

    // Mapping: SectorDao -> Treasury Address
    // Invariant A1: all 5 sectors must be registered
    // Invariant A2: each address is bound to exactly one sector
    sector_treasury_map: HashMap<String, PublicKey>, // sector_str -> treasury_address

    // Immutability enforcement (Invariant A3)
    // Once initialized == true, mapping cannot change
    initialized: bool,
}

impl TreasuryRegistry {
    /// Initialize the registry with all five sector treasuries.
    ///
    /// # Parameters:
    /// - authorized_admin: can read registry, but cannot mutate in Phase 1
    /// - authorized_fee_collector: used to validate treasury authorization
    /// - sector_treasury_map: map of SectorDao -> TreasuryAddress
    ///   Must contain exactly the 5 sectors: healthcare, Education, Energy, Housing, Food
    ///
    /// # Invariants enforced:
    /// - All 5 sectors are registered (A1)
    /// - All addresses are distinct (A1 corollary)
    /// - Admin and fee_collector are non-zero
    /// - After init, mapping is immutable (Invariant A3)
    pub fn init(
        authorized_admin: PublicKey,
        authorized_fee_collector: PublicKey,
        mut sector_treasury_map: HashMap<String, PublicKey>,
    ) -> Result<Self, String> {
        // Validate admin is non-zero
        if authorized_admin.as_bytes().iter().all(|b| *b == 0) {
            return Err("Authorized admin cannot be zero address".to_string());
        }

        // Validate fee_collector is non-zero
        if authorized_fee_collector.as_bytes().iter().all(|b| *b == 0) {
            return Err("Authorized fee collector cannot be zero address".to_string());
        }

        // Invariant A1: Validate all 5 sectors are present
        // Note: sector names are lowercase to match SectorDao::as_str() output
        let required_sectors = vec![
            "healthcare",
            "education",
            "energy",
            "housing",
            "food",
        ];

        for sector in &required_sectors {
            if !sector_treasury_map.contains_key(*sector) {
                return Err(format!(
                    "Sector {} not registered in treasury map",
                    sector
                ));
            }
        }

        // Invariant A1 corollary: Validate all addresses are distinct
        let mut seen_addresses = std::collections::HashSet::new();
        for (sector, address) in &sector_treasury_map {
            if !seen_addresses.insert(address.clone()) {
                return Err(format!(
                    "Duplicate treasury address for sector {}",
                    sector
                ));
            }

            // Also validate treasury address is non-zero
            if address.as_bytes().iter().all(|b| *b == 0) {
                return Err(format!(
                    "Treasury address for sector {} cannot be zero",
                    sector
                ));
            }
        }

        // Validate no extra sectors
        if sector_treasury_map.len() != required_sectors.len() {
            return Err(format!(
                "Expected {} sectors, found {}",
                required_sectors.len(),
                sector_treasury_map.len()
            ));
        }

        Ok(TreasuryRegistry {
            authorized_admin,
            authorized_fee_collector,
            sector_treasury_map,
            initialized: true, // CRITICAL: Set to true immediately after init
        })
    }

    /// Resolve treasury address for a given sector.
    ///
    /// # Pure Routing (Invariant A3):
    /// - No economic logic
    /// - No percentage math
    /// - No authorization checks
    /// - Deterministic: same input always yields same output
    ///
    /// # Returns:
    /// - Some(address) if sector is registered
    /// - None if sector not found
    pub fn get_treasury(&self, sector: &SectorDao) -> Option<PublicKey> {
        let sector_str = sector.as_str();
        self.sector_treasury_map.get(sector_str).cloned()
    }

    /// Check if registry is initialized and immutable.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get all registered sectors (for validation/testing).
    pub fn all_sectors(&self) -> Vec<String> {
        self.sector_treasury_map.keys().cloned().collect()
    }

    /// Get treasury address by sector string (internal routing).
    /// Used by fee distributor to resolve treasury address.
    pub fn get_treasury_by_sector_str(&self, sector_str: &str) -> Option<PublicKey> {
        self.sector_treasury_map.get(sector_str).cloned()
    }

    /// Validate that all 5 sectors are registered with distinct addresses.
    /// Returns true if invariants A1 and A2 hold.
    pub fn validate_registry(&self) -> Result<(), String> {
        let required_sectors = vec![
            "healthcare",
            "education",
            "energy",
            "housing",
            "food",
        ];

        // Check all sectors present
        for sector in &required_sectors {
            if !self.sector_treasury_map.contains_key(*sector) {
                return Err(format!("Missing sector: {}", sector));
            }
        }

        // Check distinctness
        let mut seen = std::collections::HashSet::new();
        for address in self.sector_treasury_map.values() {
            if !seen.insert(address.clone()) {
                return Err("Duplicate treasury address detected".to_string());
            }
        }

        Ok(())
    }
}

/// Helper function to initialize the standard 5-sector registry.
/// Used in genesis and tests.
///
/// # Parameters:
/// - admin: administrator address (typically protocol account)
/// - fee_collector: fee distributor address
/// - sector_addresses: map of 5 sector strings to treasury addresses
///   Keys must be: "healthcare", "Education", "Energy", "Housing", "Food"
pub fn init_registry(
    admin: PublicKey,
    fee_collector: PublicKey,
    sector_addresses: HashMap<String, PublicKey>,
) -> Result<TreasuryRegistry, String> {
    TreasuryRegistry::init(admin, fee_collector, sector_addresses)
}

/// Apply a fee distribution to sector treasuries via the registry.
///
/// This function wires the fee distributor to the treasury registry, enabling:
/// 1. Pure routing from SectorDao to treasury addresses (registry)
/// 2. Zero economic logic in treasuries (sector-sealed containers)
/// 3. No hardcoded addresses (deterministic resolution via registry)
///
/// # Parameters:
/// - fee_collector: The authorized fee collector address
/// - sector_allocation: A closure that takes SectorDao and returns amount to credit
/// - block_height: The current block height (for audit trail)
/// - registry: The treasury registry (for address resolution)
/// - treasuries: The initialized treasuries (mutable)
///
/// # Invariants enforced:
/// - Only registered sectors can receive credits (via registry.get_treasury())
/// - Each treasury credit uses the pre-computed amount (no % math in distribution)
/// - Authorization checks happen in SovDaoTreasury.credit()
///
/// # Returns:
/// Result indicating success or failure of any credit operation

/// Initialize all 5 sector treasuries with the given fee collector.
/// Returns a HashMap mapping sector names to initialized SovDaoTreasury instances.
///
/// # Parameters:
/// - fee_collector: The authorized fee collector address for all treasuries
/// - allocation_period: Optional economic period configuration
///
/// # Returns:
/// HashMap with 5 entries:
/// - "healthcare" -> SovDaoTreasury(healthcare sector)
/// - "education" -> SovDaoTreasury(Education sector)
/// - "energy" -> SovDaoTreasury(Energy sector)
/// - "housing" -> SovDaoTreasury(Housing sector)
/// - "food" -> SovDaoTreasury(Food sector)
///
/// # Invariants enforced:
/// - Each treasury is sector-sealed (immutable SectorDao binding)
/// - All use the same fee_collector (for deterministic authorization)
/// - All start with total_received = 0
pub fn initialize_sector_treasuries(
    fee_collector: PublicKey,
    allocation_period: Option<crate::types::dao::EconomicPeriod>,
) -> Result<HashMap<String, crate::contracts::treasuries::SovDaoTreasury>, String> {
    use crate::contracts::treasuries::SovDaoTreasury;
    
    let mut treasuries = HashMap::new();
    
    // Initialize all 5 sectors
    let sectors = vec![
        (SectorDao::Healthcare, "healthcare"),
        (SectorDao::Education, "education"),
        (SectorDao::Energy, "energy"),
        (SectorDao::Housing, "housing"),
        (SectorDao::Food, "food"),
    ];
    
    for (sector, sector_name) in sectors {
        let treasury = SovDaoTreasury::init(sector, fee_collector.clone(), allocation_period)?;
        treasuries.insert(sector_name.to_string(), treasury);
    }
    
    Ok(treasuries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    // ============================================================================
    // REGISTRY INITIALIZATION TESTS
    // ============================================================================

    fn test_registry_init_all_five_sectors() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare.clone());
        sector_map.insert("education".to_string(), education.clone());
        sector_map.insert("energy".to_string(), energy.clone());
        sector_map.insert("housing".to_string(), housing.clone());
        sector_map.insert("food".to_string(), food.clone());

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Verify all sectors are registered
        assert!(registry.is_initialized());
        assert_eq!(registry.all_sectors().len(), 5);
        
        // Verify validate passes
        assert!(registry.validate_registry().is_ok());
    }

    fn test_registry_rejects_missing_sector() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        // Missing Food!

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare);

        let result = TreasuryRegistry::init(admin, fee_collector, sector_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("food"));
    }

    fn test_registry_rejects_duplicate_addresses() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let shared = create_test_public_key(20); // Same for multiple sectors (bad!)

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare);
        sector_map.insert("$1".to_lowercase().as_str().to_string(), shared.clone());
        sector_map.insert("$1".to_lowercase().as_str().to_string(), shared.clone()); // Duplicate!
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(13));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(14));

        let result = TreasuryRegistry::init(admin, fee_collector, sector_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate"));
    }

    fn test_registry_rejects_zero_admin() {
        let zero_admin = PublicKey::new(vec![0u8; 1312]);
        let fee_collector = create_test_public_key(2);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), create_test_public_key(10));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(11));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(12));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(13));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(14));

        let result = TreasuryRegistry::init(zero_admin, fee_collector, sector_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("admin cannot be zero"));
    }

    fn test_registry_rejects_zero_fee_collector() {
        let admin = create_test_public_key(1);
        let zero_fee_collector = PublicKey::new(vec![0u8; 1312]);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), create_test_public_key(10));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(11));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(12));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(13));
        sector_map.insert("$1".to_lowercase().as_str().to_string(), create_test_public_key(14));

        let result = TreasuryRegistry::init(admin, zero_fee_collector, sector_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fee collector cannot be zero"));
    }

    // ============================================================================
    // REGISTRY ROUTING TESTS (Pure Routing - Invariant A3)
    // ============================================================================

    fn test_registry_resolve_returns_correct_address_per_sector() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare.clone());
        sector_map.insert("education".to_string(), education.clone());
        sector_map.insert("energy".to_string(), energy.clone());
        sector_map.insert("housing".to_string(), housing.clone());
        sector_map.insert("food".to_string(), food.clone());

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Verify each sector resolves to correct address
        assert_eq!(registry.get_treasury(&SectorDao::Healthcare), Some(healthcare));
        assert_eq!(registry.get_treasury(&SectorDao::Education), Some(education));
        assert_eq!(registry.get_treasury(&SectorDao::Energy), Some(energy));
        assert_eq!(registry.get_treasury(&SectorDao::Housing), Some(housing));
        assert_eq!(registry.get_treasury(&SectorDao::Food), Some(food));
    }

    fn test_registry_resolve_deterministic() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare.clone());
        sector_map.insert("education".to_string(), education.clone());
        sector_map.insert("energy".to_string(), energy.clone());
        sector_map.insert("housing".to_string(), housing.clone());
        sector_map.insert("food".to_string(), food.clone());

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Same input must always yield same output (deterministic)
        for _ in 0..10 {
            assert_eq!(
                registry.get_treasury(&SectorDao::Healthcare),
                Some(healthcare.clone())
            );
        }
    }

    fn test_registry_all_resolved_addresses_distinct() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare.clone());
        sector_map.insert("education".to_string(), education.clone());
        sector_map.insert("energy".to_string(), energy.clone());
        sector_map.insert("housing".to_string(), housing.clone());
        sector_map.insert("food".to_string(), food.clone());

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Collect all resolved addresses
        let mut addresses = vec![
            registry.get_treasury(&SectorDao::Healthcare),
            registry.get_treasury(&SectorDao::Education),
            registry.get_treasury(&SectorDao::Energy),
            registry.get_treasury(&SectorDao::Housing),
            registry.get_treasury(&SectorDao::Food),
        ];

        // All must be Some
        assert!(addresses.iter().all(|a| a.is_some()));

        // All must be distinct
        let mut unique = std::collections::HashSet::new();
        for addr in addresses.iter().flatten() {
            assert!(
                unique.insert(addr.clone()),
                "Found duplicate address in registry resolve"
            );
        }
    }

    // ============================================================================
    // REGISTRY IMMUTABILITY TESTS (Phase 1: Invariant A3)
    // ============================================================================

    fn test_registry_is_immutable_after_init() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);

    fn test_initialize_five_sector_treasuries_creates_all_instances() {
        // INVARIANT A1: Five distinct treasuries, one per sector
        let fee_collector = create_test_public_key(100);
        
        let treasuries = initialize_sector_treasuries(fee_collector.clone(), None)
            .expect("Should initialize all 5 sectors");
        
        // Verify all 5 sectors exist
        assert_eq!(treasuries.len(), 5);
        assert!(treasuries.contains_key("healthcare"));
        assert!(treasuries.contains_key("education"));
        assert!(treasuries.contains_key("energy"));
        assert!(treasuries.contains_key("housing"));
        assert!(treasuries.contains_key("food"));
    }

    fn test_sector_treasuries_are_immutably_bound_to_sectors() {
        // INVARIANT A2: Each treasury is permanently bound to its sector
        let fee_collector = create_test_public_key(101);
        
        let treasuries = initialize_sector_treasuries(fee_collector.clone(), None)
            .expect("Should initialize all 5 sectors");
        
        // Verify each treasury has the correct sector
        assert_eq!(treasuries["healthcare"].sector(), crate::types::dao::SectorDao::Healthcare);
        assert_eq!(treasuries["education"].sector(), crate::types::dao::SectorDao::Education);
        assert_eq!(treasuries["energy"].sector(), crate::types::dao::SectorDao::Energy);
        assert_eq!(treasuries["housing"].sector(), crate::types::dao::SectorDao::Housing);
        assert_eq!(treasuries["food"].sector(), crate::types::dao::SectorDao::Food);
    }

    fn test_sector_treasuries_share_same_fee_collector() {
        // All treasuries have the same authorized fee_collector
        let fee_collector = create_test_public_key(102);
        
        let treasuries = initialize_sector_treasuries(fee_collector.clone(), None)
            .expect("Should initialize all 5 sectors");
        
        for (sector_name, treasury) in treasuries.iter() {
            assert_eq!(
                treasury.authorized_fee_collector(),
                &fee_collector,
                "Sector {} has wrong fee_collector",
                sector_name
            );
        }
    }

    fn test_sector_treasuries_start_with_zero_balance() {
        // All newly initialized treasuries have total_received = 0
        let fee_collector = create_test_public_key(103);
        
        let treasuries = initialize_sector_treasuries(fee_collector.clone(), None)
            .expect("Should initialize all 5 sectors");
        
        for (sector_name, treasury) in treasuries.iter() {
            assert_eq!(
                treasury.total_received(),
                0,
                "Sector {} should start with zero balance",
                sector_name
            );
        }
    }

    fn test_registry_routes_to_correct_treasury_addresses() {
        // INVARIANT A3: Registry deterministically routes sectors to treasury addresses
        let admin = create_test_public_key(104);
        let fee_collector = create_test_public_key(105);
        
        // Create distinct addresses for each sector treasury
        let treasury_addresses: HashMap<String, PublicKey> = vec![
            ("healthcare".to_string(), create_test_public_key(1)),
            ("education".to_string(), create_test_public_key(2)),
            ("energy".to_string(), create_test_public_key(3)),
            ("housing".to_string(), create_test_public_key(4)),
            ("food".to_string(), create_test_public_key(5)),
        ]
        .into_iter()
        .collect();
        
        let registry = init_registry(admin, fee_collector, treasury_addresses.clone())
            .expect("Should initialize registry");
        
        // Verify registry routes to correct addresses
        assert_eq!(
            registry.get_treasury(&crate::types::dao::SectorDao::Healthcare),
            treasury_addresses.get("healthcare").cloned()
        );
        assert_eq!(
            registry.get_treasury(&crate::types::dao::SectorDao::Education),
            treasury_addresses.get("education").cloned()
        );
        assert_eq!(
            registry.get_treasury(&crate::types::dao::SectorDao::Energy),
            treasury_addresses.get("energy").cloned()
        );
        assert_eq!(
            registry.get_treasury(&crate::types::dao::SectorDao::Housing),
            treasury_addresses.get("housing").cloned()
        );
        assert_eq!(
            registry.get_treasury(&crate::types::dao::SectorDao::Food),
            treasury_addresses.get("food").cloned()
        );
    }

    fn test_year_5_scenario_allocation_projection() {
        // INVARIANT B3: Integration test - Year 5 example
        // $5B volume → $50M fees → $15M DAOs (30% allocation) → $3M per DAO
        
        let fee_collector = create_test_public_key(106);
        
        let treasuries = initialize_sector_treasuries(fee_collector.clone(), None)
            .expect("Should initialize all 5 sectors");
        
        // Simulate Year 5 fee distribution
        // Total DAO allocation: 15M tokens (30% of 50M fees)
        // Split evenly across 5 sectors: 3M per sector
        let total_dao_fees = 15_000_000u64;
        let per_sector_amount = total_dao_fees / 5; // 3M per sector
        
        assert_eq!(per_sector_amount, 3_000_000);
        
        // Verify each sector can receive this amount (no overflow, within u64)
        for (_sector_name, _treasury) in treasuries.iter() {
            // Treasury is initialized and ready to receive credits
            // (actual credit testing is in SovDaoTreasury unit tests)
            assert_eq!(_treasury.total_received(), 0);
        }
    }
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare.clone());
        sector_map.insert("education".to_string(), education.clone());
        sector_map.insert("energy".to_string(), energy.clone());
        sector_map.insert("housing".to_string(), housing.clone());
        sector_map.insert("food".to_string(), food.clone());

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Verify initialized flag is set
        assert!(registry.is_initialized());

        // In Phase 1, no mutation methods exist.
        // This test documents the invariant: initialized == true → mapping immutable.
        // Future phases can add governance-gated mutations that check initialized flag.
    }

    fn test_registry_validation_passes_after_init() {
        let admin = create_test_public_key(1);
        let fee_collector = create_test_public_key(2);
        let healthcare = create_test_public_key(10);
        let education = create_test_public_key(11);
        let energy = create_test_public_key(12);
        let housing = create_test_public_key(13);
        let food = create_test_public_key(14);

        let mut sector_map = HashMap::new();
        sector_map.insert("healthcare".to_string(), healthcare);

        let registry = TreasuryRegistry::init(admin, fee_collector, sector_map)
            .expect("Registry init should succeed");

        // Validation must pass
        assert!(registry.validate_registry().is_ok());
    }

}
