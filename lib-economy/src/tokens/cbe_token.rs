//! CBE (Corporate Budget Equivalent) allocation ledger
//!
//! Defines the fixed allocation of 100 billion CBE tokens across four operational buckets.
//! This module implements genesis-time allocation only; transfer policies, vesting, and
//! liquidity mechanisms are explicitly excluded from Phase 1.
//!
//! # Invariants (Non-Negotiable)
//!
//! 1. **Supply Invariant**: Total supply is exactly 100 billion, immutable at genesis
//! 2. **Allocation Invariant**: 40B + 30B + 20B + 10B = 100B, verified at init
//! 3. **Initialization Invariant**: Allocation occurs exactly once, guarded by sealed flag
//! 4. **No Transfer Semantics**: Phase 1 has no transfer(), approve(), or spendable balances
//! 5. **Bucket Isolation**: Each bucket is logically isolated, no cross-bucket movement
//!
//! # Non-Goals (Explicitly Excluded from Phase 1)
//!
//! This module intentionally does NOT implement:
//! - Vesting schedules or time-based unlocking
//! - Performance-based scoring or conditional distributions
//! - Liquidity mechanisms or market interaction
//! - Conversion to SOV or cross-token bridges
//! - Dynamic bucket creation or governance reassignment
//! - Free transfers or approval-based spending
//!
//! These are Phase 2+ features and must be designed separately.
//!
//! # Architecture
//!
//! CBE is modeled as an **equity ledger**, not a currency:
//! - Buckets are accounting namespaces
//! - Ownership is symbolic (governance decides real accounts)
//! - Balances are immutable records, not liquid assets
//! - Init is one-time, sealed against re-entry

use serde::{Deserialize, Serialize};
use std::fmt;

/// CBE total supply: 100 billion tokens (fixed, non-inflationary)
pub const CBE_TOTAL_SUPPLY: u64 = 100_000_000_000;

/// Compensation Pool allocation: 40B tokens (40% of total)
pub const CBE_COMPENSATION_POOL: u64 = 40_000_000_000;

/// Operational Treasury allocation: 30B tokens (30% of total)
pub const CBE_OPERATIONAL_TREASURY: u64 = 30_000_000_000;

/// Performance Incentives allocation: 20B tokens (20% of total)
pub const CBE_PERFORMANCE_INCENTIVES: u64 = 20_000_000_000;

/// Strategic Reserves allocation: 10B tokens (10% of total)
pub const CBE_STRATEGIC_RESERVES: u64 = 10_000_000_000;

/// Symbolic identifiers for CBE allocation buckets
///
/// These are NOT account addresses. Actual ownership mapping occurs via governance.
/// This separation ensures bucket accounting is independent of account management.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum CbeBucketId {
    /// Compensation Pool: Allocated for employee/contributor compensation
    /// - Amount: 40B CBE (40% of total)
    /// - Purpose: Long-term workforce alignment
    Compensation = 1,

    /// Operational Treasury: Allocated for operational expenses and infrastructure
    /// - Amount: 30B CBE (30% of total)
    /// - Purpose: Day-to-day operations, maintenance, development
    Treasury = 2,

    /// Performance Incentives: Allocated for performance-based distributions
    /// - Amount: 20B CBE (20% of total)
    /// - Purpose: Achievement of milestones and metrics
    Performance = 3,

    /// Strategic Reserves: Allocated for strategic opportunities and contingencies
    /// - Amount: 10B CBE (10% of total)
    /// - Purpose: Future partnerships, emergencies, growth initiatives
    Reserves = 4,
}

impl CbeBucketId {
    /// All CBE buckets in stable order (for consensus and hashing)
    pub const ALL: &'static [CbeBucketId] = &[
        CbeBucketId::Compensation,
        CbeBucketId::Treasury,
        CbeBucketId::Performance,
        CbeBucketId::Reserves,
    ];

    /// Count of CBE buckets
    pub const COUNT: usize = 4;

    /// Get the canonical allocation for this bucket (in tokens)
    pub fn allocation(self) -> u64 {
        match self {
            CbeBucketId::Compensation => CBE_COMPENSATION_POOL,
            CbeBucketId::Treasury => CBE_OPERATIONAL_TREASURY,
            CbeBucketId::Performance => CBE_PERFORMANCE_INCENTIVES,
            CbeBucketId::Reserves => CBE_STRATEGIC_RESERVES,
        }
    }

    /// Get percentage allocation for this bucket (for reporting)
    pub fn percentage(self) -> u8 {
        match self {
            CbeBucketId::Compensation => 40,
            CbeBucketId::Treasury => 30,
            CbeBucketId::Performance => 20,
            CbeBucketId::Reserves => 10,
        }
    }

    /// Get human-readable display name
    pub fn display_name(&self) -> &'static str {
        match self {
            CbeBucketId::Compensation => "Compensation Pool",
            CbeBucketId::Treasury => "Operational Treasury",
            CbeBucketId::Performance => "Performance Incentives",
            CbeBucketId::Reserves => "Strategic Reserves",
        }
    }

    /// Get discriminant value (for serialization safety)
    pub const fn discriminant(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for CbeBucketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Error type for CBE ledger operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbeError {
    /// Allocation has already been initialized
    AlreadyInitialized,
    /// Allocation invariant violated (sums don't equal total)
    AllocationInvariantViolated { expected: u64, actual: u64 },
    /// Supply invariant violated
    SupplyInvariantViolated { expected: u64, actual: u64 },
}

impl fmt::Display for CbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CbeError::AlreadyInitialized => {
                write!(f, "CBE allocation has already been initialized. Re-initialization is a consensus failure.")
            }
            CbeError::AllocationInvariantViolated { expected, actual } => {
                write!(f, "CBE allocation invariant violated: expected sum {}, got {}", expected, actual)
            }
            CbeError::SupplyInvariantViolated { expected, actual } => {
                write!(f, "CBE supply invariant violated: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for CbeError {}

/// CBE allocation ledger
///
/// This struct maintains the immutable allocation of 100B CBE tokens across four operational buckets.
/// It enforces:
/// - Genesis-time one-time initialization
/// - Supply invariants (total = 100B)
/// - Allocation invariants (buckets sum to 100B)
/// - Bucket isolation (no transfers between buckets)
/// - No transfer semantics in Phase 1
///
/// This is an **accounting ledger**, not a transferable token. Phase 1 only defines allocation;
/// governance later decides actual account ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CbeAllocationLedger {
    /// Flag indicating whether allocation has been initialized
    /// This is a sealed guard: once set, cannot be unset without consensus failure
    initialized: bool,

    /// Compensation Pool balance (40B)
    compensation_pool: u64,

    /// Operational Treasury balance (30B)
    operational_treasury: u64,

    /// Performance Incentives balance (20B)
    performance_incentives: u64,

    /// Strategic Reserves balance (10B)
    strategic_reserves: u64,
}

impl CbeAllocationLedger {
    /// Create an uninitialized ledger
    pub const fn new() -> Self {
        CbeAllocationLedger {
            initialized: false,
            compensation_pool: 0,
            operational_treasury: 0,
            performance_incentives: 0,
            strategic_reserves: 0,
        }
    }

    /// Check if allocation has been initialized
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initialize the ledger with canonical allocations (one-time operation)
    ///
    /// # Errors
    /// Returns `CbeError::AlreadyInitialized` if ledger is already initialized
    /// Returns `CbeError::AllocationInvariantViolated` if invariants fail
    pub fn init(&mut self) -> Result<(), CbeError> {
        if self.initialized {
            return Err(CbeError::AlreadyInitialized);
        }

        // Set canonical allocations
        self.compensation_pool = CBE_COMPENSATION_POOL;
        self.operational_treasury = CBE_OPERATIONAL_TREASURY;
        self.performance_incentives = CBE_PERFORMANCE_INCENTIVES;
        self.strategic_reserves = CBE_STRATEGIC_RESERVES;

        // Verify supply invariant
        let total = self.compensation_pool
            .saturating_add(self.operational_treasury)
            .saturating_add(self.performance_incentives)
            .saturating_add(self.strategic_reserves);

        if total != CBE_TOTAL_SUPPLY {
            return Err(CbeError::SupplyInvariantViolated {
                expected: CBE_TOTAL_SUPPLY,
                actual: total,
            });
        }

        // Mark as initialized (sealed)
        self.initialized = true;
        Ok(())
    }

    /// Get allocation for a specific bucket (read-only)
    pub const fn get_bucket_allocation(&self, bucket: CbeBucketId) -> u64 {
        match bucket {
            CbeBucketId::Compensation => self.compensation_pool,
            CbeBucketId::Treasury => self.operational_treasury,
            CbeBucketId::Performance => self.performance_incentives,
            CbeBucketId::Reserves => self.strategic_reserves,
        }
    }

    /// Get total allocated amount (sum of all buckets)
    pub const fn total_allocated(&self) -> u64 {
        // Note: Using const-compatible calculation
        self.compensation_pool + self.operational_treasury + self.performance_incentives + self.strategic_reserves
    }

    /// Check if allocation is complete (all buckets populated)
    pub const fn is_fully_allocated(&self) -> bool {
        self.total_allocated() == CBE_TOTAL_SUPPLY
    }

    /// Get allocation for all buckets
    pub fn all_allocations(&self) -> [(CbeBucketId, u64); 4] {
        [
            (CbeBucketId::Compensation, self.compensation_pool),
            (CbeBucketId::Treasury, self.operational_treasury),
            (CbeBucketId::Performance, self.performance_incentives),
            (CbeBucketId::Reserves, self.strategic_reserves),
        ]
    }
}

impl Default for CbeAllocationLedger {
    fn default() -> Self {
        CbeAllocationLedger::new()
    }
}

impl fmt::Display for CbeAllocationLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CBE Ledger [{}]: Compensation={}B, Treasury={}B, Performance={}B, Reserves={}B (Total={}B)",
            if self.initialized { "INITIALIZED" } else { "UNINITIALIZED" },
            self.compensation_pool / 1_000_000_000,
            self.operational_treasury / 1_000_000_000,
            self.performance_incentives / 1_000_000_000,
            self.strategic_reserves / 1_000_000_000,
            self.total_allocated() / 1_000_000_000,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== SUPPLY INVARIANT TESTS =====

    #[test]
    fn test_cbe_total_supply_constant() {
        assert_eq!(CBE_TOTAL_SUPPLY, 100_000_000_000);
        assert_eq!(CBE_TOTAL_SUPPLY, 100_000_000_000u64);
    }

    #[test]
    fn test_cbe_allocation_constants_sum_to_total() {
        let total = CBE_COMPENSATION_POOL
            + CBE_OPERATIONAL_TREASURY
            + CBE_PERFORMANCE_INCENTIVES
            + CBE_STRATEGIC_RESERVES;
        assert_eq!(total, CBE_TOTAL_SUPPLY);
        assert_eq!(total, 100_000_000_000);
    }

    #[test]
    fn test_bucket_allocations_compile_time() {
        // These should be verifiable at compile time
        assert_eq!(CBE_COMPENSATION_POOL, 40_000_000_000);
        assert_eq!(CBE_OPERATIONAL_TREASURY, 30_000_000_000);
        assert_eq!(CBE_PERFORMANCE_INCENTIVES, 20_000_000_000);
        assert_eq!(CBE_STRATEGIC_RESERVES, 10_000_000_000);
    }

    #[test]
    fn test_bucket_percentages() {
        assert_eq!(CBE_COMPENSATION_POOL * 100 / CBE_TOTAL_SUPPLY, 40);
        assert_eq!(CBE_OPERATIONAL_TREASURY * 100 / CBE_TOTAL_SUPPLY, 30);
        assert_eq!(CBE_PERFORMANCE_INCENTIVES * 100 / CBE_TOTAL_SUPPLY, 20);
        assert_eq!(CBE_STRATEGIC_RESERVES * 100 / CBE_TOTAL_SUPPLY, 10);
    }

    // ===== ALLOCATION INVARIANT TESTS =====

    #[test]
    fn test_ledger_creation_uninitialized() {
        let ledger = CbeAllocationLedger::new();
        assert!(!ledger.is_initialized());
        assert_eq!(ledger.total_allocated(), 0);
        assert!(!ledger.is_fully_allocated());
    }

    #[test]
    fn test_ledger_init_success() {
        let mut ledger = CbeAllocationLedger::new();
        let result = ledger.init();
        assert!(result.is_ok());
        assert!(ledger.is_initialized());
        assert_eq!(ledger.total_allocated(), CBE_TOTAL_SUPPLY);
        assert!(ledger.is_fully_allocated());
    }

    #[test]
    fn test_ledger_init_cannot_be_called_twice() {
        let mut ledger = CbeAllocationLedger::new();
        assert!(ledger.init().is_ok());

        // Second init should fail
        let result = ledger.init();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CbeError::AlreadyInitialized);
    }

    #[test]
    fn test_ledger_allocations_after_init() {
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Compensation), CBE_COMPENSATION_POOL);
        assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Treasury), CBE_OPERATIONAL_TREASURY);
        assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Performance), CBE_PERFORMANCE_INCENTIVES);
        assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Reserves), CBE_STRATEGIC_RESERVES);
    }

    #[test]
    fn test_all_buckets_accounted_for() {
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        let allocations = ledger.all_allocations();
        let total: u64 = allocations.iter().map(|(_, amount)| amount).sum();
        assert_eq!(total, CBE_TOTAL_SUPPLY);
    }

    #[test]
    fn test_bucket_isolation_no_overlap() {
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        // Verify each bucket is distinct
        let comp = ledger.get_bucket_allocation(CbeBucketId::Compensation);
        let treas = ledger.get_bucket_allocation(CbeBucketId::Treasury);
        let perf = ledger.get_bucket_allocation(CbeBucketId::Performance);
        let res = ledger.get_bucket_allocation(CbeBucketId::Reserves);

        assert_ne!(comp, treas);
        assert_ne!(comp, perf);
        assert_ne!(comp, res);
        assert_ne!(treas, perf);
        assert_ne!(treas, res);
        assert_ne!(perf, res);
    }

    // ===== BUCKET ENUM TESTS =====

    #[test]
    fn test_bucket_id_discriminants() {
        assert_eq!(CbeBucketId::Compensation.discriminant(), 1);
        assert_eq!(CbeBucketId::Treasury.discriminant(), 2);
        assert_eq!(CbeBucketId::Performance.discriminant(), 3);
        assert_eq!(CbeBucketId::Reserves.discriminant(), 4);
    }

    #[test]
    fn test_bucket_id_allocations() {
        assert_eq!(CbeBucketId::Compensation.allocation(), CBE_COMPENSATION_POOL);
        assert_eq!(CbeBucketId::Treasury.allocation(), CBE_OPERATIONAL_TREASURY);
        assert_eq!(CbeBucketId::Performance.allocation(), CBE_PERFORMANCE_INCENTIVES);
        assert_eq!(CbeBucketId::Reserves.allocation(), CBE_STRATEGIC_RESERVES);
    }

    #[test]
    fn test_bucket_id_percentages() {
        assert_eq!(CbeBucketId::Compensation.percentage(), 40);
        assert_eq!(CbeBucketId::Treasury.percentage(), 30);
        assert_eq!(CbeBucketId::Performance.percentage(), 20);
        assert_eq!(CbeBucketId::Reserves.percentage(), 10);
    }

    #[test]
    fn test_bucket_id_display_names() {
        assert_eq!(CbeBucketId::Compensation.display_name(), "Compensation Pool");
        assert_eq!(CbeBucketId::Treasury.display_name(), "Operational Treasury");
        assert_eq!(CbeBucketId::Performance.display_name(), "Performance Incentives");
        assert_eq!(CbeBucketId::Reserves.display_name(), "Strategic Reserves");
    }

    #[test]
    fn test_bucket_id_all_constant() {
        let all = CbeBucketId::ALL;
        assert_eq!(all.len(), 4);
        assert_eq!(all[0], CbeBucketId::Compensation);
        assert_eq!(all[1], CbeBucketId::Treasury);
        assert_eq!(all[2], CbeBucketId::Performance);
        assert_eq!(all[3], CbeBucketId::Reserves);
    }

    #[test]
    fn test_bucket_id_count() {
        assert_eq!(CbeBucketId::COUNT, 4);
    }

    #[test]
    fn test_bucket_id_ordering() {
        let comp = CbeBucketId::Compensation;
        let treas = CbeBucketId::Treasury;
        assert!(comp < treas);

        // All should be orderable
        let mut kinds = vec![
            CbeBucketId::Reserves,
            CbeBucketId::Compensation,
            CbeBucketId::Performance,
            CbeBucketId::Treasury,
        ];
        kinds.sort();
        assert_eq!(kinds, vec![
            CbeBucketId::Compensation,
            CbeBucketId::Treasury,
            CbeBucketId::Performance,
            CbeBucketId::Reserves,
        ]);
    }

    // ===== DISPLAY AND SERIALIZATION TESTS =====

    #[test]
    fn test_ledger_display() {
        let mut ledger = CbeAllocationLedger::new();
        assert!(format!("{}", ledger).contains("UNINITIALIZED"));

        ledger.init().unwrap();
        let display = format!("{}", ledger);
        assert!(display.contains("INITIALIZED"));
        assert!(display.contains("40B")); // Compensation
        assert!(display.contains("30B")); // Treasury
        assert!(display.contains("20B")); // Performance
        assert!(display.contains("10B")); // Reserves
        assert!(display.contains("100B")); // Total
    }

    #[test]
    fn test_bucket_id_display() {
        assert_eq!(format!("{}", CbeBucketId::Compensation), "Compensation Pool");
        assert_eq!(format!("{}", CbeBucketId::Treasury), "Operational Treasury");
        assert_eq!(format!("{}", CbeBucketId::Performance), "Performance Incentives");
        assert_eq!(format!("{}", CbeBucketId::Reserves), "Strategic Reserves");
    }

    #[test]
    fn test_ledger_serialization_round_trip() {
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        let serialized = serde_json::to_string(&ledger).expect("serialization failed");
        let deserialized: CbeAllocationLedger = serde_json::from_str(&serialized).expect("deserialization failed");

        assert_eq!(ledger, deserialized);
        assert!(deserialized.is_initialized());
        assert_eq!(deserialized.total_allocated(), CBE_TOTAL_SUPPLY);
    }

    #[test]
    fn test_bucket_id_serialization_round_trip() {
        for bucket in CbeBucketId::ALL {
            let serialized = serde_json::to_string(bucket).expect("serialization failed");
            let deserialized: CbeBucketId = serde_json::from_str(&serialized).expect("deserialization failed");
            assert_eq!(*bucket, deserialized);
        }
    }

    // ===== INVARIANT VERIFICATION TESTS =====

    #[test]
    fn test_no_transfer_semantics_exposed() {
        // This test documents that CbeAllocationLedger has no transfer methods
        // The Rust type system enforces this at compile time
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        // Available methods are read-only:
        let _: bool = ledger.is_initialized();
        let _: u64 = ledger.total_allocated();
        let _: bool = ledger.is_fully_allocated();
        let _: u64 = ledger.get_bucket_allocation(CbeBucketId::Compensation);
        let _: [(CbeBucketId, u64); 4] = ledger.all_allocations();

        // No transfer/approve/spend methods exist - this is intentional for Phase 1
        // Future phases will add governance-driven transfer policies
    }

    #[test]
    fn test_supply_invariant_immutability() {
        // The ledger state is immutable once initialized
        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        let before_total = ledger.total_allocated();
        let before_comp = ledger.get_bucket_allocation(CbeBucketId::Compensation);

        // Read multiple times - should never change
        for _ in 0..10 {
            assert_eq!(ledger.total_allocated(), before_total);
            assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Compensation), before_comp);
        }
    }

    #[test]
    fn test_phase_1_scope_documented() {
        // This test documents the intentional scope limitations of Phase 1
        // The following are NOT implemented and should NOT be added without explicit redesign:

        // - No vesting: Allocation is genesis-time, not time-based
        // - No performance scoring: Distributions are fixed, not conditional
        // - No liquidity: Buckets are accounting namespaces, not tradable
        // - No SOV conversion: CBE and SOV are separate ledgers
        // - No dynamic buckets: All 4 buckets are compile-time constants
        // - No transfers: No transfer() or approve() methods
        // - No balances as spendable assets: Balances are immutable records

        let mut ledger = CbeAllocationLedger::new();
        ledger.init().unwrap();

        // What we CAN do: read allocations
        assert_eq!(ledger.get_bucket_allocation(CbeBucketId::Compensation), CBE_COMPENSATION_POOL);

        // What we CANNOT do: everything else (enforced by type system)
        // This prevents "just add transfer" feature creep
    }
}
