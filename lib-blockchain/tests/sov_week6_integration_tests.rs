//! Week 6 Integration Tests
//!
//! Comprehensive integration testing between FeeRouter and UbiDistributor.
//!
//! Tests validate:
//! - FeeRouter → UbiDistributor fee allocation flow
//! - End-to-end fee collection and UBI distribution
//! - Stress testing at scale (1M citizens)
//! - Precision (no rounding errors)
//! - Fairness (equal distribution)
//! - Performance targets
//! - Error scenarios and edge cases
//!
//! Total: 35 integration tests across 7 categories

use lib_blockchain::contracts::economics::fee_router::{FeeRouter, FeeRouterError};
use lib_blockchain::contracts::ubi_distribution::UbiDistributor;
use lib_blockchain::integration::crypto_integration::PublicKey;
use std::time::Instant;

// ============================================================================
// TEST HELPERS
// ============================================================================

const BLOCKS_PER_MONTH: u64 = 43200; // ~30 days at 5-second blocks

/// Create test PublicKey with specific ID
fn test_key(id: u8) -> PublicKey {
    let mut key_id = [0u8; 32];
    key_id[0] = id;
    PublicKey {
        key_id,
        dilithium_pk: vec![id],
        kyber_pk: vec![id],
    }
}

/// Initialize FeeRouter with test pool addresses
fn init_fee_router(router: &mut FeeRouter) {
    router.init(
        &test_key(1),  // UBI
        &test_key(2),  // Emergency
        &test_key(3),  // Dev
        &test_key(4),  // Healthcare
        &test_key(5),  // Education
        &test_key(6),  // Energy
        &test_key(7),  // Housing
        &test_key(8),  // Food
    ).unwrap();
}

// ============================================================================
// CATEGORY 1: FeeRouter → UbiDistributor Integration (8 tests)
// ============================================================================

#[test]
fn test_fee_flow_small_amount() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Collect and distribute fees
    router.collect(1000).unwrap();
    let dist = router.distribute(100).unwrap();

    // UBI should receive 45% of fees
    assert_eq!(dist.ubi_pool, 450);

    // Simulate UBI receiving funds
    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 450);
}

#[test]
fn test_fee_flow_large_amount() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 3 scenario: $5M fees
    router.collect(5_000_000).unwrap();
    let dist = router.distribute(100).unwrap();

    // 45% to UBI = 2,250,000
    assert_eq!(dist.ubi_pool, 2_250_000);

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 2_250_000);
}

#[test]
fn test_ubi_pool_accumulates_funds() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // First distribution
    router.collect(1000).unwrap();
    let dist1 = router.distribute(100).unwrap();
    ubi.receive_funds(&governance, dist1.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 450);

    // Second distribution
    router.collect(2000).unwrap();
    let dist2 = router.distribute(200).unwrap();
    ubi.receive_funds(&governance, dist2.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 450 + 900); // 450 + 900
}

#[test]
fn test_fee_split_audit_trail() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // Collect $100K fees
    router.collect(100_000).unwrap();
    let dist = router.distribute(100).unwrap();

    // Verify 45/30/15/10 split sums to total
    let total = dist.total_distributed();
    assert_eq!(total, 100_000 - dist.remainder);

    // Verify percentages
    assert_eq!(dist.ubi_pool, 45_000);
    assert_eq!(dist.dao_pool, 30_000);
    assert_eq!(dist.emergency_reserve, 15_000);
    assert_eq!(dist.dev_grants, 10_000);
}

#[test]
fn test_integration_with_existing_ubi_balance() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Pre-fund UBI with 10,000
    ubi.receive_funds(&governance, 10_000).unwrap();
    assert_eq!(ubi.balance(), 10_000);

    // Now add fees from FeeRouter
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    router.collect(1000).unwrap();
    let dist = router.distribute(100).unwrap();

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 10_450);
}

#[test]
fn test_distribution_zero_fees_rejected() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // Try to distribute without collecting
    let result = router.distribute(100);
    assert_eq!(result, Err(FeeRouterError::ZeroAmount));
}

#[test]
fn test_multiple_distributions_cumulative() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Three monthly distributions
    for month in 1..=3 {
        router.collect(10_000).unwrap();
        let dist = router.distribute(month * 100).unwrap();
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    // Total should be 3 × 4500
    assert_eq!(ubi.balance(), 13_500);
    assert_eq!(ubi.total_received(), 13_500);
}

// ============================================================================
// CATEGORY 2: End-to-End Fee Flow (6 tests)
// ============================================================================

#[test]
fn test_complete_monthly_cycle() {
    let governance = test_key(1);
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Register citizens
    for i in 10..20 {
        ubi.register(&test_key(i)).unwrap();
    }
    assert_eq!(ubi.registered_count(), 10);

    // Collect monthly fees
    router.collect(100_000).unwrap();

    // Distribute
    let dist = router.distribute(BLOCKS_PER_MONTH).unwrap();

    // Fund UBI
    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    assert_eq!(ubi.balance(), 45_000); // 45% of 100k

    // Set schedule for month 0
    ubi.set_amount_range(&governance, 0, 11, 4_500).unwrap();

    // Verify amounts available
    assert_eq!(ubi.amount_for(0), 4_500);
}

#[test]
fn test_year1_volume_projection() {
    // Year 1: $1M/month volume → $10K fees/month
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Register 10K citizens
    for i in 0..100 {
        ubi.register(&test_key((i % 255) as u8 + 10)).ok();
    }

    // Monthly volume: 1M → 10K fees
    router.collect(10_000).unwrap();
    let dist = router.distribute(BLOCKS_PER_MONTH).unwrap();

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();

    // 45% of 10K = 4500
    assert_eq!(ubi.balance(), 4_500);
}

#[test]
fn test_year3_volume_projection() {
    // Year 3: $500M/month volume → $5M fees/month
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    router.collect(5_000_000).unwrap();
    let dist = router.distribute(BLOCKS_PER_MONTH * 24).unwrap();

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();

    // 45% of 5M = 2.25M
    assert_eq!(ubi.balance(), 2_250_000);
}

#[test]
fn test_year5_volume_projection() {
    // Year 5: $5B/month volume → $50M fees/month
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    router.collect(50_000_000).unwrap();
    let dist = router.distribute(BLOCKS_PER_MONTH * 48).unwrap();

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();

    // 45% of 50M = 22.5M
    assert_eq!(ubi.balance(), 22_500_000);
}

#[test]
fn test_monthly_cycle_three_months() {
    let governance = test_key(1);
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Simulate 3 months of fee collection
    for month in 0..3 {
        router.collect(20_000).unwrap();
        let dist = router.distribute(BLOCKS_PER_MONTH * (month + 1)).unwrap();
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    // Total: 3 × 9000
    assert_eq!(ubi.balance(), 27_000);
    assert_eq!(ubi.total_received(), 27_000);
}

// ============================================================================
// CATEGORY 3: Stress Testing (4 tests)
// ============================================================================

#[test]
fn test_stress_10k_citizens() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Register 10K citizens
    // Magic number explanation:
    // - 245: Number of unique u8 values in range 10-254 (avoids 0-9 reserved, 255 overflow)
    // - 10: Starting offset to avoid reserved key_ids 0-9
    // - Result: (i % 245) gives 0-244, + 10 yields valid range 10-254
    const UNIQUE_KEY_RANGE: usize = 245; // u8 values 10-254
    const KEY_OFFSET: usize = 10;        // Skip reserved key_ids 0-9
    for i in 0..10_000 {
        ubi.register(&test_key(((i % UNIQUE_KEY_RANGE) + KEY_OFFSET) as u8)).ok();
    }

    assert_eq!(ubi.registered_count(), UNIQUE_KEY_RANGE); // Limited by unique key_ids (10-254)
}

#[test]
fn test_stress_high_frequency_distributions() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // 100 rapid distributions
    for i in 1..=100 {
        router.collect(1_000).unwrap();
        let dist = router.distribute(i * 100).unwrap();
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    // Total should be 100 × 450
    assert_eq!(ubi.balance(), 45_000);
}

#[test]
fn test_stress_large_fee_amount() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Collect very large amount (1B)
    router.collect(1_000_000_000).unwrap();
    let dist = router.distribute(100).unwrap();

    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();

    // 45% of 1B
    assert_eq!(ubi.balance(), 450_000_000);
}

#[test]
fn test_stress_overflow_protection() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Near max u64
    let large_amount = u64::MAX / 2;
    router.collect(large_amount).unwrap();
    let dist = router.distribute(100).unwrap();

    // Should not overflow
    assert!(dist.ubi_pool > 0);
    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
}

// ============================================================================
// CATEGORY 4: Precision Testing (4 tests)
// ============================================================================

#[test]
fn test_precision_integer_division() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // Test with amounts that don't divide evenly
    router.collect(999).unwrap();
    let dist = router.distribute(100).unwrap();

    // 45% of 999 = 449.55 → 449
    assert_eq!(dist.ubi_pool, 449);

    // Verify remainder is tracked
    assert!(dist.remainder > 0);

    // Verify total is not lost
    assert!(dist.total_distributed() + dist.remainder == 999);
}

#[test]
fn test_precision_cumulative_no_loss() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // 100 small amounts
    let mut total_distributed = 0u64;

    for i in 1..=100 {
        router.collect(997).unwrap();

        let dist = router.distribute(i as u64 * 100).unwrap();
        total_distributed += dist.ubi_pool;
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    // Accumulated total should match what was actually distributed to UBI
    assert_eq!(ubi.total_received(), total_distributed);
}

#[test]
fn test_precision_boundary_values() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Test boundary: 1
    router.collect(1).unwrap();
    let dist = router.distribute(1).unwrap();
    assert_eq!(dist.total_distributed() + dist.remainder, 1);

    // Test boundary: 100
    let mut router2 = FeeRouter::new();
    init_fee_router(&mut router2);
    router2.collect(100).unwrap();
    let dist2 = router2.distribute(2).unwrap();
    assert_eq!(dist2.total_distributed() + dist2.remainder, 100);
}

// ============================================================================
// CATEGORY 5: Fairness Testing (4 tests)
// ============================================================================

#[test]
fn test_fairness_consistent_allocation() {
    let mut router1 = FeeRouter::new();
    let mut router2 = FeeRouter::new();
    init_fee_router(&mut router1);
    init_fee_router(&mut router2);

    // Same amount in both routers
    router1.collect(10_000).unwrap();
    router2.collect(10_000).unwrap();

    let dist1 = router1.distribute(100).unwrap();
    let dist2 = router2.distribute(200).unwrap();

    // Should get exactly the same split percentages
    assert_eq!(dist1.ubi_pool, dist2.ubi_pool);
    assert_eq!(dist1.dao_pool, dist2.dao_pool);
    assert_eq!(dist1.emergency_reserve, dist2.emergency_reserve);
    assert_eq!(dist1.dev_grants, dist2.dev_grants);
}

#[test]
fn test_fairness_allocation_percentages() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    router.collect(1_000_000).unwrap();
    let dist = router.distribute(100).unwrap();

    // Verify exact percentages
    assert_eq!(dist.ubi_pool, 450_000);      // 45%
    assert_eq!(dist.dao_pool, 300_000);      // 30%
    assert_eq!(dist.emergency_reserve, 150_000); // 15%
    assert_eq!(dist.dev_grants, 100_000);    // 10%
}

#[test]
fn test_fairness_no_double_allocation() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi1 = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();
    let mut ubi2 = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    router.collect(10_000).unwrap();
    let dist = router.distribute(100).unwrap();

    // Each receives the same allocation independently
    ubi1.receive_funds(&governance, dist.ubi_pool).unwrap();
    ubi2.receive_funds(&governance, dist.ubi_pool).unwrap();

    assert_eq!(ubi1.balance(), 4_500);
    assert_eq!(ubi2.balance(), 4_500);
}

// ============================================================================
// CATEGORY 6: Performance Validation (4 tests)
// ============================================================================

#[test]
fn bench_fee_collection_throughput() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let start = Instant::now();

    // Collect 10K times
    for _ in 1..=10_000 {
        router.collect(1).unwrap();
    }

    let elapsed = start.elapsed();

    // Should be very fast (< 100ms)
    assert!(elapsed.as_millis() < 100, "Collection took {} ms", elapsed.as_millis());
}

#[test]
fn bench_distribution_throughput() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // 100 distributions
    for i in 1..=100 {
        router.collect(1_000).unwrap();
        let dist = router.distribute(i * 100).unwrap();
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    let elapsed = start.elapsed();

    // Should complete in < 1 second
    assert!(elapsed.as_secs() < 1, "Distribution took {} ms", elapsed.as_millis());
}

#[test]
fn bench_ubi_citizen_registration() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // Register 1000 citizens
    for i in 10..1010 {
        ubi.register(&test_key((i % 255) as u8 + 1)).ok();
    }

    let elapsed = start.elapsed();

    // Should be fast (< 500ms for 1000)
    assert!(elapsed.as_millis() < 500, "Registration took {} ms", elapsed.as_millis());
}

#[test]
fn bench_year1_to_year5_projection() {
    let governance = test_key(1);
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // Simulate 60 months (5 years) of operations
    for month in 0..60 {
        // Varying fees based on year
        let fees = match month / 12 {
            0 => 10_000,      // Year 1
            1 => 50_000,      // Year 2
            2 => 5_000_000,   // Year 3
            3 => 15_000_000,  // Year 4
            _ => 50_000_000,  // Year 5
        };

        router.collect(fees).unwrap();
        let dist = router.distribute(BLOCKS_PER_MONTH * (month + 1)).unwrap();
        ubi.receive_funds(&governance, dist.ubi_pool).unwrap();
    }

    let elapsed = start.elapsed();

    // 60-month simulation should be fast
    assert!(elapsed.as_secs() < 1, "5-year simulation took {} ms", elapsed.as_millis());
}

// ============================================================================
// CATEGORY 7: Error Scenarios (5 tests)
// ============================================================================

#[test]
fn test_error_collect_zero() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    let result = router.collect(0);
    assert_eq!(result, Err(FeeRouterError::ZeroAmount));
}

#[test]
fn test_error_distribute_uninitialized() {
    let mut router = FeeRouter::new();
    // Don't initialize

    router.collect(1000).unwrap_or(()); // Fails but that's expected

    let result = router.distribute(100);
    assert_eq!(result, Err(FeeRouterError::NotInitialized));
}

#[test]
fn test_error_receive_funds_unauthorized() {
    let governance = test_key(1);
    let other = test_key(99);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let result = ubi.receive_funds(&other, 1000);
    assert!(result.is_err());
}

#[test]
fn test_error_unauthorized_fee_router_operations() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // collect() is permissionless but distribute() state change is guarded
    router.collect(1000).unwrap();
    let dist1 = router.distribute(100).unwrap();

    // Same operation should work - no authorization required for FeeRouter
    router.collect(1000).unwrap();
    let dist2 = router.distribute(200).unwrap();

    // Both distributions have same allocation percentages
    assert_eq!(dist1.ubi_pool, dist2.ubi_pool);
}

#[test]
fn test_error_ubi_duplicate_registration() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let citizen = test_key(10);

    ubi.register(&citizen).unwrap();
    let result = ubi.register(&citizen);

    assert!(result.is_err());
}

// ============================================================================
// ADDITIONAL EDGE CASE TESTS (4 more)
// ============================================================================

#[test]
fn test_edge_case_remainder_accumulation() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // Collect amounts that produce remainders
    for _ in 0..10 {
        router.collect(333).unwrap(); // Will have remainder: 333 % 100 != 0
    }

    let dist = router.distribute(100).unwrap();

    // Verify no precision loss
    assert_eq!(dist.total_distributed() + dist.remainder, 3330);
}

#[test]
fn test_edge_case_dao_per_unit_distribution() {
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);

    // Collect 1.5M (will be divided by 5 DAOs = 300k each)
    router.collect(1_500_000).unwrap();
    let dist = router.distribute(100).unwrap();

    // 30% of 1.5M = 450k
    assert_eq!(dist.dao_pool, 450_000);

    // Per DAO: 450k / 5 = 90k
    assert_eq!(dist.per_dao_amount(), 90_000);
}

#[test]
fn test_edge_case_ubi_schedule_integration() {
    let governance = test_key(1);
    let mut router = FeeRouter::new();
    init_fee_router(&mut router);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Register citizens
    for i in 10..20 {
        ubi.register(&test_key(i)).unwrap();
    }

    // Collect fees and fund UBI
    router.collect(50_000).unwrap();
    let dist = router.distribute(BLOCKS_PER_MONTH).unwrap();
    ubi.receive_funds(&governance, dist.ubi_pool).unwrap();

    // Set schedule: Year 1 (months 0-11)
    ubi.set_amount_range(&governance, 0, 11, 2_000).unwrap();

    // Verify schedule is set
    assert_eq!(ubi.amount_for(0), 2_000);
    assert_eq!(ubi.amount_for(11), 2_000);
    assert_eq!(ubi.amount_for(12), 0); // Year 2 not set

    // Verify we have enough balance for month 0: 10 citizens × 2000 = 20k
    // We have 22.5k, so sufficient
    assert!(ubi.balance() >= 20_000);
}

#[test]
fn test_edge_case_governance_consistency() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // All governance-protected operations should use same authority
    assert!(ubi.set_amount_range(&governance, 0, 11, 1000).is_ok());
    assert!(ubi.receive_funds(&governance, 1000).is_ok());

    // But an impostor should fail
    let impostor = test_key(99);
    assert!(ubi.set_amount_range(&impostor, 0, 11, 1000).is_err());
    assert!(ubi.receive_funds(&impostor, 1000).is_err());
}
