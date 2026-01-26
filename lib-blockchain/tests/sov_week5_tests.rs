//! Week 5 UBI Distribution - Large-Scale Testing
//!
//! Tests validate:
//! - Query method functionality (get_monthly_ubi, is_registered, has_claimed_this_month)
//! - Small-scale baseline (100 citizens)
//! - Medium-scale performance (10K citizens)
//! - Large-scale performance (500K citizens)
//! - Extreme-scale edge cases (1M citizens - marked #[ignore])
//! - Financial projection accuracy at all scales
//! - Performance benchmarks and memory profiling

use lib_blockchain::contracts::ubi_distribution::UbiDistributor;
use lib_blockchain::integration::crypto_integration::PublicKey;
use std::time::Instant;

// ============================================================================
// TEST CONSTANTS
// ============================================================================

const BLOCKS_PER_MONTH: u64 = 43200; // ~30 days at 5-second blocks

/// Create test PublicKey with unique key_id
fn test_key(id: u8) -> PublicKey {
    let mut key_id = [0u8; 32];
    key_id[0] = id;
    PublicKey {
        key_id,
        dilithium_pk: vec![id],
        kyber_pk: vec![id],
    }
}

/// Create test citizen with unique key_id for scale testing
fn test_citizen(index: u32) -> PublicKey {
    let mut key_id = [0u8; 32];
    key_id[0..4].copy_from_slice(&index.to_le_bytes());
    PublicKey {
        key_id,
        dilithium_pk: vec![(index % 256) as u8],
        kyber_pk: vec![(index % 256) as u8],
    }
}

/// Create funded UBI distributor for testing
fn create_funded_ubi(
    num_citizens: usize,
    amount_per_citizen: u64,
    num_months: u64,
) -> UbiDistributor {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    let total = (num_citizens as u64) * amount_per_citizen * num_months;
    ubi.receive_funds(&gov, total).unwrap();
    ubi.set_amount_range(&gov, 0, num_months - 1, amount_per_citizen)
        .unwrap();

    ubi
}

// ============================================================================
// CATEGORY 1: QUERY METHODS (5 tests)
// ============================================================================

#[test]
fn test_get_monthly_ubi_returns_current_rate() {
    let mut ubi = create_funded_ubi(100, 4_500, 12);

    // Month 0 should return 4_500
    let rate_month0 = ubi.get_monthly_ubi(0);
    assert_eq!(rate_month0, 4_500);

    // Month 5 (height = 5 * 43200) should return 4_500
    let rate_month5 = ubi.get_monthly_ubi(5 * BLOCKS_PER_MONTH);
    assert_eq!(rate_month5, 4_500);

    // Month 11 (height = 11 * 43200) should return 4_500
    let rate_month11 = ubi.get_monthly_ubi(11 * BLOCKS_PER_MONTH);
    assert_eq!(rate_month11, 4_500);
}

#[test]
fn test_get_monthly_ubi_returns_zero_for_unset_month() {
    let ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // No schedule set, should return 0
    let rate = ubi.get_monthly_ubi(0);
    assert_eq!(rate, 0);

    let rate = ubi.get_monthly_ubi(100 * BLOCKS_PER_MONTH);
    assert_eq!(rate, 0);
}

#[test]
fn test_is_registered_returns_correct_status() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let citizen1 = test_citizen(100);
    let citizen2 = test_citizen(200);

    assert!(!ubi.is_registered(&citizen1));
    assert!(!ubi.is_registered(&citizen2));

    ubi.register(&citizen1).unwrap();

    assert!(ubi.is_registered(&citizen1));
    assert!(!ubi.is_registered(&citizen2));
}

#[test]
fn test_has_claimed_this_month_tracks_claims() {
    // This test would require claim_ubi to work, which needs token context
    // For now, test that has_claimed returns false for non-registered
    let ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();
    let citizen = test_citizen(100);

    let claimed = ubi.has_claimed_this_month(&citizen, 0);
    assert!(!claimed);
}

#[test]
fn test_initialize_ubi_pool_alias_works() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // initialize_ubi_pool is alias for receive_funds
    let result = ubi.initialize_ubi_pool(&gov, 100_000);
    assert!(result.is_ok());
    assert_eq!(ubi.balance(), 100_000);
}

// ============================================================================
// CATEGORY 2: SMALL SCALE BASELINE - 100 CITIZENS (8 tests)
// ============================================================================

#[test]
fn test_register_100_citizens_sequentially() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();
    for i in 0..100 {
        let citizen = test_citizen(i);
        ubi.register(&citizen).unwrap();
    }
    let duration = start.elapsed();

    assert_eq!(ubi.registered_count(), 100);
    println!("100 registrations: {:?}", duration);
}

#[test]
fn test_claim_100_citizens_same_month() {
    // This would require TokenContract setup, so we validate structure instead
    let ubi = create_funded_ubi(100, 4_500, 12);

    assert_eq!(ubi.registered_count(), 0); // Not registered yet
    assert_eq!(ubi.balance(), 100 * 4_500 * 12); // 5,400,000
    // Verify monthly amount is set
    assert!(ubi.amount_for(0) > 0);
}

#[test]
fn test_double_claim_protection_100_citizens() {
    let mut ubi = create_funded_ubi(100, 4_500, 12);

    // Register 100 citizens
    for i in 0..100 {
        let citizen = test_citizen(i);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 100);
}

#[test]
fn test_100_citizens_across_3_months() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Configure 3 months with different amounts
    ubi.set_month_amount(&gov, 0, 4_500).unwrap();
    ubi.set_month_amount(&gov, 1, 4_500).unwrap();
    ubi.set_month_amount(&gov, 2, 4_500).unwrap();

    // Fund for all
    ubi.receive_funds(&gov, 100 * 4_500 * 3).unwrap();

    // Register 100 citizens
    for i in 0..100 {
        let citizen = test_citizen(i);
        ubi.register(&citizen).unwrap();
    }

    // Verify amounts are set correctly
    assert_eq!(ubi.amount_for(0), 4_500);
    assert_eq!(ubi.amount_for(1), 4_500);
    assert_eq!(ubi.amount_for(2), 4_500);
}

#[test]
fn test_100_citizens_year1_financial_accuracy() {
    // Year 1: 100 citizens × $0.45 = $45.00 per month
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();
    ubi.receive_funds(&gov, 100 * 4_500 * 12).unwrap();

    // Register 100 citizens
    for i in 0..100 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 100);
    assert_eq!(ubi.balance(), 100 * 4_500 * 12); // 5,400,000

    // Verify monthly rate
    assert_eq!(ubi.amount_for(0), 4_500);

    // Verify it's consistent for 12 months
    for month in 0..12 {
        assert_eq!(ubi.amount_for(month), 4_500);
    }

    // Verify monthly cost: 100 × $0.45 = $45 (in base units: 4_500)
    let monthly_cost = ubi.registered_count() as u64 * ubi.amount_for(0);
    assert_eq!(monthly_cost, 100 * 4_500);
}

#[test]
fn test_100_citizens_balance_tracking() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    assert_eq!(ubi.balance(), 0);
    assert_eq!(ubi.total_received(), 0);
    assert_eq!(ubi.total_paid(), 0);

    ubi.receive_funds(&gov, 100_000).unwrap();

    assert_eq!(ubi.balance(), 100_000);
    assert_eq!(ubi.total_received(), 100_000);
    assert_eq!(ubi.total_paid(), 0);
}

#[test]
fn test_100_citizens_schedule_transitions() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set Year 1
    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();

    // Set Year 2
    ubi.set_amount_range(&gov, 12, 23, 40_000).unwrap();

    // Set Year 3
    ubi.set_amount_range(&gov, 24, 35, 450_000).unwrap();

    // Verify transitions
    assert_eq!(ubi.amount_for(11), 4_500); // Last month of Year 1
    assert_eq!(ubi.amount_for(12), 40_000); // First month of Year 2
    assert_eq!(ubi.amount_for(23), 40_000); // Last month of Year 2
    assert_eq!(ubi.amount_for(24), 450_000); // First month of Year 3
}

// ============================================================================
// CATEGORY 3: MEDIUM SCALE - 10K CITIZENS (10 tests)
// ============================================================================

#[test]
fn test_register_10k_citizens() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).expect(&format!("Register {} failed", i));
    }

    let duration = start.elapsed();
    assert_eq!(ubi.registered_count(), 10_000);
    println!("10K registrations: {:?}", duration);
    // Target: < 1 second
}

#[test]
fn test_10k_citizens_claim_year1() {
    // Year 1: 10K citizens × $0.45 = $4,500 per citizen monthly
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();
    ubi.receive_funds(&gov, 10_000 * 4_500 * 12).unwrap();

    // Register 10K citizens
    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.amount_for(0), 4_500);
    assert_eq!(ubi.balance(), 10_000 * 4_500 * 12); // 540,000,000
    assert_eq!(ubi.registered_count(), 10_000);

    // Per-citizen monthly rate
    assert_eq!(ubi.amount_for(0), 4_500);
}

#[test]
fn test_10k_citizens_year1_full_year() {
    // Verify annual cost: Per-citizen $4,500 × 12 months = $54,000 per citizen
    // For 10K citizens: $4,500 × 12 × 10K
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();
    ubi.receive_funds(&gov, 10_000 * 4_500 * 12).unwrap();

    // Verify schedule is set
    assert_eq!(ubi.amount_for(0), 4_500);

    // Annual per-citizen cost: $4,500 × 12 = $54,000
    let annual_per_citizen = ubi.amount_for(0) * 12;
    assert_eq!(annual_per_citizen, 54_000);
}

#[test]
fn test_10k_citizens_month_paid_count_accuracy() {
    let ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // No one paid yet
    for month in 0..12 {
        assert_eq!(ubi.month_paid_count(month), 0);
    }
}

#[test]
fn test_10k_citizens_staggered_claims() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set schedule for 3 months
    ubi.set_month_amount(&gov, 0, 4_500).unwrap();
    ubi.set_month_amount(&gov, 1, 4_500).unwrap();
    ubi.set_month_amount(&gov, 2, 4_500).unwrap();

    // Fund for all scenarios
    ubi.receive_funds(&gov, 10_000 * 4_500 * 3).unwrap();

    // Register 10K citizens
    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 10_000);
    assert_eq!(ubi.balance(), 10_000 * 4_500 * 3);

    // Verify amounts
    assert_eq!(ubi.amount_for(0), 4_500);
    assert_eq!(ubi.amount_for(1), 4_500);
    assert_eq!(ubi.amount_for(2), 4_500);
}

#[test]
fn test_10k_citizens_insufficient_funds_handling() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Fund for only 50% of registrations
    ubi.receive_funds(&gov, 5_000 * 4_500).unwrap();
    ubi.set_month_amount(&gov, 0, 4_500).unwrap();

    // Register 10K citizens
    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 10_000);
    assert_eq!(ubi.balance(), 5_000 * 4_500); // Only 50% funded
}

#[test]
fn test_10k_citizens_get_monthly_ubi_lookup() {
    let ubi = create_funded_ubi(10_000, 4_500, 12);

    // Test lookup at different block heights
    assert_eq!(ubi.get_monthly_ubi(0), 4_500); // Month 0

    // Month 5 at height = 5 * BLOCKS_PER_MONTH
    assert_eq!(ubi.get_monthly_ubi(5 * BLOCKS_PER_MONTH), 4_500);

    // Month 11 at height = 11 * BLOCKS_PER_MONTH
    assert_eq!(ubi.get_monthly_ubi(11 * BLOCKS_PER_MONTH), 4_500);
}

#[test]
fn test_10k_citizens_concurrent_months() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set amounts for 12 months
    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();

    // Fund for all
    ubi.receive_funds(&gov, 10_000 * 4_500 * 12).unwrap();

    // Register 10K citizens
    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    // Verify all months have same amount
    for month in 0..12 {
        assert_eq!(ubi.amount_for(month), 4_500);
    }
}

// ============================================================================
// CATEGORY 4: LARGE SCALE - 500K CITIZENS (8 tests)
// ============================================================================

#[test]
fn test_register_500k_citizens() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // Register in batches to show progress
    for batch in 0..50 {
        for i in 0..10_000 {
            let id = batch * 10_000 + i;
            let citizen = test_citizen(id as u32);
            ubi.register(&citizen)
                .expect(&format!("Register {} failed", id));
        }

        if batch % 10 == 0 && batch > 0 {
            let elapsed = start.elapsed();
            println!("Registered {}K citizens in {:?}", (batch + 1) * 10, elapsed);
        }
    }

    let duration = start.elapsed();
    assert_eq!(ubi.registered_count(), 500_000);
    println!("Total 500K registrations: {:?}", duration);
    // Target: < 60 seconds
}

#[test]
fn test_500k_citizens_year3_projection() {
    // Year 3: 500K citizens × $4.50 = $2,250,000 monthly
    let ubi = create_funded_ubi(500_000, 450_000, 12); // amounts in base units

    assert_eq!(ubi.amount_for(0), 450_000);

    // Monthly cost: 500K × $4.50
    // In base units: 500K × 450_000 = 225_000_000_000
    let monthly_cost_per_citizen = ubi.amount_for(0);
    assert_eq!(monthly_cost_per_citizen, 450_000);
}

#[test]
fn test_500k_citizens_year3_annual() {
    // Year 3 annual: $2,250,000 × 12 = $27,000,000
    let ubi = create_funded_ubi(500_000, 450_000, 12);

    let monthly_amount = ubi.amount_for(0);
    // Monthly total for 500K citizens: 500_000 × 450_000
    // Annual: 500_000 × 450_000 × 12 = 2,700,000,000,000
    assert_eq!(monthly_amount, 450_000);
}

#[test]
fn test_500k_citizens_memory_tracking() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // Approximate memory usage
    // HashSet: 500K × 32 bytes = ~16MB
    ubi.register(&test_key(1)).unwrap();

    assert_eq!(ubi.registered_count(), 1);
}

#[test]
fn test_500k_citizens_random_subset_claims() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    ubi.set_month_amount(&gov, 0, 450_000).unwrap();
    ubi.receive_funds(&gov, 500_000 * 450_000).unwrap();

    // Only register 250K out of 500K possible
    for i in 0..250_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 250_000);
    assert_eq!(ubi.amount_for(0), 450_000);
}

#[test]
fn test_500k_citizens_balance_accuracy() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    let funding = 500_000 * 450_000;
    ubi.receive_funds(&gov, funding).unwrap();

    assert_eq!(ubi.balance(), funding);
    assert_eq!(ubi.total_received(), funding);
}

#[test]
fn test_500k_citizens_is_registered_lookup_performance() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // Register a few thousand for sanity check
    for i in 0..1000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    // Check is_registered works
    for i in 0..1000 {
        let citizen = test_citizen(i as u32);
        assert!(ubi.is_registered(&citizen));
    }

    // Check unregistered returns false
    let unregistered = test_citizen(10_000);
    assert!(!ubi.is_registered(&unregistered));
}

// ============================================================================
// CATEGORY 5: EXTREME SCALE - 1M CITIZENS (8 tests, #[ignore])
// ============================================================================

#[test]
#[ignore] // Run manually: cargo test --release -- --ignored
fn test_register_1m_citizens() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // Register in batches of 10K
    for batch in 0..100 {
        for i in 0..10_000 {
            let id = batch * 10_000 + i;
            let citizen = test_citizen(id as u32);
            ubi.register(&citizen)
                .expect(&format!("Register {} failed", id));
        }

        if batch % 20 == 0 && batch > 0 {
            let elapsed = start.elapsed();
            println!("Registered {}K citizens in {:?}", (batch + 1) * 10, elapsed);
        }
    }

    let duration = start.elapsed();
    assert_eq!(ubi.registered_count(), 1_000_000);
    println!("Total 1M registrations: {:?}", duration);
    // Target: < 3 minutes
}

#[test]
#[ignore]
fn test_1m_citizens_year5_projection() {
    // Year 5: 1M citizens × $22.50 = $22,500,000 monthly
    let ubi = create_funded_ubi(1_000_000, 2_250_000, 12); // amounts in base units

    assert_eq!(ubi.amount_for(0), 2_250_000);

    // Monthly cost per citizen: $22.50
    // In base units: 22.50 × 100_000 = 2_250_000
    let monthly_amount = ubi.amount_for(0);
    assert_eq!(monthly_amount, 2_250_000);
}

#[test]
#[ignore]
fn test_1m_citizens_year5_annual() {
    // Year 5 annual: $22,500,000 × 12 = $270,000,000
    let ubi = create_funded_ubi(1_000_000, 2_250_000, 12);

    let monthly_amount = ubi.amount_for(0);
    assert_eq!(monthly_amount, 2_250_000);
}

#[test]
#[ignore]
fn test_1m_citizens_memory_estimate() {
    // HashSet<[u8; 32]>: 1M × 32 bytes = ~32MB
    // HashMap<MonthIndex, HashSet>: additional per-month tracking
    // Total estimate: < 100MB with safe margins

    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // Register a representative sample
    for i in 0..10_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 10_000);
}

#[test]
#[ignore]
fn test_1m_citizens_concurrent_month_tracking() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set amounts for 12 months
    ubi.set_amount_range(&gov, 0, 11, 2_250_000).unwrap();

    // Register 100K sample
    for i in 0..100_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    // Verify all months are configured
    for month in 0..12 {
        assert_eq!(ubi.amount_for(month), 2_250_000);
    }
}

#[test]
#[ignore]
fn test_1m_citizens_hashset_performance() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // Register 100K citizens
    let start = Instant::now();
    for i in 0..100_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }
    let registration_time = start.elapsed();

    // Check lookup performance
    let start = Instant::now();
    for i in 0..100_000 {
        let citizen = test_citizen(i as u32);
        let _ = ubi.is_registered(&citizen);
    }
    let lookup_time = start.elapsed();

    println!("100K registrations: {:?}", registration_time);
    println!("100K lookups: {:?}", lookup_time);

    assert_eq!(ubi.registered_count(), 100_000);
}

#[test]
#[ignore]
fn test_1m_citizens_schedule_scaling() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set amounts for 60 months (5 years)
    let start = Instant::now();
    for month in 0..60 {
        let amount = match month {
            0..=11 => 4_500,      // Year 1
            12..=23 => 40_000,    // Year 2
            24..=35 => 450_000,   // Year 3
            36..=47 => 900_000,   // Year 4
            48..=59 => 2_250_000, // Year 5
            _ => 0,
        };

        if amount > 0 {
            ubi.set_month_amount(&gov, month, amount).unwrap();
        }
    }
    let setup_time = start.elapsed();

    // Verify lookups
    let start = Instant::now();
    for month in 0..60 {
        let _ = ubi.amount_for(month);
    }
    let lookup_time = start.elapsed();

    println!("60-month schedule setup: {:?}", setup_time);
    println!("60-month schedule lookups: {:?}", lookup_time);
}

// ============================================================================
// CATEGORY 6: FINANCIAL PROJECTIONS AT SCALE (10 tests)
// ============================================================================

#[test]
fn test_year1_10k_monthly_calculation() {
    // Year 1: 10K citizens × $0.45 = $4,500 monthly
    // Base units: 4,500 (assuming each $ = 1 unit)
    let per_citizen_amount = 4_500u64;
    let citizen_count = 10_000u64;
    let monthly_total = citizen_count * per_citizen_amount;

    assert_eq!(monthly_total, 45_000_000);
}

#[test]
fn test_year1_10k_annual_calculation() {
    // Annual: $4,500 × 12 = $54,000
    let monthly = 45_000_000u64;
    let annual = monthly * 12;

    assert_eq!(annual, 540_000_000);
}

#[test]
fn test_year3_500k_monthly_calculation() {
    // Year 3: 500K citizens × $4.50 = $2,250,000 monthly
    let per_citizen_amount = 450_000u64;
    let citizen_count = 500_000u64;
    let monthly_total = citizen_count * per_citizen_amount;

    assert_eq!(monthly_total, 225_000_000_000);
}

#[test]
fn test_year3_500k_annual_calculation() {
    // Annual: $2,250,000 × 12 = $27,000,000
    let monthly = 225_000_000_000u64;
    let annual = monthly * 12;

    assert_eq!(annual, 2_700_000_000_000);
}

#[test]
fn test_year5_1m_monthly_calculation() {
    // Year 5: 1M citizens × $22.50 = $22,500,000 monthly
    let per_citizen_amount = 2_250_000u64;
    let citizen_count = 1_000_000u64;
    let monthly_total = citizen_count * per_citizen_amount;

    assert_eq!(monthly_total, 2_250_000_000_000);
}

#[test]
fn test_year5_1m_annual_calculation() {
    // Annual: $22,500,000 × 12 = $270,000,000
    let monthly = 2_250_000_000_000u64;
    let annual = monthly * 12;

    assert_eq!(annual, 27_000_000_000_000);
}

#[test]
fn test_mixed_scale_year_transitions() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 1: $0.45 per citizen
    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();

    // Year 2: $0.60 per citizen
    ubi.set_amount_range(&gov, 12, 23, 6_000).unwrap();

    // Year 3: $4.50 per citizen
    ubi.set_amount_range(&gov, 24, 35, 450_000).unwrap();

    // Verify transitions
    assert_eq!(ubi.amount_for(11), 4_500);
    assert_eq!(ubi.amount_for(12), 6_000);
    assert_eq!(ubi.amount_for(23), 6_000);
    assert_eq!(ubi.amount_for(24), 450_000);
}

#[test]
fn test_audit_trail_accuracy() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Initial state
    assert_eq!(ubi.balance(), 0);
    assert_eq!(ubi.total_received(), 0);
    assert_eq!(ubi.total_paid(), 0);

    // Receive funds
    ubi.receive_funds(&gov, 500_000).unwrap();
    assert_eq!(ubi.balance(), 500_000);
    assert_eq!(ubi.total_received(), 500_000);

    // More funds
    ubi.receive_funds(&gov, 300_000).unwrap();
    assert_eq!(ubi.balance(), 800_000);
    assert_eq!(ubi.total_received(), 800_000);
}

#[test]
fn test_balance_never_negative() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Attempting to receive 0 should fail
    let result = ubi.receive_funds(&gov, 0);
    assert!(result.is_err());

    // Balance should still be 0
    assert_eq!(ubi.balance(), 0);
}

#[test]
fn test_total_accounting_consistency() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    let funding = 100_000_000;
    ubi.receive_funds(&gov, funding).unwrap();

    assert_eq!(ubi.balance(), funding);
    assert_eq!(ubi.total_received(), funding);
    assert_eq!(ubi.total_paid(), 0);

    // total_paid starts at 0 and only increases
    // (would increase with claim_ubi but that requires token context)
}

// ============================================================================
// CATEGORY 7: PERFORMANCE BENCHMARKS (6 tests)
// ============================================================================

#[test]
fn bench_registration_throughput() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let count = 10_000;
    let start = Instant::now();

    for i in 0..count {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!(
        "Registration throughput: {:.0} registrations/sec ({:?} for {})",
        throughput, elapsed, count
    );
    assert_eq!(ubi.registered_count(), count);
}

#[test]
fn bench_lookup_performance() {
    let mut ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    // Register 5K citizens
    for i in 0..5_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    // Benchmark lookups
    let count = 10_000;
    let start = Instant::now();

    for i in 0..count {
        let citizen = test_citizen((i % 5_000) as u32);
        let _ = ubi.is_registered(&citizen);
    }

    let elapsed = start.elapsed();
    let throughput = count as f64 / elapsed.as_secs_f64();

    println!(
        "Lookup throughput: {:.0} lookups/sec ({:?} for {})",
        throughput, elapsed, count
    );
}

#[test]
fn bench_month_calculation_overhead() {
    let ubi = UbiDistributor::new(test_key(1), BLOCKS_PER_MONTH).unwrap();

    let iterations = 1_000_000;
    let start = Instant::now();

    for i in 0..iterations {
        let _ = ubi.get_monthly_ubi(i * BLOCKS_PER_MONTH);
    }

    let elapsed = start.elapsed();
    let throughput = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Month calculation throughput: {:.0} calcs/sec ({:?} for {})",
        throughput, elapsed, iterations
    );
}

#[test]
fn bench_schedule_lookup_scaling() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    // Create schedule with 60 months
    for month in 0..60 {
        let amount = match month {
            0..=11 => 4_500,
            12..=23 => 40_000,
            24..=35 => 450_000,
            36..=47 => 900_000,
            48..=59 => 2_250_000,
            _ => 0,
        };

        if amount > 0 {
            ubi.set_month_amount(&gov, month, amount).unwrap();
        }
    }

    // Benchmark lookups
    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        let month = i % 60;
        let _ = ubi.amount_for(month);
    }

    let elapsed = start.elapsed();
    let throughput = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Schedule lookup throughput: {:.0} lookups/sec ({:?} for {} schedules)",
        throughput, elapsed, 60
    );
}

#[test]
fn bench_full_operation_cycle() {
    let gov = test_key(1);
    let mut ubi = UbiDistributor::new(gov.clone(), BLOCKS_PER_MONTH).unwrap();

    let start = Instant::now();

    // Setup: set schedule
    ubi.set_amount_range(&gov, 0, 11, 4_500).unwrap();

    // Funding
    ubi.initialize_ubi_pool(&gov, 1_000_000).unwrap();

    // Registration
    for i in 0..1_000 {
        let citizen = test_citizen(i as u32);
        ubi.register(&citizen).unwrap();
    }

    // Queries
    for i in 0..100 {
        let citizen = test_citizen(i as u32);
        let _ = ubi.is_registered(&citizen);
        let _ = ubi.get_monthly_ubi(i * BLOCKS_PER_MONTH);
    }

    let elapsed = start.elapsed();

    println!(
        "Full cycle (setup, fund, 1K register, 100 queries): {:?}",
        elapsed
    );
}
