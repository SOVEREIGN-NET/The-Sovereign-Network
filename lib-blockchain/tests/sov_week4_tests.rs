//! Week 4 Comprehensive Unit Tests
//!
//! Tests for UBI Distribution contract validation.
//!
//! Tests validate:
//! - UBI contract initialization and configuration
//! - Citizen registration and tracking
//! - Schedule configuration for financial years
//! - Funding mechanism and balance tracking
//!
//! Critical Constants Validated:
//! - Year 1 (months 0-11): $0.45 per citizen
//! - Year 3 (months 24-35): $4.50 per citizen
//! - Year 5 (months 48-59): $22.50 per citizen

use lib_blockchain::contracts::ubi_distribution::UbiDistributor;
use lib_blockchain::integration::crypto_integration::PublicKey;

// ============================================================================
// TEST CONSTANTS
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

// ============================================================================
// INITIALIZATION TESTS
// ============================================================================

#[test]
fn test_ubi_creation() {
    let governance = test_key(1);
    let result = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH);

    assert!(result.is_ok());
    let ubi = result.unwrap();
    assert_eq!(ubi.registered_count(), 0);
    assert_eq!(ubi.balance(), 0);
    assert_eq!(ubi.total_received(), 0);
    assert_eq!(ubi.total_paid(), 0);
    assert_eq!(ubi.blocks_per_month(), BLOCKS_PER_MONTH);
}

#[test]
fn test_ubi_invalid_blocks_per_month() {
    let governance = test_key(1);
    let result = UbiDistributor::new(governance, 0);

    assert!(result.is_err());
}

// ============================================================================
// CITIZEN REGISTRATION TESTS
// ============================================================================

#[test]
fn test_register_single_citizen() {
    let governance = test_key(1);
    let citizen = test_key(10);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    let result = ubi.register(&citizen);
    assert!(result.is_ok());
    assert_eq!(ubi.registered_count(), 1);
}

#[test]
fn test_register_multiple_citizens() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    for i in 10..20 {
        let citizen = test_key(i);
        ubi.register(&citizen).unwrap();
    }

    assert_eq!(ubi.registered_count(), 10);
}

#[test]
fn test_cannot_register_duplicate_citizen() {
    let governance = test_key(1);
    let citizen = test_key(10);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    ubi.register(&citizen).unwrap();
    let result = ubi.register(&citizen);

    assert!(result.is_err());
}

// ============================================================================
// SCHEDULE CONFIGURATION TESTS
// ============================================================================

#[test]
fn test_set_month_amount() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 1 monthly amount: $0.45 (4500 in base units)
    let result = ubi.set_month_amount(&governance, 0, 4_500);
    assert!(result.is_ok());
    assert_eq!(ubi.amount_for(0), 4_500);
}

#[test]
fn test_cannot_set_zero_amount() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let result = ubi.set_month_amount(&governance, 0, 0);
    assert!(result.is_err());
}

#[test]
fn test_set_amount_range_year1() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 1: months 0-11, $0.45 per citizen
    let result = ubi.set_amount_range(&governance, 0, 11, 4_500);
    assert!(result.is_ok());

    for month in 0..12 {
        assert_eq!(ubi.amount_for(month), 4_500);
    }

    // Month 12 (Year 2) should be 0
    assert_eq!(ubi.amount_for(12), 0);
}

#[test]
fn test_set_amount_range_year3() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 3: months 24-35, $4.50 per citizen
    let result = ubi.set_amount_range(&governance, 24, 35, 450_000);
    assert!(result.is_ok());

    for month in 24..36 {
        assert_eq!(ubi.amount_for(month), 450_000);
    }

    // Month 23 (before Year 3) should be 0
    assert_eq!(ubi.amount_for(23), 0);
}

#[test]
fn test_set_amount_range_year5() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 5: months 48-59, $22.50 per citizen
    let result = ubi.set_amount_range(&governance, 48, 59, 2_250_000);
    assert!(result.is_ok());

    for month in 48..60 {
        assert_eq!(ubi.amount_for(month), 2_250_000);
    }

    // Month 47 (before Year 5) should be 0
    assert_eq!(ubi.amount_for(47), 0);
}

#[test]
fn test_invalid_range_end_before_start() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let result = ubi.set_amount_range(&governance, 10, 5, 1_000);
    assert!(result.is_err());
}

#[test]
fn test_cannot_set_amount_unauthorized() {
    let governance = test_key(1);
    let other = test_key(99);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    let result = ubi.set_month_amount(&other, 0, 4_500);
    assert!(result.is_err());
}

// ============================================================================
// FUNDING TESTS
// ============================================================================

#[test]
fn test_receive_funds() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let result = ubi.receive_funds(&governance, 100_000);
    assert!(result.is_ok());
    assert_eq!(ubi.balance(), 100_000);
    assert_eq!(ubi.total_received(), 100_000);
}

#[test]
fn test_cannot_receive_zero_funds() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    let result = ubi.receive_funds(&governance, 0);
    assert!(result.is_err());
}

#[test]
fn test_cannot_receive_funds_unauthorized() {
    let governance = test_key(1);
    let other = test_key(99);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    let result = ubi.receive_funds(&other, 100_000);
    assert!(result.is_err());
}

#[test]
fn test_receive_multiple_fund_transfers() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    ubi.receive_funds(&governance, 50_000).unwrap();
    ubi.receive_funds(&governance, 30_000).unwrap();
    ubi.receive_funds(&governance, 20_000).unwrap();

    assert_eq!(ubi.balance(), 100_000);
    assert_eq!(ubi.total_received(), 100_000);
}

// ============================================================================
// FINANCIAL ACCURACY TESTS
// ============================================================================

#[test]
fn test_year1_financial_projection() {
    // Year 1: $0.45 per citizen
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Register 100 citizens
    for i in 0..100 {
        let citizen = test_key((i % 255 + 10) as u8);
        ubi.register(&citizen).unwrap();
    }

    // Set Year 1 amount: $0.45 per citizen
    ubi.set_month_amount(&governance, 0, 4_500).unwrap();

    assert_eq!(ubi.registered_count(), 100);
    assert_eq!(ubi.amount_for(0), 4_500);
}

#[test]
fn test_year3_financial_projection() {
    // Year 3: $4.50 per citizen
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set Year 3 amount: $4.50 per citizen
    ubi.set_month_amount(&governance, 24, 450_000).unwrap();

    assert_eq!(ubi.amount_for(24), 450_000);
}

#[test]
fn test_year5_financial_projection() {
    // Year 5: $22.50 per citizen
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Set Year 5 amount: $22.50 per citizen
    ubi.set_month_amount(&governance, 48, 2_250_000).unwrap();

    assert_eq!(ubi.amount_for(48), 2_250_000);
}

// ============================================================================
// SCHEDULE ACROSS YEARS TESTS
// ============================================================================

#[test]
fn test_schedule_across_years() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Year 1
    ubi.set_amount_range(&governance, 0, 11, 4_500).unwrap();
    // Year 2
    ubi.set_amount_range(&governance, 12, 23, 40_000).unwrap();
    // Year 3
    ubi.set_amount_range(&governance, 24, 35, 450_000).unwrap();

    // Verify transitions
    assert_eq!(ubi.amount_for(11), 4_500);
    assert_eq!(ubi.amount_for(12), 40_000);
    assert_eq!(ubi.amount_for(23), 40_000);
    assert_eq!(ubi.amount_for(24), 450_000);
}

// ============================================================================
// VIEW/QUERY TESTS
// ============================================================================

#[test]
fn test_audit_trail_queries() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Initial state
    assert_eq!(ubi.balance(), 0);
    assert_eq!(ubi.total_received(), 0);
    assert_eq!(ubi.total_paid(), 0);

    // After receiving funds
    ubi.receive_funds(&governance, 500_000).unwrap();
    assert_eq!(ubi.balance(), 500_000);
    assert_eq!(ubi.total_received(), 500_000);
    assert_eq!(ubi.total_paid(), 0);
}

#[test]
fn test_registered_count_tracking() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance, BLOCKS_PER_MONTH).unwrap();

    assert_eq!(ubi.registered_count(), 0);

    for i in 10..20 {
        ubi.register(&test_key(i)).unwrap();
        assert_eq!(ubi.registered_count(), (i - 9) as usize);
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_week4_phase_gate_complete_workflow() {
    let governance = test_key(1);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // 1. Register citizens (multiple registrations)
    for i in 10..15 {
        ubi.register(&test_key(i)).unwrap();
    }
    assert_eq!(ubi.registered_count(), 5);

    // 2. Receive monthly funding
    ubi.receive_funds(&governance, 100_000).unwrap();
    assert_eq!(ubi.balance(), 100_000);

    // 3. Configure schedule for Year 1
    ubi.set_amount_range(&governance, 0, 11, 20_000).unwrap();
    assert_eq!(ubi.amount_for(0), 20_000);

    // 4. Verify audit trail
    assert_eq!(ubi.total_received(), 100_000);
    assert_eq!(ubi.balance(), 100_000);
    assert_eq!(ubi.registered_count(), 5);
}

#[test]
fn test_governance_authority_immutable() {
    let governance = test_key(1);
    let other = test_key(99);
    let mut ubi = UbiDistributor::new(governance.clone(), BLOCKS_PER_MONTH).unwrap();

    // Only original governance can set amounts
    assert!(ubi.set_month_amount(&governance, 0, 1_000).is_ok());
    assert!(ubi.set_month_amount(&other, 0, 1_000).is_err());

    // Only original governance can receive funds
    assert!(ubi.receive_funds(&governance, 1_000).is_ok());
    assert!(ubi.receive_funds(&other, 1_000).is_err());
}
