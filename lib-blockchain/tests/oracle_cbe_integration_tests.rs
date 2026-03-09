//! ORACLE-16: CBE graduation oracle gating integration tests
//!
//! Tests for:
//! - CBE graduation blocked without fresh oracle price
//! - CBE graduation rejected with stale oracle price
//! - CBE graduation accepted with fresh oracle price

use lib_blockchain::{
    contracts::bonding_curve::{BondingCurveToken, Phase, Threshold},
    contracts::tokens::CBE_SYMBOL,
    Blockchain,
};
use lib_crypto::PublicKey;

mod common;
use common::oracle_harness::OracleTestHarness;

/// Create a test CBE token with specified reserve
fn create_test_cbe_token(token_id: [u8; 32], reserve_micro_usd: u64) -> BondingCurveToken {
    BondingCurveToken {
        token_id,
        name: "Test CBE".to_string(),
        symbol: CBE_SYMBOL.to_string(),
        decimals: 8,
        phase: Phase::Curve,
        total_supply: 1_000_000_000,
        reserve_balance: reserve_micro_usd,
        curve_type: lib_blockchain::contracts::bonding_curve::CurveType::Linear {
            base_price: 1,
            slope: 1,
        },
        threshold: Threshold::ReserveAmount(269_000_000_000), // $269K
        sell_enabled: true,
        amm_pool_id: None,
        creator: PublicKey::new(vec![1u8; 32]),
        creator_did: None,
        deployed_at_block: 1,
        deployed_at_timestamp: 1,
    }
}

#[test]
fn test_cbe_graduation_blocked_without_fresh_oracle_price() {
    let mut harness = OracleTestHarness::new(4);

    // Register a CBE token with enough reserve to graduate
    let token_id = [1u8; 32];
    let token = create_test_cbe_token(token_id, 300_000_000_000); // $300K
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Try to validate graduation without any finalized price
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, harness.current_timestamp);

    assert!(result.is_err(), "should reject when no oracle price exists");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no fresh finalized oracle price"),
        "expected 'no fresh finalized oracle price' error, got: {}",
        err_msg
    );
}

#[test]
fn test_cbe_graduation_rejected_with_stale_oracle_price() {
    let mut harness = OracleTestHarness::new(4);

    // Register CBE token
    let token_id = [1u8; 32];
    let token = create_test_cbe_token(token_id, 300_000_000_000);
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Finalize a price in current epoch
    let old_epoch = harness.current_epoch();
    harness.finalize_epoch(old_epoch, 100_000_000);

    // Advance many epochs to make price stale
    let max_staleness = harness
        .blockchain
        .oracle_state
        .config()
        .max_price_staleness_epochs;
    for _ in 0..max_staleness + 2 {
        harness.advance_oracle_epoch();
    }

    // Try to graduate with stale price
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, harness.current_timestamp);

    assert!(result.is_err(), "should reject with stale oracle price");
}

#[test]
fn test_cbe_graduation_accepted_with_fresh_oracle_price() {
    let mut harness = OracleTestHarness::new(4);

    // Register CBE token
    let token_id = [1u8; 32];
    let token = create_test_cbe_token(token_id, 300_000_000_000);
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Finalize a price in current epoch
    let current_epoch = harness.current_epoch();
    harness.finalize_epoch(current_epoch, 100_000_000);

    // Try to graduate with fresh price
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, harness.current_timestamp);

    assert!(
        result.is_ok(),
        "should accept with fresh oracle price: {:?}",
        result
    );
}

#[test]
fn test_cbe_graduation_accepts_price_at_staleness_boundary() {
    let mut harness = OracleTestHarness::new(4);

    // Register CBE token
    let token_id = [1u8; 32];
    let token = create_test_cbe_token(token_id, 300_000_000_000);
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Finalize price at epoch 10
    let epoch_duration = harness.epoch_duration();
    let max_staleness = harness
        .blockchain
        .oracle_state
        .config()
        .max_price_staleness_epochs;

    // Set up blockchain to be at epoch 10
    harness.blockchain.oracle_state.try_finalize_price(
        lib_blockchain::oracle::FinalizedOraclePrice {
            epoch_id: 10,
            sov_usd_price: 100_000_000,
        },
    );

    // Check at boundary (exactly max_staleness epochs later)
    // Price finalized at epoch 10, current epoch = 10 + max_staleness - 1 = fresh
    let fresh_timestamp = (10 + max_staleness - 1) * epoch_duration + epoch_duration / 2;
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, fresh_timestamp);

    assert!(result.is_ok(), "should accept at staleness boundary");

    // Check past boundary (stale)
    let stale_timestamp = (10 + max_staleness + 1) * epoch_duration + epoch_duration / 2;
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, stale_timestamp);

    assert!(result.is_err(), "should reject past staleness boundary");
}

#[test]
fn test_non_cbe_token_skips_oracle_gate() {
    let mut harness = OracleTestHarness::new(4);

    // Register a non-CBE token (different symbol)
    let token_id = [2u8; 32];
    let mut token = create_test_cbe_token(token_id, 300_000_000_000);
    token.symbol = "NOTCBE".to_string(); // Not CBE symbol
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Should pass without any oracle price (non-CBE tokens skip the gate)
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, harness.current_timestamp);

    assert!(result.is_ok(), "non-CBE token should skip oracle gate");
}

#[test]
fn test_already_graduated_token_skips_oracle_gate() {
    let mut harness = OracleTestHarness::new(4);

    // Register a token that's already graduated
    let token_id = [3u8; 32];
    let mut token = create_test_cbe_token(token_id, 300_000_000_000);
    token.phase = Phase::Graduated; // Already graduated
    harness
        .blockchain
        .bonding_curve_registry
        .register(token)
        .unwrap();

    // Should pass without checking oracle price
    let result = harness
        .blockchain
        .validate_cbe_graduation_oracle_gate(token_id, harness.current_timestamp);

    assert!(result.is_ok(), "graduated token should skip oracle gate");
}
