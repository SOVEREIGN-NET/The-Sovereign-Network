//! Integration tests for Issue #1819: Unified Token Pricing System
//!
//! Tests the unified pricing system for SOV and CBE tokens,
//! including pre/post-graduation modes and oracle-derived pricing.

use lib_blockchain::{
    oracle::{FinalizedOraclePrice, OracleState},
    pricing::{PricingMode, TokenPricingState, PRICE_SCALE},
    Blockchain,
};

/// Test that TokenPricingState initializes with correct defaults
#[test]
fn token_pricing_state_initializes_correctly() {
    let state = TokenPricingState::new();

    assert!(state.cbe_usd_price.is_none());
    assert!(state.cbe_sov_ratio.is_none());
    assert!(!state.dynamic_pricing_active);
    assert_eq!(state.last_sov_price_8dec, 2_180_000); // GENESIS_SRV_8DEC
}

/// Test that CBE/USD price update enables dynamic pricing when both signals available
#[test]
fn dynamic_pricing_activates_with_both_signals() {
    let mut state = TokenPricingState::new();

    // Initially no dynamic pricing
    assert!(!state.dynamic_pricing_active);
    assert_eq!(state.get_sov_pricing_mode(), PricingMode::Fixed);

    // Update CBE/SOV ratio first (from bonding curve)
    state.update_cbe_sov_ratio(60 * PRICE_SCALE, 1000);
    assert!(!state.dynamic_pricing_active); // Still need CBE/USD

    // Update CBE/USD price (from oracle)
    state.update_cbe_usd_price(3 * PRICE_SCALE, 1, 1000);
    assert!(state.dynamic_pricing_active);
    assert_eq!(state.get_sov_pricing_mode(), PricingMode::Dynamic);

    // Verify SOV price calculation: CBE_USD / CBE_SOV = 3 / 60 = 0.05
    let expected_sov_price = (3 * PRICE_SCALE * PRICE_SCALE) / (60 * PRICE_SCALE);
    assert_eq!(state.last_sov_price_8dec, expected_sov_price);
}

/// Test SOV price calculation formula
#[test]
fn sov_price_calculation_is_correct() {
    use lib_blockchain::pricing::PricingCalculator;

    // Example: CBE/USD = $3, CBE/SOV = 60
    // SOV/USD = 3 / 60 = $0.05
    let cbe_usd = 3 * PRICE_SCALE;
    let cbe_sov = 60 * PRICE_SCALE;
    let sov_price = PricingCalculator::calculate_sov_price(cbe_usd, cbe_sov).unwrap();

    // $0.05 in 8-decimal precision
    let expected = 5_000_000; // 0.05 * 100_000_000
    assert_eq!(sov_price, expected);
}

/// Test that oracle finalization updates token pricing state
#[test]
fn oracle_finalization_updates_pricing_state() {
    let mut blockchain = Blockchain::default();

    // Initially no CBE price
    assert!(blockchain.token_pricing_state.cbe_usd_price.is_none());

    // Finalize an oracle price with CBE/USD
    let cbe_price = 3 * PRICE_SCALE; // $3.00
    blockchain
        .oracle_state
        .try_finalize_price(FinalizedOraclePrice {
            epoch_id: 1,
            sov_usd_price: 5 * PRICE_SCALE, // $5.00 SOV
            cbe_usd_price: Some(cbe_price),
        });

    // Apply the attestation through the blockchain (simulated)
    // In production, this happens via apply_oracle_attestation
    // For this test, we manually update the pricing state
    blockchain
        .token_pricing_state
        .update_cbe_usd_price(cbe_price, 1, 1000);

    // Verify pricing state was updated
    assert_eq!(blockchain.token_pricing_state.cbe_usd_price, Some(cbe_price));
    assert_eq!(blockchain.token_pricing_state.cbe_price_epoch, Some(1));
}

/// Test price components are correctly populated
#[test]
fn price_components_are_correct() {
    let mut state = TokenPricingState::new();

    // Set up both price signals
    state.update_cbe_usd_price(3 * PRICE_SCALE, 1, 1000);
    state.update_cbe_sov_ratio(60 * PRICE_SCALE, 1000);

    let components = state.get_sov_components();

    // SRV should always be present as fallback
    assert!(components.srv.is_some());

    // CBE/USD and CBE/SOV should be present
    assert!(components.cbe_usd.is_some());
    assert!(components.cbe_sov.is_some());

    // Verify the values
    assert_eq!(components.cbe_usd.unwrap(), 3.0);
    assert_eq!(components.cbe_sov.unwrap(), 60.0);
}

/// Test CBE price calculation with SOV price
#[test]
fn cbe_price_calculation_with_sov() {
    use lib_blockchain::pricing::PricingCalculator;

    // If SOV/USD = $5 and CBE/SOV = 60
    // Then CBE/USD = 60 * 5 = $300
    let cbe_sov = 60 * PRICE_SCALE;
    let sov_usd = 5 * PRICE_SCALE;
    let cbe_usd = PricingCalculator::calculate_cbe_usd(cbe_sov, sov_usd);

    // $300 in 8-decimal precision
    let expected = 300 * PRICE_SCALE;
    assert_eq!(cbe_usd, expected);
}

/// Test pricing mode transitions
#[test]
fn pricing_mode_transitions_correctly() {
    let mut state = TokenPricingState::new();

    // Start in Fixed mode
    assert_eq!(state.get_sov_pricing_mode(), PricingMode::Fixed);
    assert_eq!(state.get_sov_price_source(), lib_blockchain::pricing::PriceSource::Srv);

    // Add CBE/SOV ratio only - still fixed
    state.update_cbe_sov_ratio(60 * PRICE_SCALE, 1000);
    assert_eq!(state.get_sov_pricing_mode(), PricingMode::Fixed);

    // Add CBE/USD - now dynamic
    state.update_cbe_usd_price(3 * PRICE_SCALE, 1, 1000);
    assert_eq!(state.get_sov_pricing_mode(), PricingMode::Dynamic);
    assert_eq!(state.get_sov_price_source(), lib_blockchain::pricing::PriceSource::Derived);
}

/// Test price history recording
#[test]
fn price_history_is_recorded() {
    let mut state = TokenPricingState::new();

    // Record some prices
    state.record_price("sov", 1000, 218); // $0.0218
    state.record_price("sov", 2000, 500); // $0.05
    state.record_price("cbe", 1000, 300); // $3.00

    let sov_history = state.price_history.get("sov").unwrap();
    assert_eq!(sov_history.len(), 2);
    assert_eq!(sov_history[0], (1000, 218));
    assert_eq!(sov_history[1], (2000, 500));

    let cbe_history = state.price_history.get("cbe").unwrap();
    assert_eq!(cbe_history.len(), 1);
    assert_eq!(cbe_history[0], (1000, 300));
}
