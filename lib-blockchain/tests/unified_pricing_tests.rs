//! Issue #1852: Updated Integration Tests for Simplified Pricing System
//!
//! Refactored from Issue #1819 to make bonding curve PRIMARY and oracle SECONDARY.
//!
//! Key Principle:
//! > "reliance on internal mechanisms rather than external oracles for price discovery"
//!
//! Architecture:
//! ```
//! Bonding Curve (CBE/SOV) → Market Price → Oracle Observes
//! Bonding Curve = PRIMARY price source
//! Oracle = SECONDARY observer
//! ```

use lib_blockchain::pricing::{PricingPhase, TokenPricingState, GENESIS_SRV_8DEC, PRICE_SCALE};

/// Issue #1852: Test that TokenPricingState initializes with correct defaults
#[test]
fn token_pricing_state_initializes_correctly() {
    let state = TokenPricingState::new();

    // Issue #1852: No dynamic pricing, bonding curve is PRIMARY
    assert!(state.observed_curve_price.is_none());
    assert_eq!(state.phase, PricingPhase::Curve);
    assert!(!state.dynamic_pricing_active); // Always false now
    assert_eq!(state.last_sov_price_8dec, GENESIS_SRV_8DEC as u128);
}

/// Issue #1852: Test curve price observation (bonding curve is PRIMARY)
#[test]
fn curve_price_observation_works() {
    let mut state = TokenPricingState::new();

    // Initially no observed price
    assert!(state.observed_curve_price.is_none());
    assert_eq!(state.get_phase(), PricingPhase::Curve);

    // Observe price from bonding curve (NOT from oracle)
    let curve_price = 31_334_570u128; // ~0.000313 SOV per CBE
    state.observe_curve_price(curve_price, 1000);

    // Price is now observed
    assert_eq!(state.observed_curve_price, Some(curve_price));
    assert_eq!(state.get_observed_price(), Some(curve_price));
}

/// Issue #1852: Test phase transition to AMM
#[test]
fn phase_transition_to_amm() {
    let mut state = TokenPricingState::new();

    assert_eq!(state.get_phase(), PricingPhase::Curve);

    // Transition to AMM phase (post-graduation)
    state.transition_to_amm(2000);

    assert_eq!(state.get_phase(), PricingPhase::AMM);
}

/// Issue #1852: Test CBE/USD calculation (CBE/SOV × SOV/USD)
#[test]
fn cbe_usd_calculation_is_correct() {
    use lib_blockchain::pricing::PricingCalculator;

    // CBE/SOV = 0.000313, SOV/USD = $0.0218
    // CBE/USD = 0.000313 * 0.0218 = $0.00000682
    let cbe_sov = 31_334_570u128; // 0.0003133457 SOV per CBE
    let sov_usd = 2_180_000u128; // $0.0218 SOV/USD

    let cbe_usd = PricingCalculator::calculate_cbe_usd(cbe_sov, sov_usd);

    // Verify calculation: (31,334,570 * 2,180,000) / 100,000,000
    let expected = (cbe_sov * sov_usd) / PRICE_SCALE;
    assert_eq!(cbe_usd, expected);
}

/// Issue #1852: Test price conversions
#[test]
fn price_conversions_work() {
    use lib_blockchain::pricing::PricingCalculator;

    // price_usd_cents uses 4-decimal units: 1 unit = $0.0001
    // Example: $0.0218 → 218 units (0.0218 * 10_000 = 218)
    // 8-decimal representation: 0.0218 * 100_000_000 = 2_180_000
    //
    // from_cents formula: cents * PRICE_SCALE / 10_000
    // 218 * 100_000_000 / 10_000 = 2_180_000
    let cents = 218u128; // $0.0218 in 4-decimal units (1 unit = $0.0001)
    let price_8dec = PricingCalculator::from_cents(cents);
    assert_eq!(price_8dec, 2_180_000); // 8-decimal representation of $0.0218

    // Round trip: to_cents formula: (price_8dec * 10_000) / PRICE_SCALE
    // (2_180_000 * 10_000) / 100_000_000 = 218
    let back_to_cents = PricingCalculator::to_cents(price_8dec);
    assert_eq!(back_to_cents, cents);
}

/// Issue #1852: Test price history recording
#[test]
fn price_history_recording_works() {
    let mut state = TokenPricingState::new();

    // Record some prices
    state.record_price("CBE", 1_700_000_000, 300); // $3.00
    state.record_price("CBE", 1_700_000_100, 310); // $3.10
    state.record_price("CBE", 1_700_000_200, 305); // $3.05

    let history = state.get_price_history("CBE");
    assert_eq!(history.len(), 3);
    assert_eq!(history[0], (1_700_000_000, 300));
    assert_eq!(history[2], (1_700_000_200, 305));
}

/// Issue #1852: Verify oracle is observer-only (does not set prices)
#[test]
fn oracle_is_observer_only() {
    let mut state = TokenPricingState::new();

    // Oracle can provide CBE/USD (for observation/validation)
    let cbe_usd = 3 * PRICE_SCALE; // $3.00
    state.update_cbe_usd_price(cbe_usd, 1, 1000);

    // But this does NOT affect pricing
    // - No dynamic pricing mode
    // - SOV price still from SRV
    // - Bonding curve remains PRIMARY

    assert!(!state.dynamic_pricing_active);
    assert_eq!(state.get_sov_price_8dec(), GENESIS_SRV_8DEC as u128);

    // Price observation still comes from bonding curve
    assert!(state.observed_curve_price.is_none());
}

/// Issue #1852: Test that legacy methods still work (backward compatibility)
#[test]
fn legacy_methods_backward_compatible() {
    let mut state = TokenPricingState::new();

    // These methods exist for backward compatibility but don't affect pricing
    state.update_cbe_usd_price(3 * PRICE_SCALE, 1, 1000);
    state.update_cbe_sov_ratio(60 * PRICE_SCALE, 1000);

    // Pricing is still fixed (SRV-based)
    assert_eq!(
        state.get_sov_pricing_mode(),
        lib_blockchain::pricing::PricingMode::Fixed
    );
    assert_eq!(
        state.get_sov_price_source(),
        lib_blockchain::pricing::PriceSource::Srv
    );

    // Components exist but don't include oracle-derived values
    let components = state.get_sov_components();
    assert!(components.srv.is_some());
    assert!(components.cbe_usd.is_none()); // Issue #1852: oracle is observer-only
}

/// Issue #1852: Document the architecture principle
#[test]
fn architecture_principle_documented() {
    // This test documents the core principle:
    // "reliance on internal mechanisms rather than external oracles for price discovery"
    //
    // The bonding curve IS the internal mechanism.
    // The oracle only validates graduation thresholds and provides transparency.

    println!("Issue #1852 Architecture:");
    println!("  Bonding Curve = PRIMARY price source");
    println!("  Oracle = SECONDARY observer (read-only)");
    println!("  SOV price = SRV (fixed, not derived from oracle)");
    println!("  CBE price = Bonding curve (internal mechanism)");
}
