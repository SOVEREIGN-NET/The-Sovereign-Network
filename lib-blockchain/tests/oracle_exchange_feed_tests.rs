//! Oracle Exchange Feed Integration Tests
//!
//! Tests the integration between exchange state and oracle price feeds
//! per Oracle Spec v1 §5.

use lib_blockchain::{
    exchange::{ExchangeState, LastTradePrice, TradingPair},
    ORACLE_PRICE_SCALE,
};

/// ORACLE-3: Verify 3 independent on-chain price sources are available.
#[test]
fn exchange_provides_three_independent_price_sources() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();
    let now = 10000u64;

    // Setup: seed all 3 price sources
    // 1. Last trade
    exchange.record_trade(&pair, 105_000_000, 1_000_000, now - 60);

    // 2. Order book
    exchange.update_bid(&pair, 104_000_000, 5_000_000);
    exchange.update_ask(&pair, 106_000_000, 5_000_000);

    // 3. VWAP history (record trades over the last hour)
    for i in 0..10 {
        let price = 100_000_000 + i * 1_000_000; // $1.00 to $1.09
        exchange.record_trade(&pair, price, 100_000, now - 3000 + i as u64 * 600);
    }

    // Verify all 3 sources are available
    let last_trade = exchange.last_trade_price_sov_usdc();
    assert!(last_trade.is_some(), "last_trade should be available");

    let mid = exchange.order_book_mid_sov_usdc();
    assert!(mid.is_some(), "order_book_mid should be available");

    let vwap = exchange.vwap_sov_usdc(now - 3600, now);
    assert!(vwap.is_some(), "vwap should be available");

    // All 3 sources should be independent (different calculation methods)
    let last_trade_price = last_trade.ok_or("Automatic Remediation")?.price_atomic;
    let mid_price = mid.ok_or("Automatic Remediation")?;
    let vwap_price = vwap.ok_or("Automatic Remediation")?;

    // They should generally be close but can differ slightly
    // Verify they're all in reasonable ranges ($0.50 - $2.00 at 1e8 scale)
    let min_price = 50_000_000u128;
    let max_price = 200_000_000u128;

    assert!(
        last_trade_price >= min_price && last_trade_price <= max_price,
        "last_trade price should be in reasonable range"
    );
    assert!(
        mid_price >= min_price && mid_price <= max_price,
        "order_book_mid price should be in reasonable range"
    );
    assert!(
        vwap_price >= min_price && vwap_price <= max_price,
        "vwap price should be in reasonable range"
    );
}

/// ORACLE-3: Verify prices use ORACLE_PRICE_SCALE (1e8) fixed-point.
#[test]
fn exchange_prices_use_oracle_scale() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();

    // Record a trade at exactly $1.50 = 150_000_000 at 1e8 scale
    let price_150 = 150_000_000u128;
    exchange.record_trade(&pair, price_150, 1_000_000, 1000);

    let last_trade = exchange.last_trade_price_sov_usdc().ok_or("Automatic Remediation")?;
    assert_eq!(last_trade.price_atomic, price_150);
    assert_eq!(last_trade.price_atomic, 150 * ORACLE_PRICE_SCALE / 100);
}

/// ORACLE-3: Verify order book mid price calculation.
#[test]
fn order_book_mid_is_average_of_best_bid_and_ask() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();

    // Best bid: $0.99 (99_000_000), Best ask: $1.01 (101_000_000)
    // Mid should be $1.00 (100_000_000)
    exchange.update_bid(&pair, 99_000_000, 1_000_000);
    exchange.update_ask(&pair, 101_000_000, 1_000_000);

    let mid = exchange.order_book_mid_sov_usdc().ok_or("Automatic Remediation")?;
    assert_eq!(mid, 100_000_000); // ($0.99 + $1.01) / 2 = $1.00
}

/// ORACLE-3: Verify VWAP calculation over time window.
#[test]
fn vwap_is_volume_weighted_average() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();
    let now = 10000u64;

    // Trade 1: 10 SOV at $1.00
    exchange.record_trade(&pair, 100_000_000, 10_000_000, now - 1800);
    // Trade 2: 20 SOV at $1.10
    exchange.record_trade(&pair, 110_000_000, 20_000_000, now - 1200);
    // Trade 3: 30 SOV at $1.20
    exchange.record_trade(&pair, 120_000_000, 30_000_000, now - 600);

    // VWAP = (10*1.00 + 20*1.10 + 30*1.20) / (10+20+30) = 68/60 = $1.1333...
    let vwap = exchange.vwap_sov_usdc(now - 3600, now).ok_or("Automatic Remediation")?;

    // Expected: 68,000,000 / 60 = 1,133,333.33... (at 1e8 scale)
    let expected =
        (100_000_000u128 * 10_000_000 + 110_000_000 * 20_000_000 + 120_000_000 * 30_000_000)
            / (10_000_000 + 20_000_000 + 30_000_000);

    assert_eq!(vwap, expected);
    // Should be approximately $1.133
    assert!(vwap > 113_000_000 && vwap < 114_000_000);
}

/// ORACLE-3: Verify VWAP returns None when no trades in window.
#[test]
fn vwap_returns_none_for_empty_window() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();

    // Record a trade at t=1000
    exchange.record_trade(&pair, 100_000_000, 1_000_000, 1000);

    // Query VWAP for a window that doesn't include the trade
    let vwap = exchange.vwap_sov_usdc(2000, 3000);
    assert!(
        vwap.is_none(),
        "vwap should be None when no trades in window"
    );
}

/// ORACLE-3: Verify last trade returns most recent trade.
#[test]
fn last_trade_returns_most_recent() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();

    // Record older trade
    exchange.record_trade(&pair, 100_000_000, 1_000_000, 1000);

    // Record newer trade at higher price
    exchange.record_trade(&pair, 110_000_000, 2_000_000, 2000);

    let last_trade = exchange.last_trade_price_sov_usdc().ok_or("Automatic Remediation")?;
    assert_eq!(last_trade.price_atomic, 110_000_000);
    assert_eq!(last_trade.timestamp, 2000);
}

/// ORACLE-3: Verify order book returns None when one side is missing.
#[test]
fn order_book_mid_requires_both_sides() {
    let mut exchange = ExchangeState::new();
    let pair = TradingPair::sov_usdc();

    // Only bids
    exchange.update_bid(&pair, 99_000_000, 1_000_000);
    assert!(exchange.order_book_mid_sov_usdc().is_none());

    // Clear and add only asks
    exchange = ExchangeState::new();
    exchange.update_ask(&pair, 101_000_000, 1_000_000);
    assert!(exchange.order_book_mid_sov_usdc().is_none());

    // Now both sides
    exchange.update_bid(&pair, 99_000_000, 1_000_000);
    assert!(exchange.order_book_mid_sov_usdc().is_some());
}

/// ORACLE-3: Verify trading pair equality and SOV/USDC helper.
#[test]
fn trading_pair_helpers_work() {
    let sov_usdc_1 = TradingPair::sov_usdc();
    let sov_usdc_2 = TradingPair::new("SOV", "USDC");
    let usdc_sov = TradingPair::new("USDC", "SOV");

    assert_eq!(sov_usdc_1, sov_usdc_2);
    assert_ne!(sov_usdc_1, usdc_sov);
    assert_eq!(sov_usdc_1.base, "SOV");
    assert_eq!(sov_usdc_1.quote, "USDC");
}

/// ORACLE-3: Verify LastTradePrice struct fields.
#[test]
fn last_trade_price_structure() {
    let price = LastTradePrice {
        price_atomic: 150_000_000,
        timestamp: 1234567890,
    };

    assert_eq!(price.price_atomic, 150_000_000);
    assert_eq!(price.timestamp, 1234567890);
}
