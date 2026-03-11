//! Exchange State
//!
//! Manages on-chain order book state and provides price feeds for oracle.

use serde::{Deserialize, Serialize};

/// A trading pair identifier (e.g., "SOV/USDC").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TradingPair {
    pub base: String,  // e.g., "SOV"
    pub quote: String, // e.g., "USDC"
}

impl TradingPair {
    /// Create a new trading pair.
    pub fn new(base: impl Into<String>, quote: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            quote: quote.into(),
        }
    }

    /// The canonical SOV/USDC pair.
    pub fn sov_usdc() -> Self {
        Self::new("SOV", "USDC")
    }

    /// The CBE/USD on-ramp pair.
    ///
    /// Populated by on-ramp gateway transactions where users buy CBE with USD/stablecoin.
    /// Used by the oracle for Mode B SOV/USD derivation:
    ///   P_SOV/USD = P_CBE/USD_onramp_vwap / P_CBE/SOV_curve
    pub fn cbe_usd() -> Self {
        Self::new("CBE", "USD")
    }
}

/// Last trade price information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastTradePrice {
    /// Price in atomic ORACLE_PRICE_SCALE (1e8) units.
    pub price_atomic: u128,
    /// Unix timestamp of the trade.
    pub timestamp: u64,
}

/// Exchange state for on-chain order book.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeState {
    /// Last trade prices by trading pair.
    last_trade_prices: std::collections::HashMap<TradingPair, LastTradePrice>,
    /// Order book bids (price level -> total volume) by pair.
    /// Prices are stored in atomic units.
    order_book_bids: std::collections::HashMap<TradingPair, std::collections::BTreeMap<u128, u128>>,
    /// Order book asks (price level -> total volume) by pair.
    /// Prices are stored in atomic units.
    order_book_asks: std::collections::HashMap<TradingPair, std::collections::BTreeMap<u128, u128>>,
    /// Trade history for VWAP calculation: (timestamp, price, volume).
    /// Limited to recent trades to prevent unbounded growth.
    trade_history: std::collections::HashMap<TradingPair, Vec<(u64, u128, u128)>>,
}

impl ExchangeState {
    /// Create a new empty exchange state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a trade and update last trade price and trade history.
    pub fn record_trade(
        &mut self,
        pair: &TradingPair,
        price_atomic: u128,
        volume: u128,
        timestamp: u64,
    ) {
        // Update last trade price
        self.last_trade_prices.insert(
            pair.clone(),
            LastTradePrice {
                price_atomic,
                timestamp,
            },
        );

        // Add to trade history
        let history = self.trade_history.entry(pair.clone()).or_default();
        history.push((timestamp, price_atomic, volume));

        // Prune old trades (keep last 1000 per pair)
        const MAX_TRADE_HISTORY: usize = 1000;
        if history.len() > MAX_TRADE_HISTORY {
            *history = history.split_off(history.len() - MAX_TRADE_HISTORY);
        }
    }

    /// Update order book bid at a price level.
    /// Set volume to 0 to remove the level.
    pub fn update_bid(&mut self, pair: &TradingPair, price_atomic: u128, volume: u128) {
        let bids = self.order_book_bids.entry(pair.clone()).or_default();
        if volume == 0 {
            bids.remove(&price_atomic);
        } else {
            bids.insert(price_atomic, volume);
        }
    }

    /// Update order book ask at a price level.
    /// Set volume to 0 to remove the level.
    pub fn update_ask(&mut self, pair: &TradingPair, price_atomic: u128, volume: u128) {
        let asks = self.order_book_asks.entry(pair.clone()).or_default();
        if volume == 0 {
            asks.remove(&price_atomic);
        } else {
            asks.insert(price_atomic, volume);
        }
    }

    // =========================================================================
    // Oracle Price Feed Methods
    // =========================================================================

    /// Price (in atomic ORACLE_PRICE_SCALE units) and timestamp of most recent
    /// SOV/USDC trade.
    ///
    /// Returns `None` if no trades have occurred.
    pub fn last_trade_price_sov_usdc(&self) -> Option<LastTradePrice> {
        self.last_trade_prices
            .get(&TradingPair::sov_usdc())
            .copied()
    }

    /// (best_bid + best_ask) / 2 for SOV/USDC, in atomic units.
    ///
    /// Returns `None` if order book is empty or one side is missing.
    pub fn order_book_mid_sov_usdc(&self) -> Option<u128> {
        let pair = TradingPair::sov_usdc();

        let bids = self.order_book_bids.get(&pair)?;
        let asks = self.order_book_asks.get(&pair)?;

        // Best bid is the highest price (max key)
        let best_bid = bids.keys().next_back().copied()?;

        // Best ask is the lowest price (min key)
        let best_ask = asks.keys().next().copied()?;

        // Calculate mid price with checked arithmetic
        let sum = best_bid.checked_add(best_ask)?;
        Some(sum / 2)
    }

    /// Last trade price for CBE/USD on-ramp transactions.
    ///
    /// Returns `None` until the first on-ramp transaction is recorded.
    pub fn last_trade_price_cbe_usd(&self) -> Option<LastTradePrice> {
        self.last_trade_prices
            .get(&TradingPair::cbe_usd())
            .copied()
    }

    /// Volume-weighted average price for CBE/USD on-ramp trades in [since_ts, until_ts].
    ///
    /// Returns `None` until on-ramp transactions are recorded.
    /// This is the primary input for oracle Mode B SOV/USD derivation.
    pub fn vwap_cbe_usd(&self, since_ts: u64, until_ts: u64) -> Option<u128> {
        let pair = TradingPair::cbe_usd();
        let history = self.trade_history.get(&pair)?;

        let mut total_volume: u128 = 0;
        let mut volume_x_price: u128 = 0;

        for (timestamp, price, volume) in history {
            if *timestamp >= since_ts && *timestamp <= until_ts {
                total_volume = total_volume.checked_add(*volume)?;
                volume_x_price = volume_x_price.checked_add(volume.checked_mul(*price)?)?;
            }
        }

        if total_volume == 0 {
            return None;
        }

        Some(volume_x_price / total_volume)
    }

    /// Volume-weighted average price for SOV/USDC trades in [since_ts, until_ts].
    ///
    /// Returns `None` if no trades in the window.
    pub fn vwap_sov_usdc(&self, since_ts: u64, until_ts: u64) -> Option<u128> {
        let pair = TradingPair::sov_usdc();
        let history = self.trade_history.get(&pair)?;

        let mut total_volume: u128 = 0;
        let mut volume_x_price: u128 = 0;

        for (timestamp, price, volume) in history {
            if *timestamp >= since_ts && *timestamp <= until_ts {
                total_volume = total_volume.checked_add(*volume)?;
                volume_x_price = volume_x_price.checked_add(volume.checked_mul(*price)?)?;
            }
        }

        if total_volume == 0 {
            return None;
        }

        Some(volume_x_price / total_volume)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_trade_price_returns_most_recent() {
        let mut state = ExchangeState::new();
        let pair = TradingPair::sov_usdc();

        // No trades yet
        assert!(state.last_trade_price_sov_usdc().is_none());

        // Record first trade
        state.record_trade(&pair, 100_000_000, 1_000_000, 1000);
        let price1 = state.last_trade_price_sov_usdc().unwrap();
        assert_eq!(price1.price_atomic, 100_000_000);
        assert_eq!(price1.timestamp, 1000);

        // Record second trade (newer)
        state.record_trade(&pair, 105_000_000, 2_000_000, 2000);
        let price2 = state.last_trade_price_sov_usdc().unwrap();
        assert_eq!(price2.price_atomic, 105_000_000);
        assert_eq!(price2.timestamp, 2000);
    }

    #[test]
    fn order_book_mid_calculates_correctly() {
        let mut state = ExchangeState::new();
        let pair = TradingPair::sov_usdc();

        // Empty order book
        assert!(state.order_book_mid_sov_usdc().is_none());

        // Only bids
        state.update_bid(&pair, 99_000_000, 1_000_000);
        assert!(state.order_book_mid_sov_usdc().is_none());

        // Only asks
        state.update_ask(&pair, 101_000_000, 1_000_000);
        state.order_book_bids.clear(); // Clear bids
        assert!(state.order_book_mid_sov_usdc().is_none());

        // Both sides
        state.update_bid(&pair, 99_000_000, 1_000_000);
        let mid = state.order_book_mid_sov_usdc().unwrap();
        assert_eq!(mid, 100_000_000); // (99M + 101M) / 2
    }

    #[test]
    fn vwap_calculates_correctly() {
        let mut state = ExchangeState::new();
        let pair = TradingPair::sov_usdc();

        // No trades
        assert!(state.vwap_sov_usdc(0, 10000).is_none());

        // Record trades
        // Trade 1: price=100, vol=10 at t=100
        state.record_trade(&pair, 100_000_000, 10_000_000, 100);
        // Trade 2: price=110, vol=20 at t=200
        state.record_trade(&pair, 110_000_000, 20_000_000, 200);
        // Trade 3: price=120, vol=30 at t=300
        state.record_trade(&pair, 120_000_000, 30_000_000, 300);

        // VWAP for all trades: (100*10 + 110*20 + 120*30) / (10+20+30) = 6800/60 = 113.33...
        let vwap_all = state.vwap_sov_usdc(0, 10000).unwrap();
        let expected =
            (100_000_000u128 * 10_000_000 + 110_000_000 * 20_000_000 + 120_000_000 * 30_000_000)
                / (10_000_000 + 20_000_000 + 30_000_000);
        assert_eq!(vwap_all, expected);

        // VWAP for first two trades only
        let vwap_first_two = state.vwap_sov_usdc(0, 200).unwrap();
        let expected_first_two =
            (100_000_000u128 * 10_000_000 + 110_000_000 * 20_000_000) / (10_000_000 + 20_000_000);
        assert_eq!(vwap_first_two, expected_first_two);

        // VWAP for no trades in window
        assert!(state.vwap_sov_usdc(10000, 20000).is_none());
    }

    #[test]
    fn trading_pair_equality() {
        let pair1 = TradingPair::new("SOV", "USDC");
        let pair2 = TradingPair::new("SOV", "USDC");
        let pair3 = TradingPair::new("USDC", "SOV");

        assert_eq!(pair1, pair2);
        assert_ne!(pair1, pair3);
    }
}
