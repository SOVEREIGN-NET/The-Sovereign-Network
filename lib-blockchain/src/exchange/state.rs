//! Exchange State
//!
//! Generic on-chain order book infrastructure.
//! CBE/USD on-ramp trades are tracked in `crate::onramp::OnRampState`.
//!
//! Note: `TradingPair::sov_usdc()` and the associated helpers below are retained
//! for integration test coverage only. SOV/USDC does not exist as a live pair —
//! SOV/USD is always oracle-derived (Mode A/B), never order-book traded.

use serde::{Deserialize, Serialize};

/// A trading pair identifier (e.g., "SOV/USDC").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TradingPair {
    pub base: String,
    pub quote: String,
}

impl TradingPair {
    /// Create a new trading pair.
    pub fn new(base: impl Into<String>, quote: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            quote: quote.into(),
        }
    }

    pub fn sov_usdc() -> Self {
        Self::new("SOV", "USDC")
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
    order_book_bids: std::collections::HashMap<TradingPair, std::collections::BTreeMap<u128, u128>>,
    /// Order book asks (price level -> total volume) by pair.
    order_book_asks: std::collections::HashMap<TradingPair, std::collections::BTreeMap<u128, u128>>,
    /// Trade history for VWAP calculation: (timestamp, price, volume).
    trade_history: std::collections::HashMap<TradingPair, Vec<(u64, u128, u128)>>,
}

impl ExchangeState {
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
        self.last_trade_prices.insert(
            pair.clone(),
            LastTradePrice {
                price_atomic,
                timestamp,
            },
        );

        let history = self.trade_history.entry(pair.clone()).or_default();
        history.push((timestamp, price_atomic, volume));

        const MAX_TRADE_HISTORY: usize = 1000;
        if history.len() > MAX_TRADE_HISTORY {
            *history = history.split_off(history.len() - MAX_TRADE_HISTORY);
        }
    }

    /// Update order book bid at a price level. Set volume to 0 to remove the level.
    pub fn update_bid(&mut self, pair: &TradingPair, price_atomic: u128, volume: u128) {
        let bids = self.order_book_bids.entry(pair.clone()).or_default();
        if volume == 0 {
            bids.remove(&price_atomic);
        } else {
            bids.insert(price_atomic, volume);
        }
    }

    /// Update order book ask at a price level. Set volume to 0 to remove the level.
    pub fn update_ask(&mut self, pair: &TradingPair, price_atomic: u128, volume: u128) {
        let asks = self.order_book_asks.entry(pair.clone()).or_default();
        if volume == 0 {
            asks.remove(&price_atomic);
        } else {
            asks.insert(price_atomic, volume);
        }
    }

    pub fn last_trade_price_sov_usdc(&self) -> Option<LastTradePrice> {
        self.last_trade_prices.get(&TradingPair::sov_usdc()).copied()
    }

    pub fn order_book_mid_sov_usdc(&self) -> Option<u128> {
        let pair = TradingPair::sov_usdc();
        let bids = self.order_book_bids.get(&pair)?;
        let asks = self.order_book_asks.get(&pair)?;
        let best_bid = bids.keys().next_back().copied()?;
        let best_ask = asks.keys().next().copied()?;
        Some(best_bid.checked_add(best_ask)? / 2)
    }

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
    fn trading_pair_equality() {
        let pair1 = TradingPair::new("SOV", "USDC");
        let pair2 = TradingPair::new("SOV", "USDC");
        let pair3 = TradingPair::new("USDC", "SOV");

        assert_eq!(pair1, pair2);
        assert_ne!(pair1, pair3);
    }

    #[test]
    fn record_trade_stores_last_price() {
        let mut state = ExchangeState::new();
        let pair = TradingPair::new("SOV", "USDC");
        state.record_trade(&pair, 100_000_000, 1_000_000, 1000);
        let price = state.last_trade_prices.get(&pair).unwrap();
        assert_eq!(price.price_atomic, 100_000_000);
        assert_eq!(price.timestamp, 1000);
    }
}
