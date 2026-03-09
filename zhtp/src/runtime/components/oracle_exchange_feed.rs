//! Exchange Price Feed Service for Oracle Protocol
//!
//! Implements §5 of Oracle Spec v1: Sourcing price data from 3 independent
//! on-chain exchange sources:
//! 1. Last trade price
//! 2. Order book mid price
//! 3. VWAP (Volume-Weighted Average Price)
//!
//! All prices are returned in ORACLE_PRICE_SCALE (1e8) atomic units.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Price source identifier for logging and attestation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriceSource {
    LastTrade,
    OrderBookMid,
    Vwap,
}

impl PriceSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PriceSource::LastTrade => "last_trade",
            PriceSource::OrderBookMid => "order_book_mid",
            PriceSource::Vwap => "vwap",
        }
    }
}

/// A price sample from an on-chain source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceSample {
    /// Price in atomic ORACLE_PRICE_SCALE units.
    pub price_atomic: u128,
    /// Unix timestamp when the price was sampled.
    pub timestamp: u64,
    /// Source of the price.
    pub source: PriceSource,
}

/// Exchange price feed service for oracle protocol.
///
/// This service queries the on-chain exchange state to gather price data
/// from 3 independent sources as required by Oracle Spec v1 §5.
pub struct ExchangePriceFeed;

impl ExchangePriceFeed {
    /// Creates a new exchange price feed service.
    pub fn new() -> Self {
        Self
    }

    /// Gather prices from 3 independent on-chain sources.
    ///
    /// Returns up to 3 price samples:
    /// - Last trade price (if available)
    /// - Order book mid price (if available)
    /// - VWAP over the last N seconds (if available)
    ///
    /// Prices are in atomic ORACLE_PRICE_SCALE (1e8) units.
    pub async fn gather_prices(
        &self,
        blockchain: Arc<RwLock<lib_blockchain::blockchain::Blockchain>>,
        current_timestamp: u64,
    ) -> Vec<PriceSample> {
        let mut samples = Vec::with_capacity(3);
        let bc = blockchain.read().await;

        // Source 1: Last trade price
        if let Some(last_trade) = bc.exchange_state.last_trade_price_sov_usdc() {
            debug!(
                price = last_trade.price_atomic,
                timestamp = last_trade.timestamp,
                "ExchangePriceFeed: last_trade price"
            );
            samples.push(PriceSample {
                price_atomic: last_trade.price_atomic,
                timestamp: last_trade.timestamp,
                source: PriceSource::LastTrade,
            });
        } else {
            warn!("ExchangePriceFeed: last_trade price unavailable");
        }

        // Source 2: Order book mid price
        if let Some(mid_price) = bc.exchange_state.order_book_mid_sov_usdc() {
            debug!(price = mid_price, "ExchangePriceFeed: order_book_mid price");
            samples.push(PriceSample {
                price_atomic: mid_price,
                timestamp: current_timestamp,
                source: PriceSource::OrderBookMid,
            });
        } else {
            warn!("ExchangePriceFeed: order_book_mid price unavailable");
        }

        // Source 3: VWAP over the last 1 hour (3600 seconds)
        // This provides a smoothed price that is resistant to short-term manipulation
        const VWAP_WINDOW_SECS: u64 = 3600;
        let vwap_since = current_timestamp.saturating_sub(VWAP_WINDOW_SECS);

        if let Some(vwap) = bc
            .exchange_state
            .vwap_sov_usdc(vwap_since, current_timestamp)
        {
            debug!(
                price = vwap,
                window_secs = VWAP_WINDOW_SECS,
                "ExchangePriceFeed: vwap price"
            );
            samples.push(PriceSample {
                price_atomic: vwap,
                timestamp: current_timestamp,
                source: PriceSource::Vwap,
            });
        } else {
            warn!("ExchangePriceFeed: vwap price unavailable (no trades in window)");
        }

        samples
    }

    /// Calculate the median price from multiple samples.
    ///
    /// Returns `None` if no samples are available.
    pub fn median_price(samples: &[PriceSample]) -> Option<u128> {
        if samples.is_empty() {
            return None;
        }

        let mut prices: Vec<u128> = samples.iter().map(|s| s.price_atomic).collect();
        prices.sort();

        let mid = prices.len() / 2;
        if prices.len() % 2 == 0 {
            // Even number of samples: average the two middle values
            let sum = prices[mid - 1].checked_add(prices[mid])?;
            Some(sum / 2)
        } else {
            // Odd number of samples: take the middle value
            Some(prices[mid])
        }
    }

    /// Validate that a price is within reasonable bounds.
    ///
    /// This is a sanity check to prevent obviously invalid prices from
    /// being included in attestations.
    pub fn is_price_valid(price_atomic: u128) -> bool {
        // Minimum price: $0.00000001 (1e-8 USD)
        const MIN_PRICE_ATOMIC: u128 = 1;

        // Maximum price: $1,000,000.00 (1e6 USD)
        // At 1e8 scale, this is 1e14
        const MAX_PRICE_ATOMIC: u128 = 100_0000_0000_0000u128; // $1M * 1e8

        price_atomic >= MIN_PRICE_ATOMIC && price_atomic <= MAX_PRICE_ATOMIC
    }
}

impl Default for ExchangePriceFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_price_calculates_correctly() {
        // Odd number of samples
        let samples = vec![
            PriceSample {
                price_atomic: 100_000_000,
                timestamp: 1000,
                source: PriceSource::LastTrade,
            },
            PriceSample {
                price_atomic: 110_000_000,
                timestamp: 1001,
                source: PriceSource::OrderBookMid,
            },
            PriceSample {
                price_atomic: 120_000_000,
                timestamp: 1002,
                source: PriceSource::Vwap,
            },
        ];
        assert_eq!(ExchangePriceFeed::median_price(&samples), Some(110_000_000));

        // Even number of samples
        let samples = vec![
            PriceSample {
                price_atomic: 100_000_000,
                timestamp: 1000,
                source: PriceSource::LastTrade,
            },
            PriceSample {
                price_atomic: 120_000_000,
                timestamp: 1001,
                source: PriceSource::OrderBookMid,
            },
        ];
        // Median of 100M and 120M = (100M + 120M) / 2 = 110M
        assert_eq!(ExchangePriceFeed::median_price(&samples), Some(110_000_000));

        // Empty samples
        let empty: Vec<PriceSample> = vec![];
        assert_eq!(ExchangePriceFeed::median_price(&empty), None);
    }

    #[test]
    fn price_validation_sanity_checks() {
        // Valid prices
        assert!(ExchangePriceFeed::is_price_valid(1)); // Minimum valid
        assert!(ExchangePriceFeed::is_price_valid(100_000_000)); // $1.00
        assert!(ExchangePriceFeed::is_price_valid(100_0000_0000_0000u128)); // $1M maximum

        // Invalid prices
        assert!(!ExchangePriceFeed::is_price_valid(0)); // Too low
        assert!(!ExchangePriceFeed::is_price_valid(100_0001_0000_0000u128)); // Too high (> $1M)
    }

    #[test]
    fn price_source_as_str() {
        assert_eq!(PriceSource::LastTrade.as_str(), "last_trade");
        assert_eq!(PriceSource::OrderBookMid.as_str(), "order_book_mid");
        assert_eq!(PriceSource::Vwap.as_str(), "vwap");
    }
}
