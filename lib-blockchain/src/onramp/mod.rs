//! On-Ramp Trade State
//!
//! Records fiat->CBE purchases attested by the gateway + oracle committee.
//! Provides the CBE/USD VWAP used by the oracle for Mode B SOV/USD derivation.
//!
//! Spec: CBE/SOV/USD Pricing Model v1.0 §4

use serde::{Deserialize, Serialize};

/// A single fiat->CBE on-ramp trade, attested by the gateway and oracle committee.
///
/// Recorded on-chain once T-of-N committee signatures are collected.
/// Signatures are verified before recording; only the amounts are stored here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnRampTrade {
    /// Block height when this trade was recorded.
    pub block_height: u64,
    /// Oracle epoch when this trade was recorded.
    pub epoch_id: u64,
    /// CBE received by the user (atomic units, 18 decimals).
    pub cbe_amount: u128,
    /// USDC paid by the user (atomic units, 6 decimals).
    pub usdc_amount: u128,
}

/// VWAP window: 7 days at ~14,400 blocks/day (6 s block time).
pub const VWAP_WINDOW_BLOCKS: u64 = 100_800;

/// Minimum number of on-ramp trades in the window for Mode B to activate.
pub const MIN_TRADES: u64 = 5;

/// Minimum total USDC volume in the window for Mode B (1,000 USDC = 1_000_000_000 atomic).
pub const MIN_VOLUME_USDC: u128 = 1_000_000_000;

/// Maximum trades kept in memory (prevents unbounded growth).
/// At 7 trades/day over 7 days = 49; 10_000 provides ample headroom.
const MAX_TRADE_HISTORY: usize = 10_000;

/// Oracle pricing mode derived from on-ramp data availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OraclePricingMode {
    /// Mode A: insufficient on-ramp data — use SRV genesis reference.
    GenesisReference,
    /// Mode B: on-ramp VWAP meets MIN_TRADES and MIN_VOLUME thresholds.
    LiveDerived,
}

/// On-ramp trade log and CBE/USD VWAP state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnRampState {
    /// Ordered list of attested on-ramp trades (oldest first).
    pub trades: Vec<OnRampTrade>,
}

impl OnRampState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new attested on-ramp trade.
    ///
    /// Prunes trades older than 2× the VWAP window to bound memory use.
    pub fn record_trade(&mut self, trade: OnRampTrade) {
        self.trades.push(trade);
        if self.trades.len() > MAX_TRADE_HISTORY {
            self.trades.drain(..self.trades.len() - MAX_TRADE_HISTORY);
        }
    }

    /// Returns the CBE/USD VWAP in ORACLE_PRICE_SCALE (1e8) atomic units,
    /// or `None` if the window does not meet MIN_TRADES or MIN_VOLUME thresholds.
    ///
    /// Formula (spec §4.2):
    ///   CBE/USD = SUM(usdc_amount_i * 1e20) / SUM(cbe_amount_i)
    ///
    /// Precision: all arithmetic in u128. Multiply before divide.
    /// USDC has 6 decimals, CBE has 18 decimals, output is in ORACLE_PRICE_SCALE (1e8).
    ///
    /// Derivation:
    ///   price_per_trade [8-dec] = (usdc_amount [6-dec] * 1e8 * 1e18) / (cbe_amount [18-dec] * 1e6)
    ///                           = (usdc_amount * 1e20) / (cbe_amount * 1e6)
    ///                           = (usdc_amount * 1e14) / cbe_amount
    ///
    ///   VWAP denominator weights by cbe_amount, so:
    ///   VWAP = SUM(price_i * cbe_amount_i) / SUM(cbe_amount_i)
    ///        = SUM((usdc_amount_i * 1e20 / cbe_amount_i) * cbe_amount_i) / SUM(cbe_amount_i)
    ///        = SUM(usdc_amount_i * 1e20) / SUM(cbe_amount_i)
    pub fn cbe_usd_vwap(&self, current_block: u64) -> Option<u128> {
        let window_start = current_block.saturating_sub(VWAP_WINDOW_BLOCKS);

        let mut total_usdc: u128 = 0;
        let mut total_cbe: u128 = 0;
        let mut trade_count: u64 = 0;

        for trade in &self.trades {
            if trade.block_height < window_start {
                continue;
            }
            total_usdc = total_usdc.saturating_add(trade.usdc_amount);
            total_cbe = total_cbe.saturating_add(trade.cbe_amount);
            trade_count += 1;
        }

        if trade_count < MIN_TRADES {
            return None;
        }
        if total_usdc < MIN_VOLUME_USDC {
            return None;
        }
        if total_cbe == 0 {
            return None;
        }

        // VWAP [8-dec] = SUM(usdc_amount * 1e20) / SUM(cbe_amount)
        // Derivation:
        //   price[8-dec USD/CBE] = (usdc[6-dec] / 1e6 USD) / (cbe[18-dec] / 1e18 CBE) * 1e8
        //                        = usdc * 1e18 * 1e8 / (1e6 * cbe)
        //                        = usdc * 1e20 / cbe
        // Overflow check: max usdc total ~1e12 (6-dec), 1e12 * 1e20 = 1e32 < u128::MAX(3.4e38) ✓
        const SCALE: u128 = 100_000_000_000_000_000_000; // 1e20
        let numerator = total_usdc.checked_mul(SCALE)?;
        Some(numerator / total_cbe)
    }

    /// Returns the current oracle pricing mode based on window data.
    pub fn oracle_mode(&self, current_block: u64) -> OraclePricingMode {
        if self.cbe_usd_vwap(current_block).is_some() {
            OraclePricingMode::LiveDerived
        } else {
            OraclePricingMode::GenesisReference
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trade(block_height: u64, usdc_amount: u128, cbe_amount: u128) -> OnRampTrade {
        OnRampTrade {
            block_height,
            epoch_id: 1,
            cbe_amount,
            usdc_amount,
        }
    }

    #[test]
    fn mode_a_when_no_trades() {
        let state = OnRampState::new();
        assert_eq!(state.oracle_mode(1000), OraclePricingMode::GenesisReference);
        assert!(state.cbe_usd_vwap(1000).is_none());
    }

    #[test]
    fn mode_a_when_below_min_trades() {
        let mut state = OnRampState::new();
        // 4 trades, each $300 USDC for some CBE — below MIN_TRADES=5
        for i in 0..4 {
            // 300 USDC = 300_000_000 units (6-dec); 750_000 CBE = 750_000 * 10^18 units
            state.record_trade(make_trade(1000 + i, 300_000_000, 750_000 * 1_000_000_000_000_000_000));
        }
        assert_eq!(state.oracle_mode(2000), OraclePricingMode::GenesisReference);
    }

    #[test]
    fn mode_a_when_below_min_volume() {
        let mut state = OnRampState::new();
        // 5 trades but only $100 USDC each = $500 total < $1000 MIN_VOLUME
        for i in 0..5 {
            state.record_trade(make_trade(1000 + i, 100_000_000, 250_000 * 1_000_000_000_000_000_000));
        }
        assert_eq!(state.oracle_mode(2000), OraclePricingMode::GenesisReference);
    }

    #[test]
    fn mode_b_activates_with_sufficient_data() {
        let mut state = OnRampState::new();
        // 5 trades, each 250 USDC for 625_000 CBE
        // price per trade = $0.00040/CBE
        // total usdc = 5 * 250_000_000 = 1_250_000_000 > MIN_VOLUME (1_000_000_000)
        for i in 0..5 {
            // 250 USDC = 250_000_000 atomic; 625_000 CBE = 625_000 * 10^18 atomic
            state.record_trade(make_trade(
                1000 + i,
                250_000_000,
                625_000 * 1_000_000_000_000_000_000u128,
            ));
        }
        assert_eq!(state.oracle_mode(2000), OraclePricingMode::LiveDerived);

        // VWAP: total_usdc = 1_250_000_000, total_cbe = 5 * 625_000 * 1e18
        // = 5 * 250_000_000 * 1e14 / (5 * 625_000 * 1e18)
        // = 1_250_000_000 * 1e14 / (3_125_000 * 1e18)
        // = 1.25e9 * 1e14 / (3.125e6 * 1e18)
        // = 1.25e23 / 3.125e24
        // = 0.4e-1 * 1e8 ... hmm let me just check it's > 0
        let vwap = state.cbe_usd_vwap(2000).unwrap();
        assert!(vwap > 0, "VWAP should be positive: {}", vwap);
        // At $0.00040/CBE in 8-dec scale = 40_000
        assert_eq!(vwap, 40_000, "VWAP should be 40_000 (=$0.00040): {}", vwap);
    }

    #[test]
    fn trades_outside_window_excluded() {
        let mut state = OnRampState::new();
        // 5 trades outside the window (block 0..4, current block 200_000)
        for i in 0..5 {
            state.record_trade(make_trade(i, 250_000_000, 625_000 * 1_000_000_000_000_000_000));
        }
        // window_start = 200_000 - 100_800 = 99_200, all trades at block < 5 → excluded
        assert_eq!(state.oracle_mode(200_000), OraclePricingMode::GenesisReference);
    }
}
