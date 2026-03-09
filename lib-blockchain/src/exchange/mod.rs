//! Sovereign Network Exchange Module
//!
//! On-chain order book exchange for SOV/USDC and other trading pairs.
//! This module provides the exchange state and price feeds for the oracle.

pub mod state;

pub use state::{ExchangeState, LastTradePrice, TradingPair};
