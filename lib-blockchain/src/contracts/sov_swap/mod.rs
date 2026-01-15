//! # SOV Swap - Minimal AMM for SOV↔DAO Token Swaps
//!
//! This module implements a minimal Automated Market Maker (AMM) for swapping
//! between SOV tokens and DAO tokens (both NP and FP). It uses the constant
//! product formula (x * y = k) for pricing.
//!
//! ## Key Features
//! - Constant product AMM (x * y = k)
//! - 1% default fee routed to treasury
//! - Governance-controlled fee adjustment
//! - NP↔FP swap blocking (SOV must be intermediary)
//! - Event emission for all operations
//!
//! ## Security Invariants
//!
//! ### Invariant S1: Reserve Conservation
//! After any swap: `sov_reserve * token_reserve >= k` (accounting for fees)
//! The product may increase due to fees but never decrease.
//!
//! ### Invariant S2: SOV Intermediary Requirement
//! Direct NP↔FP swaps are blocked. Users must:
//! 1. Swap NP → SOV
//! 2. Swap SOV → FP (or vice versa)
//!
//! ### Invariant S3: Fee Immutability by Non-Governance
//! Only the governance address can modify fee parameters.
//!
//! ### Invariant S4: Pool Initialization Atomicity
//! A pool is either fully initialized or not at all.
//! Partial initialization states are impossible.

pub mod core;

// Re-export core types
pub use core::{PoolState, SovSwapPool, SwapDirection, SwapError, SwapResult};

/// Gas cost for swap operations
pub const GAS_SWAP: u64 = 5000;

/// Gas cost for pool initialization
pub const GAS_INIT_POOL: u64 = 10000;

/// Gas cost for fee updates
pub const GAS_SET_FEE: u64 = 2000;

/// Default fee in basis points (1% = 100 bps)
pub const DEFAULT_FEE_BPS: u16 = 100;

/// Maximum fee in basis points (10% = 1000 bps)
pub const MAX_FEE_BPS: u16 = 1000;

/// Minimum liquidity to prevent division by zero attacks
pub const MINIMUM_LIQUIDITY: u64 = 1000;

/// Domain separator for pool ID derivation
pub const POOL_ID_DOMAIN: &[u8] = b"SOV_SWAP_POOL_V1";
