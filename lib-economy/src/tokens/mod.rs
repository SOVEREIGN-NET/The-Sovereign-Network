//! Token systems and allocation ledgers
//!
//! This module contains definitions for various token types used in the Sovereign Network economy.
//! Token modules are data-only: they define allocations and invariants but not transfer policies,
//! vesting mechanics, or market interactions.

pub mod cbe_token;

// Re-export key types
pub use cbe_token::{
    CbeAllocationLedger, CbeBucketId, CbeError, CBE_COMPENSATION_POOL, CBE_OPERATIONAL_TREASURY,
    CBE_PERFORMANCE_INCENTIVES, CBE_STRATEGIC_RESERVES, CBE_TOTAL_SUPPLY,
};
