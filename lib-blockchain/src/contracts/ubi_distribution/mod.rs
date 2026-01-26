//! UBI Distribution Module
//!
//! This module contains the Universal Basic Income (UBI) distribution contract
//! for the SOV economic system, enabling fair monthly distributions to registered
//! citizens.

pub mod core;
pub mod types;

#[cfg(test)]
pub mod red_tests;

// Re-export key types
pub use core::UbiDistributor;
pub use types::{
    MonthIndex, EpochIndex, Error,
    // Event schemas (Issue #844 Prep Phase)
    UbiClaimRecorded, UbiDistributed, UbiPoolStatus, UbiClaimRejected,
};
