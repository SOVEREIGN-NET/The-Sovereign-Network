//! UBI Distribution Module
//!
//! This module contains the Universal Basic Income (UBI) distribution contract
//! for the SOV economic system, enabling fair monthly distributions to registered
//! citizens.

pub mod core;
pub mod types;

// Re-export key types
pub use core::UbiDistributor;
pub use types::{MonthIndex, Error};
