//! UBI and reward distribution mechanics module
//!
//! Handles the calculation and distribution of Universal Basic Income
//! and welfare services based on DAO treasury allocations.

pub mod automated_payouts;
pub mod reward_distribution;
pub mod ubi_calculation;
pub mod ubi_distribution;
pub mod welfare_funding;

pub use automated_payouts::*;
pub use reward_distribution::*;
pub use ubi_calculation::*;
pub use ubi_distribution::*;
pub use welfare_funding::*;
