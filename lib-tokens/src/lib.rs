//! ZHTP Token Contract Specification v2
//!
//! This crate defines token contract primitives.
//!
//! Consensus token execution is enforced in `lib-blockchain`.
//!
//! # Key Types
//!
//! - [`TokenContract`]: The canonical token contract (spec_version = 2)
//! - [`SupplyPolicy`]: Controls minting behavior
//! - [`TransferPolicy`]: Controls transfer restrictions
//! - [`FeeSchedule`]: Transfer and burn fee configuration
//!
//! # Execution
//!
//! Use [`apply_token_transfer`] to execute transfers with full validation.

pub mod contract;
pub mod errors;
pub mod transfer;

pub use contract::*;
pub use errors::*;
pub use transfer::apply_token_transfer;
