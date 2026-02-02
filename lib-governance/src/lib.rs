//! ZHTP Governance - Deterministic Configuration Updates
//!
//! This crate provides governance transaction types for deterministic
//! configuration changes in the ZHTP blockchain.
//!
//! # Key Principles
//!
//! 1. **No immediate activation**: All changes must specify a future block height
//! 2. **Height-based only**: Time-based activation is not supported
//! 3. **Applied in executor**: Governance txs are processed like any other tx
//! 4. **Stored in chain state**: Pending changes are part of consensus state
//!
//! # Usage
//!
//! ```ignore
//! use lib_governance::{GovernanceConfigTx, ConfigField};
//!
//! let tx = GovernanceConfigTx {
//!     target: token_id,
//!     field: ConfigField::TransferFeeBps,
//!     new_value_hash: hash_of_new_value,
//!     activates_at: current_height + 1000, // Must be in future
//! };
//! ```

pub mod tx;
pub mod fields;
pub mod pending;
pub mod errors;

pub use tx::GovernanceConfigTx;
pub use fields::ConfigField;
pub use pending::{PendingChange, PendingChanges};
pub use errors::{GovernanceError, GovernanceResult};
