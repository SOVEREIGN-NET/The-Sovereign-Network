//! ZHTP UTXO Execution
//!
//! This crate provides the canonical UTXO application logic for native transfers.
//!
//! # Key Rules
//!
//! 1. **Inputs must exist**: All referenced UTXOs must be present in state
//! 2. **No double spend**: Each UTXO can only be spent once
//! 3. **Outputs created before commit only**: New UTXOs are pending until block commit
//!
//! # Usage
//!
//! ```ignore
//! use lib_utxo::{apply_native_transfer, UtxoStore};
//!
//! let outcome = apply_native_transfer(&store, &tx, tx_hash, height)?;
//! ```

pub mod types;
pub mod apply;
pub mod errors;

pub use types::*;
pub use apply::apply_native_transfer;
pub use errors::{UtxoError, UtxoResult};
