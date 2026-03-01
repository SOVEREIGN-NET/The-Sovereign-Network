//! ZHTP Fee Model
//!
//! Pure, deterministic fee computation for the ZHTP blockchain.
//!
//! # Design Principles
//!
//! 1. **Pure functions** - No side effects, no global state
//! 2. **Deterministic** - Same inputs produce identical outputs across all platforms
//! 3. **No floats** - All arithmetic uses u64/u128 integers
//! 4. **Overflow-safe** - Uses checked/saturating arithmetic
//!
//! # Type Architecture
//!
//! Pure data types (`TxKind`, `SigScheme`, `FeeInput`, `FeeParams`, `FeeDeficit`)
//! are defined in `lib-types::fees` and re-exported here for convenience.
//!
//! # Usage
//!
//! ```ignore
//! use lib_fees::{compute_fee_v2, FeeInput, FeeParams, TxKind, SigScheme};
//!
//! let input = FeeInput {
//!     kind: TxKind::NativeTransfer,
//!     sig_scheme: SigScheme::Ed25519,
//!     sig_count: 1,
//!     envelope_bytes: 200,
//!     payload_bytes: 32,
//!     witness_bytes: 64,
//!     exec_units: 0,
//!     state_reads: 2,
//!     state_writes: 2,
//!     state_write_bytes: 64,
//! };
//!
//! let params = FeeParams::default();
//! let fee = compute_fee_v2(&input, &params);
//! ```

pub mod model_v2;

#[cfg(test)]
mod golden_vectors;

// Re-export pure data types from lib-types (canonical location)
pub use lib_types::fees::{FeeDeficit, FeeInput, FeeParams, SigScheme, TxKind};

// Re-export computation functions and logic from model_v2
pub use model_v2::{compute_fee_v2, verify_fee};
