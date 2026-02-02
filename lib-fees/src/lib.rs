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

pub use model_v2::*;
