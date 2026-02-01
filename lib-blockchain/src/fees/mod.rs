//! Fee Model v2 Module
//!
//! Deterministic fee calculation for Phase 2 block execution.
//!
//! # Overview
//!
//! Fee Model v2 computes minimum transaction fees based on:
//! - Transaction kind (NativeTransfer, TokenTransfer, etc.)
//! - Signature scheme (Ed25519, Dilithium5, Hybrid)
//! - Resource usage (bytes, state operations)
//!
//! # Usage
//!
//! ```ignore
//! use lib_blockchain::fees::{FeeInput, FeeParamsV2, TxKind, SigScheme, compute_fee_v2};
//!
//! let params = FeeParamsV2::default();
//! let input = FeeInput::new(
//!     TxKind::NativeTransfer,
//!     SigScheme::Ed25519,
//!     1,     // sig_count
//!     50,    // envelope_bytes
//!     200,   // payload_bytes
//!     64,    // witness_bytes
//!     2,     // state_reads
//!     4,     // state_writes
//!     256,   // state_write_bytes
//! );
//!
//! let min_fee = compute_fee_v2(&input, &params);
//! ```
//!
//! # Design Principles
//!
//! 1. **Determinism**: Same input always produces same output
//! 2. **Purity**: No side effects, no global state access
//! 3. **Overflow safety**: Uses u128 internally for all arithmetic

pub mod types;
pub mod model_v2;
pub mod classifiers;

// Re-exports for convenience
pub use types::{
    FeeInput,
    FeeParamsV2,
    SigScheme,
    TxKind,
};

pub use model_v2::{
    compute_fee_v2,
    validate_block_limits,
};

pub use classifiers::{
    classify_transaction,
    classify_transfer,
    classify_token_transfer,
    classify_coinbase,
};
