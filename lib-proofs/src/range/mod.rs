//! Range proof module
//!
//! Provides zero-knowledge range proofs that allow proving a value lies
//! within a specified range without revealing the exact value.

pub mod bulletproofs;
pub mod range_proof;
pub mod verification;

// Re-export range types
pub use range_proof::*;
pub use verification::*;
