//! Transaction ZK proofs module
//!
//! Provides zero-knowledge proofs for blockchain transactions, including
//! balance verification, amount validation, and nullifier proofs to prevent
//! double-spending while preserving privacy.

pub mod circuit;
pub mod prover;
pub mod transaction_proof;
pub mod verification;

// Re-export transaction types
pub use prover::*;
pub use transaction_proof::*;
pub use verification::*;
