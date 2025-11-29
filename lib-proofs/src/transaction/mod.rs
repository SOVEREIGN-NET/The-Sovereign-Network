//! Transaction ZK proofs module
//! 
//! Provides zero-knowledge proofs for blockchain transactions, including
//! balance verification, amount validation, and nullifier proofs to prevent
//! double-spending while preserving privacy.

pub mod transaction_proof;
pub mod prover;
pub mod verification;

// Re-export transaction types
pub use transaction_proof::*;
pub use prover::*;
pub use verification::*;
