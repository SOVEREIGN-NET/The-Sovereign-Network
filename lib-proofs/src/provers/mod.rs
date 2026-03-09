//! Proof generation modules
//!
//! Provides specialized provers for different types of zero-knowledge proofs
//! with optimized performance for each proof type.

pub mod identity_prover;
pub mod merkle_prover;
pub mod range_prover;
pub mod transaction_prover;

// Re-export main types
pub use identity_prover::IdentityProver;
pub use merkle_prover::MerkleProver;
pub use range_prover::RangeProver;
pub use transaction_prover::TransactionProver;
