//! Proof generation modules
//! 
//! Provides specialized provers for different types of zero-knowledge proofs
//! with optimized performance for each proof type.

pub mod transaction_prover;
pub mod identity_prover;
pub mod range_prover;
pub mod merkle_prover;

// Re-export main types
pub use transaction_prover::TransactionProver;
pub use identity_prover::IdentityProver;
pub use range_prover::RangeProver;
pub use merkle_prover::MerkleProver;
