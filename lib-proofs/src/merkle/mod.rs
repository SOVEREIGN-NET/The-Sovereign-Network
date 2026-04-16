//! Merkle tree proofs module
//!
//! Provides zero-knowledge Merkle tree operations including tree construction,
//! inclusion proof generation, and verification without revealing tree structure.

pub mod poseidon_tree;
pub mod proof_generation;
pub mod tree;
pub mod verification;

// Re-export merkle types
#[cfg(feature = "real-proofs")]
pub use poseidon_tree::*;
pub use proof_generation::*;
pub use tree::*;
pub use verification::*;
