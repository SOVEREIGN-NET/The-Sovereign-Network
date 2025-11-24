//! Merkle tree proofs module
//! 
//! Provides zero-knowledge Merkle tree operations including tree construction,
//! inclusion proof generation, and verification without revealing tree structure.

pub mod tree;
pub mod proof_generation;
pub mod verification;

// Re-export merkle types
pub use tree::*;
pub use proof_generation::*;
pub use verification::*;
