//! Plonky2 integration module
//!
//! Provides high-performance recursive SNARK implementations using Plonky2
//! for complex zero-knowledge computations and verification.

pub mod proof_system;
pub mod recursive;
pub mod verification;

// Re-export main types from the actual implementations
pub use proof_system::{
    CircuitBuilder, CircuitConfig, CircuitConstraint, CircuitGate, Plonky2Proof, ZkCircuit,
    ZkProofStats, ZkProofSystem,
};
pub use recursive::{
    generate_batch_recursive_proof, verify_batch_recursive_proof, RecursiveConfig, RecursiveProof,
    RecursiveProofBuilder, RecursiveVerifier,
};
pub use verification::{verify_plonky2_proof, CircuitStats, Plonky2Verifier, VerificationContext};
