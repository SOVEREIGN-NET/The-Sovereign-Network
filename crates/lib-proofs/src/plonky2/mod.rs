//! Plonky2 integration module
//! 
//! Provides high-performance recursive SNARK implementations using Plonky2
//! for complex zero-knowledge computations and verification.

pub mod proof_system;
pub mod recursive;
pub mod verification;

// Re-export main types from the actual implementations
pub use proof_system::{
    ZkProofSystem, Plonky2Proof, ZkProofStats,
    CircuitBuilder, CircuitConfig, ZkCircuit, CircuitGate, CircuitConstraint
};
pub use verification::{CircuitStats, Plonky2Verifier, VerificationContext, verify_plonky2_proof};
pub use recursive::{RecursiveProof, RecursiveConfig, RecursiveProofBuilder, RecursiveVerifier,
    generate_batch_recursive_proof, verify_batch_recursive_proof};
