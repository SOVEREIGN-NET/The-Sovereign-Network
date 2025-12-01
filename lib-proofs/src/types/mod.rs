//! Core ZK proof types and structures
//! 
//! This module provides the fundamental type definitions for the ZHTP 
//! zero-knowledge proof system, including proof structures, verification
//! results, Merkle proof components, and the V1 proof envelope/registry
//! used for governed identity/governance proofs.

pub mod zk_proof;
pub mod merkle_proof;
pub mod verification_result;

// NEW: V1 proof envelope and registry
pub mod proof_envelope;

// Re-export types for convenience
pub use zk_proof::*;
pub use merkle_proof::*;
pub use verification_result::*;
pub use proof_envelope::*;
