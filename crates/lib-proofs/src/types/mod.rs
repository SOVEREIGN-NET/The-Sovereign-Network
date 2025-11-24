//! Core ZK proof types and structures
//! 
//! This module provides the fundamental type definitions for the ZHTP 
//! zero-knowledge proof system, including proof structures, verification
//! results, and Merkle proof components.

pub mod zk_proof;
pub mod merkle_proof;
pub mod verification_result;

// Re-export types for convenience
pub use zk_proof::*;
pub use merkle_proof::*;
pub use verification_result::*;
