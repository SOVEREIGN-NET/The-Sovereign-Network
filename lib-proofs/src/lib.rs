//! # ZHTP Zero-Knowledge Proof System - Unified Plonky2 Backend
//! 
//! Production-ready zero-knowledge proof system for ZHTP blockchain with unified Plonky2 backend:
//! - Unified Plonky2 backend for all proof types
//! - Transaction privacy and validation
//! - Identity proofs with selective disclosure
//! - Range proofs for value validation
//! - Merkle trees with ZK inclusion proofs
//! 
//! ## Features
//! 
//! - **Unified ZK System**: All proofs use the same Plonky2 backend for consistency
//! - **Transaction Proofs**: Privacy-preserving transaction validation
//! - **Identity Proofs**: Selective disclosure of identity attributes
//! - **Range Proofs**: Prove values are within ranges without revealing them
//! - **Merkle Proofs**: Zero-knowledge inclusion proofs for data structures
//! - **Plonky2 Integration**: Production-grade recursive SNARKs
//! 
//! ## Example
//! 
//! ```rust
//! use lib_proofs::{ZkProof, ZkTransactionProof, ZkRangeProof};
//! 
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! // Generate range proof using unified system
//! let range_proof = ZkRangeProof::generate(100, 0, 1000, [1u8; 32])?;
//! 
//! // All proofs can be verified using the same interface
//! let is_valid = range_proof.verify()?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use anyhow::Result;

// Re-export core types for unified ZK system
pub use types::zk_proof::ZkProof;
pub use transaction::transaction_proof::ZkTransactionProof;
pub use merkle::{tree::*, proof_generation::*, verification::*};
pub use range::range_proof::ZkRangeProof;
pub use identity::identity_proof::ZkIdentityProof;
pub use plonky2::proof_system::ZkProofSystem;

// Re-export prover and verifier modules
pub use provers::*;
pub use verifiers::*;

// Specifically re-export recursive aggregation components
pub use verifiers::{RecursiveProofAggregator, InstantStateVerifier, BlockAggregatedProof, ChainRecursiveProof};

// NEW: Re-export ZK integration functionality (moved from lib-crypto)
pub use zk_integration::*;

// NEW: Re-export state proof system for bootstrapping and mesh integration
pub use state::*;

// NEW: Re-export recursive proof system
pub use recursive::*;

// Module declarations
pub mod types;
pub mod transaction;
pub mod merkle;
pub mod range;
pub mod identity;
pub mod plonky2;
pub mod circuits;
pub mod provers;
pub mod verifiers;

// NEW: ZK integration module (moved from lib-crypto)
pub mod zk_integration;

// NEW: State proof system for bootstrapping and mesh integration
pub mod state;

// NEW: Recursive proof system for hierarchical aggregation
pub mod recursive;

// Type aliases for backward compatibility
pub use types::zk_proof::ZkProof as ZeroKnowledgeProof;
pub use types::MerkleProof;

/// Initialize the unified ZK proof system
pub fn initialize_zk_system() -> Result<ZkProofSystem> {
    ZkProofSystem::new()
}

/// Create a default proof for development/testing using unified system
pub fn create_default_proof() -> ZkProof {
    ZkProof::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_zk_system_initialization() {
        let zk_system = initialize_zk_system();
        assert!(zk_system.is_ok());
    }

    #[test]
    fn test_default_proof_creation() {
        let proof = create_default_proof();
        assert!(proof.is_empty());
    }
}
