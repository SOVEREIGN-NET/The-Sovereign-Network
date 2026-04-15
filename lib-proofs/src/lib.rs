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
//! ```rust,no_run
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
pub use backend::{get_backend, BackendProof, ProofBackend};
pub use identity::identity_proof::ZkIdentityProof;
pub use merkle::{proof_generation::*, tree::*, verification::*};
#[doc(hidden)]
#[deprecated(since = "0.2.0", note = "Use lib_proofs::backend::get_backend() instead")]
pub use plonky2::proof_system::ZkProofSystem;
pub use range::range_proof::ZkRangeProof;
pub use transaction::transaction_proof::ZkTransactionProof;
pub use types::zk_proof::ZkProof;

// Re-export prover and verifier modules
pub use provers::*;
pub use verifiers::*;

// Specifically re-export recursive aggregation components
pub use verifiers::{
    BlockAggregatedProof, ChainRecursiveProof, InstantStateVerifier, RecursiveProofAggregator,
};

// NEW: Re-export ZK integration functionality (moved from lib-crypto)
pub use zk_integration::*;

// NEW: Re-export state proof system for bootstrapping and mesh integration
pub use state::*;

// NEW: Re-export recursive proof system
pub use recursive::*;

// Module declarations
pub mod backend;
pub mod circuits;
pub mod identity;
pub mod merkle;
pub(crate) mod plonky2;
pub mod provers;
pub mod range;
pub mod transaction;
pub mod types;
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
#[deprecated(since = "0.2.0", note = "Use lib_proofs::backend::get_backend() instead")]
pub fn initialize_zk_system() -> Result<ZkProofSystem> {
    #[allow(deprecated)]
    ZkProofSystem::new()
}

/// Create a default proof for development/testing using unified system.
///
/// **TEST / FAKE-PROOFS ONLY.** Unavailable in production builds.
#[cfg(feature = "fake-proofs")]
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
    #[cfg(feature = "fake-proofs")]
    fn test_default_proof_creation() {
        let proof = create_default_proof();
        assert!(proof.is_empty());
        assert!(proof.is_mock);
    }
}
