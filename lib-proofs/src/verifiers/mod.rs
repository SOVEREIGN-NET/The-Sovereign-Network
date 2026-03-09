//! Proof verification modules
//!
//! Provides specialized verifiers for different types of zero-knowledge proofs
//! with optimized verification performance and batch processing.

pub mod identity_verifier;
pub mod merkle_verifier;
pub mod range_verifier;
pub mod recursive_aggregator;
pub mod state_verifier;
pub mod transaction_verifier;

// Re-export main types
pub use identity_verifier::IdentityVerifier;
pub use range_verifier::RangeVerifier;
pub use recursive_aggregator::{
    BlockAggregatedProof, ChainRecursiveProof, InstantStateVerifier, RecursiveProofAggregator,
    StateSummary,
};
pub use state_verifier::StateVerifier;
pub use transaction_verifier::TransactionVerifier;

// Re-export merkle verification functions
pub use merkle_verifier::{
    batch_verify_merkle_proofs, verify_merkle_proof, verify_merkle_proof_detailed,
    verify_with_tree, verify_with_tree_detailed,
};
