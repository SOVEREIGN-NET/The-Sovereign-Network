//! Identity zero-knowledge proof module
//!
//! Provides identity verification proofs that allow proving possession of
//! specific credentials or attributes without revealing the actual identity.

pub mod circuit;
pub mod credential_proof;
pub mod identity_proof;
pub mod verification;

// Re-export main types
pub use credential_proof::{CredentialClaim, CredentialSchema, ZkCredentialProof};
pub use identity_proof::{IdentityAttributes, IdentityCommitment, ZkIdentityProof};
pub use verification::{
    verify_credential_proof, verify_identity_proof, IdentityVerificationResult,
};

// Re-export circuit helpers when real-proofs is enabled
#[cfg(feature = "real-proofs")]
pub use circuit::real::{compute_identity_commitment, prove_identity, verify_identity};
