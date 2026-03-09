//! Identity zero-knowledge proof module
//!
//! Provides identity verification proofs that allow proving possession of
//! specific credentials or attributes without revealing the actual identity.

pub mod credential_proof;
pub mod identity_proof;
pub mod verification;

// Re-export main types
pub use credential_proof::{CredentialClaim, CredentialSchema, ZkCredentialProof};
pub use identity_proof::{IdentityAttributes, IdentityCommitment, ZkIdentityProof};
pub use verification::{
    verify_credential_proof, verify_identity_proof, IdentityVerificationResult,
};
