//! Identity zero-knowledge proof module
//! 
//! Provides identity verification proofs that allow proving possession of
//! specific credentials or attributes without revealing the actual identity.

pub mod identity_proof;
pub mod credential_proof;
pub mod verification;

// Re-export main types
pub use identity_proof::{ZkIdentityProof, IdentityCommitment, IdentityAttributes};
pub use credential_proof::{ZkCredentialProof, CredentialSchema, CredentialClaim};
pub use verification::{verify_identity_proof, verify_credential_proof, IdentityVerificationResult};
