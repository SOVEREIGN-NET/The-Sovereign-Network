//! Credential system implementations

pub mod zk_credential;
pub mod attestation;
pub mod verification;
pub mod creation;

// Re-exports
pub use zk_credential::ZkCredential;
pub use attestation::IdentityAttestation;
pub use crate::types::{CredentialType, AttestationType};
