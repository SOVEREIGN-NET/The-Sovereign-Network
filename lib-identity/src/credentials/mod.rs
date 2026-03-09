//! Credential system implementations

pub mod attestation;
pub mod creation;
pub mod verification;
pub mod zk_credential;

// Re-exports
pub use crate::types::{AttestationType, CredentialType};
pub use attestation::IdentityAttestation;
pub use zk_credential::ZkCredential;
