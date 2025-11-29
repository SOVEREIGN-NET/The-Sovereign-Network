// packages/lib-identity/src/privacy/mod.rs
// Privacy and zero-knowledge proof module exports

pub mod zk_proofs;
pub mod privacy_credentials;
pub mod requirements_verification;

// Re-export all privacy types and functions
pub use zk_proofs::*;
pub use privacy_credentials::*;
pub use requirements_verification::*;
