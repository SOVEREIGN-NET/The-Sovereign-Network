// packages/lib-identity/src/privacy/mod.rs
// Privacy and zero-knowledge proof module exports

pub mod privacy_credentials;
pub mod requirements_verification;
pub mod zk_proofs;

// Re-export all privacy types and functions
pub use privacy_credentials::*;
pub use requirements_verification::*;
pub use zk_proofs::*;
