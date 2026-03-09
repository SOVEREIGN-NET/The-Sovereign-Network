pub mod identity_proofs;
pub mod proof_verification;
pub mod ubi_proofs;

#[cfg(test)]
mod identity_proofs_test;

pub use identity_proofs::*;
pub use ubi_proofs::*;

// Zero-knowledge proof integration for mesh privacy
