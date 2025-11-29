pub mod identity_proofs;
pub mod ubi_proofs;
pub mod proof_verification;

#[cfg(test)]
mod identity_proofs_test;

pub use identity_proofs::*;
pub use ubi_proofs::*;
pub use proof_verification::*;

// Zero-knowledge proof integration for mesh privacy
