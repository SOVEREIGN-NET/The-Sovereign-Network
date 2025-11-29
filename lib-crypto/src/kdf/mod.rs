//! Key derivation functions module
//! 
//! implementations from crypto.rs preserving secure key derivation

pub mod hkdf;

// Re-export main functions
pub use hkdf::{derive_keys, hkdf_sha3};
