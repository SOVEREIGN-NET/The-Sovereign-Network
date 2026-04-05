//! Utility functions module
//!
//! implementations from crypto.rs preserving convenience functions

pub mod compatibility;
pub mod encoding;

// Re-export main functions
pub use compatibility::{generate_keypair, sign_message};
pub use encoding::{dilithium5_pk_from_bytes, dilithium5_pk_from_hex};
