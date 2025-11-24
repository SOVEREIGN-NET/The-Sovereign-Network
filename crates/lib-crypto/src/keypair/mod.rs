//! KeyPair management module
//! 
//! implementations from crypto.rs preserving working post-quantum cryptography

pub mod generation;
pub mod derivation;
pub mod operations;

// Re-export main KeyPair type
pub use generation::KeyPair;
