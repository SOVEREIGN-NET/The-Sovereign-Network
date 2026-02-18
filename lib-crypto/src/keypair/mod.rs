//! KeyPair management module
//! 
//! implementations from crypto.rs preserving working post-quantum cryptography

pub mod generation;
pub mod operations;

// Re-export main KeyPair type
pub use generation::KeyPair;

// Re-export consensus signature scheme validation
pub use operations::{CONSENSUS_SIGNATURE_SCHEME, validate_consensus_signature_scheme};
