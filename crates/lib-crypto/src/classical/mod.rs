//! Classical cryptography compatibility module
//! 
//! Ed25519 and Curve25519 operations for legacy compatibility and ring signatures

pub mod ed25519;
pub mod curve25519;

// Re-export main functions
pub use ed25519::*;
pub use curve25519::*;
