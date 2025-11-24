//! Utility functions module
//! 
//! implementations from crypto.rs preserving convenience functions

pub mod compatibility;

// Re-export main functions
pub use compatibility::{generate_keypair, sign_message};
