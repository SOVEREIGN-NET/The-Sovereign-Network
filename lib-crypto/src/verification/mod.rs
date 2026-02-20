//! Signature verification module
//!
//! implementations from crypto.rs preserving working verification logic

pub mod dev_mode;
pub mod signature_verify;

// Re-export main functions
pub use signature_verify::{
    validate_consensus_vote_signature_scheme, verify_consensus_vote_signature, verify_signature,
};

// Re-export development mode functions (gated behind feature)
#[cfg(feature = "development")]
pub use dev_mode::development::{
    accept_development_signature, is_development_public_key, is_development_signature,
};
