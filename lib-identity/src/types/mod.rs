//! Core identity types for ZHTP Identity Management

pub mod identity_types;
pub mod credential_types;
pub mod proof_params;
pub mod verification_result;

// Re-exports
pub use identity_types::*;
pub use credential_types::*;
pub use proof_params::*;
pub use verification_result::*;

// DID-related types from did module (remaining types after cleanup)
// Note: Removed placeholder creation types - use IdentityManager::create_citizen_identity() instead
