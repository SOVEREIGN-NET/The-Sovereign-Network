//! Pure functional business logic
//!
//! This module contains pure functions that implement business logic
//! without side effects. These functions can be tested independently
//! and composed together to build imperative shell functions.
//!
//! The key principle: All functions here are pure - they take inputs,
//! return outputs, and have no side effects (no I/O, no printing, no state mutation).

pub mod paths;
pub mod identity;
pub mod wallet;
pub mod config;
pub mod deploy;

// Re-export commonly used types
pub use paths::{normalize_path, expand_home_directory};
pub use identity::{IdentityKeys, validate_identity_name};
pub use wallet::{WalletMetadata, validate_wallet_name};
pub use deploy::{FileManifest, DeploymentConfig};
