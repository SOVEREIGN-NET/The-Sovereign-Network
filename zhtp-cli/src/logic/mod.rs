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
pub mod network;

// Re-export commonly used types
pub use paths::{normalize_path, expand_home_directory};
pub use identity::{IdentityKeys, IdentityMetadata, validate_identity_name, parse_identity_type, validate_did, extract_name_from_did, is_identity_name_available};
pub use wallet::{WalletMetadata, validate_wallet_name, validate_wallet_type, validate_wallet_address, validate_transaction_amount, calculate_min_fee, is_balance_sufficient};
pub use config::{validate_output_format, validate_log_level};
pub use deploy::{FileManifest, DeploymentConfig};
pub use network::{validate_socket_address, validate_ping_count};
