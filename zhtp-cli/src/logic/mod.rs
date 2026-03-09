//! Pure functional business logic
//!
//! This module contains pure functions that implement business logic
//! without side effects. These functions can be tested independently
//! and composed together to build imperative shell functions.
//!
//! The key principle: All functions here are pure - they take inputs,
//! return outputs, and have no side effects (no I/O, no printing, no state mutation).

pub mod config;
pub mod deploy;
pub mod identity;
pub mod network;
pub mod paths;
pub mod wallet;

// Re-export commonly used types
pub use config::{validate_log_level, validate_output_format};
pub use deploy::{DeploymentConfig, FileManifest};
pub use identity::{
    extract_name_from_did, is_identity_name_available, parse_identity_type, validate_did,
    validate_identity_name, IdentityKeys, IdentityMetadata,
};
pub use network::{validate_ping_count, validate_socket_address};
pub use paths::{expand_home_directory, normalize_path};
pub use wallet::{
    calculate_min_fee, is_balance_sufficient, validate_transaction_amount, validate_wallet_address,
    validate_wallet_name, validate_wallet_type, WalletMetadata,
};
