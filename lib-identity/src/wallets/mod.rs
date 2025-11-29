//! Integrated wallet management for ZHTP Identity
//! 
//! This module provides integration with the quantum wallet system,
//! allowing identities to manage multiple wallets with different purposes.

pub mod manager_integration;
pub mod multi_wallet;
pub mod wallet_operations;
pub mod wallet_types;
pub mod dao_hierarchy_demo;

// Re-exports for compatibility with original identity.rs
pub use manager_integration::{IdentityWallets, WalletPasswordError, WalletPasswordValidation};
pub use wallet_types::{WalletType, WalletId, QuantumWallet, WalletSummary};
pub use wallet_operations::*;
