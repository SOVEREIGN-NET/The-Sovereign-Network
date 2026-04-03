//! Integrated wallet management for ZHTP Identity
//!
//! This module provides integration with the quantum wallet system,
//! allowing identities to manage multiple wallets with different purposes.

pub mod dao_hierarchy_demo;
pub mod manager_integration;
pub mod multi_wallet;
pub mod wallet_operations;
pub mod wallet_password;
pub mod wallet_types;

// Re-exports for compatibility with original identity.rs
pub use manager_integration::WalletManager;
pub use wallet_operations::*;
pub use wallet_password::{WalletPasswordError, WalletPasswordManager, WalletPasswordValidation};
pub use wallet_types::{
    ContentMetadataSnapshot,
    // Content ownership types
    ContentOwnershipRecord,
    ContentOwnershipStatistics,
    ContentTransfer,
    ContentTransferType,
    DaoGovernanceSettings,
    DaoHierarchyInfo,
    // DAO wallet types
    DaoWalletProperties,
    PublicTransactionEntry,
    QuantumWallet,
    TransparencyLevel,
    WalletId,
    WalletSummary,
    WalletType,
};
