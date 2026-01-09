//! # ZHTP Smart Contract System
//!
//! A comprehensive smart contract platform integrated into the ZHTP blockchain,
//! featuring multi-token support, decentralized messaging, social platform
//! contracts, and advanced gas pricing system with zero-knowledge integration.

#[cfg(feature = "contracts")]
pub mod base;
#[cfg(feature = "contracts")]
pub mod types;
#[cfg(feature = "contracts")]
pub mod contacts;
#[cfg(feature = "contracts")]
pub mod executor;
#[cfg(feature = "contracts")]
pub mod files;
#[cfg(feature = "contracts")]
pub mod groups;
#[cfg(feature = "contracts")]
pub mod integration;
#[cfg(feature = "contracts")]
pub mod messaging;
#[cfg(feature = "contracts")]
pub mod runtime;
#[cfg(feature = "contracts")]
pub mod tokens;
#[cfg(feature = "contracts")]
pub mod treasuries;
#[cfg(feature = "contracts")]
pub mod emergency_reserve;
#[cfg(feature = "contracts")]
pub mod dao_registry;
#[cfg(feature = "contracts")]
pub mod dev_grants;
#[cfg(feature = "contracts")]
pub mod ubi_distribution;
#[cfg(feature = "contracts")]
pub mod sov_swap;
#[cfg(feature = "contracts")]
pub mod utils;
#[cfg(feature = "contracts")]
pub mod web4;

// Re-export core types and functionality when contracts feature is enabled
#[cfg(feature = "contracts")]
pub use base::SmartContract;
#[cfg(feature = "contracts")]
pub use executor::{ContractExecutor, ExecutionContext, MemoryStorage, ContractStorage};
#[cfg(feature = "contracts")]
pub use integration::{BlockchainIntegration, ContractTransactionBuilder, ContractEvent, ContractEventListener, ContractEventPublisher};
#[cfg(feature = "contracts")]
pub use runtime::{ContractRuntime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeFactory, NativeRuntime};
#[cfg(all(feature = "contracts", feature = "wasm-runtime"))]
pub use runtime::wasm_engine::WasmEngine;
#[cfg(feature = "contracts")]
pub use runtime::sandbox::{SandboxConfig, SecurityLevel, ContractSandbox};
#[cfg(feature = "contracts")]
pub use crate::types::{
    ContractCall, ContractLog, ContractPermissions, ContractResult, ContractType, MessageType, CallPermissions, EventType,
};

// Re-export all contract-specific types
#[cfg(feature = "contracts")]
pub use contacts::ContactEntry;
#[cfg(feature = "contracts")]
pub use files::{SharedFile, FileContract};
#[cfg(feature = "contracts")]
pub use groups::GroupChat;
#[cfg(feature = "contracts")]
pub use messaging::{WhisperMessage, MessageContract, MessageThread, GroupThread};
#[cfg(feature = "contracts")]
pub use tokens::{TokenContract, functions};
#[cfg(feature = "contracts")]
pub use treasuries::SovDaoTreasury;
#[cfg(feature = "contracts")]
pub use emergency_reserve::EmergencyReserve;
#[cfg(feature = "contracts")]
pub use dao_registry::{DAORegistry, DAOEntry, derive_dao_id};
#[cfg(feature = "contracts")]
pub use dev_grants::{DevGrants, ProposalId, Amount, ApprovedGrant, Disbursement, ProposalStatus, Error as DevGrantsError};
#[cfg(feature = "contracts")]
pub use ubi_distribution::{UbiDistributor, MonthIndex, Error as UbiError};
#[cfg(feature = "contracts")]
pub use sov_swap::{SovSwapPool, SwapDirection, SwapResult, PoolState, SwapError};
#[cfg(feature = "contracts")]
pub use utils::*;
#[cfg(feature = "contracts")]
pub use web4::{Web4Contract, WebsiteContract, WebsiteMetadata, ContentRoute, DomainRecord, WebsiteDeploymentData};

// Re-export testing framework when available
#[cfg(all(feature = "contracts", feature = "testing"))]
pub mod testing;
#[cfg(all(feature = "contracts", feature = "testing"))]
pub use testing::{ContractTestFramework, IntegrationTestScenarios, PerformanceBenchmarks};

// Error handling
#[cfg(feature = "contracts")]
pub use anyhow::{Error, Result};

/// Contract gas pricing constants
#[cfg(feature = "contracts")]
pub const GAS_BASE: u64 = 1000; // Base gas cost for any contract operation
#[cfg(feature = "contracts")]
pub const GAS_TOKEN: u64 = 2000; // Gas cost for token operations
#[cfg(feature = "contracts")]
pub const GAS_MESSAGING: u64 = 3000; // Gas cost for messaging operations  
#[cfg(feature = "contracts")]
pub const GAS_CONTACT: u64 = 1500; // Gas cost for contact operations
#[cfg(feature = "contracts")]
pub const GAS_GROUP: u64 = 2500; // Gas cost for group operations

/// ZHTP native token constants
#[cfg(feature = "contracts")]
pub const ZHTP_TOKEN_SYMBOL: &str = "ZHTP";
#[cfg(feature = "contracts")]
pub const ZHTP_TOKEN_NAME: &str = "ZHTP";
#[cfg(feature = "contracts")]
pub const ZHTP_DECIMALS: u8 = 8;
#[cfg(feature = "contracts")]
pub const ZHTP_MAX_SUPPLY: u64 = 21_000_000 * 100_000_000; // 21M ZHTP with 8 decimals

/// Contract version information
#[cfg(feature = "contracts")]
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "contracts")]
pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(all(test, feature = "contracts"))]
mod tests {
    use super::*;

    #[test]
    fn test_gas_constants() {
        assert_eq!(GAS_BASE, 1000);
        assert_eq!(GAS_TOKEN, 2000);
        assert_eq!(GAS_MESSAGING, 3000);
        assert_eq!(GAS_CONTACT, 1500);
        assert_eq!(GAS_GROUP, 2500);
    }

    #[test]
    fn test_lib_constants() {
        assert_eq!(ZHTP_TOKEN_SYMBOL, "ZHTP");
        assert_eq!(ZHTP_TOKEN_NAME, "ZHTP");
        assert_eq!(ZHTP_DECIMALS, 8);
        assert_eq!(ZHTP_MAX_SUPPLY, 2_100_000_000_000_000);
    }
}
