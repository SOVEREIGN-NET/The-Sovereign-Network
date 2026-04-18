//! # ZHTP Smart Contract System
//!
//! A comprehensive smart contract platform integrated into the ZHTP blockchain,
//! featuring multi-token support, decentralized messaging, social platform
//! contracts, and advanced gas pricing system with zero-knowledge integration.

#[cfg(feature = "contracts")]
pub mod abi;
#[cfg(feature = "contracts")]
pub mod approval_verifier;
#[cfg(feature = "contracts")]
pub mod base;
#[cfg(feature = "contracts")]
pub mod bonding_curve;
#[cfg(feature = "contracts")]
pub mod calls;
#[cfg(feature = "contracts")]
pub mod contacts;
#[cfg(feature = "contracts")]
pub mod dao;
#[cfg(feature = "contracts")]
pub mod dao_registry;
#[cfg(feature = "contracts")]
pub mod dev_grants;
#[cfg(feature = "contracts")]
pub mod economics;
#[cfg(feature = "contracts")]
pub mod emergency_reserve;
#[cfg(feature = "contracts")]
pub mod employment;
#[cfg(feature = "contracts")]
pub mod executor;
#[cfg(feature = "contracts")]
pub mod files;
#[cfg(feature = "contracts")]
pub mod governance;
pub mod nft;
#[cfg(feature = "contracts")]
pub mod groups;
#[cfg(feature = "contracts")]
pub mod integration;
#[cfg(feature = "contracts")]
pub mod messaging;
#[cfg(feature = "contracts")]
pub mod root_registry;
#[cfg(feature = "contracts")]
pub mod runtime;
#[cfg(feature = "contracts")]
pub mod sov_swap;
#[cfg(feature = "contracts")]
pub mod staking;
#[cfg(feature = "contracts")]
pub mod tokens;
#[cfg(feature = "contracts")]
pub mod treasuries;
#[cfg(feature = "contracts")]
pub mod treasury_kernel;
#[cfg(feature = "contracts")]
pub mod types;
#[cfg(feature = "contracts")]
pub mod ubi_distribution;
#[cfg(feature = "contracts")]
pub mod utils;
#[cfg(feature = "contracts")]
pub mod web4;

// Re-export core types and functionality when contracts feature is enabled
#[cfg(feature = "contracts")]
pub use crate::types::{
    CallPermissions, ContractCall, ContractLog, ContractPermissions, ContractResult, ContractType,
    EventType, MessageType,
};
#[cfg(feature = "contracts")]
pub use base::SmartContract;
#[cfg(feature = "contracts")]
pub use executor::{ContractExecutor, ContractStorage, ExecutionContext, MemoryStorage};
#[cfg(feature = "contracts")]
pub use integration::{
    BlockchainIntegration, ContractEvent, ContractEventListener, ContractEventPublisher,
    ContractTransactionBuilder,
};
#[cfg(feature = "contracts")]
pub use runtime::sandbox::{ContractSandbox, SandboxConfig, SecurityLevel};
#[cfg(all(feature = "contracts", feature = "wasm-runtime"))]
pub use runtime::wasm_engine::WasmEngine;
#[cfg(feature = "contracts")]
pub use runtime::{
    ContractRuntime, NativeRuntime, RuntimeConfig, RuntimeContext, RuntimeFactory, RuntimeResult,
};

// Re-export all contract-specific types
#[cfg(feature = "contracts")]
pub use bonding_curve::AmmPool;
#[cfg(feature = "contracts")]
pub use contacts::ContactEntry;
#[cfg(feature = "contracts")]
pub use dao_registry::{derive_dao_id, DAOEntry, DAORegistry};
#[cfg(feature = "contracts")]
pub use dev_grants::{
    Amount, ApprovedGrant, DevGrants, Disbursement, Error as DevGrantsError, ProposalId,
    ProposalStatus,
};
#[cfg(feature = "contracts")]
pub use economics::{
    DaoDistribution, FeeDistribution, FeeRouter, FeeRouterError, DAO_ALLOCATION_PERCENT,
    DEV_ALLOCATION_PERCENT, EMERGENCY_ALLOCATION_PERCENT, FEE_RATE_BASIS_POINTS,
    UBI_ALLOCATION_PERCENT,
};
#[cfg(feature = "contracts")]
pub use emergency_reserve::EmergencyReserve;
#[cfg(feature = "contracts")]
pub use employment::{
    ContractAccessType, EconomicPeriod, EmploymentContract, EmploymentRegistry, EmploymentStatus,
    PaymentDetails, ProfitShareResult, TerminationReason,
};
#[cfg(feature = "contracts")]
pub use files::{FileContract, SharedFile};
#[cfg(feature = "contracts")]
pub use governance::{
    CitizenRegistry, CitizenRole, CitizenRoleError, EntityRegistry, EntityRegistryError,
    EntityType, RegistryStats, Role,
};
#[cfg(feature = "contracts")]
pub use groups::GroupChat;
#[cfg(feature = "contracts")]
pub use messaging::{GroupThread, MessageContract, MessageThread, WhisperMessage};
#[cfg(feature = "contracts")]
pub use sov_swap::{
    LiquidityPosition, LpPositionsManager, LpRewardBreakdown, PoolState, SovSwapPool,
    SwapDirection, SwapError, SwapResult,
};
#[cfg(feature = "contracts")]
pub use staking::{
    GlobalStakingGuardrails, LaunchedDao, PendingDao, SovDaoStaking, StakingPosition,
};
#[cfg(feature = "contracts")]
pub use tokens::TokenContract;
#[cfg(feature = "contracts")]
pub use treasuries::SovDaoTreasury;
#[cfg(feature = "contracts")]
pub use treasury_kernel::{KernelState, KernelStats, RejectionReason, TreasuryKernel};
#[cfg(feature = "contracts")]
pub use ubi_distribution::{
    EpochIndex, Error as UbiError, MonthIndex, UbiClaimRecorded, UbiClaimRejected, UbiDistributed,
    UbiDistributor, UbiPoolStatus,
};
// Note: utils is a sub-module available for internal contract utilities
#[cfg(feature = "contracts")]
pub use root_registry::{
    compute_name_hash, parse_and_validate, DaoId, GovernanceRecord, NameClass, NameClassification,
    NameHash, NameRecord, NameStatus, ReservedReason, RootRegistry, VerificationLevel,
    WelfareSector, ZoneController,
};
#[cfg(feature = "contracts")]
pub use web4::{
    ContentRoute, DomainRecord, Web4Contract, WebsiteContract, WebsiteDeploymentData,
    WebsiteMetadata,
};

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

#[cfg(feature = "contracts")]
pub use tokens::constants::SOV_TOKEN_DECIMALS as SOV_NATIVE_DECIMALS;
#[cfg(feature = "contracts")]
pub use tokens::constants::SOV_TOKEN_MAX_SUPPLY as SOV_NATIVE_MAX_SUPPLY;
#[cfg(feature = "contracts")]
pub use tokens::constants::SOV_TOKEN_NAME as SOV_NATIVE_NAME;
/// SOV native token constants — re-exported from canonical source (tokens::constants)
#[cfg(feature = "contracts")]
pub use tokens::constants::SOV_TOKEN_SYMBOL as SOV_NATIVE_SYMBOL;

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
        assert_eq!(SOV_NATIVE_SYMBOL, "SOV");
        assert_eq!(SOV_NATIVE_NAME, "Sovereign");
        assert_eq!(SOV_NATIVE_DECIMALS, 18);
        assert_eq!(SOV_NATIVE_MAX_SUPPLY, lib_types::SOV_MAX_SUPPLY);
    }
}
