//! ZHTP Blockchain Package
//! 
//! Core blockchain implementation with zero-knowledge transactions
//! and quantum-resistant consensus integration. Focuses on blockchain
//! fundamentals while delegating specialized functionality to other packages.

// External dependencies
extern crate lib_crypto;
extern crate lib_proofs;
extern crate lib_identity;
extern crate lib_economy;

pub mod types;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod mempool;
pub mod integration;
pub mod utils;
pub mod edge_node_state;
pub mod dht_index;
pub mod receipts;
mod fork_recovery; // gutted in Issue #936; kept as private to avoid orphan module errors
pub mod events;
pub mod byzantine_evidence;
pub mod storage;
pub mod execution;
pub mod validation;
pub mod fees;
pub mod sync;
pub mod protocol;
pub mod resources;
pub mod snapshot;
pub mod vm;

// Smart contracts submodule (feature-gated)
#[cfg(feature = "contracts")]
pub mod contracts;

// Re-export core types for convenience
// Types module (all types are already explicitly re-exported in types/mod.rs)
pub use types::{
    TransactionType, Hash, Difficulty,
    blake3_hash, hash_to_hex, hex_to_hash, zero_hash, is_zero_hash, Hashable,
    calculate_target, meets_difficulty, target_to_difficulty, max_target, min_target,
    adjust_difficulty, adjust_difficulty_with_config, difficulty_to_work,
    MiningProfile, MiningConfig, get_mining_config_from_env, validate_mining_for_chain,
    DAOType, TokenClass, DAOMetadata, TreasuryAllocation, SectorDao, DifficultyParameterUpdateData,
    WelfareSectorId, SectorVerificationFloor,
};

// Transaction module (core types and functions)
pub use transaction::{
    Transaction, DaoProposalData, DaoVoteData, DaoExecutionData, UbiClaimData,
    ProfitDeclarationData, RevenueSource, TransactionInput, TransactionOutput,
    IdentityTransactionData, WalletTransactionData, WalletReference, WalletPrivateData,
    ValidatorTransactionData, ValidatorOperation,
    TransactionBuilder, TransactionCreateError,
    create_transfer_transaction, create_identity_transaction, create_wallet_transaction,
    create_contract_transaction, create_token_transaction,
    ValidationError, ValidationResult, TransactionValidator, StatefulTransactionValidator,
    hash_transaction, hash_transaction_for_signing, hash_transaction_input, hash_transaction_output,
    calculate_transaction_merkle_root, generate_nullifier, create_commitment, create_encrypted_note, hash_for_signature,
    SigningError, sign_transaction, verify_transaction_signature,
};

// Block module (core types and functions)
pub use block::{
    Block, BlockHeader, create_genesis_block, BlockValidationResult, BlockValidationError,
    BlockBuilder, create_block, create_genesis_block_with_transactions,
    mine_block,  // Deprecated stub - BFT-A-935
    mine_block_with_config,  // Deprecated stub - BFT-A-935
    estimate_block_time, select_transactions_for_block,
};

// Blockchain module
pub use blockchain::{
    Blockchain, BlockchainImport, BlockchainBroadcastMessage, EconomicsTransaction, ValidatorInfo,
    ConsensusCheckpoint
};

// Mempool module
pub use mempool::{Mempool, MempoolStats, MempoolError};

// DHT Index module
pub use dht_index::{IndexedBlockHeader, IndexedTransactionSummary};

// Receipts module
pub use receipts::{TransactionReceipt, TransactionStatus};

// Sync module (Phase 3A)
pub use sync::{ChainSync, SyncError, SyncResult, ImportResult};

// Snapshot module (Phase 11)
pub use snapshot::{Snapshot, SnapshotError, SnapshotResult, snapshot, restore};

// Protocol module (Phase 3B)
pub use protocol::{ProtocolParams, ProtocolError, ProtocolResult, fee_model, PROTOCOL_PARAMS_KEY};

// Re-export enhanced integrations
pub use integration::enhanced_zk_crypto::{
    EnhancedTransactionValidator,
    EnhancedTransactionCreator,
    EnhancedConsensusValidator,
    TransactionSpec,
};

// Re-export economic integration
pub use integration::economic_integration::{
    EconomicTransactionProcessor,
    TreasuryStats,
    create_economic_processor,
    create_welfare_funding_transactions,
    validate_dao_fee_calculation,
    calculate_minimum_blockchain_fee,
    convert_economy_amount_to_blockchain,
    convert_blockchain_amount_to_economy,
};

// Re-export consensus integration
pub use integration::consensus_integration::{
    BlockchainConsensusCoordinator,
    ConsensusStatus,
    initialize_consensus_integration,
    initialize_consensus_integration_with_difficulty_config,
    create_dao_proposal_transaction,
    create_dao_vote_transaction,
};

// Re-export difficulty types from lib-consensus for convenience
pub use lib_consensus::{DifficultyConfig, DifficultyManager, DifficultyError, DifficultyResult};

// Re-export storage types (Phase 1 storage layer)
pub use storage::{
    BlockchainStore, SledStore, StorageError, StorageResult,
    BlockHash, TxHash, OutPoint, Address, TokenId, Utxo,
    AccountState, WalletState, WalletMetadata, IdentityState, IdentityAttribute,
    IdentityStatus, ValidatorState, ValidatorStatus,
};

// Re-export execution types (Phase 2 execution layer)
pub use execution::{
    BlockExecutor, ExecutorConfig, ApplyOutcome, StateChangesSummary,
    BlockApplyError, BlockApplyResult, TxApplyError, TxApplyResult,
    StateMutator, StateView, StateViewExt,
};

// Phase 2 validation module available as crate::validation
// Not re-exported at top level to avoid conflict with transaction::validation

// Re-export contracts when feature is enabled
// contracts/mod.rs has explicit re-exports, so this is safe and curated
#[cfg(feature = "contracts")]
pub use contracts::{
    SmartContract, ContractExecutor, ExecutionContext, MemoryStorage, ContractStorage,
    BlockchainIntegration, ContractTransactionBuilder, ContractEvent, ContractEventListener, ContractEventPublisher,
    ContractRuntime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeFactory, NativeRuntime,
    ContractCall, ContractLog, ContractPermissions, ContractResult, ContractType, MessageType, CallPermissions, EventType,
    ContactEntry, SharedFile, FileContract, GroupChat,
    WhisperMessage, MessageContract, MessageThread, GroupThread,
    TokenContract, SovDaoTreasury, EmergencyReserve,
    DAORegistry, DAOEntry, derive_dao_id,
    DevGrants, ProposalId, Amount, ApprovedGrant, Disbursement, ProposalStatus,
    UbiDistributor, MonthIndex,
    SovSwapPool, SwapDirection, SwapResult, PoolState, SwapError,
    LiquidityPosition, LpRewardBreakdown, LpPositionsManager,
    SovDaoStaking, GlobalStakingGuardrails, PendingDao, StakingPosition, LaunchedDao,
    EntityRegistry, EntityType, Role, EntityRegistryError,
    FeeRouter, FeeRouterError, FeeDistribution, DaoDistribution,
    FEE_RATE_BASIS_POINTS, UBI_ALLOCATION_PERCENT, DAO_ALLOCATION_PERCENT,
    EMERGENCY_ALLOCATION_PERCENT, DEV_ALLOCATION_PERCENT,
    Web4Contract, WebsiteContract, WebsiteMetadata, ContentRoute, DomainRecord, WebsiteDeploymentData,
    RootRegistry, NameRecord, NameClass, ZoneController, NameStatus, VerificationLevel,
    ReservedReason, WelfareSector, NameHash, DaoId, NameClassification,
    GovernanceRecord, parse_and_validate, compute_name_hash,
    Error, Result,
    GAS_BASE, GAS_TOKEN, GAS_MESSAGING, GAS_CONTACT, GAS_GROUP,
};

/// ZHTP blockchain protocol version.
///
/// # Protocol Upgrade Policy (BFT-H)
///
/// Protocol upgrades are consensus-critical and must follow this policy:
/// - Upgrades are gated by block height; incompatible peers and blocks are
///   rejected **deterministically** at both the handshake layer and block
///   acceptance layer.
/// - A new version MUST be accompanied by a hard-fork activation height constant
///   (see `PROTOCOL_VERSION_ACTIVATION_HEIGHTS` map below).
/// - Validators running an incompatible version are automatically rejected
///   and cannot participate in consensus.
/// - Version transitions happen at specific block heights to coordinate network-wide upgrades.
pub const BLOCKCHAIN_VERSION: u32 = 1;

/// Minimum compatible protocol version.
///
/// Peers advertising a version below this value are rejected immediately.
/// Update this constant when a breaking protocol change is introduced.
pub const MIN_COMPATIBLE_PROTOCOL_VERSION: u32 = 1;

/// Protocol version activation heights for hard forks.
///
/// Maps protocol version -> block height at which that version becomes active.
/// Nodes must enforce that blocks use the correct version for their height.
///
/// # Example
/// ```ignore
/// // Version 1 active from genesis
/// (1, 0)
/// // Version 2 activates at block 100000
/// (2, 100000)
/// ```
pub const PROTOCOL_VERSION_ACTIVATION_HEIGHTS: &[(u32, u64)] = &[
    (1, 0), // Version 1 active from genesis
];

/// Enforces the protocol version gate for a connecting peer.
///
/// Returns `Ok(())` if the peer version is within the accepted range,
/// otherwise returns an `Err` describing the mismatch. This check MUST be
/// performed before accepting any block or vote from a peer.
///
/// # Errors
/// Returns an error if `peer_version < MIN_COMPATIBLE_PROTOCOL_VERSION` or
/// `peer_version > BLOCKCHAIN_VERSION`.
pub fn enforce_protocol_version_gate(peer_version: u32) -> anyhow::Result<()> {
    if peer_version < MIN_COMPATIBLE_PROTOCOL_VERSION {
        return Err(anyhow::anyhow!(
            "peer protocol version {} is below minimum compatible version {}; upgrade required",
            peer_version,
            MIN_COMPATIBLE_PROTOCOL_VERSION
        ));
    }
    if peer_version > BLOCKCHAIN_VERSION {
        return Err(anyhow::anyhow!(
            "peer protocol version {} is ahead of local version {}; local node must be upgraded",
            peer_version,
            BLOCKCHAIN_VERSION
        ));
    }
    Ok(())
}

/// Determines the expected protocol version for a given block height.
///
/// Returns the highest protocol version that is active at or before the given height.
///
/// # Panics
/// Panics if `PROTOCOL_VERSION_ACTIVATION_HEIGHTS` is empty or misconfigured.
pub fn expected_protocol_version_at_height(height: u64) -> u32 {
    let mut active_version = 1;
    for &(version, activation_height) in PROTOCOL_VERSION_ACTIVATION_HEIGHTS {
        if height >= activation_height {
            active_version = version;
        } else {
            break;
        }
    }
    active_version
}

/// Enforces that a block's protocol version matches the expected version for its height.
///
/// This ensures that protocol upgrades happen at coordinated block heights across the network.
///
/// # Errors
/// Returns an error if the block's version doesn't match the expected version for its height.
pub fn enforce_block_protocol_version(block_version: u32, block_height: u64) -> anyhow::Result<()> {
    let expected = expected_protocol_version_at_height(block_height);
    if block_version != expected {
        return Err(anyhow::anyhow!(
            "block at height {} has protocol version {} but expected version {} for this height",
            block_height,
            block_version,
            expected
        ));
    }
    Ok(())
}

#[cfg(test)]
mod protocol_version_tests {
    use super::*;

    #[test]
    fn test_enforce_protocol_version_gate_accepts_current() {
        assert!(enforce_protocol_version_gate(BLOCKCHAIN_VERSION).is_ok());
    }

    #[test]
    fn test_enforce_protocol_version_gate_rejects_old() {
        // Test rejection of version 0 (always invalid)
        let result = enforce_protocol_version_gate(0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("below minimum"));
    }

    #[test]
    fn test_enforce_protocol_version_gate_rejects_future() {
        let result = enforce_protocol_version_gate(BLOCKCHAIN_VERSION + 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ahead of local version"));
    }

    #[test]
    fn test_expected_protocol_version_at_height() {
        // Version 1 should be active from genesis
        assert_eq!(expected_protocol_version_at_height(0), 1);
        assert_eq!(expected_protocol_version_at_height(1), 1);
        assert_eq!(expected_protocol_version_at_height(1000), 1);
        assert_eq!(expected_protocol_version_at_height(u64::MAX), 1);
    }

    #[test]
    fn test_enforce_block_protocol_version_accepts_correct() {
        // Version 1 at early heights should be accepted
        assert!(enforce_block_protocol_version(1, 0).is_ok());
        assert!(enforce_block_protocol_version(1, 100).is_ok());
    }

    #[test]
    fn test_enforce_block_protocol_version_rejects_wrong() {
        // Version 2 at height 0 should be rejected (not yet active)
        let result = enforce_block_protocol_version(2, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected version 1"));
        
        // Version 0 at any height should be rejected
        let result = enforce_block_protocol_version(0, 100);
        assert!(result.is_err());
    }
}

/// Maximum block size in bytes (1MB)
pub const MAX_BLOCK_SIZE: usize = 1_048_576;

/// Target block time in seconds (10 seconds)
pub const TARGET_BLOCK_TIME: u64 = 10;

/// Maximum transactions per block
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 4096;

/// Genesis block timestamp (January 1, 2022 00:00:00 UTC)
pub const GENESIS_TIMESTAMP: u64 = 1640995200;

/// Initial difficulty for proof of work
pub const INITIAL_DIFFICULTY: u32 = 0x1d00ffff;

/// Difficulty adjustment interval (blocks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target timespan for difficulty adjustment (2 weeks)
pub const TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;

/// Maximum nullifier cache size
pub const MAX_NULLIFIER_CACHE: usize = 1_000_000;

/// Maximum UTXO cache size  
pub const MAX_UTXO_CACHE: usize = 10_000_000;

/// Genesis block message
pub const GENESIS_MESSAGE: &[u8] = b"In the beginning was the Word, and the Word was ZHTP";

/// Get blockchain health information for monitoring
pub fn get_blockchain_health() -> Result<BlockchainHealth, String> {
    Ok(BlockchainHealth {
        is_synced: true,
        current_height: 12345,
        peer_count: 8,
        mempool_size: 42,
        last_block_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        difficulty: INITIAL_DIFFICULTY,
        network_hashrate: 1000000, // Example hashrate
    })
}

/// Get comprehensive blockchain information
pub fn get_blockchain_info() -> Result<BlockchainInfo, String> {
    Ok(BlockchainInfo {
        version: BLOCKCHAIN_VERSION,
        protocol_version: 1,
        blocks: 12345,
        timeoffset: 0,
        connections: 8,
        proxy: None,
        difficulty: INITIAL_DIFFICULTY as f64,
        testnet: false,
        keypoololdest: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        keypoolsize: 100,
        paytxfee: 0.0001,
        mininput: 0.0001,
        errors: None,
    })
}

/// Get current blockchain height asynchronously
pub async fn get_current_block_height() -> Result<u64, String> {
    // In production, this would query the actual blockchain state
    Ok(12345)
}

/// Get treasury balance for economic calculations
pub fn get_treasury_balance() -> Result<u64, String> {
    // Return a default treasury balance
    // In production, this would query the actual treasury state
    Ok(1_000_000_000) // 1 billion tokens
}

/// Blockchain health status structure
#[derive(Debug, Clone)]
pub struct BlockchainHealth {
    /// Whether the blockchain is fully synced
    pub is_synced: bool,
    /// Current blockchain height
    pub current_height: u64,
    /// Number of connected peers
    pub peer_count: u32,
    /// Number of transactions in mempool
    pub mempool_size: u32,
    /// Timestamp of last block
    pub last_block_time: u64,
    /// Current network difficulty
    pub difficulty: u32,
    /// Network hash rate estimate
    pub network_hashrate: u64,
}

/// Comprehensive blockchain information structure
#[derive(Debug, Clone)]
pub struct BlockchainInfo {
    /// Blockchain software version
    pub version: u32,
    /// Protocol version
    pub protocol_version: u32,
    /// Current block count
    pub blocks: u64,
    /// Time offset from system clock
    pub timeoffset: i64,
    /// Number of peer connections
    pub connections: u32,
    /// Proxy configuration
    pub proxy: Option<String>,
    /// Current network difficulty
    pub difficulty: f64,
    /// Whether running on testnet
    pub testnet: bool,
    /// Oldest key in keypool
    pub keypoololdest: u64,
    /// Size of keypool
    pub keypoolsize: u32,
    /// Transaction fee per byte
    pub paytxfee: f64,
    /// Minimum input value
    pub mininput: f64,
    /// Any blockchain errors
    pub errors: Option<String>,
}

// NOTE: Shared blockchain provider has been removed.
// Use zhtp::runtime::blockchain_provider::get_global_blockchain() instead.
// This provides better control over blockchain initialization and lifecycle.

pub mod execution_limits;
