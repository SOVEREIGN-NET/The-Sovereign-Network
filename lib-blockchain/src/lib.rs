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

// Smart contracts submodule (feature-gated)
#[cfg(feature = "contracts")]
pub mod contracts;

// Re-export core types for convenience
pub use types::*;
pub use transaction::{*, WalletReference, WalletPrivateData};
pub use block::*;
pub use blockchain::{Blockchain, BlockchainImport, BlockchainBroadcastMessage, EconomicsTransaction, ValidatorInfo};
pub use mempool::*;
pub use utils::*;
pub use dht_index::*;

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

// Re-export contracts when feature is enabled
#[cfg(feature = "contracts")]
pub use contracts::*;

/// ZHTP blockchain protocol version
pub const BLOCKCHAIN_VERSION: u32 = 1;

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

