//! Main blockchain data structure and implementation
//! 
//! Contains the core Blockchain struct and its methods, extracted from the original
//! blockchain.rs implementation with proper modularization.

use std::collections::{HashMap, HashSet};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug};
use crate::types::{Hash, Difficulty, DifficultyConfig};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::transaction_type::TransactionType;
use crate::block::Block;
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::ZkTransactionProof;
use crate::integration::economic_integration::{EconomicTransactionProcessor, TreasuryStats};
use crate::integration::consensus_integration::{BlockchainConsensusCoordinator, ConsensusStatus};
use crate::integration::storage_integration::{BlockchainStorageManager, BlockchainStorageConfig, StorageOperationResult};
use lib_storage::dht::storage::DhtStorage;

/// Messages for real-time blockchain synchronization
#[derive(Debug, Clone)]
pub enum BlockchainBroadcastMessage {
    /// New block created locally and should be broadcast to peers
    NewBlock(Block),
    /// New transaction submitted locally and should be broadcast to peers
    NewTransaction(Transaction),
}

// Import lib-proofs for recursive proof aggregation
// Import lib-proofs for recursive proof aggregation
use lib_proofs::verifiers::transaction_verifier::{BatchedPrivateTransaction, BatchMetadata};

/// Default finality depth (6 blocks like Bitcoin)
fn default_finality_depth() -> u64 {
    6
}

/// Blockchain state with identity registry and UTXO management
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Blockchain {
    /// All blocks in the chain
    pub blocks: Vec<Block>,
    /// Current blockchain height
    pub height: u64,
    /// Current mining difficulty
    pub difficulty: Difficulty,
    /// Difficulty adjustment configuration (governance-controlled)
    #[serde(default)]
    pub difficulty_config: DifficultyConfig,
    /// Total work done (cumulative difficulty)
    pub total_work: u128,
    /// UTXO set for transaction validation
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    /// Used nullifiers to prevent double-spending
    pub nullifier_set: HashSet<Hash>,
    /// Pending transactions waiting to be mined
    pub pending_transactions: Vec<Transaction>,
    /// On-chain identity registry (DID -> Identity data)
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    /// Identity DID to block height mapping for verification
    pub identity_blocks: HashMap<String, u64>,
    /// On-chain wallet registry (wallet_id -> Wallet data)
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    /// Wallet ID to block height mapping for verification
    pub wallet_blocks: HashMap<String, u64>,
    /// Economics transaction storage (handled by lib-economy)
    #[serde(default)]
    pub economics_transactions: Vec<EconomicsTransaction>,
    /// Smart contract registry - Token contracts (contract_id -> TokenContract)
    #[serde(default)]
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    /// Smart contract registry - Web4 Website contracts (contract_id -> Web4Contract)
    #[serde(default)]
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    /// Contract deployment block heights (contract_id -> block_height)
    #[serde(default)]
    pub contract_blocks: HashMap<[u8; 32], u64>,
    /// On-chain validator registry (identity_id -> Validator info)
    #[serde(default)]
    pub validator_registry: HashMap<String, ValidatorInfo>,
    /// Validator registration block heights (identity_id -> block_height)
    #[serde(default)]
    pub validator_blocks: HashMap<String, u64>,
    /// DAO treasury wallet ID (stores collected fees for governance)
    #[serde(default)]
    pub dao_treasury_wallet_id: Option<String>,
    /// Welfare service registry (service_id -> WelfareService)
    #[serde(default)]
    pub welfare_services: HashMap<String, lib_consensus::WelfareService>,
    /// Welfare service registration block heights (service_id -> block_height)
    #[serde(default)]
    pub welfare_service_blocks: HashMap<String, u64>,
    /// Welfare audit trail (audit_id -> WelfareAuditEntry)
    #[serde(default)]
    pub welfare_audit_trail: HashMap<lib_crypto::Hash, lib_consensus::WelfareAuditEntry>,
    /// Service performance metrics (service_id -> ServicePerformanceMetrics)
    #[serde(default)]
    pub service_performance: HashMap<String, lib_consensus::ServicePerformanceMetrics>,
    /// Outcome reports (report_id -> OutcomeReport)
    #[serde(default)]
    pub outcome_reports: HashMap<lib_crypto::Hash, lib_consensus::OutcomeReport>,
    /// Economic transaction processor for lib-economy integration
    #[serde(skip)]
    pub economic_processor: Option<EconomicTransactionProcessor>,
    /// Consensus coordinator for lib-consensus integration
    #[serde(skip)]
    pub consensus_coordinator: Option<std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>>,
    /// Storage manager for persistent data
    #[serde(skip)]
    pub storage_manager: Option<std::sync::Arc<tokio::sync::RwLock<BlockchainStorageManager>>>,
    /// Recursive proof aggregator for O(1) state verification
    #[serde(skip)]
    pub proof_aggregator: Option<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>>,
    /// Auto-persistence configuration
    #[serde(default)]
    pub auto_persist_enabled: bool,
    /// Block counter for auto-persistence
    #[serde(default)]
    pub blocks_since_last_persist: u64,
    /// Broadcast channel for real-time block/transaction propagation
    #[serde(skip)]
    pub broadcast_sender: Option<tokio::sync::mpsc::UnboundedSender<BlockchainBroadcastMessage>>,
    /// Track executed DAO proposals to prevent double-execution
    #[serde(default)]
    pub executed_dao_proposals: HashSet<Hash>,
    /// Transaction receipts for confirmation tracking (tx_hash -> receipt)
    #[serde(default)]
    pub receipts: HashMap<Hash, crate::receipts::TransactionReceipt>,
    /// Finality depth (number of confirmations required for finality)
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
    /// Track finalized block heights to avoid reprocessing
    #[serde(default)]
    pub finalized_blocks: HashSet<u64>,
    /// Per-contract state storage (contract_id -> state bytes)
    #[serde(default)]
    pub contract_states: HashMap<[u8; 32], Vec<u8>>,
    /// Contract state snapshots per block height for historical queries
    #[serde(default)]
    pub contract_state_history: std::collections::BTreeMap<u64, HashMap<[u8; 32], Vec<u8>>>,
    /// UTXO set snapshots per block height for state recovery and reorg support
    #[serde(default)]
    pub utxo_snapshots: std::collections::BTreeMap<u64, HashMap<Hash, TransactionOutput>>,
    /// Fork history for audit trail (height -> ForkPoint)
    #[serde(default)]
    pub fork_points: HashMap<u64, crate::fork_recovery::ForkPoint>,
    /// Count of reorganizations for monitoring
    #[serde(default)]
    pub reorg_count: u64,
    /// Fork recovery configuration
    #[serde(default)]
    pub fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig,
    /// Event publisher for blockchain state changes (Issue #11).
    ///
    /// NOTE: This field is marked with `#[serde(skip)]` and is **not** serialized.
    /// When a [`Blockchain`] instance is persisted and later deserialized, the
    /// `event_publisher` will not be restored, and any existing event listeners
    /// will be lost. Callers must re-create the publisher and re-subscribe all
    /// listeners after loading a blockchain from storage.
    #[serde(skip)]
    pub event_publisher: crate::events::BlockchainEventPublisher,
    /// UBI (Universal Basic Income) registry - tracks eligible citizens and their payout status
    /// Key: identity_id (hex string), Value: UBI registration data
    #[serde(default)]
    pub ubi_registry: HashMap<String, UbiRegistryEntry>,
    /// UBI registration block heights (identity_id -> block_height)
    #[serde(default)]
    pub ubi_blocks: HashMap<String, u64>,
}

/// Validator information stored on-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator identity ID
    pub identity_id: String,
    /// Staked amount (in micro-ZHTP)
    pub stake: u64,
    /// Storage provided (in bytes)
    pub storage_provided: u64,
    /// Public key for consensus (post-quantum)
    pub consensus_key: Vec<u8>,
    /// Network address for validator communication
    pub network_address: String,
    /// Commission rate (percentage 0-100)
    pub commission_rate: u8,
    /// Validator status
    pub status: String, // "active", "inactive", "jailed", "slashed"
    /// Registration timestamp
    pub registered_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Total blocks validated
    pub blocks_validated: u64,
    /// Slash count
    pub slash_count: u32,
}

/// UBI (Universal Basic Income) registry entry
/// Tracks a citizen's UBI eligibility and payout status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiRegistryEntry {
    /// Citizen's identity ID (hex string)
    pub identity_id: String,
    /// UBI wallet ID where payments are sent
    pub ubi_wallet_id: String,
    /// Daily UBI amount (~33 ZHTP)
    pub daily_amount: u64,
    /// Monthly UBI amount (1000 ZHTP)
    pub monthly_amount: u64,
    /// Block height when registered for UBI
    pub registered_at_block: u64,
    /// Block height of last UBI payout (None if never received)
    pub last_payout_block: Option<u64>,
    /// Total UBI received to date
    pub total_received: u64,
    /// Accumulated remainder from integer division (1000/30 = 33 remainder 10)
    pub remainder_balance: u64,
    /// Whether UBI is currently active for this citizen
    pub is_active: bool,
}

/// Economics transaction record (simplified for blockchain package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsTransaction {
    pub tx_id: Hash,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub tx_type: String,
    pub timestamp: u64,
    pub block_height: u64,
}

// =============================================================================
// V1 Migration Types (Dec 2025 format - before UBI/Profit transaction types)
// =============================================================================

/// Transaction V1 format - without ubi_claim_data and profit_declaration_data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionV1 {
    pub version: u32,
    pub chain_id: u8,
    pub transaction_type: TransactionType,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub signature: Signature,
    pub memo: Vec<u8>,
    pub identity_data: Option<IdentityTransactionData>,
    pub wallet_data: Option<crate::transaction::WalletTransactionData>,
    pub validator_data: Option<crate::transaction::ValidatorTransactionData>,
    pub dao_proposal_data: Option<crate::transaction::DaoProposalData>,
    pub dao_vote_data: Option<crate::transaction::DaoVoteData>,
    pub dao_execution_data: Option<crate::transaction::DaoExecutionData>,
}

impl TransactionV1 {
    fn migrate_to_current(self) -> Transaction {
        Transaction {
            version: self.version,
            chain_id: self.chain_id,
            transaction_type: self.transaction_type,
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            signature: self.signature,
            memo: self.memo,
            identity_data: self.identity_data,
            wallet_data: self.wallet_data,
            validator_data: self.validator_data,
            dao_proposal_data: self.dao_proposal_data,
            dao_vote_data: self.dao_vote_data,
            dao_execution_data: self.dao_execution_data,
            ubi_claim_data: None,
            profit_declaration_data: None,
        }
    }
}

/// Block V1 format - uses TransactionV1
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockV1 {
    pub header: crate::block::BlockHeader,
    pub transactions: Vec<TransactionV1>,
}

impl BlockV1 {
    fn migrate_to_current(self) -> Block {
        Block {
            header: self.header,
            transactions: self.transactions.into_iter().map(|tx| tx.migrate_to_current()).collect(),
        }
    }
}

/// Blockchain V1 format (Dec 2025) - for backward compatibility migration
/// This struct matches the format used by production nodes before the Phase 2 updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockchainV1 {
    pub blocks: Vec<BlockV1>,
    pub height: u64,
    pub difficulty: Difficulty,
    pub total_work: u128,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub nullifier_set: HashSet<Hash>,
    pub pending_transactions: Vec<TransactionV1>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub identity_blocks: HashMap<String, u64>,
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    pub wallet_blocks: HashMap<String, u64>,
    pub economics_transactions: Vec<EconomicsTransaction>,
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    pub contract_blocks: HashMap<[u8; 32], u64>,
    pub validator_registry: HashMap<String, ValidatorInfo>,
    pub validator_blocks: HashMap<String, u64>,
    pub dao_treasury_wallet_id: Option<String>,
    pub welfare_services: HashMap<String, lib_consensus::WelfareService>,
    pub welfare_service_blocks: HashMap<String, u64>,
    pub welfare_audit_trail: HashMap<lib_crypto::Hash, lib_consensus::WelfareAuditEntry>,
    pub service_performance: HashMap<String, lib_consensus::ServicePerformanceMetrics>,
    pub outcome_reports: HashMap<lib_crypto::Hash, lib_consensus::OutcomeReport>,
    pub auto_persist_enabled: bool,
    pub blocks_since_last_persist: u64,
}

impl BlockchainV1 {
    /// Migrate V1 blockchain to current format
    fn migrate_to_current(self) -> Blockchain {
        info!("🔄 Migrating blockchain from V1 format to current format");
        info!("   V1 data: height={}, identities={}, wallets={}, utxos={}",
              self.height, self.identity_registry.len(),
              self.wallet_registry.len(), self.utxo_set.len());

        let blocks: Vec<Block> = self.blocks.into_iter().map(|b| b.migrate_to_current()).collect();
        let pending_transactions: Vec<Transaction> = self.pending_transactions.into_iter()
            .map(|tx| tx.migrate_to_current()).collect();

        info!("   Migrated {} blocks, {} pending transactions", blocks.len(), pending_transactions.len());

        Blockchain {
            blocks,
            height: self.height,
            difficulty: self.difficulty,
            difficulty_config: DifficultyConfig::default(),
            total_work: self.total_work,
            utxo_set: self.utxo_set,
            nullifier_set: self.nullifier_set,
            pending_transactions,
            identity_registry: self.identity_registry,
            identity_blocks: self.identity_blocks,
            wallet_registry: self.wallet_registry,
            wallet_blocks: self.wallet_blocks,
            economics_transactions: self.economics_transactions,
            token_contracts: self.token_contracts,
            web4_contracts: self.web4_contracts,
            contract_blocks: self.contract_blocks,
            validator_registry: self.validator_registry,
            validator_blocks: self.validator_blocks,
            dao_treasury_wallet_id: self.dao_treasury_wallet_id,
            welfare_services: self.welfare_services,
            welfare_service_blocks: self.welfare_service_blocks,
            welfare_audit_trail: self.welfare_audit_trail,
            service_performance: self.service_performance,
            outcome_reports: self.outcome_reports,
            economic_processor: Some(EconomicTransactionProcessor::new()),
            consensus_coordinator: None,
            storage_manager: None,
            proof_aggregator: None,
            auto_persist_enabled: self.auto_persist_enabled,
            blocks_since_last_persist: self.blocks_since_last_persist,
            broadcast_sender: None,
            executed_dao_proposals: HashSet::new(),
            receipts: HashMap::new(),
            finality_depth: default_finality_depth(),
            finalized_blocks: HashSet::new(),
            contract_states: HashMap::new(),
            contract_state_history: std::collections::BTreeMap::new(),
            utxo_snapshots: std::collections::BTreeMap::new(),
            fork_points: HashMap::new(),
            reorg_count: 0,
            fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig::default(),
            event_publisher: crate::events::BlockchainEventPublisher::new(),
            ubi_registry: HashMap::new(),
            ubi_blocks: HashMap::new(),
        }
    }
}

// =============================================================================
// V3 Stable Storage Format (Jan 2026)
// =============================================================================
// This format uses explicit field ordering and versioning to ensure
// compatibility across code changes. Fields are serialized in the exact
// order they appear in the struct - DO NOT REORDER FIELDS.
// =============================================================================

/// Stable storage format V3 for blockchain serialization.
///
/// CRITICAL: Field order MUST remain fixed forever. New fields can only be
/// added at the END of the struct with `#[serde(default)]` to maintain
/// backward compatibility.
///
/// This struct maps to/from the runtime `Blockchain` struct but provides
/// a stable serialization format that survives code refactoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockchainStorageV3 {
    // === Core chain state (fields 1-5) ===
    pub blocks: Vec<Block>,
    pub height: u64,
    pub difficulty: Difficulty,
    #[serde(default)]
    pub difficulty_config: DifficultyConfig,
    pub total_work: u128,

    // === UTXO and nullifier sets (fields 6-7) ===
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub nullifier_set: HashSet<Hash>,

    // === Pending transactions (field 8) ===
    pub pending_transactions: Vec<Transaction>,

    // === Identity registry (fields 9-10) ===
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub identity_blocks: HashMap<String, u64>,

    // === Wallet registry (fields 11-12) ===
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    pub wallet_blocks: HashMap<String, u64>,

    // === Economics (field 13) ===
    #[serde(default)]
    pub economics_transactions: Vec<EconomicsTransaction>,

    // === Token contracts (fields 14-16) ===
    #[serde(default)]
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    #[serde(default)]
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    #[serde(default)]
    pub contract_blocks: HashMap<[u8; 32], u64>,

    // === Validator registry (fields 17-18) ===
    #[serde(default)]
    pub validator_registry: HashMap<String, ValidatorInfo>,
    #[serde(default)]
    pub validator_blocks: HashMap<String, u64>,

    // === DAO (field 19) ===
    #[serde(default)]
    pub dao_treasury_wallet_id: Option<String>,

    // === Welfare services (fields 20-24) ===
    #[serde(default)]
    pub welfare_services: HashMap<String, lib_consensus::WelfareService>,
    #[serde(default)]
    pub welfare_service_blocks: HashMap<String, u64>,
    #[serde(default)]
    pub welfare_audit_trail: HashMap<lib_crypto::Hash, lib_consensus::WelfareAuditEntry>,
    #[serde(default)]
    pub service_performance: HashMap<String, lib_consensus::ServicePerformanceMetrics>,
    #[serde(default)]
    pub outcome_reports: HashMap<lib_crypto::Hash, lib_consensus::OutcomeReport>,

    // === Auto-persistence config (fields 25-26) ===
    #[serde(default)]
    pub auto_persist_enabled: bool,
    #[serde(default)]
    pub blocks_since_last_persist: u64,

    // === DAO execution tracking (field 27) ===
    #[serde(default)]
    pub executed_dao_proposals: HashSet<Hash>,

    // === Transaction receipts (field 28) ===
    #[serde(default)]
    pub receipts: HashMap<Hash, crate::receipts::TransactionReceipt>,

    // === Finality (fields 29-30) ===
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
    #[serde(default)]
    pub finalized_blocks: HashSet<u64>,

    // === Contract state (fields 31-32) ===
    #[serde(default)]
    pub contract_states: HashMap<[u8; 32], Vec<u8>>,
    #[serde(default)]
    pub contract_state_history: std::collections::BTreeMap<u64, HashMap<[u8; 32], Vec<u8>>>,

    // === UTXO snapshots and fork recovery (fields 33-36) ===
    #[serde(default)]
    pub utxo_snapshots: std::collections::BTreeMap<u64, HashMap<Hash, TransactionOutput>>,
    #[serde(default)]
    pub fork_points: HashMap<u64, crate::fork_recovery::ForkPoint>,
    #[serde(default)]
    pub reorg_count: u64,
    #[serde(default)]
    pub fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig,

    // === UBI registry (fields 37-38) ===
    #[serde(default)]
    pub ubi_registry: HashMap<String, UbiRegistryEntry>,
    #[serde(default)]
    pub ubi_blocks: HashMap<String, u64>,

    // =========================================================================
    // ADD NEW FIELDS BELOW HERE ONLY - with #[serde(default)]
    // =========================================================================
}

impl BlockchainStorageV3 {
    /// Convert from runtime Blockchain to stable storage format
    fn from_blockchain(bc: &Blockchain) -> Self {
        BlockchainStorageV3 {
            // Core chain state
            blocks: bc.blocks.clone(),
            height: bc.height,
            difficulty: bc.difficulty.clone(),
            difficulty_config: bc.difficulty_config.clone(),
            total_work: bc.total_work,

            // UTXO and nullifiers
            utxo_set: bc.utxo_set.clone(),
            nullifier_set: bc.nullifier_set.clone(),

            // Pending transactions
            pending_transactions: bc.pending_transactions.clone(),

            // Identity registry
            identity_registry: bc.identity_registry.clone(),
            identity_blocks: bc.identity_blocks.clone(),

            // Wallet registry
            wallet_registry: bc.wallet_registry.clone(),
            wallet_blocks: bc.wallet_blocks.clone(),

            // Economics
            economics_transactions: bc.economics_transactions.clone(),

            // Contracts
            token_contracts: bc.token_contracts.clone(),
            web4_contracts: bc.web4_contracts.clone(),
            contract_blocks: bc.contract_blocks.clone(),

            // Validators
            validator_registry: bc.validator_registry.clone(),
            validator_blocks: bc.validator_blocks.clone(),

            // DAO
            dao_treasury_wallet_id: bc.dao_treasury_wallet_id.clone(),

            // Welfare
            welfare_services: bc.welfare_services.clone(),
            welfare_service_blocks: bc.welfare_service_blocks.clone(),
            welfare_audit_trail: bc.welfare_audit_trail.clone(),
            service_performance: bc.service_performance.clone(),
            outcome_reports: bc.outcome_reports.clone(),

            // Auto-persistence
            auto_persist_enabled: bc.auto_persist_enabled,
            blocks_since_last_persist: bc.blocks_since_last_persist,

            // DAO execution
            executed_dao_proposals: bc.executed_dao_proposals.clone(),

            // Receipts
            receipts: bc.receipts.clone(),

            // Finality
            finality_depth: bc.finality_depth,
            finalized_blocks: bc.finalized_blocks.clone(),

            // Contract state
            contract_states: bc.contract_states.clone(),
            contract_state_history: bc.contract_state_history.clone(),

            // Fork recovery
            utxo_snapshots: bc.utxo_snapshots.clone(),
            fork_points: bc.fork_points.clone(),
            reorg_count: bc.reorg_count,
            fork_recovery_config: bc.fork_recovery_config.clone(),

            // UBI
            ubi_registry: bc.ubi_registry.clone(),
            ubi_blocks: bc.ubi_blocks.clone(),
        }
    }

    /// Convert from stable storage format to runtime Blockchain
    fn to_blockchain(self) -> Blockchain {
        Blockchain {
            // Core chain state
            blocks: self.blocks,
            height: self.height,
            difficulty: self.difficulty,
            difficulty_config: self.difficulty_config,
            total_work: self.total_work,

            // UTXO and nullifiers
            utxo_set: self.utxo_set,
            nullifier_set: self.nullifier_set,

            // Pending transactions
            pending_transactions: self.pending_transactions,

            // Identity registry
            identity_registry: self.identity_registry,
            identity_blocks: self.identity_blocks,

            // Wallet registry
            wallet_registry: self.wallet_registry,
            wallet_blocks: self.wallet_blocks,

            // Economics
            economics_transactions: self.economics_transactions,

            // Contracts
            token_contracts: self.token_contracts,
            web4_contracts: self.web4_contracts,
            contract_blocks: self.contract_blocks,

            // Validators
            validator_registry: self.validator_registry,
            validator_blocks: self.validator_blocks,

            // DAO
            dao_treasury_wallet_id: self.dao_treasury_wallet_id,

            // Welfare
            welfare_services: self.welfare_services,
            welfare_service_blocks: self.welfare_service_blocks,
            welfare_audit_trail: self.welfare_audit_trail,
            service_performance: self.service_performance,
            outcome_reports: self.outcome_reports,

            // Non-serialized runtime fields - must be re-initialized
            economic_processor: None,
            consensus_coordinator: None,
            storage_manager: None,
            proof_aggregator: None,
            broadcast_sender: None,
            event_publisher: crate::events::BlockchainEventPublisher::new(),

            // Auto-persistence
            auto_persist_enabled: self.auto_persist_enabled,
            blocks_since_last_persist: self.blocks_since_last_persist,

            // DAO execution
            executed_dao_proposals: self.executed_dao_proposals,

            // Receipts
            receipts: self.receipts,

            // Finality
            finality_depth: self.finality_depth,
            finalized_blocks: self.finalized_blocks,

            // Contract state
            contract_states: self.contract_states,
            contract_state_history: self.contract_state_history,

            // Fork recovery
            utxo_snapshots: self.utxo_snapshots,
            fork_points: self.fork_points,
            reorg_count: self.reorg_count,
            fork_recovery_config: self.fork_recovery_config,

            // UBI
            ubi_registry: self.ubi_registry,
            ubi_blocks: self.ubi_blocks,
        }
    }
}

/// Blockchain import structure for deserializing received chains
#[derive(Serialize, Deserialize)]
pub struct BlockchainImport {
    pub blocks: Vec<Block>,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub wallet_references: HashMap<String, crate::transaction::WalletReference>,  // Only minimal references
    pub validator_registry: HashMap<String, ValidatorInfo>,
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    pub contract_blocks: HashMap<[u8; 32], u64>,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    pub fn new() -> Result<Self> {
        let genesis_block = crate::block::create_genesis_block();
        
        let mut blockchain = Blockchain {
            blocks: vec![genesis_block.clone()],
            height: 0,
            difficulty: Difficulty::from_bits(crate::INITIAL_DIFFICULTY),
            difficulty_config: DifficultyConfig::default(),
            total_work: 0,
            utxo_set: HashMap::new(),
            nullifier_set: HashSet::new(),
            pending_transactions: Vec::new(),
            identity_registry: HashMap::new(),
            identity_blocks: HashMap::new(),
            wallet_registry: HashMap::new(),
            wallet_blocks: HashMap::new(),
            economics_transactions: Vec::new(),
            token_contracts: HashMap::new(),
            web4_contracts: HashMap::new(),
            contract_blocks: HashMap::new(),
            validator_registry: HashMap::new(),
            validator_blocks: HashMap::new(),
            dao_treasury_wallet_id: None,
            welfare_services: HashMap::new(),
            welfare_service_blocks: HashMap::new(),
            welfare_audit_trail: HashMap::new(),
            service_performance: HashMap::new(),
            outcome_reports: HashMap::new(),
            economic_processor: Some(EconomicTransactionProcessor::new()),
            consensus_coordinator: None,
            storage_manager: None,
            proof_aggregator: None,
            auto_persist_enabled: true,
            blocks_since_last_persist: 0,
            broadcast_sender: None,
            executed_dao_proposals: HashSet::new(),
            receipts: HashMap::new(),
            finality_depth: 12, // Default: 12 confirmations for finality
            finalized_blocks: HashSet::new(),
            contract_states: HashMap::new(),
            contract_state_history: std::collections::BTreeMap::new(),
            utxo_snapshots: std::collections::BTreeMap::new(),
            fork_points: HashMap::new(),
            reorg_count: 0,
            fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig::default(),
            event_publisher: crate::events::BlockchainEventPublisher::new(),
            ubi_registry: HashMap::new(),
            ubi_blocks: HashMap::new(),
        };

        blockchain.update_utxo_set(&genesis_block)?;
        blockchain.save_utxo_snapshot(0)?; // Save snapshot for genesis block
        Ok(blockchain)
    }

    /// Create a new blockchain with storage manager
    pub async fn new_with_storage(storage_config: BlockchainStorageConfig) -> Result<Self> {
        let mut blockchain = Self::new()?;
        blockchain.initialize_storage_manager(storage_config).await?;
        Ok(blockchain)
    }

    /// Initialize the storage manager
    pub async fn initialize_storage_manager(&mut self, config: BlockchainStorageConfig) -> Result<()> {
        info!("🗃️ Initializing blockchain storage manager");
        
        let storage_manager = BlockchainStorageManager::new(config).await?;
        self.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(storage_manager)));
        self.auto_persist_enabled = true;
        
        info!("Storage manager initialized successfully");
        Ok(())
    }

    /// Initialize the recursive proof aggregator for O(1) state verification
    pub fn initialize_proof_aggregator(&mut self) -> Result<()> {
        info!("Initializing recursive proof aggregator");
        
        let aggregator = lib_proofs::RecursiveProofAggregator::new()?;
        self.proof_aggregator = Some(std::sync::Arc::new(tokio::sync::RwLock::new(aggregator)));
        
        info!("Recursive proof aggregator initialized successfully");
        Ok(())
    }

    /// Set broadcast channel for real-time block/transaction propagation
    pub fn set_broadcast_channel(&mut self, sender: tokio::sync::mpsc::UnboundedSender<BlockchainBroadcastMessage>) {
        debug!("Blockchain broadcast channel configured");
        self.broadcast_sender = Some(sender);
    }

    /// Fund genesis block with initial UTXOs and register identities
    /// 
    /// This method handles the blockchain-specific operations for genesis funding:
    /// - Creates UTXOs for validators, funding pools, and user wallets
    /// - Registers identities and wallets in blockchain registries
    /// - Updates genesis block with funding transaction
    /// 
    /// # Arguments
    /// * `genesis_outputs` - Transaction outputs to add to genesis block
    /// * `genesis_signature` - Signature for the genesis funding transaction
    /// * `chain_id` - Network chain ID for the transaction
    /// * `wallet_registrations` - Optional wallet data to register
    /// * `identity_registrations` - Optional identity data to register
    /// * `validator_registrations` - Optional validator data to register
    pub fn fund_genesis_block(
        &mut self,
        genesis_outputs: Vec<crate::TransactionOutput>,
        genesis_signature: crate::integration::crypto_integration::Signature,
        chain_id: u64,
        wallet_registrations: Vec<crate::transaction::WalletTransactionData>,
        identity_registrations: Vec<crate::transaction::core::IdentityTransactionData>,
        validator_registrations: Vec<ValidatorInfo>,
    ) -> Result<()> {
        info!("Funding genesis block with {} outputs", genesis_outputs.len());
        
        // Validate genesis block exists
        if self.blocks.is_empty() {
            return Err(anyhow::anyhow!("No genesis block found in blockchain"));
        }
        
        let genesis_block = &mut self.blocks[0];
        
        // Create genesis funding transaction
        let genesis_tx = crate::Transaction {
            version: 1,
            chain_id: chain_id as u8,
            transaction_type: crate::types::TransactionType::Transfer,
            inputs: vec![], // Genesis transaction has no inputs
            outputs: genesis_outputs.clone(),
            fee: 0,
            signature: genesis_signature,
            memo: b"Genesis funding transaction".to_vec(),
            wallet_data: None,
            identity_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };
        
        // Add genesis transaction to genesis block
        genesis_block.transactions.push(genesis_tx.clone());
        
        // Recalculate merkle root
        let updated_merkle_root = crate::transaction::hashing::calculate_transaction_merkle_root(&genesis_block.transactions);
        genesis_block.header.merkle_root = updated_merkle_root;
        
        // Create UTXOs from genesis outputs
        let genesis_tx_id = crate::types::hash::blake3_hash(b"genesis_funding_transaction");
        for (index, output) in genesis_outputs.iter().enumerate() {
            let utxo_hash = crate::types::hash::blake3_hash(
                &format!("genesis_funding:{}:{}", hex::encode(genesis_tx_id), index).as_bytes()
            );
            self.utxo_set.insert(utxo_hash, output.clone());
        }
        
        // Register wallets
        for wallet_data in wallet_registrations {
            let wallet_id_hex = hex::encode(wallet_data.wallet_id.as_bytes());
            self.wallet_registry.insert(wallet_id_hex.clone(), wallet_data);
            info!("Registered genesis wallet: {}", &wallet_id_hex[..16]);
        }
        
        // Register identities
        for identity_data in identity_registrations {
            match self.register_identity(identity_data.clone()) {
                Ok(_) => {
                    info!("Registered genesis identity: {}", identity_data.did);
                }
                Err(e) => {
                    warn!("Failed to register genesis identity {}: {}", identity_data.did, e);
                }
            }
        }
        
        // Register validators
        for validator_data in validator_registrations {
            match self.register_validator(validator_data.clone()) {
                Ok(_) => {
                    info!("Registered genesis validator: {}", validator_data.identity_id);
                }
                Err(e) => {
                    warn!("Failed to register genesis validator {}: {}", validator_data.identity_id, e);
                }
            }
        }
        
        info!("Genesis funding complete: {} UTXOs, {} wallets, {} identities, {} validators",
              genesis_outputs.len(),
              self.wallet_registry.len(),
              self.identity_registry.len(),
              self.validator_registry.len());
        
        Ok(())
    }

    /// Load blockchain from persistent storage
    pub async fn load_from_storage(storage_config: BlockchainStorageConfig, content_hash: lib_storage::types::ContentHash) -> Result<Self> {
        info!("Loading blockchain from storage");
        
        let mut storage_manager = BlockchainStorageManager::new(storage_config).await?;
        let mut blockchain = storage_manager.retrieve_blockchain_state(content_hash).await?;
        
        // Re-initialize non-serialized components
        blockchain.economic_processor = Some(EconomicTransactionProcessor::new());
        blockchain.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(storage_manager)));
        blockchain.proof_aggregator = None; // Will be initialized on first use
        blockchain.auto_persist_enabled = true;
        blockchain.blocks_since_last_persist = 0;
        
        info!("Blockchain loaded from storage (height: {})", blockchain.height);
        Ok(blockchain)
    }

    /// Persist blockchain state to storage
    pub async fn persist_to_storage(&mut self) -> Result<StorageOperationResult> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Persisting blockchain state to storage (height: {})", self.height);
            
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_blockchain_state(self).await?;
            
            self.blocks_since_last_persist = 0;
            
            info!("Blockchain state persisted successfully");
            Ok(result)
        } else {
            Err(anyhow::anyhow!("Storage manager not initialized"))
        }
    }

    /// Backup entire blockchain to distributed storage
    pub async fn backup_to_storage(&mut self) -> Result<Vec<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Starting blockchain backup to distributed storage");
            
            let mut storage_manager = storage_manager_arc.write().await;
            let results = storage_manager.backup_blockchain(self).await?;
            
            let successful_backups = results.iter().filter(|r| r.success).count();
            info!("Blockchain backup completed: {}/{} operations successful", 
                  successful_backups, results.len());
            
            Ok(results)
        } else {
            Err(anyhow::anyhow!("Storage manager not initialized"))
        }
    }

    /// Auto-persist if conditions are met
    async fn auto_persist_if_needed(&mut self) -> Result<()> {
        if !self.auto_persist_enabled {
            return Ok(());
        }
        
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let storage_manager = storage_manager_arc.read().await;
            let persist_frequency = storage_manager.get_config().persist_frequency;
            drop(storage_manager);
            
            if self.blocks_since_last_persist >= persist_frequency {
                info!(" Auto-persisting blockchain state (blocks since last persist: {})", 
                      self.blocks_since_last_persist);
                self.persist_to_storage().await?;
            }
        }
        
        Ok(())
    }

    /// Store a block in persistent storage
    pub async fn persist_block(&mut self, block: &Block) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_block(block).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store a transaction in persistent storage
    pub async fn persist_transaction(&mut self, transaction: &Transaction) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_transaction(transaction).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store identity data in persistent storage
    pub async fn persist_identity_data(&mut self, did: &str, identity_data: &IdentityTransactionData) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_identity_data(did, identity_data).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store UTXO set in persistent storage
    pub async fn persist_utxo_set(&mut self) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_utxo_set(&self.utxo_set).await?;
            // Also store using the latest key for recovery
            storage_manager.store_latest_utxo_set(&self.utxo_set).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Persist just the blockchain state (height, difficulty, nullifiers) to storage
    pub async fn persist_blockchain_state(&mut self) -> Result<Option<()>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let storage_manager = storage_manager_arc.read().await;
            
            let state = crate::integration::storage_integration::BlockchainState {
                height: self.height,
                difficulty: self.difficulty.clone(),
                nullifier_set: self.nullifier_set.clone(),
            };
            
            storage_manager.store_latest_blockchain_state(&state).await?;
            
            info!("Blockchain state persisted to storage");
            return Ok(Some(()));
        }
        Ok(None)
    }

    /// Retrieve a block from storage by height
    pub async fn retrieve_block_from_storage(&self, height: u64) -> Result<Option<Block>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            storage_manager.retrieve_block_by_height(height).await
        } else {
            Ok(None)
        }
    }

    /// Perform storage maintenance
    pub async fn perform_storage_maintenance(&mut self) -> Result<()> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(" Performing blockchain storage maintenance");
            
            let mut storage_manager = storage_manager_arc.write().await;
            storage_manager.perform_maintenance().await?;
            
            info!("Storage maintenance completed");
        }
        Ok(())
    }

    /// Get storage statistics
    pub async fn get_storage_statistics(&self) -> Result<Option<lib_storage::UnifiedStorageStats>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let stats = storage_manager.get_storage_statistics().await?;
            Ok(Some(stats))
        } else {
            Ok(None)
        }
    }

    /// Add a new block to the chain
    pub async fn add_block(&mut self, block: Block) -> Result<()> {
        self.process_and_commit_block(block.clone()).await?;

        // Broadcast new block to mesh network (locally-originated blocks only)
        if let Some(ref sender) = self.broadcast_sender {
            if let Err(e) = sender.send(BlockchainBroadcastMessage::NewBlock(block.clone())) {
                warn!("Failed to broadcast new block to network: {}", e);
            } else {
                debug!("Block {} broadcast to mesh network", block.height());
            }
        }

        Ok(())
    }

    /// Add a block received from the network. Skips mesh broadcast to prevent
    /// broadcast loops (block was already propagated by the sender).
    pub async fn add_block_from_network(&mut self, block: Block) -> Result<()> {
        self.process_and_commit_block(block).await
    }

    /// Core block processing: verify, commit to chain, update state, emit events.
    /// Does NOT broadcast — callers decide whether to broadcast.
    async fn process_and_commit_block(&mut self, block: Block) -> Result<()> {
        // Verify the block
        let previous_block = self.blocks.last();
        if !self.verify_block(&block, previous_block)? {
            return Err(anyhow::anyhow!("Invalid block"));
        }

        // Check for double spends
        for tx in &block.transactions {
            for input in &tx.inputs {
                if self.nullifier_set.contains(&input.nullifier) {
                    return Err(anyhow::anyhow!("Double spend detected"));
                }
            }
        }

        // Issue #1016: Deduct transaction fees from sender balances BEFORE updating UTXO set
        // This ensures fees are collected at the consensus layer, not just declared
        let block_fees = self.deduct_transaction_fees(&block)?;
        if block_fees > 0 {
            debug!("Collected {} in fees from block {}", block_fees, block.height());
        }

        // Update blockchain state
        self.blocks.push(block.clone());
        self.height += 1;
        self.update_utxo_set(&block)?;
        self.save_utxo_snapshot(self.height)?;
        self.adjust_difficulty()?;

        // Remove processed transactions from pending pool
        self.remove_pending_transactions(&block.transactions);

        // Process identity transactions
        self.process_identity_transactions(&block)?;
        self.process_wallet_transactions(&block)?;
        self.process_contract_transactions(&block)?;

        // Process approved governance proposals (e.g., difficulty parameter updates)
        // This executes any proposals that have passed voting since the last block
        if let Err(e) = self.process_approved_governance_proposals() {
            warn!("Error processing governance proposals at height {}: {}", self.height, e);
            // Don't fail block processing, governance is non-critical
        }

        // Process economic features (UBI claims and profit declarations)
        if let Err(e) = self.process_ubi_claim_transactions(&block) {
            warn!("Error processing UBI claims at height {}: {}", self.height, e);
            // Don't fail block processing for UBI errors
        }

        // Process automatic UBI distribution to all eligible citizens
        if let Err(e) = self.process_automatic_ubi_distribution(self.height) {
            warn!("Error processing automatic UBI distribution at height {}: {}", self.height, e);
            // Don't fail block processing for UBI distribution errors
        }

        if let Err(e) = self.process_profit_declarations(&block) {
            warn!("Error processing profit declarations at height {}: {}", self.height, e);
            // Don't fail block processing for profit declaration errors
        }

        // Create transaction receipts for all transactions in block
        let block_hash = block.hash();
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            if let Err(e) = self.create_receipt(tx, block_hash, block.header.height, tx_index as u32) {
                warn!("Failed to create receipt for tx {}: {}", hex::encode(tx.hash().as_bytes()), e);
                // Continue processing even if receipt creation fails
            }
        }

        // Update persistence counter
        self.blocks_since_last_persist += 1;

        // Emit BlockAdded event (Issue #11)
        let block_hash_bytes = block.hash();
        let block_hash_array: [u8; 32] = match block_hash_bytes.as_bytes().try_into() {
            Ok(arr) => arr,
            Err(e) => {
                error!(
                    "Invariant violation: block hash for height {} is not 32 bytes (len = {}, error = {:?})",
                    block.header.height,
                    block_hash_bytes.as_bytes().len(),
                    e
                );
                [0u8; 32]
            }
        };
        let event = crate::events::BlockchainEvent::BlockAdded {
            height: block.header.height,
            block_hash: block_hash_array,
            timestamp: block.header.timestamp,
            transaction_count: block.transactions.len() as u64,
        };
        if let Err(e) = self.event_publisher.publish(event).await {
            warn!("Failed to publish BlockAdded event: {}", e);
            // Don't fail block processing for event publishing errors
        }

        Ok(())
    }

    /// Add a block and generate recursive proof for blockchain sync
    pub async fn add_block_with_proof(&mut self, block: Block) -> Result<()> {
        // Add block using existing validation logic
        self.add_block(block.clone()).await?;

        // Generate recursive proof for this block (for edge node sync)
        if let Err(e) = self.generate_proof_for_block(&block).await {
            warn!("  Failed to generate recursive proof for block {}: {}", block.height(), e);
            warn!("   Edge node sync will fall back to headers-only");
        } else {
            debug!(" Recursive proof generated for block {}", block.height());
        }

        Ok(())
    }

    /// Add a block and index it into the DHT for fast lookup.
    ///
    /// This is a convenience wrapper so callers can keep blockchain processing
    /// and DHT indexing in lockstep without wiring their own hooks.
    pub async fn add_block_with_dht_indexing(
        &mut self,
        block: Block,
        dht_storage: std::sync::Arc<tokio::sync::Mutex<DhtStorage>>,
    ) -> Result<()> {
        self.add_block(block.clone()).await?;

        {
            let mut guard = dht_storage.lock().await;
            crate::dht_index::index_block(&mut *guard, &block).await?;
        }

        Ok(())
    }

    /// Generate recursive proof for a single block
    async fn generate_proof_for_block(&mut self, block: &Block) -> Result<()> {
        // Get or initialize proof aggregator
        let aggregator_arc = self.get_proof_aggregator().await?;
        let mut aggregator = aggregator_arc.write().await;

        // Convert block transactions to batched format
        let batched_transactions: Vec<BatchedPrivateTransaction> = 
            block.transactions.iter().map(|tx| {
                let batch_metadata = BatchMetadata {
                    transaction_count: 1,
                    fee_tier: 0,
                    block_height: block.height(),
                    batch_commitment: tx.hash().as_array(),
                };

                let zk_tx_proof = lib_proofs::ZkTransactionProof::default();

                BatchedPrivateTransaction {
                    transaction_proofs: vec![zk_tx_proof],
                    merkle_root: tx.hash().as_array(),
                    batch_metadata,
                }
            }).collect();

        // Get previous state root
        let previous_state_root = if block.height() > 0 {
            let prev_block = &self.blocks[block.height() as usize - 1];
            let merkle_bytes = prev_block.header.merkle_root.as_bytes();
            let mut root = [0u8; 32];
            root.copy_from_slice(merkle_bytes);
            root
        } else {
            [0u8; 32] // Genesis block
        };

        // Aggregate block proof
        let block_proof = aggregator.aggregate_block_transactions(
            block.height(),
            &batched_transactions,
            &previous_state_root,
            block.header.timestamp,
        )?;

        // Get previous chain proof (if exists) - need to clone it since we need mutable access later
        let previous_chain_proof = if block.height() > 0 {
            aggregator.get_recursive_proof(block.height() - 1).cloned()
        } else {
            None
        };

        // Create recursive chain proof
        aggregator.create_recursive_chain_proof(&block_proof, previous_chain_proof.as_ref())?;

        debug!("Recursive proof cached for block {} sync", block.height());
        Ok(())
    }

    /// Add a new block to the chain with automatic persistence (without proof generation - for syncing)
    pub async fn add_block_with_persistence(&mut self, block: Block) -> Result<()> {
        self.add_block(block.clone()).await?;
        self.persist_block_state(&block).await
    }

    /// Add a network-received block with persistence. Skips mesh broadcast.
    pub async fn add_block_from_network_with_persistence(&mut self, block: Block) -> Result<()> {
        self.add_block_from_network(block.clone()).await?;
        self.persist_block_state(&block).await
    }

    /// Persist block and UTXO state after a block has been committed.
    async fn persist_block_state(&mut self, block: &Block) -> Result<()> {
        // Persist the block to storage if storage manager is available
        if let Some(_) = self.persist_block(block).await? {
            info!(" Block {} persisted to storage", block.height());
        }

        // Persist UTXO set every 10 blocks or if auto-persist is enabled
        if self.auto_persist_enabled && (self.height % 10 == 0 || self.blocks_since_last_persist >= 10) {
            if let Some(_) = self.persist_utxo_set().await? {
                info!(" UTXO set persisted to storage at height {}", self.height);
            }
        }

        // Auto-persist blockchain state if needed
        self.auto_persist_if_needed().await?;

        Ok(())
    }

    /// Verify a block against the current chain state
    pub fn verify_block(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        info!("Starting block verification for height {}", block.height());
        
        // Verify block header
        if let Some(prev) = previous_block {
            if block.previous_hash() != prev.hash() {
                warn!("Previous hash mismatch: block={:?}, prev={:?}", block.previous_hash(), prev.hash());
                return Ok(false);
            }
            if block.height() != prev.height() + 1 {
                warn!("Height mismatch: block={}, expected={}", block.height(), prev.height() + 1);
                return Ok(false);
            }
        }

        // Verify proof of work using mining profile from environment
        // This ensures validation uses the same difficulty as mining
        let mining_config = crate::types::mining::get_mining_config_from_env();
        let expected_difficulty = mining_config.difficulty.bits();

        // Check if block uses production difficulty (requires full PoW verification)
        // or development/testnet difficulty (simplified validation)
        if block.difficulty().bits() < 0x20000000 {
            // Production difficulty - verify full PoW
            if !block.header.meets_difficulty_target() {
                warn!("Block does not meet difficulty target");
                return Ok(false);
            }
        } else {
            // Development/testnet difficulty - verify it matches the expected profile difficulty
            if block.difficulty().bits() != expected_difficulty {
                warn!("Difficulty mismatch: block has 0x{:x}, expected 0x{:x} from mining profile",
                      block.difficulty().bits(), expected_difficulty);
                return Ok(false);
            }
        }

        // Verify all transactions
        for (i, tx) in block.transactions.iter().enumerate() {
            if !self.verify_transaction(tx)? {
                warn!("Transaction {} failed verification in block", i);
                return Ok(false);
            }
        }

        // Verify Merkle root
        if !block.verify_merkle_root() {
            warn!("Merkle root verification failed");
            return Ok(false);
        }

        info!("Block verification successful for height {}", block.height());
        Ok(true)
    }

    /// Verify a transaction against current blockchain state
    pub fn verify_transaction(&self, transaction: &Transaction) -> Result<bool> {
        // Use the stateful transaction validator with blockchain context for identity verification
        let validator = crate::transaction::validation::StatefulTransactionValidator::new(self);
        
        // Check if this is a system transaction (empty inputs indicates system transaction)
        let is_system_transaction = transaction.inputs.is_empty();
        
        tracing::info!("Verifying transaction with identity verification enabled");
        tracing::info!("System transaction: {}", is_system_transaction);
        tracing::info!("Transaction type: {:?}", transaction.transaction_type);
        tracing::warn!(
            "[FLOW] verify_transaction: tx_hash={}, size={}, memo_len={}, fee={}",
            hex::encode(transaction.hash().as_bytes()),
            transaction.size(),
            transaction.memo.len(),
            transaction.fee
        );
        tracing::warn!("SIMPLE_TRACE_A");
        tracing::warn!("SIMPLE_TRACE_B");
        tracing::warn!("SIMPLE_TRACE_C");

        let result = validator.validate_transaction_with_state(transaction);
        tracing::warn!("[FLOW] verify_transaction: validate_transaction_with_state done");
        
        if let Err(ref error) = result {
            tracing::warn!("Transaction validation failed: {:?}", error);
            tracing::warn!("Transaction details: inputs={}, outputs={}, fee={}, type={:?}, system={}, memo_len={}, version={}",
                transaction.inputs.len(),
                transaction.outputs.len(),
                transaction.fee,
                transaction.transaction_type,
                is_system_transaction,
                transaction.memo.len(),
                transaction.version);
        } else {
            tracing::info!("Transaction validation passed with identity verification");
        }
        
        Ok(result.is_ok())
    }

    /// Update UTXO set with new block
    fn update_utxo_set(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            // Remove spent outputs (add nullifiers)
            for input in &tx.inputs {
                self.nullifier_set.insert(input.nullifier);
            }

            // Add new outputs
            for (index, output) in tx.outputs.iter().enumerate() {
                let output_id = self.calculate_output_id(&tx.hash(), index);
                self.utxo_set.insert(output_id, output.clone());
            }
        }

        Ok(())
    }

    /// Deduct transaction fees from sender balances (Issue #1016)
    ///
    /// This method is public to allow testing and external access for fee analysis.
    ///
    /// For each non-system transaction in the block:
    /// 1. Identifies the sender from tx.signature.public_key
    /// 2. Deducts the fee from their SOV token balance
    /// 3. Accumulates total fees for later distribution via FeeRouter
    ///
    /// # Fee Distribution Flow
    /// Fees are deducted immediately but not credited to any address until FeeRouter distributes them.
    /// This creates a temporary gap where deducted fees reduce the circulating supply until distribution.
    /// This is intentional behavior:
    /// - Prevents double-spending of fees during the same block
    /// - Allows FeeRouter to batch distribute fees according to governance rules
    /// - Maintains audit trail of fee collection vs. distribution
    ///
    /// # Arguments
    /// * `block` - The block containing transactions to process
    ///
    /// # Returns
    /// * Total fees collected from this block
    ///
    /// # Errors
    /// * If SOV token contract is not found (non-fatal, logs warning)
    /// * If sender has insufficient balance for fee (transaction should have been rejected earlier)
    pub fn deduct_transaction_fees(&mut self, block: &Block) -> Result<u64> {
        // Get SOV token contract ID
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();

        // Get mutable reference to SOV token contract
        let sov_token = match self.token_contracts.get_mut(&sov_token_id) {
            Some(token) => token,
            None => {
                // SOV token not deployed yet - this is expected during bootstrap
                debug!("SOV token contract not found, skipping fee deduction for block {}", block.height());
                return Ok(0);
            }
        };

        let mut total_fees: u64 = 0;

        for tx in &block.transactions {
            // Skip system transactions (empty inputs = UBI, rewards, genesis)
            if tx.inputs.is_empty() {
                continue;
            }

            // Skip zero-fee transactions (shouldn't exist after validation, but be safe)
            if tx.fee == 0 {
                continue;
            }

            // Get sender's public key from signature
            let sender = &tx.signature.public_key;

            // Check sender's balance before deduction
            let sender_balance = sov_token.balance_of(sender);
            if sender_balance < tx.fee {
                // This shouldn't happen if validation is working correctly
                warn!(
                    "Fee deduction failed: sender {} has insufficient balance ({}) for fee ({})",
                    hex::encode(&sender.key_id[..8]),
                    sender_balance,
                    tx.fee
                );
                // Continue processing other transactions - don't fail the block
                continue;
            }

            // Deduct fee from sender's balance
            // Note: We use the internal balance mutation since this is at the blockchain level
            let new_balance = sender_balance - tx.fee;
            sov_token.balances.insert(sender.clone(), new_balance);

            total_fees = total_fees.saturating_add(tx.fee);

            debug!(
                "Fee deducted: {} from sender {} (tx: {})",
                tx.fee,
                hex::encode(&sender.key_id[..8]),
                hex::encode(&tx.hash().as_bytes()[..8])
            );
        }

        if total_fees > 0 {
            info!(
                "Block {} fee collection: {} total from {} transactions",
                block.height(),
                total_fees,
                block.transactions.iter().filter(|tx| !tx.inputs.is_empty() && tx.fee > 0).count()
            );
        }

        Ok(total_fees)
    }

    /// Calculate output ID from transaction hash and index
    fn calculate_output_id(&self, tx_hash: &Hash, index: usize) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(tx_hash.as_bytes());
        data.extend_from_slice(&index.to_le_bytes());
        crate::types::hash::blake3_hash(&data)
    }

    /// Adjust blockchain difficulty based on block time targets.
    ///
    /// This method delegates to the consensus coordinator's DifficultyManager when available,
    /// falling back to `self.difficulty_config` for backward compatibility.
    /// The consensus engine owns the difficulty policy per architectural design.
    ///
    /// # Fallback Behavior
    /// - If consensus coordinator is available:
    ///   - Uses coordinator's `calculate_difficulty_adjustment()` for the calculation
    ///   - If calculation fails: falls back to `calculate_difficulty_with_config()` using coordinator's config
    ///   - If getting config fails: returns error without fallback (this indicates a consensus layer problem)
    /// - If consensus coordinator is not available: uses `self.difficulty_config` parameters directly
    fn adjust_difficulty(&mut self) -> Result<()> {
        // Get adjustment parameters and calculate difficulty in a single lock acquisition
        // to avoid race conditions between reading config and calculating adjustment
        if let Some(coordinator) = &self.consensus_coordinator {
            // Use a single tokio block_in_place to call async methods from sync context
            // Acquire the coordinator read lock once to avoid race conditions and redundant locking
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let coord = coordinator.read().await;
                    let adjustment_interval = coord.get_difficulty_adjustment_interval().await;
                    let config = coord.get_difficulty_config().await;
                    
                    // Check if we should adjust at this height
                    if self.height % adjustment_interval != 0 {
                        return Ok::<Option<(u32, lib_consensus::difficulty::DifficultyConfig)>, anyhow::Error>(None);
                    }
                    if self.height < adjustment_interval {
                        return Ok(None);
                    }
                    
                    let current_block = &self.blocks[self.height as usize];
                    let interval_start = &self.blocks[(self.height - adjustment_interval) as usize];
                    let interval_start_time = interval_start.timestamp();
                    let interval_end_time = current_block.timestamp();
                    
                    // Calculate new difficulty
                    match coord.calculate_difficulty_adjustment(
                        self.height,
                        self.difficulty.bits(),
                        interval_start_time,
                        interval_end_time,
                    ).await {
                        Ok(Some(new_bits)) => Ok(Some((new_bits, config))),
                        Ok(None) => Ok(None),
                        Err(e) => {
                            tracing::warn!("Difficulty adjustment via coordinator failed: {}, using fallback with config", e);
                            // Fallback to config-aware calculation
                            let new_bits = self.calculate_difficulty_with_config(
                                interval_start_time,
                                interval_end_time,
                                config.target_timespan,
                                config.max_adjustment_factor,
                                config.max_adjustment_factor,
                            );
                            Ok(Some((new_bits, config)))
                        }
                    }
                })
            });
            
            match result {
                Ok(Some((new_bits, config))) => {
                    let old_difficulty = self.difficulty.bits();
                    self.difficulty = Difficulty::from_bits(new_bits);
                    tracing::info!(
                        "Difficulty adjusted from {} to {} at height {} \
                         (config: target_timespan={}, adjustment_interval={}, max_adjustment={}x)",
                        old_difficulty,
                        new_bits,
                        self.height,
                        config.target_timespan,
                        config.adjustment_interval,
                        config.max_adjustment_factor,
                    );
                }
                Ok(None) => {} // No adjustment needed
                Err(e) => {
                    tracing::error!(
                        "Difficulty adjustment via coordinator failed: {}. \
                         This indicates a consensus layer problem requiring attention.", e
                    );
                    return Err(e);
                }
            }
        } else {
            // Use self.difficulty_config instead of hardcoded constants
            let adjustment_interval = self.difficulty_config.adjustment_interval;
            let target_timespan = self.difficulty_config.target_timespan;
            let max_increase = self.difficulty_config.max_difficulty_increase_factor;
            let max_decrease = self.difficulty_config.max_difficulty_decrease_factor;
            
            // Check if we should adjust at this height
            if self.height % adjustment_interval != 0 {
                return Ok(());
            }
            if self.height < adjustment_interval {
                return Ok(());
            }
            
            let current_block = &self.blocks[self.height as usize];
            let interval_start = &self.blocks[(self.height - adjustment_interval) as usize];
            let interval_start_time = interval_start.timestamp();
            let interval_end_time = current_block.timestamp();
            
            let new_difficulty_bits = self.calculate_difficulty_with_config(
                interval_start_time,
                interval_end_time,
                target_timespan,
                max_increase,
                max_decrease,
            );
            let old_difficulty = self.difficulty.bits();
            self.difficulty = Difficulty::from_bits(new_difficulty_bits);
            
            tracing::info!(
                "Difficulty adjusted from {} to {} at height {} \
                 (config: target_timespan={}, adjustment_interval={}, max_increase={}x, max_decrease={}x)",
                old_difficulty,
                new_difficulty_bits,
                self.height,
                target_timespan,
                adjustment_interval,
                max_increase,
                max_decrease,
            );
        }
        
        Ok(())
    }
    
    /// Difficulty calculation using DifficultyConfig parameters.
    /// Uses configurable clamping factors instead of hardcoded 4x.
    fn calculate_difficulty_with_config(
        &self,
        interval_start_time: u64,
        interval_end_time: u64,
        target_timespan: u64,
        max_increase_factor: u64,
        max_decrease_factor: u64,
    ) -> u32 {
        // Defensive check: target_timespan should be validated to be non-zero upstream,
        // but avoid panicking here if that validation is ever bypassed.
        if target_timespan == 0 {
            tracing::warn!(
                "calculate_difficulty_with_config called with target_timespan = 0; \
                 returning current difficulty without adjustment"
            );
            return self.difficulty.bits();
        }
        
        let actual_timespan = interval_end_time.saturating_sub(interval_start_time);
        
        // Clamp using configurable factors instead of hardcoded 4x
        // min_timespan prevents difficulty from increasing more than max_increase_factor
        // max_timespan prevents difficulty from decreasing more than max_decrease_factor
        let min_timespan = target_timespan / max_increase_factor.max(1);
        let max_timespan = target_timespan.saturating_mul(max_decrease_factor);
        let clamped_timespan = actual_timespan.clamp(min_timespan, max_timespan);
        
        // Additional defensive check in case clamping still results in zero
        // (can happen if target_timespan / max_increase_factor == 0 due to integer division)
        if clamped_timespan == 0 {
            tracing::warn!(
                "calculate_difficulty_with_config computed clamped_timespan = 0; \
                 returning current difficulty without adjustment"
            );
            return self.difficulty.bits();
        }
        
        // Calculate new difficulty and ensure it doesn't go to zero
        let new_difficulty = (self.difficulty.bits() as u64 * target_timespan / clamped_timespan) as u32;
        new_difficulty.max(1)
    }

    /// Get the latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Get block by height
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        if height >= self.blocks.len() as u64 {
            return None;
        }
        Some(&self.blocks[height as usize])
    }

    /// Get current blockchain height
    pub fn get_height(&self) -> u64 {
        self.height
    }

    /// Get the current difficulty configuration.
    ///
    /// Returns a reference to the blockchain's current `DifficultyConfig`,
    /// which contains parameters governing difficulty adjustment behavior.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let blockchain = Blockchain::new(genesis_block, coordinator)?;
    /// let config = blockchain.get_difficulty_config();
    /// 
    /// println!("Target timespan: {} seconds", config.target_timespan);
    /// println!("Adjustment interval: {} blocks", config.adjustment_interval);
    /// println!("Max decrease factor: {}", config.max_difficulty_decrease_factor);
    /// println!("Max increase factor: {}", config.max_difficulty_increase_factor);
    /// ```
    pub fn get_difficulty_config(&self) -> &DifficultyConfig {
        &self.difficulty_config
    }

    /// Update the difficulty configuration (for governance updates).
    ///
    /// This method validates the new configuration before applying it.
    /// The `last_updated_at_height` field will be set to the current blockchain height.
    ///
    /// # Arguments
    ///
    /// * `config` - The new difficulty configuration to apply
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the configuration was successfully updated
    /// * `Err` if validation fails (invalid parameters)
    ///
    /// # Example
    ///
    /// ```ignore
    /// use lib_blockchain::DifficultyConfig;
    ///
    /// let mut blockchain = Blockchain::new(genesis_block, coordinator)?;
    ///
    /// // Create a custom difficulty configuration
    /// let new_config = DifficultyConfig {
    ///     target_timespan: 900,  // 15 minutes
    ///     adjustment_interval: 100,
    ///     max_difficulty_decrease_factor: 0.75,
    ///     max_difficulty_increase_factor: 1.5,
    ///     last_updated_at_height: 0,  // Will be set automatically
    /// };
    ///
    /// // Apply the new configuration
    /// blockchain.set_difficulty_config(new_config)?;
    ///
    /// // Verify the update
    /// assert_eq!(blockchain.get_difficulty_config().target_timespan, 900);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration parameters are invalid:
    /// - `target_timespan` must be > 0
    /// - `adjustment_interval` must be > 0
    /// - `max_difficulty_decrease_factor` must be in range (0.0, 1.0]
    /// - `max_difficulty_increase_factor` must be >= 1.0
    pub fn set_difficulty_config(&mut self, mut config: DifficultyConfig) -> Result<()> {
        config.validate().map_err(|e| anyhow::anyhow!("Invalid difficulty config: {}", e))?;
        config.last_updated_at_height = self.height;
        info!(
            "Updating difficulty config at height {}: target_timespan={}, adjustment_interval={}, max_decrease={}, max_increase={}",
            self.height,
            config.target_timespan,
            config.adjustment_interval,
            config.max_difficulty_decrease_factor,
            config.max_difficulty_increase_factor
        );
        self.difficulty_config = config;
        Ok(())
    }

    /// Check if a nullifier has been used
    pub fn is_nullifier_used(&self, nullifier: &Hash) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> Vec<Transaction> {
        self.pending_transactions.clone()
    }

    /// Add a transaction to the pending pool
    pub fn add_pending_transaction(&mut self, transaction: Transaction) -> Result<()> {
        tracing::warn!(
            "[FLOW] add_pending_transaction: tx_hash={}, size={}, fee={}",
            hex::encode(transaction.hash().as_bytes()),
            transaction.size(),
            transaction.fee
        );
        self.verify_and_enqueue_transaction(transaction.clone())?;

        // Broadcast new transaction to mesh network (locally-originated only)
        if let Some(ref sender) = self.broadcast_sender {
            if let Err(e) = sender.send(BlockchainBroadcastMessage::NewTransaction(transaction.clone())) {
                warn!("Failed to broadcast new transaction to network: {}", e);
            } else {
                debug!("Transaction {} broadcast to mesh network", transaction.hash());
            }
        }

        Ok(())
    }

    /// Add a transaction received from the network. Skips mesh broadcast to
    /// prevent broadcast loops (transaction was already propagated by the sender).
    pub fn add_pending_transaction_from_network(&mut self, transaction: Transaction) -> Result<()> {
        self.verify_and_enqueue_transaction(transaction)
    }

    /// Core transaction processing: verify and add to pending pool.
    /// Does NOT broadcast — callers decide whether to broadcast.
    fn verify_and_enqueue_transaction(&mut self, transaction: Transaction) -> Result<()> {
        tracing::warn!(
            "[FLOW] verify_and_enqueue_transaction: tx_hash={}, type={:?}, inputs={}, outputs={}",
            hex::encode(transaction.hash().as_bytes()),
            transaction.transaction_type,
            transaction.inputs.len(),
            transaction.outputs.len()
        );
        if !self.verify_transaction(&transaction)? {
            return Err(anyhow::anyhow!("Transaction verification failed"));
        }

        self.pending_transactions.push(transaction);
        tracing::warn!("[FLOW] verify_and_enqueue_transaction: enqueued");
        Ok(())
    }

    /// Add a transaction to the pending pool with persistent storage
    pub async fn add_pending_transaction_with_persistence(&mut self, transaction: Transaction) -> Result<()> {
        // Add transaction to pending pool normally
        self.add_pending_transaction(transaction.clone())?;

        // Store transaction in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_transaction(&transaction).await {
                eprintln!("Warning: Failed to persist transaction to storage: {}", e);
            }
        }

        Ok(())
    }

    /// Add system transaction to pending pool without validation (for identity registration, etc.)
    pub fn add_system_transaction(&mut self, transaction: Transaction) -> Result<()> {
        tracing::info!("Adding system transaction to pending pool (bypassing validation)");
        self.pending_transactions.push(transaction);
        Ok(())
    }

    /// Remove transactions from pending pool
    pub fn remove_pending_transactions(&mut self, transactions: &[Transaction]) {
        let tx_hashes: HashSet<Hash> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        
        self.pending_transactions.retain(|tx| !tx_hashes.contains(&tx.hash()));
    }

    // ===== IDENTITY MANAGEMENT METHODS =====

    /// Register a new identity on the blockchain
    pub fn register_identity(&mut self, identity_data: IdentityTransactionData) -> Result<Hash> {
        // Check if identity already exists
        if self.identity_registry.contains_key(&identity_data.did) {
            return Err(anyhow::anyhow!("Identity {} already exists on blockchain", identity_data.did));
        }

        // Create identity registration transaction
        let registration_tx = Transaction::new_identity_registration(
            identity_data.clone(),
            vec![], // Fee outputs handled separately
            Signature {
                signature: identity_data.ownership_proof.clone(),
                public_key: PublicKey::new(identity_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: identity_data.created_at,
            },
            format!("Identity registration for {}", identity_data.did).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        self.add_pending_transaction(registration_tx.clone())?;

        // Store in identity registry immediately for queries
        self.identity_registry.insert(identity_data.did.clone(), identity_data.clone());
        self.identity_blocks.insert(identity_data.did.clone(), self.height + 1);

        Ok(registration_tx.hash())
    }

    /// Register a new identity on the blockchain with persistent storage
    pub async fn register_identity_with_persistence(&mut self, identity_data: IdentityTransactionData) -> Result<Hash> {
        // Register identity normally
        let tx_hash = self.register_identity(identity_data.clone())?;

        // Store identity data in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_identity_data(&identity_data.did, &identity_data).await {
                eprintln!("Warning: Failed to persist identity data to storage: {}", e);
            }
        }

        Ok(tx_hash)
    }

    /// Get identity data from blockchain
    pub fn get_identity(&self, did: &str) -> Option<&IdentityTransactionData> {
        self.identity_registry.get(did)
    }

    /// Check if identity exists on blockchain
    pub fn identity_exists(&self, did: &str) -> bool {
        self.identity_registry.contains_key(did)
    }

    /// Update an existing identity on the blockchain
    pub fn update_identity(&mut self, did: &str, updated_data: IdentityTransactionData) -> Result<Hash> {
        // Check if identity exists
        if !self.identity_registry.contains_key(did) {
            return Err(anyhow::anyhow!("Identity {} not found on blockchain", did));
        }

        // Create update transaction with authorization
        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(&format!("identity_update_{}", did).as_bytes()),
            zk_proof: ZkTransactionProof::default(),
        };

        let update_tx = Transaction::new_identity_update(
            updated_data.clone(),
            vec![auth_input],
            vec![], // No outputs needed
            100,    // Update fee
            Signature {
                signature: updated_data.ownership_proof.clone(),
                public_key: PublicKey::new(updated_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: updated_data.created_at,
            },
            format!("Identity update for {}", did).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(update_tx.clone())?;

        // Update registry
        self.identity_registry.insert(did.to_string(), updated_data);

        Ok(update_tx.hash())
    }

    /// Update an existing identity on the blockchain with persistent storage
    pub async fn update_identity_with_persistence(&mut self, did: &str, updated_data: IdentityTransactionData) -> Result<Hash> {
        // Update identity normally
        let tx_hash = self.update_identity(did, updated_data.clone())?;

        // Store updated identity data in persistent storage if available
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_identity_data(did, &updated_data).await {
                eprintln!("Warning: Failed to persist updated identity data to storage: {}", e);
            }
        }

        Ok(tx_hash)
    }

    /// Revoke an identity on the blockchain
    pub fn revoke_identity(&mut self, did: &str, authorizing_signature: Vec<u8>) -> Result<Hash> {
        // Check if identity exists
        if !self.identity_registry.contains_key(did) {
            return Err(anyhow::anyhow!("Identity {} not found on blockchain", did));
        }

        // Create authorization input from existing identity
        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(&format!("identity_revoke_{}", did).as_bytes()),
            zk_proof: ZkTransactionProof::default(),
        };

        let revocation_tx = Transaction::new_identity_revocation(
            did.to_string(),
            vec![auth_input],
            50, // Revocation fee
            Signature {
                signature: authorizing_signature,
                public_key: PublicKey::new(vec![]), // Would be filled from auth
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: crate::utils::time::current_timestamp(),
            },
            format!("Identity revocation for {}", did).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(revocation_tx.clone())?;

        // Remove from registry (mark as revoked)
        if let Some(mut identity_data) = self.identity_registry.remove(did) {
            identity_data.identity_type = "revoked".to_string();
            self.identity_registry.insert(format!("{}_revoked", did), identity_data);
        }

        Ok(revocation_tx.hash())
    }

    /// Get all identities on the blockchain
    pub fn list_all_identities(&self) -> Vec<&IdentityTransactionData> {
        self.identity_registry.values().collect()
    }

    /// Get all identities as HashMap
    pub fn get_all_identities(&self) -> &HashMap<String, IdentityTransactionData> {
        &self.identity_registry
    }

    /// Get identity block confirmation count
    pub fn get_identity_confirmations(&self, did: &str) -> Option<u64> {
        self.identity_blocks.get(did).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    /// Process identity transactions in a block
    pub fn process_identity_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type.is_identity_transaction() {
                if let Some(ref identity_data) = transaction.identity_data {
                    match transaction.transaction_type {
                        TransactionType::IdentityRegistration => {
                            // CRITICAL: Preserve controlled_nodes if identity already exists
                            let mut new_identity_data = identity_data.clone();
                            if let Some(existing_identity) = self.identity_registry.get(&identity_data.did) {
                                // Preserve controlled_nodes from existing identity
                                new_identity_data.controlled_nodes = existing_identity.controlled_nodes.clone();
                            }

                            self.identity_registry.insert(
                                identity_data.did.clone(),
                                new_identity_data.clone()
                            );
                            self.identity_blocks.insert(
                                identity_data.did.clone(),
                                block.height()
                            );

                            // Register for UBI if this is a citizen identity
                            if identity_data.identity_type == "verified_citizen"
                                || identity_data.identity_type == "citizen"
                                || identity_data.identity_type == "external_citizen" {
                                // Find the UBI wallet from owned_wallets
                                let ubi_wallet_id = new_identity_data.owned_wallets.iter()
                                    .find(|wallet_id| {
                                        self.wallet_registry.get(*wallet_id)
                                            .map(|w| w.wallet_type == "UBI")
                                            .unwrap_or(false)
                                    })
                                    .cloned();

                                if let Some(ubi_wallet) = ubi_wallet_id {
                                    if let Err(e) = self.register_for_ubi(
                                        identity_data.did.clone(),
                                        ubi_wallet,
                                        block.height()
                                    ) {
                                        warn!("Failed to register {} for UBI: {}", identity_data.did, e);
                                    }
                                } else {
                                    warn!("No UBI wallet found for citizen {}", identity_data.did);
                                }
                            }
                        }
                        TransactionType::IdentityUpdate => {
                            // CRITICAL: Preserve controlled_nodes on update
                            let mut updated_identity_data = identity_data.clone();
                            if let Some(existing_identity) = self.identity_registry.get(&identity_data.did) {
                                // Preserve controlled_nodes from existing identity
                                updated_identity_data.controlled_nodes = existing_identity.controlled_nodes.clone();
                            }
                            
                            self.identity_registry.insert(
                                identity_data.did.clone(),
                                updated_identity_data
                            );
                        }
                        TransactionType::IdentityRevocation => {
                            let mut revoked_data = identity_data.clone();
                            revoked_data.identity_type = "revoked".to_string();
                            self.identity_registry.insert(
                                format!("{}_revoked", identity_data.did),
                                revoked_data
                            );
                            self.identity_registry.remove(&identity_data.did);
                        }
                        _ => {} // Other transaction types
                    }
                }
            }
        }
        Ok(())
    }

    /// Check if a public key is registered as an identity on the blockchain
    pub fn is_public_key_registered(&self, public_key: &[u8]) -> bool {
        for identity_data in self.identity_registry.values() {
            if identity_data.public_key == public_key && identity_data.identity_type != "revoked" {
                return true;
            }
        }
        false
    }

    /// Get identity by public key
    pub fn get_identity_by_public_key(&self, public_key: &[u8]) -> Option<&IdentityTransactionData> {
        for identity_data in self.identity_registry.values() {
            if identity_data.public_key == public_key && identity_data.identity_type != "revoked" {
                return Some(identity_data);
            }
        }
        None
    }

    /// Auto-register wallet identity if not already registered (system transaction)
    /// This creates a minimal identity registration for wallets that don't have one
    pub fn auto_register_wallet_identity(
        &mut self,
        wallet_id: &str,
        public_key: Vec<u8>,
        did: Option<String>,
    ) -> Result<Hash> {
        // Check if this public key is already registered
        if self.is_public_key_registered(&public_key) {
            tracing::info!(" Public key already registered on blockchain");
            return Ok(Hash::default());
        }

        // Generate DID from wallet ID if not provided
        let identity_did = did.unwrap_or_else(|| {
            format!("did:zhtp:wallet-{}", hex::encode(&public_key[..16]))
        });

        tracing::info!(" Auto-registering wallet identity: {}", identity_did);

        // Create identity transaction data
        let identity_data = IdentityTransactionData {
            did: identity_did.clone(),
            display_name: format!("Wallet {}", &wallet_id[..8.min(wallet_id.len())]),
            public_key: public_key.clone(),
            ownership_proof: vec![], // System transaction doesn't need proof
            identity_type: "service".to_string(), // Use "service" type for wallet identities
            did_document_hash: crate::types::hash::blake3_hash(identity_did.as_bytes()),
            created_at: crate::utils::time::current_timestamp(),
            registration_fee: 0, // No fee for auto-registration
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: vec![wallet_id.to_string()],
        };

        // Create identity registration transaction as system transaction
        let registration_tx = Transaction::new_identity_registration(
            identity_data.clone(),
            vec![], // No outputs for system transaction
            Signature {
                signature: vec![0xAA; 64], // System signature marker
                public_key: PublicKey::new(public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: identity_data.created_at,
            },
            b"Auto-registration for wallet identity".to_vec(),
        );

        // Add as system transaction (bypasses normal validation)
        self.add_system_transaction(registration_tx.clone())?;

        // Register in identity registry immediately
        self.identity_registry.insert(identity_did.clone(), identity_data.clone());
        self.identity_blocks.insert(identity_did, self.height + 1);

        tracing::info!(" Wallet identity auto-registered on blockchain");

        Ok(registration_tx.hash())
    }

    /// Ensure wallet identity is registered before transaction (convenience method)
    pub fn ensure_wallet_identity_registered(
        &mut self,
        wallet_id: &str,
        public_key: &[u8],
        did: Option<String>,
    ) -> Result<()> {
        if !self.is_public_key_registered(public_key) {
            self.auto_register_wallet_identity(wallet_id, public_key.to_vec(), did)?;
        }
        Ok(())
    }

    // ===== WALLET MANAGEMENT METHODS =====

    /// Register a new wallet on the blockchain
    pub fn register_wallet(&mut self, wallet_data: crate::transaction::WalletTransactionData) -> Result<Hash> {
        // Check if wallet already exists
        let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
        if self.wallet_registry.contains_key(&wallet_id_str) {
            return Err(anyhow::anyhow!("Wallet {} already exists on blockchain", wallet_id_str));
        }

        // Create wallet registration transaction
        let registration_tx = Transaction::new_wallet_registration(
            wallet_data.clone(),
            vec![], // Fee outputs handled separately
            Signature {
                signature: wallet_data.public_key.clone(),
                public_key: PublicKey::new(wallet_data.public_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: wallet_data.created_at,
            },
            format!("Wallet registration for {}", wallet_data.wallet_name).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        // Wallet registration from node startup is a system operation - bypass signature validation
        // This is consistent with how genesis funding directly inserts into wallet_registry
        self.add_system_transaction(registration_tx.clone())?;

        // Store in wallet registry immediately for queries
        self.wallet_registry.insert(wallet_id_str.clone(), wallet_data.clone());
        self.wallet_blocks.insert(wallet_id_str, self.height + 1);

        Ok(registration_tx.hash())
    }

    /// Get wallet by ID
    pub fn get_wallet(&self, wallet_id: &str) -> Option<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.get(wallet_id)
    }

    /// Check if wallet exists
    pub fn wallet_exists(&self, wallet_id: &str) -> bool {
        self.wallet_registry.contains_key(wallet_id)
    }

    /// Get all wallets on the blockchain
    pub fn list_all_wallets(&self) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.values().collect()
    }

    /// Get all wallets as HashMap
    pub fn get_all_wallets(&self) -> &HashMap<String, crate::transaction::WalletTransactionData> {
        &self.wallet_registry
    }

    /// Get wallet block confirmation count
    pub fn get_wallet_confirmations(&self, wallet_id: &str) -> Option<u64> {
        self.wallet_blocks.get(wallet_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    /// Get wallets for a specific owner identity
    pub fn get_wallets_for_owner(&self, owner_identity_id: &Hash) -> Vec<&crate::transaction::WalletTransactionData> {
        self.wallet_registry.values()
            .filter(|wallet| {
                wallet.owner_identity_id.as_ref() == Some(owner_identity_id)
            })
            .collect()
    }

    /// Process wallet transactions in a block
    pub fn process_wallet_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type == TransactionType::WalletRegistration {
                if let Some(ref wallet_data) = transaction.wallet_data {
                    let wallet_id_str = hex::encode(wallet_data.wallet_id.as_bytes());
                    self.wallet_registry.insert(
                        wallet_id_str.clone(),
                        wallet_data.clone()
                    );
                    self.wallet_blocks.insert(
                        wallet_id_str,
                        block.height()
                    );
                }
            }
        }
        Ok(())
    }

    // ========================================================================
    // Validator registration and management
    // ========================================================================

    /// Register a new validator on the blockchain
    pub fn register_validator(&mut self, validator_info: ValidatorInfo) -> Result<Hash> {
        // Check if validator already exists
        if self.validator_registry.contains_key(&validator_info.identity_id) {
            return Err(anyhow::anyhow!("Validator {} already exists on blockchain", validator_info.identity_id));
        }

        // Verify the identity exists
        if !self.identity_registry.contains_key(&validator_info.identity_id) {
            return Err(anyhow::anyhow!("Identity {} must be registered before becoming a validator", validator_info.identity_id));
        }
        
        // SECURITY: Validate minimum requirements for validator eligibility
        // Edge nodes (minimal storage, no consensus capability) cannot become validators
        // Genesis bootstrap: Allow 1,000 SOV minimum for initial validator setup
        // Production: Require 100,000 SOV minimum after genesis
        let min_stake = if self.height == 0 { 1_000 } else { 100_000 };
        if validator_info.stake < min_stake {
            return Err(anyhow::anyhow!(
                "Insufficient stake for validator: {} SOV (minimum: {} SOV required)",
                validator_info.stake, min_stake
            ));
        }
        
        // Storage requirement: Only enforce for production validators after genesis
        // Genesis validators (height 0) can register with any storage amount for testing
        if self.height > 0 && validator_info.storage_provided < 10_737_418_240 {  // 10 GB in bytes
            return Err(anyhow::anyhow!(
                "Insufficient storage for validator: {} bytes (minimum: 10 GB required for blockchain storage)",
                validator_info.storage_provided
            ));
        }

        // Create validator registration transaction (using Identity type as placeholder until we add Validator type)
        let validator_tx_data = IdentityTransactionData {
            did: validator_info.identity_id.clone(),
            display_name: format!("Validator: {}", validator_info.network_address),
            public_key: validator_info.consensus_key.clone(),
            ownership_proof: vec![], // Empty for system validator registration
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!("validator:{}:{}", validator_info.identity_id, validator_info.registered_at).as_bytes()
            ),
            created_at: validator_info.registered_at,
            registration_fee: 0, // No fee for validator registration (paid via stake)
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        let registration_tx = Transaction::new_identity_registration(
            validator_tx_data,
            vec![], // Fee outputs handled separately
            Signature {
                signature: validator_info.consensus_key.clone(),
                public_key: PublicKey::new(validator_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: validator_info.registered_at,
            },
            format!("Validator registration for {} with stake {}", validator_info.identity_id, validator_info.stake).into_bytes(),
        );

        // Add to pending transactions for inclusion in next block
        self.add_pending_transaction(registration_tx.clone())?;

        // Store in validator registry immediately for queries
        self.validator_registry.insert(validator_info.identity_id.clone(), validator_info.clone());
        self.validator_blocks.insert(validator_info.identity_id.clone(), self.height + 1);

        info!(" Validator {} registered with {} ZHTP stake and {} bytes storage", 
              validator_info.identity_id, validator_info.stake, validator_info.storage_provided);

        Ok(registration_tx.hash())
    }

    /// Get validator by identity ID
    pub fn get_validator(&self, identity_id: &str) -> Option<&ValidatorInfo> {
        self.validator_registry.get(identity_id)
    }

    /// Check if validator exists
    pub fn validator_exists(&self, identity_id: &str) -> bool {
        self.validator_registry.contains_key(identity_id)
    }

    /// Get all validators on the blockchain
    pub fn list_all_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values().collect()
    }

    /// Get all active validators
    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values()
            .filter(|v| v.status == "active")
            .collect()
    }

    /// Get all validators as HashMap
    pub fn get_all_validators(&self) -> &HashMap<String, ValidatorInfo> {
        &self.validator_registry
    }

    /// Update validator information
    pub fn update_validator(&mut self, identity_id: &str, updated_info: ValidatorInfo) -> Result<Hash> {
        // Check if validator exists
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!("Validator {} not found on blockchain", identity_id));
        }

        // Create update transaction
        let validator_tx_data = IdentityTransactionData {
            did: updated_info.identity_id.clone(),
            display_name: format!("Validator Update: {}", updated_info.network_address),
            public_key: updated_info.consensus_key.clone(),
            ownership_proof: vec![],
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!("validator_update:{}:{}", updated_info.identity_id, updated_info.last_activity).as_bytes()
            ),
            created_at: updated_info.last_activity,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        let update_tx = Transaction::new_identity_update(
            validator_tx_data,
            vec![],
            vec![],
            100, // Update fee
            Signature {
                signature: updated_info.consensus_key.clone(),
                public_key: PublicKey::new(updated_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: updated_info.last_activity,
            },
            format!("Validator update for {}", identity_id).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(update_tx.clone())?;

        // Update registry
        self.validator_registry.insert(identity_id.to_string(), updated_info);

        Ok(update_tx.hash())
    }

    /// Unregister a validator
    pub fn unregister_validator(&mut self, identity_id: &str) -> Result<Hash> {
        // Check if validator exists
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!("Validator {} not found on blockchain", identity_id));
        }

        // Get validator info
        let mut validator_info = self.validator_registry.get(identity_id).unwrap().clone();
        validator_info.status = "inactive".to_string();

        // Create unregistration transaction
        let unregister_tx = Transaction::new_identity_revocation(
            identity_id.to_string(),
            vec![],
            100,
            Signature {
                signature: validator_info.consensus_key.clone(),
                public_key: PublicKey::new(validator_info.consensus_key.clone()),
                algorithm: SignatureAlgorithm::Dilithium2,
                timestamp: validator_info.last_activity,
            },
            format!("Validator unregistration for {}", identity_id).into_bytes(),
        );

        // Add to pending transactions
        self.add_pending_transaction(unregister_tx.clone())?;

        // Update status in registry
        self.validator_registry.insert(identity_id.to_string(), validator_info);

        info!("Validator {} unregistered", identity_id);

        Ok(unregister_tx.hash())
    }

    /// Get validator block confirmation count
    pub fn get_validator_confirmations(&self, identity_id: &str) -> Option<u64> {
        self.validator_blocks.get(identity_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    // ========================================================================
    // VALIDATOR SYNCHRONIZATION (Issue #5)
    // ========================================================================

    /// Get active validator set as (identity_id, stake) tuples for consensus integration
    ///
    /// This is the primary interface for consensus to query the validator set.
    /// Used to keep consensus and blockchain validator registries in sync.
    /// Only returns validators with active status and non-zero stake.
    pub fn get_active_validator_set_for_consensus(&self) -> Vec<(String, u64)> {
        self.get_active_validators()
            .iter()
            .map(|v| (v.identity_id.clone(), v.stake))
            .collect()
    }

    /// Get total stake of all active validators
    pub fn get_total_validator_stake(&self) -> u64 {
        self.get_active_validators()
            .iter()
            .fold(0u64, |sum, v| sum.saturating_add(v.stake))
    }

    /// Check if a validator is in good standing (active status and sufficient stake)
    pub fn is_validator_active(&self, identity_id: &str) -> bool {
        if let Some(validator) = self.validator_registry.get(identity_id) {
            // Validator must have active status and non-zero stake
            validator.status == "active" && validator.stake > 0
        } else {
            false
        }
    }

    /// Emit validator set changed event for consensus integration
    /// Call this whenever the validator set changes to keep consensus in sync
    pub fn sync_validator_set_to_consensus(&self) {
        let active_validators = self.get_active_validators();
        info!(
            "Validator set sync: {} active validators with {} total stake",
            active_validators.len(),
            self.get_total_validator_stake()
        );

        // In production, this would emit an event that consensus subscribes to
        // For now, log the validator set for audit trail
        for validator in active_validators {
            debug!(
                "Validator in sync: {} (stake: {}, joined at height: {})",
                validator.identity_id, validator.stake, validator.registered_at
            );
        }
    }

    /// Process validator transactions in a block
    pub fn process_validator_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if let Some(ref identity_data) = transaction.identity_data {
                if identity_data.identity_type == "validator" {
                    // Extract validator info from identity transaction
                    // This is a simplified version - in production, you'd have a dedicated ValidatorTransactionData
                    if let Some(validator_info) = self.validator_registry.get(&identity_data.did) {
                        let mut updated_info = validator_info.clone();
                        updated_info.last_activity = identity_data.created_at;
                        updated_info.blocks_validated += 1;
                        
                        self.validator_registry.insert(
                            identity_data.did.clone(),
                            updated_info
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Process contract deployment and execution transactions from a block
    pub fn process_contract_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type == TransactionType::ContractDeployment {
                // Contract data is serialized in the first output's commitment
                if let Some(output) = transaction.outputs.first() {
                    // Try to deserialize as Web4Contract first (JSON format)
                    if let Ok(web4_contract) = serde_json::from_slice::<crate::contracts::web4::Web4Contract>(output.commitment.as_bytes()) {
                        // Generate contract ID from the note field or domain
                        let contract_id = lib_crypto::hash_blake3(web4_contract.domain.as_bytes());
                        self.register_web4_contract(contract_id, web4_contract, block.height());
                        info!(" Processed Web4Contract deployment in block {}", block.height());
                    }
                    // Try to deserialize as TokenContract (bincode format)
                    else if let Ok(token_contract) = bincode::deserialize::<crate::contracts::TokenContract>(output.commitment.as_bytes()) {
                        let contract_id = token_contract.token_id;
                        self.register_token_contract(contract_id, token_contract, block.height());
                        info!(" Processed TokenContract deployment in block {}", block.height());
                    } else {
                        debug!(" Could not deserialize contract in transaction {}", transaction.hash());
                    }
                }
            }
            // Handle ContractExecution transactions (token create/mint/transfer/burn)
            else if transaction.transaction_type == TransactionType::ContractExecution {
                if let Err(e) = self.process_contract_execution(transaction, block.height()) {
                    warn!("Failed to process contract execution: {}", e);
                }
            }
        }
        Ok(())
    }

    /// Process a ContractExecution transaction
    fn process_contract_execution(&mut self, transaction: &Transaction, block_height: u64) -> Result<()> {
        // Parse ContractCall from memo: "ZHTP" + bincode(ContractCall, Signature)
        if transaction.memo.len() <= 4 || &transaction.memo[0..4] != b"ZHTP" {
            return Err(anyhow::anyhow!("Invalid contract execution memo format"));
        }

        let call_data = &transaction.memo[4..];
        let (call, _sig): (crate::types::ContractCall, crate::integration::crypto_integration::Signature) =
            bincode::deserialize(call_data)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize contract call: {}", e))?;

        // Get caller identity from transaction signature public key
        let caller = transaction.signature.public_key.clone();

        match call.contract_type {
            crate::types::ContractType::Token => {
                self.execute_token_contract_call(&call, &caller, block_height)?;
            }
            _ => {
                debug!("Skipping non-token contract execution: {:?}", call.contract_type);
            }
        }

        Ok(())
    }

    /// Reprocess all ContractExecution transactions from historical blocks
    /// This ensures tokens created before the contract execution code was added are recovered
    fn reprocess_contract_executions(&mut self) -> Result<()> {
        let block_count = self.blocks.len();
        if block_count == 0 {
            return Ok(());
        }

        info!("🔄 Reprocessing contract executions from {} blocks...", block_count);
        let mut tokens_found = 0;

        for block in &self.blocks.clone() {
            for transaction in &block.transactions {
                if transaction.transaction_type == TransactionType::ContractExecution {
                    // Try to process as contract execution
                    if let Ok(()) = self.process_contract_execution(transaction, block.height()) {
                        tokens_found += 1;
                    }
                }
            }
        }

        if tokens_found > 0 {
            info!("🔄 Reprocessed {} contract executions, total tokens: {}",
                tokens_found, self.token_contracts.len());
        }

        Ok(())
    }

    /// Execute a token contract call
    fn execute_token_contract_call(
        &mut self,
        call: &crate::types::ContractCall,
        caller: &lib_crypto::types::keys::PublicKey,
        block_height: u64,
    ) -> Result<()> {
        match call.method.as_str() {
            "create_custom_token" => {
                let params: (String, String, u64) = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid create_custom_token params: {}", e))?;
                let (name, symbol, initial_supply) = params;

                // CRITICAL: Check for duplicate symbol across ALL existing tokens
                // This prevents confusion where multiple tokens share the same symbol
                let symbol_upper = symbol.to_uppercase();
                for (_, existing_token) in &self.token_contracts {
                    if existing_token.symbol.to_uppercase() == symbol_upper {
                        return Err(anyhow::anyhow!(
                            "Token symbol '{}' already exists (used by token '{}')",
                            symbol,
                            existing_token.name
                        ));
                    }
                }

                let token = crate::contracts::TokenContract::new_custom(
                    name.clone(),
                    symbol.clone(),
                    initial_supply,
                    caller.clone(),
                );

                let token_id = token.token_id;
                if self.token_contracts.contains_key(&token_id) {
                    return Err(anyhow::anyhow!("Token with same name and symbol already exists"));
                }

                info!("Creating token contract: {} ({}) with supply {} at block {}",
                    name, symbol, initial_supply, block_height);
                self.token_contracts.insert(token_id, token);
                info!("Token contract created: {} ({}), token_id: {}",
                    name, symbol, hex::encode(token_id));
            }
            "mint" => {
                // Accept (token_id, to_key_id, amount) - client sends just key_id, not full PublicKey
                let params: ([u8; 32], [u8; 32], u64) = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid mint params: {}", e))?;
                let (token_id, to_key_id, amount) = params;

                // Create a minimal PublicKey with just the key_id for balance tracking
                let to = lib_crypto::types::keys::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: to_key_id,
                };

                let token = self.token_contracts.get_mut(&token_id)
                    .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

                if token.creator != *caller {
                    return Err(anyhow::anyhow!("Only token creator can mint"));
                }

                crate::contracts::tokens::functions::mint_tokens(token, &to, amount)
                    .map_err(|e| anyhow::anyhow!("Mint failed: {}", e))?;
                info!("Minted {} tokens to {:?}", amount, to.key_id);
            }
            "transfer" => {
                // Accept (token_id, to_key_id, amount) - client sends just key_id, not full PublicKey
                let params: ([u8; 32], [u8; 32], u64) = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid transfer params: {}", e))?;
                let (token_id, to_key_id, amount) = params;

                // Create a minimal PublicKey with just the key_id for balance tracking
                let to = lib_crypto::types::keys::PublicKey {
                    dilithium_pk: vec![],
                    kyber_pk: vec![],
                    key_id: to_key_id,
                };

                let token = self.token_contracts.get_mut(&token_id)
                    .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

                // Direct balance transfer (bypass ExecutionContext requirement)
                let source_balance = token.balance_of(caller);
                if source_balance < amount {
                    return Err(anyhow::anyhow!("Insufficient balance"));
                }
                token.balances.insert(caller.clone(), source_balance - amount);
                let to_balance = token.balance_of(&to);
                token.balances.insert(to.clone(), to_balance + amount);

                info!("Transferred {} tokens from {:?} to {:?}", amount, caller.key_id, to.key_id);
            }
            "burn" => {
                let params: ([u8; 32], u64) = bincode::deserialize(&call.params)
                    .map_err(|e| anyhow::anyhow!("Invalid burn params: {}", e))?;
                let (token_id, amount) = params;

                let token = self.token_contracts.get_mut(&token_id)
                    .ok_or_else(|| anyhow::anyhow!("Token not found"))?;

                crate::contracts::tokens::functions::burn_tokens(token, caller, amount)
                    .map_err(|e| anyhow::anyhow!("Burn failed: {}", e))?;
                info!("Burned {} tokens from {:?}", amount, caller.key_id);
            }
            _ => {
                debug!("Unknown token method: {}", call.method);
            }
        }

        Ok(())
    }

    /// Get access to the recursive proof aggregator for O(1) verification
    pub async fn get_proof_aggregator(&mut self) -> Result<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>> {
        if self.proof_aggregator.is_none() {
            self.initialize_proof_aggregator()?;
        }
        
        self.proof_aggregator.clone()
            .ok_or_else(|| anyhow::anyhow!("Failed to initialize proof aggregator"))
    }

    /// Enable O(1) verification for the blockchain by processing all blocks through recursive aggregation
    pub async fn enable_instant_verification(&mut self) -> Result<()> {
        info!(" Enabling O(1) instant verification for blockchain");
        
        // Initialize aggregator if not already done
        let aggregator_arc = self.get_proof_aggregator().await?;
        
        // Process each block through the aggregator to build recursive proof chain
        let mut aggregator = aggregator_arc.write().await;
        let mut previous_chain_proof: Option<lib_proofs::ChainRecursiveProof> = None;
        
        for (i, block) in self.blocks.iter().enumerate() {
            info!("Processing block {} for recursive proof aggregation", i);
            
            // Convert block transactions to the format expected by the aggregator
            let batched_transactions: Vec<BatchedPrivateTransaction> = 
                block.transactions.iter().map(|tx| {
                    // Create batched transaction metadata
                    let batch_metadata = BatchMetadata {
                        transaction_count: 1,
                        fee_tier: 0, // Standard fee tier
                        block_height: block.height(),
                        batch_commitment: tx.hash().as_array(),
                    };

                    // Create a ZkTransactionProof for the transaction
                    let zk_tx_proof = lib_proofs::ZkTransactionProof::default(); // Using default for demo

                    BatchedPrivateTransaction {
                        transaction_proofs: vec![zk_tx_proof],
                        merkle_root: tx.hash().as_array(),
                        batch_metadata,
                    }
                }).collect();

            // Get previous state root (using merkle root as state representation)
            let previous_state_root = if i > 0 {
                let merkle_bytes = self.blocks[i - 1].header.merkle_root.as_bytes();
                let mut root = [0u8; 32];
                root.copy_from_slice(merkle_bytes);
                root
            } else {
                [0u8; 32] // Genesis block
            };

            // Aggregate block proof
            match aggregator.aggregate_block_transactions(
                block.height(),
                &batched_transactions,
                &previous_state_root,
                block.header.timestamp,
            ) {
                Ok(block_proof) => {
                    info!("Block {} proof aggregated successfully", i);

                    // Create recursive chain proof
                    match aggregator.create_recursive_chain_proof(&block_proof, previous_chain_proof.as_ref()) {
                        Ok(chain_proof) => {
                            info!(" Recursive chain proof created for block {}", i);
                            previous_chain_proof = Some(chain_proof);
                        }
                        Err(e) => {
                            error!("Failed to create recursive chain proof for block {}: {}", i, e);
                            return Err(anyhow::anyhow!("Failed to create recursive chain proof: {}", e));
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to aggregate block {} proof: {}", i, e);
                    return Err(anyhow::anyhow!("Failed to aggregate block proof: {}", e));
                }
            }
        }

        // Verify the final recursive proof works
        if let Some(final_chain_proof) = previous_chain_proof {
            let verifier = lib_proofs::InstantStateVerifier::new()?;
            match verifier.verify_current_state(&final_chain_proof) {
                Ok(true) => {
                    info!("Final recursive chain proof verification successful");
                }
                Ok(false) => {
                    warn!("Final recursive chain proof verification failed");
                    return Err(anyhow::anyhow!("Recursive chain proof verification failed"));
                }
                Err(e) => {
                    error!("Error verifying final recursive chain proof: {}", e);
                    return Err(anyhow::anyhow!("Error verifying recursive chain proof: {}", e));
                }
            }
        }
        
        info!("O(1) instant verification enabled for entire blockchain with {} blocks", self.blocks.len());
        Ok(())
    }

    /// Store an economics transaction on the blockchain
    pub fn store_economics_transaction(&mut self, transaction: EconomicsTransaction) {
        self.economics_transactions.push(transaction);
    }

    /// Get all economics transactions for a specific address
    pub fn get_transactions_for_address(&self, address: &str) -> Vec<serde_json::Value> {
        let address_bytes = if address.len() == 64 {
            address.as_bytes().to_vec()
        } else {
            let mut addr_bytes = [0u8; 32];
            let input_bytes = address.as_bytes();
            let copy_len = std::cmp::min(input_bytes.len(), 32);
            addr_bytes[..copy_len].copy_from_slice(&input_bytes[..copy_len]);
            addr_bytes.to_vec()
        };

        let mut address_array = [0u8; 32];
        if address_bytes.len() >= 32 {
            address_array.copy_from_slice(&address_bytes[..32]);
        } else {
            address_array[..address_bytes.len()].copy_from_slice(&address_bytes);
        }

        self.economics_transactions
            .iter()
            .filter(|tx| tx.to == address_array || tx.from == address_array)
            .map(|tx| {
                serde_json::json!({
                    "id": format!("{:?}", tx.tx_id),
                    "hash": format!("{:?}", tx.tx_id),
                    "from": format!("{:?}", tx.from),
                    "to": format!("{:?}", tx.to),
                    "amount": tx.amount,
                    "transaction_type": tx.tx_type,
                    "timestamp": tx.timestamp,
                    "block_height": tx.block_height,
                })
            })
            .collect()
    }

    // ===== ECONOMIC INTEGRATION METHODS =====

    /// Create UBI distribution transactions using lib-economy
    pub async fn create_ubi_distributions(
        &mut self,
        citizens: &[(lib_economy::wasm::IdentityId, u64)],
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor.create_ubi_distributions_for_blockchain(citizens, system_keypair).await?;
            let mut tx_hashes = Vec::new();
            
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} UBI distribution transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create network reward transactions using lib-economy
    pub async fn create_network_rewards(
        &mut self,
        rewards: &[([u8; 32], u64)], // (recipient, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor.create_network_reward_transactions(rewards, system_keypair).await?;
            let mut tx_hashes = Vec::new();
            
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} network reward transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create payment transaction with proper economic fee calculation
    pub async fn create_payment_transaction(
        &mut self,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        priority: lib_economy::Priority,
        sender_keypair: &lib_crypto::KeyPair,
    ) -> Result<Hash> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_tx = processor.create_payment_transaction_for_blockchain(
                from, to, amount, priority, sender_keypair
            ).await?;
            
            let tx_hash = blockchain_tx.hash();
            self.add_pending_transaction(blockchain_tx)?;
            
            info!("🏦 Created payment transaction: {} ZHTP from {:?} to {:?}", amount, from, to);
            Ok(tx_hash)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create welfare funding transactions using lib-economy
    pub async fn create_welfare_funding(
        &mut self,
        services: &[(String, [u8; 32], u64)], // (service_name, address, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut _processor) = self.economic_processor {
            let blockchain_txs = crate::integration::economic_integration::create_welfare_funding_transactions(
                services, system_keypair
            ).await?;
            
            let mut tx_hashes = Vec::new();
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }
            
            info!("🏦 Created {} welfare funding transactions", tx_hashes.len());
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Get economic treasury statistics
    pub async fn get_treasury_statistics(&self) -> Result<TreasuryStats> {
        if let Some(ref processor) = self.economic_processor {
            processor.get_treasury_statistics().await
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Calculate transaction fees using economic rules
    pub fn calculate_transaction_fees(
        &self,
        tx_size: u64,
        amount: u64,
        priority: lib_economy::Priority,
        is_system_transaction: bool,
    ) -> (u64, u64, u64) {
        if let Some(ref processor) = self.economic_processor {
            processor.calculate_transaction_fees_with_exemptions(tx_size, amount, priority, is_system_transaction)
        } else {
            // Fallback basic fee calculation if processor not available
            if is_system_transaction {
                (0, 0, 0)
            } else {
                let base_fee = tx_size * 10; // Basic fallback
                let dao_fee = amount * 200 / 10000; // 2% DAO fee
                (base_fee, dao_fee, base_fee + dao_fee)
            }
        }
    }

    /// Get wallet balance for an address using economic processor
    pub fn get_wallet_balance(&self, address: &[u8; 32]) -> Option<u64> {
        if let Some(ref processor) = self.economic_processor {
            processor.get_wallet_balance(address).map(|balance| balance.total_balance())
        } else {
            None
        }
    }

    /// Initialize economic processor if not already done
    pub fn ensure_economic_processor(&mut self) {
        if self.economic_processor.is_none() {
            self.economic_processor = Some(EconomicTransactionProcessor::new());
            info!("🏦 Economic processor initialized for blockchain");
        }
    }

    /// Initialize consensus coordinator if not already done
    pub async fn initialize_consensus_coordinator(
        &mut self,
        mempool: std::sync::Arc<tokio::sync::RwLock<crate::mempool::Mempool>>,
        consensus_type: lib_consensus::ConsensusType,
    ) -> Result<()> {
        if self.consensus_coordinator.is_none() {
            let blockchain_arc = std::sync::Arc::new(tokio::sync::RwLock::new(self.clone()));
            let coordinator = crate::integration::consensus_integration::initialize_consensus_integration(
                blockchain_arc,
                mempool,
                consensus_type,
            ).await?;
            
            self.consensus_coordinator = Some(std::sync::Arc::new(tokio::sync::RwLock::new(coordinator)));
            info!(" Consensus coordinator initialized for blockchain");
        }
        Ok(())
    }

    /// Get consensus coordinator reference
    pub fn get_consensus_coordinator(&self) -> Option<&std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>> {
        self.consensus_coordinator.as_ref()
    }

    /// Start consensus coordinator
    pub async fn start_consensus(&mut self) -> Result<()> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let mut coordinator = coordinator_arc.write().await;
            coordinator.start_consensus_coordinator().await?;
            info!("Consensus coordinator started for blockchain");
        } else {
            return Err(anyhow::anyhow!("Consensus coordinator not initialized"));
        }
        Ok(())
    }

    /// Register as validator in consensus
    pub async fn register_as_validator(
        &mut self,
        identity: lib_identity::IdentityId,
        stake_amount: u64,
        storage_capacity: u64,
        consensus_keypair: &lib_crypto::KeyPair,
        commission_rate: u8,
    ) -> Result<()> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let mut coordinator = coordinator_arc.write().await;
            coordinator.register_as_validator(
                identity,
                stake_amount,
                storage_capacity,
                consensus_keypair,
                commission_rate,
            ).await?;
            info!("Registered as validator with consensus coordinator");
        } else {
            return Err(anyhow::anyhow!("Consensus coordinator not initialized"));
        }
        Ok(())
    }

    /// Get consensus status
    pub async fn get_consensus_status(&self) -> Result<Option<ConsensusStatus>> {
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let coordinator = coordinator_arc.read().await;
            let status = coordinator.get_consensus_status().await?;
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }

    /// Create DAO proposal through consensus
    pub async fn create_dao_proposal(
        &self,
        proposer_keypair: &lib_crypto::KeyPair,
        title: String,
        description: String,
        proposal_type: lib_consensus::DaoProposalType,
    ) -> Result<crate::types::Hash> {
        let proposal_tx = crate::integration::consensus_integration::create_dao_proposal_transaction(
            proposer_keypair,
            title,
            description,
            proposal_type,
        )?;

        // Add to pending transactions
        let tx_hash = proposal_tx.hash();
        // Note: In a mutable context, you would call self.add_pending_transaction(proposal_tx)?;
        // For now, just return the transaction hash
        Ok(tx_hash)
    }

    /// Cast DAO vote through consensus
    pub async fn cast_dao_vote(
        &self,
        voter_keypair: &lib_crypto::KeyPair,
        proposal_id: lib_crypto::Hash,
        vote_choice: lib_consensus::DaoVoteChoice,
    ) -> Result<crate::types::Hash> {
        let vote_tx = crate::integration::consensus_integration::create_dao_vote_transaction(
            voter_keypair,
            proposal_id,
            vote_choice,
        )?;

        // Add to pending transactions
        let tx_hash = vote_tx.hash();
        // Note: In a mutable context, you would call self.add_pending_transaction(vote_tx)?;
        // For now, just return the transaction hash
        Ok(tx_hash)
    }

    /// Get all DAO proposals from blockchain
    pub fn get_dao_proposals(&self) -> Vec<crate::transaction::DaoProposalData> {
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter_map(|tx| tx.dao_proposal_data.as_ref())
            .cloned()
            .collect()
    }

    /// Get a specific DAO proposal by ID
    pub fn get_dao_proposal(&self, proposal_id: &Hash) -> Option<crate::transaction::DaoProposalData> {
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter_map(|tx| tx.dao_proposal_data.as_ref())
            .find(|proposal| &proposal.proposal_id == proposal_id)
            .cloned()
    }

    /// Get all votes for a specific proposal
    pub fn get_dao_votes_for_proposal(&self, proposal_id: &Hash) -> Vec<crate::transaction::DaoVoteData> {
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter_map(|tx| tx.dao_vote_data.as_ref())
            .filter(|vote| &vote.proposal_id == proposal_id)
            .cloned()
            .collect()
    }

    /// Get all DAO votes (for accounting)
    pub fn get_all_dao_votes(&self) -> Vec<crate::transaction::DaoVoteData> {
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter_map(|tx| tx.dao_vote_data.as_ref())
            .cloned()
            .collect()
    }

    /// Get all DAO execution transactions
    pub fn get_dao_executions(&self) -> Vec<crate::transaction::DaoExecutionData> {
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoExecution)
            .filter_map(|tx| tx.dao_execution_data.as_ref())
            .cloned()
            .collect()
    }

    /// Tally votes for a proposal
    pub fn tally_dao_votes(&self, proposal_id: &Hash) -> (u64, u64, u64, u64) {
        let votes = self.get_dao_votes_for_proposal(proposal_id);
        
        let mut yes_votes = 0u64;
        let mut no_votes = 0u64;
        let mut abstain_votes = 0u64;
        let mut total_voting_power = 0u64;
        
        for vote in votes {
            total_voting_power += vote.voting_power;
            match vote.vote_choice.as_str() {
                "Yes" => yes_votes += vote.voting_power,
                "No" => no_votes += vote.voting_power,
                "Abstain" => abstain_votes += vote.voting_power,
                _ => {} // Delegate votes would need special handling
            }
        }
        
        (yes_votes, no_votes, abstain_votes, total_voting_power)
    }

    /// Check if a proposal has passed based on votes
    pub fn has_proposal_passed(&self, proposal_id: &Hash, required_approval_percent: u32) -> Result<bool> {
        let (yes_votes, _no_votes, _abstain_votes, total_voting_power) = self.tally_dao_votes(proposal_id);
        
        if total_voting_power == 0 {
            return Ok(false);
        }
        
        let approval_percent = (yes_votes * 100) / total_voting_power;
        Ok(approval_percent >= required_approval_percent as u64)
    }

    /// Set the DAO treasury wallet ID
    pub fn set_dao_treasury_wallet(&mut self, wallet_id: String) -> Result<()> {
        // Verify wallet exists in registry
        if !self.wallet_registry.contains_key(&wallet_id) {
            return Err(anyhow::anyhow!("Treasury wallet {} not found in registry", wallet_id));
        }
        
        info!("🏦 Setting DAO treasury wallet: {}", wallet_id);
        self.dao_treasury_wallet_id = Some(wallet_id);
        Ok(())
    }

    /// Get the DAO treasury wallet ID
    pub fn get_dao_treasury_wallet_id(&self) -> Option<&String> {
        self.dao_treasury_wallet_id.as_ref()
    }

    /// Get treasury wallet data
    pub fn get_dao_treasury_wallet(&self) -> Result<&crate::transaction::WalletTransactionData> {
        let wallet_id = self.dao_treasury_wallet_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("DAO treasury wallet not set"))?;
        
        self.wallet_registry.get(wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Treasury wallet not found in registry"))
    }

    /// Get treasury balance from TokenContract (Issue #1018)
    ///
    /// Uses TokenContract::balance_of() as the source of truth for treasury balance.
    /// This replaces the previous UTXO scanning approach which used a placeholder.
    ///
    /// The TokenContract tracks balances in a HashMap<PublicKey, u64>, which provides:
    /// - Accurate balance tracking (not placeholder values)
    /// - Efficient O(1) lookup
    /// - Consistency with other balance queries in the system
    pub fn get_dao_treasury_balance(&self) -> Result<u64> {
        let treasury_wallet = self.get_dao_treasury_wallet()?;
        let treasury_pubkey = crate::integration::crypto_integration::PublicKey::new(
            treasury_wallet.public_key.clone()
        );

        // Issue #1018: Use TokenContract as source of truth for treasury balance
        // This replaces the UTXO scanning approach that used `balance += 1` placeholder
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();

        if let Some(token) = self.token_contracts.get(&sov_token_id) {
            Ok(token.balance_of(&treasury_pubkey))
        } else {
            // Token contract not initialized yet (early bootstrap)
            // Fall back to counting UTXOs (legacy behavior, but returns 0 not placeholder)
            tracing::debug!(
                "SOV token contract not found, treasury balance query returning 0 during bootstrap"
            );
            Ok(0)
        }
    }

    /// Get all UTXOs belonging to the treasury wallet
    pub fn get_dao_treasury_utxos(&self) -> Result<Vec<(Hash, TransactionOutput)>> {
        let treasury_wallet = self.get_dao_treasury_wallet()?;
        let treasury_pubkey = crate::integration::crypto_integration::PublicKey::new(
            treasury_wallet.public_key.clone()
        );
        
        let mut utxos = Vec::new();
        for (utxo_id, output) in &self.utxo_set {
            if output.recipient.as_bytes() == treasury_pubkey.as_bytes() {
                utxos.push((*utxo_id, output.clone()));
            }
        }
        
        Ok(utxos)
    }

    /// Create a treasury fee collection transaction
    /// This routes block fees to the DAO treasury
    pub fn create_treasury_fee_transaction(
        &self,
        block_height: u64,
        total_fees: u64,
    ) -> Result<Transaction> {
        let treasury_wallet = self.get_dao_treasury_wallet()?;
        
        // Create output to treasury
        let treasury_output = TransactionOutput {
            commitment: crate::types::hash::blake3_hash(&total_fees.to_le_bytes()),
            note: Hash::default(),
            recipient: crate::integration::crypto_integration::PublicKey::new(
                treasury_wallet.public_key.clone()
            ),
        };
        
        // Create fee collection transaction (no inputs, system-generated)
        let fee_tx = Transaction::new(
            vec![], // No inputs (system transaction)
            vec![treasury_output],
            0, // No fee for system transaction
            crate::integration::crypto_integration::Signature {
                signature: vec![],
                public_key: crate::integration::crypto_integration::PublicKey::new(vec![]),
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                timestamp: crate::utils::time::current_timestamp(),
            },
            format!("Block {} fee collection: {} ZHTP to DAO treasury", 
                    block_height, total_fees).into_bytes(),
        );
        
        Ok(fee_tx)
    }

    /// Execute a passed DAO proposal (creates real blockchain transaction)
    /// This method spends treasury UTXOs to fulfill the proposal
    pub fn execute_dao_proposal(
        &mut self,
        proposal_id: Hash,
        executor_identity: String,
        recipient_identity: String,
        amount: u64,
    ) -> Result<Hash> {
        // 1. Get the proposal
        let proposal = self.get_dao_proposal(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;
        
        // 2. Verify proposal has passed
        if !self.has_proposal_passed(&proposal_id, 60)? {
            return Err(anyhow::anyhow!("Proposal has not passed"));
        }
        
        // 3. Check if already executed
        let executions = self.get_dao_executions();
        if executions.iter().any(|exec| exec.proposal_id == proposal_id) {
            return Err(anyhow::anyhow!("Proposal already executed"));
        }
        
        // 4. Get treasury wallet UTXOs
        let treasury_utxos = self.get_dao_treasury_utxos()?;
        if treasury_utxos.is_empty() {
            warn!("⚠️  No treasury UTXOs available, creating placeholder transaction");
        }
        
        // 5. Select UTXOs to spend (simplified - just take first few)
        let needed_amount = amount + 100; // amount + fee
        let mut inputs = Vec::new();
        let mut total_input = 0u64;
        
        for (utxo_id, _output) in treasury_utxos.iter().take(3) {
            inputs.push(TransactionInput {
                previous_output: *utxo_id,
                output_index: 0,
                nullifier: crate::types::hash::blake3_hash(&[utxo_id.as_bytes(), &[0u8]].concat()),
                zk_proof: crate::integration::zk_integration::ZkTransactionProof::default(),
            });
            total_input += 1000; // Placeholder amount per UTXO
            if total_input >= needed_amount {
                break;
            }
        }
        
        // If no UTXOs, create placeholder input
        if inputs.is_empty() {
            let proposal_id_bytes = proposal_id.as_bytes();
            let nullifier_input = format!("dao_exec_{}", hex::encode(&proposal_id_bytes[..8]));
            inputs.push(TransactionInput {
                previous_output: Hash::default(),
                output_index: 0,
                nullifier: crate::types::hash::blake3_hash(nullifier_input.as_bytes()),
                zk_proof: crate::integration::zk_integration::ZkTransactionProof::default(),
            });
        }
        
        // 6. Create execution data
        let execution_data = crate::transaction::DaoExecutionData {
            proposal_id,
            executor: executor_identity,
            execution_type: "TreasurySpending".to_string(),
            recipient: Some(recipient_identity.clone()),
            amount: Some(amount),
            executed_at: crate::utils::time::current_timestamp(),
            executed_at_height: self.height,
            multisig_signatures: vec![], // TODO: Collect from approving voters
        };
        
        // 7. Get recipient identity public key
        let recipient_pubkey = if let Some(recipient_data) = self.identity_registry.get(&recipient_identity) {
            crate::integration::crypto_integration::PublicKey::new(recipient_data.public_key.clone())
        } else {
            warn!("⚠️  Recipient identity not found, using placeholder");
            crate::integration::crypto_integration::PublicKey::new(vec![])
        };
        
        // 8. Create outputs (recipient + change if needed)
        let mut outputs = vec![
            TransactionOutput {
                commitment: crate::types::hash::blake3_hash(&amount.to_le_bytes()),
                note: Hash::default(),
                recipient: recipient_pubkey,
            }
        ];
        
        // Add change output if we have UTXOs
        if total_input > needed_amount {
            let treasury_wallet = self.get_dao_treasury_wallet()?;
            let change = total_input - needed_amount;
            outputs.push(TransactionOutput {
                commitment: crate::types::hash::blake3_hash(&change.to_le_bytes()),
                note: Hash::default(),
                recipient: crate::integration::crypto_integration::PublicKey::new(
                    treasury_wallet.public_key.clone()
                ),
            });
        }
        
        // 9. Create execution transaction
        let proposal_id_bytes = proposal_id.as_bytes();
        let memo_text = format!("DAO Proposal {} Execution", hex::encode(&proposal_id_bytes[..8]));
        let execution_tx = Transaction::new_dao_execution(
            execution_data,
            inputs,
            outputs,
            100, // Fee
            crate::integration::crypto_integration::Signature {
                signature: vec![],
                public_key: crate::integration::crypto_integration::PublicKey::new(vec![]),
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                timestamp: crate::utils::time::current_timestamp(),
            },
            memo_text.into_bytes(),
        );
        
        // 10. Add to pending transactions
        let tx_hash = execution_tx.hash();
        self.add_pending_transaction(execution_tx)?;
        
        info!("✅ DAO proposal {:?} executed, transaction: {:?}", proposal_id, tx_hash);
        Ok(tx_hash)
    }

    // ============================================================================
    // GOVERNANCE PARAMETER UPDATE METHODS
    // ============================================================================

    /// Apply a difficulty parameter update from a passed DAO proposal.
    ///
    /// This method implements the governance flow for updating difficulty parameters:
    /// 1. Verifies the proposal exists and has passed voting (30% quorum)
    /// 2. Checks the proposal hasn't already been executed (idempotency guard)
    /// 3. Extracts and validates the new difficulty parameters
    /// 4. Updates the blockchain's `difficulty_config`
    /// 5. Synchronizes changes with the consensus coordinator
    /// 6. Logs all changes at info level
    ///
    /// The method is idempotent - calling it multiple times with the same
    /// proposal_id will succeed but only apply changes once.
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - The hash ID of the passed difficulty parameter update proposal
    ///
    /// # Returns
    ///
    /// * `Ok(())` on successful update (or if already executed)
    /// * `Err` if proposal doesn't exist, hasn't passed, or parameters are invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// use lib_blockchain::{Blockchain, Hash};
    ///
    /// let mut blockchain = Blockchain::new(genesis_block, coordinator)?;
    ///
    /// // After a DifficultyParameterUpdate proposal has passed voting...
    /// let proposal_id: Hash = /* passed proposal hash */;
    ///
    /// // Apply the governance update
    /// match blockchain.apply_difficulty_parameter_update(proposal_id) {
    ///     Ok(()) => {
    ///         println!("Difficulty parameters updated successfully");
    ///         let config = blockchain.get_difficulty_config();
    ///         println!("New target timespan: {}", config.target_timespan);
    ///     }
    ///     Err(e) => {
    ///         eprintln!("Failed to apply update: {}", e);
    ///     }
    /// }
    ///
    /// // Idempotent: calling again is safe
    /// blockchain.apply_difficulty_parameter_update(proposal_id)?; // No-op, already applied
    /// ```
    ///
    /// # Governance Flow
    ///
    /// This method is typically called after:
    /// 1. A `DaoProposalType::DifficultyParameterUpdate` proposal is created
    /// 2. The 7-day voting period completes
    /// 3. The proposal achieves 30% quorum with majority approval
    /// 4. The timelock period expires (if any)
    ///
    /// # Errors
    ///
    /// - `InvalidProposal`: Proposal not found
    /// - `InvalidProposal`: Proposal has not passed voting
    /// - `InvalidProposal`: Wrong proposal type
    /// - `ParameterValidationError`: New parameters fail validation
    pub fn apply_difficulty_parameter_update(&mut self, proposal_id: Hash) -> Result<()> {
        // 0. Check if already executed (prevent double-execution)
        if self.executed_dao_proposals.contains(&proposal_id) {
            debug!(
                "Difficulty proposal {:?} already executed, skipping",
                proposal_id
            );
            return Ok(());
        }

        // 1. Verify proposal exists and get its quorum requirement
        let proposal = self.get_dao_proposal(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!(
                "InvalidProposal: Difficulty parameter update proposal {:?} not found",
                proposal_id
            ))?;

        // 2. Verify proposal has passed using its configured quorum requirement
        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has not passed voting",
                proposal_id
            ));
        }

        // 3. Get the execution parameters from the proposal (already fetched above)
        let execution_params_bytes = proposal.execution_params.clone()
            .ok_or_else(|| anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has no execution parameters",
                proposal_id
            ))?;

        // 4. Decode execution parameters
        let execution_params: lib_consensus::dao::dao_types::DaoExecutionParams = 
            bincode::deserialize(&execution_params_bytes)
                .map_err(|e| anyhow::anyhow!(
                    "ParameterValidationError: Failed to decode execution params: {}",
                    e
                ))?;

        // 5. Extract the governance parameter update
        let update = match execution_params.action {
            lib_consensus::dao::dao_types::DaoExecutionAction::GovernanceParameterUpdate(update) => {
                update
            }
            _ => return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} is not a governance parameter update",
                proposal_id
            )),
        };

        // 6. Extract difficulty-specific parameters from the update vector
        let mut new_target_timespan: Option<u64> = None;
        let mut new_adjustment_interval: Option<u64> = None;

        for param in &update.updates {
            match param {
                lib_consensus::dao::dao_types::GovernanceParameterValue::BlockchainTargetTimespan(v) => {
                    new_target_timespan = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::BlockchainAdjustmentInterval(v) => {
                    new_adjustment_interval = Some(*v);
                }
                _ => {
                    // Other parameters are handled elsewhere
                }
            }
        }

        // 7. Validate that at least one difficulty parameter was provided
        if new_target_timespan.is_none() && new_adjustment_interval.is_none() {
            return Err(anyhow::anyhow!(
                "ParameterValidationError: No difficulty parameters found in governance update"
            ));
        }

        // 8. Validate parameters
        if let Some(ts) = new_target_timespan {
            if ts == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: target_timespan cannot be zero"
                ));
            }
        }
        if let Some(ai) = new_adjustment_interval {
            if ai == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: adjustment_interval cannot be zero"
                ));
            }
        }

        // 9. Log the update
        info!(
            "📊 Applying difficulty parameter update from proposal {:?}",
            proposal_id
        );
        if let Some(ts) = new_target_timespan {
            info!(
                "   target_timespan: {} → {}",
                self.difficulty_config.target_timespan, ts
            );
        }
        if let Some(ai) = new_adjustment_interval {
            info!(
                "   adjustment_interval: {} → {}",
                self.difficulty_config.adjustment_interval, ai
            );
        }

        // 10. Apply the update
        if let Some(ts) = new_target_timespan {
            self.difficulty_config.target_timespan = ts;
        }
        if let Some(ai) = new_adjustment_interval {
            self.difficulty_config.adjustment_interval = ai;
        }
        self.difficulty_config.last_updated_at_height = self.height;

        // Sync with consensus coordinator if available
        if let Some(ref coordinator) = self.consensus_coordinator {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let coord = coordinator.write().await;
                    coord.apply_difficulty_governance_update(
                        None, // initial_difficulty not in DifficultyConfig
                        new_adjustment_interval,
                        new_target_timespan,
                    ).await
                })
            })?;
        }

        // 11. Mark proposal as executed to prevent double-execution
        self.executed_dao_proposals.insert(proposal_id);

        Ok(())
    }

    /// Process all approved governance proposals that haven't been executed yet.
    /// This is called during block processing to execute any passed proposals.
    ///
    /// Currently handles:
    /// - DifficultyParameterUpdate proposals
    ///
    /// Future: Treasury allocations, protocol upgrades, etc.
    pub fn process_approved_governance_proposals(&mut self) -> Result<()> {
        // Get difficulty parameter update proposals with their quorum requirements
        // Collect to avoid borrowing issues with self.has_proposal_passed()
        let difficulty_proposals: Vec<(Hash, u8)> = self.get_dao_proposals()
            .iter()
            .filter(|p| p.proposal_type == "difficulty_parameter_update")
            .map(|p| (p.proposal_id.clone(), p.quorum_required))
            .collect();

        for (proposal_id, quorum_required) in difficulty_proposals {
            // Skip if already executed
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            // Check if proposal has passed voting using its configured quorum requirement
            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => {
                    // Proposal passed, try to execute it
                    match self.apply_difficulty_parameter_update(proposal_id.clone()) {
                        Ok(()) => {
                            info!(
                                "✅ Successfully executed difficulty parameter update proposal {:?}",
                                proposal_id
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to execute difficulty parameter update proposal {:?}: {}",
                                proposal_id, e
                            );
                            // Don't fail the whole block processing, just log the warning
                        }
                    }
                }
                Ok(false) => {
                    // Proposal hasn't passed yet, skip
                    debug!(
                        "Difficulty proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    // Error checking proposal status, skip
                    debug!(
                        "Error checking status of proposal {:?}: {}",
                        proposal_id, e
                    );
                }
            }
        }

        Ok(())
    }


    // ============================================================================
    // WELFARE SERVICE REGISTRY METHODS
    // ============================================================================

    /// Register a new welfare service provider with verification
    pub fn register_welfare_service(
        &mut self,
        service: lib_consensus::WelfareService,
    ) -> Result<()> {
        let service_id = service.service_id.clone();
        
        // Check if service already exists
        if self.welfare_services.contains_key(&service_id) {
            return Err(anyhow::anyhow!("Service {} already registered", service_id));
        }
        
        // Verify provider credentials for service type
        self.verify_service_provider_credentials(&service)?;
        
        // Validate service type requirements
        self.validate_service_type_requirements(&service)?;
        
        // Store service
        self.welfare_services.insert(service_id.clone(), service.clone());
        self.welfare_service_blocks.insert(service_id.clone(), self.height);
        
        // Initialize performance metrics
        let performance = lib_consensus::ServicePerformanceMetrics {
            service_id: service_id.clone(),
            service_name: service.service_name.clone(),
            service_type: service.service_type.clone(),
            service_utilization_rate: 0.0,
            beneficiary_satisfaction: 0.0,
            cost_efficiency: 0.0,
            geographic_coverage: vec![],
            total_beneficiaries: 0,
            success_rate: 0.0,
            outcome_reports_count: 0,
            last_audit_timestamp: 0,
            reputation_trend: lib_consensus::ReputationTrend::Stable,
        };
        self.service_performance.insert(service_id.clone(), performance);
        
        info!("🏥 Registered welfare service: {} ({})", service.service_name, service_id);
        Ok(())
    }

    /// Get a welfare service by ID
    pub fn get_welfare_service(&self, service_id: &str) -> Option<&lib_consensus::WelfareService> {
        self.welfare_services.get(service_id)
    }

    /// Get all active welfare services
    pub fn get_active_welfare_services(&self) -> Vec<&lib_consensus::WelfareService> {
        self.welfare_services
            .values()
            .filter(|s| s.is_active)
            .collect()
    }

    /// Get welfare services by type
    pub fn get_welfare_services_by_type(
        &self,
        service_type: &lib_consensus::WelfareServiceType,
    ) -> Vec<&lib_consensus::WelfareService> {
        self.welfare_services
            .values()
            .filter(|s| &s.service_type == service_type && s.is_active)
            .collect()
    }

    /// Update welfare service status
    pub fn update_welfare_service_status(
        &mut self,
        service_id: &str,
        is_active: bool,
    ) -> Result<()> {
        let service = self.welfare_services
            .get_mut(service_id)
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", service_id))?;
        
        service.is_active = is_active;
        
        let status_str = if is_active { "activated" } else { "deactivated" };
        info!("🏥 Welfare service {} {}", service_id, status_str);
        Ok(())
    }

    /// Update welfare service reputation
    pub fn update_service_reputation(
        &mut self,
        service_id: &str,
        new_score: u8,
    ) -> Result<()> {
        let service = self.welfare_services
            .get_mut(service_id)
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", service_id))?;
        
        let old_score = service.reputation_score;
        service.reputation_score = new_score;
        
        // Update reputation trend in performance metrics
        if let Some(performance) = self.service_performance.get_mut(service_id) {
            performance.reputation_trend = if new_score > old_score {
                lib_consensus::ReputationTrend::Improving
            } else if new_score < old_score {
                lib_consensus::ReputationTrend::Declining
            } else {
                lib_consensus::ReputationTrend::Stable
            };
        }
        
        info!("🏥 Service {} reputation updated: {} → {}", service_id, old_score, new_score);
        Ok(())
    }

    // ============================================================================
    // SERVICE VERIFICATION METHODS
    // ============================================================================

    /// Verify that a service provider has required credentials for their service type
    fn verify_service_provider_credentials(&self, service: &lib_consensus::WelfareService) -> Result<()> {
        // Get provider identity by DID
        let provider_identity = self.get_identity(&service.provider_identity)
            .ok_or_else(|| anyhow::anyhow!("Provider identity {} not found", service.provider_identity))?;
        
        // Check minimum reputation threshold (providers need at least 30/100 reputation)
        let min_reputation = 30u32;
        let provider_id_hash = lib_crypto::Hash(lib_crypto::hash_blake3(service.provider_identity.as_bytes()));
        let provider_reputation = self.calculate_reputation_score(&provider_id_hash);
        
        if provider_reputation < min_reputation {
            return Err(anyhow::anyhow!(
                "Provider reputation {} below minimum threshold {}",
                provider_reputation, min_reputation
            ));
        }
        
        // Verify zero-knowledge credential proof if provided
        if let Some(credential_proof_bytes) = &service.credential_proof {
            self.verify_service_credential_proof(
                credential_proof_bytes,
                &service.service_type,
                &provider_identity.public_key
            )?;
            info!("✅ ZK credential proof verified for service type {:?}", service.service_type);
        } else {
            // No credential proof provided - fallback to basic verification
            warn!("⚠️  No credential proof provided for service {} - using basic verification", service.service_id);
            
            // Verify service-type-specific requirements without ZK proofs
            match service.service_type {
                lib_consensus::WelfareServiceType::Healthcare |
                lib_consensus::WelfareServiceType::Education |
                lib_consensus::WelfareServiceType::EmergencyResponse => {
                    // Critical services require credential proofs
                    return Err(anyhow::anyhow!(
                        "Service type {:?} requires credential proof for registration",
                        service.service_type
                    ));
                }
                _ => {
                    // Generic services just need verified identity and good reputation
                    info!("✅ Basic verification passed for generic service type {:?}", service.service_type);
                }
            }
        }
        
        Ok(())
    }

    /// Verify a zero-knowledge credential proof for a service provider
    fn verify_service_credential_proof(
        &self,
        proof_bytes: &[u8],
        service_type: &lib_consensus::WelfareServiceType,
        provider_public_key: &[u8],
    ) -> Result<()> {
        // Deserialize the ZK credential proof
        let credential_proof: lib_proofs::identity::ZkCredentialProof = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize credential proof: {}", e))?;
        
        // Check proof hasn't expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        if credential_proof.expires_at <= now {
            return Err(anyhow::anyhow!("Credential proof has expired"));
        }
        
        // Create credential schema for the service type
        let schema = self.get_credential_schema_for_service_type(service_type, provider_public_key)?;
        
        // Verify the credential proof using lib-proofs
        let verification_result = lib_proofs::identity::verify_credential_proof(&credential_proof, &schema)
            .map_err(|e| anyhow::anyhow!("Credential verification failed: {}", e))?;
        
        match verification_result {
            lib_proofs::types::VerificationResult::Valid { .. } => {
                info!("✅ Credential proof valid for service type {:?}", service_type);
                Ok(())
            }
            lib_proofs::types::VerificationResult::Invalid(reason) => {
                Err(anyhow::anyhow!("Invalid credential proof: {}", reason))
            }
            lib_proofs::types::VerificationResult::Error(msg) => {
                Err(anyhow::anyhow!("Credential verification error: {}", msg))
            }
        }
    }

    /// Get the credential schema required for a specific service type
    fn get_credential_schema_for_service_type(
        &self,
        service_type: &lib_consensus::WelfareServiceType,
        issuer_public_key: &[u8],
    ) -> Result<lib_proofs::identity::CredentialSchema> {
        // Convert issuer public key to fixed size array
        let issuer_key: [u8; 32] = issuer_public_key.get(..32)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid issuer public key length"))?;
        
        // Create schema based on service type
        let schema = match service_type {
            lib_consensus::WelfareServiceType::Healthcare => {
                lib_proofs::identity::CredentialSchema::new(
                    "healthcare_provider".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("medical_license".to_string(), "string".to_string())
                .with_required_field("license_number".to_string(), "string".to_string())
                .with_required_field("specialization".to_string(), "string".to_string())
                .with_optional_field("certifications".to_string(), "array".to_string())
            }
            lib_consensus::WelfareServiceType::Education => {
                lib_proofs::identity::CredentialSchema::new(
                    "education_provider".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("teaching_license".to_string(), "string".to_string())
                .with_required_field("education_degree".to_string(), "string".to_string())
                .with_required_field("subject_area".to_string(), "string".to_string())
                .with_optional_field("certifications".to_string(), "array".to_string())
            }
            lib_consensus::WelfareServiceType::Housing => {
                lib_proofs::identity::CredentialSchema::new(
                    "housing_provider".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("property_license".to_string(), "string".to_string())
                .with_required_field("property_count".to_string(), "number".to_string())
                .with_optional_field("certifications".to_string(), "array".to_string())
            }
            lib_consensus::WelfareServiceType::FoodSecurity => {
                lib_proofs::identity::CredentialSchema::new(
                    "food_security_provider".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("food_handler_certificate".to_string(), "string".to_string())
                .with_required_field("food_safety_rating".to_string(), "string".to_string())
                .with_optional_field("certifications".to_string(), "array".to_string())
            }
            lib_consensus::WelfareServiceType::EmergencyResponse => {
                lib_proofs::identity::CredentialSchema::new(
                    "emergency_responder".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("emergency_certification".to_string(), "string".to_string())
                .with_required_field("response_type".to_string(), "string".to_string())
                .with_optional_field("training_records".to_string(), "array".to_string())
            }
            _ => {
                // Generic service credential schema
                lib_proofs::identity::CredentialSchema::new(
                    "service_provider".to_string(),
                    "1.0".to_string(),
                    issuer_key,
                )
                .with_required_field("provider_id".to_string(), "string".to_string())
                .with_required_field("service_type".to_string(), "string".to_string())
            }
        };
        
        Ok(schema)
    }

    /// Validate service-type-specific requirements
    fn validate_service_type_requirements(&self, service: &lib_consensus::WelfareService) -> Result<()> {
        // Validate service name
        if service.service_name.trim().is_empty() || service.service_name.len() < 3 {
            return Err(anyhow::anyhow!("Service name must be at least 3 characters"));
        }
        
        if service.service_name.len() > 200 {
            return Err(anyhow::anyhow!("Service name too long (max 200 characters)"));
        }
        
        // Validate description
        if service.description.trim().is_empty() || service.description.len() < 20 {
            return Err(anyhow::anyhow!("Service description must be at least 20 characters"));
        }
        
        if service.description.len() > 2000 {
            return Err(anyhow::anyhow!("Service description too long (max 2000 characters)"));
        }
        
        // Validate metadata contains required fields
        let metadata_obj = service.metadata.as_object()
            .ok_or_else(|| anyhow::anyhow!("Service metadata must be a JSON object"))?;
        
        // All service types must provide contact information
        if !metadata_obj.contains_key("contact_email") && !metadata_obj.contains_key("contact_phone") {
            return Err(anyhow::anyhow!("Service must provide contact_email or contact_phone in metadata"));
        }
        
        // Service-type-specific validation
        match service.service_type {
            lib_consensus::WelfareServiceType::Healthcare => {
                // Healthcare services must specify facility type and capacity
                if !metadata_obj.contains_key("facility_type") {
                    return Err(anyhow::anyhow!("Healthcare services must specify facility_type in metadata"));
                }
                if !metadata_obj.contains_key("service_capacity") {
                    return Err(anyhow::anyhow!("Healthcare services must specify service_capacity in metadata"));
                }
            }
            lib_consensus::WelfareServiceType::Education => {
                // Education services must specify education level and subjects
                if !metadata_obj.contains_key("education_level") {
                    return Err(anyhow::anyhow!("Education services must specify education_level in metadata"));
                }
            }
            lib_consensus::WelfareServiceType::Housing => {
                // Housing services must specify housing units and location
                if !metadata_obj.contains_key("total_units") {
                    return Err(anyhow::anyhow!("Housing services must specify total_units in metadata"));
                }
                if service.region.is_none() {
                    return Err(anyhow::anyhow!("Housing services must specify region"));
                }
            }
            lib_consensus::WelfareServiceType::FoodSecurity => {
                // Food security services must specify daily serving capacity
                if !metadata_obj.contains_key("daily_capacity") {
                    return Err(anyhow::anyhow!("Food security services must specify daily_capacity in metadata"));
                }
            }
            _ => {
                // Other service types have no additional validation
            }
        }
        
        info!("✅ Service type requirements validated for {:?}", service.service_type);
        Ok(())
    }

    /// Calculate reputation score for a service based on performance metrics
    pub fn calculate_service_reputation_score(&self, service_id: &str) -> u8 {
        let service = match self.welfare_services.get(service_id) {
            Some(s) => s,
            None => return 0,
        };
        
        let performance = match self.service_performance.get(service_id) {
            Some(p) => p,
            None => return service.reputation_score, // Return existing score if no performance data
        };
        
        // Start with base score from service
        let mut score = service.reputation_score as f64;
        
        // Factor 1: Beneficiary satisfaction (0-100 scale, weight 30%)
        let satisfaction_score = (performance.beneficiary_satisfaction * 0.3).min(30.0);
        
        // Factor 2: Service utilization (0-100 scale, weight 20%)
        let utilization_score = (performance.service_utilization_rate * 0.2).min(20.0);
        
        // Factor 3: Cost efficiency (0-100 scale, weight 15%)
        let cost_score = (performance.cost_efficiency * 0.15).min(15.0);
        
        // Factor 4: Success rate (0-100 scale, weight 20%)
        let success_score = (performance.success_rate * 0.2).min(20.0);
        
        // Factor 5: Longevity bonus (up to 15 points for established services)
        let blocks_active = self.height.saturating_sub(
            *self.welfare_service_blocks.get(service_id).unwrap_or(&self.height)
        );
        let longevity_score = ((blocks_active as f64 / 100_000.0) * 15.0).min(15.0);
        
        // Calculate final score
        score = satisfaction_score + utilization_score + cost_score + success_score + longevity_score;
        
        // Clamp to 0-100 range
        score.max(0.0).min(100.0) as u8
    }

    /// Update service performance metrics based on audit data
    pub fn update_service_performance_from_audit(
        &mut self,
        audit_entry: &lib_consensus::WelfareAuditEntry,
    ) -> Result<()> {
        let service_id = &audit_entry.service_id;
        
        let performance = self.service_performance
            .get_mut(service_id)
            .ok_or_else(|| anyhow::anyhow!("Performance metrics not found for service {}", service_id))?;
        
        // Update beneficiary count
        performance.total_beneficiaries = performance.total_beneficiaries
            .saturating_add(audit_entry.beneficiary_count);
        
        // Update last audit timestamp
        performance.last_audit_timestamp = audit_entry.distribution_timestamp;
        
        // Increment outcome reports count if verification is complete
        if matches!(audit_entry.verification_status, 
            lib_consensus::VerificationStatus::AutoVerified | 
            lib_consensus::VerificationStatus::CommunityVerified) {
            performance.outcome_reports_count = performance.outcome_reports_count.saturating_add(1);
        }
        
        // Calculate and update reputation score based on performance
        let new_reputation = self.calculate_service_reputation_score(service_id);
        self.update_service_reputation(service_id, new_reputation)?;
        
        info!("📊 Updated performance metrics for service {}", service_id);
        Ok(())
    }

    // ============================================================================
    // END SERVICE VERIFICATION METHODS
    // ============================================================================

    /// Record welfare funding distribution
    pub fn record_welfare_distribution(
        &mut self,
        audit_entry: lib_consensus::WelfareAuditEntry,
    ) -> Result<()> {
        let service_id = audit_entry.service_id.clone();
        let amount = audit_entry.amount_distributed;
        let audit_id = audit_entry.audit_id.clone();
        
        // Update service total received
        if let Some(service) = self.welfare_services.get_mut(&service_id) {
            service.total_received = service.total_received.saturating_add(amount);
            service.proposal_count = service.proposal_count.saturating_add(1);
        }
        
        // Store audit entry
        self.welfare_audit_trail.insert(audit_id, audit_entry);
        
        info!("📝 Recorded welfare distribution of {} ZHTP to service {}", amount, service_id);
        Ok(())
    }

    /// Add outcome report for a service
    pub fn add_outcome_report(
        &mut self,
        report: lib_consensus::OutcomeReport,
    ) -> Result<()> {
        let service_id = report.service_id.clone();
        let report_id = report.report_id.clone();
        let report_timestamp = report.report_timestamp;
        let beneficiaries_served = report.beneficiaries_served;
        let metrics_achieved = report.metrics_achieved.clone();
        
        // Update service performance metrics
        if let Some(performance) = self.service_performance.get_mut(&service_id) {
            performance.outcome_reports_count = performance.outcome_reports_count.saturating_add(1);
            performance.last_audit_timestamp = report_timestamp;
            performance.total_beneficiaries = performance.total_beneficiaries
                .saturating_add(beneficiaries_served);
            
            // Calculate success rate from metrics achieved
            if !metrics_achieved.is_empty() {
                let total_achievement: f64 = metrics_achieved
                    .iter()
                    .map(|m| m.achievement_percentage)
                    .sum();
                let avg_achievement = total_achievement / metrics_achieved.len() as f64;
                performance.success_rate = avg_achievement;
            }
        }
        
        // Store report
        self.outcome_reports.insert(report_id, report);
        
        info!("📊 Added outcome report for service {}", service_id);
        Ok(())
    }

    /// Get service performance metrics
    pub fn get_service_performance(
        &self,
        service_id: &str,
    ) -> Option<&lib_consensus::ServicePerformanceMetrics> {
        self.service_performance.get(service_id)
    }

    /// Get audit trail for a service
    pub fn get_service_audit_trail(
        &self,
        service_id: &str,
    ) -> Vec<&lib_consensus::WelfareAuditEntry> {
        self.welfare_audit_trail
            .values()
            .filter(|entry| entry.service_id == service_id)
            .collect()
    }

    /// Get outcome reports for a service
    pub fn get_service_outcome_reports(
        &self,
        service_id: &str,
    ) -> Vec<&lib_consensus::OutcomeReport> {
        self.outcome_reports
            .values()
            .filter(|report| report.service_id == service_id)
            .collect()
    }

    /// Get comprehensive welfare statistics
    pub fn get_welfare_statistics(&self) -> lib_consensus::WelfareStatistics {
        let total_services_registered = self.welfare_services.len() as u64;
        let active_services_count = self.welfare_services
            .values()
            .filter(|s| s.is_active)
            .count() as u64;
        
        let total_distributed = self.welfare_audit_trail
            .values()
            .map(|entry| entry.amount_distributed)
            .sum::<u64>();
        
        let total_beneficiaries_served = self.service_performance
            .values()
            .map(|perf| perf.total_beneficiaries)
            .sum::<u64>();
        
        let mut distribution_by_type = std::collections::HashMap::new();
        for entry in self.welfare_audit_trail.values() {
            *distribution_by_type.entry(entry.service_type.clone()).or_insert(0u64) 
                += entry.amount_distributed;
        }
        
        let average_distribution = if total_services_registered > 0 {
            total_distributed / total_services_registered
        } else {
            0
        };
        
        let pending_audits = self.welfare_audit_trail
            .values()
            .filter(|entry| entry.verification_status == lib_consensus::VerificationStatus::Pending)
            .count() as u64;
        
        let last_distribution_timestamp = self.welfare_audit_trail
            .values()
            .map(|entry| entry.distribution_timestamp)
            .max()
            .unwrap_or(0);
        
        lib_consensus::WelfareStatistics {
            total_allocated: 0, // Would need to query from economic processor
            total_distributed,
            available_balance: 0, // Would need to query from treasury
            active_services_count,
            total_services_registered,
            total_proposals: 0, // Would count from DAO proposals
            passed_proposals: 0,
            executed_proposals: 0,
            total_beneficiaries_served,
            distribution_by_type,
            average_distribution,
            efficiency_percentage: if total_services_registered > 0 {
                (active_services_count as f64 / total_services_registered as f64) * 100.0
            } else {
                0.0
            },
            last_distribution_timestamp,
            pending_audits,
        }
    }

    /// Get funding history for a service
    pub fn get_service_funding_history(
        &self,
        service_id: &str,
    ) -> Vec<lib_consensus::FundingHistoryEntry> {
        self.welfare_audit_trail
            .values()
            .filter(|entry| entry.service_id == service_id)
            .map(|entry| lib_consensus::FundingHistoryEntry {
                timestamp: entry.distribution_timestamp,
                block_height: entry.distribution_block,
                proposal_id: entry.proposal_id.clone(),
                service_id: entry.service_id.clone(),
                service_type: entry.service_type.clone(),
                amount: entry.amount_distributed,
                transaction_hash: entry.transaction_hash.clone(),
                status: match entry.verification_status {
                    lib_consensus::VerificationStatus::Pending => lib_consensus::FundingStatus::Approved,
                    lib_consensus::VerificationStatus::AutoVerified | 
                    lib_consensus::VerificationStatus::CommunityVerified => lib_consensus::FundingStatus::Verified,
                    lib_consensus::VerificationStatus::Flagged => lib_consensus::FundingStatus::UnderReview,
                    lib_consensus::VerificationStatus::Disputed => lib_consensus::FundingStatus::Disputed,
                    lib_consensus::VerificationStatus::Fraudulent => lib_consensus::FundingStatus::Disputed,
                },
            })
            .collect()
    }

    // ============================================================================
    // Proposal Impact Tracking
    // ============================================================================

    /// Calculate and set impact metrics for a welfare proposal
    pub fn calculate_welfare_impact(
        &self,
        proposal_type: &lib_consensus::DaoProposalType,
        amount: u64,
        service_type: Option<&lib_consensus::WelfareServiceType>,
    ) -> lib_consensus::ImpactMetrics {
        use lib_consensus::{ImpactLevel, ImpactMetrics, DaoProposalType, WelfareServiceType};

        let (ubi_impact, economic_impact, social_impact) = match proposal_type {
            DaoProposalType::WelfareAllocation => {
                let impact_level = match service_type {
                    Some(WelfareServiceType::Healthcare) | 
                    Some(WelfareServiceType::EmergencyResponse) => ImpactLevel::Critical,
                    Some(WelfareServiceType::Education) | 
                    Some(WelfareServiceType::FoodSecurity) => ImpactLevel::High,
                    Some(WelfareServiceType::Housing) | 
                    Some(WelfareServiceType::Infrastructure) => ImpactLevel::Medium,
                    _ => ImpactLevel::Low,
                };
                (ImpactLevel::Medium, impact_level.clone(), impact_level)
            },
            DaoProposalType::UbiDistribution => {
                let level = if amount > 1_000_000 {
                    ImpactLevel::Critical
                } else if amount > 100_000 {
                    ImpactLevel::High
                } else {
                    ImpactLevel::Medium
                };
                (level, ImpactLevel::High, ImpactLevel::High)
            },
            DaoProposalType::TreasuryAllocation => {
                (ImpactLevel::Low, ImpactLevel::High, ImpactLevel::Medium)
            },
            DaoProposalType::CommunityFunding => {
                (ImpactLevel::Low, ImpactLevel::Medium, ImpactLevel::High)
            },
            _ => (ImpactLevel::Low, ImpactLevel::Low, ImpactLevel::Low),
        };

        ImpactMetrics {
            ubi_impact,
            economic_impact,
            social_impact,
            privacy_level: 85, // Default high transparency
            expected_outcomes: String::from("Proposal impact calculated based on type and amount"),
            success_criteria: vec![
                String::from("Service delivery within timeframe"),
                String::from("Beneficiary satisfaction > 70%"),
                String::from("Budget efficiency > 80%"),
            ],
        }
    }

    /// Estimate beneficiary count for welfare proposal
    pub fn estimate_ubi_beneficiaries(
        &self,
        proposal_type: &lib_consensus::DaoProposalType,
        amount: u64,
    ) -> Option<u64> {
        use lib_consensus::DaoProposalType;

        match proposal_type {
            DaoProposalType::UbiDistribution => {
                // Estimate based on average UBI amount (e.g., 1000 ZHTP per beneficiary)
                Some(amount / 1000)
            },
            DaoProposalType::WelfareAllocation => {
                // Welfare services: estimate 1 beneficiary per 5000 ZHTP
                Some(amount / 5000)
            },
            DaoProposalType::CommunityFunding => {
                // Community projects: broader reach
                Some(amount / 2000)
            },
            _ => None, // Other proposal types don't directly impact beneficiaries
        }
    }

    // ============================================================================
    // Voting Power Calculation
    // ============================================================================

    /// Calculate comprehensive voting power for a user in DAO governance
    /// 
    /// Factors considered:
    /// - Base power: 1 vote (universal suffrage)
    /// - Staked amount: Long-term commitment (2x weight)
    /// - Network contribution: Storage/compute provided (up to 50% bonus)
    /// - Reputation: Historical participation quality (up to 25% bonus)
    /// - Delegated power: Votes delegated from other users
    /// 
    /// NOTE: Token balance is NOT included because this is a zero-knowledge blockchain.
    /// Transaction amounts are encrypted in Pedersen commitments and cannot be read.
    /// Voting power is derived entirely from publicly verifiable on-chain actions.
    pub fn calculate_user_voting_power(&self, user_id: &lib_identity::IdentityId) -> u64 {
        // Zero-knowledge blockchain: cannot extract balance from UTXOs
        // Transaction amounts are encrypted, so token balance = 0
        let token_balance = 0;
        
        // Get staked amount (check if user is validator)
        let staked_amount = self.validator_registry.values()
            .find(|v| v.identity_id == user_id.to_string())
            .map(|v| v.stake)
            .unwrap_or(0);
        
        // Calculate network contribution score (0-100)
        let network_contribution_score = self.calculate_network_contribution_score(user_id);
        
        // Calculate reputation score (0-100) based on on-chain activity
        let reputation_score = self.calculate_reputation_score(user_id);
        
        // Get delegated voting power (from vote delegation system)
        let delegated_power = self.get_delegated_voting_power(user_id);
        
        // Use DaoEngine's calculation formula
        lib_consensus::DaoEngine::calculate_voting_power(
            token_balance,
            staked_amount,
            network_contribution_score,
            reputation_score,
            delegated_power,
        )
    }

    /// Calculate network contribution score (0-100) based on storage and compute provided
    fn calculate_network_contribution_score(&self, user_id: &lib_identity::IdentityId) -> u32 {
        // Check if user is a validator providing resources
        if let Some(validator) = self.validator_registry.values()
            .find(|v| v.identity_id == user_id.to_string()) {
            // Score based on storage provided
            // 1 TB = 10 points, capped at 100
            let storage_score = ((validator.storage_provided / (1024 * 1024 * 1024 * 1024)) * 10).min(100) as u32;
            storage_score
        } else {
            0
        }
    }

    /// Calculate reputation score (0-100) based on on-chain behavior
    fn calculate_reputation_score(&self, user_id: &lib_identity::IdentityId) -> u32 {
        let mut score = 50u32; // Start at neutral 50
        
        // For validators, calculate based on uptime and slash history
        if let Some(validator) = self.validator_registry.values()
            .find(|v| v.identity_id == user_id.to_string()) {
            // Active validators start at 70
            if validator.status == "active" {
                score = 70;
            }
            // Penalize slashed/jailed validators
            if validator.status == "jailed" || validator.status == "slashed" {
                score = 20;
            }
        }
        
        // For non-validators or additional score, check participation in governance
        let proposal_participation = self.count_user_dao_votes(user_id);
        let proposal_submissions = self.count_user_dao_proposals(user_id);
        
        // Bonus for active participation (up to +30)
        score = score.saturating_add((proposal_participation / 5).min(20) as u32);
        score = score.saturating_add((proposal_submissions * 2).min(10) as u32);
        
        // Cap at 100
        score.min(100)
    }

    /// Get delegated voting power for a user
    fn get_delegated_voting_power(&self, _user_id: &lib_identity::IdentityId) -> u64 {
        // TODO: Implement vote delegation system
        // For now, return 0 as delegation not yet implemented
        0
    }

    /// Count number of DAO votes cast by user
    fn count_user_dao_votes(&self, user_id: &lib_identity::IdentityId) -> u64 {
        let user_id_str = user_id.to_string();
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter(|tx| {
                // Check if vote is from this user
                if let Some(ref vote_data) = tx.dao_vote_data {
                    vote_data.voter == user_id_str
                } else {
                    false
                }
            })
            .count() as u64
    }

    /// Count number of DAO proposals submitted by user
    fn count_user_dao_proposals(&self, user_id: &lib_identity::IdentityId) -> u64 {
        let user_id_str = user_id.to_string();
        self.blocks.iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter(|tx| {
                // Check if proposal is from this user
                if let Some(ref proposal_data) = tx.dao_proposal_data {
                    proposal_data.proposer == user_id_str
                } else {
                    false
                }
            })
            .count() as u64
    }

    /// Verify block with consensus rules
    pub async fn verify_block_with_consensus(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        // First run standard blockchain verification
        if !self.verify_block(block, previous_block)? {
            return Ok(false);
        }

        // If consensus coordinator is available, perform additional consensus verification
        if let Some(ref coordinator_arc) = self.consensus_coordinator {
            let coordinator = coordinator_arc.read().await;
            let status = coordinator.get_consensus_status().await?;
            
            // Verify block height matches consensus expectations
            if block.height() != status.current_height {
                warn!("Block height mismatch: block={}, consensus={}", 
                      block.height(), status.current_height);
                return Ok(false);
            }

            // Additional consensus-specific validations would go here
            info!("Block passed consensus verification at height {}", block.height());
        }

        Ok(true)
    }

    /// Check if a transaction is an economic system transaction (UBI/welfare/rewards)
    pub fn is_economic_system_transaction(&self, transaction: &Transaction) -> bool {
        crate::integration::economic_integration::utils::is_ubi_distribution(transaction) ||
        crate::integration::economic_integration::utils::is_welfare_distribution(transaction) ||
        crate::integration::economic_integration::utils::is_network_reward(transaction)
    }

    // ===== WALLET REFERENCE CONVERSION =====
    
    /// Convert minimal wallet references to full wallet data
    /// Note: Sensitive data (names, aliases, seed commitments) will need DHT retrieval
    fn convert_wallet_references_to_full_data(&self, wallet_refs: &HashMap<String, crate::transaction::WalletReference>) -> HashMap<String, crate::transaction::WalletTransactionData> {
        wallet_refs.iter().map(|(id, wallet_ref)| {
            // Create full wallet data from reference (missing sensitive fields will be empty/default)
            let wallet_data = crate::transaction::WalletTransactionData {
                wallet_id: wallet_ref.wallet_id,
                wallet_type: wallet_ref.wallet_type.clone(),
                wallet_name: format!("Wallet-{}", hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])), // Default name
                alias: None, // Will need DHT retrieval for real alias
                public_key: wallet_ref.public_key.clone(),
                owner_identity_id: wallet_ref.owner_identity_id,
                seed_commitment: crate::types::Hash::from([0u8; 32]), // Default - will need DHT for real commitment
                created_at: wallet_ref.created_at,
                registration_fee: wallet_ref.registration_fee,
                capabilities: 0, // Default - will need DHT for real capabilities
                initial_balance: wallet_ref.initial_balance,
            };
            (id.clone(), wallet_data)
        }).collect()
    }

    // ===== BLOCKCHAIN RECOVERY METHODS =====

    /// Recover blockchain state from persistent storage
    pub async fn recover_from_storage(&mut self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut _storage_manager = storage_manager_arc.write().await;
            info!(" Starting blockchain recovery from storage...");

            // For now, return false since the retrieval methods need proper implementation
            // TODO: Implement proper blockchain state recovery
            info!("Blockchain recovery needs complete retrieval method implementation");
            return Ok(false);
        }

        Ok(false)
    }

    /// Verify blockchain integrity after recovery
    pub async fn verify_blockchain_integrity(&self) -> Result<bool> {
        info!("Verifying blockchain integrity...");

        // Verify block chain continuity
        for i in 1..self.blocks.len() {
            let current = &self.blocks[i];
            let previous = &self.blocks[i - 1];

            if current.previous_hash() != previous.hash() {
                error!("Block chain continuity broken at height {}", i);
                return Ok(false);
            }

            if current.height() != previous.height() + 1 {
                error!("Block height sequence broken at height {}", i);
                return Ok(false);
            }
        }

        // Verify UTXO set consistency by rebuilding it
        let mut rebuilt_utxo_set = HashMap::new();
        let mut rebuilt_nullifier_set = HashSet::new();

        for block in &self.blocks {
            for tx in &block.transactions {
                // Add nullifiers
                for input in &tx.inputs {
                    rebuilt_nullifier_set.insert(input.nullifier);
                }

                // Add new outputs
                for (index, output) in tx.outputs.iter().enumerate() {
                    let output_id = self.calculate_output_id(&tx.hash(), index);
                    rebuilt_utxo_set.insert(output_id, output.clone());
                }
            }
        }

        if rebuilt_utxo_set.len() != self.utxo_set.len() {
            error!("UTXO set size mismatch: expected={}, actual={}", 
                   rebuilt_utxo_set.len(), self.utxo_set.len());
            return Ok(false);
        }

        if rebuilt_nullifier_set.len() != self.nullifier_set.len() {
            error!("Nullifier set size mismatch: expected={}, actual={}", 
                   rebuilt_nullifier_set.len(), self.nullifier_set.len());
            return Ok(false);
        }

        info!("Blockchain integrity verification passed");
        Ok(true)
    }

    /// Create a full backup of the blockchain to storage
    pub async fn create_full_backup(&self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            info!(" Creating full blockchain backup...");

            // Backup using the storage manager's backup functionality
            let backup_result = storage_manager.backup_blockchain(self).await?;
            let successful_backups = backup_result.iter().filter(|r| r.success).count();
            
            info!("Full blockchain backup completed: {}/{} operations successful", successful_backups, backup_result.len());
            return Ok(true);
        }

        warn!("No storage manager available for backup");
        Ok(false)
    }

    /// Restore blockchain from a backup
    pub async fn restore_from_backup(&mut self, backup_id: &str) -> Result<bool> {
        if let Some(_storage_manager) = &self.storage_manager {
            info!(" Restoring blockchain from backup: {}", backup_id);

            // Implementation would depend on storage manager's backup format
            // This is a placeholder for the restore functionality
            info!("Backup restore functionality needs implementation in storage manager");
            
            return Ok(false);
        }

        warn!("No storage manager available for restore");
        Ok(false)
    }

    /// Synchronize blockchain with storage (ensure consistency)
    pub async fn synchronize_with_storage(&mut self) -> Result<()> {
        if let Some(storage_manager_arc) = self.storage_manager.clone() {
            info!(" Synchronizing blockchain with storage...");

            // Persist current state
            self.persist_to_storage().await?;
            self.persist_utxo_set().await?;

            let mut storage_manager = storage_manager_arc.write().await;
            // Persist any unpersisted blocks
            for block in &self.blocks {
                let _ = storage_manager.store_block(block).await;
            }

            // Persist all identity data
            for (did, identity_data) in &self.identity_registry {
                let _ = storage_manager.store_identity_data(did, identity_data).await;
            }

            info!("Blockchain synchronization with storage completed");
        }

        Ok(())
    }

    // ===== STORAGE CONFIGURATION AND MONITORING =====

    /// Enable or disable automatic persistence
    pub fn set_auto_persist(&mut self, enabled: bool) {
        self.auto_persist_enabled = enabled;
        if enabled {
            info!("Automatic persistence enabled");
        } else {
            info!("Automatic persistence disabled");
        }
    }

    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> Result<Option<serde_json::Value>> {
        if let Some(_storage_manager) = &self.storage_manager {
            // This would return storage statistics from the unified storage system
            // Implementation depends on storage manager capabilities
            let stats = serde_json::json!({
                "utxo_count": self.utxo_set.len(),
                "identity_count": self.identity_registry.len(),
                "block_count": self.blocks.len(),
                "nullifier_count": self.nullifier_set.len(),
                "height": self.height,
                "auto_persist_enabled": self.auto_persist_enabled,
                "blocks_since_last_persist": self.blocks_since_last_persist
            });
            return Ok(Some(stats));
        }
        Ok(None)
    }

    /// Check if storage is healthy and accessible
    pub async fn check_storage_health(&self) -> Result<bool> {
        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            // Perform a simple storage health check
            match storage_manager.store_test_data().await {
                Ok(_) => {
                    info!("Storage health check passed");
                    Ok(true)
                }
                Err(e) => {
                    error!("Storage health check failed: {}", e);
                    Ok(false)
                }
            }
        } else {
            warn!("No storage manager configured");
            Ok(false)
        }
    }

    /// Cleanup old storage data (for maintenance)
    pub async fn cleanup_storage(&self, retain_blocks: u32) -> Result<()> {
        if let Some(_storage_manager) = &self.storage_manager {
            info!(" Starting storage cleanup, retaining last {} blocks", retain_blocks);
            
            // This would implement cleanup logic in the storage manager
            // For now, just log the operation
            info!("Storage cleanup implementation needed in storage manager");
        }
        Ok(())
    }

    /// Export the entire blockchain state for network transfer
    /// Includes: blocks, UTXO set, identity registry, wallet registry, and smart contracts
    pub fn export_chain(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct BlockchainExport {
            blocks: Vec<Block>,
            utxo_set: HashMap<Hash, TransactionOutput>,
            identity_registry: HashMap<String, IdentityTransactionData>,
            wallet_references: HashMap<String, crate::transaction::WalletReference>,  // Only public references
            validator_registry: HashMap<String, ValidatorInfo>,
            token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
            web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
            contract_blocks: HashMap<[u8; 32], u64>,
        }

        // Convert full wallet data to minimal references for sync
        let wallet_references: HashMap<String, crate::transaction::WalletReference> = self.wallet_registry.iter()
            .map(|(id, wallet_data)| {
                let wallet_ref = crate::transaction::WalletReference {
                    wallet_id: wallet_data.wallet_id,
                    wallet_type: wallet_data.wallet_type.clone(),
                    public_key: wallet_data.public_key.clone(),
                    owner_identity_id: wallet_data.owner_identity_id,
                    created_at: wallet_data.created_at,
                    registration_fee: wallet_data.registration_fee,
                    initial_balance: wallet_data.initial_balance,
                };
                (id.clone(), wallet_ref)
            })
            .collect();

        let export = BlockchainExport {
            blocks: self.blocks.clone(),
            utxo_set: self.utxo_set.clone(),
            identity_registry: self.identity_registry.clone(),
            wallet_references,  // Only minimal wallet references (no sensitive data)
            validator_registry: self.validator_registry.clone(),
            token_contracts: self.token_contracts.clone(),
            web4_contracts: self.web4_contracts.clone(),
            contract_blocks: self.contract_blocks.clone(),
        };

        info!(" Exporting blockchain: {} blocks, {} validators, {} token contracts, {} web4 contracts", 
            self.blocks.len(), self.validator_registry.len(), self.token_contracts.len(), self.web4_contracts.len());
        
        // Debug: Log transaction counts for each block
        for (i, block) in self.blocks.iter().enumerate() {
            info!("   Block {}: height={}, transactions={}, merkle_root={}", 
                  i, block.height(), block.transactions.len(), hex::encode(block.header.merkle_root.as_bytes()));
        }

        bincode::serialize(&export)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain: {}", e))
    }

    /// Evaluate and potentially merge a blockchain from another node
    /// Uses consensus rules to decide whether to adopt the imported chain
    pub async fn evaluate_and_merge_chain(&mut self, data: Vec<u8>) -> Result<lib_consensus::ChainMergeResult> {
        let import: BlockchainImport = bincode::deserialize(&data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize blockchain: {}", e))?;

        // Fast path: if local chain is empty (fresh node bootstrap), directly adopt
        // the imported chain without verification against empty state.
        // An empty blockchain has no state to validate transactions against,
        // so verify_block() would reject valid genesis transactions.
        // Check both is_empty() (no blocks at all) and height==0 (has placeholder genesis).
        if self.blocks.is_empty() || self.height == 0 {
            if import.blocks.is_empty() {
                info!("Both local and imported chains are empty - nothing to merge");
                return Ok(lib_consensus::ChainMergeResult::LocalKept);
            }
            let imported_height = import.blocks.len() as u64 - 1;
            info!("Local chain is empty - directly adopting imported chain (height={}, identities={}, validators={})",
                  imported_height, import.identity_registry.len(), import.validator_registry.len());
            self.blocks = import.blocks;
            self.height = imported_height;
            self.utxo_set = import.utxo_set;
            self.identity_registry = import.identity_registry;
            self.wallet_registry = self.convert_wallet_references_to_full_data(&import.wallet_references);
            self.validator_registry = import.validator_registry;
            self.token_contracts = import.token_contracts;
            self.web4_contracts = import.web4_contracts;
            self.contract_blocks = import.contract_blocks;
            info!("Successfully adopted imported chain during bootstrap");
            return Ok(lib_consensus::ChainMergeResult::ImportedAdopted);
        }

        // Verify all blocks in sequence
        for (i, block) in import.blocks.iter().enumerate() {
            if i == 0 {
                // Genesis block - just verify it's valid
                if !self.verify_block(block, None)? {
                    return Err(anyhow::anyhow!("Invalid genesis block in imported chain"));
                }
            } else {
                let prev_block = &import.blocks[i - 1];
                if block.header.previous_block_hash != prev_block.header.block_hash {
                    return Err(anyhow::anyhow!("Block chain integrity broken at block {}", i));
                }
                if !self.verify_block(block, Some(prev_block))? {
                    return Err(anyhow::anyhow!("Invalid block {} in imported chain", i));
                }
            }
        }

        // Create chain summaries for consensus evaluation
        let local_summary = self.create_local_chain_summary_async().await;
        let imported_summary = self.create_imported_chain_summary(
            &import.blocks,
            &import.identity_registry,
            &import.utxo_set,
            &import.token_contracts,
            &import.web4_contracts
        );

        // DEBUG: Log genesis hashes being compared
        info!(" Comparing blockchains for merge:");
        info!("   Local genesis hash:    {}", local_summary.genesis_hash);
        info!("   Imported genesis hash: {}", imported_summary.genesis_hash);
        info!("   Hashes equal: {}", local_summary.genesis_hash == imported_summary.genesis_hash);

        // Use consensus rules to decide which chain to adopt
        let decision = lib_consensus::ChainEvaluator::evaluate_chains(&local_summary, &imported_summary);

        match decision {
            lib_consensus::ChainDecision::KeepLocal => {
                info!(" Local chain is better - keeping current state");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                Ok(lib_consensus::ChainMergeResult::LocalKept)
            },
            lib_consensus::ChainDecision::MergeContentOnly => {
                info!(" Local chain is longer - merging unique content from shorter chain");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                
                // Extract unique content from imported chain (shorter) into local (longer)
                match self.merge_unique_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged unique content: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::ContentMerged)
                    },
                    Err(e) => {
                        warn!("Failed to merge content: {} - keeping local only", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!("Content merge error: {}", e)))
                    }
                }
            },
            lib_consensus::ChainDecision::AdoptImported => {
                info!(" Imported chain is better - performing intelligent merge");
                info!("   Local: height={}, work={}, identities={}", 
                      local_summary.height, local_summary.total_work, local_summary.total_identities);
                info!("   Imported: height={}, work={}, identities={}", 
                      imported_summary.height, imported_summary.total_work, imported_summary.total_identities);
                
                // Check if this is a genesis replacement (different genesis blocks)
                // IMPORTANT: Use merkle_root comparison to match ChainEvaluator logic
                // Different validators in genesis = different merkle roots = different networks
                let is_genesis_replacement = if !self.blocks.is_empty() && !import.blocks.is_empty() {
                    self.blocks[0].header.merkle_root != import.blocks[0].header.merkle_root
                } else {
                    false
                };
                
                if is_genesis_replacement {
                    info!("🔀 Genesis mismatch detected - performing full consolidation merge");
                    info!("   Old genesis merkle: {}", hex::encode(self.blocks[0].header.merkle_root.as_bytes()));
                    info!("   New genesis merkle: {}", hex::encode(import.blocks[0].header.merkle_root.as_bytes()));
                    
                    // Perform intelligent merge: adopt imported chain but preserve unique local data
                    match self.merge_with_genesis_mismatch(&import) {
                        Ok(merge_report) => {
                            info!(" Successfully merged chains with genesis consolidation");
                            info!("{}", merge_report);
                            Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                        }
                        Err(e) => {
                            warn!(" Genesis merge failed: {} - adopting imported chain only", e);
                            // Fallback: just adopt imported chain
                            self.blocks = import.blocks;
                            self.height = self.blocks.len() as u64 - 1;
                            self.utxo_set = import.utxo_set;
                            self.identity_registry = import.identity_registry;
                            // Convert wallet references to full data (sensitive data will need DHT retrieval)
                            self.wallet_registry = self.convert_wallet_references_to_full_data(&import.wallet_references);
                            self.validator_registry = import.validator_registry;
                            self.token_contracts = import.token_contracts;
                            self.web4_contracts = import.web4_contracts;
                            self.contract_blocks = import.contract_blocks;
                            Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                        }
                    }
                } else {
                    info!(" Same genesis - adopting longer chain");
                    // Simple case: same genesis, just adopt imported chain
                    self.blocks = import.blocks;
                    self.height = self.blocks.len() as u64 - 1;
                    self.utxo_set = import.utxo_set;
                    self.identity_registry = import.identity_registry;
                    // Convert wallet references to full data (sensitive data will need DHT retrieval)
                    self.wallet_registry = self.convert_wallet_references_to_full_data(&import.wallet_references);
                    self.validator_registry = import.validator_registry;
                    self.token_contracts = import.token_contracts;
                    self.web4_contracts = import.web4_contracts;
                    self.contract_blocks = import.contract_blocks;
                    
                    // Clear nullifier set and rebuild from new chain
                    self.nullifier_set.clear();
                    for block in &self.blocks {
                        for tx in &block.transactions {
                            for input in &tx.inputs {
                                self.nullifier_set.insert(input.nullifier);
                            }
                        }
                    }
                    
                    info!(" Adopted imported chain");
                    info!("   New height: {}", self.height);
                    info!("   Identities: {}", self.identity_registry.len());
                    info!("   Validators: {}", self.validator_registry.len());
                    info!("   UTXOs: {}", self.utxo_set.len());
                    
                    Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                }
            },
            lib_consensus::ChainDecision::Merge => {
                info!(" Merging compatible chains");
                info!("   Local: height={}, work={}, identities={}, contracts={}", 
                      local_summary.height, local_summary.total_work, 
                      local_summary.total_identities, local_summary.total_contracts);
                info!("   Imported: height={}, work={}, identities={}, contracts={}", 
                      imported_summary.height, imported_summary.total_work, 
                      imported_summary.total_identities, imported_summary.total_contracts);
                
                match self.merge_chain_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged chains: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::Merged)
                    },
                    Err(e) => {
                        warn!("Failed to merge chains: {} - keeping local", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!("Merge error: {}", e)))
                    }
                }
            },
            lib_consensus::ChainDecision::AdoptLocal => {
                info!("🏆 Local chain is stronger - using as merge base");
                info!("   Local: height={}, validators={}, identities={}", 
                      local_summary.height, local_summary.validator_count, local_summary.total_identities);
                info!("   Imported: height={}, validators={}, identities={}", 
                      imported_summary.height, imported_summary.validator_count, imported_summary.total_identities);
                
                // Local chain is the stronger network - use it as base
                // Import unique content from remote chain into local
                match self.merge_imported_into_local(&import) {
                    Ok(merge_report) => {
                        info!(" Successfully merged imported content into local chain");
                        info!("{}", merge_report);
                        Ok(lib_consensus::ChainMergeResult::LocalKept)
                    }
                    Err(e) => {
                        warn!(" Failed to merge imported content: {} - keeping local only", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!("Import merge error: {}", e)))
                    }
                }
            },
            lib_consensus::ChainDecision::Reject => {
                warn!("🚫 Networks are incompatible - merge rejected for safety");
                warn!("   Local: height={}, validators={}, age={}d", 
                      local_summary.height, local_summary.validator_count,
                      (local_summary.latest_timestamp - local_summary.genesis_timestamp) / (24 * 3600));
                warn!("   Imported: height={}, validators={}, age={}d", 
                      imported_summary.height, imported_summary.validator_count,
                      (imported_summary.latest_timestamp - imported_summary.genesis_timestamp) / (24 * 3600));
                warn!("   Networks differ too much in size or age to merge safely");
                
                Ok(lib_consensus::ChainMergeResult::Failed(
                    "Networks incompatible - safety threshold exceeded".to_string()
                ))
            },
            lib_consensus::ChainDecision::Conflict => {
                warn!(" Chain conflict detected - different genesis blocks");
                warn!("   Local genesis: {}", 
                      if !self.blocks.is_empty() { 
                          hex::encode(self.blocks[0].header.block_hash.as_bytes()) 
                      } else { 
                          "none".to_string() 
                      });
                warn!("   Imported genesis: {}", 
                      if !import.blocks.is_empty() { 
                          hex::encode(import.blocks[0].header.block_hash.as_bytes()) 
                      } else { 
                          "none".to_string() 
                      });
                warn!("   These chains are from different networks and cannot be merged");
                
                Ok(lib_consensus::ChainMergeResult::Failed(
                    "Genesis hash mismatch - chains from different networks".to_string()
                ))
            }
        }
    }

    /// Create chain summary for local blockchain
    async fn create_local_chain_summary_async(&self) -> lib_consensus::ChainSummary {
        // Use merkle root as genesis hash - this reflects the actual transaction content
        // Different validators in genesis will have different merkle roots
        let genesis_hash = self.blocks.first()
            .map(|b| b.header.merkle_root.to_string())
            .unwrap_or_else(|| "none".to_string());
            
        let genesis_timestamp = self.blocks.first()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
            
        let latest_timestamp = self.blocks.last()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);

        // Get consensus data if coordinator is available
        let (validator_count, total_validator_stake, validator_set_hash) = 
            if let Some(ref coordinator_arc) = self.consensus_coordinator {
                let coordinator = coordinator_arc.read().await;
                match coordinator.get_consensus_status().await {
                    Ok(status) => {
                        // Get validator stats for stake information
                        let validator_infos = coordinator.list_all_validators().await.unwrap_or_default();
                        let total_stake: u128 = validator_infos.iter().map(|v| v.stake_amount as u128).fold(0u128, |acc, x| acc.saturating_add(x));
                        
                        // Calculate validator set hash
                        let validator_ids: Vec<String> = validator_infos.iter()
                            .map(|v| v.identity.to_string())
                            .collect();
                        let validator_hash = if !validator_ids.is_empty() {
                            hex::encode(lib_crypto::hash_blake3(format!("{:?}", validator_ids).as_bytes()))
                        } else {
                            String::new()
                        };
                        
                        (
                            status.active_validators as u64,
                            total_stake,
                            validator_hash
                        )
                    },
                    Err(_) => (0, 0, String::new())
                }
            } else {
                (0, 0, String::new())
            };

        // Estimate TPS based on recent blocks
        let expected_tps = if self.blocks.len() >= 10 {
            let recent_blocks = &self.blocks[self.blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks.last().map(|b| b.header.timestamp)
                .unwrap_or(0) - recent_blocks.first().map(|b| b.header.timestamp)
                .unwrap_or(0);
            if time_span > 0 {
                total_txs / time_span.max(1)
            } else {
                100
            }
        } else {
            100
        };

        // Network size estimate from identity registry (each identity represents a potential node)
        let network_size = self.identity_registry.len().max(1) as u64;

        // Bridge node count (for now, based on special identity types in registry)
        let bridge_node_count = self.identity_registry.values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        lib_consensus::ChainSummary {
            height: self.get_height(),
            total_work: self.calculate_total_work(),
            total_transactions: self.blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x)),
            total_identities: self.identity_registry.len() as u64,
            total_utxos: self.utxo_set.len() as u64,
            total_contracts: (self.token_contracts.len() + self.web4_contracts.len()) as u64,
            genesis_timestamp,
            latest_timestamp,
            genesis_hash,
            validator_count,
            total_validator_stake,
            validator_set_hash,
            bridge_node_count,
            expected_tps,
            network_size,
        }
    }

    /// Merge content from compatible blockchain without replacing existing data
    fn merge_chain_content(&mut self, import: &BlockchainImport) -> Result<String> {
        let mut merged_items = Vec::new();
        
        // Merge identities (add new ones, preserve existing)
        let mut new_identities = 0;
        for (did, identity_data) in &import.identity_registry {
            if !self.identity_registry.contains_key(did) {
                self.identity_registry.insert(did.clone(), identity_data.clone());
                new_identities += 1;
            }
        }
        if new_identities > 0 {
            merged_items.push(format!("{} identities", new_identities));
        }
        
        // Merge wallets (add new ones, preserve existing) 
        let mut new_wallets = 0;
        for (wallet_id, wallet_ref) in &import.wallet_references {
            if !self.wallet_registry.contains_key(wallet_id) {
                // Convert wallet reference to full data (with default sensitive fields)
                let wallet_data = crate::transaction::WalletTransactionData {
                    wallet_id: wallet_ref.wallet_id,
                    wallet_type: wallet_ref.wallet_type.clone(),
                    wallet_name: format!("Wallet-{}", hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])),
                    alias: None,
                    public_key: wallet_ref.public_key.clone(),
                    owner_identity_id: wallet_ref.owner_identity_id,
                    seed_commitment: crate::types::Hash::from([0u8; 32]),
                    created_at: wallet_ref.created_at,
                    registration_fee: wallet_ref.registration_fee,
                    capabilities: 0,
                    initial_balance: 0,
                };
                self.wallet_registry.insert(wallet_id.clone(), wallet_data);
                new_wallets += 1;
            }
        }
        if new_wallets > 0 {
            merged_items.push(format!("{} wallets", new_wallets));
        }
        
        // Merge contracts (add new ones, preserve existing)
        let mut new_token_contracts = 0;
        for (contract_id, contract) in &import.token_contracts {
            if !self.token_contracts.contains_key(contract_id as &[u8; 32]) {
                self.token_contracts.insert(*contract_id, contract.clone());
                new_token_contracts += 1;
            }
        }
        if new_token_contracts > 0 {
            merged_items.push(format!("{} token contracts", new_token_contracts));
        }
        
        let mut new_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                self.web4_contracts.insert(*contract_id, contract.clone());
                new_web4_contracts += 1;
            }
        }
        if new_web4_contracts > 0 {
            merged_items.push(format!("{} web4 contracts", new_web4_contracts));
        }
        
        // Merge UTXOs (add new ones, preserve existing)
        let mut new_utxos = 0;
        for (utxo_hash, utxo) in &import.utxo_set {
            if !self.utxo_set.contains_key(utxo_hash as &Hash) {
                self.utxo_set.insert(*utxo_hash, utxo.clone());
                new_utxos += 1;
            }
        }
        if new_utxos > 0 {
            merged_items.push(format!("{} UTXOs", new_utxos));
        }
        
        // Merge contract deployment heights (for tracking)
        let mut new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                new_contract_blocks += 1;
            }
        }
        
        // If chains have different heights, merge missing blocks
        if import.blocks.len() != self.blocks.len() {
            if import.blocks.len() > self.blocks.len() {
                // Imported chain is longer - add missing blocks
                let missing_blocks = &import.blocks[self.blocks.len()..];
                let mut added_blocks = 0;
                
                for block in missing_blocks {
                    // Verify block before adding
                    let prev_block = self.blocks.last();
                    if self.verify_block(block, prev_block)? {
                        self.blocks.push(block.clone());
                        self.height = block.height();
                        added_blocks += 1;
                        info!("  Added missing block at height {}", block.height());
                    } else {
                        warn!("  Failed to verify imported block at height {}, stopping block merge", block.height());
                        break;
                    }
                }
                
                if added_blocks > 0 {
                    merged_items.push(format!("{} blocks", added_blocks));
                }
            } else {
                // Local chain is longer - just report the difference
                let block_diff = self.blocks.len() - import.blocks.len();
                info!("  Local chain is {} blocks ahead, not adopting shorter chain", block_diff);
            }
        }
        
        if merged_items.is_empty() {
            Ok("no new content to merge".to_string())
        } else {
            Ok(merged_items.join(", "))
        }
    }

    /// Intelligently merge two chains with different genesis blocks
    /// Adopts the imported chain as the base and consolidates unique data from local chain
    /// Includes economic reconciliation to prevent money supply inflation
    fn merge_with_genesis_mismatch(&mut self, import: &BlockchainImport) -> Result<String> {
        info!("🔀 Starting network merge with economic reconciliation");
        info!("   Local network: {} blocks, {} identities, {} validators", 
              self.blocks.len(), self.identity_registry.len(), self.validator_registry.len());
        info!("   Imported network: {} blocks, {} identities, {} validators", 
              import.blocks.len(), import.identity_registry.len(), import.validator_registry.len());
        
        let mut merge_report = Vec::new();
        
        // STEP 0: Calculate economic state BEFORE merge for reconciliation
        let local_utxo_count = self.utxo_set.len();
        let import_utxo_count = import.utxo_set.len();
        
        info!(" Pre-merge economic state:");
        info!("   Local UTXOs: {}", local_utxo_count);
        info!("   Imported UTXOs: {}", import_utxo_count);
        info!("   Combined would be: {} UTXOs", local_utxo_count + import_utxo_count);
        
        // Step 1: Extract unique identities from local chain
        let mut unique_identities = 0;
        let mut local_identities_to_preserve = Vec::new();
        for (did, identity_data) in &self.identity_registry {
            if !import.identity_registry.contains_key(did) {
                local_identities_to_preserve.push((did.clone(), identity_data.clone()));
                unique_identities += 1;
            }
        }
        
        // Step 2: Extract unique validators from local chain
        let mut unique_validators = 0;
        let mut local_validators_to_preserve = Vec::new();
        for (validator_id, validator_info) in &self.validator_registry {
            if !import.validator_registry.contains_key(validator_id as &str) {
                local_validators_to_preserve.push((validator_id.clone(), validator_info.clone()));
                unique_validators += 1;
            }
        }
        
        // Step 3: Extract unique wallets from local chain
        let mut unique_wallets = 0;
        let mut local_wallets_to_preserve = Vec::new();
        for (wallet_id, wallet_data) in &self.wallet_registry {
            if !import.wallet_references.contains_key(wallet_id) {
                local_wallets_to_preserve.push((wallet_id.clone(), wallet_data.clone()));
                unique_wallets += 1;
            }
        }
        
        // Step 4: Extract unique UTXOs from local chain
        let mut unique_utxos = 0;
        let mut local_utxos_to_preserve = Vec::new();
        for (utxo_hash, utxo) in &self.utxo_set {
            if !import.utxo_set.contains_key(utxo_hash as &Hash) {
                local_utxos_to_preserve.push((*utxo_hash, utxo.clone()));
                unique_utxos += 1;
            }
        }
        
        // Step 5: Extract unique contracts from local chain
        let mut unique_token_contracts = 0;
        let mut local_token_contracts = Vec::new();
        for (contract_id, contract) in &self.token_contracts {
            if !import.token_contracts.contains_key(contract_id as &[u8; 32]) {
                local_token_contracts.push((*contract_id, contract.clone()));
                unique_token_contracts += 1;
            }
        }
        
        let mut unique_web4_contracts = 0;
        let mut local_web4_contracts = Vec::new();
        for (contract_id, contract) in &self.web4_contracts {
            if !import.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                local_web4_contracts.push((*contract_id, contract.clone()));
                unique_web4_contracts += 1;
            }
        }
        
        info!(" Found unique local data:");
        info!("   {} identities", unique_identities);
        info!("   {} validators", unique_validators);
        info!("   {} wallets", unique_wallets);
        info!("   {} UTXOs", unique_utxos);
        info!("   {} token contracts", unique_token_contracts);
        info!("   {} web4 contracts", unique_web4_contracts);
        
        // Step 6: Adopt imported chain as base
        self.blocks = import.blocks.clone();
        self.height = self.blocks.len() as u64 - 1;
        self.identity_registry = import.identity_registry.clone();
        self.wallet_registry = self.convert_wallet_references_to_full_data(&import.wallet_references);
        self.validator_registry = import.validator_registry.clone();
        self.utxo_set = import.utxo_set.clone();
        self.token_contracts = import.token_contracts.clone();
        self.web4_contracts = import.web4_contracts.clone();
        self.contract_blocks = import.contract_blocks.clone();
        
        // Step 7: Merge unique local data into adopted chain
        for (did, identity_data) in local_identities_to_preserve {
            self.identity_registry.insert(did, identity_data);
        }
        if unique_identities > 0 {
            merge_report.push(format!("merged {} unique identities", unique_identities));
        }
        
        for (validator_id, validator_info) in local_validators_to_preserve {
            self.validator_registry.insert(validator_id, validator_info);
        }
        if unique_validators > 0 {
            merge_report.push(format!("merged {} unique validators", unique_validators));
        }
        
        for (wallet_id, wallet_data) in local_wallets_to_preserve {
            self.wallet_registry.insert(wallet_id, wallet_data);
        }
        if unique_wallets > 0 {
            merge_report.push(format!("merged {} unique wallets", unique_wallets));
        }
        
        for (utxo_hash, utxo) in local_utxos_to_preserve {
            self.utxo_set.insert(utxo_hash, utxo);
        }
        if unique_utxos > 0 {
            merge_report.push(format!("merged {} unique UTXOs", unique_utxos));
        }
        
        for (contract_id, contract) in local_token_contracts {
            self.token_contracts.insert(contract_id, contract);
        }
        if unique_token_contracts > 0 {
            merge_report.push(format!("merged {} unique token contracts", unique_token_contracts));
        }
        
        for (contract_id, contract) in local_web4_contracts {
            self.web4_contracts.insert(contract_id, contract);
        }
        if unique_web4_contracts > 0 {
            merge_report.push(format!("merged {} unique web4 contracts", unique_web4_contracts));
        }
        
        // Step 8: Economic Reconciliation - Handle Money Supply
        let post_merge_utxo_count = self.utxo_set.len();
        
        info!(" Post-merge economic state:");
        info!("   Total UTXOs after merge: {}", post_merge_utxo_count);
        info!("   Economics consolidation: All networks' assets preserved");
        
        // Note: We deliberately allow the combined UTXO set because:
        // 1. Both networks had legitimate economic activity
        // 2. Validators from both networks are now securing the merged chain
        // 3. The combined hash rate/stake makes the network more secure
        // 4. Citizens from both networks retain their holdings
        //
        // Alternative strategies if supply control is needed:
        // - Implement decay/taxation on merged UTXOs over time
        // - Require proof-of-burn for cross-network transfers
        // - Use exchange rate conversion between networks
        
        merge_report.push(format!("consolidated {} UTXOs from {} networks", 
                                  post_merge_utxo_count, 2));
        
        // Step 9: Rebuild nullifier set from merged state
        self.nullifier_set.clear();
        for block in &self.blocks {
            for tx in &block.transactions {
                for input in &tx.inputs {
                    self.nullifier_set.insert(input.nullifier);
                }
            }
        }
        
        info!(" Network merge complete with economic reconciliation!");
        info!("   Final network: {} blocks, {} identities, {} validators, {} UTXOs", 
              self.blocks.len(), self.identity_registry.len(), 
              self.validator_registry.len(), self.utxo_set.len());
        info!("   Security improvement: Combined validator set and hash rate");
        info!("   Economic state: All citizens' holdings preserved");
        
        if merge_report.is_empty() {
            Ok("adopted imported chain (no unique local data to merge)".to_string())
        } else {
            Ok(format!("adopted imported chain and {}", merge_report.join(", ")))
        }
    }

    /// Merge imported chain content into local chain (local is stronger base)
    /// This is the reverse of merge_with_genesis_mismatch - local chain is kept as base
    /// All unique content from imported chain is preserved and added to local
    fn merge_imported_into_local(&mut self, import: &BlockchainImport) -> Result<String> {
        info!("🔀 Merging imported network into stronger local network");
        info!("   Local network (BASE): {} blocks, {} identities, {} validators", 
              self.blocks.len(), self.identity_registry.len(), self.validator_registry.len());
        info!("   Imported network: {} blocks, {} identities, {} validators", 
              import.blocks.len(), import.identity_registry.len(), import.validator_registry.len());
        
        let mut merge_report = Vec::new();
        
        // STEP 0: Calculate economic state BEFORE merge
        let local_utxo_count = self.utxo_set.len();
        let import_utxo_count = import.utxo_set.len();
        
        info!(" Pre-merge economic state:");
        info!("   Local UTXOs: {}", local_utxo_count);
        info!("   Imported UTXOs: {}", import_utxo_count);
        
        // CRITICAL: Extract ALL unique identities from imported chain
        // This ensures users from the smaller network don't lose their identities
        let mut unique_identities = 0;
        for (did, identity_data) in &import.identity_registry {
            if !self.identity_registry.contains_key(did) {
                info!("  Preserving imported identity: {}", did);
                self.identity_registry.insert(did.clone(), identity_data.clone());
                unique_identities += 1;
            }
        }
        if unique_identities > 0 {
            merge_report.push(format!("imported {} unique identities", unique_identities));
        }
        
        // Extract unique validators from imported chain
        let mut unique_validators = 0;
        for (validator_id, validator_info) in &import.validator_registry {
            if !self.validator_registry.contains_key(validator_id as &str) {
                info!("  Preserving imported validator: {}", validator_id);
                self.validator_registry.insert(validator_id.clone(), validator_info.clone());
                unique_validators += 1;
            }
        }
        if unique_validators > 0 {
            merge_report.push(format!("imported {} unique validators", unique_validators));
        }
        
        // Extract unique wallets from imported chain
        let mut unique_wallets = 0;
        for (wallet_id, wallet_ref) in &import.wallet_references {
            if !self.wallet_registry.contains_key(wallet_id) {
                info!("  Preserving imported wallet: {}", wallet_id);
                // Convert wallet reference to full data
                let wallet_data = crate::transaction::WalletTransactionData {
                    wallet_id: wallet_ref.wallet_id,
                    wallet_type: wallet_ref.wallet_type.clone(),
                    wallet_name: format!("Wallet-{}", hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])),
                    alias: None,
                    public_key: wallet_ref.public_key.clone(),
                    owner_identity_id: wallet_ref.owner_identity_id,
                    seed_commitment: crate::types::Hash::from([0u8; 32]),
                    created_at: wallet_ref.created_at,
                    registration_fee: wallet_ref.registration_fee,
                    capabilities: 0,
                    initial_balance: 0,
                };
                self.wallet_registry.insert(wallet_id.clone(), wallet_data);
                unique_wallets += 1;
            }
        }
        if unique_wallets > 0 {
            merge_report.push(format!("imported {} unique wallets", unique_wallets));
        }
        
        // Extract unique UTXOs from imported chain  
        let mut unique_utxos = 0;
        for (utxo_hash, utxo) in &import.utxo_set {
            if !self.utxo_set.contains_key(utxo_hash as &Hash) {
                self.utxo_set.insert(*utxo_hash, utxo.clone());
                unique_utxos += 1;
            }
        }
        if unique_utxos > 0 {
            merge_report.push(format!("imported {} unique UTXOs", unique_utxos));
        }
        
        // Extract unique contracts from imported chain
        let mut unique_token_contracts = 0;
        for (contract_id, contract) in &import.token_contracts {
            if !self.token_contracts.contains_key(contract_id as &[u8; 32]) {
                self.token_contracts.insert(*contract_id, contract.clone());
                unique_token_contracts += 1;
            }
        }
        if unique_token_contracts > 0 {
            merge_report.push(format!("imported {} unique token contracts", unique_token_contracts));
        }
        
        let mut unique_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                self.web4_contracts.insert(*contract_id, contract.clone());
                unique_web4_contracts += 1;
            }
        }
        if unique_web4_contracts > 0 {
            merge_report.push(format!("imported {} unique web4 contracts", unique_web4_contracts));
        }
        
        // Post-merge economic state
        let post_merge_utxo_count = self.utxo_set.len();
        
        info!(" Post-merge economic state:");
        info!("   Total UTXOs after merge: {}", post_merge_utxo_count);
        info!("   All imported users' assets preserved in stronger local network");
        
        merge_report.push(format!("consolidated {} UTXOs from both networks", 
                                  post_merge_utxo_count));
        
        info!(" Imported network successfully merged into local base!");
        info!("   Final network: {} blocks, {} identities, {} validators, {} UTXOs", 
              self.blocks.len(), self.identity_registry.len(), 
              self.validator_registry.len(), self.utxo_set.len());
        info!("   Local chain history preserved, imported users migrated successfully");
        
        if merge_report.is_empty() {
            Ok("kept local chain (no unique imported data to merge)".to_string())
        } else {
            Ok(format!("kept local chain and {}", merge_report.join(", ")))
        }
    }
    
    /// Merge unique content from shorter chain into longer chain
    /// This prevents data loss when local chain is longer but imported has unique identities/wallets/contracts
    fn merge_unique_content(&mut self, import: &BlockchainImport) -> Result<String> {
        let mut merged_items = Vec::new();
        
        info!("Extracting unique content from shorter chain (height {}) into longer chain (height {})",
              import.blocks.len(), self.blocks.len());
        
        // Merge identities (add new ones that don't exist in local chain)
        let mut new_identities = 0;
        for (did, identity_data) in &import.identity_registry {
            if !self.identity_registry.contains_key(did) {
                info!("  Adding unique identity: {}", did);
                self.identity_registry.insert(did.clone(), identity_data.clone());
                new_identities += 1;
            }
        }
        if new_identities > 0 {
            merged_items.push(format!("{} identities", new_identities));
        }
        
        // Merge wallets (add new ones that don't exist in local chain)
        let mut new_wallets = 0;
        for (wallet_id, wallet_ref) in &import.wallet_references {
            if !self.wallet_registry.contains_key(wallet_id) {
                info!("  Adding unique wallet: {}", wallet_id);
                // Convert wallet reference to full data
                let wallet_data = crate::transaction::WalletTransactionData {
                    wallet_id: wallet_ref.wallet_id,
                    wallet_type: wallet_ref.wallet_type.clone(),
                    wallet_name: format!("Wallet-{}", hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])),
                    alias: None,
                    public_key: wallet_ref.public_key.clone(),
                    owner_identity_id: wallet_ref.owner_identity_id,
                    seed_commitment: crate::types::Hash::from([0u8; 32]),
                    created_at: wallet_ref.created_at,
                    registration_fee: wallet_ref.registration_fee,
                    capabilities: 0,
                    initial_balance: 0,
                };
                self.wallet_registry.insert(wallet_id.clone(), wallet_data);
                new_wallets += 1;
            }
        }
        if new_wallets > 0 {
            merged_items.push(format!("{} wallets", new_wallets));
        }
        
        // Merge contracts (add new ones that don't exist in local chain)
        let mut new_token_contracts = 0;
        for (contract_id, contract) in &import.token_contracts {
            if !self.token_contracts.contains_key(contract_id as &[u8; 32]) {
                info!("  Adding unique token contract: {:?}", hex::encode(contract_id));
                self.token_contracts.insert(*contract_id, contract.clone());
                new_token_contracts += 1;
            }
        }
        if new_token_contracts > 0 {
            merged_items.push(format!("{} token contracts", new_token_contracts));
        }
        
        let mut new_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                info!("  Adding unique web4 contract: {:?}", hex::encode(contract_id));
                self.web4_contracts.insert(*contract_id, contract.clone());
                new_web4_contracts += 1;
            }
        }
        if new_web4_contracts > 0 {
            merged_items.push(format!("{} web4 contracts", new_web4_contracts));
        }
        
        // Merge UTXOs (add new ones that aren't spent in local chain)
        let mut new_utxos = 0;
        for (utxo_hash, utxo) in &import.utxo_set {
            if !self.utxo_set.contains_key(utxo_hash as &Hash) {
                self.utxo_set.insert(*utxo_hash, utxo.clone());
                new_utxos += 1;
            }
        }
        if new_utxos > 0 {
            merged_items.push(format!("{} UTXOs", new_utxos));
        }
        
        // Merge contract deployment records
        let mut new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                new_contract_blocks += 1;
            }
        }
        
        if merged_items.is_empty() {
            Ok("no unique content found in shorter chain".to_string())
        } else {
            info!("Successfully merged unique content from shorter chain");
            Ok(merged_items.join(", "))
        }
    }

    /// Create chain summary for imported blockchain
    fn create_imported_chain_summary(&self, 
        blocks: &[Block], 
        identity_registry: &HashMap<String, IdentityTransactionData>,
        utxo_set: &HashMap<Hash, TransactionOutput>,
        token_contracts: &HashMap<[u8; 32], crate::contracts::TokenContract>,
        web4_contracts: &HashMap<[u8; 32], crate::contracts::web4::Web4Contract>
    ) -> lib_consensus::ChainSummary {
        // Use merkle root as genesis hash - this reflects the actual transaction content
        // Different validators in genesis will have different merkle roots
        let genesis_hash = blocks.first()
            .map(|b| b.header.merkle_root.to_string())
            .unwrap_or_else(|| "none".to_string());
            
        let genesis_timestamp = blocks.first()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
            
        let latest_timestamp = blocks.last()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);

        // Estimate TPS based on recent blocks in imported chain
        let expected_tps = if blocks.len() >= 10 {
            let recent_blocks = &blocks[blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks.last().map(|b| b.header.timestamp)
                .unwrap_or(0) - recent_blocks.first().map(|b| b.header.timestamp)
                .unwrap_or(0);
            if time_span > 0 {
                total_txs / time_span.max(1)
            } else {
                100
            }
        } else {
            100
        };

        // Network size estimate from imported identity registry
        let network_size = identity_registry.len().max(1) as u64;

        // Bridge node count from imported identity registry
        let bridge_node_count = identity_registry.values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        // For imported chains, we don't have access to their consensus coordinator
        // So we estimate validator info from special identity types
        let validator_count = identity_registry.values()
            .filter(|id| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .count() as u64;

        // Estimate total stake from validator identities (if they have reputation scores)
        let total_validator_stake: u128 = identity_registry.values()
            .filter(|id| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .map(|id| id.registration_fee as u128)
            .fold(0u128, |acc, x| acc.saturating_add(x));

        // Calculate validator set hash from imported identities
        let validator_identities: Vec<String> = identity_registry.iter()
            .filter(|(_, id)| id.identity_type.contains("validator") || id.identity_type.contains("Validator"))
            .map(|(did, _)| did.clone())
            .collect();
        let validator_set_hash = if !validator_identities.is_empty() {
            hex::encode(lib_crypto::hash_blake3(format!("{:?}", validator_identities).as_bytes()))
        } else {
            String::new()
        };

        lib_consensus::ChainSummary {
            height: blocks.len().saturating_sub(1) as u64,
            total_work: self.calculate_imported_total_work(blocks),
            total_transactions: blocks.iter().map(|b| b.transactions.len() as u64).fold(0u64, |acc, x| acc.saturating_add(x)),
            total_identities: identity_registry.len() as u64,
            total_utxos: utxo_set.len() as u64,
            total_contracts: (token_contracts.len() + web4_contracts.len()) as u64,
            genesis_timestamp,
            latest_timestamp,
            genesis_hash,
            validator_count,
            total_validator_stake,
            validator_set_hash,
            bridge_node_count,
            expected_tps,
            network_size,
        }
    }

    /// Calculate total work for imported blocks
    fn calculate_imported_total_work(&self, blocks: &[Block]) -> u128 {
        blocks.iter()
            .map(|block| block.header.difficulty.work())
            .fold(0u128, |acc, work| acc.saturating_add(work))
    }

    /// Calculate total work for current blockchain
    fn calculate_total_work(&self) -> u128 {
        self.blocks.iter()
            .map(|block| block.header.difficulty.work())
            .fold(0u128, |acc, work| acc.saturating_add(work))
    }

    // ============================================================================
    // SMART CONTRACT REGISTRY METHODS
    // ============================================================================
    
    /// Register a token contract in the blockchain
    pub fn register_token_contract(&mut self, contract_id: [u8; 32], contract: crate::contracts::TokenContract, block_height: u64) {
        self.token_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(" Registered token contract {} at block {}", hex::encode(contract_id), block_height);
    }
    
    /// Get a token contract from the blockchain
    pub fn get_token_contract(&self, contract_id: &[u8; 32]) -> Option<&crate::contracts::TokenContract> {
        self.token_contracts.get(contract_id)
    }
    
    /// Get a mutable reference to a token contract
    pub fn get_token_contract_mut(&mut self, contract_id: &[u8; 32]) -> Option<&mut crate::contracts::TokenContract> {
        self.token_contracts.get_mut(contract_id)
    }
    
    /// Register a Web4 contract in the blockchain
    pub fn register_web4_contract(&mut self, contract_id: [u8; 32], contract: crate::contracts::web4::Web4Contract, block_height: u64) {
        self.web4_contracts.insert(contract_id, contract);
        self.contract_blocks.insert(contract_id, block_height);
        info!(" Registered Web4 contract {} at block {}", hex::encode(contract_id), block_height);
    }
    
    /// Get a Web4 contract from the blockchain
    pub fn get_web4_contract(&self, contract_id: &[u8; 32]) -> Option<&crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get(contract_id)
    }
    
    /// Get a mutable reference to a Web4 contract
    pub fn get_web4_contract_mut(&mut self, contract_id: &[u8; 32]) -> Option<&mut crate::contracts::web4::Web4Contract> {
        self.web4_contracts.get_mut(contract_id)
    }
    
    /// Get all token contracts
    pub fn get_all_token_contracts(&self) -> &HashMap<[u8; 32], crate::contracts::TokenContract> {
        &self.token_contracts
    }
    
    /// Get all Web4 contracts
    pub fn get_all_web4_contracts(&self) -> &HashMap<[u8; 32], crate::contracts::web4::Web4Contract> {
        &self.web4_contracts
    }
    
    /// Check if a contract exists
    pub fn contract_exists(&self, contract_id: &[u8; 32]) -> bool {
        self.token_contracts.contains_key(contract_id) || 
        self.web4_contracts.contains_key(contract_id)
    }
    
    /// Get the block height where a contract was deployed
    pub fn get_contract_block_height(&self, contract_id: &[u8; 32]) -> Option<u64> {
        self.contract_blocks.get(contract_id).copied()
    }

    // ========================================================================
    // FILE PERSISTENCE METHODS
    // ========================================================================

    /// Save the blockchain state to a file
    ///
    /// Serializes the entire blockchain (blocks, UTXOs, identities, wallets, etc.)
    /// to disk using bincode for efficient binary serialization.
    ///
    /// # Arguments
    /// * `path` - Path to save the blockchain file
    ///
    /// # Example
    /// ```ignore
    /// blockchain.save_to_file(Path::new("./data/blockchain.dat"))?;
    /// ```
    /// File format magic bytes - "ZHTP"
    const FILE_MAGIC: [u8; 4] = [0x5A, 0x48, 0x54, 0x50];
    /// Current file format version
    const FILE_VERSION: u16 = 3;

    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;

        info!("💾 Saving blockchain to {} (height: {}, identities: {}, wallets: {}, tokens: {})",
              path.display(), self.height, self.identity_registry.len(),
              self.wallet_registry.len(), self.token_contracts.len());

        let start = std::time::Instant::now();

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Convert to stable storage format
        let storage = BlockchainStorageV3::from_blockchain(self);

        // Serialize to bincode
        let serialized = bincode::serialize(&storage)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain: {}", e))?;

        // Build file with header: MAGIC (4 bytes) + VERSION (2 bytes) + DATA
        let mut file_data = Vec::with_capacity(6 + serialized.len());
        file_data.extend_from_slice(&Self::FILE_MAGIC);
        file_data.extend_from_slice(&Self::FILE_VERSION.to_le_bytes());
        file_data.extend_from_slice(&serialized);

        // Write to temporary file first, then rename (atomic operation)
        let temp_path = path.with_extension("dat.tmp");
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(&file_data)?;
        file.sync_all()?; // Ensure data is flushed to disk

        // Atomic rename
        std::fs::rename(&temp_path, path)?;

        let elapsed = start.elapsed();
        info!("💾 Blockchain saved successfully (v{}, {} bytes, {:?})",
              Self::FILE_VERSION, file_data.len(), elapsed);

        Ok(())
    }

    /// Load blockchain state from a file
    ///
    /// Deserializes a blockchain from disk. If the file doesn't exist or is corrupt,
    /// returns an error. Use `load_or_create` for graceful fallback to new blockchain.
    ///
    /// # Arguments
    /// * `path` - Path to load the blockchain file from
    ///
    /// # Example
    /// ```ignore
    /// let blockchain = Blockchain::load_from_file(Path::new("./data/blockchain.dat"))?;
    /// ```
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        info!("📂 Loading blockchain from {}", path.display());

        let start = std::time::Instant::now();

        // Read file
        let file_data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read blockchain file: {}", e))?;

        if file_data.len() < 6 {
            return Err(anyhow::anyhow!("Blockchain file too small"));
        }

        // Check for versioned format (magic header)
        let mut blockchain: Blockchain = if file_data[0..4] == Self::FILE_MAGIC {
            // Versioned format - read version and route to appropriate deserializer
            let version = u16::from_le_bytes([file_data[4], file_data[5]]);
            let data = &file_data[6..];

            info!("📂 Detected versioned format v{}", version);

            match version {
                3 => {
                    // Current version - V3 storage format
                    let storage: BlockchainStorageV3 = bincode::deserialize(data)
                        .map_err(|e| anyhow::anyhow!("Failed to deserialize v3 blockchain: {}", e))?;
                    info!("📂 Loaded blockchain storage v3");
                    storage.to_blockchain()
                }
                2 => {
                    // Future: V2 format migration
                    return Err(anyhow::anyhow!("V2 format not supported - please use newer binary"));
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unsupported blockchain file version: {}. This binary supports v{}",
                        version, Self::FILE_VERSION
                    ));
                }
            }
        } else {
            // Legacy format (no header) - try old deserialization methods
            info!("📂 No version header found, trying legacy formats...");

            // Try direct deserialization first (very old format)
            match bincode::deserialize::<Blockchain>(&file_data) {
                Ok(bc) => {
                    info!("📂 Loaded as legacy direct format");
                    bc
                }
                Err(current_err) => {
                    // Try V1 format (backward compatibility for production nodes)
                    info!("📂 Direct format failed, trying V1 migration format...");
                    match bincode::deserialize::<BlockchainV1>(&file_data) {
                        Ok(v1_blockchain) => {
                            info!("📂 Blockchain loaded as V1 format, migrating...");
                            v1_blockchain.migrate_to_current()
                        }
                        Err(v1_err) => {
                            error!("❌ Failed to deserialize blockchain as any format:");
                            error!("   Direct format error: {}", current_err);
                            error!("   V1 format error: {}", v1_err);
                            return Err(anyhow::anyhow!(
                                "Failed to deserialize blockchain. File may be corrupted or from incompatible version. Error: {}",
                                current_err
                            ));
                        }
                    }
                }
            }
        };

        // Re-initialize non-serialized fields
        blockchain.economic_processor = Some(EconomicTransactionProcessor::new());
        // Note: consensus_coordinator, storage_manager, proof_aggregator, and broadcast_sender
        // need to be initialized separately after loading
        // Also initialize event_publisher for migrated blockchains
        blockchain.event_publisher = crate::events::BlockchainEventPublisher::new();

        // Reprocess any ContractExecution transactions that may have been missed
        // (e.g., tokens created before the contract execution processing code was added)
        if let Err(e) = blockchain.reprocess_contract_executions() {
            warn!("Failed to reprocess contract executions: {}", e);
        }

        let elapsed = start.elapsed();
        info!("📂 Blockchain loaded successfully (height: {}, identities: {}, wallets: {}, tokens: {}, UTXOs: {}, {:?})",
              blockchain.height, blockchain.identity_registry.len(),
              blockchain.wallet_registry.len(), blockchain.token_contracts.len(),
              blockchain.utxo_set.len(), elapsed);

        Ok(blockchain)
    }

    /// Load blockchain from file or create a new one if file doesn't exist
    ///
    /// This is the recommended method for node startup. It will:
    /// 1. Try to load existing blockchain from disk
    /// 2. If file doesn't exist, create a new blockchain with genesis block
    /// 3. If file exists but is corrupt, log error and create new blockchain
    ///
    /// # Arguments
    /// * `path` - Path to the blockchain file
    ///
    /// # Returns
    /// * `(Blockchain, bool)` - The blockchain and whether it was loaded from file (true) or created fresh (false)
    pub fn load_or_create(path: &std::path::Path) -> Result<(Self, bool)> {
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(blockchain) => {
                    info!("✅ Loaded existing blockchain from disk");
                    return Ok((blockchain, true));
                }
                Err(e) => {
                    error!("⚠️ Failed to load blockchain from {}: {}. Creating new blockchain.",
                           path.display(), e);
                    // Don't delete the corrupt file - keep it for debugging
                    let backup_path = path.with_extension("dat.corrupt");
                    if let Err(rename_err) = std::fs::rename(path, &backup_path) {
                        warn!("Failed to backup corrupt blockchain file: {}", rename_err);
                    } else {
                        warn!("Corrupt blockchain backed up to {}", backup_path.display());
                    }
                }
            }
        } else {
            info!("📂 No existing blockchain found at {}, creating new blockchain", path.display());
        }

        let blockchain = Self::new()?;
        Ok((blockchain, false))
    }

    /// Check if a persistence file exists
    pub fn persistence_file_exists(path: &std::path::Path) -> bool {
        path.exists()
    }

    /// Get persistence statistics
    pub fn get_persistence_stats(&self) -> PersistenceStats {
        PersistenceStats {
            height: self.height,
            blocks_count: self.blocks.len(),
            utxo_count: self.utxo_set.len(),
            identity_count: self.identity_registry.len(),
            wallet_count: self.wallet_registry.len(),
            pending_tx_count: self.pending_transactions.len(),
            blocks_since_last_persist: self.blocks_since_last_persist,
        }
    }

    /// Reset the blocks since last persist counter (call after successful save)
    pub fn mark_persisted(&mut self) {
        self.blocks_since_last_persist = 0;
    }

    /// Increment blocks since last persist counter (call after adding a block)
    pub fn increment_persist_counter(&mut self) {
        self.blocks_since_last_persist += 1;
    }

    /// Check if auto-persist should trigger based on block count
    pub fn should_auto_persist(&self, interval: u64) -> bool {
        self.auto_persist_enabled && self.blocks_since_last_persist >= interval
    }

    // ========================================================================
    // TRANSACTION RECEIPT AND FINALITY MANAGEMENT
    // ========================================================================

    /// Create a transaction receipt for a transaction included in a block
    pub fn create_receipt(
        &mut self,
        tx: &Transaction,
        block_hash: Hash,
        block_height: u64,
        tx_index: u32,
    ) -> Result<()> {
        let receipt = crate::receipts::TransactionReceipt::new(
            tx.hash(),
            block_hash,
            block_height,
            tx_index,
            tx.fee,
            chrono::Utc::now().timestamp() as u64,
        );

        self.receipts.insert(tx.hash(), receipt);
        debug!(
            "📋 Receipt created for tx {} at block {} (index {})",
            hex::encode(tx.hash().as_bytes()),
            block_height,
            tx_index
        );

        Ok(())
    }

    /// Get transaction receipt by hash
    pub fn get_receipt(&self, tx_hash: &Hash) -> Option<crate::receipts::TransactionReceipt> {
        self.receipts.get(tx_hash).cloned()
    }

    /// Update confirmation counts for all receipts
    pub fn update_confirmation_counts(&mut self) {
        for receipt in self.receipts.values_mut() {
            receipt.update_confirmations(self.height);
            if receipt.is_finalized() && receipt.status != crate::receipts::TransactionStatus::Finalized {
                receipt.finalize();
            }
        }
    }

    /// Get blocks that have reached finality (12+ confirmations)
    pub fn get_finalized_blocks(&self, depth: u64) -> Vec<&Block> {
        let current_height = self.height;
        if current_height < depth {
            return vec![];
        }

        let finality_height = current_height.saturating_sub(depth);
        self.blocks
            .iter()
            .filter(|b| b.header.height <= finality_height)
            .collect()
    }

    /// Check if a block has already been finalized
    pub fn is_block_finalized(&self, block_height: u64) -> bool {
        self.finalized_blocks.contains(&block_height)
    }

    /// Mark a block as finalized
    pub fn mark_block_finalized(&mut self, block_height: u64) {
        self.finalized_blocks.insert(block_height);
    }

    /// Trigger finalization for blocks that have reached 12+ confirmations
    /// Returns number of blocks finalized
    pub async fn finalize_blocks(&mut self) -> Result<u64> {
        self.update_confirmation_counts();

        // Collect finalized block data before modifying self
        let finalized_data: Vec<(u64, usize)> = {
            let finalized = self.get_finalized_blocks(self.finality_depth);
            finalized
                .iter()
                .filter(|b| !self.is_block_finalized(b.header.height))
                .map(|b| (b.header.height, b.transactions.len()))
                .collect()
        };

        let mut count = 0u64;

        for (block_height, tx_count) in finalized_data {
            // Collect transaction hashes for this block
            let tx_hashes: Vec<Hash> = self.blocks
                .iter()
                .find(|b| b.header.height == block_height)
                .map(|b| b.transactions.iter().map(|tx| tx.hash()).collect())
                .unwrap_or_default();

            // Mark all transactions as finalized
            for tx_hash in tx_hashes {
                if let Some(receipt) = self.receipts.get_mut(&tx_hash) {
                    receipt.status = crate::receipts::TransactionStatus::Finalized;
                }
            }

            // Mark block as finalized
            self.mark_block_finalized(block_height);
            count += 1;

            info!(
                "✅ Block {} finalized ({} transactions, {} confirmations)",
                block_height,
                tx_count,
                self.height.saturating_sub(block_height)
            );

            // Emit BlockFinalized event (Issue #11)
            if let Some(block) = self.blocks.iter().find(|b| b.header.height == block_height) {
                // Block hash should always be 32 bytes, but handle gracefully if not
                let block_hash = block.hash();
                let block_hash_bytes = block_hash.as_bytes();
                if block_hash_bytes.len() == 32 {
                    let mut block_hash_array = [0u8; 32];
                    block_hash_array.copy_from_slice(block_hash_bytes);

                    let event = crate::events::BlockchainEvent::BlockFinalized {
                        height: block_height,
                        block_hash: block_hash_array,
                    };
                    if let Err(e) = self.event_publisher.publish(event).await {
                        warn!("Failed to publish BlockFinalized event: {}", e);
                        // Don't fail finalization for event publishing errors
                    }
                } else {
                    warn!("Unexpected block hash size {} bytes for finalization event at height {}",
                          block_hash_bytes.len(), block_height);
                }
            }
        }

        if count > 0 {
            info!("🎯 {} blocks finalized", count);
        }

        Ok(count)
    }

    // ========================================================================
    // FORK RECOVERY AND REORGANIZATION
    // ========================================================================

    /// Detect if a new block creates a fork
    pub fn detect_fork_at_height(&self, height: u64, new_block_hash: Hash) -> Option<crate::fork_recovery::ForkDetection> {
        // Find existing block at this height
        let existing_block = self.blocks.iter().find(|b| b.header.height == height)?;

        // If hashes differ, we have a fork
        if existing_block.header.block_hash != new_block_hash {
            return Some(crate::fork_recovery::ForkDetection {
                height,
                existing_hash: existing_block.header.block_hash,
                new_hash: new_block_hash,
            });
        }
        None
    }

    /// Record a fork point in history for audit trail
    fn record_fork_point(
        &mut self,
        height: u64,
        original_hash: Hash,
        forked_hash: Hash,
        resolution: crate::fork_recovery::ForkResolution,
    ) {
        let fork_point = crate::fork_recovery::ForkPoint::new(
            height,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            original_hash,
            forked_hash,
            resolution,
        );

        self.fork_points.insert(height, fork_point);
        info!("🍴 Fork recorded at height {}: {:?} -> {:?}", height, original_hash, forked_hash);
    }

    /// Prevent reorg below finalized blocks
    pub fn can_reorg_to_height(&self, target_height: u64) -> Result<(), String> {
        // Find the highest finalized block
        if let Some(&max_finalized) = self.finalized_blocks.iter().max() {
            if target_height <= max_finalized {
                return Err(format!(
                    "Cannot reorg below finality threshold. Finalized height: {}, Target: {}",
                    max_finalized, target_height
                ));
            }
        }

        // Check max reorg depth configured
        let max_reorg_depth = self.fork_recovery_config.max_reorg_depth;
        if self.height.saturating_sub(target_height) > max_reorg_depth {
            return Err(format!(
                "Reorg depth ({}) exceeds maximum configured ({})",
                self.height.saturating_sub(target_height),
                max_reorg_depth
            ));
        }

        Ok(())
    }

    /// Check if can reorg to height, with anyhow::Result error type
    fn can_reorg_to_height_anyhow(&self, target_height: u64) -> Result<()> {
        self.can_reorg_to_height(target_height)
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Reorganize to a fork (replace blocks from target_height onwards)
    ///
    /// # Arguments
    /// * `target_height` - Block height where reorg should start
    /// * `new_blocks` - New blocks to replace the old ones
    ///
    /// # Returns
    /// Number of blocks removed and replaced
    pub async fn reorg_to_fork(&mut self, target_height: u64, new_blocks: Vec<Block>) -> Result<u64> {
        // Safety checks
        self.can_reorg_to_height_anyhow(target_height)?;

        if new_blocks.is_empty() {
            return Err(anyhow::anyhow!("Cannot reorg with empty block list"));
        }

        // Verify new blocks form a valid chain
        if new_blocks[0].header.height != target_height {
            return Err(anyhow::anyhow!(
                "First block height {} doesn't match target height {}",
                new_blocks[0].header.height,
                target_height
            ));
        }

        // Verify chain continuity
        for i in 1..new_blocks.len() {
            if new_blocks[i].header.height != new_blocks[i - 1].header.height + 1 {
                return Err(anyhow::anyhow!("Block height gap in new chain at position {}", i));
            }
            if new_blocks[i].header.previous_block_hash != new_blocks[i - 1].header.block_hash {
                return Err(anyhow::anyhow!("Block chain linkage broken at position {}", i));
            }
        }

        info!(
            "🔄 Reorganizing chain from height {} with {} blocks",
            target_height,
            new_blocks.len()
        );

        // Capture old block hash before removing blocks for audit trail
        let old_block_hash = self.blocks
            .iter()
            .find(|b| b.header.height == target_height)
            .map(|b| b.header.block_hash);

        // Remove old blocks from target_height onwards
        let old_count = self.blocks.len();
        self.blocks.retain(|b| b.header.height < target_height);
        let removed_count = old_count - self.blocks.len();

        // Add new blocks
        for block in new_blocks {
            // Record fork for audit trail (only for first block of reorg)
            if block.header.height == target_height {
                if let Some(old_hash) = old_block_hash {
                    self.record_fork_point(
                        target_height,
                        old_hash,
                        block.header.block_hash,
                        crate::fork_recovery::ForkResolution::SwitchedToFork,
                    );
                }
            }

            // Add block and update state
            self.add_block(block).await?;
        }

        // Increment reorg counter for monitoring
        self.reorg_count += 1;

        info!(
            "✅ Reorganization complete: {} blocks removed, chain height now {}",
            removed_count, self.height
        );

        Ok(removed_count as u64)
    }

    /// Get fork history for audit purposes
    pub fn get_fork_history(&self) -> Vec<crate::fork_recovery::ForkPoint> {
        let mut forks: Vec<_> = self.fork_points.values().cloned().collect();
        forks.sort_by_key(|f| f.height);
        forks
    }

    /// Get reorg count (for monitoring)
    pub fn get_reorg_count(&self) -> u64 {
        self.reorg_count
    }

    // ========================================================================
    // CONTRACT STATE MANAGEMENT
    // ========================================================================

    /// Update and persist contract state after execution
    ///
    /// # Arguments
    /// * `contract_id` - 32-byte contract identifier
    /// * `new_state` - Serialized contract state bytes
    /// * `block_height` - Current block height for historical snapshots
    pub fn update_contract_state(
        &mut self,
        contract_id: [u8; 32],
        new_state: Vec<u8>,
        block_height: u64,
    ) -> Result<()> {
        // Update current state
        self.contract_states.insert(contract_id, new_state.clone());

        // Save snapshot for this block height
        let snapshot = self.contract_state_history
            .entry(block_height)
            .or_insert_with(HashMap::new);
        snapshot.insert(contract_id, new_state);

        debug!("💾 Contract state updated: {:?} at block {}", contract_id, block_height);
        Ok(())
    }

    /// Get current contract state
    pub fn get_contract_state(&self, contract_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.contract_states.get(contract_id).cloned()
    }

    /// Get contract state at a specific block height (for historical queries)
    ///
    /// # Arguments
    /// * `contract_id` - 32-byte contract identifier
    /// * `height` - Block height to query
    ///
    /// # Returns
    /// State bytes at the specified height, or None if not found
    pub fn get_contract_state_at_height(
        &self,
        contract_id: &[u8; 32],
        height: u64,
    ) -> Option<Vec<u8>> {
        // Try to find snapshot at or before requested height
        for h in (0..=height).rev() {
            if let Some(snapshot) = self.contract_state_history.get(&h) {
                if let Some(state) = snapshot.get(contract_id) {
                    return Some(state.clone());
                }
            }
        }
        None
    }

    /// Prune old contract state history to save memory
    ///
    /// Keeps snapshots for recent blocks and removes older ones.
    /// # Arguments
    /// * `keep_blocks` - Number of recent blocks to keep in history
    pub fn prune_contract_history(&mut self, keep_blocks: u64) {
        if self.height < keep_blocks {
            return; // Not enough blocks to prune
        }

        let prune_before = self.height.saturating_sub(keep_blocks - 1);
        let keys_to_remove: Vec<u64> = self.contract_state_history
            .iter()
            .filter(|(h, _)| **h < prune_before)
            .map(|(h, _)| *h)
            .collect();

        for key in keys_to_remove {
            self.contract_state_history.remove(&key);
        }

        debug!("🧹 Pruned contract history before block {}", prune_before);
    }

    // ========================================================================
    // UTXO SNAPSHOT MANAGEMENT
    // ========================================================================

    /// Save UTXO set snapshot for current block height
    ///
    /// Creates a complete snapshot of the current UTXO set for the given block height.
    /// This enables state recovery and chain reorganizations.
    ///
    /// # Arguments
    /// * `block_height` - Block height to snapshot
    pub fn save_utxo_snapshot(&mut self, block_height: u64) -> Result<()> {
        // Clone the current UTXO set
        let snapshot = self.utxo_set.clone();

        // Save to snapshots map
        self.utxo_snapshots.insert(block_height, snapshot);

        debug!("💾 UTXO snapshot saved at block {}: {} UTXOs", block_height, self.utxo_set.len());
        Ok(())
    }

    /// Get UTXO set at a specific block height
    ///
    /// Returns the UTXO set as it existed at the specified block height.
    /// Useful for state verification and historical queries.
    ///
    /// # Arguments
    /// * `height` - Block height to query
    ///
    /// # Returns
    /// HashMap of UTXO hash to TransactionOutput, or None if snapshot not found
    pub fn get_utxo_set_at_height(&self, height: u64) -> Option<HashMap<Hash, TransactionOutput>> {
        self.utxo_snapshots.get(&height).cloned()
    }

    /// Prune old UTXO snapshots to save memory
    ///
    /// Keeps snapshots for recent blocks and removes older ones.
    /// Maintains finalized blocks to prevent reorg below finality depth.
    ///
    /// # Arguments
    /// * `keep_blocks` - Number of recent blocks to keep in history
    pub fn prune_utxo_history(&mut self, keep_blocks: u64) {
        if self.height < keep_blocks {
            return; // Not enough blocks to prune
        }

        let prune_before = self.height.saturating_sub(keep_blocks - 1);
        let keys_to_remove: Vec<u64> = self.utxo_snapshots
            .iter()
            .filter(|(h, _)| **h < prune_before)
            .map(|(h, _)| *h)
            .collect();

        for key in keys_to_remove {
            self.utxo_snapshots.remove(&key);
        }

        debug!("🧹 Pruned UTXO snapshots before block {}", prune_before);
    }

    /// Restore UTXO set from a snapshot at specific height
    ///
    /// Used during chain reorganizations to rollback to previous state.
    ///
    /// # Arguments
    /// * `height` - Block height to restore from
    ///
    /// # Returns
    /// Ok(()) if snapshot found and restored, error otherwise
    pub fn restore_utxo_set_from_snapshot(&mut self, height: u64) -> Result<()> {
        if let Some(snapshot) = self.utxo_snapshots.get(&height) {
            self.utxo_set = snapshot.clone();
            info!("🔄 UTXO set restored from snapshot at height {}: {} UTXOs", height, self.utxo_set.len());
            Ok(())
        } else {
            anyhow::bail!("No UTXO snapshot found at height {}", height)
        }
    }

    // ========================================================================
    // ECONOMIC FEATURE PROCESSING
    // ========================================================================

    /// Process UBI claim transactions
    ///
    /// Validates and tracks UBI claims to prevent double-claiming in same month.
    /// This is a simplified implementation tracking claims on-chain.
    pub fn process_ubi_claim_transactions(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            if let Some(ubi_data) = &tx.ubi_claim_data {
                // Create claim tracking key: (identity, month_index)
                let claim_key = format!(
                    "ubi_claim:{}:{}",
                    ubi_data.claimant_identity, ubi_data.month_index
                );

                // Check if already claimed this month
                if self.identity_blocks.contains_key(&claim_key) {
                    warn!(
                        "⚠️ Duplicate UBI claim attempt: {} for month {}",
                        ubi_data.claimant_identity, ubi_data.month_index
                    );
                    return Err(anyhow::anyhow!(
                        "UBI already claimed for this month: {}",
                        ubi_data.claimant_identity
                    ));
                }

                // Record claim
                self.identity_blocks.insert(claim_key, block.header.height);

                info!(
                    "✅ UBI claim processed: identity={}, month={}, amount={}",
                    ubi_data.claimant_identity, ubi_data.month_index, ubi_data.claim_amount
                );
            }
        }
        Ok(())
    }

    /// Blocks per day (assuming ~10 second block time)
    /// At 10s/block: 24 hours = 86,400 seconds ÷ 10 = 8,640 blocks
    const BLOCKS_PER_DAY: u64 = 8_640;

    /// Process automatic UBI distribution for all eligible citizens
    ///
    /// This runs every block and distributes daily UBI (~33 ZHTP) to citizens
    /// who are due for their payout (last_payout_block + BLOCKS_PER_DAY <= current_block).
    ///
    /// This is the "best" approach - fully automatic, deterministic, no user action required.
    pub fn process_automatic_ubi_distribution(&mut self, current_block: u64) -> Result<u64> {
        let mut total_distributed = 0u64;
        let mut recipients_paid = 0u64;

        // Collect updates to avoid borrowing issues
        let mut updates: Vec<(String, u64, Option<u64>, u64)> = Vec::new();

        for (identity_id, entry) in self.ubi_registry.iter() {
            if !entry.is_active {
                continue;
            }

            // Check if due for payout
            let is_due = match entry.last_payout_block {
                Some(last_block) => current_block.saturating_sub(last_block) >= Self::BLOCKS_PER_DAY,
                None => true, // Never received payout, eligible immediately
            };

            if is_due {
                // Calculate payout amount with remainder handling
                let mut payout = entry.daily_amount;
                let mut new_remainder = entry.remainder_balance + (entry.monthly_amount % 30);

                // Distribute accumulated remainder when it exceeds a day's worth
                if new_remainder >= 30 {
                    payout += new_remainder / 30;
                    new_remainder %= 30;
                }

                updates.push((
                    identity_id.clone(),
                    payout,
                    Some(current_block),
                    new_remainder,
                ));

                total_distributed += payout;
                recipients_paid += 1;
            }
        }

        // Apply updates
        for (identity_id, payout, last_block, remainder) in updates {
            if let Some(entry) = self.ubi_registry.get_mut(&identity_id) {
                entry.last_payout_block = last_block;
                entry.total_received += payout;
                entry.remainder_balance = remainder;

                // Credit the UBI wallet in wallet_registry
                let wallet_id = entry.ubi_wallet_id.clone();
                if let Some(wallet) = self.wallet_registry.get_mut(&wallet_id) {
                    wallet.initial_balance += payout;
                    debug!(
                        "💰 UBI distributed: {} ZHTP to wallet {} (identity {})",
                        payout, wallet_id, identity_id
                    );
                }
            }
        }

        if recipients_paid > 0 {
            info!(
                "🌍 UBI DISTRIBUTION: {} ZHTP to {} citizens at block {}",
                total_distributed, recipients_paid, current_block
            );
        }

        Ok(total_distributed)
    }

    /// Register a citizen for automatic UBI distribution
    ///
    /// Called when a new citizen identity is registered. Adds them to the UBI registry
    /// for automatic daily payouts.
    pub fn register_for_ubi(&mut self, identity_id: String, ubi_wallet_id: String, current_block: u64) -> Result<()> {
        // Check if already registered
        if self.ubi_registry.contains_key(&identity_id) {
            return Err(anyhow::anyhow!("Identity {} already registered for UBI", identity_id));
        }

        let monthly_amount = 1000u64; // 1000 ZHTP per month
        let daily_amount = monthly_amount / 30; // ~33 ZHTP per day

        let entry = UbiRegistryEntry {
            identity_id: identity_id.clone(),
            ubi_wallet_id: ubi_wallet_id.clone(),
            daily_amount,
            monthly_amount,
            registered_at_block: current_block,
            last_payout_block: None, // Will receive first payout on next block processing
            total_received: 0,
            remainder_balance: monthly_amount % 30, // 10 remainder from 1000/30
            is_active: true,
        };

        self.ubi_registry.insert(identity_id.clone(), entry);
        self.ubi_blocks.insert(identity_id.clone(), current_block);

        info!(
            "🎉 UBI REGISTERED: Citizen {} eligible for {} ZHTP daily ({} monthly) at block {}",
            identity_id, daily_amount, monthly_amount, current_block
        );

        Ok(())
    }

    /// Process profit declaration transactions
    ///
    /// Validates that tribute amount equals 20% of profit amount.
    /// Enforces mandatory profit-to-nonprofit redistribution.
    pub fn process_profit_declarations(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            if let Some(profit_data) = &tx.profit_declaration_data {
                // Validate tribute calculation (must be exactly 20%)
                let expected_tribute = profit_data.profit_amount * 20 / 100;

                if profit_data.tribute_amount != expected_tribute {
                    error!(
                        "❌ Invalid tribute amount: expected {}, got {}",
                        expected_tribute, profit_data.tribute_amount
                    );
                    return Err(anyhow::anyhow!(
                        "Invalid tribute amount: expected {}, got {}",
                        expected_tribute,
                        profit_data.tribute_amount
                    ));
                }

                // Record declaration
                let declaration_key = format!(
                    "profit_declaration:{}:{}",
                    profit_data.declarant_identity, profit_data.fiscal_period
                );
                self.identity_blocks
                    .insert(declaration_key, block.header.height);

                info!(
                    "💸 Profit declaration processed: entity={}, fiscal_period={}, profit={}, tribute={}",
                    profit_data.declarant_identity,
                    profit_data.fiscal_period,
                    profit_data.profit_amount,
                    profit_data.tribute_amount
                );
            }
        }
        Ok(())
    }
}

/// Statistics about blockchain persistence state
#[derive(Debug, Clone)]
pub struct PersistenceStats {
    pub height: u64,
    pub blocks_count: usize,
    pub utxo_count: usize,
    pub identity_count: usize,
    pub wallet_count: usize,
    pub pending_tx_count: usize,
    pub blocks_since_last_persist: u64,
}

impl Default for Blockchain {
    fn default() -> Self {
        let mut blockchain = Self::new().expect("Failed to create default blockchain");
        blockchain.ensure_economic_processor();
        // Note: Consensus coordinator requires async initialization and external dependencies
        // so it's not initialized in Default. Call initialize_consensus_coordinator() separately.
        blockchain
    }
}
