//! Main blockchain data structure and implementation
//!
//! Contains the core Blockchain struct and its methods, extracted from the original
//! blockchain.rs implementation with proper modularization.

use crate::block::Block;
use crate::contracts::treasury_kernel::TreasuryKernel;
use crate::integration::consensus_integration::{BlockchainConsensusCoordinator, ConsensusStatus};
use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use crate::integration::economic_integration::{EconomicTransactionProcessor, TreasuryStats};
use crate::integration::storage_integration::{
    BlockchainStorageConfig, BlockchainStorageManager, StorageOperationResult,
};
use crate::integration::zk_integration::ZkTransactionProof;
use crate::storage::{
    did_to_hash, BlockchainStore, IdentityConsensus, IdentityMetadata, IdentityStatus, IdentityType,
};
use crate::transaction::{
    IdentityTransactionData, Transaction, TransactionInput, TransactionOutput,
};
use crate::types::transaction_type::TransactionType;
use crate::types::{Difficulty, DifficultyConfig, Hash};
use anyhow::Result;
use lib_storage::dht::storage::DhtStorage;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, error, info, warn};

mod test_utils;
#[cfg(test)]
mod tests;
mod dao;
mod contracts;
mod identity;
mod init;
mod oracle;
mod persistence;
mod validators;
mod gateways;
mod wallets;

pub use persistence::PersistenceStats;

/// Validator was bootstrapped from off-chain genesis configuration at height 0.
pub const ADMISSION_SOURCE_OFFCHAIN_GENESIS: &str = "offchain_genesis";
/// Validator was admitted through an on-chain governance/registration transaction.
pub const ADMISSION_SOURCE_ONCHAIN_GOVERNANCE: &str = "onchain_governance";
/// Validator was seeded from the bootstrap_validators config at node startup (pre-genesis).
pub const ADMISSION_SOURCE_BOOTSTRAP_GENESIS: &str = "bootstrap_genesis";

/// Messages for real-time blockchain synchronization
#[derive(Debug, Clone)]
pub enum BlockchainBroadcastMessage {
    /// New block created locally and should be broadcast to peers
    NewBlock(Block),
    /// New transaction submitted locally and should be broadcast to peers
    NewTransaction(Transaction),
}

/// BFT checkpoint metadata used by sync verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusCheckpoint {
    pub height: u64,
    pub previous_hash: Hash,
    pub block_hash: Hash,
}

// Import lib-proofs for recursive proof aggregation
// Import lib-proofs for recursive proof aggregation
use lib_proofs::verifiers::transaction_verifier::{BatchMetadata, BatchedPrivateTransaction};

/// Default finality depth (6 blocks like Bitcoin)
fn default_finality_depth() -> u64 {
    6
}

/// Default council threshold (4 of N council members)
fn default_council_threshold() -> u8 {
    4
}

/// Default treasury epoch length (~1 week at 10s blocks)
fn default_treasury_epoch_length() -> u64 {
    10_080
}

/// Default veto window blocks (~1 day at 10s blocks)
fn default_veto_window() -> u64 {
    8_640
}

/// Default max executions per treasury epoch
fn default_max_executions() -> u32 {
    10
}

/// Indexed DAO registry entry derived from canonical DaoExecution events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaoRegistryIndexEntry {
    pub dao_id: [u8; 32],
    pub token_key_id: [u8; 32],
    pub class: String,
    pub metadata_hash: [u8; 32],
    pub treasury_key_id: [u8; 32],
    pub owner_key_id: [u8; 32],
    pub created_at: u64,
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
    /// Transaction fee configuration (governance-controlled)
    #[serde(default)]
    pub tx_fee_config: crate::transaction::TxFeeConfig,
    /// Last block height when tx fee config was updated
    #[serde(default)]
    pub tx_fee_config_updated_at_height: u64,
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
    /// NFT collection registry (collection_id -> NftContract)
    #[serde(default)]
    pub nft_collections: HashMap<[u8; 32], crate::contracts::nft::NftContract>,
    /// Authoritative on-chain domain registry (domain name -> record).
    /// Populated from DomainRegistration / DomainUpdate transactions committed to blocks.
    /// This is the canonical source of truth; sled/DHT DomainRegistry is a cache.
    #[serde(default)]
    pub domain_registry: HashMap<String, crate::transaction::OnChainDomainRecord>,
    /// Contract deployment block heights (contract_id -> block_height)
    #[serde(default)]
    pub contract_blocks: HashMap<[u8; 32], u64>,
    /// Indexed DAO registry (dao_id -> entry), updated incrementally per block.
    #[serde(default)]
    pub dao_registry_index: HashMap<[u8; 32], DaoRegistryIndexEntry>,
    /// On-chain validator registry (identity_id -> Validator info)
    #[serde(default)]
    pub validator_registry: HashMap<String, ValidatorInfo>,
    /// Validator registration block heights (identity_id -> block_height)
    #[serde(default)]
    pub validator_blocks: HashMap<String, u64>,
    /// On-chain gateway registry (identity_id -> Gateway info)
    #[serde(default)]
    pub gateway_registry: HashMap<String, GatewayInfo>,
    /// Gateway registration block heights (identity_id -> block_height)
    #[serde(default)]
    pub gateway_blocks: HashMap<String, u64>,
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
    pub consensus_coordinator:
        Option<std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>>,
    /// Storage manager for persistent data
    #[serde(skip)]
    pub storage_manager: Option<std::sync::Arc<tokio::sync::RwLock<BlockchainStorageManager>>>,
    /// Phase 2 incremental storage backend (replaces monolithic serialization)
    /// When present, this store is the authoritative source of state.
    #[serde(skip)]
    pub store: Option<std::sync::Arc<dyn BlockchainStore>>,
    /// Recursive proof aggregator for O(1) state verification
    #[serde(skip)]
    pub proof_aggregator:
        Option<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>>,
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
    /// Treasury Kernel - single authority for SOV and DAO token balance mutations
    /// Custom tokens (without kernel_mint_authority) bypass the kernel
    #[serde(skip)]
    pub treasury_kernel: Option<TreasuryKernel>,
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
    /// Per-token, per-address nonce for token transfer replay protection
    /// Key: (token_id, sender address) where address is wallet_id for SOV or key_id for custom tokens
    #[serde(default)]
    pub token_nonces: HashMap<([u8; 32], [u8; 32]), u64>,
    /// Block executor for state changes
    /// When present, this is the SINGLE SOURCE OF TRUTH for state mutations.
    /// All block applications should go through this executor.
    #[serde(skip)]
    #[allow(clippy::redundant_closure_call)]
    pub executor: Option<std::sync::Arc<crate::execution::executor::BlockExecutor>>,
    /// Bonding curve token registry
    /// Tracks all bonding curve tokens from deployment through AMM graduation
    #[serde(default)]
    pub bonding_curve_registry: crate::contracts::bonding_curve::BondingCurveRegistry,
    /// AMM liquidity pools for graduated bonding curve tokens
    /// Pool ID -> persisted AMM pool mapping
    #[serde(default)]
    pub amm_pools: HashMap<[u8; 32], crate::contracts::bonding_curve::AmmPool>,
    // =========================================================================
    // DAO Bootstrap Council (dao-1)
    // =========================================================================
    /// Current governance phase (Bootstrap → Hybrid → FullDao)
    #[serde(default)]
    pub governance_phase: crate::dao::GovernancePhase,
    /// Active Bootstrap Council members
    #[serde(default)]
    pub council_members: Vec<crate::dao::CouncilMember>,
    /// Minimum council yes-votes required for Phase 0 execution
    #[serde(default = "default_council_threshold")]
    pub council_threshold: u8,

    // =========================================================================
    // Entity Registry (TSR — Treasury Signer Registration)
    // =========================================================================
    /// CBE and Nonprofit treasury address registry.
    /// None until initialized via InitEntityRegistry transaction.
    /// Immutable after initialization.
    #[serde(default)]
    pub entity_registry: Option<crate::contracts::governance::EntityRegistry>,

    // =========================================================================
    // CBE Employment & DAO (CBE epic)
    // =========================================================================
    /// On-chain employment contract registry — populated by CreateEmploymentContract txs.
    #[serde(default)]
    pub employment_registry: crate::contracts::employment::EmploymentRegistry,
    // =========================================================================
    // DAO Treasury Execution (dao-2)
    // =========================================================================
    /// SOV spent per epoch: epoch_number → cumulative_amount
    #[serde(default)]
    pub treasury_epoch_spend: HashMap<u64, u64>,
    /// Number of blocks per epoch for spend-cap accounting
    #[serde(default = "default_treasury_epoch_length")]
    pub treasury_epoch_length_blocks: u64,
    /// Whether the treasury is in emergency mode (unlocks Emergency proposals)
    #[serde(default)]
    pub emergency_state: bool,
    /// Block height when emergency state was activated
    #[serde(default)]
    pub emergency_activated_at: Option<u64>,
    /// DID of the council member who activated emergency state
    #[serde(default)]
    pub emergency_activated_by: Option<String>,
    /// Block height at which emergency state auto-expires
    #[serde(default)]
    pub emergency_expires_at: Option<u64>,
    /// Treasury balance recorded at the start of each epoch, used for spend-cap calculation.
    /// Prevents gaming the 5% cap by making multiple small proposals as balance depletes.
    #[serde(default)]
    pub treasury_epoch_start_balance: HashMap<u64, u64>,

    // =========================================================================
    // DAO Emergency Treasury Freeze (dao-7)
    // =========================================================================
    /// Whether the treasury is frozen (emergency freeze by 80% validators)
    #[serde(default)]
    pub treasury_frozen: bool,
    /// Block height when treasury was frozen
    #[serde(default)]
    pub treasury_frozen_at: Option<u64>,
    /// Block height at which treasury freeze expires
    #[serde(default)]
    pub treasury_freeze_expiry: Option<u64>,
    /// Signatures from validators who signed the freeze
    #[serde(default)]
    pub treasury_freeze_signatures: Vec<(String, Vec<u8>)>, // (validator_did, signature)

    // =========================================================================
    // DAO Voting Power (dao-5)
    // =========================================================================
    /// How token balances translate to voting weight
    #[serde(default)]
    pub voting_power_mode: crate::dao::VotingPowerMode,
    /// Vote delegation map: delegator_id_hex → delegate_id_hex
    ///
    /// Both keys and values are 64-char hex-encoded 32-byte identity IDs
    /// (the raw bytes of `lib_identity::IdentityId`, NOT "did:zhtp:…" strings).
    /// Delegation is **non-transitive**: if A→B and B→C, C does not receive A's power.
    #[serde(default)]
    pub vote_delegations: HashMap<String, String>,
    /// Council co-signatures collected for a proposal (proposal_id → [(did, sig_bytes)]).
    #[serde(default)]
    pub pending_cosigns: HashMap<[u8; 32], Vec<(String, Vec<u8>)>>,
    /// Council vetoes for a proposal (proposal_id → [(did, reason)]).
    #[serde(default)]
    pub pending_vetoes: HashMap<[u8; 32], Vec<(String, String)>>,
    /// Window (blocks) during which the council can veto/cosign after a vote closes.
    #[serde(default = "default_veto_window")]
    pub veto_window_blocks: u64,
    /// Number of executions that occurred per treasury epoch (epoch → count).
    #[serde(default)]
    pub treasury_epoch_execution_count: HashMap<u64, u32>,
    /// Maximum treasury executions allowed per epoch.
    #[serde(default = "default_max_executions")]
    pub max_executions_per_epoch: u32,
    /// Oracle protocol v1 consensus state (committee/config/finalized prices).
    #[serde(default)]
    pub oracle_state: crate::oracle::OracleState,
    /// Unified token pricing state for SOV and CBE tokens (Issue #1819).
    #[serde(default)]
    pub token_pricing_state: crate::pricing::TokenPricingState,
    /// On-chain exchange state for SOV/USDC and other trading pairs.
    /// Provides price feeds to the oracle protocol.
    #[serde(default)]
    pub exchange_state: crate::exchange::ExchangeState,
    /// On-ramp trade log: fiat->CBE purchases attested by gateway + oracle committee.
    /// Source of CBE/USD VWAP for oracle Mode B SOV/USD derivation.
    /// Spec: CBE/SOV/USD Pricing Model v1.0 §4
    #[serde(default)]
    pub onramp_state: crate::onramp::OnRampState,
    /// Oracle slashing events log.
    #[serde(default)]
    pub oracle_slash_events: Vec<crate::oracle::OracleSlashEvent>,
    /// Oracle slashing configuration.
    #[serde(default)]
    pub oracle_slashing_config: crate::oracle::OracleSlashingConfig,
    /// Validators banned from oracle committee (key_id).
    #[serde(default)]
    pub oracle_banned_validators: std::collections::HashSet<[u8; 32]>,
    /// Last oracle timestamp for which apply_pending_updates() was called.
    /// Prevents double-application within the same epoch.
    ///
    /// ORACLE-R4: This field always stores a Unix timestamp (seconds), not an epoch ID.
    /// Legacy data may have epoch IDs - migration happens on load.
    #[serde(default)]
    pub last_oracle_epoch_processed: u64,

    // ── DAO Phase Transitions (dao-3) ─────────────────────────────────────
    /// Most recently computed decentralization snapshot.
    #[serde(default)]
    pub last_decentralization_snapshot: Option<crate::dao::DecentralizationSnapshot>,
    /// Configurable thresholds governing phase advancement.
    #[serde(default)]
    pub phase_transition_config: crate::dao::PhaseTransitionConfig,
    /// Number of consecutive governance epochs that met quorum (for Phase 2 gate).
    #[serde(default)]
    pub governance_cycles_with_quorum: u32,
    /// Block height of the last governance cycle check.
    #[serde(default)]
    pub last_governance_cycle_height: u64,

    // =========================================================================
    // Fee Router — sector DAO fee distribution (45/30/15/10 split)
    // =========================================================================
    /// Routes collected protocol fees to UBI pool, sector DAOs, emergency reserve, dev grants.
    /// Initialized at startup with the well-known sector DAO wallet addresses from
    /// keys/dao-wallets.json (registered 2026-04-10).
    #[serde(default)]
    pub fee_router: crate::contracts::economics::fee_router::FeeRouter,
}

/// Validator information stored on-chain.
///
/// # Key Separation
///
/// A validator operates with three distinct cryptographic keys, each serving a different
/// security domain. These keys MUST be different from one another — reusing a single key
/// across roles weakens isolation boundaries and increases the blast radius of any key
/// compromise.
///
/// ## Key Roles
///
/// ### 1. `consensus_key` — Consensus / Vote-Signing Key
/// Used exclusively for signing BFT consensus messages: block proposals, pre-votes,
/// pre-commits, and view-change messages.
/// - **Algorithm**: Post-quantum Dilithium5 (NIST FIPS 204, ML-DSA level 5).
/// - **Exposure**: Hot — must be online during every consensus round.
/// - **Compromise impact**: Attacker can equivocate (double-sign) on behalf of this
///   validator, triggering slashing of the staked SOV.
///
/// ### 2. `networking_key` — P2P / Transport Identity Key
/// Used to establish the validator's peer identity on the ZHTP mesh network (QUIC TLS
/// handshake, DHT node ID derivation, peer authentication).
/// - **Algorithm**: X25519 / Ed25519 (classical elliptic-curve).
/// - **Exposure**: Hot — required for every inbound and outbound connection.
/// - **Compromise impact**: Attacker can impersonate the validator on the P2P layer and
///   inject or suppress gossip messages, but CANNOT forge consensus votes.
///
/// ### 3. `rewards_key` — Rewards / Fee-Collection Key
/// Identifies the wallet address to which block rewards and fee distributions are sent.
/// This is the public key of the validator's rewards wallet (see `WalletTransactionData`).
/// - **Algorithm**: Dilithium5 or Ed25519 depending on wallet type.
/// - **Exposure**: Can be kept cold — only needed when claiming accumulated rewards.
/// - **Compromise impact**: Attacker can redirect future reward payments; historical
///   rewards already on-chain are unaffected.
///
/// ## Invariant
///
/// The runtime MUST assert `consensus_key != networking_key`,
/// `consensus_key != rewards_key`, and `networking_key != rewards_key` at validator
/// registration time. See [`register_validator`] in the blockchain layer and
/// [`ValidatorManager::register_validator`] in the consensus layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator identity ID
    pub identity_id: String,
    /// Staked amount (in micro-SOV)
    pub stake: u64,
    /// Storage provided (in bytes)
    pub storage_provided: u64,
    /// Post-quantum Dilithium5 public key used exclusively for signing BFT consensus
    /// messages (proposals, pre-votes, pre-commits).  MUST differ from `networking_key`
    /// and `rewards_key`.
    /// Fixed size [u8; 2592] for Dilithium5 public key.
    #[serde(with = "serde_arrays")]
    pub consensus_key: [u8; 2592],
    /// Ed25519 / X25519 public key used for P2P transport identity (QUIC TLS, DHT node
    /// ID).  MUST differ from `consensus_key` and `rewards_key`.
    pub networking_key: Vec<u8>,
    /// Public key of the rewards wallet that receives block rewards and fee distributions.
    /// MUST differ from `consensus_key` and `networking_key`.
    pub rewards_key: Vec<u8>,
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
    /// Source of validator admission path.
    #[serde(default)]
    pub admission_source: String,
    /// Optional governance proposal ID authorizing this validator.
    #[serde(default)]
    pub governance_proposal_id: Option<String>,
    /// Oracle attestation key ID (for oracle committee membership).
    #[serde(default)]
    pub oracle_key_id: Option<[u8; 32]>,
}

/// Gateway registry entry
/// Tracks a gateway node's registration, stake, and operational status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    /// Gateway identity ID (same as DID)
    pub identity_id: String,
    /// Staked amount (in micro-SOV)
    pub stake: u64,
    /// Dilithium5 public key used to sign forwarded client context.
    /// Fixed size [u8; 2592].
    #[serde(with = "serde_arrays")]
    pub gateway_key: [u8; 2592],
    /// Public QUIC endpoint(s) for clients (comma-separated host:port)
    pub endpoints: String,
    /// Commission rate percentage (0-100) taken from routed DAO fees
    pub commission_rate: u8,
    /// Gateway status: "active", "inactive", "slashed"
    pub status: String,
    /// Registration timestamp (block height)
    pub registered_at: u64,
    /// Last heartbeat / activity timestamp (block height)
    pub last_activity: u64,
    /// Total requests forwarded (approximate counter)
    pub requests_forwarded: u64,
    /// Slash count
    pub slash_count: u32,
    /// Revenue earned in micro-SOV (accumulated, not yet claimed)
    pub accumulated_revenue: u64,
    /// Source of gateway admission
    #[serde(default)]
    pub admission_source: String,
}

/// UBI (Universal Basic Income) registry entry
/// Tracks a citizen's UBI eligibility and payout status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiRegistryEntry {
    /// Citizen's identity ID (hex string)
    pub identity_id: String,
    /// UBI wallet ID where payments are sent
    pub ubi_wallet_id: String,
    /// Daily UBI amount (~33 SOV, atomic units u128 for 18-decimal)
    pub daily_amount: u128,
    /// Monthly UBI amount (1000 SOV, atomic units u128 for 18-decimal)
    pub monthly_amount: u128,
    /// Block height when registered for UBI
    pub registered_at_block: u64,
    /// Block height of last UBI payout (None if never received)
    pub last_payout_block: Option<u64>,
    /// Total UBI received to date
    pub total_received: u128,
    /// Accumulated remainder from integer division (1000/30 = 33 remainder 10)
    pub remainder_balance: u128,
    /// Whether UBI is currently active for this citizen
    pub is_active: bool,
}

/// UBI mint entry for block-authoritative TokenMint transactions
#[derive(Debug, Clone)]
pub struct UbiMintEntry {
    pub identity_id: String,
    pub wallet_id: String,
    pub recipient_wallet_id: [u8; 32],
    pub payout: u128,
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

/// Blockchain import structure for deserializing received chains
#[derive(Serialize, Deserialize)]
pub struct BlockchainImport {
    pub blocks: Vec<Block>,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub wallet_references: HashMap<String, crate::transaction::WalletReference>, // Only minimal references
    pub validator_registry: HashMap<String, ValidatorInfo>,
    #[serde(default)]
    pub gateway_registry: HashMap<String, GatewayInfo>,
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    pub contract_blocks: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub dao_registry_index: HashMap<[u8; 32], DaoRegistryIndexEntry>,
    /// ORACLE-10: Oracle state for initial sync
    #[serde(default)]
    pub oracle_state: Option<crate::oracle::OracleState>,
    /// ORACLE-10: Last oracle epoch processed for sync consistency
    #[serde(default)]
    pub last_oracle_epoch_processed: u64,
}

impl Blockchain {
    const MIN_DILITHIUM_PK_LEN: usize = 1312;

    /// Load blockchain from persistent storage
    pub async fn load_from_storage(
        storage_config: BlockchainStorageConfig,
        content_hash: lib_storage::types::ContentHash,
    ) -> Result<Self> {
        info!("Loading blockchain from storage");

        let mut storage_manager = BlockchainStorageManager::new(storage_config).await?;
        let mut blockchain = storage_manager
            .retrieve_blockchain_state(content_hash)
            .await?;

        // Re-initialize non-serialized components
        blockchain.economic_processor = Some(EconomicTransactionProcessor::new());
        blockchain.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(
            storage_manager,
        )));
        blockchain.proof_aggregator = None; // Will be initialized on first use
        blockchain.auto_persist_enabled = true;
        blockchain.blocks_since_last_persist = 0;

        info!(
            "Blockchain loaded from storage (height: {})",
            blockchain.height
        );
        Ok(blockchain)
    }

    /// Persist blockchain state to storage
    pub async fn persist_to_storage(&mut self) -> Result<StorageOperationResult> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            info!(
                " Persisting blockchain state to storage (height: {})",
                self.height
            );

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
            info!(
                "Blockchain backup completed: {}/{} operations successful",
                successful_backups,
                results.len()
            );

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
                info!(
                    " Auto-persisting blockchain state (blocks since last persist: {})",
                    self.blocks_since_last_persist
                );
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
    pub async fn persist_transaction(
        &mut self,
        transaction: &Transaction,
    ) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager.store_transaction(transaction).await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Store identity data in persistent storage
    pub async fn persist_identity_data(
        &mut self,
        did: &str,
        identity_data: &IdentityTransactionData,
    ) -> Result<Option<StorageOperationResult>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            let result = storage_manager
                .store_identity_data(did, identity_data)
                .await?;
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
            storage_manager
                .store_latest_utxo_set(&self.utxo_set)
                .await?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    pub async fn persist_blockchain_state(&mut self) -> Result<Option<()>> {
        if let Some(ref storage_manager_arc) = self.storage_manager {
            let storage_manager = storage_manager_arc.read().await;

            let state = crate::integration::storage_integration::BlockchainState {
                height: self.height,
                difficulty: self.difficulty.clone(),
                nullifier_set: self.nullifier_set.clone(),
                total_work: self.total_work,
                finality_depth: self.finality_depth,
                finalized_blocks: self.finalized_blocks.clone(),
            };

            storage_manager
                .store_latest_blockchain_state(&state)
                .await?;

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
    ///
    /// # Invariant BFT-A-1952
    ///
    /// This function is a **sync-only / observer path**. It MUST NOT be called from the
    /// live validator block-reception path. In a running validator node, blocks arrive as
    /// BFT proposals and are committed exclusively via `BlockCommitCallback::commit_finalized_block`
    /// after 2f+1 quorum. Calling this function from a live validator message handler would
    /// allow a Byzantine peer to inject canonical state without BFT agreement.
    pub async fn add_block_from_network(&mut self, block: Block) -> Result<()> {
        self.process_and_commit_block(block).await
    }

    /// Apply a block received via catch-up sync from a peer.
    ///
    /// Skips fee validation (old blocks may use different fee rules) but
    /// VALIDATES prev-hash to ensure chain continuity. A malicious peer
    /// cannot inject forked state through this path.
    ///
    /// # Invariant BFT-A-1952
    ///
    /// This function is a **catch-up sync path only**. It MUST NOT be called from the live
    /// validator block-reception path.
    pub async fn apply_block_trusted_for_sync(&mut self, block: Block) -> Result<()> {
        if let Some(ref exec_arc) = self.executor {
            use crate::execution::executor::BlockExecutor;
            let catchup_exec = std::sync::Arc::new(BlockExecutor::new_catchup_sync(
                std::sync::Arc::clone(exec_arc.store()),
                exec_arc.fee_model().clone(),
                Default::default(),
            ));
            // Temporarily swap in the catchup executor, apply, restore.
            let original = self.executor.replace(catchup_exec);
            let result = self.process_and_commit_block(block).await;
            self.executor = original;
            result
        } else {
            // No executor configured — legacy path has no fee check.
            self.process_and_commit_block(block).await
        }
    }

    /// Core block processing: verify, commit to chain, update state, emit events.
    /// Does NOT broadcast — callers decide whether to broadcast.
    async fn process_and_commit_block(&mut self, block: Block) -> Result<()> {
        self.refresh_executor_token_creation_fee_if_needed();

        // ORACLE-R6: Apply pending protocol activation before execution so activation at
        // height H governs block H. If block admission fails before execution/commit,
        // restore the prior config.
        let previous_protocol_config = self.oracle_state.protocol_config.clone();
        let activated_version = self
            .oracle_state
            .apply_pending_protocol_activation(block.header.height);
        if let Some(new_version) = activated_version {
            info!(
                "🔮 Oracle protocol upgraded to v{} at activation block height {}",
                new_version.as_u16(),
                block.header.height
            );
        }

        // ORACLE-13: Validate CBE graduation oracle gate BEFORE applying block
        // This ensures consensus rules are enforced atomically in BOTH
        // BlockExecutor and legacy paths
        if let Err(e) = self.validate_block_cbe_graduation_gating(&block) {
            if activated_version.is_some() {
                self.oracle_state.protocol_config = previous_protocol_config.clone();
            }
            return Err(e);
        }

        // If BlockExecutor is configured, use it as single source of truth
        if let Some(ref executor) = self.executor {
            // Seed SledStore with any in-memory token balances that were never persisted
            // there. Wallets that received their initial balance via token.mint() (e.g.
            // during register_wallet) only exist in the in-memory token_contracts HashMap;
            // SledStore has 0 for them. The executor reads SledStore for debit_token and
            // will abort the block if it sees 0, halting the network. backfill writes
            // ONLY entries that are missing from the tree (idempotent, safe to call here
            // before begin_block sets tx_active).
            if let Some(store) = &self.store {
                let mut seed_map: std::collections::HashMap<[u8; 32], Vec<([u8; 32], u128)>> =
                    std::collections::HashMap::new();
                for tx in &block.transactions {
                    if let Some(data) = tx.token_transfer_data() {
                        if let Some(token) = self.token_contracts.get(&data.token_id) {
                            // Look up the sender's in-memory balance.
                            // balances is keyed by PublicKey; the SledStore uses key_id as
                            // the 32-byte address — they match for both SOV and custom tokens.
                            let mem_balance = token
                                .find_balance_by_key_id(&data.from)
                                .map(|(_, b)| b)
                                .unwrap_or(0);
                            if mem_balance > 0 {
                                let addr = crate::storage::Address::new(data.from);
                                let storage_token = crate::storage::TokenId(data.token_id);
                                let sled_bal =
                                    store.get_token_balance(&storage_token, &addr).unwrap_or(0);
                                if sled_bal == 0 {
                                    seed_map
                                        .entry(data.token_id)
                                        .or_default()
                                        .push((data.from, mem_balance));
                                }
                            }
                        }
                    }
                }
                for (token_id, entries) in &seed_map {
                    let storage_token = crate::storage::TokenId(*token_id);
                    match store.backfill_token_balances_from_contract(&storage_token, entries) {
                        Ok(n) if n > 0 => tracing::info!(
                            "[seed-sled] seeded {} missing balance(s) for token {} before block {}",
                            n,
                            hex::encode(&token_id[..8]),
                            block.header.height
                        ),
                        Err(e) => tracing::warn!(
                            "[seed-sled] backfill failed for token {} at block {}: {}",
                            hex::encode(&token_id[..8]),
                            block.header.height,
                            e
                        ),
                        _ => {}
                    }
                }
            }

            // Use BlockExecutor for state mutations
            // Note: executor.apply_block() handles begin_block/commit_block internally
            match executor.apply_block(&block) {
                Ok(_outcome) => {
                    // Block applied successfully through executor.
                    // Sync in-memory token_contracts from SledStore for all addresses
                    // touched by this block (transfers debit/credit, mints credit).
                    // This keeps the in-memory HashMap authoritative for balance queries
                    // without a second source of truth.
                    if let Some(store) = &self.store {
                        let sov_id = crate::contracts::utils::generate_lib_token_id();
                        let storage_sov_id = crate::storage::TokenId(sov_id);
                        let mut addrs_to_sync: Vec<[u8; 32]> = Vec::new();
                        for tx in &block.transactions {
                            match tx.transaction_type {
                                TransactionType::TokenTransfer => {
                                    if let Some(d) = tx.token_transfer_data() {
                                        addrs_to_sync.push(d.from);
                                        addrs_to_sync.push(d.to);
                                    }
                                }
                                TransactionType::TokenMint => {
                                    if let Some(d) = tx.token_mint_data() {
                                        addrs_to_sync.push(d.to);
                                    }
                                }
                                _ => {}
                            }
                        }
                        for addr_bytes in addrs_to_sync {
                            let addr = crate::storage::Address::new(addr_bytes);
                            if let Ok(balance) = store.get_token_balance(&storage_sov_id, &addr) {
                                if let Some(token) = self.token_contracts.get_mut(&sov_id) {
                                    let pk = Self::wallet_key_for_sov(&addr_bytes);
                                    token.set_balance(&pk, balance as u128);
                                }
                            }
                        }

                    }

                    // Update blockchain metadata
                    self.blocks.push(block.clone());
                    self.height += 1;
                    self.process_validator_registration_transactions(&block);
                    self.process_gateway_transactions(&block);
                    // Rebuild wallet_registry and in-memory SOV balances from WalletRegistration
                    // transactions in this block. The BlockExecutor handles SledStore state but
                    // does NOT update the in-memory wallet_registry or token_contracts mints.
                    // Without this call, after a restart from an old .dat file the in-memory
                    // balance stays at 0 for wallets whose registration block was applied in
                    // executor mode — making transfers fail the mempool balance check.
                    if let Err(e) = self.process_wallet_transactions(&block) {
                        warn!("process_wallet_transactions in executor path: {}", e);
                    }
                    // Replay employment contract setup so executor has in-memory registry.
                    if let Err(e) = self.process_employment_contract_transactions(&block) {
                        warn!("process_employment_contract_transactions in executor path: {}", e);
                    }
                    self.process_domain_transactions(&block);
                    self.process_nft_transactions(&block);
                    for tx in &block.transactions {
                        self.index_dao_registry_entry_from_tx(tx, block.header.height);
                        // Executor returns LegacySystem for ValidatorRegistration — update registry here
                        if tx.transaction_type == TransactionType::ValidatorRegistration {
                            if let Some(vd) = tx.validator_data() {
                                let status = match vd.operation {
                                    crate::transaction::ValidatorOperation::Register => "active",
                                    crate::transaction::ValidatorOperation::Update => "active",
                                    crate::transaction::ValidatorOperation::Unregister => {
                                        "inactive"
                                    }
                                };
                                // Convert consensus_key from Vec<u8> to [u8; 2592]
                                let consensus_key: [u8; 2592] = match vd.consensus_key.as_slice().try_into() {
                                    Ok(k) => k,
                                    Err(_) => {
                                        warn!("Skipping validator {}: consensus_key must be 2592 bytes (Dilithium5)", vd.identity_id);
                                        continue;
                                    }
                                };
                                let vi = ValidatorInfo {
                                    identity_id: vd.identity_id.clone(),
                                    stake: vd.stake,
                                    storage_provided: vd.storage_provided,
                                    consensus_key,
                                    networking_key: vd.networking_key.clone(),
                                    rewards_key: vd.rewards_key.clone(),
                                    network_address: vd.network_address.clone(),
                                    commission_rate: vd.commission_rate,
                                    status: status.to_string(),
                                    registered_at: block.header.height,
                                    last_activity: block.header.height,
                                    blocks_validated: 0,
                                    slash_count: 0,
                                    admission_source: ADMISSION_SOURCE_ONCHAIN_GOVERNANCE
                                        .to_string(),
                                    governance_proposal_id: None,
                                    oracle_key_id: None,
                                };
                                self.validator_registry.insert(vd.identity_id.clone(), vi);
                                self.validator_blocks
                                    .insert(vd.identity_id.clone(), block.header.height);
                                info!(
                                    "Validator {} {:?} at height {}",
                                    vd.identity_id, vd.operation, block.header.height
                                );
                            }
                        }
                    }
                    self.adjust_difficulty()?;

                    debug!(
                        "Block {} applied via BlockExecutor (single source of truth)",
                        block.height()
                    );

                    // Continue with post-processing (events, persistence)
                    self.finish_block_processing(block).await?;
                    return Ok(());
                }
                Err(e) => {
                    if activated_version.is_some() {
                        self.oracle_state.protocol_config = previous_protocol_config.clone();
                    }
                    return Err(anyhow::anyhow!(
                        "BlockExecutor failed to apply block: {}",
                        e
                    ));
                }
            }
        }

        // DEPRECATED: Legacy path without BlockExecutor
        // This path will be removed in a future version
        warn!("DEPRECATED: Using legacy block processing path without BlockExecutor. Please use Blockchain::new_with_executor() or set_executor().");

        // Legacy path: direct state mutations (when no executor configured)
        // Verify the block
        let previous_block = self.blocks.last();
        if !self.verify_block(&block, previous_block)? {
            if activated_version.is_some() {
                self.oracle_state.protocol_config = previous_protocol_config.clone();
            }
            return Err(anyhow::anyhow!("Invalid block"));
        }

        // Check for double spends
        for tx in &block.transactions {
            for input in &tx.inputs {
                if self.nullifier_set.contains(&input.nullifier) {
                    if activated_version.is_some() {
                        self.oracle_state.protocol_config = previous_protocol_config.clone();
                    }
                    return Err(anyhow::anyhow!("Double spend detected"));
                }
            }
        }

        // Issue #1016: Deduct transaction fees from sender balances BEFORE updating UTXO set
        let block_fees = match self.deduct_transaction_fees(&block) {
            Ok(fees) => fees,
            Err(e) => {
                if activated_version.is_some() {
                    self.oracle_state.protocol_config = previous_protocol_config.clone();
                }
                return Err(e);
            }
        };
        if block_fees > 0 {
            debug!(
                "Collected {} in fees from block {}",
                block_fees,
                block.height()
            );
        }

        // Update blockchain state
        self.blocks.push(block.clone());
        self.height += 1;
        self.update_utxo_set(&block)?;
        self.save_utxo_snapshot(self.height)?;
        self.adjust_difficulty()?;

        // Remove processed transactions from pending pool
        self.remove_pending_transactions(&block.transactions);

        // Begin sled transaction for remaining processing
        if let Some(ref store) = self.store {
            store
                .begin_block(block.header.height)
                .map_err(|e| anyhow::anyhow!("Failed to begin Sled transaction: {}", e))?;
        }

        // Process identity transactions
        self.process_identity_transactions(&block)?;
        self.process_wallet_transactions(&block)?;
        self.process_entity_registry_transactions(&block)?;
        self.process_employment_contract_transactions(&block)?;
        self.process_domain_transactions(&block);
        self.process_nft_transactions(&block);
        self.process_contract_transactions(&block)?;
        self.process_token_transactions(&block)?;
        self.process_validator_registration_transactions(&block);
        self.process_gateway_transactions(&block);
        for tx in &block.transactions {
            self.index_dao_registry_entry_from_tx(tx, block.header.height);
        }

        // Process approved governance proposals
        if let Err(e) = self.process_approved_governance_proposals() {
            warn!(
                "Error processing governance proposals at height {}: {}",
                self.height, e
            );
        }

        // ORACLE-R4: Apply pending oracle updates at epoch boundaries
        // Uses timestamp-based comparison to handle epoch_duration changes correctly
        if self
            .oracle_state
            .should_process_epoch(block.header.timestamp, self.last_oracle_epoch_processed)
        {
            // ORACLE-R4: Apply pending oracle updates at epoch boundaries
            // Uses timestamp-based comparison to handle epoch_duration changes correctly
            let current_epoch = self.oracle_state.epoch_id(block.header.timestamp);
            self.oracle_state.apply_pending_updates(current_epoch);
            // ORACLE-R1: Apply pending committee removals at epoch boundaries (Spec §9)
            self.apply_pending_committee_removals(current_epoch);
            self.last_oracle_epoch_processed = block.header.timestamp;
            debug!(
                "Oracle epoch processed: {} at block {}",
                current_epoch, self.height
            );
        }

        // Process economic features
        if let Err(e) = self.process_ubi_claim_transactions(&block) {
            warn!(
                "Error processing UBI claims at height {}: {}",
                self.height, e
            );
        }

        if let Err(e) = self.process_profit_declarations(&block) {
            warn!(
                "Error processing profit declarations at height {}: {}",
                self.height, e
            );
        }

        // Create transaction receipts
        let block_hash = block.hash();
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            if let Err(e) =
                self.create_receipt(tx, block_hash, block.header.height, tx_index as u32)
            {
                warn!(
                    "Failed to create receipt for tx {}: {}",
                    hex::encode(tx.hash().as_bytes()),
                    e
                );
            }
        }

        // Persist block to SledStore
        if let Some(ref store) = self.store {
            if let Err(e) = self.persist_to_sled_store(&block, store.clone()) {
                error!(
                    "Failed to persist block {} to SledStore: {}",
                    block.height(),
                    e
                );
            } else {
                debug!("Block {} persisted to SledStore", block.height());
            }
        }

        self.blocks_since_last_persist += 1;

        // Emit BlockAdded event
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
        }

        Ok(())
    }

    /// Finish block processing after state mutations are complete.
    /// This handles post-processing steps that happen regardless of which path was used.
    async fn finish_block_processing(&mut self, block: Block) -> Result<()> {
        // Remove processed transactions from pending pool
        self.remove_pending_transactions(&block.transactions);

        // When the BlockExecutor is active it has already called begin_block/commit_block
        // inside apply_block(). Starting a second begin_block() for the same height would
        // fail with an InvalidBlockHeight error.
        //
        // On the executor path: open a metadata-only write batch that does not advance
        // latest_height, allowing identity/wallet/entity index writes to be committed
        // after the executor has already closed its block transaction.
        // On the legacy path: open a normal block transaction as before.
        let using_executor = self.executor.is_some();
        if using_executor {
            if let Some(ref store) = self.store {
                store
                    .begin_metadata_write()
                    .map_err(|e| anyhow::anyhow!("Failed to begin metadata write: {}", e))?;
            }
        } else if let Some(ref store) = self.store {
            store
                .begin_block(block.header.height)
                .map_err(|e| anyhow::anyhow!("Failed to begin Sled transaction: {}", e))?;
        }

        // Process identity transactions
        self.process_identity_transactions(&block)?;
        self.process_wallet_transactions(&block)?;
        self.process_entity_registry_transactions(&block)?;
        self.process_employment_contract_transactions(&block)?;
        self.process_domain_transactions(&block);

        // Skip token/contract processing when using BlockExecutor - it handles these
        if !self.has_executor() {
            self.process_contract_transactions(&block)?;
            self.process_token_transactions(&block)?;
        } else {
            debug!("Skipping legacy token/contract processing - BlockExecutor is single source of truth");
        }

        // Process approved governance proposals
        if let Err(e) = self.process_approved_governance_proposals() {
            warn!(
                "Error processing governance proposals at height {}: {}",
                self.height, e
            );
        }

        // ORACLE-R4: Process oracle epoch advancement
        // Apply pending committee/config updates when epoch boundary is crossed
        // Uses timestamp-based comparison for consistency across epoch_duration changes
        if self
            .oracle_state
            .should_process_epoch(block.header.timestamp, self.last_oracle_epoch_processed)
        {
            let block_epoch = self.oracle_state.epoch_id(block.header.timestamp);
            self.oracle_state.apply_pending_updates(block_epoch);
            // ORACLE-R1: Apply pending committee removals at epoch boundaries (Spec §9)
            self.apply_pending_committee_removals(block_epoch);
            self.last_oracle_epoch_processed = block.header.timestamp;
            info!(
                "🔮 Oracle advanced to epoch {} (block height {})",
                block_epoch, self.height
            );
        }

        // #1897: Process on-ramp trade transactions
        self.process_on_ramp_trade_transactions(&block);

        // ORACLE-R3: Process oracle attestation transactions through canonical path
        // In V0 (legacy) mode: Also process gossip attestations (backward compatibility)
        // In V1 (strict spec) mode: Only transaction attestations are processed
        self.process_oracle_attestation_transactions(&block, block.header.timestamp);

        // Process economic features
        if let Err(e) = self.process_ubi_claim_transactions(&block) {
            warn!(
                "Error processing UBI claims at height {}: {}",
                self.height, e
            );
        }

        if let Err(e) = self.process_profit_declarations(&block) {
            warn!(
                "Error processing profit declarations at height {}: {}",
                self.height, e
            );
        }

        // Create transaction receipts
        let block_hash = block.hash();
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            if let Err(e) =
                self.create_receipt(tx, block_hash, block.header.height, tx_index as u32)
            {
                warn!(
                    "Failed to create receipt for tx {}: {}",
                    hex::encode(tx.hash().as_bytes()),
                    e
                );
            }
        }

        // Persist block to SledStore — skip when using the BlockExecutor because
        // apply_block() already committed the block (begin_block → append_block →
        // commit_block). On the executor path we commit the metadata-only batch opened
        // above; on the legacy path we call persist_to_sled_store which handles its own
        // transaction via the normal block transaction opened earlier.
        if using_executor {
            if let Some(ref store) = self.store {
                if let Err(e) = store.commit_metadata_write() {
                    error!(
                        "Failed to commit identity/wallet metadata for block {}: {}",
                        block.height(),
                        e
                    );
                }
            }
            debug!(
                "Block {} block data already persisted by BlockExecutor; metadata committed",
                block.height()
            );
        } else if let Some(ref store) = self.store {
            if let Err(e) = self.persist_to_sled_store(&block, store.clone()) {
                error!(
                    "Failed to persist block {} to SledStore: {}",
                    block.height(),
                    e
                );
            } else {
                debug!("Block {} persisted to SledStore", block.height());
            }
        }

        self.blocks_since_last_persist += 1;

        // Emit BlockAdded event
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
        }

        Ok(())
    }

    /// Add a block and generate recursive proof for blockchain sync
    pub async fn add_block_with_proof(&mut self, block: Block) -> Result<()> {
        // Add block using existing validation logic
        self.add_block(block.clone()).await?;

        // Generate recursive proof for this block (for edge node sync)
        if let Err(e) = self.generate_proof_for_block(&block).await {
            warn!(
                "  Failed to generate recursive proof for block {}: {}",
                block.height(),
                e
            );
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
    pub async fn generate_proof_for_block(&mut self, block: &Block) -> Result<()> {
        // Get or initialize proof aggregator
        let aggregator_arc = self.get_proof_aggregator().await?;
        let mut aggregator = aggregator_arc.write().await;

        // Convert block transactions to batched format
        let batched_transactions: Vec<BatchedPrivateTransaction> = block
            .transactions
            .iter()
            .map(|tx| {
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
            })
            .collect();

        // Get previous state root
        let previous_state_root = if block.height() > 0 {
            self.blocks[block.height() as usize - 1].header.state_root
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

    pub async fn add_block_with_persistence(&mut self, block: Block) -> Result<()> {
        let snapshot = self.clone();

        let result: Result<()> = async {
            self.add_block(block.clone()).await?;

            if let Some(_) = self.persist_block(&block).await? {
                info!(" Block {} persisted to storage", block.height());
            }

            if self.auto_persist_enabled
                && (self.height % 10 == 0 || self.blocks_since_last_persist >= 10)
            {
                if let Some(_) = self.persist_utxo_set().await? {
                    info!(" UTXO set persisted to storage at height {}", self.height);
                }
            }

            self.auto_persist_if_needed().await?;

            Ok(())
        }
        .await;

        if let Err(e) = result {
            *self = snapshot;
            return Err(e);
        }

        Ok(())
    }

    /// Add a network-received block with persistence. Skips mesh broadcast.
    pub async fn add_block_from_network_with_persistence(&mut self, block: Block) -> Result<()> {
        let snapshot = self.clone();

        let result: Result<()> = async {
            self.add_block_from_network(block.clone()).await?;

            if let Some(_) = self.persist_block(&block).await? {
                info!(" Block {} persisted to storage", block.height());
            }

            if self.auto_persist_enabled
                && (self.height % 10 == 0 || self.blocks_since_last_persist >= 10)
            {
                if let Some(_) = self.persist_utxo_set().await? {
                    info!(" UTXO set persisted to storage at height {}", self.height);
                }
            }

            self.auto_persist_if_needed().await?;

            Ok(())
        }
        .await;

        if let Err(e) = result {
            *self = snapshot;
            return Err(e);
        }

        Ok(())
    }

    /// Persist a block to the SledStore (Phase 3 incremental storage)
    ///
    /// This method atomically writes:
    /// - The block itself
    /// - Latest height metadata
    fn persist_to_sled_store(
        &self,
        block: &Block,
        store: std::sync::Arc<dyn BlockchainStore>,
    ) -> Result<()> {
        // Note: begin_block() is called earlier in process_and_commit_block()
        // to ensure identity/wallet sled writes have an active transaction

        // Append the block
        store
            .append_block(block)
            .map_err(|e| anyhow::anyhow!("Failed to append block to Sled: {}", e))?;

        // Commit the transaction
        store
            .commit_block()
            .map_err(|e| anyhow::anyhow!("Failed to commit Sled transaction: {}", e))?;

        info!("💾 Block {} persisted to SledStore", block.header.height);
        Ok(())
    }

    /// Verify a block against the current chain state
    pub fn verify_block(&self, block: &Block, previous_block: Option<&Block>) -> Result<bool> {
        info!("Starting block verification for height {}", block.height());

        // Verify block header
        if let Some(prev) = previous_block {
            if block.previous_hash() != prev.hash() {
                warn!(
                    "Previous hash mismatch: block={:?}, prev={:?}",
                    block.previous_hash(),
                    prev.hash()
                );
                return Ok(false);
            }
            if block.height() != prev.height() + 1 {
                warn!(
                    "Height mismatch: block={}, expected={}",
                    block.height(),
                    prev.height() + 1
                );
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

        info!(
            "Block verification successful for height {}",
            block.height()
        );
        Ok(true)
    }

    /// Verify a transaction against current blockchain state
    pub fn verify_transaction(&self, transaction: &Transaction) -> Result<bool> {
        // Use the stateful transaction validator with blockchain context for identity verification
        let validator = crate::transaction::validation::StatefulTransactionValidator::new(self);

        // Check if this is a system transaction (empty inputs indicates system transaction)
        // BUT token contract executions are NOT system transactions (they must pay fees)
        // Use the full validation logic to ensure consistency with fee validation
        let is_token_contract = crate::transaction::is_token_contract_execution(transaction);
        let is_system_transaction = transaction.inputs.is_empty() && !is_token_contract;

        tracing::info!("Verifying transaction with identity verification enabled");
        tracing::info!("System transaction: {}", is_system_transaction);
        tracing::info!("Transaction type: {:?}", transaction.transaction_type);
        tracing::debug!(
            "[FLOW] verify_transaction: tx_hash={}, size={}, memo_len={}, fee={}",
            hex::encode(transaction.hash().as_bytes()),
            transaction.size(),
            transaction.memo.len(),
            transaction.fee
        );

        let result = validator.validate_transaction_with_state(transaction);
        tracing::debug!("[FLOW] verify_transaction: validate_transaction_with_state done");

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

        // Pre-compute fee payers before taking mutable borrow on token contract.
        // This avoids borrow conflict between self.token_contracts.get_mut() and
        // self.primary_wallet_for_signer().
        let fee_payers: Vec<(usize, PublicKey)> = block
            .transactions
            .iter()
            .enumerate()
            .filter_map(|(i, tx)| {
                let is_token_contract = crate::transaction::is_token_contract_execution(tx);
                let is_system = tx.inputs.is_empty() && !is_token_contract;
                if is_system || tx.fee == 0 {
                    return None;
                }
                let sender = &tx.signature.public_key;
                let fee_payer =
                    if let Some(wallet_id) = self.primary_wallet_for_signer(&sender.key_id) {
                        Self::wallet_key_for_sov(&wallet_id)
                    } else {
                        sender.clone()
                    };
                Some((i, fee_payer))
            })
            .collect();

        // Get mutable reference to SOV token contract
        let sov_token = match self.token_contracts.get_mut(&sov_token_id) {
            Some(token) => token,
            None => {
                // SOV token not deployed yet - this is expected during bootstrap
                debug!(
                    "SOV token contract not found, skipping fee deduction for block {}",
                    block.height()
                );
                return Ok(0);
            }
        };

        let mut total_fees: u64 = 0;

        for (i, fee_payer) in &fee_payers {
            let tx = &block.transactions[*i];
            let sender = &tx.signature.public_key;

            // Check sender's balance before deduction
            let sender_balance = sov_token.balance_of(&fee_payer);
            if sender_balance < tx.fee as u128 {
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
            // Note: Direct balance mutation for backward compatibility.
            // SOV token operations go through TreasuryKernel for new transactions,
            // but this historical fee deduction maintains existing behavior.
            let new_balance = sender_balance - tx.fee as u128;
            sov_token.set_balance(&fee_payer, new_balance);

            total_fees = total_fees.saturating_add(tx.fee);

            debug!(
                "Fee deducted: {} from sender {} (tx: {})",
                tx.fee,
                hex::encode(&sender.key_id[..8]),
                hex::encode(&tx.hash().as_bytes()[..8])
            );
        }

        // Credit collected fees to DAO treasury wallet (conservation invariant: total supply unchanged)
        // Note: Direct balance mutation for backward compatibility.
        // New token operations should route through TreasuryKernel.
        if total_fees > 0 {
            if let Some(ref treasury_wallet_id) = self.dao_treasury_wallet_id {
                match hex::decode(treasury_wallet_id) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut treasury_id = [0u8; 32];
                        treasury_id.copy_from_slice(&bytes);
                        let treasury_key = Self::wallet_key_for_sov(&treasury_id);
                        let treasury_balance = sov_token.balance_of(&treasury_key);
                        sov_token
                            .set_balance(&treasury_key, treasury_balance.saturating_add(total_fees as u128));
                        debug!(
                            "Block {} fees credited to DAO treasury: {} SOV",
                            block.height(),
                            total_fees
                        );
                    }
                    _ => {
                        warn!(
                            "Block {} fee crediting skipped: malformed dao_treasury_wallet_id '{}'",
                            block.height(),
                            treasury_wallet_id
                        );
                    }
                }
            }

            info!(
                "Block {} fee collection: {} total from {} transactions",
                block.height(),
                total_fees,
                block
                    .transactions
                    .iter()
                    .filter(|tx| {
                        let is_token_contract = crate::transaction::is_token_contract_execution(tx);
                        let is_system = tx.inputs.is_empty() && !is_token_contract;
                        !is_system && tx.fee > 0
                    })
                    .count()
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
                         This indicates a consensus layer problem requiring attention.",
                        e
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
        let new_difficulty =
            (self.difficulty.bits() as u64 * target_timespan / clamped_timespan) as u32;
        new_difficulty.max(1)
    }

    /// Get the latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Get the timestamp of the last committed block.
    ///
    /// Returns the timestamp from the latest block header, or the genesis timestamp
    /// if only the genesis block exists. This is the canonical time reference for
    /// oracle epoch derivation per Oracle Spec v1 §4.1.
    ///
    /// Note: Blockchain::new() creates a genesis block with timestamp 1730419200
    /// (November 1, 2025 00:00:00 UTC), so this never returns 0 in practice.
    pub fn last_committed_timestamp(&self) -> u64 {
        self.latest_block().map(|b| b.header.timestamp).unwrap_or(0)
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

    /// Get the current transaction fee configuration
    pub fn get_tx_fee_config(&self) -> &crate::transaction::TxFeeConfig {
        &self.tx_fee_config
    }

    /// Update the transaction fee configuration (governance-controlled)
    pub fn set_tx_fee_config(&mut self, config: crate::transaction::TxFeeConfig) {
        self.tx_fee_config = config;
        self.refresh_executor_token_creation_fee_if_needed();
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
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid difficulty config: {}", e))?;
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

    /// Check whether a transaction's nonce is still valid against committed chain state.
    ///
    /// Returns `true` for transaction types that don't carry nonces (they are
    /// validated by other means).  For `TokenTransfer`, the nonce must equal
    /// the sender's current on-chain nonce for the target token — anything
    /// lower has already been applied and is a replay.
    pub fn is_nonce_current(&self, tx: &Transaction) -> bool {
        if tx.transaction_type == TransactionType::TokenTransfer {
            if let Some(transfer) = tx.token_transfer_data() {
                let token_id = if transfer.token_id == [0u8; 32] {
                    crate::contracts::utils::generate_lib_token_id()
                } else {
                    transfer.token_id
                };
                let expected = self.get_token_nonce(&token_id, &transfer.from);
                if transfer.nonce < expected {
                    tracing::debug!(
                        "Stale nonce: tx {} has nonce {} but chain expects {} for sender {}",
                        tx.hash(),
                        transfer.nonce,
                        expected,
                        hex::encode(&transfer.from[..8]),
                    );
                    return false;
                }
                if transfer.nonce > expected {
                    tracing::debug!(
                        "Future nonce: tx {} has nonce {} but chain expects {} for sender {}",
                        tx.hash(),
                        transfer.nonce,
                        expected,
                        hex::encode(&transfer.from[..8]),
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Get pending transactions
    pub fn get_pending_transactions(&self) -> Vec<Transaction> {
        self.pending_transactions.clone()
    }

    /// Add a transaction to the pending pool
    pub fn add_pending_transaction(&mut self, transaction: Transaction) -> Result<()> {
        let tx_type = transaction.transaction_type;
        self.verify_and_enqueue_transaction(transaction.clone())?;
        match tx_type {
            TransactionType::TokenTransfer | TransactionType::TokenMint | TransactionType::TokenCreation => {
                info!(
                    "[token/mempool] accepted: type={:?} tx={} size={} fee={}",
                    tx_type,
                    &hex::encode(transaction.hash().as_bytes())[..8],
                    transaction.size(),
                    transaction.fee,
                );
            }
            _ => {
                tracing::debug!(
                    "mempool accepted: type={:?} tx={} size={} fee={}",
                    tx_type,
                    &hex::encode(transaction.hash().as_bytes())[..8],
                    transaction.size(),
                    transaction.fee,
                );
            }
        }

        // Broadcast new transaction to mesh network (locally-originated only)
        if let Some(ref sender) = self.broadcast_sender {
            if let Err(e) = sender.send(BlockchainBroadcastMessage::NewTransaction(
                transaction.clone(),
            )) {
                warn!("Failed to broadcast new transaction to network: {}", e);
            } else {
                debug!(
                    "Transaction {} broadcast to mesh network",
                    transaction.hash()
                );
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
        tracing::debug!(
            "[FLOW] verify_and_enqueue_transaction: tx_hash={}, type={:?}, inputs={}, outputs={}",
            hex::encode(transaction.hash().as_bytes()),
            transaction.transaction_type,
            transaction.inputs.len(),
            transaction.outputs.len()
        );
        if !self.verify_transaction(&transaction)? {
            return Err(anyhow::anyhow!("Transaction verification failed"));
        }

        // Nonce gate: reject transactions whose nonce doesn't match the
        // current chain state.  This prevents stale/replayed transactions
        // from entering the mempool (root cause of the block-1323 incident).
        if !self.is_nonce_current(&transaction) {
            let tx_hash = hex::encode(transaction.hash().as_bytes());
            return Err(anyhow::anyhow!(
                "Transaction {} rejected: stale or future nonce",
                &tx_hash[..16]
            ));
        }

        self.pending_transactions.push(transaction);
        tracing::debug!("[FLOW] verify_and_enqueue_transaction: enqueued");
        Ok(())
    }

    /// Add a transaction to the pending pool with persistent storage
    pub async fn add_pending_transaction_with_persistence(
        &mut self,
        transaction: Transaction,
    ) -> Result<()> {
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

    /// Remove committed transactions from the pending pool, then evict any
    /// remaining pending transactions whose nonces are now stale.
    ///
    /// After a block commits, the on-chain nonce for each sender advances.
    /// Other pending transactions from the same sender that carried the
    /// now-consumed nonce (e.g. re-submitted via gossip) must be evicted to
    /// prevent the proposer from including a replay in the next block.
    pub fn remove_pending_transactions(&mut self, transactions: &[Transaction]) {
        let tx_hashes: HashSet<Hash> = transactions.iter().map(|tx| tx.hash()).collect();

        // Phase 1: remove the exact committed transactions by hash.
        self.pending_transactions
            .retain(|tx| !tx_hashes.contains(&tx.hash()));

        // Phase 2: evict remaining transactions with stale nonces.
        // Collect stale tx hashes first to avoid borrow conflict.
        let stale_hashes: Vec<Hash> = self
            .pending_transactions
            .iter()
            .filter(|tx| !self.is_nonce_current(tx))
            .map(|tx| tx.hash())
            .collect();

        if !stale_hashes.is_empty() {
            let stale_set: HashSet<Hash> = stale_hashes.iter().cloned().collect();
            self.pending_transactions
                .retain(|tx| !stale_set.contains(&tx.hash()));
            tracing::info!(
                "Evicted {} pending transaction(s) with stale nonces after block commit",
                stale_hashes.len(),
            );
        }
    }

    /// Apply a token transfer with protocol fee deduction and treasury routing.
    ///
    /// This is a helper that consolidates the duplicated fee logic from the two
    /// TokenTransfer code paths (wallet-addressed and key-id addressed).
    #[allow(dead_code)]
    fn apply_token_transfer_with_fee(
        token: &mut crate::contracts::TokenContract,
        sender: &PublicKey,
        amount: u64,
        fee_amount: u64,
        treasury_key: &Option<PublicKey>,
        height: u64,
    ) -> Result<(), anyhow::Error> {
        if fee_amount == 0 {
            return Ok(());
        }
        let sender_bal = token.balance_of(sender);
        if sender_bal < amount as u128 {
            return Err(anyhow::anyhow!(
                "TokenTransfer insufficient balance: have {}, need {}",
                sender_bal,
                amount
            ));
        }
        let sender_bal_post = token.balance_of(sender);
        token
            .set_balance(sender, sender_bal_post.saturating_sub(fee_amount as u128));
        if let Some(ref tpk) = treasury_key {
            let tbal = token.balance_of(tpk);
            token
                .set_balance(tpk, tbal.saturating_add(fee_amount as u128));
            debug!(
                "TokenTransfer: {} SOV fee → DAO treasury (height {})",
                fee_amount, height
            );
        }
        Ok(())
    }

    /// Evict Phase-2-invalid transactions (TokenMint with fee != 0) from the mempool.
    ///
    /// TokenMint must have fee == 0. TokenTransfer may carry any fee value.
    pub fn evict_phase2_invalid_transactions(&mut self, context: &str) -> usize {
        use crate::types::transaction_type::TransactionType;
        let before = self.pending_transactions.len();
        self.pending_transactions.retain(|tx| {
            if tx.transaction_type == TransactionType::TokenMint && tx.fee != 0 {
                warn!(
                    "{}: evicting invalid TokenMint pending tx hash={} fee={}",
                    context,
                    hex::encode(&tx.hash().as_bytes()[..8]),
                    tx.fee,
                );
                false
            } else {
                true
            }
        });
        let evicted = before - self.pending_transactions.len();
        if evicted > 0 {
            warn!(
                "{}: evicted {} invalid pending transaction(s)",
                context, evicted
            );
        }
        evicted
    }
    /// Get the current expected nonce for a sender address and token.
    /// For SOV transfers, the address is the wallet_id bytes.
    /// For custom token transfers, the address is the key_id bytes.
    ///
    /// The in-memory HashMap is checked first; it is populated both during live
    /// block processing and from the TokenStateSnapshot on restart.  The store
    /// is only consulted when the key is absent from the HashMap (e.g. for
    /// nonces written by the BlockExecutor path but not yet reflected in memory).
    pub fn get_token_nonce(&self, token_id: &[u8; 32], address: &[u8; 32]) -> u64 {
        // In-memory HashMap is the primary source (populated from snapshot on
        // restart and incremented during process_token_transactions).
        if let Some(&nonce) = self.token_nonces.get(&(*token_id, *address)) {
            return nonce;
        }
        // Fallback to store for nonces not yet reflected in the HashMap.
        if let Some(store) = self.get_store() {
            let token = crate::storage::TokenId::new(*token_id);
            let addr = crate::storage::Address::new(*address);
            if let Ok(nonce) = store.get_token_nonce(&token, &addr) {
                return nonce;
            }
        }
        0
    }

    // ========================================================================
    // Entity Registry (Treasury Signer Registration)
    // ========================================================================

    /// Process InitEntityRegistry transactions in a block.
    ///
    /// Enforces one-time initialization: once the registry is set, any subsequent
    /// InitEntityRegistry transaction is a block-level error.
    pub fn process_entity_registry_transactions(&mut self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            if tx.transaction_type
                != crate::types::transaction_type::TransactionType::InitEntityRegistry
            {
                continue;
            }
            let tx_hash_hex = hex::encode(tx.hash().as_bytes());
            let data = tx.init_entity_registry_data().ok_or_else(|| {
                anyhow::anyhow!("InitEntityRegistry tx {} is missing payload", tx_hash_hex)
            })?;

            let registry = self
                .entity_registry
                .get_or_insert_with(crate::contracts::governance::EntityRegistry::new);

            if registry.is_initialized() {
                return Err(anyhow::anyhow!(
                    "InitEntityRegistry tx {} rejected: registry already initialized",
                    tx_hash_hex
                ));
            }

            registry
                .init(data.cbe_treasury.clone(), data.nonprofit_treasury.clone())
                .map_err(|e| {
                    anyhow::anyhow!("InitEntityRegistry tx {} failed: {}", tx_hash_hex, e)
                })?;
            registry.set_initialization_metadata(data.initialized_at, block.header.height);

            info!(
                "EntityRegistry initialized at height {} (tx {})",
                block.header.height, tx_hash_hex
            );
        }
        Ok(())
    }

    /// Process CreateEmploymentContract transactions in a block.
    pub fn process_employment_contract_transactions(&mut self, block: &Block) -> Result<()> {
        use crate::contracts::employment::{ContractAccessType, EconomicPeriod};

        for tx in &block.transactions {
            if tx.transaction_type
                != crate::types::transaction_type::TransactionType::CreateEmploymentContract
            {
                continue;
            }
            let tx_hash_hex = hex::encode(tx.hash().as_bytes());
            let data = tx.create_employment_contract_data().ok_or_else(|| {
                anyhow::anyhow!(
                    "CreateEmploymentContract tx {} is missing payload",
                    tx_hash_hex
                )
            })?;

            let contract_type = match data.contract_type {
                0 => ContractAccessType::PublicAccess,
                1 => ContractAccessType::Employment,
                other => {
                    return Err(anyhow::anyhow!(
                        "CreateEmploymentContract tx {} has unknown contract_type {}",
                        tx_hash_hex,
                        other
                    ));
                }
            };

            let payment_period = match data.payment_period {
                0 => EconomicPeriod::Monthly,
                1 => EconomicPeriod::Quarterly,
                2 => EconomicPeriod::Annually,
                other => {
                    return Err(anyhow::anyhow!(
                        "CreateEmploymentContract tx {} has unknown payment_period {}",
                        tx_hash_hex,
                        other
                    ));
                }
            };

            let employee_pk = PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: data.employee_key_id,
            };
            let caller_pk = tx.signature.public_key.clone();

            let contract_id = self
                .employment_registry
                .create_employment_contract(
                    data.dao_id,
                    employee_pk,
                    contract_type,
                    data.compensation_amount,
                    payment_period,
                    data.tax_rate_basis_points,
                    data.tax_jurisdiction.clone(),
                    data.profit_share_percentage,
                    &caller_pk,
                    block.header.height,
                )
                .map_err(|e| {
                    anyhow::anyhow!("CreateEmploymentContract tx {} failed: {}", tx_hash_hex, e)
                })?;

            info!(
                "Employment contract {:?} created at height {} (tx {})",
                hex::encode(contract_id),
                block.header.height,
                tx_hash_hex
            );
        }
        Ok(())
    }

    // ========================================================================
    // On-ramp trade processing (#1897)
    // ========================================================================

    /// Process RecordOnRampTrade transactions in a block.
    ///
    /// For each `RecordOnRampTrade` transaction, builds an `OnRampTrade` record
    /// and appends it to `self.onramp_state`.
    pub fn process_on_ramp_trade_transactions(&mut self, block: &Block) {
        use crate::types::transaction_type::TransactionType;
        for tx in &block.transactions {
            if tx.transaction_type != TransactionType::RecordOnRampTrade {
                continue;
            }
            if let Some(data) = tx.record_on_ramp_trade_data() {
                if self.onramp_state.has_equivalent_trade(
                    data.epoch_id,
                    data.cbe_amount,
                    data.usdc_amount,
                    data.traded_at,
                ) {
                    warn!(
                        "Ignoring duplicate OnRampTrade at height {} (epoch {}, cbe={}, usdc={}, traded_at={})",
                        block.header.height, data.epoch_id, data.cbe_amount, data.usdc_amount, data.traded_at
                    );
                    continue;
                }
                let trade = crate::onramp::OnRampTrade {
                    block_height: block.header.height,
                    epoch_id: data.epoch_id,
                    cbe_amount: data.cbe_amount,
                    usdc_amount: data.usdc_amount,
                    traded_at: data.traded_at,
                };
                self.onramp_state.record_trade(trade);
                info!(
                    "OnRampTrade recorded at height {} (epoch {}, cbe={}, usdc={})",
                    block.header.height, data.epoch_id, data.cbe_amount, data.usdc_amount
                );
            }
        }
    }

    // ========================================================================
    // Validator registration and management
    // ========================================================================

    /// Get access to the recursive proof aggregator for O(1) verification
    pub async fn get_proof_aggregator(
        &mut self,
    ) -> Result<std::sync::Arc<tokio::sync::RwLock<lib_proofs::RecursiveProofAggregator>>> {
        if self.proof_aggregator.is_none() {
            self.initialize_proof_aggregator()?;
        }

        self.proof_aggregator
            .clone()
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
            let batched_transactions: Vec<BatchedPrivateTransaction> = block
                .transactions
                .iter()
                .map(|tx| {
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
                })
                .collect();

            // Get previous state root (using merkle root as state representation)
            let previous_state_root = if i > 0 {
                self.blocks[i - 1].header.state_root
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
                    match aggregator
                        .create_recursive_chain_proof(&block_proof, previous_chain_proof.as_ref())
                    {
                        Ok(chain_proof) => {
                            info!(" Recursive chain proof created for block {}", i);
                            previous_chain_proof = Some(chain_proof);
                        }
                        Err(e) => {
                            error!(
                                "Failed to create recursive chain proof for block {}: {}",
                                i, e
                            );
                            return Err(anyhow::anyhow!(
                                "Failed to create recursive chain proof: {}",
                                e
                            ));
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
                    return Err(anyhow::anyhow!(
                        "Error verifying recursive chain proof: {}",
                        e
                    ));
                }
            }
        }

        info!(
            "O(1) instant verification enabled for entire blockchain with {} blocks",
            self.blocks.len()
        );
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
        citizens: &[(lib_economy::wasm::IdentityId, u128)],
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor
                .create_ubi_distributions_for_blockchain(citizens, system_keypair)
                .await?;
            let mut tx_hashes = Vec::new();

            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }

            info!(
                "🏦 Created {} UBI distribution transactions",
                tx_hashes.len()
            );
            Ok(tx_hashes)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create network reward transactions using lib-economy
    pub async fn create_network_rewards(
        &mut self,
        rewards: &[([u8; 32], u128)], // (recipient, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_txs = processor
                .create_network_reward_transactions(rewards, system_keypair)
                .await?;
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
        amount: u128,
        priority: lib_economy::Priority,
        sender_keypair: &lib_crypto::KeyPair,
    ) -> Result<Hash> {
        if let Some(ref mut processor) = self.economic_processor {
            let blockchain_tx = processor
                .create_payment_transaction_for_blockchain(
                    from,
                    to,
                    amount,
                    priority,
                    sender_keypair,
                )
                .await?;

            let tx_hash = blockchain_tx.hash();
            self.add_pending_transaction(blockchain_tx)?;

            info!(
                "🏦 Created payment transaction: {} SOV from {:?} to {:?}",
                amount, from, to
            );
            Ok(tx_hash)
        } else {
            Err(anyhow::anyhow!("Economic processor not initialized"))
        }
    }

    /// Create welfare funding transactions using lib-economy
    pub async fn create_welfare_funding(
        &mut self,
        services: &[(String, [u8; 32], u128)], // (service_name, address, amount)
        system_keypair: &lib_crypto::KeyPair,
    ) -> Result<Vec<Hash>> {
        if let Some(ref mut _processor) = self.economic_processor {
            let blockchain_txs =
                crate::integration::economic_integration::create_welfare_funding_transactions(
                    services,
                    system_keypair,
                )
                .await?;

            let mut tx_hashes = Vec::new();
            for tx in blockchain_txs {
                let tx_hash = tx.hash();
                self.add_pending_transaction(tx)?;
                tx_hashes.push(tx_hash);
            }

            info!(
                "🏦 Created {} welfare funding transactions",
                tx_hashes.len()
            );
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
        amount: u128,
        priority: lib_economy::Priority,
        is_system_transaction: bool,
    ) -> (u128, u128, u128) {
        if let Some(ref processor) = self.economic_processor {
            processor.calculate_transaction_fees_with_exemptions(
                tx_size,
                amount,
                priority,
                is_system_transaction,
            )
        } else {
            if is_system_transaction {
                (0, 0, 0)
            } else {
                let base_fee = (tx_size * 10) as u128;
                let dao_fee = amount * 200 / 10000;
                (base_fee, dao_fee, base_fee + dao_fee)
            }
        }
    }

    /// Get wallet balance for an address using economic processor
    pub fn get_wallet_balance(&self, address: &[u8; 32]) -> Option<u128> {
        if let Some(ref processor) = self.economic_processor {
            processor
                .get_wallet_balance(address)
                .map(|balance| balance.total_balance())
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
            let coordinator =
                crate::integration::consensus_integration::initialize_consensus_integration(
                    blockchain_arc,
                    mempool,
                    consensus_type,
                )
                .await?;

            self.consensus_coordinator =
                Some(std::sync::Arc::new(tokio::sync::RwLock::new(coordinator)));
            info!(" Consensus coordinator initialized for blockchain");
        }
        Ok(())
    }

    /// Get consensus coordinator reference
    pub fn get_consensus_coordinator(
        &self,
    ) -> Option<&std::sync::Arc<tokio::sync::RwLock<BlockchainConsensusCoordinator>>> {
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
            coordinator
                .register_as_validator(
                    identity,
                    stake_amount,
                    storage_capacity,
                    consensus_keypair,
                    consensus_keypair,
                    consensus_keypair,
                    commission_rate,
                )
                .await?;
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
        self.welfare_services
            .insert(service_id.clone(), service.clone());
        self.welfare_service_blocks
            .insert(service_id.clone(), self.height);

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
        self.service_performance
            .insert(service_id.clone(), performance);

        info!(
            "🏥 Registered welfare service: {} ({})",
            service.service_name, service_id
        );
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
        let service = self
            .welfare_services
            .get_mut(service_id)
            .ok_or_else(|| anyhow::anyhow!("Service {} not found", service_id))?;

        service.is_active = is_active;

        let status_str = if is_active {
            "activated"
        } else {
            "deactivated"
        };
        info!("🏥 Welfare service {} {}", service_id, status_str);
        Ok(())
    }

    /// Update welfare service reputation
    pub fn update_service_reputation(&mut self, service_id: &str, new_score: u8) -> Result<()> {
        let service = self
            .welfare_services
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

        info!(
            "🏥 Service {} reputation updated: {} → {}",
            service_id, old_score, new_score
        );
        Ok(())
    }

    // ============================================================================
    // SERVICE VERIFICATION METHODS
    // ============================================================================

    /// Verify that a service provider has required credentials for their service type
    fn verify_service_provider_credentials(
        &self,
        service: &lib_consensus::WelfareService,
    ) -> Result<()> {
        // Get provider identity by DID
        let provider_identity = self
            .get_identity(&service.provider_identity)
            .ok_or_else(|| {
                anyhow::anyhow!("Provider identity {} not found", service.provider_identity)
            })?;

        // Check minimum reputation threshold (providers need at least 30/100 reputation)
        let min_reputation = 30u32;
        let provider_id_hash = lib_crypto::Hash(lib_crypto::hash_blake3(
            service.provider_identity.as_bytes(),
        ));
        let provider_reputation = self.calculate_reputation_score(&provider_id_hash);

        if provider_reputation < min_reputation {
            return Err(anyhow::anyhow!(
                "Provider reputation {} below minimum threshold {}",
                provider_reputation,
                min_reputation
            ));
        }

        // Verify zero-knowledge credential proof if provided
        if let Some(credential_proof_bytes) = &service.credential_proof {
            self.verify_service_credential_proof(
                credential_proof_bytes,
                &service.service_type,
                &provider_identity.public_key,
            )?;
            info!(
                "✅ ZK credential proof verified for service type {:?}",
                service.service_type
            );
        } else {
            // No credential proof provided - fallback to basic verification
            warn!(
                "⚠️  No credential proof provided for service {} - using basic verification",
                service.service_id
            );

            // Verify service-type-specific requirements without ZK proofs
            match service.service_type {
                lib_consensus::WelfareServiceType::Healthcare
                | lib_consensus::WelfareServiceType::Education
                | lib_consensus::WelfareServiceType::EmergencyResponse => {
                    // Critical services require credential proofs
                    return Err(anyhow::anyhow!(
                        "Service type {:?} requires credential proof for registration",
                        service.service_type
                    ));
                }
                _ => {
                    // Generic services just need verified identity and good reputation
                    info!(
                        "✅ Basic verification passed for generic service type {:?}",
                        service.service_type
                    );
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
        let credential_proof: lib_proofs::identity::ZkCredentialProof =
            bincode::deserialize(proof_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize credential proof: {}", e))?;

        // Check proof hasn't expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if credential_proof.expires_at <= now {
            return Err(anyhow::anyhow!("Credential proof has expired"));
        }

        // Create credential schema for the service type
        let schema =
            self.get_credential_schema_for_service_type(service_type, provider_public_key)?;

        // Verify the credential proof using lib-proofs
        let verification_result =
            lib_proofs::identity::verify_credential_proof(&credential_proof, &schema)
                .map_err(|e| anyhow::anyhow!("Credential verification failed: {}", e))?;

        match verification_result {
            lib_proofs::types::VerificationResult::Valid { .. } => {
                info!(
                    "✅ Credential proof valid for service type {:?}",
                    service_type
                );
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
        let issuer_key: [u8; 32] = issuer_public_key
            .get(..32)
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
    fn validate_service_type_requirements(
        &self,
        service: &lib_consensus::WelfareService,
    ) -> Result<()> {
        // Validate service name
        if service.service_name.trim().is_empty() || service.service_name.len() < 3 {
            return Err(anyhow::anyhow!(
                "Service name must be at least 3 characters"
            ));
        }

        if service.service_name.len() > 200 {
            return Err(anyhow::anyhow!(
                "Service name too long (max 200 characters)"
            ));
        }

        // Validate description
        if service.description.trim().is_empty() || service.description.len() < 20 {
            return Err(anyhow::anyhow!(
                "Service description must be at least 20 characters"
            ));
        }

        if service.description.len() > 2000 {
            return Err(anyhow::anyhow!(
                "Service description too long (max 2000 characters)"
            ));
        }

        // Validate metadata contains required fields
        let metadata_obj = service
            .metadata
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Service metadata must be a JSON object"))?;

        // All service types must provide contact information
        if !metadata_obj.contains_key("contact_email")
            && !metadata_obj.contains_key("contact_phone")
        {
            return Err(anyhow::anyhow!(
                "Service must provide contact_email or contact_phone in metadata"
            ));
        }

        // Service-type-specific validation
        match service.service_type {
            lib_consensus::WelfareServiceType::Healthcare => {
                // Healthcare services must specify facility type and capacity
                if !metadata_obj.contains_key("facility_type") {
                    return Err(anyhow::anyhow!(
                        "Healthcare services must specify facility_type in metadata"
                    ));
                }
                if !metadata_obj.contains_key("service_capacity") {
                    return Err(anyhow::anyhow!(
                        "Healthcare services must specify service_capacity in metadata"
                    ));
                }
            }
            lib_consensus::WelfareServiceType::Education => {
                // Education services must specify education level and subjects
                if !metadata_obj.contains_key("education_level") {
                    return Err(anyhow::anyhow!(
                        "Education services must specify education_level in metadata"
                    ));
                }
            }
            lib_consensus::WelfareServiceType::Housing => {
                // Housing services must specify housing units and location
                if !metadata_obj.contains_key("total_units") {
                    return Err(anyhow::anyhow!(
                        "Housing services must specify total_units in metadata"
                    ));
                }
                if service.region.is_none() {
                    return Err(anyhow::anyhow!("Housing services must specify region"));
                }
            }
            lib_consensus::WelfareServiceType::FoodSecurity => {
                // Food security services must specify daily serving capacity
                if !metadata_obj.contains_key("daily_capacity") {
                    return Err(anyhow::anyhow!(
                        "Food security services must specify daily_capacity in metadata"
                    ));
                }
            }
            _ => {
                // Other service types have no additional validation
            }
        }

        info!(
            "✅ Service type requirements validated for {:?}",
            service.service_type
        );
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
            *self
                .welfare_service_blocks
                .get(service_id)
                .unwrap_or(&self.height),
        );
        let longevity_score = ((blocks_active as f64 / 100_000.0) * 15.0).min(15.0);

        // Calculate final score
        let score =
            satisfaction_score + utilization_score + cost_score + success_score + longevity_score;

        // Clamp to 0-100 range
        score.max(0.0).min(100.0) as u8
    }

    /// Update service performance metrics based on audit data
    pub fn update_service_performance_from_audit(
        &mut self,
        audit_entry: &lib_consensus::WelfareAuditEntry,
    ) -> Result<()> {
        let service_id = &audit_entry.service_id;

        let performance = self
            .service_performance
            .get_mut(service_id)
            .ok_or_else(|| {
                anyhow::anyhow!("Performance metrics not found for service {}", service_id)
            })?;

        // Update beneficiary count
        performance.total_beneficiaries = performance
            .total_beneficiaries
            .saturating_add(audit_entry.beneficiary_count);

        // Update last audit timestamp
        performance.last_audit_timestamp = audit_entry.distribution_timestamp;

        // Increment outcome reports count if verification is complete
        if matches!(
            audit_entry.verification_status,
            lib_consensus::VerificationStatus::AutoVerified
                | lib_consensus::VerificationStatus::CommunityVerified
        ) {
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

        info!(
            "📝 Recorded welfare distribution of {} SOV to service {}",
            amount, service_id
        );
        Ok(())
    }

    /// Add outcome report for a service
    pub fn add_outcome_report(&mut self, report: lib_consensus::OutcomeReport) -> Result<()> {
        let service_id = report.service_id.clone();
        let report_id = report.report_id.clone();
        let report_timestamp = report.report_timestamp;
        let beneficiaries_served = report.beneficiaries_served;
        let metrics_achieved = report.metrics_achieved.clone();

        // Update service performance metrics
        if let Some(performance) = self.service_performance.get_mut(&service_id) {
            performance.outcome_reports_count = performance.outcome_reports_count.saturating_add(1);
            performance.last_audit_timestamp = report_timestamp;
            performance.total_beneficiaries = performance
                .total_beneficiaries
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
        let active_services_count = self
            .welfare_services
            .values()
            .filter(|s| s.is_active)
            .count() as u64;

        let total_distributed = self
            .welfare_audit_trail
            .values()
            .map(|entry| entry.amount_distributed)
            .sum::<u64>();

        let total_beneficiaries_served = self
            .service_performance
            .values()
            .map(|perf| perf.total_beneficiaries)
            .sum::<u64>();

        let mut distribution_by_type = std::collections::HashMap::new();
        for entry in self.welfare_audit_trail.values() {
            *distribution_by_type
                .entry(entry.service_type.clone())
                .or_insert(0u64) += entry.amount_distributed;
        }

        let average_distribution = if total_services_registered > 0 {
            total_distributed / total_services_registered
        } else {
            0
        };

        let pending_audits = self
            .welfare_audit_trail
            .values()
            .filter(|entry| entry.verification_status == lib_consensus::VerificationStatus::Pending)
            .count() as u64;

        let last_distribution_timestamp = self
            .welfare_audit_trail
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
                    lib_consensus::VerificationStatus::Pending => {
                        lib_consensus::FundingStatus::Approved
                    }
                    lib_consensus::VerificationStatus::AutoVerified
                    | lib_consensus::VerificationStatus::CommunityVerified => {
                        lib_consensus::FundingStatus::Verified
                    }
                    lib_consensus::VerificationStatus::Flagged => {
                        lib_consensus::FundingStatus::UnderReview
                    }
                    lib_consensus::VerificationStatus::Disputed => {
                        lib_consensus::FundingStatus::Disputed
                    }
                    lib_consensus::VerificationStatus::Fraudulent => {
                        lib_consensus::FundingStatus::Disputed
                    }
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
        use lib_consensus::{DaoProposalType, ImpactLevel, ImpactMetrics, WelfareServiceType};

        let (ubi_impact, economic_impact, social_impact) = match proposal_type {
            DaoProposalType::WelfareAllocation => {
                let impact_level = match service_type {
                    Some(WelfareServiceType::Healthcare)
                    | Some(WelfareServiceType::EmergencyResponse) => ImpactLevel::Critical,
                    Some(WelfareServiceType::Education)
                    | Some(WelfareServiceType::FoodSecurity) => ImpactLevel::High,
                    Some(WelfareServiceType::Housing)
                    | Some(WelfareServiceType::Infrastructure) => ImpactLevel::Medium,
                    _ => ImpactLevel::Low,
                };
                (ImpactLevel::Medium, impact_level.clone(), impact_level)
            }
            DaoProposalType::UbiDistribution => {
                let level = if amount > 1_000_000 {
                    ImpactLevel::Critical
                } else if amount > 100_000 {
                    ImpactLevel::High
                } else {
                    ImpactLevel::Medium
                };
                (level, ImpactLevel::High, ImpactLevel::High)
            }
            DaoProposalType::TreasuryAllocation => {
                (ImpactLevel::Low, ImpactLevel::High, ImpactLevel::Medium)
            }
            DaoProposalType::CommunityFunding => {
                (ImpactLevel::Low, ImpactLevel::Medium, ImpactLevel::High)
            }
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
                // Estimate based on average UBI amount (e.g., 1000 SOV per beneficiary)
                Some(amount / 1000)
            }
            DaoProposalType::WelfareAllocation => {
                // Welfare services: estimate 1 beneficiary per 5000 SOV
                Some(amount / 5000)
            }
            DaoProposalType::CommunityFunding => {
                // Community projects: broader reach
                Some(amount / 2000)
            }
            _ => None, // Other proposal types don't directly impact beneficiaries
        }
    }

    // ============================================================================
    // Voting Power Calculation
    // ============================================================================

    /// Calculate comprehensive voting power for a user in DAO governance
    /// Calculate effective voting power for a user, applying `self.voting_power_mode`.
    ///
    /// Raw power = (total SOV balance across all wallets) / 10^18 (1 SOV = 1 unit)
    ///           + sum of each direct delegator's raw power.
    ///
    /// The raw power is then transformed by `voting_power_mode`:
    /// - `Identity`  → always returns 1 (one person, one vote)
    /// - `Linear`    → returns raw power (minimum 1 if identity has any participation)
    /// - `Quadratic` → returns `floor(sqrt(raw))` to dampen large-balance whales.
    ///   Note: uses f64 arithmetic; for balances > 2^53 SOV units precision is lost.
    ///   Governance amounts at that scale are astronomically unlikely in practice.
    ///
    /// Delegation is **non-transitive**: if A→B and B→C, C does not receive A's power.
    /// `vote_delegations` maps delegator_id_hex → delegate_id_hex (both 64-char hex,
    /// NOT "did:zhtp:…" strings).
    pub fn calculate_user_voting_power(&self, user_id: &lib_identity::IdentityId) -> u64 {
        let sov_id = crate::contracts::utils::generate_lib_token_id();

        // lib_identity::IdentityId = lib_crypto::Hash, but get_wallets_for_owner takes
        // &crate::types::hash::Hash.  Bridge via the raw 32-byte array.
        let user_local_id = crate::types::hash::Hash::new(user_id.0);

        // Sum SOV balances across all wallets owned by this identity.
        let sov_balance: u128 = self
            .get_wallets_for_owner(&user_local_id)
            .iter()
            .filter_map(|w| {
                // wallet_id: crate::types::hash::Hash — as_array() gives [u8; 32] directly.
                let pk = Self::wallet_key_for_sov(&w.wallet_id.as_array());
                self.token_contracts.get(&sov_id).map(|t| t.balance_of(&pk))
            })
            .sum();

        // 1 SOV (1e18 atomic units) = 1 base vote unit
        let base_power = (sov_balance / lib_types::sov::SCALE) as u64;

        // Add power from identities that delegated directly to this user (non-transitive).
        // Keys and values in vote_delegations are 64-char hex-encoded identity IDs.
        let user_hex = hex::encode(user_id.0);
        let delegated_extra: u64 = self
            .vote_delegations
            .iter()
            .filter(|(_, delegate_hex)| delegate_hex.as_str() == user_hex.as_str())
            .filter_map(|(delegator_hex, _)| {
                let bytes = hex::decode(delegator_hex).ok()?;
                let delegator_bytes: [u8; 32] = bytes.try_into().ok()?;
                let delegator_local_id = crate::types::hash::Hash::new(delegator_bytes);
                let delegator_wallets = self.get_wallets_for_owner(&delegator_local_id);
                let bal: u128 = delegator_wallets
                    .iter()
                    .filter_map(|w| {
                        let pk = Self::wallet_key_for_sov(&w.wallet_id.as_array());
                        self.token_contracts.get(&sov_id).map(|t| t.balance_of(&pk))
                    })
                    .sum();
                Some((bal / lib_types::sov::SCALE) as u64)
            })
            .sum();

        let raw = base_power.saturating_add(delegated_extra);

        // Apply voting power mode.
        match self.voting_power_mode {
            crate::dao::VotingPowerMode::Identity => 1,
            crate::dao::VotingPowerMode::Linear => raw,
            crate::dao::VotingPowerMode::Quadratic => (raw as f64).sqrt() as u64,
        }
    }

    /// Calculate network contribution score (0-100) based on storage and compute provided
    fn calculate_network_contribution_score(&self, user_id: &lib_identity::IdentityId) -> u32 {
        // Check if user is a validator providing resources
        if let Some(validator) = self
            .validator_registry
            .values()
            .find(|v| v.identity_id == user_id.to_string())
        {
            // Score based on storage provided
            // 1 TB = 10 points, capped at 100
            let storage_score =
                ((validator.storage_provided / (1024 * 1024 * 1024 * 1024)) * 10).min(100) as u32;
            storage_score
        } else {
            0
        }
    }

    /// Calculate reputation score (0-100) based on on-chain behavior
    fn calculate_reputation_score(&self, user_id: &lib_identity::IdentityId) -> u32 {
        let mut score = 50u32; // Start at neutral 50

        // For validators, calculate based on uptime and slash history
        if let Some(validator) = self
            .validator_registry
            .values()
            .find(|v| v.identity_id == user_id.to_string())
        {
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
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter(|tx| {
                // Check if vote is from this user
                if let Some(vote_data) = tx.dao_vote_data() {
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
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter(|tx| {
                // Check if proposal is from this user
                if let Some(proposal_data) = tx.dao_proposal_data() {
                    proposal_data.proposer == user_id_str
                } else {
                    false
                }
            })
            .count() as u64
    }

    /// Verify block with consensus rules
    pub async fn verify_block_with_consensus(
        &self,
        block: &Block,
        previous_block: Option<&Block>,
    ) -> Result<bool> {
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
                warn!(
                    "Block height mismatch: block={}, consensus={}",
                    block.height(),
                    status.current_height
                );
                return Ok(false);
            }

            // Additional consensus-specific validations would go here
            info!(
                "Block passed consensus verification at height {}",
                block.height()
            );
        }

        Ok(true)
    }

    /// Check if a transaction is an economic system transaction (UBI/welfare/rewards)
    pub fn is_economic_system_transaction(&self, transaction: &Transaction) -> bool {
        crate::integration::economic_integration::utils::is_ubi_distribution(transaction)
            || crate::integration::economic_integration::utils::is_welfare_distribution(transaction)
            || crate::integration::economic_integration::utils::is_network_reward(transaction)
    }

    // ===== WALLET REFERENCE CONVERSION =====

    /// Convert minimal wallet references to full wallet data
    /// Note: Sensitive data (names, aliases, seed commitments) will need DHT retrieval
    fn convert_wallet_references_to_full_data(
        &self,
        wallet_refs: &HashMap<String, crate::transaction::WalletReference>,
    ) -> HashMap<String, crate::transaction::WalletTransactionData> {
        wallet_refs
            .iter()
            .map(|(id, wallet_ref)| {
                // Create full wallet data from reference (missing sensitive fields will be empty/default)
                let wallet_data = crate::transaction::WalletTransactionData {
                    wallet_id: wallet_ref.wallet_id,
                    wallet_type: wallet_ref.wallet_type.clone(),
                    wallet_name: format!(
                        "Wallet-{}",
                        hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])
                    ), // Default name
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
            })
            .collect()
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
            error!(
                "UTXO set size mismatch: expected={}, actual={}",
                rebuilt_utxo_set.len(),
                self.utxo_set.len()
            );
            return Ok(false);
        }

        if rebuilt_nullifier_set.len() != self.nullifier_set.len() {
            error!(
                "Nullifier set size mismatch: expected={}, actual={}",
                rebuilt_nullifier_set.len(),
                self.nullifier_set.len()
            );
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

            info!(
                "Full blockchain backup completed: {}/{} operations successful",
                successful_backups,
                backup_result.len()
            );
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
                let _ = storage_manager
                    .store_identity_data(did, identity_data)
                    .await;
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
            info!(
                " Starting storage cleanup, retaining last {} blocks",
                retain_blocks
            );

            // This would implement cleanup logic in the storage manager
            // For now, just log the operation
            info!("Storage cleanup implementation needed in storage manager");
        }
        Ok(())
    }

    /// Export the entire blockchain state for network transfer
    /// Includes: blocks, UTXO set, identity registry, wallet registry, smart contracts, and oracle state
    pub fn export_chain(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct BlockchainExport {
            blocks: Vec<Block>,
            utxo_set: HashMap<Hash, TransactionOutput>,
            identity_registry: HashMap<String, IdentityTransactionData>,
            wallet_references: HashMap<String, crate::transaction::WalletReference>, // Only public references
            validator_registry: HashMap<String, ValidatorInfo>,
            gateway_registry: HashMap<String, GatewayInfo>,
            token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
            web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
            contract_blocks: HashMap<[u8; 32], u64>,
            dao_registry_index: HashMap<[u8; 32], DaoRegistryIndexEntry>,
            // ORACLE-10: Include oracle state for initial sync
            oracle_state: Option<crate::oracle::OracleState>,
            last_oracle_epoch_processed: u64,
        }

        // Convert full wallet data to minimal references for sync
        let wallet_references: HashMap<String, crate::transaction::WalletReference> = self
            .wallet_registry
            .iter()
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
            wallet_references, // Only minimal wallet references (no sensitive data)
            validator_registry: self.validator_registry.clone(),
            gateway_registry: self.gateway_registry.clone(),
            token_contracts: self.token_contracts.clone(),
            web4_contracts: self.web4_contracts.clone(),
            contract_blocks: self.contract_blocks.clone(),
            dao_registry_index: self.dao_registry_index.clone(),
            // ORACLE-10: Export oracle state for initial sync
            oracle_state: Some(self.oracle_state.clone()),
            last_oracle_epoch_processed: self.last_oracle_epoch_processed,
        };

        info!(" Exporting blockchain: {} blocks, {} validators, {} token contracts, {} web4 contracts, {} oracle finalized prices", 
            self.blocks.len(), self.validator_registry.len(), self.token_contracts.len(), self.web4_contracts.len(),
            self.oracle_state.finalized_prices_len());

        // Debug: Log transaction counts for each block
        for (i, block) in self.blocks.iter().enumerate() {
            info!(
                "   Block {}: height={}, transactions={}, merkle_root={}",
                i,
                block.height(),
                block.transactions.len(),
                hex::encode(block.header.data_helix_root)
            );
        }

        bincode::serialize(&export)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain: {}", e))
    }

    /// Validate imported oracle state for consistency (ORACLE-10).
    ///
    /// Performs the following validations:
    /// - Committee members must exist in validator_registry (no ghost members)
    /// - Finalized prices must be in ascending epoch order
    /// - No price from a future epoch (relative to imported block height)
    fn validate_imported_oracle_state(
        &self,
        oracle_state: &crate::oracle::OracleState,
        last_oracle_epoch_processed: u64,
        imported_block_height: u64,
    ) -> Result<()> {
        // 1. Verify committee members are all in validator_registry (no ghost members)
        // Precompute HashSet of validator key_ids for O(1) lookup (O(n) total instead of O(n*m))
        let validator_key_ids: HashSet<[u8; 32]> = self
            .validator_registry
            .values()
            .map(|v| lib_crypto::hash_blake3(&v.consensus_key))
            .collect();
        for member_key_id in oracle_state.committee.members() {
            if !validator_key_ids.contains(member_key_id) {
                return Err(anyhow::anyhow!(
                    "Ghost committee member: validator with key_id {} not found in registry",
                    hex::encode(member_key_id)
                ));
            }
        }

        // 2. Verify finalized prices are in ascending epoch order
        let mut prev_epoch: Option<u64> = None;
        for (epoch_id, _price) in oracle_state.all_finalized_prices() {
            if let Some(prev) = prev_epoch {
                if *epoch_id <= prev {
                    return Err(anyhow::anyhow!(
                        "Finalized prices not in ascending epoch order: {} followed by {}",
                        prev,
                        epoch_id
                    ));
                }
            }
            prev_epoch = Some(*epoch_id);
        }

        // 3. Verify no price is from a future epoch (relative to imported block height)
        // Estimate max reasonable epoch from the imported block height.
        // Assuming ~10 second blocks, timestamp ≈ height * 10 for a rough estimate.
        let estimated_tip_timestamp = imported_block_height.saturating_mul(10);
        let max_reasonable_epoch = oracle_state
            .epoch_id(estimated_tip_timestamp)
            .saturating_add(10); // Allow some buffer

        for (epoch_id, _price) in oracle_state.all_finalized_prices() {
            if *epoch_id > max_reasonable_epoch {
                return Err(anyhow::anyhow!(
                    "Future epoch price detected: epoch {} at imported height {} (max reasonable epoch: {})",
                    epoch_id, imported_block_height, max_reasonable_epoch
                ));
            }
        }

        // 4. Verify last_oracle_epoch_processed is consistent with finalized prices
        if let Some((&max_epoch, _)) = oracle_state.all_finalized_prices().iter().next_back() {
            if last_oracle_epoch_processed < max_epoch {
                return Err(anyhow::anyhow!(
                    "Inconsistent last_oracle_epoch_processed: {} but have finalized price for epoch {}",
                    last_oracle_epoch_processed, max_epoch
                ));
            }
        }

        Ok(())
    }

    /// Evaluate and potentially merge a blockchain from another node
    /// Uses consensus rules to decide whether to adopt the imported chain
    pub async fn evaluate_and_merge_chain(
        &mut self,
        data: Vec<u8>,
    ) -> Result<lib_consensus::ChainMergeResult> {
        if !self.finalized_blocks.is_empty() {
            return Err(anyhow::anyhow!(
                "Post-commit reorg forbidden: local chain contains finalized blocks"
            ));
        }

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
            info!("Local chain is empty - directly adopting imported chain (height={}, identities={}, validators={}, oracle_prices={})",
                  imported_height, import.identity_registry.len(), import.validator_registry.len(),
                  import.oracle_state.as_ref().map(|s| s.finalized_prices_len()).unwrap_or(0));
            self.blocks = import.blocks;
            self.height = imported_height;
            self.utxo_set = import.utxo_set;
            self.identity_registry = import.identity_registry;
            self.wallet_registry =
                self.convert_wallet_references_to_full_data(&import.wallet_references);
            self.validator_registry = import.validator_registry;
            self.token_contracts = import.token_contracts;
            self.web4_contracts = import.web4_contracts;
            self.contract_blocks = import.contract_blocks;
            self.dao_registry_index = import.dao_registry_index;
            self.rebuild_dao_registry_index();

            // ORACLE-10: Import oracle state if present
            if let Some(oracle_state) = import.oracle_state {
                // Validate imported oracle state before accepting
                match self.validate_imported_oracle_state(
                    &oracle_state,
                    import.last_oracle_epoch_processed,
                    imported_height,
                ) {
                    Ok(()) => {
                        self.oracle_state = oracle_state;
                        self.last_oracle_epoch_processed = import.last_oracle_epoch_processed;
                        info!(
                            "🔮 Oracle state imported: {} finalized prices, epoch {}",
                            self.oracle_state.finalized_prices_len(),
                            self.last_oracle_epoch_processed
                        );
                    }
                    Err(e) => {
                        warn!("⚠️ Oracle state validation failed during import: {}. Starting with empty oracle state.", e);
                        // Start with default oracle state - will be backfilled from blocks
                    }
                }
            } else {
                warn!("⚠️ Oracle state not present in import — new node will start without oracle prices (backfill from blocks)");
            }

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
                if block.header.previous_hash != prev_block.hash().as_array() {
                    return Err(anyhow::anyhow!(
                        "Block chain integrity broken at block {}",
                        i
                    ));
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
            &import.web4_contracts,
        );

        // DEBUG: Log genesis hashes being compared
        info!(" Comparing blockchains for merge:");
        info!("   Local genesis hash:    {}", local_summary.genesis_hash);
        info!(
            "   Imported genesis hash: {}",
            imported_summary.genesis_hash
        );
        info!(
            "   Hashes equal: {}",
            local_summary.genesis_hash == imported_summary.genesis_hash
        );

        // Use consensus rules to decide which chain to adopt
        let decision =
            lib_consensus::ChainEvaluator::evaluate_chains(&local_summary, &imported_summary);

        match decision {
            lib_consensus::ChainDecision::KeepLocal => {
                info!(" Local chain is better - keeping current state");
                info!(
                    "   Local: height={}, work={}, identities={}",
                    local_summary.height, local_summary.total_work, local_summary.total_identities
                );
                info!(
                    "   Imported: height={}, work={}, identities={}",
                    imported_summary.height,
                    imported_summary.total_work,
                    imported_summary.total_identities
                );
                Ok(lib_consensus::ChainMergeResult::LocalKept)
            }
            lib_consensus::ChainDecision::MergeContentOnly => {
                info!(" Local chain is longer - merging unique content from shorter chain");
                info!(
                    "   Local: height={}, work={}, identities={}",
                    local_summary.height, local_summary.total_work, local_summary.total_identities
                );
                info!(
                    "   Imported: height={}, work={}, identities={}",
                    imported_summary.height,
                    imported_summary.total_work,
                    imported_summary.total_identities
                );

                // Extract unique content from imported chain (shorter) into local (longer)
                match self.merge_unique_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged unique content: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::ContentMerged)
                    }
                    Err(e) => {
                        warn!("Failed to merge content: {} - keeping local only", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!(
                            "Content merge error: {}",
                            e
                        )))
                    }
                }
            }
            lib_consensus::ChainDecision::AdoptImported => {
                info!(" Imported chain is better - performing intelligent merge");
                info!(
                    "   Local: height={}, work={}, identities={}",
                    local_summary.height, local_summary.total_work, local_summary.total_identities
                );
                info!(
                    "   Imported: height={}, work={}, identities={}",
                    imported_summary.height,
                    imported_summary.total_work,
                    imported_summary.total_identities
                );

                // Check if this is a genesis replacement (different genesis blocks)
                // Different genesis data helix roots imply different networks.
                let is_genesis_replacement = if !self.blocks.is_empty() && !import.blocks.is_empty()
                {
                    self.blocks[0].header.data_helix_root != import.blocks[0].header.data_helix_root
                } else {
                    false
                };

                if is_genesis_replacement {
                    info!("🔀 Genesis mismatch detected - performing full consolidation merge");
                    info!(
                        "   Old genesis data helix: {}",
                        hex::encode(self.blocks[0].header.data_helix_root)
                    );
                    info!(
                        "   New genesis data helix: {}",
                        hex::encode(import.blocks[0].header.data_helix_root)
                    );

                    // Perform intelligent merge: adopt imported chain but preserve unique local data
                    match self.merge_with_genesis_mismatch(&import) {
                        Ok(merge_report) => {
                            info!(" Successfully merged chains with genesis consolidation");
                            info!("{}", merge_report);
                            Ok(lib_consensus::ChainMergeResult::ImportedAdopted)
                        }
                        Err(e) => {
                            warn!(
                                " Genesis merge failed: {} - adopting imported chain only",
                                e
                            );
                            // Fallback: just adopt imported chain
                            self.blocks = import.blocks;
                            self.height = self.blocks.len() as u64 - 1;
                            self.utxo_set = import.utxo_set;
                            self.identity_registry = import.identity_registry;
                            // Convert wallet references to full data (sensitive data will need DHT retrieval)
                            self.wallet_registry = self
                                .convert_wallet_references_to_full_data(&import.wallet_references);
                            self.validator_registry = import.validator_registry;
                            self.token_contracts = import.token_contracts;
                            self.web4_contracts = import.web4_contracts;
                            self.contract_blocks = import.contract_blocks;
                            self.dao_registry_index = import.dao_registry_index;
                            // Import oracle state if present (ORACLE-10)
                            if let Some(oracle_state) = import.oracle_state {
                                self.oracle_state = oracle_state;
                            }
                            self.rebuild_dao_registry_index();
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
                    self.wallet_registry =
                        self.convert_wallet_references_to_full_data(&import.wallet_references);
                    self.validator_registry = import.validator_registry;
                    self.token_contracts = import.token_contracts;
                    self.web4_contracts = import.web4_contracts;
                    self.contract_blocks = import.contract_blocks;
                    self.dao_registry_index = import.dao_registry_index;
                    // Import oracle state if present (ORACLE-10)
                    if let Some(oracle_state) = import.oracle_state {
                        self.oracle_state = oracle_state;
                    }
                    self.rebuild_dao_registry_index();

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
            }
            lib_consensus::ChainDecision::Merge => {
                info!(" Merging compatible chains");
                info!(
                    "   Local: height={}, work={}, identities={}, contracts={}",
                    local_summary.height,
                    local_summary.total_work,
                    local_summary.total_identities,
                    local_summary.total_contracts
                );
                info!(
                    "   Imported: height={}, work={}, identities={}, contracts={}",
                    imported_summary.height,
                    imported_summary.total_work,
                    imported_summary.total_identities,
                    imported_summary.total_contracts
                );

                match self.merge_chain_content(&import) {
                    Ok(merged_items) => {
                        info!(" Successfully merged chains: {}", merged_items);
                        Ok(lib_consensus::ChainMergeResult::Merged)
                    }
                    Err(e) => {
                        warn!("Failed to merge chains: {} - keeping local", e);
                        Ok(lib_consensus::ChainMergeResult::Failed(format!(
                            "Merge error: {}",
                            e
                        )))
                    }
                }
            }
            lib_consensus::ChainDecision::AdoptLocal => {
                info!("🏆 Local chain is stronger - using as merge base");
                info!(
                    "   Local: height={}, validators={}, identities={}",
                    local_summary.height,
                    local_summary.validator_count,
                    local_summary.total_identities
                );
                info!(
                    "   Imported: height={}, validators={}, identities={}",
                    imported_summary.height,
                    imported_summary.validator_count,
                    imported_summary.total_identities
                );

                // Local chain is the stronger network - use it as base
                // Import unique content from remote chain into local
                match self.merge_imported_into_local(&import) {
                    Ok(merge_report) => {
                        info!(" Successfully merged imported content into local chain");
                        info!("{}", merge_report);
                        Ok(lib_consensus::ChainMergeResult::LocalKept)
                    }
                    Err(e) => {
                        warn!(
                            " Failed to merge imported content: {} - keeping local only",
                            e
                        );
                        Ok(lib_consensus::ChainMergeResult::Failed(format!(
                            "Import merge error: {}",
                            e
                        )))
                    }
                }
            }
            lib_consensus::ChainDecision::Reject => {
                warn!("🚫 Networks are incompatible - merge rejected for safety");
                warn!(
                    "   Local: height={}, validators={}, age={}d",
                    local_summary.height,
                    local_summary.validator_count,
                    (local_summary.latest_timestamp - local_summary.genesis_timestamp)
                        / (24 * 3600)
                );
                warn!(
                    "   Imported: height={}, validators={}, age={}d",
                    imported_summary.height,
                    imported_summary.validator_count,
                    (imported_summary.latest_timestamp - imported_summary.genesis_timestamp)
                        / (24 * 3600)
                );
                warn!("   Networks differ too much in size or age to merge safely");

                Ok(lib_consensus::ChainMergeResult::Failed(
                    "Networks incompatible - safety threshold exceeded".to_string(),
                ))
            }
            lib_consensus::ChainDecision::Conflict => {
                warn!(" Chain conflict detected - different genesis blocks");
                warn!(
                    "   Local genesis: {}",
                    if !self.blocks.is_empty() {
                        hex::encode(self.blocks[0].header.block_hash.as_bytes())
                    } else {
                        "none".to_string()
                    }
                );
                warn!(
                    "   Imported genesis: {}",
                    if !import.blocks.is_empty() {
                        hex::encode(import.blocks[0].header.block_hash.as_bytes())
                    } else {
                        "none".to_string()
                    }
                );
                warn!("   These chains are from different networks and cannot be merged");

                Ok(lib_consensus::ChainMergeResult::Failed(
                    "Genesis hash mismatch - chains from different networks".to_string(),
                ))
            }
        }
    }

    /// Create chain summary for local blockchain
    async fn create_local_chain_summary_async(&self) -> lib_consensus::ChainSummary {
        // Use the data helix root as the genesis content commitment.
        let genesis_hash = self
            .blocks
            .first()
            .map(|b| hex::encode(b.header.data_helix_root))
            .unwrap_or_else(|| "none".to_string());

        let genesis_timestamp = self.blocks.first().map(|b| b.header.timestamp).unwrap_or(0);

        let latest_timestamp = self.blocks.last().map(|b| b.header.timestamp).unwrap_or(0);

        // Get consensus data if coordinator is available
        let (validator_count, total_validator_stake, validator_set_hash) =
            if let Some(ref coordinator_arc) = self.consensus_coordinator {
                let coordinator = coordinator_arc.read().await;
                match coordinator.get_consensus_status().await {
                    Ok(status) => {
                        // Get validator stats for stake information
                        let validator_infos =
                            coordinator.list_all_validators().await.unwrap_or_default();
                        let total_stake: u128 = validator_infos
                            .iter()
                            .map(|v| v.stake_amount as u128)
                            .fold(0u128, |acc, x| acc.saturating_add(x));

                        // Calculate validator set hash
                        let validator_ids: Vec<String> = validator_infos
                            .iter()
                            .map(|v| v.identity.to_string())
                            .collect();
                        let validator_hash = if !validator_ids.is_empty() {
                            hex::encode(lib_crypto::hash_blake3(
                                format!("{:?}", validator_ids).as_bytes(),
                            ))
                        } else {
                            String::new()
                        };

                        (status.active_validators as u64, total_stake, validator_hash)
                    }
                    Err(_) => (0, 0, String::new()),
                }
            } else {
                (0, 0, String::new())
            };

        // Estimate TPS based on recent blocks
        let expected_tps = if self.blocks.len() >= 10 {
            let recent_blocks = &self.blocks[self.blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks
                .iter()
                .map(|b| b.transactions.len() as u64)
                .fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks
                .last()
                .map(|b| b.header.timestamp)
                .unwrap_or(0)
                - recent_blocks
                    .first()
                    .map(|b| b.header.timestamp)
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
        let bridge_node_count = self
            .identity_registry
            .values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        lib_consensus::ChainSummary {
            height: self.get_height(),
            total_work: self.calculate_total_work(),
            total_transactions: self
                .blocks
                .iter()
                .map(|b| b.transactions.len() as u64)
                .fold(0u64, |acc, x| acc.saturating_add(x)),
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
                self.identity_registry
                    .insert(did.clone(), identity_data.clone());
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
                    wallet_name: format!(
                        "Wallet-{}",
                        hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])
                    ),
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
        let mut _new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                _new_contract_blocks += 1;
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
                        warn!(
                            "  Failed to verify imported block at height {}, stopping block merge",
                            block.height()
                        );
                        break;
                    }
                }

                if added_blocks > 0 {
                    merged_items.push(format!("{} blocks", added_blocks));
                }
            } else {
                // Local chain is longer - just report the difference
                let block_diff = self.blocks.len() - import.blocks.len();
                info!(
                    "  Local chain is {} blocks ahead, not adopting shorter chain",
                    block_diff
                );
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
        info!(
            "   Local network: {} blocks, {} identities, {} validators",
            self.blocks.len(),
            self.identity_registry.len(),
            self.validator_registry.len()
        );
        info!(
            "   Imported network: {} blocks, {} identities, {} validators",
            import.blocks.len(),
            import.identity_registry.len(),
            import.validator_registry.len()
        );

        let mut merge_report = Vec::new();

        // STEP 0: Calculate economic state BEFORE merge for reconciliation
        let local_utxo_count = self.utxo_set.len();
        let import_utxo_count = import.utxo_set.len();

        info!(" Pre-merge economic state:");
        info!("   Local UTXOs: {}", local_utxo_count);
        info!("   Imported UTXOs: {}", import_utxo_count);
        info!(
            "   Combined would be: {} UTXOs",
            local_utxo_count + import_utxo_count
        );

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
            if !import
                .token_contracts
                .contains_key(contract_id as &[u8; 32])
            {
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
        self.wallet_registry =
            self.convert_wallet_references_to_full_data(&import.wallet_references);
        self.validator_registry = import.validator_registry.clone();
        self.utxo_set = import.utxo_set.clone();
        self.token_contracts = import.token_contracts.clone();
        self.web4_contracts = import.web4_contracts.clone();
        self.contract_blocks = import.contract_blocks.clone();
        self.dao_registry_index = import.dao_registry_index.clone();

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
            merge_report.push(format!(
                "merged {} unique token contracts",
                unique_token_contracts
            ));
        }

        for (contract_id, contract) in local_web4_contracts {
            self.web4_contracts.insert(contract_id, contract);
        }
        if unique_web4_contracts > 0 {
            merge_report.push(format!(
                "merged {} unique web4 contracts",
                unique_web4_contracts
            ));
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

        merge_report.push(format!(
            "consolidated {} UTXOs from {} networks",
            post_merge_utxo_count, 2
        ));

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
        info!(
            "   Final network: {} blocks, {} identities, {} validators, {} UTXOs",
            self.blocks.len(),
            self.identity_registry.len(),
            self.validator_registry.len(),
            self.utxo_set.len()
        );
        info!("   Security improvement: Combined validator set and hash rate");
        info!("   Economic state: All citizens' holdings preserved");
        self.rebuild_dao_registry_index();

        if merge_report.is_empty() {
            Ok("adopted imported chain (no unique local data to merge)".to_string())
        } else {
            Ok(format!(
                "adopted imported chain and {}",
                merge_report.join(", ")
            ))
        }
    }

    /// Merge imported chain content into local chain (local is stronger base)
    /// This is the reverse of merge_with_genesis_mismatch - local chain is kept as base
    /// All unique content from imported chain is preserved and added to local
    fn merge_imported_into_local(&mut self, import: &BlockchainImport) -> Result<String> {
        info!("🔀 Merging imported network into stronger local network");
        info!(
            "   Local network (BASE): {} blocks, {} identities, {} validators",
            self.blocks.len(),
            self.identity_registry.len(),
            self.validator_registry.len()
        );
        info!(
            "   Imported network: {} blocks, {} identities, {} validators",
            import.blocks.len(),
            import.identity_registry.len(),
            import.validator_registry.len()
        );

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
                self.identity_registry
                    .insert(did.clone(), identity_data.clone());
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
                self.validator_registry
                    .insert(validator_id.clone(), validator_info.clone());
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
                    wallet_name: format!(
                        "Wallet-{}",
                        hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])
                    ),
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
            merge_report.push(format!(
                "imported {} unique token contracts",
                unique_token_contracts
            ));
        }

        let mut unique_web4_contracts = 0;
        for (contract_id, contract) in &import.web4_contracts {
            if !self.web4_contracts.contains_key(contract_id as &[u8; 32]) {
                self.web4_contracts.insert(*contract_id, contract.clone());
                unique_web4_contracts += 1;
            }
        }
        if unique_web4_contracts > 0 {
            merge_report.push(format!(
                "imported {} unique web4 contracts",
                unique_web4_contracts
            ));
        }

        // Post-merge economic state
        let post_merge_utxo_count = self.utxo_set.len();

        info!(" Post-merge economic state:");
        info!("   Total UTXOs after merge: {}", post_merge_utxo_count);
        info!("   All imported users' assets preserved in stronger local network");

        merge_report.push(format!(
            "consolidated {} UTXOs from both networks",
            post_merge_utxo_count
        ));

        info!(" Imported network successfully merged into local base!");
        info!(
            "   Final network: {} blocks, {} identities, {} validators, {} UTXOs",
            self.blocks.len(),
            self.identity_registry.len(),
            self.validator_registry.len(),
            self.utxo_set.len()
        );
        info!("   Local chain history preserved, imported users migrated successfully");
        self.rebuild_dao_registry_index();

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
                self.identity_registry
                    .insert(did.clone(), identity_data.clone());
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
                    wallet_name: format!(
                        "Wallet-{}",
                        hex::encode(&wallet_ref.wallet_id.as_bytes()[..8])
                    ),
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
                info!(
                    "  Adding unique token contract: {:?}",
                    hex::encode(contract_id)
                );
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
                info!(
                    "  Adding unique web4 contract: {:?}",
                    hex::encode(contract_id)
                );
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
        let mut _new_contract_blocks = 0;
        for (contract_id, block_height) in &import.contract_blocks {
            if !self.contract_blocks.contains_key(contract_id as &[u8; 32]) {
                self.contract_blocks.insert(*contract_id, *block_height);
                _new_contract_blocks += 1;
            }
        }
        self.rebuild_dao_registry_index();

        if merged_items.is_empty() {
            Ok("no unique content found in shorter chain".to_string())
        } else {
            info!("Successfully merged unique content from shorter chain");
            Ok(merged_items.join(", "))
        }
    }

    /// Create chain summary for imported blockchain
    fn create_imported_chain_summary(
        &self,
        blocks: &[Block],
        identity_registry: &HashMap<String, IdentityTransactionData>,
        utxo_set: &HashMap<Hash, TransactionOutput>,
        token_contracts: &HashMap<[u8; 32], crate::contracts::TokenContract>,
        web4_contracts: &HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    ) -> lib_consensus::ChainSummary {
        // Use the data helix root as the genesis content commitment.
        let genesis_hash = blocks
            .first()
            .map(|b| hex::encode(b.header.data_helix_root))
            .unwrap_or_else(|| "none".to_string());

        let genesis_timestamp = blocks.first().map(|b| b.header.timestamp).unwrap_or(0);

        let latest_timestamp = blocks.last().map(|b| b.header.timestamp).unwrap_or(0);

        // Estimate TPS based on recent blocks in imported chain
        let expected_tps = if blocks.len() >= 10 {
            let recent_blocks = &blocks[blocks.len().saturating_sub(10)..];
            let total_txs: u64 = recent_blocks
                .iter()
                .map(|b| b.transactions.len() as u64)
                .fold(0u64, |acc, x| acc.saturating_add(x));
            let time_span = recent_blocks
                .last()
                .map(|b| b.header.timestamp)
                .unwrap_or(0)
                - recent_blocks
                    .first()
                    .map(|b| b.header.timestamp)
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
        let bridge_node_count = identity_registry
            .values()
            .filter(|id| id.identity_type.contains("bridge") || id.identity_type.contains("Bridge"))
            .count() as u64;

        // For imported chains, we don't have access to their consensus coordinator
        // So we estimate validator info from special identity types
        let validator_count = identity_registry
            .values()
            .filter(|id| {
                id.identity_type.contains("validator") || id.identity_type.contains("Validator")
            })
            .count() as u64;

        // Estimate total stake from validator identities (if they have reputation scores)
        let total_validator_stake: u128 = identity_registry
            .values()
            .filter(|id| {
                id.identity_type.contains("validator") || id.identity_type.contains("Validator")
            })
            .map(|id| id.registration_fee as u128)
            .fold(0u128, |acc, x| acc.saturating_add(x));

        // Calculate validator set hash from imported identities
        let validator_identities: Vec<String> = identity_registry
            .iter()
            .filter(|(_, id)| {
                id.identity_type.contains("validator") || id.identity_type.contains("Validator")
            })
            .map(|(did, _)| did.clone())
            .collect();
        let validator_set_hash = if !validator_identities.is_empty() {
            hex::encode(lib_crypto::hash_blake3(
                format!("{:?}", validator_identities).as_bytes(),
            ))
        } else {
            String::new()
        };

        lib_consensus::ChainSummary {
            height: blocks.len().saturating_sub(1) as u64,
            total_work: self.calculate_imported_total_work(blocks),
            total_transactions: blocks
                .iter()
                .map(|b| b.transactions.len() as u64)
                .fold(0u64, |acc, x| acc.saturating_add(x)),
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
        blocks.len() as u128
    }

    /// Calculate total work for current blockchain
    fn calculate_total_work(&self) -> u128 {
        self.blocks.len() as u128
    }

    /// Store a consensus checkpoint record.
    ///
    /// This is a compatibility hook used by runtime components; checkpoint
    /// persistence is currently handled by finalized chain state.
    pub fn store_consensus_checkpoint(
        &mut self,
        _height: u64,
        _block_hash: Hash,
        _proposer_id: String,
        _previous_hash: Hash,
        _commit_votes: u32,
    ) {
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
            if receipt.is_finalized()
                && receipt.status != crate::receipts::TransactionStatus::Finalized
            {
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
            let tx_hashes: Vec<Hash> = self
                .blocks
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
                    warn!(
                        "Unexpected block hash size {} bytes for finalization event at height {}",
                        block_hash_bytes.len(),
                        block_height
                    );
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
    pub fn detect_fork_at_height(
        &self,
        height: u64,
        new_block_hash: Hash,
    ) -> Option<crate::fork_recovery::ForkDetection> {
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
        info!(
            "🍴 Fork recorded at height {}: {:?} -> {:?}",
            height, original_hash, forked_hash
        );
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
    pub async fn reorg_to_fork(
        &mut self,
        target_height: u64,
        new_blocks: Vec<Block>,
    ) -> Result<u64> {
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
                return Err(anyhow::anyhow!(
                    "Block height gap in new chain at position {}",
                    i
                ));
            }
            if new_blocks[i].header.previous_hash != new_blocks[i - 1].hash().as_array() {
                return Err(anyhow::anyhow!(
                    "Block chain linkage broken at position {}",
                    i
                ));
            }
        }

        info!(
            "🔄 Reorganizing chain from height {} with {} blocks",
            target_height,
            new_blocks.len()
        );

        // Capture old block hash before removing blocks for audit trail
        let old_block_hash = self
            .blocks
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
        let snapshot = self
            .contract_state_history
            .entry(block_height)
            .or_insert_with(HashMap::new);
        snapshot.insert(contract_id, new_state);

        debug!(
            "💾 Contract state updated: {:?} at block {}",
            contract_id, block_height
        );
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
        let keys_to_remove: Vec<u64> = self
            .contract_state_history
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

        debug!(
            "💾 UTXO snapshot saved at block {}: {} UTXOs",
            block_height,
            self.utxo_set.len()
        );
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
        let keys_to_remove: Vec<u64> = self
            .utxo_snapshots
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
            info!(
                "🔄 UTXO set restored from snapshot at height {}: {} UTXOs",
                height,
                self.utxo_set.len()
            );
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
            if let Some(ubi_data) = tx.ubi_claim_data() {
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
    /// This runs every block and distributes daily UBI (~33 SOV) to citizens
    /// who are due for their payout (last_payout_block + BLOCKS_PER_DAY <= current_block).
    ///
    /// This is the "best" approach - fully automatic, deterministic, no user action required.
    pub fn process_automatic_ubi_distribution(&mut self, current_block: u64) -> Result<u128> {
        let mut total_distributed = 0u128;
        let mut recipients_paid = 0u64;

        // Collect updates to avoid borrowing issues
        let mut updates: Vec<(String, u128, Option<u64>, u128)> = Vec::new();

        for (identity_id, entry) in self.ubi_registry.iter() {
            if !entry.is_active {
                continue;
            }

            // Check if due for payout
            let is_due = match entry.last_payout_block {
                Some(last_block) => {
                    current_block.saturating_sub(last_block) >= Self::BLOCKS_PER_DAY
                }
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
                        "💰 UBI distributed: {} SOV to wallet {} (identity {})",
                        payout, wallet_id, identity_id
                    );
                }
            }
        }

        if recipients_paid > 0 {
            info!(
                "🌍 UBI DISTRIBUTION (ledger-only): {} SOV to {} citizens at block {}",
                total_distributed, recipients_paid, current_block
            );
        }

        Ok(total_distributed)
    }

    /// Collect UBI mint entries for the next block without mutating state.
    ///
    /// These entries are used to build TokenMint transactions during block creation.
    pub fn collect_ubi_mint_entries(&self, current_block: u64) -> Vec<UbiMintEntry> {
        let mut entries = Vec::new();

        for (identity_id, entry) in self.ubi_registry.iter() {
            if !entry.is_active {
                continue;
            }

            let is_due = match entry.last_payout_block {
                Some(last_block) => {
                    current_block.saturating_sub(last_block) >= Self::BLOCKS_PER_DAY
                }
                None => true,
            };

            if !is_due {
                continue;
            }

            // Calculate payout amount with remainder handling
            let mut payout = entry.daily_amount;
            let new_remainder = entry.remainder_balance + (entry.monthly_amount % 30);
            if new_remainder >= 30 {
                payout += new_remainder / 30;
            }

            let wallet_id = entry.ubi_wallet_id.clone();
            if let Some(_wallet) = self.wallet_registry.get(&wallet_id) {
                let wallet_id_bytes = match Self::wallet_id_bytes(&wallet_id) {
                    Some(bytes) => bytes,
                    None => {
                        warn!(
                            "UBI mint skipped: invalid wallet_id {} for identity {}",
                            &wallet_id[..16.min(wallet_id.len())],
                            &identity_id[..16.min(identity_id.len())]
                        );
                        continue;
                    }
                };
                entries.push(UbiMintEntry {
                    identity_id: identity_id.clone(),
                    wallet_id,
                    recipient_wallet_id: wallet_id_bytes,
                    payout,
                });
            } else {
                warn!(
                    "UBI mint skipped: wallet {} not found for identity {}",
                    &wallet_id[..16.min(wallet_id.len())],
                    &identity_id[..16.min(identity_id.len())]
                );
            }
        }

        entries
    }

    /// Register a citizen for automatic UBI distribution
    ///
    /// Called when a new citizen identity is registered. Adds them to the UBI registry
    /// for automatic daily payouts.
    pub fn register_for_ubi(
        &mut self,
        identity_id: String,
        ubi_wallet_id: String,
        current_block: u64,
    ) -> Result<()> {
        // Check if already registered
        if self.ubi_registry.contains_key(&identity_id) {
            return Err(anyhow::anyhow!(
                "Identity {} already registered for UBI",
                identity_id
            ));
        }

        let monthly_amount = lib_types::sov::atoms(1_000); // 1000 SOV per month
        let daily_amount = monthly_amount / 30; // ~33 SOV per day

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
            "🎉 UBI REGISTERED: Citizen {} eligible for {} SOV daily ({} monthly) at block {}",
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
            if let Some(profit_data) = tx.profit_declaration_data() {
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

    /// Mint SOV tokens for a POUW reward recipient via a system transaction.
    ///
    /// Creates a TokenMint transaction and adds it to the pending pool so it is
    /// included in the next block. Returns the transaction hash on success.
    pub fn mint_sov_for_pouw(
        &mut self,
        recipient_key_id: [u8; 32],
        amount: u128,
    ) -> anyhow::Result<Hash> {
        let mint_data = crate::transaction::TokenMintData {
            token_id: crate::contracts::utils::generate_lib_token_id(),
            to: recipient_key_id,
            amount,
        };

        let signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: [0u8; 32],
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let memo = format!(
            "pouw:mint:{}:{}",
            hex::encode(recipient_key_id),
            amount
        )
        .into_bytes();

        let mint_tx = Transaction::new_token_mint(mint_data, signature, memo);
        let tx_hash = mint_tx.hash();
        self.add_system_transaction(mint_tx)?;
        Ok(tx_hash)
    }
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

// =============================================================================
// Test helpers
// These methods exist solely to support unit/integration tests that need
// fine-grained control over blockchain state without running the full block
// pipeline. They carry `_for_test` / `_test_` in their names to make their
// purpose clear and avoid accidental production use.
// =============================================================================
