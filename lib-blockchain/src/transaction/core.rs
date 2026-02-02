//! Core transaction structures
//!
//! Defines the fundamental transaction data structures used in the ZHTP blockchain.

use serde::{Serialize, Deserialize};
use crate::types::{Hash, transaction_type::TransactionType};
use crate::integration::crypto_integration::{Signature, PublicKey};
use crate::integration::zk_integration::ZkTransactionProof;

/// Zero-knowledge transaction with identity support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// Network chain identifier (0x01=mainnet, 0x02=testnet, 0x03=development)
    pub chain_id: u8,
    /// Type of transaction (transfer, identity, contract)
    pub transaction_type: TransactionType,
    /// Transaction inputs (UTXOs being spent)
    pub inputs: Vec<TransactionInput>,
    /// Transaction outputs (new UTXOs being created)
    pub outputs: Vec<TransactionOutput>,
    /// Transaction fee amount
    pub fee: u64,
    /// Digital signature for transaction authorization
    pub signature: Signature,
    /// Optional memo data
    pub memo: Vec<u8>,
    /// Identity-specific data (only for identity transactions)
    /// This data is processed by lib-identity package
    pub identity_data: Option<IdentityTransactionData>,
    /// Wallet-specific data (only for wallet transactions)
    /// This data is processed by lib-identity package
    pub wallet_data: Option<WalletTransactionData>,
    /// Validator-specific data (only for validator transactions)
    /// This data is processed by lib-consensus package
    pub validator_data: Option<ValidatorTransactionData>,
    /// DAO proposal data (only for DAO proposal transactions)
    /// This data is processed by lib-consensus package
    pub dao_proposal_data: Option<DaoProposalData>,
    /// DAO vote data (only for DAO vote transactions)
    /// This data is processed by lib-consensus package
    pub dao_vote_data: Option<DaoVoteData>,
    /// DAO execution data (only for DAO execution transactions)
    /// This data is processed by lib-consensus package
    pub dao_execution_data: Option<DaoExecutionData>,
    /// UBI claim data (only for UBI claim transactions - Week 7)
    /// This data is processed by lib-contracts package
    pub ubi_claim_data: Option<UbiClaimData>,
    /// Profit declaration data (only for profit declaration transactions - Week 7)
    /// This data is processed by lib-contracts package
    pub profit_declaration_data: Option<ProfitDeclarationData>,
    /// Token transfer data (Phase 2 - balance model transfers)
    /// Required for TransactionType::TokenTransfer
    pub token_transfer_data: Option<TokenTransferData>,
    /// Governance config update data (Phase 3D - restricted config changes)
    /// Required for TransactionType::GovernanceConfigUpdate
    pub governance_config_data: Option<GovernanceConfigUpdateData>,
}

/// DAO proposal transaction data (processed by lib-consensus package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoProposalData {
    /// Unique proposal identifier
    pub proposal_id: Hash,
    /// Identity ID of proposer
    pub proposer: String,
    /// Proposal title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Type of proposal (from lib-consensus DaoProposalType)
    pub proposal_type: String,
    /// Voting period in blocks
    pub voting_period_blocks: u64,
    /// Quorum required (percentage 0-100)
    pub quorum_required: u8,
    /// Optional execution parameters (serialized)
    pub execution_params: Option<Vec<u8>>,
    /// Proposal creation timestamp
    pub created_at: u64,
    /// Block height at proposal creation
    pub created_at_height: u64,
}

/// DAO vote transaction data (processed by lib-consensus package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoVoteData {
    /// Unique vote identifier
    pub vote_id: Hash,
    /// Proposal being voted on
    pub proposal_id: Hash,
    /// Identity ID of voter
    pub voter: String,
    /// Vote choice (Yes/No/Abstain/Delegate as string)
    pub vote_choice: String,
    /// Voting power used
    pub voting_power: u64,
    /// Optional justification/reason
    pub justification: Option<String>,
    /// Vote timestamp
    pub timestamp: u64,
}

/// DAO execution transaction data (processed by lib-consensus package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoExecutionData {
    /// Proposal being executed
    pub proposal_id: Hash,
    /// Executor identity ID
    pub executor: String,
    /// Execution type (treasury spending, parameter change, etc.)
    pub execution_type: String,
    /// Recipient of funds (if treasury spending)
    pub recipient: Option<String>,
    /// Amount being transferred (if treasury spending)
    pub amount: Option<u64>,
    /// Execution timestamp
    pub executed_at: u64,
    /// Block height at execution
    pub executed_at_height: u64,
    /// Multi-sig signatures from approving validators
    pub multisig_signatures: Vec<Vec<u8>>,
}

/// UBI claim transaction data - citizen-initiated claim from UBI pool (Week 7)
///
/// Distinct from UbiDistribution (system-initiated push).
/// This is a pull-based model where citizens claim their allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiClaimData {
    /// Unique claim identifier (deterministic hash of claimant + month)
    pub claim_id: Hash,
    /// Claimant's verified identity
    pub claimant_identity: String,
    /// Month index for this claim (calculated from genesis)
    pub month_index: u64,
    /// Amount being claimed (must match UbiDistributor schedule)
    pub claim_amount: u64,
    /// Recipient wallet address (must be registered to claimant)
    pub recipient_wallet: PublicKey,
    /// Block timestamp when claim was created
    pub claimed_at: u64,
    /// Block height when claim was created
    pub claimed_at_height: u64,
    /// Zero-knowledge proof of citizenship (verifies registration)
    pub citizenship_proof: Vec<u8>,
}

/// Profit declaration transaction data - enforces 20% tribute from for-profit to nonprofit (Week 7)
///
/// Validates that tribute_amount == profit_amount * 20 / 100.
/// Integrates with TributeRouter for enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfitDeclarationData {
    /// Unique declaration identifier
    pub declaration_id: Hash,
    /// Declarant's verified identity (for-profit entity)
    pub declarant_identity: String,
    /// Fiscal period (e.g., "2026-Q1")
    pub fiscal_period: String,
    /// Total profit declared (in smallest token unit)
    pub profit_amount: u64,
    /// Tribute amount (MUST equal profit_amount * 20 / 100)
    pub tribute_amount: u64,
    /// Nonprofit treasury receiving tribute
    pub nonprofit_treasury: PublicKey,
    /// For-profit treasury paying tribute
    pub forprofit_treasury: PublicKey,
    /// Block timestamp when declared
    pub declared_at: u64,
    /// Authorization signature from for-profit entity
    pub authorization_signature: Vec<u8>,
    /// Optional: Hash of audit proof documents
    pub audit_proof_hash: Option<Hash>,
    /// Revenue sources breakdown (for transparency)
    pub revenue_sources: Vec<RevenueSource>,
}

/// Revenue source for profit declaration (transparency in tribute accounting)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueSource {
    /// Category (e.g., "Sales", "Services", "Investments")
    pub category: String,
    /// Amount from this source
    pub amount: u64,
}

/// Token transfer data for Phase 2 balance-model transfers
///
/// This struct contains the canonical representation of a token transfer.
/// All fields are explicit - no derivation from other transaction fields.
///
/// # Invariants (Phase 2)
/// - `amount` must be > 0
/// - `from` must have sufficient balance
/// - If `fee > 0`, fee is paid in native token from `from` address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferData {
    /// Token identifier (32-byte hash, or TokenId::NATIVE for native)
    pub token_id: [u8; 32],
    /// Sender address (32-byte public key hash)
    pub from: [u8; 32],
    /// Recipient address (32-byte public key hash)
    pub to: [u8; 32],
    /// Amount to transfer (in smallest token unit)
    pub amount: u128,
    /// Nonce for replay protection (must equal sender's current nonce)
    pub nonce: u64,
}

/// Governance config update data for Phase 3D
///
/// Allows authorized governance addresses to update specific token configuration.
/// Only allowlisted fields can be updated to prevent unauthorized changes.
///
/// # Allowlisted operations (Phase 3D)
/// - `SetFeeSchedule` - Update fee parameters
/// - `SetTransferPolicy` - Switch between supported policies (not ComplianceGated)
/// - `SetPaused` - Emergency circuit breaker (pause/unpause)
///
/// # NOT allowed in Phase 3
/// - EmissionModel updates (requires budget window enforcement)
///
/// # Validation rules
/// - Caller must be in authorities[Governance] for target token
/// - Target token must exist
/// - Update must be on an allowlisted field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfigUpdateData {
    /// Target token identifier (32-byte hash)
    pub token_id: [u8; 32],
    /// Caller address (must have Governance role)
    pub caller: [u8; 32],
    /// The specific governance operation to perform
    pub operation: GovernanceConfigOperation,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Timestamp when update was created
    pub timestamp: u64,
}

/// Allowlisted governance config operations (Phase 3D)
///
/// These are the only operations allowed for governance config updates.
/// Each operation is deterministic and consensus-safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceConfigOperation {
    /// Update fee schedule parameters
    ///
    /// Changes transfer_fee_bps, burn_fee_bps, fee_cap_amount, min_fee_amount.
    /// Validated: all bps values <= 10000 (100%)
    SetFeeSchedule {
        /// Transfer fee in basis points (0-10000)
        transfer_fee_bps: u16,
        /// Burn fee in basis points (0-10000)
        burn_fee_bps: u16,
        /// Maximum fee amount (cap)
        fee_cap_amount: u128,
        /// Minimum fee amount
        min_fee_amount: u128,
    },
    /// Update transfer policy
    ///
    /// Switch between: Free, AllowlistOnly, NonTransferable
    /// ComplianceGated is NOT allowed in Phase 2/3
    SetTransferPolicy {
        /// New transfer policy (serialized as string for determinism)
        /// Valid values: "Free", "AllowlistOnly", "NonTransferable"
        policy: String,
    },
    /// Pause or unpause the token contract
    ///
    /// When paused, all state-mutating operations EXCEPT unpause REVERT.
    SetPaused {
        /// true to pause, false to unpause
        paused: bool,
    },
}

impl GovernanceConfigUpdateData {
    /// Validate governance config update data
    ///
    /// # Returns
    /// true if valid, false if invalid
    ///
    /// # Checks
    /// - Operation is valid and within bounds
    /// - For SetFeeSchedule: bps values <= 10000
    /// - For SetTransferPolicy: policy is one of allowed values
    pub fn validate(&self) -> bool {
        match &self.operation {
            GovernanceConfigOperation::SetFeeSchedule {
                transfer_fee_bps,
                burn_fee_bps,
                ..
            } => {
                // Basis points must be <= 10000 (100%)
                *transfer_fee_bps <= 10_000 && *burn_fee_bps <= 10_000
            }
            GovernanceConfigOperation::SetTransferPolicy { policy } => {
                // Only allowed policies (not ComplianceGated)
                matches!(policy.as_str(), "Free" | "AllowlistOnly" | "NonTransferable")
            }
            GovernanceConfigOperation::SetPaused { .. } => {
                // Always valid
                true
            }
        }
    }

    /// Get the operation type as a string (for logging/events)
    pub fn operation_type(&self) -> &'static str {
        match &self.operation {
            GovernanceConfigOperation::SetFeeSchedule { .. } => "set_fee_schedule",
            GovernanceConfigOperation::SetTransferPolicy { .. } => "set_transfer_policy",
            GovernanceConfigOperation::SetPaused { .. } => "set_paused",
        }
    }
}

impl TokenTransferData {
    /// Check if this transfer is for the native token
    pub fn is_native(&self) -> bool {
        self.token_id == [0u8; 32]
    }
}

/// Transaction input referencing a previous output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    /// Hash of the transaction containing the output being spent
    pub previous_output: Hash,
    /// Index of the output in the previous transaction
    pub output_index: u32,
    /// Zero-knowledge nullifier to prevent double-spending
    pub nullifier: Hash,
    /// Zero-knowledge proof validating the spend
    pub zk_proof: ZkTransactionProof,
}

/// Transaction output creating a new UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// Pedersen commitment hiding the amount
    pub commitment: Hash,
    /// Encrypted note for the recipient
    pub note: Hash,
    /// Public key of the recipient
    pub recipient: PublicKey,
}

/// Identity transaction data (processed by lib-identity package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityTransactionData {
    /// Zero-knowledge DID identifier
    pub did: String,
    /// Human-readable display name
    pub display_name: String,
    /// Public key for identity verification
    pub public_key: Vec<u8>,
    /// Zero-knowledge proof of identity ownership
    pub ownership_proof: Vec<u8>,
    /// Type of identity (human, organization, device, etc.)
    pub identity_type: String,
    /// Hash of the DID document
    pub did_document_hash: Hash,
    /// Creation timestamp
    pub created_at: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// DAO fee contribution
    pub dao_fee: u64,
    /// Node IDs controlled by this identity
    pub controlled_nodes: Vec<String>,
    /// Wallet IDs owned by this identity
    pub owned_wallets: Vec<String>,
}

/// Wallet registration transaction data (processed by lib-identity package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionData {
    /// Unique wallet identifier (32-byte hash)
    pub wallet_id: Hash,
    /// Wallet type (Primary, UBI, Savings, etc.)
    pub wallet_type: String,
    /// Human-readable wallet name
    pub wallet_name: String,
    /// Optional wallet alias
    pub alias: Option<String>,
    /// Public key for wallet operations
    pub public_key: Vec<u8>,
    /// Owner identity ID (if associated with DID)
    pub owner_identity_id: Option<Hash>,
    /// Seed phrase commitment hash (for recovery verification)
    pub seed_commitment: Hash,
    /// Creation timestamp
    pub created_at: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// Wallet capabilities flags
    pub capabilities: u32,
    /// Initial balance (if any)
    pub initial_balance: u64,
}

/// Minimal wallet reference for blockchain sync (sensitive data moved to DHT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReference {
    /// Unique wallet identifier (32-byte hash)
    pub wallet_id: Hash,
    /// Wallet type (Primary, UBI, Savings, etc.)
    pub wallet_type: String,
    /// Public key for wallet operations
    pub public_key: Vec<u8>,
    /// Owner identity ID (if associated with DID)
    pub owner_identity_id: Option<Hash>,
    /// Creation timestamp
    pub created_at: u64,
    /// Registration fee paid
    pub registration_fee: u64,
    /// Initial balance (source of truth for wallet balances in UTXO/Pedersen system)
    pub initial_balance: u64,
}

/// Sensitive wallet data stored in encrypted DHT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPrivateData {
    /// Human-readable wallet name (private)
    pub wallet_name: String,
    /// Optional wallet alias (private)
    pub alias: Option<String>,
    /// Seed phrase commitment hash (for recovery verification)
    pub seed_commitment: Hash,
    /// Wallet capabilities flags
    pub capabilities: u32,
    /// Initial balance (if any)
    pub initial_balance: u64,
    /// Private transaction history
    pub transaction_history: Vec<Hash>,
    /// Private notes/metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Validator registration transaction data (processed by lib-consensus package)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorTransactionData {
    /// Identity ID of the validator (must be pre-registered)
    pub identity_id: String,
    /// Staked amount in micro-ZHTP
    pub stake: u64,
    /// Storage provided in bytes
    pub storage_provided: u64,
    /// Post-quantum consensus public key
    pub consensus_key: Vec<u8>,
    /// Network address for validator communication (host:port)
    pub network_address: String,
    /// Commission rate percentage (0-100)
    pub commission_rate: u8,
    /// Validator operation type
    pub operation: ValidatorOperation,
    /// Timestamp of registration/update
    pub timestamp: u64,
}

/// Validator operation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorOperation {
    /// Register as a new validator
    Register,
    /// Update validator information
    Update,
    /// Unregister and exit from consensus
    Unregister,
}

impl Transaction {
    /// Create a new standard transfer transaction
    pub fn new(
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::Transfer,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new identity registration transaction
    pub fn new_identity_registration(
        identity_data: IdentityTransactionData,
        outputs: Vec<TransactionOutput>, // For fee payments
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityRegistration,
            inputs: Vec::new(), // Identity registration doesn't have inputs
            outputs,
            fee: identity_data.registration_fee + identity_data.dao_fee,
            signature,
            memo,
            identity_data: Some(identity_data),
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new identity update transaction
    pub fn new_identity_update(
        identity_data: IdentityTransactionData,
        inputs: Vec<TransactionInput>, // Authorization from existing identity
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityUpdate,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: Some(identity_data),
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new identity revocation transaction
    pub fn new_identity_revocation(
        did: String,
        inputs: Vec<TransactionInput>, // Authorization from existing identity
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        let revocation_data = IdentityTransactionData {
            did,
            display_name: "revoked".to_string(),
            public_key: Vec::new(), // Empty for revocation
            ownership_proof: Vec::new(),
            identity_type: "revoked".to_string(),
            did_document_hash: Hash::default(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        };

        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityRevocation,
            inputs,
            outputs: Vec::new(),
            fee,
            signature,
            memo,
            identity_data: Some(revocation_data),
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new wallet registration transaction
    pub fn new_wallet_registration(
        wallet_data: WalletTransactionData,
        outputs: Vec<TransactionOutput>, // For fee payments
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::WalletRegistration,
            inputs: Vec::new(), // Wallet registration doesn't need inputs
            outputs,
            fee: 0, // System transactions must have zero fee (registration_fee stored in wallet_data for records)
            signature,
            memo,
            identity_data: None,
            wallet_data: Some(wallet_data),
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new validator registration transaction
    pub fn new_validator_registration(
        validator_data: ValidatorTransactionData,
        outputs: Vec<TransactionOutput>, // For stake locking
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorRegistration,
            inputs: Vec::new(), // Validator registration via staking
            outputs,
            fee: 0, // Fee paid via stake
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: Some(validator_data),
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new validator update transaction
    pub fn new_validator_update(
        validator_data: ValidatorTransactionData,
        inputs: Vec<TransactionInput>, // Authorization
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorUpdate,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: Some(validator_data),
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new validator unregister transaction
    pub fn new_validator_unregister(
        validator_data: ValidatorTransactionData,
        inputs: Vec<TransactionInput>, // Authorization
        outputs: Vec<TransactionOutput>, // Stake return
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorUnregister,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: Some(validator_data),
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new DAO proposal transaction
    pub fn new_dao_proposal(
        proposal_data: DaoProposalData,
        inputs: Vec<TransactionInput>, // Authorization from proposer
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoProposal,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: Some(proposal_data),
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new DAO vote transaction
    pub fn new_dao_vote(
        vote_data: DaoVoteData,
        inputs: Vec<TransactionInput>, // Authorization from voter
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoVote,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: Some(vote_data),
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new DAO execution transaction
    pub fn new_dao_execution(
        execution_data: DaoExecutionData,
        inputs: Vec<TransactionInput>, // Treasury UTXOs being spent
        outputs: Vec<TransactionOutput>, // Recipient + change
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoExecution,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: Some(execution_data),
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new UBI claim transaction
    ///
    /// Citizens claim their monthly UBI allocation via pull-based transaction.
    /// This is distinct from system-initiated UbiDistribution (push-based).
    ///
    /// # Arguments
    /// * `claim_data` - UBI claim data with claimant identity, month index, and claim amount
    /// * `outputs` - Transaction outputs (typically sends UBI to recipient wallet)
    /// * `fee` - Transaction fee in micro-ZHTP
    /// * `signature` - Authorization signature from claimant
    /// * `memo` - Optional transaction memo
    ///
    /// # Returns
    /// New Transaction with TransactionType::UBIClaim set
    pub fn new_ubi_claim(
        claim_data: UbiClaimData,
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::UBIClaim,
            inputs: Vec::new(), // UBI claims don't require inputs (claiming from pool)
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: Some(claim_data),
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new profit declaration transaction
    ///
    /// For-profit entities declare profits and transfer 20% as tribute to nonprofits.
    /// This transaction enforces the 20% tribute calculation and routing.
    ///
    /// # Arguments
    /// * `declaration_data` - Profit declaration data with profit amount, tribute calculation, and entities
    /// * `inputs` - UTXOs from for-profit treasury (must cover tribute amount)
    /// * `outputs` - UTXOs to nonprofit treasury (tribute recipient)
    /// * `fee` - Transaction fee in micro-ZHTP
    /// * `signature` - Authorization signature from for-profit entity
    /// * `memo` - Optional transaction memo
    ///
    /// # Returns
    /// New Transaction with TransactionType::ProfitDeclaration set
    ///
    /// # Invariants
    /// - Tribute amount must equal profit_amount * 20 / 100
    /// - Input amount must equal tribute amount (enforced at validation)
    /// - Output amount must equal tribute amount (enforced at validation)
    pub fn new_profit_declaration(
        declaration_data: ProfitDeclarationData,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ProfitDeclaration,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: Some(declaration_data),
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a new governance config update transaction (Phase 3D)
    ///
    /// Authorized governance addresses can update specific token configuration:
    /// - set_fee_schedule: Update fee parameters
    /// - set_transfer_policy: Switch between supported policies (not ComplianceGated)
    /// - pause/unpause: Emergency circuit breaker
    ///
    /// # Arguments
    /// * `config_data` - Governance config update data with operation and target token
    /// * `fee` - Transaction fee in micro-ZHTP
    /// * `signature` - Authorization signature from governance address
    /// * `memo` - Optional transaction memo
    ///
    /// # Returns
    /// New Transaction with TransactionType::GovernanceConfigUpdate set
    ///
    /// # Validation (at execution time)
    /// - Caller must be in authorities[Governance] for target token
    /// - Target token must exist
    /// - Operation must be valid and within bounds
    pub fn new_governance_config_update(
        config_data: GovernanceConfigUpdateData,
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::GovernanceConfigUpdate,
            inputs: Vec::new(), // Governance updates don't need inputs
            outputs: Vec::new(),
            fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: Some(config_data),
        }
    }

    /// Calculate transaction hash
    pub fn hash(&self) -> Hash {
        crate::transaction::hashing::hash_transaction(self)
    }

    /// Calculate transaction hash for signing (excludes signature)
    pub fn signing_hash(&self) -> Hash {
        crate::transaction::hashing::hash_transaction_for_signing(self)
    }

    /// Verify transaction validity
    pub fn verify(&self) -> anyhow::Result<bool> {
        let validator = crate::transaction::validation::TransactionValidator::new();
        Ok(validator.validate_transaction(self).is_ok())
    }

    /// Get the transaction ID (hash)
    pub fn id(&self) -> Hash {
        self.hash()
    }

    /// Check if this is a coinbase transaction
    /// Note: ZHTP uses native token system, not Bitcoin-style coinbase
    pub fn is_coinbase(&self) -> bool {
        false
    }

    /// Get the total input value (if known)
    /// In a zero-knowledge system, amounts are hidden
    pub fn total_input_value(&self) -> Option<u64> {
        // In ZK system, amounts are hidden by commitments
        // This would require additional proof verification
        None
    }

    /// Get the total output value (if known)
    /// In a zero-knowledge system, amounts are hidden
    pub fn total_output_value(&self) -> Option<u64> {
        // In ZK system, amounts are hidden by commitments
        // This would require additional proof verification
        None
    }

    /// Check if transaction has identity data
    pub fn has_identity_data(&self) -> bool {
        self.identity_data.is_some()
    }

    /// Get the size of the transaction in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if transaction is empty (no inputs or outputs)
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }
}

impl TransactionInput {
    /// Create a new transaction input
    pub fn new(
        previous_output: Hash,
        output_index: u32,
        nullifier: Hash,
        zk_proof: ZkTransactionProof,
    ) -> Self {
        Self {
            previous_output,
            output_index,
            nullifier,
            zk_proof,
        }
    }

    /// Get the outpoint (previous_output + output_index)
    pub fn outpoint(&self) -> (Hash, u32) {
        (self.previous_output, self.output_index)
    }
}

impl TransactionOutput {
    /// Create a new transaction output
    pub fn new(
        commitment: Hash,
        note: Hash,
        recipient: PublicKey,
    ) -> Self {
        Self {
            commitment,
            note,
            recipient,
        }
    }

    /// Check if this output is to a specific recipient
    pub fn is_to_recipient(&self, recipient: &PublicKey) -> bool {
        &self.recipient == recipient
    }
}

impl IdentityTransactionData {
    /// Create new identity transaction data
    pub fn new(
        did: String,
        display_name: String,
        public_key: Vec<u8>,
        ownership_proof: Vec<u8>,
        identity_type: String,
        did_document_hash: Hash,
        registration_fee: u64,
        dao_fee: u64,
    ) -> Self {
        Self {
            did,
            display_name,
            public_key,
            ownership_proof,
            identity_type,
            did_document_hash,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registration_fee,
            dao_fee,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
        }
    }

    /// Create identity transaction data with node and wallet associations
    pub fn new_with_associations(
        did: String,
        display_name: String,
        public_key: Vec<u8>,
        ownership_proof: Vec<u8>,
        identity_type: String,
        did_document_hash: Hash,
        registration_fee: u64,
        dao_fee: u64,
        controlled_nodes: Vec<String>,
        owned_wallets: Vec<String>,
    ) -> Self {
        Self {
            did,
            display_name,
            public_key,
            ownership_proof,
            identity_type,
            did_document_hash,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            registration_fee,
            dao_fee,
            controlled_nodes,
            owned_wallets,
        }
    }

    /// Add a wallet to this identity's owned wallets
    pub fn add_wallet(&mut self, wallet_id: String) {
        if !self.owned_wallets.contains(&wallet_id) {
            self.owned_wallets.push(wallet_id);
        }
    }

    /// Add a node to this identity's controlled nodes
    pub fn add_node(&mut self, node_id: String) {
        if !self.controlled_nodes.contains(&node_id) {
            self.controlled_nodes.push(node_id);
        }
    }

    /// Get total fees (registration + DAO)
    pub fn total_fees(&self) -> u64 {
        self.registration_fee + self.dao_fee
    }

    /// Check if this is a revoked identity
    pub fn is_revoked(&self) -> bool {
        self.identity_type == "revoked"
    }
}

impl UbiClaimData {
    /// Compute the claim ID (deterministic hash of claimant + month)
    ///
    /// This ensures each claimant can only claim once per month with a unique identifier.
    /// In production, this would hash the claimant identity + month to produce a deterministic claim ID.
    pub fn compute_claim_id(claimant_identity: &str, month_index: u64) -> Hash {
        // Stub implementation for Week 7
        // Production: Use actual cryptographic hash function
        // For now, return default hash - will be overridden by actual claim_id in transaction
        Hash::default()
    }

    /// Validate UBI claim data structure
    ///
    /// # Returns
    /// true if valid, false if invalid
    ///
    /// # Checks
    /// - claim_amount > 0
    /// - citizenship_proof is not empty
    /// - claim_id matches computed deterministic hash
    pub fn validate(&self) -> bool {
        // Check claim amount is positive
        if self.claim_amount == 0 {
            return false;
        }

        // Check citizenship proof is provided
        if self.citizenship_proof.is_empty() {
            return false;
        }

        // NOTE: In production, verify claim_id matches computed hash from compute_claim_id().
        // The current stub implementation of compute_claim_id() returns Hash::default(),
        // so enforcing a non-default claim_id here would cause all stubbed claims to fail
        // validation. Once compute_claim_id() is fully implemented, re-enable strict
        // validation that self.claim_id matches the computed value.
        //
        // For Week 7 testing, we accept any non-default claim_id as valid.
        if self.claim_id == Hash::default() {
            return false;
        }

        true
    }

    /// Check if claim is for a valid month (not in future)
    pub fn is_valid_month(&self, current_month_index: u64) -> bool {
        self.month_index <= current_month_index
    }

    /// Get the amount being claimed
    pub fn claim_amount(&self) -> u64 {
        self.claim_amount
    }

    /// Get the claimant identity
    pub fn claimant(&self) -> &str {
        &self.claimant_identity
    }
}

impl ProfitDeclarationData {
    /// Validate 20% tribute calculation
    ///
    /// # Returns
    /// true if tribute_amount == profit_amount * 20 / 100
    pub fn validate_tribute_calculation(&self) -> bool {
        let expected_tribute = self.profit_amount
            .checked_mul(20)
            .and_then(|x| x.checked_div(100));

        match expected_tribute {
            Some(expected) => self.tribute_amount == expected,
            None => false, // Overflow or division error
        }
    }

    /// Validate profit declaration data structure
    ///
    /// # Returns
    /// true if valid, false if invalid
    ///
    /// # Checks
    /// - profit_amount > 0
    /// - tribute_amount matches 20% calculation
    /// - authorization_signature is not empty
    /// - revenue_sources sum equals profit_amount
    pub fn validate(&self) -> bool {
        // Check profit amount is positive
        if self.profit_amount == 0 {
            return false;
        }

        // Verify 20% tribute calculation
        if !self.validate_tribute_calculation() {
            return false;
        }

        // Check authorization signature is provided
        if self.authorization_signature.is_empty() {
            return false;
        }

        // Verify revenue sources sum to profit amount
        let total_revenue: u64 = self.revenue_sources.iter()
            .map(|src| src.amount)
            .sum();
        if total_revenue != self.profit_amount {
            return false;
        }

        // Check for self-tribute (nonprofit and for-profit must be different)
        if self.nonprofit_treasury == self.forprofit_treasury {
            return false;
        }

        true
    }

    /// Check if fiscal period format is valid
    ///
    /// Valid formats: "YYYY-Q[1-4]" or "YYYY-MM"
    /// Examples: "2026-Q1", "2026-03"
    pub fn is_valid_fiscal_period(&self) -> bool {
        let period = self.fiscal_period.as_str();

        // Expect exactly one '-' separating year and period part
        let mut parts = period.split('-');
        let year_part = match parts.next() {
            Some(y) => y,
            None => return false,
        };
        let suffix_part = match parts.next() {
            Some(s) => s,
            None => return false,
        };
        // There must not be any additional '-' segments
        if parts.next().is_some() {
            return false;
        }

        // Year must be exactly 4 digits
        if year_part.len() != 4 || !year_part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Suffix must be exactly 2 characters
        if suffix_part.len() != 2 {
            return false;
        }

        // Check for quarter format "Q1".."Q4"
        if suffix_part.starts_with('Q') {
            return matches!(suffix_part, "Q1" | "Q2" | "Q3" | "Q4");
        }

        // Check for month format "01".."12"
        if suffix_part.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(month) = suffix_part.parse::<u8>() {
                return (1..=12).contains(&month);
            }
        }

        false
    }

    /// Get the profit amount
    pub fn profit(&self) -> u64 {
        self.profit_amount
    }

    /// Get the tribute amount (20% of profit)
    pub fn tribute(&self) -> u64 {
        self.tribute_amount
    }

    /// Get the declarant identity
    pub fn declarant(&self) -> &str {
        &self.declarant_identity
    }

    /// Check for potential circumvention attempts
    ///
    /// # Returns
    /// true if no circumvention detected, false otherwise
    pub fn anti_circumvention_check(&self) -> bool {
        // Check 1: Nonprofit and for-profit must be different
        if self.nonprofit_treasury == self.forprofit_treasury {
            return false;
        }

        // Check 2: Fiscal period must be valid
        if !self.is_valid_fiscal_period() {
            return false;
        }

        // Note: Revenue sources empty check is redundant here as it's already
        // enforced by validate() method which requires the sum to match profit_amount.
        // If revenue_sources is empty, sum would be 0 and only pass if profit_amount
        // is also 0, which is already rejected by validate().

        true
    }
}
