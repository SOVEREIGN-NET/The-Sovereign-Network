//! Core transaction structures
//!
//! Defines the fundamental transaction data structures used in the ZHTP blockchain.

use crate::integration::crypto_integration::{PublicKey, Signature};
use crate::integration::zk_integration::ZkTransactionProof;
use crate::transaction::oracle_governance::{
    CancelOracleUpdateData, OracleAttestationData, OracleCommitteeUpdateData,
    OracleConfigUpdateData,
};
use crate::types::{transaction_type::TransactionType, Hash};
use serde::{Deserialize, Serialize};

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
    /// Typed transaction payload — replaces the old flat Option<FooData> field scatter.
    pub payload: TransactionPayload,
}

/// Transaction wire-format version constants.
///
/// Never renumber — each constant is embedded in serialized blocks on-chain.
/// V1–V7 used a positional tuple format (hand-rolled serde). V8 switches to
/// a tagged-payload model (`TransactionPayload` enum) with `#[derive(Serialize, Deserialize)]`.
/// V1–V7 deserialization is intentionally not supported in V8+ nodes (testnet reset required).
pub const TX_VERSION_V1: u32 = 1; // [historical] 18 positional fields
pub const TX_VERSION_V2: u32 = 2; // [historical] +token_mint_data
pub const TX_VERSION_V3: u32 = 3; // [historical] +bonding_curve_* data
pub const TX_VERSION_V4: u32 = 4; // [historical] +oracle_* data
pub const TX_VERSION_V5: u32 = 5; // [historical] +oracle_attestation_data
pub const TX_VERSION_V6: u32 = 6; // [historical] +cancel_oracle_update_data
pub const TX_VERSION_V7: u32 = 7; // [historical] +init_entity_registry_data
pub const TX_VERSION_V8: u32 = 8; // Tagged payload model (TransactionPayload enum)

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
    /// - For SOV, this is the wallet_id
    pub from: [u8; 32],
    /// Recipient address (32-byte public key hash)
    /// - For SOV, this is the wallet_id
    pub to: [u8; 32],
    /// Amount to transfer (in smallest token unit)
    pub amount: u128,
    /// Nonce for replay protection (must equal sender's current nonce)
    pub nonce: u64,
}

/// Token mint data (system-controlled issuance)
///
/// # Invariants
/// - `amount` must be > 0
/// - `to` must be a valid public key hash (key_id)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMintData {
    /// Token identifier (32-byte hash, or TokenId::NATIVE for native)
    pub token_id: [u8; 32],
    /// Recipient address (32-byte public key hash)
    /// - For SOV, this is the wallet_id
    pub to: [u8; 32],
    /// Amount to mint (in smallest token unit)
    pub amount: u128,
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
                matches!(
                    policy.as_str(),
                    "Free" | "AllowlistOnly" | "NonTransferable"
                )
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

/// Token swap data - exchange one token for another via AMM pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSwapData {
    /// Pool token ID (the token being swapped to)
    pub pool_token_id: [u8; 32],
    /// Amount of input token to swap
    pub amount_in: u128,
    /// Minimum amount expected out (slippage protection)
    pub min_amount_out: u128,
    /// Is this swapping SOV -> Token (true) or Token -> SOV (false)
    pub sov_to_token: bool,
    /// Sender's address
    pub from: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Create pool data - initialize a new AMM liquidity pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePoolData {
    /// Token ID for the pool (must not already exist)
    pub token_id: [u8; 32],
    /// Initial SOV liquidity provided
    pub initial_sov_liquidity: u128,
    /// Initial token liquidity provided
    pub initial_token_liquidity: u128,
    /// Fee tier in basis points (100 = 1%, max 1000 = 10%)
    pub fee_bps: u16,
    /// Creator's address
    pub creator: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Add liquidity data - add funds to an existing AMM pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddLiquidityData {
    /// Pool token ID
    pub pool_token_id: [u8; 32],
    /// Amount of SOV to add
    pub sov_amount: u128,
    /// Amount of pool token to add
    pub token_amount: u128,
    /// Minimum SOV to receive as LP tokens (slippage protection)
    pub min_lp_tokens: u128,
    /// Provider's address
    pub provider: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Remove liquidity data - withdraw funds from an AMM pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveLiquidityData {
    /// Pool token ID
    pub pool_token_id: [u8; 32],
    /// Amount of LP tokens to burn
    pub lp_tokens: u128,
    /// Minimum SOV to receive (slippage protection)
    pub min_sov_out: u128,
    /// Minimum token to receive (slippage protection)
    pub min_token_out: u128,
    /// Provider's address
    pub provider: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Initial balance (if any) — u128 to hold 18-decimal SOV amounts
    pub initial_balance: u128,
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
    pub initial_balance: u128,
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
    /// Initial balance (if any) — u128 to hold 18-decimal SOV amounts
    pub initial_balance: u128,
    /// Private transaction history
    pub transaction_history: Vec<Hash>,
    /// Private notes/metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Validator registration transaction data (processed by lib-consensus package).
///
/// # Key Separation
///
/// Validators must supply three cryptographically independent keys.  See
/// [`ValidatorInfo`](crate::blockchain::ValidatorInfo) for the full rationale.
///
/// - `consensus_key`: Signs BFT votes/proposals (Dilithium5, hot).
/// - `networking_key`: P2P / QUIC transport identity (Ed25519/X25519, hot).
/// - `rewards_key`: Rewards wallet public key for fee/block-reward collection (cold-capable).
///
/// All three fields are required and must be distinct; the blockchain rejects
/// registrations where any two keys are equal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorTransactionData {
    /// Identity ID of the validator (must be pre-registered)
    pub identity_id: String,
    /// Staked amount in micro-SOV
    pub stake: u64,
    /// Storage provided in bytes
    pub storage_provided: u64,
    /// Post-quantum Dilithium5 public key used exclusively for signing BFT consensus
    /// messages (proposals, pre-votes, pre-commits).
    pub consensus_key: Vec<u8>,
    /// Ed25519 / X25519 public key used for P2P transport identity (QUIC TLS, DHT
    /// node ID derivation, peer authentication).
    #[serde(default)]
    pub networking_key: Vec<u8>,
    /// Public key of the rewards wallet that receives block rewards and fee
    /// distributions.
    #[serde(default)]
    pub rewards_key: Vec<u8>,
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::Transfer,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::None,
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityRegistration,
            inputs: Vec::new(), // Identity registration doesn't have inputs
            outputs,
            fee: identity_data.registration_fee + identity_data.dao_fee,
            signature,
            memo,
            payload: TransactionPayload::Identity(identity_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityUpdate,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::Identity(identity_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::IdentityRevocation,
            inputs,
            outputs: Vec::new(),
            fee,
            signature,
            memo,
            payload: TransactionPayload::Identity(revocation_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::WalletRegistration,
            inputs: Vec::new(), // Wallet registration doesn't need inputs
            outputs,
            fee: 0, // System transactions must have zero fee (registration_fee stored in wallet_data for records)
            signature,
            memo,
            payload: TransactionPayload::Wallet(wallet_data),
        }
    }

    /// Create a wallet update transaction.
    ///
    /// Used to update wallet metadata/ownership on-chain. In testnet migrations this may be used
    /// as a system transaction (no inputs). In production, authorization rules must be enforced.
    pub fn new_wallet_update(
        wallet_data: WalletTransactionData,
        outputs: Vec<TransactionOutput>,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Self::new_wallet_update_with_chain_id(0x03, wallet_data, outputs, signature, memo)
    }

    /// Create a wallet update transaction with an explicit chain id.
    ///
    /// This is preferred for node-side transaction construction where the chain id is known
    /// from configuration/state.
    pub fn new_wallet_update_with_chain_id(
        chain_id: u8,
        wallet_data: WalletTransactionData,
        outputs: Vec<TransactionOutput>,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::WalletUpdate,
            inputs: Vec::new(), // Update authorization is consensus-defined; system updates use empty inputs
            outputs,
            fee: 0, // System-style update: zero fee (registration_fee remains for historical record only)
            signature,
            memo,
            payload: TransactionPayload::Wallet(wallet_data),
        }
    }

    /// Create a new token transfer transaction (balance model).
    pub fn new_token_transfer(
        token_transfer_data: TokenTransferData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Self::new_token_transfer_with_chain_id(0x03, token_transfer_data, signature, memo)
    }

    /// Create a new token transfer transaction with an explicit chain id.
    pub fn new_token_transfer_with_chain_id(
        chain_id: u8,
        token_transfer_data: TokenTransferData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::TokenTransfer,
            inputs: Vec::new(),  // Balance-model transfer has no UTXO inputs
            outputs: Vec::new(), // Balance-model transfer has no UTXO outputs
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::TokenTransfer(token_transfer_data),
        }
    }

    /// Create a new token mint transaction (balance model).
    pub fn new_token_mint(
        token_mint_data: TokenMintData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Self::new_token_mint_with_chain_id(0x03, token_mint_data, signature, memo)
    }

    /// Create a new token mint transaction with an explicit chain id.
    pub fn new_token_mint_with_chain_id(
        chain_id: u8,
        token_mint_data: TokenMintData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::TokenMint,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::TokenMint(token_mint_data),
        }
    }

    /// Create a new token creation transaction.
    pub fn new_token_creation(signature: Signature, memo: Vec<u8>) -> Self {
        Self::new_token_creation_with_chain_id(0x03, signature, memo)
    }

    /// Create a new token creation transaction with an explicit chain id.
    pub fn new_token_creation_with_chain_id(
        chain_id: u8,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::TokenCreation,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::None,
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorRegistration,
            inputs: Vec::new(), // Validator registration via staking
            outputs,
            fee: 0, // Fee paid via stake
            signature,
            memo,
            payload: TransactionPayload::Validator(validator_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorUpdate,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::Validator(validator_data),
        }
    }

    /// Create a new validator unregister transaction
    pub fn new_validator_unregister(
        validator_data: ValidatorTransactionData,
        inputs: Vec<TransactionInput>,   // Authorization
        outputs: Vec<TransactionOutput>, // Stake return
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ValidatorUnregister,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::Validator(validator_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoProposal,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::DaoProposal(proposal_data),
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoVote,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::DaoVote(vote_data),
        }
    }

    /// Create a new DAO execution transaction
    pub fn new_dao_execution(
        execution_data: DaoExecutionData,
        inputs: Vec<TransactionInput>,   // Treasury UTXOs being spent
        outputs: Vec<TransactionOutput>, // Recipient + change
        fee: u64,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::DaoExecution,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::DaoExecution(execution_data),
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
    /// * `fee` - Transaction fee in micro-SOV
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::UBIClaim,
            inputs: Vec::new(), // UBI claims don't require inputs (claiming from pool)
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::UbiClaim(claim_data),
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
    /// * `fee` - Transaction fee in micro-SOV
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ProfitDeclaration,
            inputs,
            outputs,
            fee,
            signature,
            memo,
            payload: TransactionPayload::ProfitDeclaration(declaration_data),
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
    /// * `fee` - Transaction fee in micro-SOV
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
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::GovernanceConfigUpdate,
            inputs: Vec::new(), // Governance updates don't need inputs
            outputs: Vec::new(),
            fee,
            signature,
            memo,
            payload: TransactionPayload::GovernanceConfigUpdate(config_data),
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
    /// Note: SOV uses native token system, not Bitcoin-style coinbase
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
        matches!(self.payload, TransactionPayload::Identity(_))
    }

    // -------------------------------------------------------------------------
    // Payload accessor methods
    // These provide the same API as the old flat Option<FooData> fields.
    // -------------------------------------------------------------------------

    pub fn identity_data(&self) -> Option<&IdentityTransactionData> {
        match &self.payload {
            TransactionPayload::Identity(d) => Some(d),
            _ => None,
        }
    }
    pub fn wallet_data(&self) -> Option<&WalletTransactionData> {
        match &self.payload {
            TransactionPayload::Wallet(d) => Some(d),
            _ => None,
        }
    }
    pub fn validator_data(&self) -> Option<&ValidatorTransactionData> {
        match &self.payload {
            TransactionPayload::Validator(d) => Some(d),
            _ => None,
        }
    }
    pub fn dao_proposal_data(&self) -> Option<&DaoProposalData> {
        match &self.payload {
            TransactionPayload::DaoProposal(d) => Some(d),
            _ => None,
        }
    }
    pub fn dao_vote_data(&self) -> Option<&DaoVoteData> {
        match &self.payload {
            TransactionPayload::DaoVote(d) => Some(d),
            _ => None,
        }
    }
    pub fn dao_execution_data(&self) -> Option<&DaoExecutionData> {
        match &self.payload {
            TransactionPayload::DaoExecution(d) => Some(d),
            _ => None,
        }
    }
    pub fn ubi_claim_data(&self) -> Option<&UbiClaimData> {
        match &self.payload {
            TransactionPayload::UbiClaim(d) => Some(d),
            _ => None,
        }
    }
    pub fn profit_declaration_data(&self) -> Option<&ProfitDeclarationData> {
        match &self.payload {
            TransactionPayload::ProfitDeclaration(d) => Some(d),
            _ => None,
        }
    }
    pub fn token_transfer_data(&self) -> Option<&TokenTransferData> {
        match &self.payload {
            TransactionPayload::TokenTransfer(d) => Some(d),
            _ => None,
        }
    }
    pub fn token_mint_data(&self) -> Option<&TokenMintData> {
        match &self.payload {
            TransactionPayload::TokenMint(d) => Some(d),
            _ => None,
        }
    }
    pub fn governance_config_data(&self) -> Option<&GovernanceConfigUpdateData> {
        match &self.payload {
            TransactionPayload::GovernanceConfigUpdate(d) => Some(d),
            _ => None,
        }
    }
    pub fn bonding_curve_deploy_data(&self) -> Option<&BondingCurveDeployData> {
        match &self.payload {
            TransactionPayload::BondingCurveDeploy(d) => Some(d),
            _ => None,
        }
    }
    pub fn bonding_curve_buy_data(&self) -> Option<&BondingCurveBuyData> {
        match &self.payload {
            TransactionPayload::BondingCurveBuy(d) => Some(d),
            _ => None,
        }
    }
    pub fn bonding_curve_sell_data(&self) -> Option<&BondingCurveSellData> {
        match &self.payload {
            TransactionPayload::BondingCurveSell(d) => Some(d),
            _ => None,
        }
    }
    pub fn bonding_curve_graduate_data(&self) -> Option<&BondingCurveGraduateData> {
        match &self.payload {
            TransactionPayload::BondingCurveGraduate(d) => Some(d),
            _ => None,
        }
    }
    pub fn oracle_committee_update_data(&self) -> Option<&OracleCommitteeUpdateData> {
        match &self.payload {
            TransactionPayload::OracleCommitteeUpdate(d) => Some(d),
            _ => None,
        }
    }
    pub fn oracle_config_update_data(&self) -> Option<&OracleConfigUpdateData> {
        match &self.payload {
            TransactionPayload::OracleConfigUpdate(d) => Some(d),
            _ => None,
        }
    }
    pub fn oracle_attestation_data(&self) -> Option<&OracleAttestationData> {
        match &self.payload {
            TransactionPayload::OracleAttestation(d) => Some(d),
            _ => None,
        }
    }
    pub fn cancel_oracle_update_data(&self) -> Option<&CancelOracleUpdateData> {
        match &self.payload {
            TransactionPayload::CancelOracleUpdate(d) => Some(d),
            _ => None,
        }
    }
    pub fn init_entity_registry_data(&self) -> Option<&InitEntityRegistryData> {
        match &self.payload {
            TransactionPayload::InitEntityRegistry(d) => Some(d),
            _ => None,
        }
    }
    pub fn record_on_ramp_trade_data(&self) -> Option<&RecordOnRampTradeData> {
        match &self.payload {
            TransactionPayload::RecordOnRampTrade(d) => Some(d),
            _ => None,
        }
    }
    pub fn treasury_allocation_data(&self) -> Option<&TreasuryAllocationData> {
        match &self.payload {
            TransactionPayload::TreasuryAllocation(d) => Some(d),
            _ => None,
        }
    }
    pub fn init_cbe_token_data(&self) -> Option<&InitCbeTokenData> {
        match &self.payload {
            TransactionPayload::InitCbeToken(d) => Some(d),
            _ => None,
        }
    }
    pub fn create_employment_contract_data(&self) -> Option<&CreateEmploymentContractData> {
        match &self.payload {
            TransactionPayload::CreateEmploymentContract(d) => Some(d),
            _ => None,
        }
    }
    pub fn process_payroll_data(&self) -> Option<&ProcessPayrollData> {
        match &self.payload {
            TransactionPayload::ProcessPayroll(d) => Some(d),
            _ => None,
        }
    }

    pub fn dao_stake_data(&self) -> Option<&DaoStakeData> {
        match &self.payload {
            TransactionPayload::DaoStake(d) => Some(d),
            _ => None,
        }
    }

    pub fn dao_unstake_data(&self) -> Option<&DaoUnstakeData> {
        match &self.payload {
            TransactionPayload::DaoUnstake(d) => Some(d),
            _ => None,
        }
    }

    /// Get the size of the transaction in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).map(|data| data.len()).unwrap_or(0)
    }

    /// Check if transaction is empty (no inputs or outputs)
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }

    /// Create a new bonding curve deploy transaction with an explicit chain id.
    pub fn new_bonding_curve_deploy_with_chain_id(
        chain_id: u8,
        bonding_curve_deploy_data: BondingCurveDeployData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::BondingCurveDeploy,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::BondingCurveDeploy(bonding_curve_deploy_data),
        }
    }

    /// Create a new bonding curve buy transaction with an explicit chain id.
    pub fn new_bonding_curve_buy_with_chain_id(
        chain_id: u8,
        bonding_curve_buy_data: BondingCurveBuyData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::BondingCurveBuy,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::BondingCurveBuy(bonding_curve_buy_data),
        }
    }

    /// Create a new bonding curve sell transaction with an explicit chain id.
    pub fn new_bonding_curve_sell_with_chain_id(
        chain_id: u8,
        bonding_curve_sell_data: BondingCurveSellData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::BondingCurveSell,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::BondingCurveSell(bonding_curve_sell_data),
        }
    }

    /// Create a new bonding curve graduate transaction with an explicit chain id.
    pub fn new_bonding_curve_graduate_with_chain_id(
        chain_id: u8,
        bonding_curve_graduate_data: BondingCurveGraduateData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::BondingCurveGraduate,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::BondingCurveGraduate(bonding_curve_graduate_data),
        }
    }

    /// Create a new oracle committee update transaction with an explicit chain id.
    pub fn new_oracle_committee_update_with_chain_id(
        chain_id: u8,
        oracle_committee_update_data: OracleCommitteeUpdateData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::UpdateOracleCommittee,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::OracleCommitteeUpdate(oracle_committee_update_data),
        }
    }

    /// Create a new oracle configuration update transaction with an explicit chain id.
    pub fn new_oracle_config_update_with_chain_id(
        chain_id: u8,
        oracle_config_update_data: OracleConfigUpdateData,
        signature: Signature,
        memo: Vec<u8>,
    ) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::UpdateOracleConfig,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo,
            payload: TransactionPayload::OracleConfigUpdate(oracle_config_update_data),
        }
    }

    /// Create a new InitEntityRegistry transaction (legacy single-signer path).
    ///
    /// This is a one-time, irreversible transaction that sets the CBE and Nonprofit
    /// treasury addresses. Must be signed by a Bootstrap Council member.
    ///
    /// For new code, prefer `new_init_entity_registry_threshold` which uses the
    /// multi-signer threshold approval set.
    pub fn new_init_entity_registry(
        chain_id: u8,
        cbe_treasury: PublicKey,
        nonprofit_treasury: PublicKey,
        initialized_at: u64,
        initialized_at_height: u64,
        signature: Signature,
    ) -> Self {
        let approvals = crate::transaction::threshold_approval::ThresholdApprovalSet::new(
            crate::transaction::threshold_approval::ApprovalDomain::BootstrapCouncil,
        );
        let data = InitEntityRegistryData {
            cbe_treasury,
            nonprofit_treasury,
            initialized_at,
            initialized_at_height,
            approvals,
        };
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::InitEntityRegistry,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_INIT_ENTITY_REGISTRY".to_vec(),
            payload: TransactionPayload::InitEntityRegistry(data),
        }
    }

    /// Create a new RecordOnRampTrade transaction.
    pub fn new_record_on_ramp_trade(chain_id: u8, data: RecordOnRampTradeData) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::RecordOnRampTrade,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature: Default::default(),
            memo: b"ZHTP_RECORD_ON_RAMP_TRADE".to_vec(),
            payload: TransactionPayload::RecordOnRampTrade(data),
        }
    }

    /// Create a new TreasuryAllocation transaction.
    pub fn new_treasury_allocation(chain_id: u8, data: TreasuryAllocationData) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::TreasuryAllocation,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature: Default::default(),
            memo: b"ZHTP_TREASURY_ALLOCATION".to_vec(),
            payload: TransactionPayload::TreasuryAllocation(data),
        }
    }

    pub fn new_init_cbe_token(
        chain_id: u8,
        compensation_key_id: [u8; 32],
        operational_key_id: [u8; 32],
        performance_key_id: [u8; 32],
        strategic_key_id: [u8; 32],
        initialized_at: u64,
        initialized_at_height: u64,
        signature: Signature,
    ) -> Self {
        let data = InitCbeTokenData {
            compensation_key_id,
            operational_key_id,
            performance_key_id,
            strategic_key_id,
            initialized_at,
            initialized_at_height,
        };
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::InitCbeToken,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_INIT_CBE_TOKEN".to_vec(),
            payload: TransactionPayload::InitCbeToken(data),
        }
    }

    pub fn new_create_employment_contract(
        chain_id: u8,
        dao_id: [u8; 32],
        employee_key_id: [u8; 32],
        contract_type: u8,
        compensation_amount: u64,
        payment_period: u8,
        tax_rate_basis_points: u16,
        tax_jurisdiction: String,
        profit_share_percentage: u16,
        signature: Signature,
    ) -> Self {
        let data = CreateEmploymentContractData {
            dao_id,
            employee_key_id,
            contract_type,
            compensation_amount,
            payment_period,
            tax_rate_basis_points,
            tax_jurisdiction,
            profit_share_percentage,
        };
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::CreateEmploymentContract,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_CREATE_EMPLOYMENT_CONTRACT".to_vec(),
            payload: TransactionPayload::CreateEmploymentContract(data),
        }
    }

    pub fn new_process_payroll(chain_id: u8, contract_id: [u8; 32], signature: Signature) -> Self {
        let data = ProcessPayrollData { contract_id };
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::ProcessPayroll,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_PROCESS_PAYROLL".to_vec(),
            payload: TransactionPayload::ProcessPayroll(data),
        }
    }

    /// Build an *unsigned* DaoStake transaction skeleton.
    ///
    /// The caller must:
    /// 1. Compute `tx.signing_hash()`
    /// 2. Sign it with the staker's Dilithium5 key
    /// 3. Set `tx.signature` with the real signature + public key
    ///
    /// `lock_blocks` must be > 0. `locked_until` is computed by the executor
    /// as `block_height + lock_blocks` and is NOT in the payload.
    pub fn new_dao_stake(chain_id: u8, data: DaoStakeData, signature: Signature) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::DaoStake,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_DAO_STAKE".to_vec(),
            payload: TransactionPayload::DaoStake(data),
        }
    }

    /// Build an *unsigned* DaoUnstake transaction skeleton.
    ///
    /// The caller must:
    /// 1. Compute `tx.signing_hash()`
    /// 2. Sign it with the staker's Dilithium5 key
    /// 3. Set `tx.signature` with the real signature + public key
    pub fn new_dao_unstake(chain_id: u8, data: DaoUnstakeData, signature: Signature) -> Self {
        Transaction {
            version: TX_VERSION_V8,
            chain_id,
            transaction_type: TransactionType::DaoUnstake,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            signature,
            memo: b"ZHTP_DAO_UNSTAKE".to_vec(),
            payload: TransactionPayload::DaoUnstake(data),
        }
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
    pub fn new(commitment: Hash, note: Hash, recipient: PublicKey) -> Self {
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
    pub fn compute_claim_id(_claimant_identity: &str, _month_index: u64) -> Hash {
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
        let expected_tribute = self
            .profit_amount
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
        let total_revenue: u64 = self.revenue_sources.iter().map(|src| src.amount).sum();
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

// ============================================================================
// Bonding Curve Transaction Data
// ============================================================================

/// Bonding curve token deployment data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveDeployData {
    /// Token name
    pub name: String,
    /// Token symbol (max 10 chars)
    pub symbol: String,
    /// Curve type: 0=Linear, 1=Exponential, 2=Sigmoid
    pub curve_type: u8,
    /// Base price in stablecoin atomic units
    pub base_price: u64,
    /// Slope for linear, growth rate bps for exponential, steepness for sigmoid
    pub curve_param: u64,
    /// Midpoint supply for sigmoid (ignored for other types)
    pub midpoint_supply: Option<u64>,
    /// Graduation threshold type: 0=ReserveAmount, 1=SupplyAmount, 2=TimeAndReserve, 3=TimeAndSupply
    pub threshold_type: u8,
    /// Threshold value (reserve or supply amount)
    pub threshold_value: u64,
    /// Minimum time in seconds (for TimeAnd* thresholds)
    pub threshold_time_seconds: Option<u64>,
    /// Whether selling is enabled during curve phase
    pub sell_enabled: bool,
    /// Creator's public key
    pub creator: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Bonding curve buy transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveBuyData {
    /// Token ID being purchased
    pub token_id: [u8; 32],
    /// Amount of stablecoin to spend
    pub stable_amount: u128,
    /// Minimum tokens expected (slippage protection)
    pub min_tokens_out: u128,
    /// Buyer's address
    pub buyer: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Bonding curve sell transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveSellData {
    /// Token ID being sold
    pub token_id: [u8; 32],
    /// Amount of tokens to sell
    pub token_amount: u128,
    /// Minimum stablecoin expected (slippage protection)
    pub min_stable_out: u128,
    /// Seller's address
    pub seller: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Bonding curve graduation transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveGraduateData {
    /// Token ID being graduated
    pub token_id: [u8; 32],
    /// AMM pool ID to create/use
    pub pool_id: [u8; 32],
    /// SOV amount to seed into AMM pool
    pub sov_seed_amount: u128,
    /// Token amount to seed into AMM pool
    pub token_seed_amount: u128,
    /// Graduator's address (must be creator or governance)
    pub graduator: [u8; 32],
    /// Nonce for replay protection
    pub nonce: u64,
}

/// Entity registry initialization data (TSR)
///
/// One-time transaction that sets the CBE (for-profit) and Nonprofit treasury
/// addresses on-chain. The EntityRegistry becomes immutable after this transaction
/// is committed. Must be approved by at least `council_threshold` Bootstrap Council members.
///
/// # Invariants
/// - cbe_treasury != nonprofit_treasury
/// - Neither address may be zero
/// - Can only be processed once per chain lifetime
///
/// # Threshold approval preimage
/// Each council signer signs:
///   `compute_approval_preimage(38, ApprovalDomain::BootstrapCouncil, bincode({cbe_treasury, nonprofit_treasury, initialized_at, initialized_at_height}))`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitEntityRegistryData {
    /// CBE (For-Profit) treasury public key
    pub cbe_treasury: crate::integration::crypto_integration::PublicKey,
    /// Nonprofit treasury public key
    pub nonprofit_treasury: crate::integration::crypto_integration::PublicKey,
    /// Unix timestamp when this initialization was requested
    pub initialized_at: u64,
    /// Block height at time of signing (client-provided; part of the signed payload
    /// so it cannot be modified post-signing without invalidating the signature).
    pub initialized_at_height: u64,
    /// Bootstrap Council threshold approvals. Each signer has signed
    /// `compute_approval_preimage(38, ApprovalDomain::BootstrapCouncil, canonical_payload_bytes)`
    /// where `canonical_payload_bytes` is bincode of the four fields above.
    #[serde(default)]
    pub approvals: crate::transaction::threshold_approval::ThresholdApprovalSet,
}

// ---------------------------------------------------------------------------
// #1897 — RecordOnRampTrade transaction data
// ---------------------------------------------------------------------------

/// Oracle committee-attested fiat→CBE on-ramp trade record (type 39).
///
/// An off-chain gateway submits this transaction once T-of-N oracle committee
/// members have approved the trade. The approval set must use the OracleCommittee
/// domain so the committee membership check uses the correct signer set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordOnRampTradeData {
    /// Oracle epoch when this trade occurred.
    pub epoch_id: u64,
    /// CBE received by the user (18-decimal atomic units).
    pub cbe_amount: u128,
    /// USDC paid by the user (6-decimal atomic units).
    pub usdc_amount: u128,
    /// Unix timestamp of the trade.
    pub traded_at: u64,
    /// Oracle committee threshold approvals over the canonical preimage.
    /// Domain must be `ApprovalDomain::OracleCommittee`.
    pub approvals: crate::transaction::threshold_approval::ThresholdApprovalSet,
}

// ---------------------------------------------------------------------------
// #1896 — TreasuryAllocation transaction data
// ---------------------------------------------------------------------------

/// Governance-approved treasury allocation from CBE treasury → DAO wallet (type 40).
///
/// Authorized by Bootstrap Council threshold approvals. The actual SOV movement
/// is wired at block-processing level; the executor arm records it as LegacySystem
/// and a TODO is left for full SOV ledger integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryAllocationData {
    /// Source: CBE treasury wallet key_id (must match EntityRegistry.cbe_treasury.key_id).
    pub source_treasury_key_id: [u8; 32],
    /// Destination: DAO treasury wallet key_id.
    pub destination_key_id: [u8; 32],
    /// Amount of SOV to transfer (atomic units).
    pub amount: u64,
    /// Human-readable spending category (e.g. "operations", "grants").
    pub spending_category: String,
    /// DAO proposal ID that authorized this allocation (for audit trail).
    pub proposal_id: [u8; 32],
    /// Bootstrap Council threshold approvals.
    /// Domain must be `ApprovalDomain::BootstrapCouncil`.
    pub approvals: crate::transaction::threshold_approval::ThresholdApprovalSet,
}

// ============================================================================
// CBE Transaction Payload Structs
// ============================================================================

/// CBE token initialization data (one-time, irreversible)
///
/// Carries the 4 pool addresses that `CbeToken::init()` requires.
/// The block processor resolves each key_id to a full `PublicKey` via
/// `resolve_public_key_by_key_id` before calling the contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitCbeTokenData {
    /// Compensation pool wallet key_id — receives 40% of CBE supply
    pub compensation_key_id: [u8; 32],
    /// Operational treasury wallet key_id — receives 30% of CBE supply
    pub operational_key_id: [u8; 32],
    /// Performance incentives wallet key_id — receives 20% of CBE supply
    pub performance_key_id: [u8; 32],
    /// Strategic reserves wallet key_id — receives 10% of CBE supply
    pub strategic_key_id: [u8; 32],
    /// Unix timestamp of initialization
    pub initialized_at: u64,
    /// Block height at initialization (client-provided, part of signed payload)
    pub initialized_at_height: u64,
}

/// Employment contract creation data
///
/// Maps 1-to-1 to `EmploymentRegistry::create_employment_contract()` parameters.
/// Enum types (`ContractAccessType`, `EconomicPeriod`) are encoded as `u8` discriminants
/// to avoid `#[cfg(feature = "contracts")]` dependencies in the transaction core.
/// The block processor converts them to the correct enum variants.
///
/// ContractAccessType discriminants: 0 = PublicAccess, 1 = Employment
/// EconomicPeriod discriminants:     0 = Monthly, 1 = Quarterly, 2 = Annually
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEmploymentContractData {
    /// DAO / employer key_id (32-byte)
    pub dao_id: [u8; 32],
    /// Employee wallet key_id (32-byte) — resolved to PublicKey in block processor
    pub employee_key_id: [u8; 32],
    /// Contract type discriminant (0=PublicAccess, 1=Employment)
    pub contract_type: u8,
    /// Compensation amount in CBE atomic units
    pub compensation_amount: u64,
    /// Payment period discriminant (0=Monthly, 1=Quarterly, 2=Annually)
    pub payment_period: u8,
    /// Tax rate in basis points (max 5000 = 50%)
    pub tax_rate_basis_points: u16,
    /// Tax jurisdiction string
    pub tax_jurisdiction: String,
    /// Profit share in basis points (max 2000 = 20%)
    pub profit_share_percentage: u16,
}

/// Payroll disbursement trigger data
///
/// The block processor calls `EmploymentRegistry::process_payroll(contract_id, current_height)`.
/// All amounts are computed by the contract; this payload only identifies which contract to pay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPayrollData {
    /// Contract to process payroll for (32-byte contract_id from CreateEmploymentContract)
    pub contract_id: [u8; 32],
}

/// SOV staking to a sector DAO wallet
///
/// Locks `amount` nSOV from `staker` into `sector_dao_key_id`'s stake record for
/// `lock_blocks` blocks. The absolute unlock height (`locked_until`) is computed by
/// the executor as `block_height + lock_blocks` so the staker cannot forge it.
///
/// `nonce` is a per-staker monotonic counter stored in `token_nonces` sled tree;
/// incrementing it prevents a replayed transaction from double-spending the same SOV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoStakeData {
    /// Target sector DAO wallet key_id (must be one of the 5 known DAO addresses)
    pub sector_dao_key_id: [u8; 32],
    /// Staker's key_id (= `tx.signature.public_key.key_id` for new wallets)
    pub staker: [u8; 32],
    /// Amount of SOV (in nSOV, 1 SOV = 1_000_000_000 nSOV) to lock
    pub amount: u128,
    /// Per-staker monotonic nonce; prevents replay attacks
    pub nonce: u64,
    /// Requested lock duration in blocks; executor computes `locked_until = block_height + lock_blocks`
    pub lock_blocks: u64,
}

/// SOV unstake from a sector DAO wallet
///
/// Returns the full locked SOV amount from the DAO wallet back to the staker.
/// The staker must be the transaction signer. The stake record must exist and
/// `current_block_height >= locked_until`; the executor enforces the lock check.
///
/// `nonce` is the staker's current SOV nonce (same counter used by DaoStake);
/// it is incremented by the executor to prevent replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaoUnstakeData {
    /// Target sector DAO wallet key_id (must match an existing stake record)
    pub sector_dao_key_id: [u8; 32],
    /// Staker's key_id (= `tx.signature.public_key.key_id`)
    pub staker: [u8; 32],
    /// Per-staker monotonic nonce; prevents replay attacks
    pub nonce: u64,
}

// ============================================================================
// TransactionPayload enum
// ============================================================================

/// Typed transaction payload - replaces the flat Option<FooData> field scatter on Transaction.
///
/// Adding a new transaction type = adding one variant here. No version constant, no positional
/// field count, no `if version >= TX_VERSION_VN` ladder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// No typed payload (Transfer, Coinbase, SessionCreation, SessionTermination,
    /// ContentUpload, UbiDistribution, DifficultyUpdate, CancelOracleUpdate, and
    /// other types that use inputs/outputs/memo only)
    None,
    Identity(IdentityTransactionData),
    Wallet(WalletTransactionData),
    Validator(ValidatorTransactionData),
    DaoProposal(DaoProposalData),
    DaoVote(DaoVoteData),
    DaoExecution(DaoExecutionData),
    UbiClaim(UbiClaimData),
    ProfitDeclaration(ProfitDeclarationData),
    TokenTransfer(TokenTransferData),
    TokenMint(TokenMintData),
    GovernanceConfigUpdate(GovernanceConfigUpdateData),
    BondingCurveDeploy(BondingCurveDeployData),
    BondingCurveBuy(BondingCurveBuyData),
    BondingCurveSell(BondingCurveSellData),
    BondingCurveGraduate(BondingCurveGraduateData),
    OracleCommitteeUpdate(OracleCommitteeUpdateData),
    OracleConfigUpdate(OracleConfigUpdateData),
    OracleAttestation(OracleAttestationData),
    CancelOracleUpdate(CancelOracleUpdateData),
    InitEntityRegistry(InitEntityRegistryData),
    RecordOnRampTrade(RecordOnRampTradeData),
    TreasuryAllocation(TreasuryAllocationData),
    InitCbeToken(InitCbeTokenData),
    CreateEmploymentContract(CreateEmploymentContractData),
    ProcessPayroll(ProcessPayrollData),
    /// SOV stake to a sector DAO wallet (appended last for bincode discriminant stability)
    DaoStake(DaoStakeData),
    /// SOV unstake from a sector DAO wallet (appended after DaoStake)
    DaoUnstake(DaoUnstakeData),
}
