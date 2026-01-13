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
            fee: wallet_data.registration_fee,
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
