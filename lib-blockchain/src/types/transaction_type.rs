//! Transaction type definitions
//!
//! Defines the types of transactions supported by the ZHTP blockchain.
//! Note: Identity transaction processing is handled by integration with lib-identity package.
//!
//! # Serialization Stability
//!
//! IMPORTANT: This enum uses explicit discriminant values via `#[repr(u8)]` to ensure
//! stable serialization across versions. When adding new variants:
//! 1. ALWAYS assign an explicit value (do NOT rely on implicit ordering)
//! 2. NEVER reuse a value from a removed variant
//! 3. NEVER change the value of an existing variant
//!
//! The explicit `#[repr(u8)]` ensures bincode serializes to a single byte with
//! predictable values, making cross-platform compatibility reliable.

use serde::{Serialize, Deserialize};

/// Transaction types supported by ZHTP blockchain
///
/// Uses explicit discriminant values (`#[repr(u8)]`) for stable serialization.
/// Bincode will serialize these as single bytes with the assigned values.
/// See module-level documentation for rules on adding new variants.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TransactionType {
    /// Standard value transfer between accounts
    Transfer = 0,
    /// Coinbase transaction (block reward, no inputs)
    Coinbase = 1,
    /// Token transfer (balance model, not UTXO)
    TokenTransfer = 2,
    /// Identity registration on blockchain (delegates to lib-identity)
    IdentityRegistration = 3,
    /// Identity update/modification (delegates to lib-identity)
    IdentityUpdate = 4,
    /// Identity revocation (delegates to lib-identity)
    IdentityRevocation = 5,
    /// Smart contract deployment (delegates to lib-contracts)
    ContractDeployment = 6,
    /// Smart contract execution (delegates to lib-contracts)
    ContractExecution = 7,
    /// Session creation for audit/tracking purposes
    SessionCreation = 8,
    /// Session termination for audit/tracking purposes
    SessionTermination = 9,
    /// Content upload transaction
    ContentUpload = 10,
    /// Universal Basic Income distribution
    UbiDistribution = 11,
    /// Wallet registration/creation on blockchain
    WalletRegistration = 12,
    /// Validator registration for consensus participation
    ValidatorRegistration = 13,
    /// Validator information update
    ValidatorUpdate = 14,
    /// Validator unregistration/exit from consensus
    ValidatorUnregister = 15,
    /// DAO governance proposal submission
    DaoProposal = 16,
    /// DAO governance vote on a proposal
    DaoVote = 17,
    /// DAO proposal execution (treasury spending)
    DaoExecution = 18,
    /// Difficulty parameter update (via DAO governance)
    ///
    /// Used to update the blockchain's difficulty adjustment parameters
    /// after a DifficultyParameterUpdate DAO proposal has been approved.
    DifficultyUpdate = 19,
    /// UBI claim - citizen-initiated claim from UBI pool (Week 7)
    ///
    /// Distinct from UbiDistribution (system-initiated push).
    /// This is a pull-based model where citizens claim their allocation.
    UBIClaim = 20,
    /// Profit declaration - enforces 20% tribute from for-profit to nonprofit (Week 7)
    ///
    /// Validates that tribute_amount == profit_amount * 20 / 100.
    /// Integrates with TributeRouter for enforcement.
    ProfitDeclaration = 21,
    /// Token governance configuration update (Phase 3D)
    ///
    /// Allows authorized governance addresses to update specific token configuration:
    /// - set_fee_schedule: Update fee parameters
    /// - set_transfer_policy: Switch between supported policies (not ComplianceGated)
    /// - pause/unpause: Emergency circuit breaker
    ///
    /// Requires: caller has Governance role in token's authorities
    GovernanceConfigUpdate = 22,
    /// Wallet update (owner/public key rebinding, rotation, metadata updates)
    ///
    /// This is a durable on-chain update for existing wallet records.
    WalletUpdate = 23,
}

impl TransactionType {
    /// Check if this transaction type relates to identity management
    pub fn is_identity_transaction(&self) -> bool {
        matches!(self, 
            TransactionType::IdentityRegistration |
            TransactionType::IdentityUpdate |
            TransactionType::IdentityRevocation
        )
    }

    /// Check if this transaction type relates to smart contracts
    pub fn is_contract_transaction(&self) -> bool {
        matches!(self,
            TransactionType::ContractDeployment |
            TransactionType::ContractExecution
        )
    }

    /// Check if this transaction type relates to wallet management
    pub fn is_wallet_transaction(&self) -> bool {
        matches!(self, TransactionType::WalletRegistration | TransactionType::WalletUpdate)
    }

    /// Check if this is a standard transfer transaction
    pub fn is_transfer(&self) -> bool {
        matches!(self, TransactionType::Transfer)
    }

    /// Check if this is a coinbase (block reward) transaction
    pub fn is_coinbase(&self) -> bool {
        matches!(self, TransactionType::Coinbase)
    }

    /// Check if this is a token transfer transaction
    pub fn is_token_transfer(&self) -> bool {
        matches!(self, TransactionType::TokenTransfer)
    }

    /// Check if this transaction type relates to validator management
    pub fn is_validator_transaction(&self) -> bool {
        matches!(self,
            TransactionType::ValidatorRegistration |
            TransactionType::ValidatorUpdate |
            TransactionType::ValidatorUnregister
        )
    }

    /// Check if this transaction type relates to DAO governance
    pub fn is_dao_transaction(&self) -> bool {
        matches!(self,
            TransactionType::DaoProposal |
            TransactionType::DaoVote |
            TransactionType::DaoExecution |
            TransactionType::DifficultyUpdate
        )
    }

    /// Get a human-readable description of the transaction type
    pub fn description(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "Standard value transfer",
            TransactionType::Coinbase => "Block reward (coinbase)",
            TransactionType::TokenTransfer => "Token transfer (balance model)",
            TransactionType::IdentityRegistration => "Identity registration",
            TransactionType::IdentityUpdate => "Identity update",
            TransactionType::IdentityRevocation => "Identity revocation",
            TransactionType::ContractDeployment => "Smart contract deployment",
            TransactionType::ContractExecution => "Smart contract execution",
            TransactionType::SessionCreation => "Session creation for audit/tracking",
            TransactionType::SessionTermination => "Session termination for audit/tracking",
            TransactionType::ContentUpload => "Content upload transaction",
            TransactionType::UbiDistribution => "Universal Basic Income distribution",
            TransactionType::WalletRegistration => "Wallet registration/creation",
            TransactionType::WalletUpdate => "Wallet update (metadata/ownership)",
            TransactionType::ValidatorRegistration => "Validator registration for consensus",
            TransactionType::ValidatorUpdate => "Validator information update",
            TransactionType::ValidatorUnregister => "Validator unregistration/exit",
            TransactionType::DaoProposal => "DAO governance proposal submission",
            TransactionType::DaoVote => "DAO governance vote on proposal",
            TransactionType::DaoExecution => "DAO proposal execution (treasury spending)",
            TransactionType::DifficultyUpdate => "Difficulty parameter update (via DAO governance)",
            TransactionType::UBIClaim => "UBI claim - citizen-initiated claim from pool",
            TransactionType::ProfitDeclaration => "Profit declaration - enforces 20% tribute",
            TransactionType::GovernanceConfigUpdate => "Token governance configuration update",
        }
    }

    /// Get the transaction type as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "transfer",
            TransactionType::Coinbase => "coinbase",
            TransactionType::TokenTransfer => "token_transfer",
            TransactionType::IdentityRegistration => "identity_registration",
            TransactionType::IdentityUpdate => "identity_update",
            TransactionType::IdentityRevocation => "identity_revocation",
            TransactionType::ContractDeployment => "contract_deployment",
            TransactionType::ContractExecution => "contract_execution",
            TransactionType::SessionCreation => "session_creation",
            TransactionType::SessionTermination => "session_termination",
            TransactionType::ContentUpload => "content_upload",
            TransactionType::UbiDistribution => "ubi_distribution",
            TransactionType::WalletRegistration => "wallet_registration",
            TransactionType::WalletUpdate => "wallet_update",
            TransactionType::ValidatorRegistration => "validator_registration",
            TransactionType::ValidatorUpdate => "validator_update",
            TransactionType::ValidatorUnregister => "validator_unregister",
            TransactionType::DaoProposal => "dao_proposal",
            TransactionType::DaoVote => "dao_vote",
            TransactionType::DaoExecution => "dao_execution",
            TransactionType::DifficultyUpdate => "difficulty_update",
            TransactionType::UBIClaim => "ubi_claim",
            TransactionType::ProfitDeclaration => "profit_declaration",
            TransactionType::GovernanceConfigUpdate => "governance_config_update",
        }
    }

    /// Parse transaction type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "transfer" => Some(TransactionType::Transfer),
            "coinbase" => Some(TransactionType::Coinbase),
            "token_transfer" => Some(TransactionType::TokenTransfer),
            "identity_registration" => Some(TransactionType::IdentityRegistration),
            "identity_update" => Some(TransactionType::IdentityUpdate),
            "identity_revocation" => Some(TransactionType::IdentityRevocation),
            "contract_deployment" => Some(TransactionType::ContractDeployment),
            "contract_execution" => Some(TransactionType::ContractExecution),
            "session_creation" => Some(TransactionType::SessionCreation),
            "session_termination" => Some(TransactionType::SessionTermination),
            "content_upload" => Some(TransactionType::ContentUpload),
            "ubi_distribution" => Some(TransactionType::UbiDistribution),
            "wallet_registration" => Some(TransactionType::WalletRegistration),
            "wallet_update" => Some(TransactionType::WalletUpdate),
            "validator_registration" => Some(TransactionType::ValidatorRegistration),
            "validator_update" => Some(TransactionType::ValidatorUpdate),
            "validator_unregister" => Some(TransactionType::ValidatorUnregister),
            "dao_proposal" => Some(TransactionType::DaoProposal),
            "dao_vote" => Some(TransactionType::DaoVote),
            "dao_execution" => Some(TransactionType::DaoExecution),
            "difficulty_update" => Some(TransactionType::DifficultyUpdate),
            "ubi_claim" => Some(TransactionType::UBIClaim),
            "profit_declaration" => Some(TransactionType::ProfitDeclaration),
            "governance_config_update" => Some(TransactionType::GovernanceConfigUpdate),
            _ => None,
        }
    }

    /// Check if this transaction type is a governance config update
    pub fn is_governance_config_update(&self) -> bool {
        matches!(self, TransactionType::GovernanceConfigUpdate)
    }

    /// Check if this transaction type relates to UBI (pull-based claims vs system-initiated distribution)
    pub fn is_ubi_claim(&self) -> bool {
        matches!(self, TransactionType::UBIClaim)
    }

    /// Check if this transaction type relates to profit declarations (for-profit to nonprofit tribute)
    pub fn is_profit_declaration(&self) -> bool {
        matches!(self, TransactionType::ProfitDeclaration)
    }
}
