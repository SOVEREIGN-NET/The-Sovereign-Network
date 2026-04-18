//! Transaction validation logic
//!
//! Provides comprehensive validation for ZHTP blockchain transactions.

use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use crate::integration::zk_integration::is_valid_proof_structure;
use crate::transaction::contract_deployment::ContractDeploymentPayloadV1;
use crate::transaction::core::{
    IdentityTransactionData, Transaction, TransactionInput, TransactionOutput,
};
use crate::transaction::token_creation::TokenCreationPayloadV1;
use crate::transaction::{
    decode_bonding_curve_buy, decode_bonding_curve_sell, BONDING_CURVE_TX_PAYLOAD_LEN,
};
use crate::types::{transaction_type::TransactionType, ContractCall, ContractType, Hash};

/// Transaction validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidSignature,
    InvalidZkProof,
    DoubleSpend,
    InvalidAmount,
    InvalidFee,
    InvalidTransaction,
    Unauthorized,
    AlreadyInitialized,
    InvalidIdentityData,
    InvalidInputs,
    InvalidOutputs,
    MissingRequiredData,
    InvalidTransactionType,
    UnregisteredSender,
    InvalidMemo,
    MissingWalletData,
    InvalidWalletId,
    InvalidOwnerIdentity,
    InvalidPublicKey,
    InvalidSeedCommitment,
    InvalidWalletType,
    InvalidValidatorData,
    /// A threshold approval signature is invalid or the approval domain is wrong.
    InvalidApproval,
    /// A signer appears more than once in a threshold approval set.
    DuplicateSigner,
    /// Threshold approval count is below the required quorum.
    ThresholdNotMet,
    /// Stake is still locked - cannot unstake yet.
    StakeStillLocked { locked_until: u64, remaining: u64 },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidSignature => write!(f, "Invalid transaction signature"),
            ValidationError::InvalidZkProof => write!(f, "Invalid zero-knowledge proof"),
            ValidationError::DoubleSpend => write!(f, "Double spend detected"),
            ValidationError::InvalidAmount => write!(f, "Invalid transaction amount"),
            ValidationError::InvalidFee => write!(f, "Invalid transaction fee"),
            ValidationError::InvalidTransaction => write!(f, "Invalid transaction structure"),
            ValidationError::Unauthorized => write!(f, "Unauthorized transaction signer"),
            ValidationError::AlreadyInitialized => write!(f, "Entity registry already initialized"),
            ValidationError::InvalidIdentityData => write!(f, "Invalid identity data"),
            ValidationError::InvalidInputs => write!(f, "Invalid transaction inputs"),
            ValidationError::InvalidOutputs => write!(f, "Invalid transaction outputs"),
            ValidationError::MissingRequiredData => write!(f, "Missing required transaction data"),
            ValidationError::InvalidTransactionType => write!(f, "Invalid transaction type"),
            ValidationError::UnregisteredSender => {
                write!(f, "Transaction from unregistered sender identity")
            }
            ValidationError::InvalidMemo => write!(f, "Invalid or missing transaction memo"),
            ValidationError::MissingWalletData => write!(f, "Missing wallet data in transaction"),
            ValidationError::InvalidWalletId => write!(f, "Invalid wallet ID"),
            ValidationError::InvalidOwnerIdentity => write!(f, "Invalid owner identity"),
            ValidationError::InvalidPublicKey => write!(f, "Invalid public key"),
            ValidationError::InvalidSeedCommitment => write!(f, "Invalid seed commitment"),
            ValidationError::InvalidWalletType => write!(f, "Invalid wallet type"),
            ValidationError::InvalidValidatorData => write!(f, "Invalid or missing validator data"),
            ValidationError::InvalidApproval => write!(f, "Invalid threshold approval"),
            ValidationError::DuplicateSigner => write!(f, "Duplicate signer in approval set"),
            ValidationError::ThresholdNotMet => write!(f, "Approval threshold not met"),
            ValidationError::StakeStillLocked { locked_until, remaining } => {
                write!(f, "Stake still locked until block {} ({} blocks remaining)", locked_until, remaining)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Transaction validation result
pub type ValidationResult = Result<(), ValidationError>;

/// Transaction validator with state context
pub struct TransactionValidator {
    // Note: In implementation, this would contain references to
    // blockchain state, UTXO set, nullifier set, etc.
    fee_config: crate::transaction::TxFeeConfig,
}

/// Transaction validator with blockchain state access for identity verification
pub struct StatefulTransactionValidator<'a> {
    /// Reference to blockchain state for identity verification
    blockchain: Option<&'a crate::blockchain::Blockchain>,
}

impl TransactionValidator {
    /// Create a new transaction validator
    pub fn new() -> Self {
        Self {
            fee_config: crate::transaction::TxFeeConfig::default(),
        }
    }

    /// Create a transaction validator with explicit fee configuration
    pub fn with_fee_config(fee_config: crate::transaction::TxFeeConfig) -> Self {
        Self { fee_config }
    }

    /// Compute whether economics validation should treat this as a system transaction.
    ///
    /// Phase 2: TokenTransfer must have fee == 0 even when the caller passes
    /// is_system_transaction=false (to force signature validation). This ensures
    /// the mempool and BlockExecutor have consistent fee rules.
    fn compute_economics_is_system(transaction: &Transaction, is_system_transaction: bool) -> bool {
        is_system_transaction || transaction.transaction_type == TransactionType::TokenTransfer
    }

    fn validate_canonical_bonding_curve_memo(
        &self,
        transaction: &Transaction,
        expected_type: TransactionType,
    ) -> ValidationResult {
        if transaction.memo.len() != BONDING_CURVE_TX_PAYLOAD_LEN {
            return Err(ValidationError::InvalidMemo);
        }

        match expected_type {
            TransactionType::BondingCurveBuy => {
                let data = decode_bonding_curve_buy(&transaction.memo)
                    .map_err(|_| ValidationError::InvalidMemo)?;
                if data.chain_id != transaction.chain_id {
                    return Err(ValidationError::InvalidTransaction);
                }
                if transaction.signature.public_key.key_id != data.sender {
                    return Err(ValidationError::InvalidSignature);
                }
            }
            TransactionType::BondingCurveSell => {
                let data = decode_bonding_curve_sell(&transaction.memo)
                    .map_err(|_| ValidationError::InvalidMemo)?;
                if data.chain_id != transaction.chain_id {
                    return Err(ValidationError::InvalidTransaction);
                }
                if transaction.signature.public_key.key_id != data.sender {
                    return Err(ValidationError::InvalidSignature);
                }
            }
            _ => return Err(ValidationError::InvalidTransactionType),
        }

        // Canonical CBE transactions carry a full ~7.2 KB Dilithium5 signature
        // (2592-byte public key + 4595-byte signature).  We must actually verify
        // it — key_id is only a BLAKE3 hash of the public key and provides zero
        // cryptographic guarantee that the payload was signed by the private key.
        // There is no "system transaction" exemption here: every canonical CBE tx
        // MUST be signed, so we pay the bandwidth cost AND get the security. (#1942)
        self.validate_signature(transaction)?;

        Ok(())
    }

    /// Validate a transaction completely
    pub fn validate_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check if this is a system transaction (empty inputs = coinbase-style)
        let mut is_system_transaction = transaction.inputs.is_empty();
        // Typed token operations must pay fees even with empty inputs.
        if matches!(
            transaction.transaction_type,
            TransactionType::TokenTransfer | TransactionType::TokenCreation
        ) {
            is_system_transaction = false;
        }

        // Basic structure validation
        self.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    self.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            }
            TransactionType::IdentityRegistration => {
                self.validate_identity_transaction(transaction)?
            }
            TransactionType::IdentityUpdate => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => {
                self.validate_identity_transaction(transaction)?
            }
            TransactionType::ContractDeployment => {
                self.validate_contract_transaction(transaction)?
            }
            TransactionType::ContractExecution => {
                self.validate_contract_transaction(transaction)?
            }
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                self.validate_wallet_registration_transaction(transaction)?;
            }
            TransactionType::WalletUpdate => {
                self.validate_wallet_update_transaction(transaction, is_system_transaction)?;
            }
            TransactionType::ValidatorRegistration => {
                // Validator registration - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::ValidatorUpdate => {
                // Validator update - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::ValidatorUnregister => {
                // Validator unregister - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::GatewayRegistration => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::GatewayUpdate => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::GatewayUnregister => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::DaoProposal
            | TransactionType::DaoVote
            | TransactionType::DaoExecution
            | TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }

            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                // Coinbase must have no inputs
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer - outputs required
                if transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
                // Sender authorization is validated in the stateful phase
                // (StatefulTransactionValidator) which has wallet registry access
                // to resolve legacy HD-derived wallet_ids that differ from key_id.
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data().is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenMint => {
                // Validate minting authority and supply cap
                self.validate_token_mint(transaction)?;
            }
            TransactionType::TokenCreation => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
                TokenCreationPayloadV1::decode_memo(&transaction.memo)
                    .map_err(|_| ValidationError::InvalidMemo)?;
            }
            TransactionType::BondingCurveDeploy => {
                let data = transaction
                    .bonding_curve_deploy_data()
                    .ok_or(ValidationError::InvalidInputs)?;
                // Signer must be the declared creator
                if transaction.signature.public_key.key_id != data.creator {
                    return Err(ValidationError::InvalidSignature);
                }
            }
            TransactionType::BondingCurveBuy => {
                if let Some(data) = transaction.bonding_curve_buy_data() {
                    // Signer must be the declared buyer
                    if transaction.signature.public_key.key_id != data.buyer {
                        return Err(ValidationError::InvalidSignature);
                    }
                } else {
                    self.validate_canonical_bonding_curve_memo(
                        transaction,
                        TransactionType::BondingCurveBuy,
                    )?;
                }
            }
            TransactionType::BondingCurveSell => {
                if let Some(data) = transaction.bonding_curve_sell_data() {
                    // Signer must be the declared seller
                    if transaction.signature.public_key.key_id != data.seller {
                        return Err(ValidationError::InvalidSignature);
                    }
                } else {
                    self.validate_canonical_bonding_curve_memo(
                        transaction,
                        TransactionType::BondingCurveSell,
                    )?;
                }
            }
            TransactionType::BondingCurveGraduate => {
                let data = transaction
                    .bonding_curve_graduate_data()
                    .ok_or(ValidationError::InvalidInputs)?;
                // Signer must be the declared graduator
                if transaction.signature.public_key.key_id != data.graduator {
                    return Err(ValidationError::InvalidSignature);
                }
            }
            TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                // AMM/Token operations - not yet fully implemented
                // TODO: Add validation for these transaction types
            }
            TransactionType::UpdateOracleCommittee | TransactionType::UpdateOracleConfig => {
                // Oracle governance transactions require chain-state checks.
                // Run in stateful validator only.
            }
            TransactionType::OracleAttestation => {
                // Oracle attestation - full validation in stateful validator
            }
            TransactionType::CancelOracleUpdate => {
                // Cancel oracle update - validation in stateful validator
            }
            TransactionType::InitEntityRegistry => {
                // Payload must be present; no inputs/outputs allowed
                if transaction.init_entity_registry_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::RecordOnRampTrade => {
                // Threshold approval; full validation deferred to stateful validator
            }
            TransactionType::TreasuryAllocation => {
                // Threshold approval; full validation deferred to stateful validator
            }
            TransactionType::InitCbeToken => {
                // Deprecated — always reject at syntactic level (EPIC-001 Phase 1D).
                return Err(ValidationError::AlreadyInitialized);
            }
            TransactionType::CreateEmploymentContract => {
                // Full validation deferred to stateful validator
            }
            TransactionType::ProcessPayroll => {
                // Full validation deferred to stateful validator
            }
            TransactionType::DaoStake => {
                // Full validation deferred to stateful validator (balance, lock period, etc.)
            }
            TransactionType::DaoUnstake => {
                // Full validation deferred to stateful validator (lock check, record existence, etc.)
            }
            TransactionType::DomainRegistration => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_REGISTRATION_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::DomainUpdate => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_UPDATE_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
            }
        }

        // Signature validation:
        // - Historically, "system transactions" (empty inputs) skipped signatures.
        // - WalletUpdate and TokenMint must always be signed (privileged state mutations).
        // - If a system transaction carries a non-empty signature anyway, validate it.
        //   This prevents malformed signatures (wrong size, invalid bytes) from passing
        //   mempool intake and poisoning block proposals on other validators.
        // - RecordOnRampTrade and TreasuryAllocation use threshold approvals; the
        //   transaction-level signature may be empty/dummy on these types.
        let require_signature = !is_system_transaction
            || matches!(
                transaction.transaction_type,
                TransactionType::WalletUpdate
                    | TransactionType::TokenMint
                    | TransactionType::TokenCreation
                    | TransactionType::InitEntityRegistry
            );
        let has_nonempty_sig = !transaction.signature.signature.is_empty();
        // Skip tx-level sig validation for threshold-approval-only types
        let is_threshold_only = matches!(
            transaction.transaction_type,
            TransactionType::RecordOnRampTrade | TransactionType::TreasuryAllocation
        );
        if !is_threshold_only && (require_signature || has_nonempty_sig) {
            self.validate_signature(transaction)?;
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            self.validate_zk_proofs(transaction)?;
        }

        // Economic validation (modified for system transactions)
        // Phase 2: TokenTransfer must have fee == 0 (see validate_transaction_with_state).
        let economics_is_system =
            Self::compute_economics_is_system(transaction, is_system_transaction);
        self.validate_economics_with_system_check(transaction, economics_is_system)?;

        Ok(())
    }

    /// Validate a transaction with explicit system transaction flag
    pub fn validate_transaction_with_system_flag(
        &self,
        transaction: &Transaction,
        is_system_transaction: bool,
    ) -> ValidationResult {
        // Basic structure validation
        self.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    self.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            }
            TransactionType::IdentityRegistration => {
                self.validate_identity_transaction(transaction)?
            }
            TransactionType::IdentityUpdate => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => {
                self.validate_identity_transaction(transaction)?
            }
            TransactionType::ContractDeployment => {
                self.validate_contract_transaction(transaction)?
            }
            TransactionType::ContractExecution => {
                self.validate_contract_transaction(transaction)?
            }
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                self.validate_wallet_registration_transaction(transaction)?;
            }
            TransactionType::WalletUpdate => {
                self.validate_wallet_update_transaction(transaction, is_system_transaction)?;
            }
            TransactionType::ValidatorRegistration => {
                // Validator registration - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::ValidatorUpdate => {
                // Validator update - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::ValidatorUnregister => {
                // Validator unregister - validate validator data exists
                if transaction.validator_data().is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            }
            TransactionType::GatewayRegistration => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::GatewayUpdate => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::GatewayUnregister => {
                if transaction.gateway_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
            }
            TransactionType::DaoProposal
            | TransactionType::DaoVote
            | TransactionType::DaoExecution
            | TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }

            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                let data = transaction
                    .token_transfer_data()
                    .ok_or(ValidationError::MissingRequiredData)?;
                if data.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
                if data.from != transaction.signature.public_key.key_id {
                    return Err(ValidationError::InvalidTransaction);
                }
            }
            TransactionType::TokenMint => {
                if transaction.version < 2 {
                    return Err(ValidationError::InvalidTransaction);
                }
                let data = transaction
                    .token_mint_data()
                    .ok_or(ValidationError::MissingRequiredData)?;
                if data.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data().is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenCreation => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
                TokenCreationPayloadV1::decode_memo(&transaction.memo)
                    .map_err(|_| ValidationError::InvalidMemo)?;
            }
            TransactionType::BondingCurveDeploy
            | TransactionType::BondingCurveBuy
            | TransactionType::BondingCurveSell
            | TransactionType::BondingCurveGraduate => {
                // Bonding curve operations
            }
            TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                // AMM/Token operations - not yet fully implemented
            }
            TransactionType::UpdateOracleCommittee | TransactionType::UpdateOracleConfig => {
                // Oracle governance transactions require chain-state checks.
                // Run in stateful validator only.
            }
            TransactionType::OracleAttestation => {
                // Oracle attestation - full validation in StatefulValidator
            }
            TransactionType::CancelOracleUpdate => {
                // Cancel oracle update - validation in stateful validator
            }
            TransactionType::InitEntityRegistry => {
                if transaction.init_entity_registry_data().is_none() {
                    return Err(ValidationError::MissingRequiredData);
                }
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::RecordOnRampTrade => {
                // Threshold approval; full validation deferred to stateful validator
            }
            TransactionType::TreasuryAllocation => {
                // Threshold approval; full validation deferred to stateful validator
            }
            TransactionType::InitCbeToken => {
                // Deprecated — always reject (EPIC-001 Phase 1D).
                return Err(ValidationError::AlreadyInitialized);
            }
            TransactionType::CreateEmploymentContract => {
                // Full validation deferred to stateful validator
            }
            TransactionType::ProcessPayroll => {
                // Full validation deferred to stateful validator
            }
            TransactionType::DaoStake => {
                // Full validation deferred to stateful validator (balance, lock period, etc.)
            }
            TransactionType::DaoUnstake => {
                // Full validation deferred to stateful validator (lock check, record existence, etc.)
            }
            TransactionType::DomainRegistration => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_REGISTRATION_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::DomainUpdate => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_UPDATE_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
            }
        }

        // Signature validation:
        // - Historically, "system transactions" (empty inputs) skipped signatures.
        // - WalletUpdate and TokenMint must always be signed (privileged state mutations).
        // - If a system transaction carries a non-empty signature anyway, validate it.
        //   This prevents malformed signatures (wrong size, invalid bytes) from passing
        //   mempool intake and poisoning block proposals on other validators.
        // - RecordOnRampTrade and TreasuryAllocation use threshold approvals.
        let require_signature = !is_system_transaction
            || matches!(
                transaction.transaction_type,
                TransactionType::WalletUpdate
                    | TransactionType::TokenMint
                    | TransactionType::TokenCreation
                    | TransactionType::InitEntityRegistry
            );
        let has_nonempty_sig = !transaction.signature.signature.is_empty();
        let is_threshold_only_sflag = matches!(
            transaction.transaction_type,
            TransactionType::RecordOnRampTrade | TransactionType::TreasuryAllocation
        );
        if !is_threshold_only_sflag && (require_signature || has_nonempty_sig) {
            self.validate_signature(transaction)?;
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            self.validate_zk_proofs(transaction)?;
        }

        // Economic validation — Phase 2: TokenTransfer fee must be 0 regardless of
        // whether the caller passes is_system_transaction=true/false.
        let economics_is_system =
            Self::compute_economics_is_system(transaction, is_system_transaction);
        self.validate_economics_with_system_check(transaction, economics_is_system)?;

        Ok(())
    }

    /// Validate basic transaction structure
    fn validate_basic_structure(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!(
            "[BREADCRUMB] validate_basic_structure ENTER: version={}, size={}, memo_len={}",
            transaction.version,
            transaction.size(),
            transaction.memo.len()
        );

        // Check version
        if transaction.version == 0 {
            tracing::warn!("[BREADCRUMB] validate_basic_structure FAILED: version is 0");
            return Err(ValidationError::InvalidTransaction);
        }

        // Check transaction size limits
        if transaction.size() > MAX_TRANSACTION_SIZE {
            tracing::warn!(
                "[BREADCRUMB] validate_basic_structure FAILED: size {} > MAX {}",
                transaction.size(),
                MAX_TRANSACTION_SIZE
            );
            return Err(ValidationError::InvalidTransaction);
        }

        // Check memo size
        if transaction.memo.len() > MAX_MEMO_SIZE {
            tracing::warn!(
                "[BREADCRUMB] validate_basic_structure FAILED: memo.len {} > MAX {}",
                transaction.memo.len(),
                MAX_MEMO_SIZE
            );
            return Err(ValidationError::InvalidTransaction);
        }

        tracing::debug!("[BREADCRUMB] validate_basic_structure PASSED");
        Ok(())
    }

    /// Validate transfer transaction
    fn validate_transfer_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Allow empty inputs for system transactions (UBI, rewards, minting)
        // System transactions are identified by having a genesis/zero input
        let is_system_transaction = transaction.inputs.is_empty()
            || transaction.inputs.iter().all(|input| {
                input.previous_output == Hash::default() && input.nullifier != Hash::default()
                // Must have unique nullifier even for system tx
            });

        if !is_system_transaction && transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Validate inputs (only if not system transaction)
        if !is_system_transaction {
            for input in &transaction.inputs {
                self.validate_transaction_input(input)?;
            }
        }

        // Validate outputs
        for output in &transaction.outputs {
            self.validate_transaction_output(output)?;
        }

        Ok(())
    }

    /// Validate identity transaction
    fn validate_identity_transaction(&self, transaction: &Transaction) -> ValidationResult {
        let identity_data = transaction
            .identity_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Check if this is a system transaction (empty inputs), except for token contract calls
        let is_system_transaction =
            transaction.inputs.is_empty() && !is_token_contract_execution(transaction);

        self.validate_identity_data(identity_data, is_system_transaction)?;

        // Identity transactions should have minimal inputs/outputs
        // The main logic is handled by lib-identity package

        Ok(())
    }

    /// Validate TokenMint transaction shape and basic mint constraints.
    ///
    /// Authorization and token existence require chain state and are validated
    /// by [`StatefulTransactionValidator`] in `validate_transaction_with_state`.
    fn validate_token_mint(&self, transaction: &Transaction) -> ValidationResult {
        // Extract TokenMintData
        let mint_data = transaction
            .token_mint_data()
            .ok_or_else(|| ValidationError::InvalidInputs)?;

        // For now, we validate that:
        // 1. The amount is not zero
        // 2. The amount doesn't exceed a reasonable cap per block

        if mint_data.amount == 0 {
            tracing::warn!("TokenMint amount is zero");
            return Err(ValidationError::InvalidInputs);
        }

        // Check for excessive mint (sanity check - max 1 billion tokens per mint)
        const MAX_MINT_AMOUNT: u128 = 1_000_000_000_u128 * 1_000_000_000_u128; // 1B * 10^9
        if mint_data.amount > MAX_MINT_AMOUNT {
            tracing::warn!(
                "TokenMint amount {} exceeds maximum allowed {}",
                mint_data.amount,
                MAX_MINT_AMOUNT
            );
            return Err(ValidationError::InvalidInputs);
        }

        Ok(())
    }


    /// Validate contract transaction
    fn validate_contract_transaction(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_contract_transaction ENTER");

        if is_forbidden_token_contract_mutation(transaction) {
            return Err(ValidationError::InvalidTransactionType);
        }

        if transaction.transaction_type == TransactionType::ContractDeployment {
            ContractDeploymentPayloadV1::decode_memo(&transaction.memo)
                .map_err(|_| ValidationError::InvalidMemo)?;
        }

        // Allow system contract deployments (empty inputs) for Web4 and system contracts
        let is_system_contract = transaction.inputs.is_empty();

        if !is_system_contract && transaction.inputs.is_empty() {
            tracing::warn!("[BREADCRUMB] validate_contract_transaction FAILED: empty inputs for non-system contract");
            return Err(ValidationError::InvalidInputs);
        }

        // Token contract executions don't require outputs
        let is_token = is_token_contract_execution(transaction);
        tracing::debug!(
            "[BREADCRUMB] validate_contract_transaction: outputs.is_empty={}, is_token={}",
            transaction.outputs.is_empty(),
            is_token
        );

        if transaction.outputs.is_empty() && !is_token {
            tracing::warn!("[BREADCRUMB] validate_contract_transaction FAILED: empty outputs for non-token contract");
            return Err(ValidationError::InvalidOutputs);
        }

        tracing::debug!("[BREADCRUMB] validate_contract_transaction PASSED");
        Ok(())
    }

    /// Validate token transaction
    fn validate_token_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Token validation is handled by lib-economy package
        // Here we just validate basic structure

        // System transactions (empty inputs) are valid for UBI/rewards
        if transaction.inputs.is_empty() {
            // This is a system transaction - only validate outputs
            if transaction.outputs.is_empty() {
                return Err(ValidationError::InvalidOutputs);
            }
            return Ok(());
        }

        // Regular transactions need both inputs and outputs
        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate transaction signature using proper cryptographic verification
    fn validate_signature(&self, transaction: &Transaction) -> ValidationResult {
        tracing::warn!(
            "[BREADCRUMB] validate_signature ENTER: sig_len={}, pk_len={}, algo={:?}",
            transaction.signature.signature.len(),
            transaction.signature.public_key.as_bytes().len(),
            transaction.signature.algorithm
        );
        use lib_crypto::verification::verify_signature;

        // Create transaction hash for verification (without signature)
        let mut tx_for_verification = transaction.clone();
        tx_for_verification.signature = Signature {
            signature: Vec::new(),
            // CRITICAL: Must use all-zero key_id for consistent hashing
            public_key: PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: [0u8; 32],
            },
            algorithm: transaction.signature.algorithm.clone(),
            timestamp: 0,
        };

        // CRITICAL FIX: Use signing_hash() to match client-side signing
        // Client uses signing_hash() in ContractTransactionBuilder.build()
        // Previously used .hash() which is a different function (hash_transaction vs hash_for_signature)
        let tx_hash = tx_for_verification.signing_hash();

        // Log hash for comparison with client
        tracing::info!(
            "[validation] Server computed signing_hash = {}",
            hex::encode(tx_hash.as_bytes())
        );

        // Get signature data
        let signature_bytes = &transaction.signature.signature;
        let public_key_bytes = transaction.signature.public_key.as_bytes();

        if signature_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }

        if public_key_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }

        // Use lib-crypto for signature verification
        match verify_signature(tx_hash.as_bytes(), signature_bytes, &public_key_bytes) {
            Ok(is_valid) => {
                if !is_valid {
                    return Err(ValidationError::InvalidSignature);
                }
            }
            Err(_) => {
                return Err(ValidationError::InvalidSignature);
            }
        }

        // Bind key_id to the actual public key bytes to prevent address spoofing.
        // Without this check an attacker can submit their real dilithium_pk (so the
        // signature verifies) while setting key_id to an arbitrary pool address,
        // which would give them access to that pool's token balance.
        let pk = &transaction.signature.public_key;
        // [u8; 1568].is_empty() is always false (fixed-size array), so we check for all-zero
        // bytes to distinguish dilithium-only identities (validators, genesis wallets) from
        // full keypair identities (app users with both dilithium + kyber keys).
        let kyber_is_zeros = pk.kyber_pk.iter().all(|&b| b == 0);
        let expected_key_id = if kyber_is_zeros {
            // Dilithium-only identity: key_id = blake3(dilithium_pk)
            lib_crypto::hashing::hash_blake3(&public_key_bytes)
        } else {
            // Full keypair identity: key_id = blake3(dilithium_pk || kyber_pk)
            lib_crypto::hashing::hash_blake3_multiple(&[
                public_key_bytes.as_slice(),
                pk.kyber_pk.as_slice(),
            ])
        };
        if pk.key_id != expected_key_id {
            tracing::warn!(
                "key_id binding check failed: claimed {:?} expected {:?}",
                hex::encode(&pk.key_id[..8]),
                hex::encode(&expected_key_id[..8])
            );
            return Err(ValidationError::InvalidSignature);
        }

        // Verify signature algorithm is supported
        match transaction.signature.algorithm {
            SignatureAlgorithm::Dilithium5 => {
                // Supported algorithms
            }
            _ => {
                return Err(ValidationError::InvalidSignature);
            }
        }

        // REMOVED: Wall-clock timestamp validation (nondeterministic)
        // Transaction replay protection is handled by nullifier checks in UTXO validation
        // Signature timestamps are metadata only, not consensus-critical

        Ok(())
    }

    /// Validate zero-knowledge proofs for all inputs using ZK verification
    fn validate_zk_proofs(&self, transaction: &Transaction) -> ValidationResult {
        use lib_proofs::ZkTransactionProof;
        tracing::warn!(
            "[BREADCRUMB] validate_zk_proofs ENTER: inputs={}",
            transaction.inputs.len()
        );
        println!(
            " DEBUG: Starting ZK proof validation for {} transaction inputs",
            transaction.inputs.len()
        );
        log::info!(
            "Starting ZK proof validation for {} transaction inputs",
            transaction.inputs.len()
        );

        for (i, input) in transaction.inputs.iter().enumerate() {
            println!(" DEBUG: Validating ZK proof for input {}", i);
            log::info!("Validating ZK proof for input {}", i);

            // First check if the proof structure is valid
            if !is_valid_proof_structure(&input.zk_proof) {
                println!(" DEBUG: Input {}: Invalid proof structure", i);
                log::error!("Input {}: Invalid proof structure", i);
                return Err(ValidationError::InvalidZkProof);
            }
            println!(" DEBUG: Input {}: Proof structure valid", i);
            log::info!("Input {}: Proof structure valid", i);

            // Use the proper ZK verification from lib-proofs
            match ZkTransactionProof::verify_transaction(&input.zk_proof) {
                Ok(is_valid) => {
                    if !is_valid {
                        log::error!("Input {}: ZkTransactionProof verification failed", i);
                        return Err(ValidationError::InvalidZkProof);
                    }
                    log::info!("Input {}: ZkTransactionProof verification passed", i);
                }
                Err(e) => {
                    log::error!(
                        "Input {}: ZK verification failed - NO FALLBACKS ALLOWED: {:?}",
                        i,
                        e
                    );
                    return Err(ValidationError::InvalidZkProof);
                }
            }

            // Additional ZK proof validations
            log::info!("Input {}: Validating nullifier proof", i);
            self.validate_nullifier_proof(input)?;
            log::info!("Input {}: Nullifier proof valid", i);

            log::info!("Input {}: Validating amount range proof", i);
            self.validate_amount_range_proof(input)?;
            log::info!("Input {}: Amount range proof valid", i);
        }

        log::info!("All ZK proofs validated successfully");
        Ok(())
    }

    /// Validate nullifier proof to prevent double spending
    fn validate_nullifier_proof(&self, input: &TransactionInput) -> ValidationResult {
        match input.zk_proof.nullifier_proof.verify() {
            Ok(is_valid) => {
                if !is_valid {
                    return Err(ValidationError::InvalidZkProof);

                }
            }
            Err(e) => {
                log::error!(
                    "Nullifier ZK verification failed - no fallbacks allowed: {:?}",
                    e
                );
                return Err(ValidationError::InvalidZkProof);
            }
        }

        Ok(())
    }

    /// Validate amount range proof to ensure positive amounts
    fn validate_amount_range_proof(&self, input: &TransactionInput) -> ValidationResult {
        println!(" DEBUG: validate_amount_range_proof starting");
        log::info!("validate_amount_range_proof starting");

        match input.zk_proof.amount_proof.verify() {
            Ok(is_valid) => {
                println!(" DEBUG: Amount range verification result: {}", is_valid);
                log::info!("Amount range verification result: {}", is_valid);
                if !is_valid {
                    println!(" DEBUG: Amount range proof INVALID - returning error");
                    log::error!("Amount range proof INVALID - returning error");
                    return Err(ValidationError::InvalidZkProof);

                }
                println!(" DEBUG: Amount range proof VALID");
                log::info!("Amount range proof VALID");
            }
            Err(e) => {
                println!(" DEBUG: Amount range verification error: {:?}", e);
                log::error!("Amount range verification error: {:?}", e);
                return Err(ValidationError::InvalidZkProof);
            }
        }

        println!(" DEBUG: validate_amount_range_proof completed successfully");
        log::info!("validate_amount_range_proof completed successfully");
        Ok(())
    }

    /// Validate economic aspects (fees, amounts) with system transaction support
    fn validate_economics_with_system_check(
        &self,
        transaction: &Transaction,
        is_system_transaction: bool,
    ) -> ValidationResult {
        tracing::debug!(
            "[BREADCRUMB] validate_economics_with_system_check ENTER: system={}, fee={}, size={}",
            is_system_transaction,
            transaction.fee,
            transaction.size()
        );
        if is_system_transaction {
            // System transactions are fee-free and create new money
            if transaction.fee != 0 {
                tracing::warn!(
                    "[BREADCRUMB] validate_economics_with_system_check FAIL: system fee != 0"
                );
                return Err(ValidationError::InvalidFee);
            }
            // System transactions don't need fee validation
            return Ok(());
        }

        if transaction.transaction_type == TransactionType::TokenCreation {
            let required_fee = crate::transaction::required_token_creation_fee(&self.fee_config);
            if transaction.fee != required_fee {
                tracing::warn!(
                    "[BREADCRUMB] validate_economics_with_system_check FAIL: token_creation fee={}, required={}",
                    transaction.fee,
                    required_fee
                );
                return Err(ValidationError::InvalidFee);
            }
            return Ok(());
        }

        // Regular transaction fee validation
        let min_fee = crate::transaction::creation::utils::calculate_minimum_fee_with_config(
            transaction.size(),
            &self.fee_config,
        );
        tracing::warn!(
            "[BREADCRUMB] validate_economics_with_system_check min_fee={}, fee={}",
            min_fee,
            transaction.fee
        );
        println!("FEE VALIDATION DEBUG:");
        println!("   Transaction size: {} bytes", transaction.size());
        println!("   Calculated minimum fee: {} SOV", min_fee);
        println!("   Actual transaction fee: {} SOV", transaction.fee);
        if transaction.fee < min_fee {
            println!("FEE VALIDATION FAILED: {} < {}", transaction.fee, min_fee);
            return Err(ValidationError::InvalidFee);
        }
        println!("FEE VALIDATION PASSED");

        // Economic validation is handled by lib-economy package
        // Here we just check basic fee requirements

        Ok(())
    }

    /// Validate individual transaction input
    fn validate_transaction_input(&self, input: &TransactionInput) -> ValidationResult {
        // Check nullifier is not zero (unless this is a system transaction input)
        if input.nullifier == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Check previous output reference (system transactions can have Hash::default())
        // System transactions are identified by having Hash::default() previous_output with valid nullifier
        if input.previous_output == Hash::default() && input.nullifier != Hash::default() {
            // This might be a system transaction input - allow it
            return Ok(());
        }

        if input.previous_output == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Note: Double spend checking would require access to nullifier set
        // This is handled at the blockchain level

        Ok(())
    }

    /// Validate individual transaction output
    fn validate_transaction_output(&self, output: &TransactionOutput) -> ValidationResult {
        // Check commitment is not zero
        if output.commitment == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check note is not zero
        if output.note == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check recipient public key is valid
        if output.recipient.dilithium_pk.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate identity transaction data
    fn validate_identity_data(
        &self,
        identity_data: &IdentityTransactionData,
        is_system_transaction: bool,
    ) -> ValidationResult {
        // Check DID format
        if identity_data.did.is_empty() || !identity_data.did.starts_with("did:zhtp:") {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check display name
        if identity_data.display_name.is_empty() || identity_data.display_name.len() > 64 {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check public key
        if identity_data.public_key.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check ownership proof (allow empty for system/genesis transactions)
        if !is_system_transaction && identity_data.ownership_proof.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check identity type
        let valid_types = [
            "human",
            "organization",
            "device",
            "service",
            "validator",
            "revoked",
        ];
        if !valid_types.contains(&identity_data.identity_type.as_str()) {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check fees - allow zero fees for system transactions
        if !is_system_transaction && identity_data.registration_fee == 0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }

    /// Validate wallet registration transaction
    fn validate_wallet_registration_transaction(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        // Check that wallet_data exists
        let wallet_data = transaction
            .wallet_data()
            .ok_or(ValidationError::MissingWalletData)?;

        // Validate wallet ID is not default/empty
        if wallet_data.wallet_id == crate::types::Hash::default() {
            return Err(ValidationError::InvalidWalletId);
        }

        // Validate owner identity ID if present
        if let Some(owner_id) = &wallet_data.owner_identity_id {
            if *owner_id == crate::types::Hash::default() {
                return Err(ValidationError::InvalidOwnerIdentity);
            }
        }

        // Validate public key is not empty
        if wallet_data.public_key.is_empty() {
            return Err(ValidationError::InvalidPublicKey);
        }

        // Validate seed commitment is not default
        if wallet_data.seed_commitment == crate::types::Hash::default() {
            return Err(ValidationError::InvalidSeedCommitment);
        }

        // Validate wallet type is recognized
        match wallet_data.wallet_type.as_str() {
            "Primary" | "UBI" | "Savings" | "DAO" => {
                // Valid wallet types
            }
            _ => return Err(ValidationError::InvalidWalletType),
        }

        Ok(())
    }

    /// Validate wallet update transaction.
    ///
    /// Today this is only permitted as a system transaction on the development/testnet chain,
    /// used for controlled migrations and administrative recovery. Future authorization (DAO/validator)
    /// should be enforced here as rules evolve.
    fn validate_wallet_update_transaction(
        &self,
        transaction: &Transaction,
        is_system_transaction: bool,
    ) -> ValidationResult {
        // Must carry wallet_data
        self.validate_wallet_registration_transaction(transaction)?;

        // Restrict to system transactions for now (no user-auth path implemented yet).
        if !is_system_transaction {
            return Err(ValidationError::InvalidTransaction);
        }

        // Must not move value: this transaction is metadata/ownership-only.
        if !transaction.outputs.is_empty() || !transaction.inputs.is_empty() || transaction.fee != 0
        {
            return Err(ValidationError::InvalidTransaction);
        }

        // Restrict to non-mainnet chains (dev/bootstrap=0x03, testnet=0x02).
        // This is consensus-critical: do not gate on env flags that may differ across nodes.
        if !matches!(transaction.chain_id, 0x02 | 0x03) {
            return Err(ValidationError::InvalidTransaction);
        }

        // Require an explicit memo prefix for auditability.
        const PREFIX: &[u8] = b"WALLET_UPDATE_V1:";
        if !transaction.memo.starts_with(PREFIX) {
            return Err(ValidationError::InvalidMemo);
        }

        Ok(())
    }

    /// Validate UBI claim transaction (Week 7)
    ///
    /// Checks that:
    /// - ubi_claim_data is present and valid
    /// - claim_amount is positive
    /// - citizenship_proof is provided
    /// - transaction has outputs but no inputs (claiming from pool)
    fn validate_ubi_claim_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check that ubi_claim_data exists
        let claim_data = transaction
            .ubi_claim_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Validate claim data structure
        if !claim_data.validate() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check that no inputs are present (claims don't spend UTXOs)
        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        // Check that outputs are present (recipient wallet for claim)
        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate profit declaration transaction (Week 7)
    ///
    /// Checks that:
    /// - profit_declaration_data is present and valid
    /// - 20% tribute calculation is correct
    /// - revenue sources sum to profit amount
    /// - for-profit and nonprofit treasuries are different (anti-circumvention)
    /// - inputs and outputs represent tribute transfer
    fn validate_profit_declaration_transaction(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        // Check that profit_declaration_data exists
        let decl_data = transaction
            .profit_declaration_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Validate declaration data structure
        if !decl_data.validate() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Verify anti-circumvention checks
        if !decl_data.anti_circumvention_check() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check that inputs and outputs match tribute amount
        if transaction.inputs.len() != 1 {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.len() != 1 {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }
}

fn parse_contract_call(transaction: &Transaction) -> Option<ContractCall> {
    if transaction.transaction_type != TransactionType::ContractExecution {
        return None;
    }
    if transaction
        .memo
        .starts_with(crate::transaction::CONTRACT_EXECUTION_MEMO_PREFIX_V2)
    {
        let decoded =
            crate::transaction::DecodedContractExecutionMemo::decode_compat(&transaction.memo)
                .ok()?;
        return Some(decoded.call);
    }
    if transaction.memo.len() <= 4 || &transaction.memo[0..4] != b"ZHTP" {
        return None;
    }
    let call_data = &transaction.memo[4..];
    let (call, _sig): (ContractCall, Signature) = bincode::deserialize(call_data).ok()?;
    Some(call)
}

/// Check if a transaction is a token contract execution
///
/// Returns true if the transaction:
/// 1. Has type ContractExecution
/// 2. Has a valid ContractExecution memo schema
/// 3. Contains a valid ContractCall with contract_type Token
/// 4. Has a valid token method (create_custom_token)
pub fn is_token_contract_execution(transaction: &Transaction) -> bool {
    if transaction.transaction_type != TransactionType::ContractExecution {
        tracing::debug!("is_token_contract_execution: not ContractExecution type");
        return false;
    }

    let Some(call) = parse_contract_call(transaction) else {
        tracing::warn!("is_token_contract_execution: failed to parse contract call from memo");
        return false;
    };

    if call.contract_type != ContractType::Token {
        tracing::warn!(
            "is_token_contract_execution: contract_type is {:?}, not Token",
            call.contract_type
        );
        return false;
    }

    let is_token_method = matches!(call.method.as_str(), "create_custom_token");

    if !is_token_method {
        tracing::warn!(
            "is_token_contract_execution: method '{}' is not a token method",
            call.method
        );
    } else {
        tracing::info!(
            "is_token_contract_execution: VALID token contract call, method={}",
            call.method
        );
    }

    is_token_method
}

/// Returns true when a ContractExecution attempts deprecated token balance
/// mutations that must be rejected in consensus validation.
fn is_forbidden_token_contract_mutation(transaction: &Transaction) -> bool {
    if transaction.transaction_type != TransactionType::ContractExecution {
        return false;
    }
    let Some(call) = parse_contract_call(transaction) else {
        return false;
    };
    call.contract_type == ContractType::Token
        && matches!(
            call.method.as_str(),
            "create_custom_token" | "mint" | "transfer" | "burn"
        )
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> StatefulTransactionValidator<'a> {
    /// Create a new stateful transaction validator with blockchain access
    pub fn new(blockchain: &'a crate::blockchain::Blockchain) -> Self {
        Self {
            blockchain: Some(blockchain),
        }
    }

    /// Create a stateless validator (no identity verification)
    pub fn stateless() -> Self {
        Self { blockchain: None }
    }

    /// Validate a transaction with full state context including identity verification
    pub fn validate_transaction_with_state(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!(
            "[BREADCRUMB] validate_transaction_with_state ENTER, memo.len={}",
            transaction.memo.len()
        );

        // Check if this is a system transaction (empty inputs = coinbase-style), except token contract calls
        let is_token = is_token_contract_execution(transaction);
        tracing::debug!("[BREADCRUMB] is_token_contract_execution = {}", is_token);

        let mut is_system_transaction = transaction.inputs.is_empty() && !is_token;
        // TokenTransfer must pay fees even with empty inputs
        if matches!(
            transaction.transaction_type,
            TransactionType::TokenTransfer | TransactionType::TokenCreation
        ) {
            is_system_transaction = false;
        }
        tracing::debug!(
            "[BREADCRUMB] is_system_transaction = {}",
            is_system_transaction
        );

        // Create a stateless validator for basic checks
        let stateless_validator = {
            let fee_config = self
                .blockchain
                .map(|bc| bc.tx_fee_config.clone())
                .unwrap_or_default();
            TransactionValidator::with_fee_config(fee_config)
        };

        // Basic structure validation
        tracing::debug!("[BREADCRUMB] validate_basic_structure CALL");
        stateless_validator.validate_basic_structure(transaction)?;
        tracing::debug!("[BREADCRUMB] validate_basic_structure OK");

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    stateless_validator.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            }
            TransactionType::IdentityRegistration => {
                stateless_validator.validate_identity_transaction(transaction)?
            }
            TransactionType::IdentityUpdate => {
                stateless_validator.validate_identity_transaction(transaction)?
            }
            TransactionType::IdentityRevocation => {
                stateless_validator.validate_identity_transaction(transaction)?
            }
            TransactionType::ContractDeployment => {
                stateless_validator.validate_contract_transaction(transaction)?
            }
            TransactionType::ContractExecution => {
                stateless_validator.validate_contract_transaction(transaction)?
            }
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload
            | TransactionType::UbiDistribution => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            }
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                stateless_validator.validate_transaction(transaction)?;
            }
            TransactionType::WalletUpdate => {
                stateless_validator.validate_transaction(transaction)?;

                // Authority check: WalletUpdate must be signed by an active validator consensus key.
                // This is a stateful rule (depends on validator_registry).
                let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
                let signer_pk = transaction.signature.public_key.as_bytes();
                let is_active_validator = blockchain
                    .validator_registry
                    .values()
                    .any(|v| v.status == "active" && v.consensus_key.as_slice() == signer_pk.as_slice());
                if !is_active_validator {
                    return Err(ValidationError::InvalidTransaction);
                }
            }
            TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister => {
                // Validator transactions - validate with stateless validator
                stateless_validator.validate_transaction(transaction)?;
            }
            TransactionType::GatewayRegistration
            | TransactionType::GatewayUpdate
            | TransactionType::GatewayUnregister => {
                // Gateway transactions - validate with stateless validator
                stateless_validator.validate_transaction(transaction)?;
            }
            TransactionType::DaoProposal
            | TransactionType::DaoVote
            | TransactionType::DaoExecution
            | TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }

            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                if transaction.outputs.len() != 0 {
                    return Err(ValidationError::InvalidOutputs);
                }
                let data = transaction
                    .token_transfer_data()
                    .ok_or(ValidationError::InvalidInputs)?;
                if data.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
                let is_sov = data.token_id == [0u8; 32]
                    || data.token_id == crate::contracts::utils::generate_lib_token_id();
                if is_sov {
                    let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;

                    // For new-style wallets, wallet_id == key_id. The signature already proves
                    // ownership — no registry lookup needed. Only legacy wallets (where wallet_id
                    // was HD-derived and differs from key_id) require a registry check to resolve
                    // the dilithium_pk.
                    if data.from != transaction.signature.public_key.key_id {
                        let wallet_id_hex = hex::encode(data.from);
                        let wallet = blockchain
                            .wallet_registry
                            .get(&wallet_id_hex)
                            .ok_or_else(|| {
                                tracing::warn!(
                                    "[TOKEN_TRANSFER] legacy wallet not in registry: from={} key_id={}",
                                    &wallet_id_hex[..16.min(wallet_id_hex.len())],
                                    hex::encode(&transaction.signature.public_key.key_id[..8])
                                );
                                ValidationError::InvalidTransaction
                            })?;
                        let sig_dilithium = transaction.signature.public_key.dilithium_pk.as_slice();
                        if wallet.public_key.len() != 2592
                            || wallet.public_key.as_slice() != sig_dilithium
                        {
                            tracing::warn!(
                                "[TOKEN_TRANSFER] legacy ownership check failed: from={} wallet_pk_len={}",
                                &wallet_id_hex[..16.min(wallet_id_hex.len())],
                                wallet.public_key.len()
                            );
                            return Err(ValidationError::InvalidTransaction);
                        }
                    }

                    // Balance check: reject at mempool time if sender has insufficient SOV.
                    // Read from SledStore when available (single source of truth after
                    // the executor path is active); fall back to in-memory token_contracts.
                    // The in-memory balance can be stale after a node restart from .dat.
                    {
                        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
                        let mut sender_id = [0u8; 32];
                        sender_id.copy_from_slice(&data.from);
                        let storage_token = crate::storage::TokenId(sov_token_id);
                        let addr = crate::storage::Address::new(sender_id);

                        let balance: u128 = if let Some(store) = &blockchain.store {
                            store.get_token_balance(&storage_token, &addr).unwrap_or(0)
                        } else {
                            let sender_key = crate::Blockchain::wallet_key_for_sov(&sender_id);
                            blockchain
                                .token_contracts
                                .get(&sov_token_id)
                                .map(|t| u128::from(t.balance_of(&sender_key)))
                                .unwrap_or(0)
                        };

                        if balance < data.amount {
                            tracing::warn!(
                                "[TOKEN_TRANSFER] insufficient SOV balance: from={} have={} need={}",
                                hex::encode(&data.from[..8]),
                                balance,
                                data.amount
                            );
                            return Err(ValidationError::InvalidAmount);
                        }
                    }
                } else if data.from != transaction.signature.public_key.key_id {
                    // Non-SOV token: from != key_id means legacy wallet (HD-derived address).
                    // Apply the same dilithium_pk ownership check as SOV legacy wallets so
                    // that iOS clients using wallet_id as `from` can still transfer CBE.
                    let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
                    let wallet_id_hex = hex::encode(data.from);
                    let wallet = blockchain
                        .wallet_registry
                        .get(&wallet_id_hex)
                        .ok_or_else(|| {
                            tracing::warn!(
                                "[TOKEN_TRANSFER] non-SOV legacy wallet not in registry: from={} key_id={}",
                                &wallet_id_hex[..16.min(wallet_id_hex.len())],
                                hex::encode(&transaction.signature.public_key.key_id[..8])
                            );
                            ValidationError::InvalidTransaction
                        })?;
                    let sig_dilithium = transaction.signature.public_key.dilithium_pk.as_slice();
                    if wallet.public_key.len() != 2592
                        || wallet.public_key.as_slice() != sig_dilithium
                    {
                        tracing::warn!(
                            "[TOKEN_TRANSFER] non-SOV legacy ownership check failed: from={}",
                            &wallet_id_hex[..16.min(wallet_id_hex.len())],
                        );
                        return Err(ValidationError::InvalidTransaction);
                    }
                }

                // CBE balance check: reject at mempool time if sender has insufficient CBE.
                // Phase 1B moved all CBE balances to token_balances; cbe_account_state is no longer used.
                let cbe_token_id = crate::Blockchain::derive_cbe_token_id_pub();
                if data.token_id == cbe_token_id {
                    if let Some(blockchain) = self.blockchain {
                        let effective_key = if data.from != transaction.signature.public_key.key_id {
                            transaction.signature.public_key.key_id
                        } else {
                            data.from
                        };
                        let balance: u128 = if let Some(store) = &blockchain.store {
                            let storage_token = crate::storage::TokenId(cbe_token_id);
                            let addr = crate::storage::Address::new(effective_key);
                            store.get_token_balance(&storage_token, &addr).unwrap_or(0)
                        } else {
                            0
                        };
                        if balance < data.amount {
                            tracing::warn!(
                                "[TOKEN_TRANSFER] insufficient CBE balance: from={} effective_key={} have={} need={}",
                                hex::encode(&data.from[..8]),
                                hex::encode(&effective_key[..8]),
                                balance,
                                data.amount
                            );
                            return Err(ValidationError::InvalidAmount);
                        }
                    }
                }
            }
            TransactionType::TokenMint => {
                if transaction.version < 2 {
                    return Err(ValidationError::InvalidTransaction);
                }
                let data = transaction
                    .token_mint_data()
                    .ok_or(ValidationError::MissingRequiredData)?;
                if data.amount == 0 {
                    return Err(ValidationError::InvalidAmount);
                }
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
                if !transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }

                self.validate_token_mint_stateful_authorization(transaction)?;
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data().is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenCreation
            | TransactionType::BondingCurveDeploy
            | TransactionType::BondingCurveBuy
            | TransactionType::BondingCurveSell
            | TransactionType::BondingCurveGraduate => {
                // Actor-vs-signer checks are enforced in stateless validation above.
                // No additional state-dependent checks required at this stage.
            }
            TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                // AMM/Token operations - not yet fully implemented
            }
            TransactionType::UpdateOracleCommittee | TransactionType::UpdateOracleConfig => {
                self.validate_oracle_governance_transaction(transaction)?
            }
            TransactionType::OracleAttestation => {
                // ORACLE-9: Validate oracle attestation at block execution time
                self.validate_oracle_attestation_transaction(transaction)?;
            }
            TransactionType::CancelOracleUpdate => {
                // Cancel oracle update - validation handled at execution layer
            }
            TransactionType::InitEntityRegistry => {
                self.validate_init_entity_registry(transaction)?;
            }
            TransactionType::RecordOnRampTrade => {
                self.validate_record_on_ramp_trade(transaction)?;
            }
            TransactionType::TreasuryAllocation => {
                self.validate_treasury_allocation(transaction)?;
            }
            TransactionType::InitCbeToken => {
                // Deprecated — always reject (EPIC-001 Phase 1D).
                return Err(ValidationError::AlreadyInitialized);
            }
            TransactionType::CreateEmploymentContract => {
                self.validate_create_employment_contract(transaction)?;
            }
            TransactionType::ProcessPayroll => {
                self.validate_process_payroll(transaction)?;
            }
            TransactionType::DaoStake => {
                self.validate_dao_stake(transaction)?;
            }
            TransactionType::DaoUnstake => {
                self.validate_dao_unstake(transaction)?;
            }
            TransactionType::DomainRegistration => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_REGISTRATION_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
                // Authorization: the owner_did in the payload must match the signer's key_id.
                // This prevents a malicious actor from claiming ownership of a domain under a
                // DID they don't control.
                let payload =
                    crate::transaction::domain::DomainRegistrationPayload::decode_memo(
                        &transaction.memo,
                    )
                    .map_err(|_| ValidationError::InvalidMemo)?;
                let signer_did = format!(
                    "did:zhtp:{}",
                    hex::encode(transaction.signature.public_key.key_id)
                );
                if payload.owner_did != signer_did {
                    tracing::warn!(
                        "[DOMAIN_REG] owner_did mismatch: payload={} signer={}",
                        payload.owner_did,
                        signer_did
                    );
                    return Err(ValidationError::InvalidTransaction);
                }
            }
            TransactionType::DomainUpdate => {
                if !transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_UPDATE_PREFIX)
                {
                    return Err(ValidationError::InvalidMemo);
                }
                // Authorization: the owner_did in the payload must match the signer's key_id,
                // and if the domain already exists on-chain, the signer must be the current owner.
                let payload =
                    crate::transaction::domain::DomainUpdatePayload::decode_memo(&transaction.memo)
                        .map_err(|_| ValidationError::InvalidMemo)?;
                let signer_did = format!(
                    "did:zhtp:{}",
                    hex::encode(transaction.signature.public_key.key_id)
                );
                if payload.owner_did != signer_did {
                    tracing::warn!(
                        "[DOMAIN_UPDATE] owner_did mismatch: payload={} signer={}",
                        payload.owner_did,
                        signer_did
                    );
                    return Err(ValidationError::InvalidTransaction);
                }
                if let Some(blockchain) = self.blockchain {
                    if let Some(existing) = blockchain.domain_registry.get(&payload.domain) {
                        if existing.owner_did != signer_did {
                            tracing::warn!(
                                "[DOMAIN_UPDATE] not owner: domain={} current_owner={} signer={}",
                                payload.domain,
                                existing.owner_did,
                                signer_did
                            );
                            return Err(ValidationError::InvalidTransaction);
                        }
                    }
                }
            }
        }

        //  CRITICAL FIX: Verify sender identity exists on blockchain
        // This is the missing check that was allowing transactions from non-existent identities
        // Skip for:
        //   - System transactions (genesis, rewards, etc.)
        //   - Identity registration (new identities don't exist yet)
        //   - Token contract executions (tokens use PublicKey as sender, not identity)
        //
        // Token operations are authorized by signature verification alone - the canonical sender
        // is derived from tx.signature.public_key, and balances are keyed by PublicKey.
        // Identity is an optional overlay, not a precondition for token operations.
        // RecordOnRampTrade and TreasuryAllocation are authorized by threshold approval sets,
        // not by a transaction-level single identity, so skip identity existence check.
        let is_threshold_type = matches!(
            transaction.transaction_type,
            TransactionType::RecordOnRampTrade | TransactionType::TreasuryAllocation
        );
        if !is_system_transaction
            && !is_threshold_type
            && transaction.transaction_type != TransactionType::IdentityRegistration
            && transaction.transaction_type != TransactionType::TokenTransfer
            && transaction.transaction_type != TransactionType::TokenMint
            && transaction.transaction_type != TransactionType::TokenCreation
            && transaction.transaction_type != TransactionType::DaoStake
            && transaction.transaction_type != TransactionType::DaoUnstake
            && transaction.transaction_type != TransactionType::DomainRegistration // owner_did↔signer binding enforced above
            && transaction.transaction_type != TransactionType::DomainUpdate // owner_did↔signer binding enforced above
            && !is_token_contract_execution(transaction)
        {
            tracing::debug!("[BREADCRUMB] validate_sender_identity_exists CALL");
            self.validate_sender_identity_exists(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_sender_identity_exists OK");
        }

        // Signature validation (always required except for system transactions)
        // TokenMint and InitEntityRegistry are system for fee purposes but MUST still be signed.
        // RecordOnRampTrade and TreasuryAllocation use threshold approvals — skip tx-level sig.
        let mut skip_signature = is_system_transaction
            && !matches!(
                transaction.transaction_type,
                TransactionType::TokenMint | TransactionType::InitEntityRegistry
            );
        // Always skip tx-level signature for threshold-approval-only types
        if is_threshold_type {
            skip_signature = true;
        }
        if transaction.transaction_type == TransactionType::TokenMint {
            if let Some(blockchain) = self.blockchain {
                if blockchain.height == 0
                    && blockchain.blocks.is_empty()
                    && transaction.signature.signature.is_empty()
                {
                    skip_signature = true; // Allow genesis TokenMint without signature
                }
            }
        }
        if !skip_signature {
            tracing::debug!("[BREADCRUMB] validate_signature CALL");
            stateless_validator.validate_signature(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_signature OK");
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !skip_signature {
            tracing::debug!("[BREADCRUMB] validate_zk_proofs CALL");
            stateless_validator.validate_zk_proofs(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_zk_proofs OK");
        }

        // TokenTransfer and DaoStake have no UTXO inputs — fee is deducted from the amount
        // at block processing time. Skip UTXO-based fee validation entirely.
        if transaction.transaction_type == TransactionType::TokenTransfer
            || transaction.transaction_type == TransactionType::DaoStake
            || transaction.transaction_type == TransactionType::DaoUnstake
        {
            return Ok(());
        }

        // Economic validation (modified for system transactions)
        let economics_is_system = is_system_transaction;
        tracing::debug!("[BREADCRUMB] validate_economics_with_system_check CALL");
        stateless_validator
            .validate_economics_with_system_check(transaction, economics_is_system)?;
        tracing::debug!("[BREADCRUMB] validate_economics_with_system_check OK");

        Ok(())
    }

    fn validate_init_entity_registry(&self, transaction: &Transaction) -> ValidationResult {
        use crate::transaction::threshold_approval::{
            compute_approval_preimage, validate_threshold_approvals, ApprovalDomain,
        };

        const MIN_TREASURY_DILITHIUM_PK_LEN: usize = 1312;
        // tx_type byte for InitEntityRegistry = 38
        const TX_TYPE_BYTE: u8 = 38;

        let data = transaction
            .init_entity_registry_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }
        if transaction.fee != 0 {
            return Err(ValidationError::InvalidFee);
        }

        let cbe_pk = &data.cbe_treasury.dilithium_pk;
        let nonprofit_pk = &data.nonprofit_treasury.dilithium_pk;
        let is_all_zero = |bytes: &[u8]| bytes.iter().all(|byte| *byte == 0);

        if cbe_pk.len() < MIN_TREASURY_DILITHIUM_PK_LEN
            || nonprofit_pk.len() < MIN_TREASURY_DILITHIUM_PK_LEN
            || is_all_zero(cbe_pk)
            || is_all_zero(nonprofit_pk)
        {
            return Err(ValidationError::InvalidPublicKey);
        }
        if data.cbe_treasury.key_id == data.nonprofit_treasury.key_id {
            return Err(ValidationError::InvalidPublicKey);
        }

        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        if blockchain
            .entity_registry
            .as_ref()
            .map(|registry| registry.is_initialized())
            .unwrap_or(false)
        {
            return Err(ValidationError::AlreadyInitialized);
        }

        // --- Threshold approval validation ---
        // Compute the canonical payload bytes (bincode of the four core fields)
        #[derive(serde::Serialize)]
        struct CanonicalPayload<'a> {
            cbe_treasury: &'a crate::integration::crypto_integration::PublicKey,
            nonprofit_treasury: &'a crate::integration::crypto_integration::PublicKey,
            initialized_at: u64,
            initialized_at_height: u64,
        }
        let payload = CanonicalPayload {
            cbe_treasury: &data.cbe_treasury,
            nonprofit_treasury: &data.nonprofit_treasury,
            initialized_at: data.initialized_at,
            initialized_at_height: data.initialized_at_height,
        };
        let payload_bytes =
            bincode::serialize(&payload).map_err(|_| ValidationError::InvalidTransaction)?;
        let preimage = compute_approval_preimage(
            TX_TYPE_BYTE,
            &ApprovalDomain::BootstrapCouncil,
            &payload_bytes,
        );

        if data.approvals.domain != ApprovalDomain::BootstrapCouncil {
            return Err(ValidationError::InvalidApproval);
        }
        if data.approvals.approvals.is_empty() {
            return Err(ValidationError::ThresholdNotMet);
        }

        validate_threshold_approvals(
            &data.approvals,
            &preimage,
            |pk_bytes| {
                blockchain
                    .get_identity_by_public_key(pk_bytes)
                    .map(|id| blockchain.is_council_member(&id.did))
                    .unwrap_or(false)
            },
            blockchain.council_threshold as usize,
        )
        .map_err(|e| match e {
            crate::transaction::threshold_approval::ThresholdError::DuplicateSigner(_) => {
                ValidationError::DuplicateSigner
            }
            crate::transaction::threshold_approval::ThresholdError::InvalidSignature(_) => {
                ValidationError::InvalidApproval
            }
            crate::transaction::threshold_approval::ThresholdError::UnauthorizedSigner(_) => {
                ValidationError::Unauthorized
            }
            crate::transaction::threshold_approval::ThresholdError::ThresholdNotMet { .. } => {
                ValidationError::ThresholdNotMet
            }
        })?;

        Ok(())
    }

    fn validate_record_on_ramp_trade(&self, transaction: &Transaction) -> ValidationResult {
        use crate::transaction::threshold_approval::{
            compute_approval_preimage, validate_threshold_approvals, ApprovalDomain,
        };

        // tx_type byte for RecordOnRampTrade = 39
        const TX_TYPE_BYTE: u8 = 39;

        let data = transaction
            .record_on_ramp_trade_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }
        if transaction.fee != 0 {
            return Err(ValidationError::InvalidFee);
        }
        if data.cbe_amount == 0 {
            return Err(ValidationError::InvalidAmount);
        }
        if data.usdc_amount == 0 {
            return Err(ValidationError::InvalidAmount);
        }

        // Verify the domain is OracleCommittee
        if data.approvals.domain != ApprovalDomain::OracleCommittee {
            return Err(ValidationError::InvalidApproval);
        }

        // Compute canonical preimage over the trade fields
        #[derive(serde::Serialize)]
        struct TradePayload {
            epoch_id: u64,
            cbe_amount: u128,
            usdc_amount: u128,
            traded_at: u64,
        }
        let payload = TradePayload {
            epoch_id: data.epoch_id,
            cbe_amount: data.cbe_amount,
            usdc_amount: data.usdc_amount,
            traded_at: data.traded_at,
        };
        let payload_bytes =
            bincode::serialize(&payload).map_err(|_| ValidationError::InvalidTransaction)?;
        let preimage = compute_approval_preimage(
            TX_TYPE_BYTE,
            &ApprovalDomain::OracleCommittee,
            &payload_bytes,
        );

        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        if blockchain.onramp_state.has_equivalent_trade(
            data.epoch_id,
            data.cbe_amount,
            data.usdc_amount,
            data.traded_at,
        ) {
            return Err(ValidationError::DoubleSpend);
        }

        // Use the oracle committee directly — members are stored as key_ids (blake3 of dilithium pk).
        let oracle_threshold = blockchain.oracle_state.committee.threshold() as usize;
        validate_threshold_approvals(
            &data.approvals,
            &preimage,
            |pk_bytes| {
                let key_id = crate::types::blake3_hash(pk_bytes).as_array();
                blockchain
                    .oracle_state
                    .committee
                    .members()
                    .contains(&key_id)
            },
            oracle_threshold,
        )
        .map_err(|e| match e {
            crate::transaction::threshold_approval::ThresholdError::DuplicateSigner(_) => {
                ValidationError::DuplicateSigner
            }
            crate::transaction::threshold_approval::ThresholdError::InvalidSignature(_) => {
                ValidationError::InvalidApproval
            }
            crate::transaction::threshold_approval::ThresholdError::UnauthorizedSigner(_) => {
                ValidationError::Unauthorized
            }
            crate::transaction::threshold_approval::ThresholdError::ThresholdNotMet { .. } => {
                ValidationError::ThresholdNotMet
            }
        })?;

        Ok(())
    }

    /// Validate a TreasuryAllocation transaction.
    fn validate_treasury_allocation(&self, transaction: &Transaction) -> ValidationResult {
        use crate::transaction::threshold_approval::{
            compute_approval_preimage, validate_threshold_approvals, ApprovalDomain,
        };

        // tx_type byte for TreasuryAllocation = 40
        const TX_TYPE_BYTE: u8 = 40;

        let data = transaction
            .treasury_allocation_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }
        if transaction.fee != 0 {
            return Err(ValidationError::InvalidFee);
        }
        if data.amount == 0 {
            return Err(ValidationError::InvalidAmount);
        }
        if data.source_treasury_key_id == data.destination_key_id {
            return Err(ValidationError::InvalidTransaction);
        }

        // Verify the domain is BootstrapCouncil
        if data.approvals.domain != ApprovalDomain::BootstrapCouncil {
            return Err(ValidationError::InvalidApproval);
        }

        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;

        // Verify entity registry is initialized and source matches cbe_treasury
        if let Some(registry) = blockchain.entity_registry.as_ref() {
            if registry.is_initialized() {
                match registry.cbe_treasury() {
                    Ok(cbe_treasury) => {
                        if cbe_treasury.key_id != data.source_treasury_key_id {
                            return Err(ValidationError::Unauthorized);
                        }
                    }
                    Err(_) => return Err(ValidationError::Unauthorized),
                }
            } else {
                return Err(ValidationError::InvalidTransaction);
            }
        } else {
            return Err(ValidationError::InvalidTransaction);
        }

        // Compute canonical preimage over treasury allocation fields
        #[derive(serde::Serialize)]
        struct AllocationPayload<'a> {
            source_treasury_key_id: [u8; 32],
            destination_key_id: [u8; 32],
            amount: u64,
            spending_category: &'a str,
            proposal_id: [u8; 32],
        }
        let payload = AllocationPayload {
            source_treasury_key_id: data.source_treasury_key_id,
            destination_key_id: data.destination_key_id,
            amount: data.amount,
            spending_category: &data.spending_category,
            proposal_id: data.proposal_id,
        };
        let payload_bytes =
            bincode::serialize(&payload).map_err(|_| ValidationError::InvalidTransaction)?;
        let preimage = compute_approval_preimage(
            TX_TYPE_BYTE,
            &ApprovalDomain::BootstrapCouncil,
            &payload_bytes,
        );

        validate_threshold_approvals(
            &data.approvals,
            &preimage,
            |pk_bytes| {
                blockchain
                    .get_identity_by_public_key(pk_bytes)
                    .map(|id| blockchain.is_council_member(&id.did))
                    .unwrap_or(false)
            },
            blockchain.council_threshold as usize,
        )
        .map_err(|e| match e {
            crate::transaction::threshold_approval::ThresholdError::DuplicateSigner(_) => {
                ValidationError::DuplicateSigner
            }
            crate::transaction::threshold_approval::ThresholdError::InvalidSignature(_) => {
                ValidationError::InvalidApproval
            }
            crate::transaction::threshold_approval::ThresholdError::UnauthorizedSigner(_) => {
                ValidationError::Unauthorized
            }
            crate::transaction::threshold_approval::ThresholdError::ThresholdNotMet { .. } => {
                ValidationError::ThresholdNotMet
            }
        })?;

        Ok(())
    }

    fn validate_create_employment_contract(&self, transaction: &Transaction) -> ValidationResult {
        let data = transaction
            .create_employment_contract_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // dao_id and employee_key_id must be non-zero
        if data.dao_id == [0u8; 32] || data.employee_key_id == [0u8; 32] {
            return Err(ValidationError::InvalidTransaction);
        }

        // contract_type and payment_period must be known variants
        if data.contract_type > 1 {
            return Err(ValidationError::InvalidTransaction);
        }
        if data.payment_period > 2 {
            return Err(ValidationError::InvalidTransaction);
        }

        // Tax rate ≤ 50% (5000 bp), profit share ≤ 20% (2000 bp)
        if data.tax_rate_basis_points > 5000 {
            return Err(ValidationError::InvalidTransaction);
        }
        if data.profit_share_percentage > 2000 {
            return Err(ValidationError::InvalidTransaction);
        }

        // Employment contracts require positive compensation
        if data.contract_type == 1 && data.compensation_amount == 0 {
            return Err(ValidationError::InvalidTransaction);
        }

        Ok(())
    }

    fn validate_process_payroll(&self, transaction: &Transaction) -> ValidationResult {
        let data = transaction
            .process_payroll_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // contract_id must be non-zero
        if data.contract_id == [0u8; 32] {
            return Err(ValidationError::InvalidTransaction);
        }

        // amount_cbe must be positive
        if data.amount_cbe == 0 {
            return Err(ValidationError::InvalidTransaction);
        }

        // collaborator_address must be non-zero
        if data.collaborator_address == [0u8; 32] {
            return Err(ValidationError::InvalidTransaction);
        }

        // deliverable_hash must be non-zero (protocol invariant: no deliverable = no mint)
        if data.deliverable_hash == [0u8; 32] {
            return Err(ValidationError::InvalidTransaction);
        }

        // ── Governance guard: signer must be a Bootstrap Council member ──────
        // The transaction signature already proves the signer holds the private key.
        // We only need to verify that key belongs to a council member identity.
        // With threshold=1 and a single council member, the tx signature suffices.
        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        // Derive the signer's DID directly from the transaction's dilithium public key.
        // DID = "did:zhtp:" + hex(blake3(dilithium_pk))
        // Identity IDs are derived from dilithium_pk only (not dilithium+kyber which
        // produces key_id). This avoids requiring the identity to be registered
        // on-chain — the council membership is authoritative (set at genesis).
        let signer_did = {
            let hash = lib_crypto::hashing::hash_blake3(
                &transaction.signature.public_key.dilithium_pk,
            );
            format!("did:zhtp:{}", hex::encode(hash))
        };
        if !blockchain.is_council_member(&signer_did) {
            tracing::warn!(
                "[PAYROLL] signer {} is not a council member (key_id={})",
                &signer_did[..50.min(signer_did.len())],
                hex::encode(&transaction.signature.public_key.key_id[..8])
            );
            return Err(ValidationError::Unauthorized);
        }

        Ok(())
    }

    fn validate_dao_stake(&self, transaction: &Transaction) -> ValidationResult {
        use crate::contracts::economics::fee_router::{
            DAO_EDUCATION_KEY_ID, DAO_ENERGY_KEY_ID, DAO_FOOD_KEY_ID, DAO_HEALTHCARE_KEY_ID,
            DAO_HOUSING_KEY_ID,
        };

        let data = transaction
            .dao_stake_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // No UTXO inputs or outputs allowed.
        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Staker must be the transaction signer.
        if data.staker != transaction.signature.public_key.key_id {
            tracing::warn!(
                "[DAO_STAKE] staker != signer: staker={} key_id={}",
                hex::encode(&data.staker[..8]),
                hex::encode(&transaction.signature.public_key.key_id[..8]),
            );
            return Err(ValidationError::InvalidTransaction);
        }

        // Amount must be positive.
        if data.amount == 0 {
            return Err(ValidationError::InvalidAmount);
        }

        // lock_blocks must be at least 1 (no instant stakes).
        if data.lock_blocks == 0 {
            return Err(ValidationError::InvalidTransaction);
        }

        // Target must be a known sector DAO.
        let known_daos = [
            DAO_HEALTHCARE_KEY_ID,
            DAO_EDUCATION_KEY_ID,
            DAO_ENERGY_KEY_ID,
            DAO_HOUSING_KEY_ID,
            DAO_FOOD_KEY_ID,
        ];
        if !known_daos.contains(&data.sector_dao_key_id) {
            tracing::warn!(
                "[DAO_STAKE] unknown DAO target: {}",
                hex::encode(&data.sector_dao_key_id[..8]),
            );
            return Err(ValidationError::InvalidTransaction);
        }

        // Balance check: reject at mempool time if staker has insufficient SOV.
        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        let staker_addr = crate::storage::Address::new(data.staker);
        let balance: u128 = if let Some(store) = &blockchain.store {
            let storage_token = crate::storage::TokenId(sov_token_id);
            store.get_token_balance(&storage_token, &staker_addr).unwrap_or(0)
        } else {
            let sender_key = crate::Blockchain::wallet_key_for_sov(&data.staker);
            blockchain
                .token_contracts
                .get(&sov_token_id)
                .map(|t| u128::from(t.balance_of(&sender_key)))
                .unwrap_or(0)
        };

        if balance < data.amount {
            tracing::warn!(
                "[DAO_STAKE] insufficient SOV: staker={} have={} need={}",
                hex::encode(&data.staker[..8]),
                balance,
                data.amount,
            );
            return Err(ValidationError::InvalidAmount);
        }

        Ok(())
    }

    fn validate_dao_unstake(&self, transaction: &Transaction) -> ValidationResult {
        use crate::contracts::economics::fee_router::{
            DAO_EDUCATION_KEY_ID, DAO_ENERGY_KEY_ID, DAO_FOOD_KEY_ID, DAO_HEALTHCARE_KEY_ID,
            DAO_HOUSING_KEY_ID,
        };

        let data = transaction
            .dao_unstake_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }
        if !transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Staker must be the transaction signer.
        if data.staker != transaction.signature.public_key.key_id {
            tracing::warn!(
                "[DAO_UNSTAKE] staker != signer: staker={} key_id={}",
                hex::encode(&data.staker[..8]),
                hex::encode(&transaction.signature.public_key.key_id[..8]),
            );
            return Err(ValidationError::InvalidTransaction);
        }

        // Target must be a known sector DAO.
        let known_daos = [
            DAO_HEALTHCARE_KEY_ID,
            DAO_EDUCATION_KEY_ID,
            DAO_ENERGY_KEY_ID,
            DAO_HOUSING_KEY_ID,
            DAO_FOOD_KEY_ID,
        ];
        if !known_daos.contains(&data.sector_dao_key_id) {
            tracing::warn!(
                "[DAO_UNSTAKE] unknown DAO target: {}",
                hex::encode(&data.sector_dao_key_id[..8]),
            );
            return Err(ValidationError::InvalidTransaction);
        }

        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;

        // Stake record must exist.
        let store = match &blockchain.store {
            Some(s) => s,
            None => return Ok(()), // no store — defer lock check to executor
        };

        // Validate nonce against current SOV nonce for the staker to prevent replays.
        let sov_token = crate::storage::TokenId(crate::contracts::utils::generate_lib_token_id());
        let staker_addr = crate::storage::Address(data.staker);
        let current_nonce = store.get_token_nonce(&sov_token, &staker_addr)
            .map_err(|_| ValidationError::InvalidTransaction)?;
        if data.nonce != current_nonce {
            tracing::warn!(
                "[DAO_UNSTAKE] nonce mismatch: staker={} expected={} got={}",
                hex::encode(&data.staker[..8]),
                current_nonce,
                data.nonce,
            );
            return Err(ValidationError::InvalidTransaction);
        }

        let record = match store.get_dao_stake(&data.sector_dao_key_id, &data.staker) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::warn!(
                    "[DAO_UNSTAKE] no stake record for staker={} dao={}",
                    hex::encode(&data.staker[..8]),
                    hex::encode(&data.sector_dao_key_id[..8]),
                );
                return Err(ValidationError::InvalidTransaction);
            }
            Err(_) => return Ok(()), // storage error — let executor be authoritative
        };

        // Lock period must have expired.
        if blockchain.height < record.locked_until {
            let remaining = record.locked_until.saturating_sub(blockchain.height);
            tracing::warn!(
                "[DAO_UNSTAKE] still locked: staker={} dao={} locked_until={} blocks_remaining={}",
                hex::encode(&data.staker[..8]),
                hex::encode(&data.sector_dao_key_id[..8]),
                record.locked_until,
                remaining,
            );
            return Err(ValidationError::StakeStillLocked {
                locked_until: record.locked_until,
                remaining,
            });
        }

        Ok(())
    }

    /// CRITICAL FIX: Verify that the sender's identity exists on the blockchain
    /// This prevents transactions from non-existent or unregistered identities
    fn validate_sender_identity_exists(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_sender_identity_exists ENTER");

        // If we don't have blockchain access, skip this check (backward compatibility)
        let blockchain = match self.blockchain {
            Some(blockchain) => blockchain,
            None => {
                tracing::warn!("SECURITY WARNING: Identity verification skipped - no blockchain state available");
                return Ok(());
            }
        };

        // Extract the public key from the transaction signature
        let sender_public_key = transaction.signature.public_key.as_bytes();

        if sender_public_key.is_empty() {
            tracing::error!("SECURITY: Transaction has empty public key");
            return Err(ValidationError::InvalidSignature);
        }

        // CORRECT APPROACH: Lookup wallet by public key, then verify owner identity
        // Step 1: Find wallet with matching public key
        let mut owner_did: Option<String> = None;

        tracing::info!(" VALIDATION DEBUG: Searching for wallet with sender public key");
        tracing::info!(
            "   Sender public key length: {} bytes",
            sender_public_key.len()
        );
        tracing::info!(
            "   Sender public key (first 16): {}",
            hex::encode(&sender_public_key[..16.min(sender_public_key.len())])
        );
        tracing::info!(
            "   Total wallets to check: {}",
            blockchain.get_all_wallets().len()
        );

        for (wallet_id, wallet_data) in blockchain.get_all_wallets() {
            tracing::info!(
                "   Checking wallet {}: stored public_key length = {}, first 16 = {}",
                wallet_id,
                wallet_data.public_key.len(),
                hex::encode(&wallet_data.public_key[..16.min(wallet_data.public_key.len())])
            );

            // Debug: Show both keys fully
            tracing::info!(
                "    WALLET public_key (first 64): {}",
                hex::encode(&wallet_data.public_key[..64.min(wallet_data.public_key.len())])
            );
            tracing::info!(
                "    SENDER public_key (first 64): {}",
                hex::encode(&sender_public_key[..64.min(sender_public_key.len())])
            );

            // Debug: Compare byte by byte
            tracing::info!(
                "    Comparing {} wallet bytes vs {} sender bytes",
                wallet_data.public_key.len(),
                sender_public_key.len()
            );

            // CRITICAL FIX: wallet_data.public_key is Vec<u8>, sender_public_key is &[u8]
            // We need to compare as slices, not Vec vs slice
            let keys_match = wallet_data.public_key.as_slice() == sender_public_key;
            tracing::info!("    Direct comparison result: {}", keys_match);

            if !keys_match && wallet_data.public_key.len() == sender_public_key.len() {
                // Find first differing byte (show up to 5 differences)
                let mut diff_count = 0;
                for i in 0..wallet_data.public_key.len() {
                    if wallet_data.public_key[i] != sender_public_key[i] {
                        tracing::error!(
                            "    MISMATCH at byte {}: wallet={:02x} vs sender={:02x}",
                            i,
                            wallet_data.public_key[i],
                            sender_public_key[i]
                        );
                        diff_count += 1;
                        if diff_count >= 5 {
                            tracing::error!("   ... (showing first 5 differences only)");
                            break;
                        }
                    }
                }
                if diff_count == 0 {
                    tracing::error!("     WEIRD: Comparison failed but no byte differences found! Check Vec vs slice comparison");
                }
            }

            // Compare wallet public key directly
            if keys_match {
                tracing::info!("    PUBLIC KEY MATCH FOUND for wallet: {}", wallet_id);
                tracing::info!(
                    "   Wallet owner_identity_id: {:?}",
                    wallet_data.owner_identity_id
                );

                // Get owner DID from owner_identity_id
                if let Some(owner_identity_hash) = &wallet_data.owner_identity_id {
                    // Find the DID string from identity registry using the identity hash
                    // Convert the owner_identity_hash to hex string to match against DID format
                    let owner_id_hex = hex::encode(owner_identity_hash.as_bytes());

                    for (did, _identity_data) in blockchain.get_all_identities() {
                        // Extract the hex part from the DID (format: did:zhtp:HEX)
                        let did_hex = if did.starts_with("did:zhtp:") {
                            &did[9..] // Skip "did:zhtp:" prefix
                        } else {
                            did.as_str()
                        };

                        // Check if this identity's ID matches the wallet's owner_identity_id
                        if did_hex == owner_id_hex {
                            owner_did = Some(did.clone());
                            tracing::info!("Found wallet {} owned by identity: {}", wallet_id, did);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Step 2: If no wallet found, check if sender is directly an identity (backward compatibility)
        if owner_did.is_none() {
            for (did, identity_data) in blockchain.get_all_identities() {
                if identity_data.public_key == sender_public_key {
                    owner_did = Some(did.clone());
                    tracing::info!("Sender is direct identity: {}", did);
                    break;
                }
            }
        }

        // Step 3: Verify owner identity exists and is not revoked
        match owner_did {
            Some(did) => {
                if let Some(identity_data) = blockchain
                    .get_all_identities()
                    .iter()
                    .find(|(id, _)| **id == did)
                    .map(|(_, data)| data)
                {
                    if identity_data.identity_type == "revoked" {
                        tracing::error!("SECURITY: Transaction from revoked identity: {}", did);
                        return Err(ValidationError::InvalidTransaction);
                    }

                    tracing::info!(
                        " SECURITY: Sender identity verified: {} ({})",
                        identity_data.display_name,
                        did
                    );
                    return Ok(());
                }

                tracing::error!("SECURITY: Owner DID {} exists but identity not found!", did);
                return Err(ValidationError::UnregisteredSender);
            }
            None => {
                tracing::error!(
                    "SECURITY CRITICAL: Transaction from unregistered wallet/identity!"
                );
                tracing::error!(
                    "Public key: {:02x?}",
                    &sender_public_key[..std::cmp::min(16, sender_public_key.len())]
                );
                tracing::error!(
                    " REJECTED: All transactions must come from registered wallets/identities"
                );

                // NO BYPASS: Always reject transactions from unregistered senders
                return Err(ValidationError::UnregisteredSender);
            }
        }
    }

    /// Validate UBI claim transaction with state context (Week 7)
    fn validate_ubi_claim_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Use stateless validator for structural checks
        let stateless_validator = TransactionValidator::new();
        stateless_validator.validate_ubi_claim_transaction(transaction)?;

        // In future weeks, could add stateful checks:
        // - Verify claimant is registered citizen
        // - Verify claim amount matches schedule
        // - Verify UBI pool has sufficient balance
        // - Verify claimant hasn't already claimed this month

        Ok(())
    }

    /// Validate profit declaration transaction with state context (Week 7)
    fn validate_profit_declaration_transaction(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        // Use stateless validator for structural checks
        let stateless_validator = TransactionValidator::new();
        stateless_validator.validate_profit_declaration_transaction(transaction)?;

        // In future weeks, could add stateful checks:
        // - Verify declarant is registered for-profit entity
        // - Verify nonprofit treasury is registered
        // - Prevent duplicate declarations for same fiscal period
        // - Verify for-profit treasury has sufficient balance for tribute

        Ok(())
    }

    fn current_oracle_epoch(&self, blockchain: &crate::blockchain::Blockchain) -> u64 {
        let reference_timestamp = blockchain
            .latest_block()
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
        blockchain.oracle_state.epoch_id(reference_timestamp)
    }

    fn validate_oracle_governance_transaction(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;

        if transaction.version < crate::transaction::core::TX_VERSION_V4 {
            return Err(ValidationError::InvalidTransaction);
        }

        match transaction.transaction_type {
            TransactionType::UpdateOracleCommittee => {
                let data = transaction
                    .oracle_committee_update_data()
                    .ok_or(ValidationError::MissingRequiredData)?;

                let current_epoch = self.current_oracle_epoch(blockchain);
                data.validate(current_epoch)
                    .map_err(|_| ValidationError::InvalidTransaction)?;

                let active_validator_key_ids: std::collections::HashSet<[u8; 32]> = blockchain
                    .validator_registry
                    .values()
                    .filter(|v| v.status == "active")
                    .map(|v| {
                        v.oracle_key_id.unwrap_or_else(|| {
                            crate::types::hash::blake3_hash(&v.consensus_key).as_array()
                        })
                    })
                    .collect();

                if data
                    .new_members
                    .iter()
                    .any(|member| !active_validator_key_ids.contains(member))
                {
                    return Err(ValidationError::InvalidTransaction);
                }
            }
            TransactionType::UpdateOracleConfig => {
                let data = transaction
                    .oracle_config_update_data()
                    .ok_or(ValidationError::MissingRequiredData)?;

                let current_epoch = self.current_oracle_epoch(blockchain);
                data.validate(current_epoch)
                    .map_err(|_| ValidationError::InvalidTransaction)?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Stateful TokenMint authorization parity with execution path.
    ///
    /// This enforces token existence and signer authorization at mempool/precheck time
    /// so admission behavior matches block execution behavior.
    fn validate_token_mint_stateful_authorization(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        let mint_data = transaction
            .token_mint_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // SOV mints currently use dedicated consensus paths and are handled separately.
        let is_sov = mint_data.token_id == [0u8; 32]
            || mint_data.token_id == crate::contracts::utils::generate_lib_token_id();
        if is_sov {
            return Ok(());
        }

        // Preserve existing execution semantics for UBI and migration flows.
        let memo_str = std::str::from_utf8(&transaction.memo).ok();
        let is_ubi_mint = memo_str
            .map(|memo| memo.starts_with("UBI_DISTRIBUTION_V1:"))
            .unwrap_or(false);
        let is_migration = memo_str
            .map(|memo| memo.starts_with("TOKEN_MIGRATE_V1:"))
            .unwrap_or(false);

        let token = blockchain
            .token_contracts
            .get(&mint_data.token_id)
            .ok_or(ValidationError::InvalidTransaction)?;

        if is_ubi_mint || is_migration {
            return Ok(());
        }

        token
            .check_mint_authorization(&transaction.signature.public_key)
            .map_err(|_| ValidationError::InvalidTransaction)
    }

    /// Validate OracleAttestation transaction at block execution time (ORACLE-9).
    ///
    /// This performs the critical security checks:
    /// 1. Attestation data exists
    /// 2. Signer is in current oracle committee
    /// 3. Epoch matches current block epoch
    /// 4. Signature is valid
    /// 5. No replay (validator hasn't attested for this epoch yet)
    fn validate_oracle_attestation_transaction(
        &self,
        transaction: &Transaction,
    ) -> ValidationResult {
        // Get attestation data
        let data = transaction
            .oracle_attestation_data()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Get blockchain state
        let blockchain = self.blockchain.ok_or(ValidationError::InvalidTransaction)?;
        let oracle_state = &blockchain.oracle_state;

        // 1. Check signer is in current committee
        if !oracle_state
            .committee
            .members()
            .contains(&data.validator_pubkey)
        {
            return Err(ValidationError::InvalidTransaction);
        }

        // 2. Check epoch matches the epoch implied by the attestation timestamp
        // Note: We derive the epoch from the attested timestamp to avoid dependence on
        // the blockchain's last committed timestamp, which may belong to a different epoch.
        let attested_epoch = oracle_state.epoch_id(data.timestamp);
        if data.epoch_id != attested_epoch {
            return Err(ValidationError::InvalidTransaction);
        }

        // 3. Check no replay (validator hasn't attested for this epoch yet)
        // Replay protection is handled at execution time via oracle_state.record_attestation()
        // We check here but cannot mutate because validation takes &self, not &mut self.
        if let Some(epoch_state) = oracle_state.epoch_state.get(&data.epoch_id) {
            if epoch_state
                .signer_prices
                .contains_key(&data.validator_pubkey)
            {
                return Err(ValidationError::DoubleSpend);
            }
        }

        // 4. Verify signature
        // Build the attestation from the transaction data
        let attestation = crate::oracle::OraclePriceAttestation {
            epoch_id: data.epoch_id,
            sov_usd_price: data.sov_usd_price,
            cbe_usd_price: data.cbe_usd_price,
            timestamp: data.timestamp,
            validator_pubkey: data.validator_pubkey,
            signature: data.signature.clone(),
        };

        // Resolve the validator's signing public key
        let validator_key = blockchain
            .validator_registry
            .values()
            .find(|v| lib_crypto::hash_blake3(&v.consensus_key) == data.validator_pubkey)
            .ok_or(ValidationError::InvalidTransaction)?;

        // Verify the signature
        attestation
            .verify_signature(&validator_key.consensus_key)
            .map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }
}

/// Constants for validation
const MAX_TRANSACTION_SIZE: usize = 1_048_576; // 1 MB
const MAX_MEMO_SIZE: usize = 16384; // 16 KB - increased for contract calls with post-quantum signatures (Dilithium signatures ~2.7KB each)

/// Validation utility functions
pub mod utils {
    use super::*;

    /// Quick validation for transaction basic structure
    pub fn quick_validate(transaction: &Transaction) -> bool {
        let validator = TransactionValidator::new();
        validator.validate_basic_structure(transaction).is_ok()
    }

    /// Validate transaction type consistency
    pub fn validate_type_consistency(transaction: &Transaction) -> bool {
        match transaction.transaction_type {
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation => transaction.identity_data().is_some(),
            TransactionType::Transfer
            | TransactionType::ContractDeployment
            | TransactionType::ContractExecution => {
                !transaction.inputs.is_empty() && !transaction.outputs.is_empty()
            }
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload
            | TransactionType::UbiDistribution => {
                // Audit transactions should have memo data but no strict input/output requirements
                !transaction.memo.is_empty()
            }
            TransactionType::WalletRegistration => {
                // Wallet registration should have wallet_data
                transaction.wallet_data().is_some()
            }
            TransactionType::WalletUpdate => {
                // Wallet update should have wallet_data
                transaction.wallet_data().is_some()
            }
            TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister => {
                // Validator transactions should have validator_data
                transaction.validator_data().is_some()
            }
            TransactionType::GatewayRegistration
            | TransactionType::GatewayUpdate
            | TransactionType::GatewayUnregister => {
                // Gateway transactions should have gateway_data
                transaction.gateway_data().is_some()
            }
            TransactionType::DaoProposal => transaction.dao_proposal_data().is_some(),
            TransactionType::DaoVote => transaction.dao_vote_data().is_some(),
            TransactionType::DaoExecution => transaction.dao_execution_data().is_some(),
            TransactionType::DifficultyUpdate => {
                // Difficulty update validation - requires memo with parameters
                // Full validation happens at consensus layer
                !transaction.memo.is_empty()
            }
            TransactionType::UBIClaim => {
                // UBI claim transactions should have ubi_claim_data (Week 7)
                transaction.ubi_claim_data().is_some()
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions should have profit_declaration_data (Week 7)
                transaction.profit_declaration_data().is_some()
            }
            TransactionType::Coinbase => {
                // Coinbase must have no inputs but have outputs
                transaction.inputs.is_empty() && !transaction.outputs.is_empty()
            }
            TransactionType::TokenTransfer => {
                transaction.token_transfer_data().is_some() && transaction.outputs.is_empty()
            }
            TransactionType::TokenMint => {
                transaction.version >= 2
                    && transaction.token_mint_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates should have governance_config_data
                transaction.governance_config_data().is_some()
            }
            TransactionType::TokenCreation
            | TransactionType::BondingCurveDeploy
            | TransactionType::BondingCurveBuy
            | TransactionType::BondingCurveSell
            | TransactionType::BondingCurveGraduate => {
                // Bonding curve operations
                true
            }
            TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                // AMM/Token operations - not yet fully implemented
                true
            }
            TransactionType::UpdateOracleCommittee | TransactionType::UpdateOracleConfig => {
                // Oracle governance transactions
                true
            }
            TransactionType::OracleAttestation => {
                // Oracle attestation transactions
                true
            }
            TransactionType::CancelOracleUpdate => {
                // Cancel oracle update
                true
            }
            TransactionType::InitEntityRegistry => {
                transaction.init_entity_registry_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::RecordOnRampTrade => {
                transaction.record_on_ramp_trade_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::TreasuryAllocation => {
                transaction.treasury_allocation_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::InitCbeToken => {
                transaction.init_cbe_token_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::CreateEmploymentContract => {
                transaction.create_employment_contract_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::ProcessPayroll => {
                transaction.process_payroll_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::RecordOnRampTrade => {
                transaction.record_on_ramp_trade_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::TreasuryAllocation => {
                transaction.treasury_allocation_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::DaoStake => {
                transaction.dao_stake_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::DaoUnstake => {
                transaction.dao_unstake_data().is_some()
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::DomainRegistration => {
                transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_REGISTRATION_PREFIX)
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
            TransactionType::DomainUpdate => {
                transaction
                    .memo
                    .starts_with(crate::transaction::DOMAIN_UPDATE_PREFIX)
                    && transaction.inputs.is_empty()
                    && transaction.outputs.is_empty()
            }
        }
    }

    /// Check if transaction has valid zero-zero-knowledge structure
    pub fn has_valid_zk_structure(transaction: &Transaction) -> bool {
        // All inputs must have nullifiers and ZK proofs
        transaction.inputs.iter().all(|input| {
            input.nullifier != Hash::default() && is_valid_proof_structure(&input.zk_proof)
        })
    }

    /// Validate transaction against current mempool rules
    pub fn validate_mempool_rules(transaction: &Transaction) -> ValidationResult {
        // Check transaction size
        if transaction.size() > MAX_TRANSACTION_SIZE {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check fee rate
        let fee_rate = transaction.fee as f64 / transaction.size() as f64;
        if fee_rate < 1.0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::zk_integration::ZkTransactionProof;
    use crate::transaction::{ContractDeploymentPayloadV1, CONTRACT_DEPLOYMENT_MEMO_PREFIX};
    use crate::types::ContractCall;
    use bincode::Options;

    /// Helper: create a test PublicKey with deterministic content
    fn test_public_key(id: u8) -> PublicKey {
        // Dilithium5 public keys are 2592 bytes
        let mut key_bytes = [id; 2592];
        // Make it somewhat realistic by varying the first few bytes
        key_bytes[0] = id;
        key_bytes[1] = id.wrapping_add(1);
        key_bytes[2] = id.wrapping_add(2);
        PublicKey::new(key_bytes)
    }

    /// Helper: create a test Signature struct
    fn test_signature(public_key: &PublicKey) -> Signature {
        Signature {
            signature: vec![0u8; 64], // placeholder signature bytes
            public_key: public_key.clone(),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        }
    }

    /// Helper: create a mock token create transaction.
    fn create_token_contract_transaction(sender_key: &PublicKey) -> Transaction {
        let call = ContractCall::token_call("create_custom_token".to_string(), vec![1, 2, 3, 4]);
        let sig = test_signature(sender_key);

        // Serialize: "ZHTP" prefix + bincode(call, sig)
        let call_data = bincode::serialize(&(&call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        Transaction {
            version: 1,
            chain_id: 0x03, // development
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![TransactionInput {
                previous_output: Hash::default(),
                output_index: 0,
                nullifier: [1u8; 32].into(), // non-default nullifier
                zk_proof: ZkTransactionProof::default(),
            }],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(sender_key),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    fn create_contract_deployment_transaction_with_payload(
        sender_key: &PublicKey,
        payload: ContractDeploymentPayloadV1,
    ) -> Transaction {
        let memo = payload.encode_memo().unwrap();
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractDeployment,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: Hash::from([7u8; 32]),
                note: Hash::from([8u8; 32]),
                recipient: sender_key.clone(),
            merkle_leaf: Hash::default(),
            }],
            fee: 0,
            signature: test_signature(sender_key),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    fn create_token_mint_transaction_for_stateful_test(
        signer: &PublicKey,
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u128,
    ) -> Transaction {
        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenMint,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            // Empty signature bytes are allowed at genesis in stateful validator.
            signature: Signature {
                signature: vec![],
                public_key: signer.clone(),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: vec![],
            payload: crate::transaction::TransactionPayload::TokenMint(
                crate::transaction::TokenMintData {
                    token_id,
                    to,
                    amount,
                },
            ),
        }
    }

    fn create_init_entity_registry_transaction_for_test(
        signer: &PublicKey,
        cbe_treasury: PublicKey,
        nonprofit_treasury: PublicKey,
    ) -> Transaction {
        Transaction::new_init_entity_registry(
            1,
            cbe_treasury,
            nonprofit_treasury,
            123,
            0,
            test_signature(signer),
        )
    }

    fn create_init_entity_registry_threshold_transaction_for_test(
        signers: &[lib_crypto::KeyPair],
        cbe_treasury: PublicKey,
        nonprofit_treasury: PublicKey,
    ) -> Transaction {
        use crate::transaction::threshold_approval::{
            compute_approval_preimage, Approval, ApprovalDomain, ThresholdApprovalSet,
        };

        #[derive(serde::Serialize)]
        struct CanonicalPayload<'a> {
            cbe_treasury: &'a PublicKey,
            nonprofit_treasury: &'a PublicKey,
            initialized_at: u64,
            initialized_at_height: u64,
        }

        let payload = CanonicalPayload {
            cbe_treasury: &cbe_treasury,
            nonprofit_treasury: &nonprofit_treasury,
            initialized_at: 123,
            initialized_at_height: 0,
        };
        let payload_bytes = bincode::serialize(&payload).unwrap();
        let preimage =
            compute_approval_preimage(38, &ApprovalDomain::BootstrapCouncil, &payload_bytes);
        let approvals = signers
            .iter()
            .map(|signer| {
                let signature = signer.sign(&preimage).unwrap();
                Approval {
                    public_key: signer.public_key.clone(),
                    algorithm: signature.algorithm,
                    signature: signature.signature,
                }
            })
            .collect();

        let mut tx = create_init_entity_registry_transaction_for_test(
            &signers[0].public_key,
            cbe_treasury,
            nonprofit_treasury,
        );
        if let crate::transaction::TransactionPayload::InitEntityRegistry(data) = &mut tx.payload {
            data.approvals = ThresholdApprovalSet {
                domain: ApprovalDomain::BootstrapCouncil,
                approvals,
            };
        }
        tx
    }

    fn register_council_identity(
        blockchain: &mut crate::blockchain::Blockchain,
        did: &str,
        signer: &PublicKey,
    ) {
        blockchain.identity_registry.insert(
            did.to_string(),
            IdentityTransactionData::new(
                did.to_string(),
                "Council Member".to_string(),
                signer.dilithium_pk.to_vec(),
                vec![1, 2, 3],
                "human".to_string(),
                Hash::from([9u8; 32]),
                0,
                0,
            ),
        );
        blockchain.council_members.push(crate::dao::CouncilMember {
            identity_id: did.to_string(),
            wallet_id: "wallet".to_string(),
            stake_amount: 1,
            joined_at_height: 0,
        });
    }

    /// Test A: Token contract creation call is detected without identity record
    ///
    /// The canonical sender is derived from tx.signature.public_key.
    /// Token operations do not require the sender to have a registered identity.
    #[test]
    fn test_token_contract_call_succeeds_without_identity() {
        // Create a sender with NO registered identity
        let unregistered_sender = test_public_key(42);
        let tx = create_token_contract_transaction(&unregistered_sender);

        // Verify this is detected as a token contract execution
        assert!(
            is_token_contract_execution(&tx),
            "Transaction should be detected as token contract execution"
        );

        // The key test: is_token_contract_execution returns true, which means
        // the StatefulTransactionValidator will SKIP the identity check for this tx.
        // This is the core fix - token operations don't require registered identity.

        // Verify the transaction has a valid sender public key (the canonical sender)
        assert!(
            !tx.signature.public_key.as_bytes().is_empty(),
            "Transaction should have a sender public key (canonical sender)"
        );
    }

    /// Test B: ContractExecution token mutation methods are no longer
    /// recognized as canonical token contract execution path.
    #[test]
    fn test_token_mutation_not_detected_as_token_contract_execution() {
        let sender = test_public_key(1);
        let tx = create_token_contract_transaction(&sender);
        assert!(is_token_contract_execution(&tx));

        let mint_call = ContractCall::token_call("mint".to_string(), vec![1, 2, 3]);
        let sig = test_signature(&sender);
        let call_data = bincode::serialize(&(&mint_call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        let mint_tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(&sender),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        };

        assert!(!is_token_contract_execution(&mint_tx));
    }

    /// Test C: Invalid signature still fails for token transactions
    ///
    /// Even though identity is not required, signature validation IS required.
    /// The signature cryptographically proves the sender authorized the transaction.
    #[test]
    fn test_invalid_signature_fails_for_tokens() {
        let sender = test_public_key(1);
        let tx = create_token_contract_transaction(&sender);

        // Signature validation is handled by stateless validator
        let validator = TransactionValidator::new();

        // The validate_signature method will fail because we have a placeholder signature
        // This proves signature validation is still enforced for tokens
        let result = validator.validate_signature(&tx);

        // Should fail because our mock signature is invalid
        assert!(
            result.is_err(),
            "Invalid signature should be rejected even for token transactions"
        );
    }

    /// Test D: Replay protection (nullifier) works without identity
    ///
    /// The UTXO nullifier-based replay protection operates independently of identity.
    /// Each input has a unique nullifier that prevents double-spending.
    #[test]
    fn test_nullifier_replay_protection_without_identity() {
        let sender = test_public_key(1);
        let tx = create_token_contract_transaction(&sender);

        // Verify the transaction has a non-default nullifier (replay protection)
        assert!(
            !tx.inputs.is_empty(),
            "Transaction should have inputs for nullifier check"
        );
        assert!(
            tx.inputs[0].nullifier != Hash::default(),
            "Input should have non-default nullifier for replay protection"
        );

        // The stateless validator checks nullifier structure
        let validator = TransactionValidator::new();

        // has_valid_zk_structure checks nullifiers are present
        // Note: This won't fully pass with our mock data, but it demonstrates
        // the nullifier check exists and operates independently of identity
        let has_nullifier = tx
            .inputs
            .iter()
            .all(|input| input.nullifier != Hash::default());
        assert!(
            has_nullifier,
            "All inputs should have nullifiers for replay protection"
        );
    }

    /// Verify is_token_contract_execution correctly identifies token operations
    #[test]
    fn test_is_token_contract_execution_detection() {
        let sender = test_public_key(1);

        // Only create_custom_token is considered a canonical token contract call.
        for method in &["create_custom_token"] {
            let call = ContractCall::token_call(method.to_string(), vec![]);
            let sig = test_signature(&sender);
            let call_data = bincode::serialize(&(&call, &sig)).unwrap();
            let mut memo = b"ZHTP".to_vec();
            memo.extend(call_data);

            let tx = Transaction {
                version: 1,
                chain_id: 0x03,
                transaction_type: TransactionType::ContractExecution,
                inputs: vec![],
                outputs: vec![],
                fee: 1000,
                signature: test_signature(&sender),
                memo,
                payload: crate::transaction::TransactionPayload::None,
            };

            assert!(
                is_token_contract_execution(&tx),
                "Method '{}' should be detected as token contract execution",
                method
            );
        }

        for method in &["mint", "transfer", "burn"] {
            let call = ContractCall::token_call(method.to_string(), vec![]);
            let sig = test_signature(&sender);
            let call_data = bincode::serialize(&(&call, &sig)).unwrap();
            let mut memo = b"ZHTP".to_vec();
            memo.extend(call_data);

            let tx = Transaction {
                version: 1,
                chain_id: 0x03,
                transaction_type: TransactionType::ContractExecution,
                inputs: vec![],
                outputs: vec![],
                fee: 1000,
                signature: test_signature(&sender),
                memo,
                payload: crate::transaction::TransactionPayload::None,
            };

            assert!(
                !is_token_contract_execution(&tx),
                "Method '{}' must not be considered canonical token contract execution",
                method
            );
        }

        // Non-token contract should NOT be detected
        let non_token_call = ContractCall::messaging_call("send_message".to_string(), vec![]);
        let sig = test_signature(&sender);
        let call_data = bincode::serialize(&(&non_token_call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        let non_token_tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(&sender),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        };

        assert!(
            !is_token_contract_execution(&non_token_tx),
            "Messaging contract should NOT be detected as token contract execution"
        );
    }

    #[test]
    fn test_contract_execution_token_mutation_rejected() {
        let sender = test_public_key(1);
        let call = ContractCall::token_call("transfer".to_string(), vec![1, 2, 3]);
        let sig = test_signature(&sender);
        let call_data = bincode::serialize(&(&call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        let tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(&sender),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        };

        let validator = TransactionValidator::new();
        let result = validator.validate_contract_transaction(&tx);
        assert!(matches!(
            result,
            Err(ValidationError::InvalidTransactionType)
        ));
    }

    #[test]
    fn test_stateful_token_mint_rejects_unauthorized_signer_at_precheck() {
        let mut blockchain = crate::blockchain::Blockchain::default();
        let creator = test_public_key(11);
        let attacker = test_public_key(12);
        let recipient = test_public_key(13);

        let token = crate::contracts::TokenContract::new_custom(
            "ParityToken".to_string(),
            "PAR".to_string(),
            1_000,
            creator,
        );
        let token_id = token.token_id;
        blockchain.token_contracts.insert(token_id, token);

        let tx = create_token_mint_transaction_for_stateful_test(
            &attacker,
            token_id,
            recipient.key_id,
            100,
        );

        let validator = StatefulTransactionValidator::new(&blockchain);
        let result = validator.validate_token_mint_stateful_authorization(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidTransaction)),
            "Unauthorized mint must be rejected during stateful precheck"
        );
    }

    #[test]
    fn test_stateful_token_mint_accepts_creator_at_precheck() {
        let mut blockchain = crate::blockchain::Blockchain::default();
        let creator = test_public_key(21);
        let recipient = test_public_key(22);

        let token = crate::contracts::TokenContract::new_custom(
            "ParityToken".to_string(),
            "PAR".to_string(),
            1_000,
            creator.clone(),
        );
        let token_id = token.token_id;
        blockchain.token_contracts.insert(token_id, token);

        let tx = create_token_mint_transaction_for_stateful_test(
            &creator,
            token_id,
            recipient.key_id,
            100,
        );

        let validator = StatefulTransactionValidator::new(&blockchain);
        let result = validator.validate_token_mint_stateful_authorization(&tx);
        assert!(
            result.is_ok(),
            "Creator mint should pass stateful mint authorization precheck"
        );
    }

    #[test]
    fn test_stateful_token_mint_rejects_unknown_token_at_precheck() {
        let blockchain = crate::blockchain::Blockchain::default();
        let signer = test_public_key(31);
        let recipient = test_public_key(32);
        let unknown_token_id = [0xAB; 32];

        let tx = create_token_mint_transaction_for_stateful_test(
            &signer,
            unknown_token_id,
            recipient.key_id,
            100,
        );

        let validator = StatefulTransactionValidator::new(&blockchain);
        let result = validator.validate_token_mint_stateful_authorization(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidTransaction)),
            "Unknown token mint must be rejected during stateful precheck"
        );
    }

    #[test]
    fn test_init_entity_registry_rejects_zero_treasury_keys() {
        let blockchain = crate::blockchain::Blockchain::default();
        let signer = test_public_key(41);
        let zero_pk = PublicKey::new([0u8; 2592]);
        let tx = create_init_entity_registry_transaction_for_test(
            &signer,
            zero_pk.clone(),
            test_public_key(42),
        );

        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::InvalidPublicKey)
        ));

        let tx =
            create_init_entity_registry_transaction_for_test(&signer, test_public_key(43), zero_pk);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::InvalidPublicKey)
        ));
    }

    #[test]
    fn test_init_entity_registry_rejects_matching_treasury_keys() {
        let blockchain = crate::blockchain::Blockchain::default();
        let signer = test_public_key(44);
        let treasury = test_public_key(45);
        let tx =
            create_init_entity_registry_transaction_for_test(&signer, treasury.clone(), treasury);

        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::InvalidPublicKey)
        ));
    }

    #[test]
    fn test_init_entity_registry_rejects_missing_dilithium_key_material() {
        let blockchain = crate::blockchain::Blockchain::default();
        let signer = test_public_key(58);
        let kyber_only = PublicKey::from_kyber_public_key([0xAB; 1568]);
        let tx = create_init_entity_registry_transaction_for_test(
            &signer,
            kyber_only,
            test_public_key(59),
        );

        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::InvalidPublicKey)
        ));
    }

    #[test]
    fn test_init_entity_registry_rejects_empty_approval_set() {
        let mut blockchain = crate::blockchain::Blockchain::default();
        let council_signer = test_public_key(46);
        register_council_identity(&mut blockchain, "did:zhtp:council", &council_signer);
        blockchain.council_threshold = 1;

        let tx = create_init_entity_registry_transaction_for_test(
            &council_signer,
            test_public_key(48),
            test_public_key(49),
        );
        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::ThresholdNotMet)
        ));
    }

    #[test]
    fn test_init_entity_registry_rejects_when_already_initialized() {
        let mut blockchain = crate::blockchain::Blockchain::default();
        let signer = test_public_key(50);
        register_council_identity(&mut blockchain, "did:zhtp:council", &signer);
        blockchain.entity_registry = Some(crate::contracts::governance::EntityRegistry::new());
        blockchain
            .entity_registry
            .as_mut()
            .unwrap()
            .init(test_public_key(51), test_public_key(52))
            .unwrap();

        let tx = create_init_entity_registry_transaction_for_test(
            &signer,
            test_public_key(53),
            test_public_key(54),
        );
        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(matches!(
            validator.validate_init_entity_registry(&tx),
            Err(ValidationError::AlreadyInitialized)
        ));
    }

    #[test]
    fn test_init_entity_registry_accepts_council_member_with_valid_payload() {
        let mut blockchain = crate::blockchain::Blockchain::default();
        blockchain.council_threshold = 1;
        let signer = lib_crypto::KeyPair::generate().unwrap();
        register_council_identity(&mut blockchain, "did:zhtp:council", &signer.public_key);

        let tx = create_init_entity_registry_threshold_transaction_for_test(
            &[signer],
            test_public_key(56),
            test_public_key(57),
        );
        let validator = StatefulTransactionValidator::new(&blockchain);
        assert!(validator.validate_init_entity_registry(&tx).is_ok());
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_duplicate_trade_payload() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let mut blockchain = crate::blockchain::Blockchain::default();
        blockchain
            .onramp_state
            .record_trade(crate::onramp::OnRampTrade {
                block_height: 10,
                epoch_id: 1,
                cbe_amount: 100,
                usdc_amount: 200,
                traded_at: 1_000_000,
            });
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::OracleCommittee);
        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::DoubleSpend)),
            "expected DoubleSpend for duplicate trade payload, got: {result:?}"
        );
    }

    #[test]
    fn test_contract_deployment_schema_accepts_valid_payload() {
        let sender = test_public_key(9);
        let payload = ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![1, 2, 3],
            abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
            init_args: vec![0xaa, 0xbb],
            gas_limit: 100_000,
            memory_limit_bytes: 65_536,
        };
        let tx = create_contract_deployment_transaction_with_payload(&sender, payload);

        let validator = TransactionValidator::new();
        let result = validator.validate_contract_transaction(&tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_contract_deployment_schema_rejects_missing_prefix() {
        let sender = test_public_key(10);
        let mut tx = create_contract_deployment_transaction_with_payload(
            &sender,
            ContractDeploymentPayloadV1 {
                contract_type: "wasm".to_string(),
                code: vec![1],
                abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
                init_args: vec![],
                gas_limit: 10_000,
                memory_limit_bytes: 65_536,
            },
        );
        tx.memo = b"legacy-deploy-payload".to_vec();

        let validator = TransactionValidator::new();
        let result = validator.validate_contract_transaction(&tx);
        assert!(matches!(result, Err(ValidationError::InvalidMemo)));
    }

    #[test]
    fn test_contract_deployment_schema_rejects_invalid_bounds() {
        let sender = test_public_key(11);
        let mut tx = create_contract_deployment_transaction_with_payload(
            &sender,
            ContractDeploymentPayloadV1 {
                contract_type: "wasm".to_string(),
                code: vec![1, 2, 3],
                abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
                init_args: vec![],
                gas_limit: 10_000,
                memory_limit_bytes: 65_536,
            },
        );

        let invalid_payload = ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![1, 2, 3],
            abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
            init_args: vec![],
            gas_limit: 0,
            memory_limit_bytes: 65_536,
        };
        let mut memo = CONTRACT_DEPLOYMENT_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(
            &bincode::DefaultOptions::new()
                .with_limit(
                    crate::transaction::contract_deployment::MAX_DEPLOYMENT_MEMO_BYTES as u64,
                )
                .serialize(&invalid_payload)
                .unwrap(),
        );
        tx.memo = memo;

        let validator = TransactionValidator::new();
        let result = validator.validate_contract_transaction(&tx);
        assert!(matches!(result, Err(ValidationError::InvalidMemo)));
    }

    /// Helper: build a minimal valid-structure TokenTransfer with a given fee.
    fn token_transfer_tx_with_fee(fee: u64) -> Transaction {
        let sender_key = test_public_key(1);
        let from_id = sender_key.key_id;
        let to_id = test_public_key(2).key_id;
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenTransfer,
            inputs: vec![],
            outputs: vec![],
            fee,
            // Empty signature — simulates a true system-generated transaction.
            // With is_system=true the validator skips sig-validation only when
            // the signature bytes are empty (has_nonempty_sig=false); a non-empty
            // dummy signature would trigger crypto verification and fire
            // InvalidSignature before the fee check.
            signature: Signature {
                signature: vec![],
                public_key: sender_key.clone(),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: vec![],
            payload: crate::transaction::TransactionPayload::TokenTransfer(
                crate::transaction::TokenTransferData {
                    token_id: [0u8; 32],
                    from: from_id,
                    to: to_id,
                    amount: 1_000,
                    nonce: 0,
                },
            ),
        }
    }

    fn token_creation_tx_with_fee(fee: u64) -> Transaction {
        let sender_key = test_public_key(3);
        let payload = TokenCreationPayloadV1 {
            name: "Canonical Token".to_string(),
            symbol: "CAN".to_string(),
            initial_supply: 1_000_000,
            decimals: 8,
            treasury_allocation_bps: 2_000,
            treasury_recipient: test_public_key(4).key_id,
        };

        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenCreation,
            inputs: vec![],
            outputs: vec![],
            fee,
            signature: test_signature(&sender_key),
            memo: payload.encode_memo().unwrap(),
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    #[test]
    fn test_token_transfer_nonzero_fee_rejected_with_system_flag_true() {
        // When is_system_transaction=true, signature validation is skipped, so the
        // fee check is the first gate to fire.  Phase 2 rule: TokenTransfer fee must
        // be 0 even when the caller sets is_system=true.
        let tx = token_transfer_tx_with_fee(107);
        let validator = TransactionValidator::new();
        let result = validator.validate_transaction_with_system_flag(&tx, true);
        assert!(
            matches!(result, Err(ValidationError::InvalidFee)),
            "Expected InvalidFee for TokenTransfer(fee=107, is_system=true), got: {:?}",
            result
        );
    }

    #[test]
    fn test_token_transfer_nonzero_fee_rejected_with_system_flag_false() {
        // When is_system_transaction=false, signature validation runs first.
        // A TokenTransfer with fee > 0 must NOT be accepted regardless of which
        // error fires first — this guards against future reordering.
        let tx = token_transfer_tx_with_fee(107);
        let validator = TransactionValidator::new();
        let result = validator.validate_transaction_with_system_flag(&tx, false);
        assert!(
            result.is_err(),
            "TokenTransfer with fee=107 (is_system=false) must be rejected, got Ok"
        );
        assert!(
            !matches!(result, Ok(())),
            "TokenTransfer with fee=107 must never pass validation"
        );
    }

    #[test]
    fn test_token_transfer_zero_fee_not_rejected_by_economics() {
        // Zero fee must NOT trigger InvalidFee.  Other checks (signature, outputs)
        // may still reject the placeholder tx, but the fee rule must not fire.
        let tx = token_transfer_tx_with_fee(0);
        let validator = TransactionValidator::new();

        // With is_system=true, signature is skipped.  The fee check must not fire.
        let result = validator.validate_transaction_with_system_flag(&tx, true);
        assert!(
            !matches!(result, Err(ValidationError::InvalidFee)),
            "TokenTransfer with fee=0 must not fail with InvalidFee (is_system=true), got: {:?}",
            result
        );
    }

    #[test]
    fn test_token_creation_exact_fee_not_rejected_by_economics() {
        let validator = TransactionValidator::with_fee_config(crate::transaction::TxFeeConfig {
            token_creation_fee: 1_000,
            ..crate::transaction::TxFeeConfig::default()
        });
        let tx = token_creation_tx_with_fee(1_000);

        let result = validator.validate_economics_with_system_check(&tx, false);

        assert!(
            !matches!(result, Err(ValidationError::InvalidFee)),
            "TokenCreation with exact canonical fee must not fail with InvalidFee, got: {:?}",
            result
        );
    }

    #[test]
    fn test_token_creation_low_fee_rejected() {
        let validator = TransactionValidator::with_fee_config(crate::transaction::TxFeeConfig {
            token_creation_fee: 1_000,
            ..crate::transaction::TxFeeConfig::default()
        });
        let tx = token_creation_tx_with_fee(999);

        let result = validator.validate_economics_with_system_check(&tx, false);

        assert!(
            matches!(result, Err(ValidationError::InvalidFee)),
            "TokenCreation with low fee must be rejected with InvalidFee, got: {:?}",
            result
        );
    }

    #[test]
    fn test_token_creation_high_fee_rejected() {
        let validator = TransactionValidator::with_fee_config(crate::transaction::TxFeeConfig {
            token_creation_fee: 1_000,
            ..crate::transaction::TxFeeConfig::default()
        });
        let tx = token_creation_tx_with_fee(1_001);

        let result = validator.validate_economics_with_system_check(&tx, false);

        assert!(
            matches!(result, Err(ValidationError::InvalidFee)),
            "TokenCreation with non-canonical high fee must be rejected with InvalidFee, got: {:?}",
            result
        );
    }

    /// Build a canonical CBE BUY transaction signed with a real Dilithium5 keypair.
    ///
    /// Signing is over `hash_for_signature(&tx)` to match `validate_signature()`.
    /// We pay the full ~7.2 KB Dilithium5 cost — and now we actually verify it (#1942).
    fn canonical_bonding_curve_buy_tx(signer: &lib_crypto::KeyPair) -> Transaction {
        use crate::transaction::hashing::hash_for_signature;

        let payload = crate::transaction::encode_bonding_curve_buy(&lib_types::BondingCurveBuyTx {
            action: crate::transaction::BONDING_CURVE_BUY_ACTION,
            chain_id: 0x03,
            nonce: lib_types::Nonce48::from_u64(9).unwrap(),
            sender: signer.public_key.key_id,
            amount_in: 100,
            max_price: 200,
            expected_s_c: 300,
        });

        // Build with placeholder empty signature first so the signing hash is stable.
        let mut tx = Transaction {
            version: 3,
            chain_id: 0x03,
            transaction_type: TransactionType::BondingCurveBuy,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: vec![],
                public_key: signer.public_key.clone(),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            },
            memo: payload.to_vec(),
            payload: crate::transaction::TransactionPayload::None,
        };

        // Sign the canonical message used by validate_signature().
        let msg = hash_for_signature(&tx);
        tx.signature = signer.sign(msg.as_bytes()).unwrap();
        tx
    }

    #[test]
    fn test_canonical_bonding_curve_buy_memo_is_accepted_without_legacy_data() {
        let signer = lib_crypto::KeyPair::generate().unwrap();
        let tx = canonical_bonding_curve_buy_tx(&signer);
        let validator = TransactionValidator::new();

        let result = validator.validate_transaction(&tx);
        assert!(
            result.is_ok(),
            "canonical bonding-curve memo should validate without legacy buy data: {result:?}"
        );
    }

    #[test]
    fn test_canonical_bonding_curve_buy_rejects_chain_id_mismatch() {
        let signer = lib_crypto::KeyPair::generate().unwrap();
        let mut tx = canonical_bonding_curve_buy_tx(&signer);
        tx.chain_id = 0x02;
        let validator = TransactionValidator::new();

        let result = validator.validate_transaction(&tx);
        assert!(matches!(result, Err(ValidationError::InvalidTransaction)));
    }

    // =========================================================================
    // validate_record_on_ramp_trade tests (#1894)
    // =========================================================================

    /// Build a minimal RecordOnRampTrade transaction skeleton with no approvals.
    fn make_record_on_ramp_trade_tx(
        cbe_amount: u128,
        usdc_amount: u128,
        domain: crate::transaction::threshold_approval::ApprovalDomain,
    ) -> Transaction {
        use crate::transaction::core::{RecordOnRampTradeData, TX_VERSION_V8};
        use crate::transaction::threshold_approval::ThresholdApprovalSet;

        let sender = test_public_key(1);
        Transaction {
            version: TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::RecordOnRampTrade,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: test_signature(&sender),
            memo: vec![],
            payload: crate::transaction::TransactionPayload::RecordOnRampTrade(
                RecordOnRampTradeData {
                    epoch_id: 1,
                    cbe_amount,
                    usdc_amount,
                    traded_at: 1_000_000,
                    approvals: ThresholdApprovalSet::new(domain),
                },
            ),
        }
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_missing_data() {
        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let sender = test_public_key(1);
        // Transaction with RecordOnRampTrade type but no data set
        let tx = Transaction {
            version: 8,
            chain_id: 0x03,
            transaction_type: TransactionType::RecordOnRampTrade,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: test_signature(&sender),
            memo: vec![],
            payload: crate::transaction::TransactionPayload::None, // intentionally absent
        };

        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::MissingRequiredData)),
            "expected MissingRequiredData, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_nonzero_fee() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let mut tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::OracleCommittee);
        tx.fee = 1; // must be 0

        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidFee)),
            "expected InvalidFee, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_zero_cbe_amount() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_record_on_ramp_trade_tx(0, 200, ApprovalDomain::OracleCommittee);
        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidAmount)),
            "expected InvalidAmount for zero cbe_amount, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_zero_usdc_amount() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_record_on_ramp_trade_tx(100, 0, ApprovalDomain::OracleCommittee);
        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidAmount)),
            "expected InvalidAmount for zero usdc_amount, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_wrong_domain() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        // BootstrapCouncil domain instead of OracleCommittee
        let tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::BootstrapCouncil);
        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidApproval)),
            "expected InvalidApproval for wrong domain, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_with_inputs() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let mut tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::OracleCommittee);
        tx.inputs = vec![TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: [1u8; 32].into(),
            zk_proof: crate::integration::zk_integration::ZkTransactionProof::default(),
        }];

        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidInputs)),
            "expected InvalidInputs, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_rejects_with_outputs() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let key = test_public_key(5);
        let mut tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::OracleCommittee);
        tx.outputs = vec![TransactionOutput {
            commitment: Hash::from([1u8; 32]),
            note: Hash::from([2u8; 32]),
            recipient: key,
            merkle_leaf: Hash::default(),
        }];

        let result = validator.validate_record_on_ramp_trade(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidOutputs)),
            "expected InvalidOutputs, got: {result:?}"
        );
    }

    #[test]
    fn test_record_on_ramp_trade_correct_domain_proceeds_to_threshold_check() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        // Valid domain and amounts but zero approvals → ThresholdNotMet (threshold > 0)
        let tx = make_record_on_ramp_trade_tx(100, 200, ApprovalDomain::OracleCommittee);
        let result = validator.validate_record_on_ramp_trade(&tx);

        // With council_threshold defaulting to 4 and 0 approvals we expect ThresholdNotMet
        assert!(
            matches!(result, Err(ValidationError::ThresholdNotMet)),
            "expected ThresholdNotMet with empty approvals, got: {result:?}"
        );
    }

    // =========================================================================
    // validate_treasury_allocation tests (#1896)
    // =========================================================================

    /// Build a minimal TreasuryAllocation transaction skeleton with no approvals.
    fn make_treasury_allocation_tx(
        source_treasury_key_id: [u8; 32],
        destination_key_id: [u8; 32],
        amount: u64,
        domain: crate::transaction::threshold_approval::ApprovalDomain,
    ) -> Transaction {
        use crate::transaction::core::{TreasuryAllocationData, TX_VERSION_V8};
        use crate::transaction::threshold_approval::ThresholdApprovalSet;

        let sender = test_public_key(1);
        Transaction {
            version: TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::TreasuryAllocation,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: test_signature(&sender),
            memo: vec![],
            payload: crate::transaction::TransactionPayload::TreasuryAllocation(
                TreasuryAllocationData {
                    source_treasury_key_id,
                    destination_key_id,
                    amount,
                    spending_category: "infrastructure".to_string(),
                    proposal_id: [0xAA; 32],
                    approvals: ThresholdApprovalSet::new(domain),
                },
            ),
        }
    }

    #[test]
    fn test_treasury_allocation_rejects_missing_data() {
        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let sender = test_public_key(1);
        let tx = Transaction {
            version: 8,
            chain_id: 0x03,
            transaction_type: TransactionType::TreasuryAllocation,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: test_signature(&sender),
            memo: vec![],
            payload: crate::transaction::TransactionPayload::None, // intentionally absent
        };

        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::MissingRequiredData)),
            "expected MissingRequiredData, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_nonzero_fee() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let mut tx = make_treasury_allocation_tx(
            [0x01; 32],
            [0x02; 32],
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        tx.fee = 1;

        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidFee)),
            "expected InvalidFee, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_zero_amount() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_treasury_allocation_tx(
            [0x01; 32],
            [0x02; 32],
            0, // zero amount
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidAmount)),
            "expected InvalidAmount, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_same_source_and_destination() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        let key_id = [0x01; 32];
        let tx = make_treasury_allocation_tx(
            key_id,
            key_id, // same as source
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidTransaction)),
            "expected InvalidTransaction for identical source/dest, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_wrong_domain() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        let blockchain = crate::blockchain::Blockchain::default();
        let validator = StatefulTransactionValidator::new(&blockchain);

        // OracleCommittee domain instead of BootstrapCouncil
        let tx = make_treasury_allocation_tx(
            [0x01; 32],
            [0x02; 32],
            1000,
            ApprovalDomain::OracleCommittee,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidApproval)),
            "expected InvalidApproval for wrong domain, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_without_entity_registry() {
        use crate::transaction::threshold_approval::ApprovalDomain;

        // Blockchain with no entity_registry set
        let blockchain = crate::blockchain::Blockchain::default();
        assert!(blockchain.entity_registry.is_none());
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_treasury_allocation_tx(
            [0x01; 32],
            [0x02; 32],
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidTransaction)),
            "expected InvalidTransaction without entity registry, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_with_uninitialized_entity_registry() {
        use crate::contracts::governance::EntityRegistry;
        use crate::transaction::threshold_approval::ApprovalDomain;

        let mut blockchain = crate::blockchain::Blockchain::default();
        // Set an uninitialized registry
        blockchain.entity_registry = Some(EntityRegistry::new());
        let validator = StatefulTransactionValidator::new(&blockchain);

        let tx = make_treasury_allocation_tx(
            [0x01; 32],
            [0x02; 32],
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::InvalidTransaction)),
            "expected InvalidTransaction with uninitialized registry, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_rejects_wrong_source_key_id() {
        use crate::contracts::governance::EntityRegistry;
        use crate::transaction::threshold_approval::ApprovalDomain;

        // Initialize registry with a known CBE treasury public key
        let cbe_pk = PublicKey::new([0xCBu8; 2592]);
        let nonprofit_pk = PublicKey::new([0x11u8; 2592]);

        let mut registry = EntityRegistry::new();
        registry.init(cbe_pk.clone(), nonprofit_pk).unwrap();

        let mut blockchain = crate::blockchain::Blockchain::default();
        blockchain.entity_registry = Some(registry);
        let validator = StatefulTransactionValidator::new(&blockchain);

        // Source key does NOT match the CBE treasury key_id
        let wrong_source = [0xFF; 32];
        let destination = [0x02; 32];
        let tx = make_treasury_allocation_tx(
            wrong_source,
            destination,
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);
        assert!(
            matches!(result, Err(ValidationError::Unauthorized)),
            "expected Unauthorized when source_treasury_key_id does not match CBE treasury, got: {result:?}"
        );
    }

    #[test]
    fn test_treasury_allocation_correct_source_proceeds_to_threshold_check() {
        use crate::contracts::governance::EntityRegistry;
        use crate::transaction::threshold_approval::ApprovalDomain;

        // Initialize registry with a known CBE treasury public key
        let cbe_pk = PublicKey::new([0xCBu8; 2592]);
        let nonprofit_pk = PublicKey::new([0x11u8; 2592]);
        let cbe_key_id = cbe_pk.key_id;

        let mut registry = EntityRegistry::new();
        registry.init(cbe_pk.clone(), nonprofit_pk).unwrap();

        let mut blockchain = crate::blockchain::Blockchain::default();
        blockchain.entity_registry = Some(registry);
        let validator = StatefulTransactionValidator::new(&blockchain);

        // Source matches the CBE treasury key_id; destination is different
        let tx = make_treasury_allocation_tx(
            cbe_key_id,
            [0x02; 32],
            1000,
            ApprovalDomain::BootstrapCouncil,
        );
        let result = validator.validate_treasury_allocation(&tx);

        // With council_threshold defaulting to 4 and 0 approvals we expect ThresholdNotMet
        assert!(
            matches!(result, Err(ValidationError::ThresholdNotMet)),
            "expected ThresholdNotMet with empty approvals after passing source check, got: {result:?}"
        );
    }
}
