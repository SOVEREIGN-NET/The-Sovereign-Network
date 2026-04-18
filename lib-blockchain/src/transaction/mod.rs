//! Transaction management module
//!
//! Handles transaction structures, creation, validation, hashing, and signing.
//! Identity transactions delegate processing to lib-identity package.

pub mod bonding_curve_codec;
pub mod contract_deployment;
pub mod contract_execution;
pub mod core;
pub mod creation;
pub mod domain;
pub mod fee;
pub mod hashing;
pub mod oracle_governance;
pub mod signing;
pub mod threshold_approval;
pub mod token_creation;
pub mod validation;

pub use domain::{
    DomainRegistrationPayload, DomainUpdatePayload, OnChainDomainRecord,
    DOMAIN_REGISTRATION_PREFIX, DOMAIN_UPDATE_PREFIX,
};

// Explicit re-exports from core module
pub use core::{
    BondingCurveBuyData, BondingCurveDeployData, BondingCurveGraduateData, BondingCurveSellData,
    CreateEmploymentContractData, DaoExecutionData, DaoProposalData, DaoStakeData, DaoUnstakeData,
    DaoVoteData, GatewayOperation, GatewayTransactionData,
    GovernanceConfigOperation, GovernanceConfigUpdateData, IdentityTransactionData,
    InitCbeTokenData, InitEntityRegistryData, ProcessPayrollData, ProfitDeclarationData,
    RecordOnRampTradeData, RevenueSource, TokenMintData, TokenTransferData, Transaction,
    TransactionInput, TransactionOutput, TransactionPayload, TreasuryAllocationData, UbiClaimData,
    ValidatorOperation, ValidatorTransactionData, WalletPrivateData, WalletReference,
    WalletTransactionData, TX_VERSION_V3, TX_VERSION_V7, TX_VERSION_V8,
};

// Re-exports from threshold_approval module
pub use threshold_approval::{
    compute_approval_preimage, validate_threshold_approvals, Approval, ApprovalDomain,
    ThresholdApprovalSet, ThresholdError, THRESHOLD_APPROVAL_DOMAIN_TAG,
};

pub use bonding_curve_codec::{
    bonding_curve_signed_region, decode_bonding_curve_buy, decode_bonding_curve_sell,
    decode_canonical_bonding_curve_tx, encode_bonding_curve_buy, encode_bonding_curve_sell,
    encode_canonical_bonding_curve_tx, envelope_signer_matches_sender, BondingCurveCodecError,
    CanonicalBondingCurveEnvelope, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
    BONDING_CURVE_SELL_ACTION, BONDING_CURVE_TX_PAYLOAD_LEN, BONDING_CURVE_TX_SIGNED_REGION_END,
};

// Re-exports from oracle_governance module
pub use oracle_governance::{
    CancelOracleUpdateData, OracleAttestationData, OracleCommitteeUpdateData,
    OracleConfigUpdateData, OracleProtocolUpgradeData,
};

// Explicit re-exports from creation module
pub use creation::{
    create_contract_deployment_transaction, create_contract_transaction,
    create_identity_transaction, create_token_transaction, create_transfer_transaction,
    create_wallet_transaction, TransactionBuilder, TransactionCreateError,
};

// Explicit re-exports from fee module
pub use contract_deployment::{
    ContractDeploymentPayloadV1, CONTRACT_DEPLOYMENT_MEMO_PREFIX, MAX_DEPLOYMENT_ABI_BYTES,
    MAX_DEPLOYMENT_CODE_BYTES, MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES, MAX_DEPLOYMENT_INIT_ARGS_BYTES,
    MAX_DEPLOYMENT_MEMORY_BYTES, MAX_DEPLOYMENT_MEMO_BYTES,
};
pub use contract_execution::{
    encode_contract_execution_memo_v2, ContractExecutionMemoVersion, DecodedContractExecutionMemo,
    CONTRACT_EXECUTION_MEMO_PREFIX_V1, CONTRACT_EXECUTION_MEMO_PREFIX_V2,
    MAX_CONTRACT_EXECUTION_MEMO_BYTES,
};
pub use fee::{required_token_creation_fee, TxFeeConfig, DEFAULT_TOKEN_CREATION_FEE};
pub use token_creation::{
    TokenCreationPayloadV1, MAX_TOKEN_CREATION_MEMO_BYTES, MAX_TOKEN_NAME_BYTES,
    MAX_TOKEN_SYMBOL_BYTES, TOKEN_CREATION_MEMO_PREFIX,
};

// Explicit re-exports from validation module
pub use validation::{
    is_token_contract_execution, StatefulTransactionValidator, TransactionValidator,
    ValidationError, ValidationResult,
};

// Explicit re-exports from hashing module
pub use hashing::{
    calculate_transaction_merkle_root, create_commitment, create_encrypted_note,
    generate_nullifier, hash_for_signature, hash_transaction, hash_transaction_for_signing,
    hash_transaction_input, hash_transaction_output,
};

// Explicit re-exports from signing module
pub use signing::{sign_transaction, verify_transaction_signature, SigningError};
