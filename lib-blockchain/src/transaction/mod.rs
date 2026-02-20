//! Transaction management module
//!
//! Handles transaction structures, creation, validation, hashing, and signing.
//! Identity transactions delegate processing to lib-identity package.

pub mod core;
pub mod creation;
pub mod validation;
pub mod hashing;
pub mod signing;
pub mod fee;
pub mod contract_deployment;
pub mod contract_execution;
pub mod token_creation;

// Explicit re-exports from core module
pub use core::{
    Transaction,
    DaoProposalData,
    DaoVoteData,
    DaoExecutionData,
    UbiClaimData,
    ProfitDeclarationData,
    RevenueSource,
    TokenTransferData,
    TokenMintData,
    TransactionInput,
    TransactionOutput,
    IdentityTransactionData,
    WalletTransactionData,
    WalletReference,
    WalletPrivateData,
    ValidatorTransactionData,
    ValidatorOperation,
};

// Explicit re-exports from creation module
pub use creation::{
    TransactionBuilder,
    TransactionCreateError,
    create_transfer_transaction,
    create_identity_transaction,
    create_wallet_transaction,
    create_contract_transaction,
    create_contract_deployment_transaction,
    create_token_transaction,
};

// Explicit re-exports from fee module
pub use fee::TxFeeConfig;
pub use contract_deployment::{
    ContractDeploymentPayloadV1,
    CONTRACT_DEPLOYMENT_MEMO_PREFIX,
    MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES,
    MAX_DEPLOYMENT_MEMO_BYTES,
    MAX_DEPLOYMENT_CODE_BYTES,
    MAX_DEPLOYMENT_ABI_BYTES,
    MAX_DEPLOYMENT_INIT_ARGS_BYTES,
    MAX_DEPLOYMENT_MEMORY_BYTES,
};
pub use contract_execution::{
    ContractExecutionMemoVersion,
    DecodedContractExecutionMemo,
    CONTRACT_EXECUTION_MEMO_PREFIX_V1,
    CONTRACT_EXECUTION_MEMO_PREFIX_V2,
    MAX_CONTRACT_EXECUTION_MEMO_BYTES,
    encode_contract_execution_memo_v2,
};
pub use token_creation::{
    TokenCreationPayloadV1,
    TOKEN_CREATION_MEMO_PREFIX,
    MAX_TOKEN_NAME_BYTES,
    MAX_TOKEN_SYMBOL_BYTES,
    MAX_TOKEN_CREATION_MEMO_BYTES,
};

// Explicit re-exports from validation module
pub use validation::{
    ValidationError,
    ValidationResult,
    TransactionValidator,
    StatefulTransactionValidator,
    is_token_contract_execution,
};

// Explicit re-exports from hashing module
pub use hashing::{
    hash_transaction,
    hash_transaction_for_signing,
    hash_transaction_input,
    hash_transaction_output,
    calculate_transaction_merkle_root,
    generate_nullifier,
    create_commitment,
    create_encrypted_note,
    hash_for_signature,
};

// Explicit re-exports from signing module
pub use signing::{
    SigningError,
    sign_transaction,
    verify_transaction_signature,
};
