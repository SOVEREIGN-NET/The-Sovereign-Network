//! Transaction management module
//!
//! Handles transaction structures, creation, validation, hashing, and signing.
//! Identity transactions delegate processing to lib-identity package.

pub mod core;
pub mod creation;
pub mod validation;
pub mod hashing;
pub mod signing;

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
    create_token_transaction,
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
