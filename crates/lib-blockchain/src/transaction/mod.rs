//! Transaction management module
//!
//! Handles transaction structures, creation, validation, hashing, and signing.
//! Identity transactions delegate processing to lib-identity package.

pub mod core;
pub mod creation;
pub mod validation;
pub mod hashing;
pub mod signing;

pub use core::*;
pub use creation::{TransactionBuilder, TransactionCreateError, create_transfer_transaction, create_identity_transaction, create_wallet_transaction, create_contract_transaction, create_token_transaction};
pub use validation::*;
pub use hashing::*;
pub use signing::{SigningError, sign_transaction, verify_transaction_signature};
