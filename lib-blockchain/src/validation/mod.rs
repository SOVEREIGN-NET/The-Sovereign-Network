//! Validation Module
//!
//! Block and transaction validation logic.
//!
//! # Validation vs Execution
//!
//! - **Validation**: Checks if block/tx is well-formed and can be applied
//! - **Execution**: Actually applies the block/tx and mutates state
//!
//! Validation happens BEFORE execution and must not modify state.
//!
//! # Phase 2 Allowlist
//!
//! Only these transaction types pass validation:
//! - Transfer (native UTXO spend/create)
//! - TokenTransfer (balance debit/credit)
//! - Coinbase (block reward)
//!
//! All other types are rejected with `UnsupportedType` error.

pub mod block_validate;
pub mod errors;
pub mod tx_validate;

// Re-exports
pub use errors::{BlockValidateError, BlockValidateResult, TxValidateError, TxValidateResult};

pub use block_validate::{
    validate_block, validate_block_context, validate_block_resource_limits,
    validate_block_structure, BlockResourceUsage, BlockValidateConfig,
};

pub use tx_validate::{
    validate_fee, validate_stateful, validate_stateful_with_fees, validate_stateless,
    validate_transactions_stateful, validate_transactions_stateless,
};
