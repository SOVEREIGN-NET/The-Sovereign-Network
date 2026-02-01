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

pub mod errors;
pub mod block_validate;
pub mod tx_validate;

// Re-exports
pub use errors::{
    BlockValidateError, BlockValidateResult,
    TxValidateError, TxValidateResult,
};

pub use block_validate::{
    BlockValidateConfig,
    BlockResourceUsage,
    validate_block_structure,
    validate_block_context,
    validate_block,
    validate_block_resource_limits,
};

pub use tx_validate::{
    validate_stateless,
    validate_stateful,
    validate_stateful_with_fees,
    validate_fee,
    validate_transactions_stateless,
    validate_transactions_stateful,
};
