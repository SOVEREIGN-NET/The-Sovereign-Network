//! Block Execution Module
//!
//! This module implements the canonical block execution pipeline.
//! It is the ONLY entry point for applying blocks to blockchain state.
//!
//! # Architecture
//!
//! ```text
//! BlockExecutor::apply_block(block)
//!     │
//!     ├── 1. Prechecks (height, structure)
//!     │
//!     ├── 2. begin_block(height)
//!     │
//!     ├── 3. For each transaction:
//!     │       ├── validate_stateless(tx)
//!     │       ├── validate_stateful(tx)  [reads only]
//!     │       └── apply(tx)              [writes via StateMutator]
//!     │
//!     ├── 4. append_block(block)
//!     │
//!     └── 5. commit_block()
//!
//!     On error: rollback_block()
//! ```
//!
//! # Key Types
//!
//! - [`BlockExecutor`] - Main entry point for block application
//! - [`StateMutator`] - Controlled state mutation primitives
//! - [`StateView`] - Read-only state access for validation
//!
//! # Invariants
//!
//! - All state mutations occur within begin_block/commit_block
//! - Rollback restores exact pre-block state
//! - Deterministic: same block + same pre-state = same mutations

pub mod errors;
pub mod executor;
pub mod state_view;
pub mod tx_apply;

// Re-exports
pub use errors::{BlockApplyError, BlockApplyResult, TxApplyError, TxApplyResult};
pub use executor::{
    ApplyOutcome, BlockExecutor, ExecutorConfig, StateChangesSummary, TokenMintOutcome,
    TokenTransferOutcome,
};
pub use state_view::{StateView, StateViewExt};
pub use tx_apply::{CoinbaseOutcome, OracleAttestationOutcome, StateMutator, TransferOutcome};
