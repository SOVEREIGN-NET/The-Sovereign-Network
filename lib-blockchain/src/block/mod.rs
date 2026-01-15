//! Block structures and handling
//!
//! Provides core block data structures and utilities for the ZHTP blockchain.

pub mod core;
pub mod creation;

// Explicit re-exports from block core module
pub use core::{
    Block,
    BlockHeader,
    create_genesis_block,
    BlockValidationResult,
    BlockValidationError,
    MAX_BLOCK_SIZE,
    MAX_TRANSACTIONS_PER_BLOCK,
    MIN_BLOCK_TIME,
    MAX_BLOCK_TIME,
};

// Explicit re-exports from block creation module
pub use creation::{
    BlockBuilder,
    create_block,
    create_genesis_block_with_transactions,
    mine_block,
    mine_block_with_config,
    estimate_block_time,
    select_transactions_for_block,
};
