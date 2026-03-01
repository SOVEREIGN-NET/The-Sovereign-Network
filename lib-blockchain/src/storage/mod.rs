//! Blockchain Storage Layer
//!
//! This module defines the storage contract for the ZHTP blockchain.
//! All persistence operations MUST go through the `BlockchainStore` trait.
//!
//! # Data Model Invariants
//!
//! These invariants are NON-NEGOTIABLE. Any PR violating them is rejected.
//!
//! 1. **Blocks are append-only** - Once written, blocks are never modified or deleted.
//!    The only valid block operation after genesis is `append_block`.
//!
//! 2. **State is fully derivable from blocks** - Given the genesis state and all blocks,
//!    the current state can be reconstructed deterministically. No "magic" state.
//!
//! 3. **State writes only occur inside begin_block → commit_block** - All state mutations
//!    (UTXOs, accounts, balances) must happen within an atomic block transaction.
//!
//! 4. **No state mutation outside block execution** - Consensus, validation, and query
//!    code may only READ state. Writes are exclusively during block application.
//!
//! 5. **Rollback must restore exact pre-block state** - If `rollback_block` is called,
//!    the state MUST be identical to before `begin_block` was called.
//!
//! # Design Principles
//!
//! - Consensus code MUST NOT know which database backend is used
//! - No `save_to_file`, `load_from_file`, or `serialize(Blockchain)` anywhere
//! - Key encoding is protocol - see `keys.rs`
//! - Types are canonical - no ad-hoc types cross the storage boundary
//!
//! # CONSENSUS CORE RULE
//!
//! **No String identifiers in consensus state. Ever.**
//!
//! All identifiers (DIDs, token names, etc.) must be represented as fixed-size
//! byte arrays ([u8; 32]) in consensus-critical data structures. Human-readable
//! strings are metadata, not consensus state.

pub mod keys;
pub mod sled_store;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// Re-export the store implementation
pub use sled_store::SledStore;

// Import ALL canonical types from lib-types
// These are the authoritative definitions for consensus-critical types
pub use lib_types::primitives::{Address, Amount, BlockHash, BlockHeight, Bps, TokenId, TxHash};

// =============================================================================
// STORAGE-SPECIFIC TYPES
// =============================================================================

/// Reference to a specific output within a transaction
///
/// This is the canonical way to identify a UTXO. Never use tx hash alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    /// Transaction containing this output
    pub tx: TxHash,
    /// Index of the output within the transaction (0-based)
    pub index: u32,
}

impl OutPoint {
    pub fn new(tx: TxHash, index: u32) -> Self {
        Self { tx, index }
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.tx, self.index)
    }
}

// =============================================================================
// EXTENSION TRAITS FOR CANONICAL TYPES
// =============================================================================
// These traits add storage-specific methods to canonical types from lib-types.
// The trait implementations (Display, AsRef, From) are in lib-types.
// =============================================================================

/// Extension trait adding storage-specific methods to BlockHash
pub trait BlockHashExt {
    /// Zero hash (used for genesis parent)
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl BlockHashExt for BlockHash {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to TxHash
pub trait TxHashExt {
    /// Zero hash
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl TxHashExt for TxHash {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to Address
pub trait AddressExt {
    /// Zero address
    const ZERO: Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl AddressExt for Address {
    const ZERO: Self = Self([0u8; 32]);

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Extension trait adding storage-specific methods to TokenId
pub trait TokenIdExt {
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl TokenIdExt for TokenId {
    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
