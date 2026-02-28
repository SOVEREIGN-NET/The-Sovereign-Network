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
//!    the current state can be reconstructed determinically. No "magic" state.
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
// These types extend canonical types with storage-specific functionality.
// They are NOT duplicates - they provide additional storage-layer behavior.
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
// This follows the "extension trait" pattern - we extend types we don't own.
// =============================================================================

/// Extension trait adding storage-specific methods to BlockHash
pub trait BlockHashExt {
    /// Zero hash (used for genesis parent)
    const ZERO: Self;
    /// Create from bytes
    fn new(bytes: [u8; 32]) -> Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl BlockHashExt for BlockHash {
    const ZERO: Self = Self([0u8; 32]);

    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for BlockHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Extension trait adding storage-specific methods to TxHash
pub trait TxHashExt {
    /// Zero hash
    const ZERO: Self;
    /// Create from bytes
    fn new(bytes: [u8; 32]) -> Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl TxHashExt for TxHash {
    const ZERO: Self = Self([0u8; 32]);

    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for TxHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Extension trait adding storage-specific methods to Address
pub trait AddressExt {
    /// Zero address
    const ZERO: Self;
    /// Create from bytes
    fn new(bytes: [u8; 32]) -> Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
}

impl AddressExt for Address {
    const ZERO: Self = Self([0u8; 32]);

    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Extension trait adding storage-specific methods to TokenId
pub trait TokenIdExt {
    /// Native SOV token (all zeros)
    const NATIVE: Self;
    /// Create from bytes
    fn new(bytes: [u8; 32]) -> Self;
    /// Convert to Vec<u8>
    fn to_vec(&self) -> Vec<u8>;
    /// Check if this is the native token
    fn is_native(&self) -> bool;
}

impl TokenIdExt for TokenId {
    const NATIVE: Self = Self([0u8; 32]);

    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn is_native(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_native() {
            write!(f, "NATIVE")
        } else {
            write!(f, "{}", hex::encode(self.0))
        }
    }
}

impl AsRef<[u8]> for TokenId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for TokenId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

// =============================================================================
// UTXO TYPE
