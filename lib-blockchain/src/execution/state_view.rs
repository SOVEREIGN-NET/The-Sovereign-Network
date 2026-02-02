//! State View - Read-Only State Access
//!
//! Provides read-only access to blockchain state during validation.
//! These functions NEVER mutate state - they are for validation checks only.
//!
//! For state mutations, use tx_apply.rs primitives.

use std::sync::Arc;

use crate::storage::{
    AccountState, Address, BlockchainStore, BlockHash, OutPoint,
    StorageResult, TokenId, Utxo,
};

/// Read-only view of blockchain state
///
/// This struct wraps a BlockchainStore reference and provides
/// convenient read-only access methods for validation.
pub struct StateView<'a> {
    store: &'a dyn BlockchainStore,
}

impl<'a> StateView<'a> {
    /// Create a new state view from a store reference
    pub fn new(store: &'a dyn BlockchainStore) -> Self {
        Self { store }
    }

    // =========================================================================
    // Block Queries
    // =========================================================================

    /// Get the latest committed block height
    pub fn latest_height(&self) -> StorageResult<u64> {
        self.store.latest_height()
    }

    /// Check if a block exists at the given height
    pub fn block_exists(&self, height: u64) -> StorageResult<bool> {
        Ok(self.store.get_block_by_height(height)?.is_some())
    }

    /// Get block hash by height
    pub fn get_block_hash(&self, height: u64) -> StorageResult<Option<BlockHash>> {
        Ok(self.store.get_block_by_height(height)?
            .map(|b| BlockHash::new(b.header.block_hash.as_array())))
    }

    // =========================================================================
    // UTXO Queries
    // =========================================================================

    /// Look up a UTXO by outpoint
    ///
    /// Returns None if the UTXO doesn't exist or has been spent.
    pub fn lookup_utxo(&self, outpoint: &OutPoint) -> StorageResult<Option<Utxo>> {
        self.store.get_utxo(outpoint)
    }

    /// Check if a UTXO exists and is unspent
    pub fn utxo_exists(&self, outpoint: &OutPoint) -> StorageResult<bool> {
        Ok(self.store.get_utxo(outpoint)?.is_some())
    }

    /// Get multiple UTXOs by outpoints
    ///
    /// Returns a Vec of Option<Utxo> in the same order as input.
    pub fn lookup_utxos(&self, outpoints: &[OutPoint]) -> StorageResult<Vec<Option<Utxo>>> {
        outpoints.iter()
            .map(|op| self.store.get_utxo(op))
            .collect()
    }

    // =========================================================================
    // Token Balance Queries
    // =========================================================================

    /// Get token balance for an address
    ///
    /// Returns 0 if no balance exists.
    pub fn get_balance(&self, token: &TokenId, addr: &Address) -> StorageResult<u128> {
        self.store.get_token_balance(token, addr)
    }

    /// Get native token balance (TokenId::NATIVE)
    pub fn get_native_balance(&self, addr: &Address) -> StorageResult<u128> {
        self.store.get_token_balance(&TokenId::NATIVE, addr)
    }

    /// Check if address has sufficient balance
    pub fn has_sufficient_balance(
        &self,
        token: &TokenId,
        addr: &Address,
        required: u128,
    ) -> StorageResult<bool> {
        let balance = self.get_balance(token, addr)?;
        Ok(balance >= required)
    }

    // =========================================================================
    // Account Queries
    // =========================================================================

    /// Get account state for an address
    ///
    /// Returns None if no account exists.
    pub fn get_account(&self, addr: &Address) -> StorageResult<Option<AccountState>> {
        self.store.get_account(addr)
    }

    /// Get account nonce (0 if account doesn't exist)
    pub fn get_nonce(&self, addr: &Address) -> StorageResult<u64> {
        Ok(self.store.get_account(addr)?
            .and_then(|a| a.wallet.map(|w| w.nonce))
            .unwrap_or(0))
    }

    /// Check if account exists
    pub fn account_exists(&self, addr: &Address) -> StorageResult<bool> {
        Ok(self.store.get_account(addr)?.is_some())
    }
}

/// Extension trait for convenient store access
pub trait StateViewExt {
    fn view(&self) -> StateView<'_>;
}

impl<T: BlockchainStore> StateViewExt for T {
    fn view(&self) -> StateView<'_> {
        StateView::new(self)
    }
}
