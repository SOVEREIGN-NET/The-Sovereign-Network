//! Transaction Application - State Mutation Primitives
//!
//! This module contains the ONLY functions allowed to mutate consensus state.
//! No other code may call BlockchainStore write methods directly.
//!
//! # Invariants
//!
//! - All mutations occur within begin_block/commit_block boundaries
//! - UTXO spends are one-time (spend removes, creating same outpoint re-adds)
//! - No negative balances (enforced by debit_token)
//! - All changes are deterministic and reproducible

use crate::block::Block;
use crate::storage::{
    AccountState, Address, BlockchainStore, OutPoint, StorageResult,
    TokenId, Utxo, WalletState,
};
use crate::transaction::{Transaction, TransactionOutput};
use crate::types::Hash;

use super::errors::{TxApplyError, TxApplyResult};

/// State mutator - wraps store and provides controlled mutation primitives
///
/// This struct ensures all state mutations go through controlled functions.
/// It must be created within a block transaction context.
pub struct StateMutator<'a> {
    store: &'a dyn BlockchainStore,
}

impl<'a> StateMutator<'a> {
    /// Create a new state mutator
    ///
    /// IMPORTANT: Only call this after store.begin_block() has been called.
    pub fn new(store: &'a dyn BlockchainStore) -> Self {
        Self { store }
    }

    // =========================================================================
    // UTXO Primitives
    // =========================================================================

    /// Spend a UTXO (load and delete atomically)
    ///
    /// Returns the UTXO that was spent.
    ///
    /// # Errors
    /// - `UtxoNotFound` if the UTXO doesn't exist
    pub fn spend_utxo(&self, outpoint: &OutPoint) -> TxApplyResult<Utxo> {
        // Load the UTXO
        let utxo = self.store
            .get_utxo(outpoint)?
            .ok_or_else(|| TxApplyError::UtxoNotFound(outpoint.clone()))?;

        // Delete it (mark as spent)
        self.store.delete_utxo(outpoint)?;

        Ok(utxo)
    }

    /// Create a new UTXO
    ///
    /// The outpoint is derived from tx_hash + output_index.
    pub fn create_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> TxApplyResult<()> {
        self.store.put_utxo(outpoint, utxo)?;
        Ok(())
    }

    /// Create UTXOs from transaction outputs with explicit amounts
    ///
    /// Helper that creates outpoints from tx hash and output indices.
    /// Amounts must be provided explicitly since TransactionOutput uses ZK commitments.
    pub fn create_utxos_with_amounts(
        &self,
        tx_hash: &Hash,
        outputs: &[TransactionOutput],
        amounts: &[u64],
        block_height: u64,
    ) -> TxApplyResult<()> {
        use crate::storage::TxHash;

        if outputs.len() != amounts.len() {
            return Err(TxApplyError::Internal(
                "Output count doesn't match amount count".to_string()
            ));
        }

        let tx_hash_bytes = tx_hash.as_array();

        for (index, (output, &amount)) in outputs.iter().zip(amounts.iter()).enumerate() {
            let outpoint = OutPoint::new(
                TxHash::new(tx_hash_bytes),
                index as u32,
            );

            let utxo = Utxo {
                amount,
                owner: Address::new(output.recipient.as_bytes().try_into().unwrap_or([0u8; 32])),
                token: TokenId::NATIVE,
                created_at_height: block_height,
                script: None,
            };

            self.create_utxo(&outpoint, &utxo)?;
        }

        Ok(())
    }

    // =========================================================================
    // Token Balance Primitives
    // =========================================================================

    /// Debit tokens from an address
    ///
    /// # Errors
    /// - `InsufficientBalance` if balance < amount
    pub fn debit_token(
        &self,
        token: TokenId,
        addr: &Address,
        amount: u128,
    ) -> TxApplyResult<()> {
        if amount == 0 {
            return Ok(());
        }

        let current = self.store.get_token_balance(token, addr)?;

        if current < amount {
            return Err(TxApplyError::InsufficientBalance {
                have: current,
                need: amount,
                token,
            });
        }

        let new_balance = current - amount;
        self.store.set_token_balance(token, addr, new_balance)?;

        Ok(())
    }

    /// Credit tokens to an address
    ///
    /// # Panics
    /// Panics on u128 overflow (should never happen in practice)
    pub fn credit_token(
        &self,
        token: TokenId,
        addr: &Address,
        amount: u128,
    ) -> TxApplyResult<()> {
        if amount == 0 {
            return Ok(());
        }

        let current = self.store.get_token_balance(token, addr)?;
        let new_balance = current.checked_add(amount)
            .expect("Token balance overflow - this should never happen");

        self.store.set_token_balance(token, addr, new_balance)?;

        Ok(())
    }

    /// Transfer tokens between addresses
    ///
    /// Atomic debit from sender, credit to receiver.
    pub fn transfer_token(
        &self,
        token: TokenId,
        from: &Address,
        to: &Address,
        amount: u128,
    ) -> TxApplyResult<()> {
        self.debit_token(token, from, amount)?;
        self.credit_token(token, to, amount)?;
        Ok(())
    }

    // =========================================================================
    // Account Primitives
    // =========================================================================

    /// Load account state, returning default if not exists
    pub fn load_account(&self, addr: &Address) -> TxApplyResult<AccountState> {
        Ok(self.store.get_account(addr)?
            .unwrap_or_else(|| AccountState::new(*addr)))
    }

    /// Store account state
    pub fn put_account(&self, addr: &Address, acct: &AccountState) -> TxApplyResult<()> {
        self.store.put_account(addr, acct)?;
        Ok(())
    }

    /// Get account nonce
    pub fn get_nonce(&self, addr: &Address) -> TxApplyResult<u64> {
        let acct = self.load_account(addr)?;
        Ok(acct.wallet.map(|w| w.nonce).unwrap_or(0))
    }

    /// Set account nonce
    pub fn set_nonce(&self, addr: &Address, nonce: u64) -> TxApplyResult<()> {
        let mut acct = self.load_account(addr)?;

        // Ensure wallet state exists
        let wallet = acct.wallet.get_or_insert_with(WalletState::default);
        wallet.nonce = nonce;

        self.put_account(addr, &acct)?;
        Ok(())
    }

    /// Increment account nonce
    pub fn increment_nonce(&self, addr: &Address) -> TxApplyResult<u64> {
        let current = self.get_nonce(addr)?;
        let new_nonce = current + 1;
        self.set_nonce(addr, new_nonce)?;
        Ok(new_nonce)
    }
}

// =============================================================================
// Transaction Type Applicators
// =============================================================================

/// Apply a native transfer transaction (UTXO model)
///
/// This spends input UTXOs and creates output UTXOs.
///
/// Phase 2 Note: Since TransactionOutput uses ZK commitments instead of plain
/// amounts, we derive output amounts by distributing input value minus fee
/// equally among outputs. This is a simplification for Phase 2.
pub fn apply_native_transfer(
    mutator: &StateMutator<'_>,
    tx: &Transaction,
    tx_hash: &Hash,
    block_height: u64,
) -> TxApplyResult<TransferOutcome> {
    use crate::storage::TxHash;

    let mut total_input: u64 = 0;

    // Spend all inputs and sum their values
    for input in &tx.inputs {
        let outpoint = OutPoint::new(
            TxHash::new(input.previous_output.as_array()),
            input.output_index,
        );

        let utxo = mutator.spend_utxo(&outpoint)?;
        total_input = total_input.saturating_add(utxo.amount);
    }

    // Calculate available value after fee
    let fee = tx.fee;
    if total_input < fee {
        return Err(TxApplyError::InsufficientInputs {
            have: total_input,
            need: fee,
        });
    }
    let available = total_input - fee;

    // Distribute available value equally among outputs
    // (Phase 2 simplification - real implementation would use ZK proofs)
    let output_count = tx.outputs.len() as u64;
    if output_count == 0 {
        return Err(TxApplyError::Internal("No outputs".to_string()));
    }
    let amount_per_output = available / output_count;
    let remainder = available % output_count;

    let mut total_output: u64 = 0;
    for (index, output) in tx.outputs.iter().enumerate() {
        let outpoint = OutPoint::new(
            TxHash::new(tx_hash.as_array()),
            index as u32,
        );

        // First output gets remainder
        let amount = if index == 0 {
            amount_per_output + remainder
        } else {
            amount_per_output
        };

        let utxo = Utxo {
            amount,
            owner: Address::new(output.recipient.as_bytes().try_into().unwrap_or([0u8; 32])),
            token: TokenId::NATIVE,
            created_at_height: block_height,
            script: None,
        };

        mutator.create_utxo(&outpoint, &utxo)?;
        total_output = total_output.saturating_add(amount);
    }

    Ok(TransferOutcome {
        inputs_spent: tx.inputs.len(),
        outputs_created: tx.outputs.len(),
        total_value: total_output,
        fee,
    })
}

/// Apply a token transfer transaction (balance model)
pub fn apply_token_transfer(
    mutator: &StateMutator<'_>,
    token: TokenId,
    from: &Address,
    to: &Address,
    amount: u128,
) -> TxApplyResult<()> {
    mutator.transfer_token(token, from, to, amount)
}

/// Apply a coinbase transaction (block reward)
///
/// Coinbase creates new value - no inputs are spent.
/// The reward is distributed equally among outputs.
pub fn apply_coinbase(
    mutator: &StateMutator<'_>,
    tx: &Transaction,
    tx_hash: &Hash,
    block_height: u64,
    expected_reward: u64,
) -> TxApplyResult<CoinbaseOutcome> {
    use crate::storage::TxHash;

    // Coinbase must have no inputs
    if !tx.inputs.is_empty() {
        return Err(TxApplyError::InvalidType(
            "Coinbase transaction must have no inputs".to_string()
        ));
    }

    if tx.outputs.is_empty() {
        return Err(TxApplyError::Internal("Coinbase must have outputs".to_string()));
    }

    // Distribute reward equally among outputs
    let output_count = tx.outputs.len() as u64;
    let amount_per_output = expected_reward / output_count;
    let remainder = expected_reward % output_count;

    let mut total_output: u64 = 0;

    for (index, output) in tx.outputs.iter().enumerate() {
        let outpoint = OutPoint::new(
            TxHash::new(tx_hash.as_array()),
            index as u32,
        );

        // First output gets remainder
        let amount = if index == 0 {
            amount_per_output + remainder
        } else {
            amount_per_output
        };

        let utxo = Utxo {
            amount,
            owner: Address::new(output.recipient.as_bytes().try_into().unwrap_or([0u8; 32])),
            token: TokenId::NATIVE,
            created_at_height: block_height,
            script: None,
        };

        mutator.create_utxo(&outpoint, &utxo)?;
        total_output = total_output.saturating_add(amount);
    }

    Ok(CoinbaseOutcome {
        outputs_created: tx.outputs.len(),
        total_reward: total_output,
    })
}

// =============================================================================
// Outcome Types
// =============================================================================

/// Outcome of a native transfer
#[derive(Debug, Clone)]
pub struct TransferOutcome {
    pub inputs_spent: usize,
    pub outputs_created: usize,
    pub total_value: u64,
    pub fee: u64,
}

/// Outcome of a coinbase transaction
#[derive(Debug, Clone)]
pub struct CoinbaseOutcome {
    pub outputs_created: usize,
    pub total_reward: u64,
}
