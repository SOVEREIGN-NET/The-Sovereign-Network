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

use crate::storage::{
    AccountState, Address, BlockchainStore, IdentityConsensus, IdentityMetadata, OutPoint, TokenId,
    Utxo, WalletState,
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
        let utxo = self
            .store
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
                "Output count doesn't match amount count".to_string(),
            ));
        }

        let tx_hash_bytes = tx_hash.as_array();

        for (index, (output, &amount)) in outputs.iter().zip(amounts.iter()).enumerate() {
            let outpoint = OutPoint::new(TxHash::new(tx_hash_bytes), index as u32);

            // Convert recipient public key to address bytes
            // IMPORTANT: Must not silently fall back to zero address on conversion failure
            let owner_bytes: [u8; 32] = output.recipient.as_bytes().try_into().map_err(|_| {
                TxApplyError::Internal(format!(
                    "Failed to convert recipient public key to address at output index {}",
                    index
                ))
            })?;

            let utxo = Utxo {
                amount,
                owner: Address::new(owner_bytes),
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
    pub fn debit_token(&self, token: &TokenId, addr: &Address, amount: u128) -> TxApplyResult<()> {
        if amount == 0 {
            return Ok(());
        }

        let current = self.store.get_token_balance(token, addr)?;

        if current < amount {
            return Err(TxApplyError::InsufficientBalance {
                have: current,
                need: amount,
                token: *token,
            });
        }

        let new_balance = current - amount;
        self.store.set_token_balance(token, addr, new_balance)?;

        Ok(())
    }

    /// Credit tokens to an address
    ///
    /// # Errors
    /// Returns `InvalidTokenAmount` on u128 overflow
    pub fn credit_token(&self, token: &TokenId, addr: &Address, amount: u128) -> TxApplyResult<()> {
        if amount == 0 {
            return Ok(());
        }

        let current = self.store.get_token_balance(token, addr)?;
        let new_balance = current.checked_add(amount).ok_or_else(|| {
            TxApplyError::InvalidTokenAmount(format!(
                "Token balance overflow: {} + {} exceeds u128::MAX",
                current, amount
            ))
        })?;

        self.store.set_token_balance(token, addr, new_balance)?;

        Ok(())
    }

    /// Transfer tokens between addresses
    ///
    /// Atomic debit from sender, credit to receiver.
    pub fn transfer_token(
        &self,
        token: &TokenId,
        from: &Address,
        to: &Address,
        amount: u128,
    ) -> TxApplyResult<()> {
        // Check if token is deflationary and apply burn if needed
        let burn_amount = if let Ok(Some(contract)) = self.store.get_token_contract(token) {
            if contract.is_deflationary && contract.burn_rate > 0 {
                // burn_rate is in basis points (1/10000)
                let burn = (amount * contract.burn_rate as u128 / 10_000) as u64;
                if burn > 0 {
                    // Debit sender the full amount
                    self.debit_token(token, from, amount)?;
                    // Credit receiver the amount minus burn
                    self.credit_token(token, to, amount.saturating_sub(burn as u128))?;
                    // Reduce total supply
                    if let Ok(Some(supply)) = self.store.get_token_supply(token) {
                        self.store
                            .put_token_supply(token, supply.saturating_sub(burn))?;
                    }
                    return Ok(());
                }
            }
            0u64
        } else {
            0u64
        };

        // Non-deflationary transfer (or burn_rate = 0)
        self.debit_token(token, from, amount)?;
        self.credit_token(token, to, amount)?;
        Ok(())
    }

    // =========================================================================
    // Token Nonce Primitives (for replay protection)
    // =========================================================================

    /// Get token nonce for a sender address
    pub fn get_token_nonce(&self, token: &TokenId, sender: &Address) -> TxApplyResult<u64> {
        Ok(self.store.get_token_nonce(token, sender)?)
    }

    /// Increment token nonce after successful transfer
    pub fn increment_token_nonce(&self, token: &TokenId, sender: &Address) -> TxApplyResult<u64> {
        let new_nonce = self.store.increment_token_nonce(token, sender)?;
        Ok(new_nonce)
    }

    /// Get a token contract by its ID.
    pub fn get_token_contract(
        &self,
        token_id: &TokenId,
    ) -> TxApplyResult<Option<crate::contracts::TokenContract>> {
        Ok(self.store.get_token_contract(token_id)?)
    }

    /// Persist a token contract in canonical state storage.
    pub fn put_token_contract(&self, contract: &crate::contracts::TokenContract) -> TxApplyResult<()> {
        self.store.put_token_contract(contract)?;
        Ok(())
    }

    /// Check whether any existing token contract uses the given symbol (case-insensitive).
    ///
    /// Used by TokenCreation to enforce symbol uniqueness across the token registry.
    pub fn token_symbol_exists_case_insensitive(&self, symbol: &str) -> TxApplyResult<bool> {
        let upper = symbol.to_ascii_uppercase();
        let contracts = self.store.iter_token_contracts()?;
        for (_id, contract) in contracts {
            if contract.symbol.to_ascii_uppercase() == upper {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // =========================================================================
    // Account Primitives
    // =========================================================================

    /// Load account state, returning default if not exists
    pub fn load_account(&self, addr: &Address) -> TxApplyResult<AccountState> {
        Ok(self
            .store
            .get_account(addr)?
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

    // =========================================================================
    // Identity Primitives (CONSENSUS CORE SPEC: Fixed-size keys only)
    // =========================================================================

    /// Register a new identity (consensus + metadata)
    ///
    /// Stores both consensus state (fixed-size, participates in state hash) and
    /// metadata (strings allowed, for DID resolution) in separate trees.
    ///
    /// # Parameters
    /// - `did_hash`: Blake3 hash of the DID string (32 bytes)
    /// - `consensus`: Fixed-size consensus state
    /// - `metadata`: Human-readable metadata for resolution
    ///
    /// # Errors
    /// - Returns error if identity with this DID hash already exists
    pub fn register_identity(
        &self,
        did_hash: &[u8; 32],
        consensus: &IdentityConsensus,
        metadata: &IdentityMetadata,
    ) -> TxApplyResult<()> {
        // Check if identity already exists
        if self.store.get_identity(did_hash)?.is_some() {
            return Err(TxApplyError::Internal(format!(
                "Identity already registered: {}",
                hex::encode(did_hash)
            )));
        }

        // Store consensus state (participates in state hash)
        self.store.put_identity(did_hash, consensus)?;

        // Store metadata (for DID resolution, non-consensus)
        self.store.put_identity_metadata(did_hash, metadata)?;

        // Update owner index
        self.store
            .put_identity_owner_index(&consensus.owner, did_hash)?;

        Ok(())
    }

    /// Update an existing identity's consensus state
    ///
    /// Replaces only the consensus state. Used for:
    /// - Adding seed commitment during migration
    /// - Status changes
    /// - Updating counts
    ///
    /// # Errors
    /// - Returns error if identity doesn't exist
    pub fn update_identity(
        &self,
        did_hash: &[u8; 32],
        consensus: &IdentityConsensus,
    ) -> TxApplyResult<()> {
        // Verify identity exists
        let existing = self.store.get_identity(did_hash)?.ok_or_else(|| {
            TxApplyError::Internal(format!(
                "Cannot update non-existent identity: {}",
                hex::encode(did_hash)
            ))
        })?;

        // Enforce immutable ownership/identity invariants
        if existing.did_hash != consensus.did_hash {
            return Err(TxApplyError::Internal(
                "Immutable DID hash mismatch".to_string(),
            ));
        }
        if existing.owner != consensus.owner {
            return Err(TxApplyError::Internal(
                "Immutable owner mismatch".to_string(),
            ));
        }
        if existing.public_key_hash != consensus.public_key_hash {
            return Err(TxApplyError::Internal(
                "Immutable public key mismatch".to_string(),
            ));
        }
        if existing.registered_at_height != consensus.registered_at_height {
            return Err(TxApplyError::Internal(
                "Immutable registered_at_height mismatch".to_string(),
            ));
        }
        if existing.identity_type != consensus.identity_type {
            return Err(TxApplyError::Internal(
                "Immutable identity type mismatch".to_string(),
            ));
        }

        self.store.put_identity(did_hash, consensus)?;
        Ok(())
    }

    /// Update identity metadata (non-consensus)
    ///
    /// Updates the human-readable metadata for DID resolution.
    /// This does NOT affect the state hash.
    pub fn update_identity_metadata(
        &self,
        did_hash: &[u8; 32],
        metadata: &IdentityMetadata,
    ) -> TxApplyResult<()> {
        // Verify identity exists (consensus must exist for metadata to be valid)
        if self.store.get_identity(did_hash)?.is_none() {
            return Err(TxApplyError::Internal(format!(
                "Cannot update metadata for non-existent identity: {}",
                hex::encode(did_hash)
            )));
        }

        self.store.put_identity_metadata(did_hash, metadata)?;
        Ok(())
    }

    /// Revoke an identity
    ///
    /// Deletes the identity from all storage trees. This is a permanent operation.
    ///
    /// # Errors
    /// - Returns error if identity doesn't exist
    pub fn revoke_identity(&self, did_hash: &[u8; 32]) -> TxApplyResult<()> {
        // Get identity to find owner for index deletion
        let identity = self.store.get_identity(did_hash)?.ok_or_else(|| {
            TxApplyError::Internal(format!(
                "Cannot revoke non-existent identity: {}",
                hex::encode(did_hash)
            ))
        })?;

        // Remove from all trees
        self.store.delete_identity(did_hash)?;
        self.store.delete_identity_metadata(did_hash)?;
        self.store.delete_identity_owner_index(&identity.owner)?;

        Ok(())
    }

    /// Get identity consensus state by DID hash
    ///
    /// Returns the fixed-size consensus state.
    /// Use `get_identity_metadata` for human-readable data.
    pub fn get_identity(&self, did_hash: &[u8; 32]) -> TxApplyResult<Option<IdentityConsensus>> {
        Ok(self.store.get_identity(did_hash)?)
    }

    /// Get identity metadata by DID hash
    ///
    /// Returns the human-readable metadata for DID resolution.
    pub fn get_identity_metadata(
        &self,
        did_hash: &[u8; 32],
    ) -> TxApplyResult<Option<IdentityMetadata>> {
        Ok(self.store.get_identity_metadata(did_hash)?)
    }

    /// Check if an identity exists
    pub fn identity_exists(&self, did_hash: &[u8; 32]) -> TxApplyResult<bool> {
        Ok(self.store.get_identity(did_hash)?.is_some())
    }

    /// Get identity by owner address
    ///
    /// Looks up the DID hash from the owner index, then retrieves the identity.
    pub fn get_identity_by_owner(
        &self,
        addr: &Address,
    ) -> TxApplyResult<Option<IdentityConsensus>> {
        match self.store.get_identity_by_owner(addr)? {
            Some(did_hash) => Ok(self.store.get_identity(&did_hash)?),
            None => Ok(None),
        }
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
        let outpoint = OutPoint::new(TxHash::new(tx_hash.as_array()), index as u32);

        // First output gets remainder
        let amount = if index == 0 {
            amount_per_output + remainder
        } else {
            amount_per_output
        };

        // Convert recipient public key to address bytes
        // IMPORTANT: Must not silently fall back to zero address on conversion failure
        let owner_bytes: [u8; 32] = output.recipient.as_bytes().try_into().map_err(|_| {
            TxApplyError::Internal(format!(
                "Failed to convert recipient public key to address at output index {}",
                index
            ))
        })?;

        let utxo = Utxo {
            amount,
            owner: Address::new(owner_bytes),
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
    token: &TokenId,
    from: &Address,
    to: &Address,
    amount: u128,
) -> TxApplyResult<()> {
    mutator.transfer_token(token, from, to, amount)
}

/// Apply a token mint transaction (balance model)
pub fn apply_token_mint(
    mutator: &StateMutator<'_>,
    token: &TokenId,
    to: &Address,
    amount: u128,
) -> TxApplyResult<()> {
    mutator.credit_token(token, to, amount)
}

/// Apply a coinbase transaction (block reward + fee collection)
///
/// Coinbase creates new value - no inputs are spent.
/// Phase 3C: Coinbase includes both block reward and collected fees.
///
/// # Arguments
/// * `mutator` - State mutator for creating UTXOs
/// * `tx` - The coinbase transaction
/// * `tx_hash` - Hash of the transaction
/// * `block_height` - Current block height
/// * `block_reward` - Expected block reward amount
/// * `fees_collected` - Total fees collected from non-coinbase transactions
/// * `fee_sink_address` - Deterministic address for fee collection
///
/// # Validation (Phase 3C)
/// - If fees_collected > 0, one output MUST go to fee_sink_address with that amount
/// - Total coinbase output = block_reward + fees_collected
pub fn apply_coinbase(
    mutator: &StateMutator<'_>,
    tx: &Transaction,
    tx_hash: &Hash,
    block_height: u64,
    block_reward: u64,
    fees_collected: u64,
    fee_sink_address: &Address,
) -> TxApplyResult<CoinbaseOutcome> {
    use crate::storage::TxHash;

    // Coinbase must have no inputs
    if !tx.inputs.is_empty() {
        return Err(TxApplyError::InvalidType(
            "Coinbase transaction must have no inputs".to_string(),
        ));
    }

    if tx.outputs.is_empty() {
        return Err(TxApplyError::Internal(
            "Coinbase must have outputs".to_string(),
        ));
    }

    let expected_total = block_reward.saturating_add(fees_collected);

    // Phase 3C: Validate fee sink output if fees were collected
    let mut fee_sink_output_found = false;
    let mut fee_sink_output_amount: u64 = 0;

    // First pass: validate structure and find fee sink output
    for (index, output) in tx.outputs.iter().enumerate() {
        // Convert recipient public key to address bytes
        // Note: In first pass we can use unwrap_or for checking fee sink,
        // but the second pass (below) will properly error on conversion failure
        let addr_bytes: [u8; 32] = output.recipient.as_bytes().try_into().unwrap_or([0u8; 32]);
        let output_address = Address::new(addr_bytes);

        if &output_address == fee_sink_address {
            fee_sink_output_found = true;
            // For coinbase, amount is in the commitment or we derive from expected
            // Since we're distributing, we'll track the fee sink output
            fee_sink_output_amount = fees_collected;
        }
    }

    // If fees were collected, fee sink output is mandatory
    if fees_collected > 0 && !fee_sink_output_found {
        return Err(TxApplyError::MissingField(format!(
            "Coinbase must include fee sink output for {} collected fees",
            fees_collected
        )));
    }

    // Calculate distribution: reward goes to non-fee-sink outputs, fees go to fee sink
    let reward_output_count = if fees_collected > 0 {
        tx.outputs.len().saturating_sub(1) as u64
    } else {
        tx.outputs.len() as u64
    };

    let amount_per_reward_output = if reward_output_count > 0 {
        block_reward / reward_output_count
    } else {
        0
    };
    let reward_remainder = if reward_output_count > 0 {
        block_reward % reward_output_count
    } else {
        0
    };

    let mut total_output: u64 = 0;
    let mut reward_output_index = 0;

    for (index, output) in tx.outputs.iter().enumerate() {
        let outpoint = OutPoint::new(TxHash::new(tx_hash.as_array()), index as u32);

        // Convert recipient public key to address bytes
        // IMPORTANT: Must not silently fall back to zero address on conversion failure
        let addr_bytes: [u8; 32] = output.recipient.as_bytes().try_into().map_err(|_| {
            TxApplyError::Internal(format!(
                "Failed to convert recipient public key to address at coinbase output index {}",
                index
            ))
        })?;
        let output_address = Address::new(addr_bytes);

        // Determine amount based on output type
        let amount = if &output_address == fee_sink_address && fees_collected > 0 {
            // This is the fee sink output
            fees_collected
        } else {
            // This is a reward output
            let amt = if reward_output_index == 0 {
                amount_per_reward_output + reward_remainder
            } else {
                amount_per_reward_output
            };
            reward_output_index += 1;
            amt
        };

        let utxo = Utxo {
            amount,
            owner: output_address,
            token: TokenId::NATIVE,
            created_at_height: block_height,
            script: None,
        };

        mutator.create_utxo(&outpoint, &utxo)?;
        total_output = total_output.saturating_add(amount);
    }

    // Verify total output matches expected
    if total_output != expected_total {
        return Err(TxApplyError::ValueMismatch {
            inputs: expected_total,
            outputs: total_output,
            fee: 0,
        });
    }

    Ok(CoinbaseOutcome {
        outputs_created: tx.outputs.len(),
        total_reward: block_reward,
        fees_collected,
        fee_sink_credited: fee_sink_output_found && fees_collected > 0,
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
    /// Phase 3C: Fees collected and routed to fee sink
    pub fees_collected: u64,
    /// Phase 3C: Whether fee sink was credited
    pub fee_sink_credited: bool,
}
