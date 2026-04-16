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
    AccountState, Address, AddressExt, BlockchainStore, IdentityConsensus, IdentityMetadata,
    IdentityMetadataView, OutPoint, TokenId, Utxo, WalletProjectionRecord, WalletState,
};
use lib_access_control::{
    AccessDomain, AccessOperation, AccessPolicy, SecurityPrincipal, SubjectRelation,
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

        // Remove from the persistent Merkle tree if it was tracked there.
        if utxo.merkle_leaf.is_some() {
            self.store.delete_utxo_merkle_leaf(outpoint)?;
        }

        Ok(utxo)
    }

    /// Create a new UTXO
    ///
    /// The outpoint is derived from tx_hash + output_index.
    pub fn create_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> TxApplyResult<()> {
        self.store.put_utxo(outpoint, utxo)?;

        // Insert into the persistent Merkle tree if a leaf commitment is present.
        if let Some(leaf) = utxo.merkle_leaf {
            self.store.put_utxo_merkle_leaf(outpoint, leaf)?;
        }

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

            // Derive address from recipient public key's 32-byte key_id
            // (blake3 hash of the dilithium public key bytes).
            let owner_bytes: [u8; 32] = output.recipient.key_id;

            let utxo = Utxo {
                amount,
                owner: Address::new(owner_bytes),
                token: TokenId::NATIVE,
                created_at_height: block_height,
                script: None,
                merkle_leaf: if output.merkle_leaf == crate::types::Hash::default() {
                    None
                } else {
                    Some(output.merkle_leaf.as_array())
                },
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
        let _burn_amount = if let Ok(Some(contract)) = self.store.get_token_contract(token) {
            if contract.is_deflationary && contract.burn_rate > 0 {
                // burn_rate is in basis points (1/10000)
                let burn = amount * contract.burn_rate as u128 / 10_000;
                if burn > 0 {
                    // Debit sender the full amount
                    self.debit_token(token, from, amount)?;
                    // Credit receiver the amount minus burn
                    self.credit_token(token, to, amount.saturating_sub(burn))?;
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
    pub fn put_token_contract(
        &self,
        contract: &crate::contracts::TokenContract,
    ) -> TxApplyResult<()> {
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
    // Canonical CBE Curve State Primitives (#1926)
    // =========================================================================

    /// Load the global canonical CBE economic state.
    ///
    /// Returns a zero-initialised default on a fresh chain.
    pub fn get_cbe_economic_state(&self) -> TxApplyResult<lib_types::BondingCurveEconomicState> {
        Ok(self.store.get_cbe_economic_state()?)
    }

    /// Persist the global canonical CBE economic state.
    pub fn put_cbe_economic_state(
        &self,
        state: &lib_types::BondingCurveEconomicState,
    ) -> TxApplyResult<()> {
        self.store.put_cbe_economic_state(state)?;
        Ok(())
    }

    /// Load the CBE account state for `key_id`, or a zero-default if new.
    pub fn get_cbe_account_state(
        &self,
        key_id: &[u8; 32],
    ) -> TxApplyResult<lib_types::BondingCurveAccountState> {
        Ok(self
            .store
            .get_cbe_account_state(key_id)?
            .unwrap_or_else(|| lib_types::BondingCurveAccountState {
                key_id: *key_id,
                balance_cbe: 0,
                balance_sov: 0,
                next_nonce: lib_types::Nonce48::zero(),
            }))
    }

    /// Persist the CBE account state for `key_id`.
    pub fn put_cbe_account_state(
        &self,
        key_id: &[u8; 32],
        state: &lib_types::BondingCurveAccountState,
    ) -> TxApplyResult<()> {
        self.store.put_cbe_account_state(key_id, state)?;
        Ok(())
    }

    // =========================================================================
    // DAO Stake Primitives
    // =========================================================================

    /// Retrieve a DAO stake record for reading (no write permission needed).
    pub fn get_dao_stake(
        &self,
        sector_dao_key_id: &[u8; 32],
        staker: &[u8; 32],
    ) -> TxApplyResult<Option<crate::storage::DaoStakeRecord>> {
        Ok(self.store.get_dao_stake(sector_dao_key_id, staker)?)
    }

    /// Persist a DAO stake record (upsert) within the current block transaction.
    pub fn put_dao_stake(&self, record: &crate::storage::DaoStakeRecord) -> TxApplyResult<()> {
        self.store.put_dao_stake(record)?;
        Ok(())
    }

    /// Delete a DAO stake record within the current block transaction.
    pub fn delete_dao_stake(
        &self,
        sector_dao_key_id: &[u8; 32],
        staker: &[u8; 32],
    ) -> TxApplyResult<()> {
        self.store.delete_dao_stake(sector_dao_key_id, staker)?;
        Ok(())
    }

    // =========================================================================
    // Contract State Primitives
    // =========================================================================

    /// Persist contract code for a contract identifier.
    pub fn put_contract_code(&self, contract_id: &[u8; 32], code: &[u8]) -> TxApplyResult<()> {
        self.store.put_contract_code(contract_id, code)?;
        Ok(())
    }

    /// Persist contract key-value storage for a contract identifier.
    pub fn put_contract_storage(
        &self,
        contract_id: &[u8; 32],
        key: &[u8],
        value: &[u8],
    ) -> TxApplyResult<()> {
        self.store.put_contract_storage(contract_id, key, value)?;
        Ok(())
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
    ///
    /// # Security
    /// This returns the raw, unfiltered metadata struct. It should only be used
    /// during internal consensus operations. All external reads must use
    /// `get_identity_metadata_filtered` instead.
    pub fn get_identity_metadata(
        &self,
        did_hash: &[u8; 32],
    ) -> TxApplyResult<Option<IdentityMetadata>> {
        Ok(self.store.get_identity_metadata(did_hash)?)
    }

    /// Get an access-controlled view of identity metadata.
    ///
    /// This is the **only** metadata method that should be used for
    /// cross-boundary reads.
    pub fn get_identity_metadata_filtered(
        &self,
        principal: &SecurityPrincipal,
        relation: SubjectRelation,
        did_hash: &[u8; 32],
    ) -> TxApplyResult<Option<IdentityMetadataView>> {
        let policy = AccessPolicy::default();

        // Baseline check: can the principal even resolve the identity?
        let core_decision = policy.check_access(
            principal,
            relation,
            AccessDomain::CoreIdentity,
            AccessOperation::Resolve,
        );
        if !core_decision.is_allowed() {
            return Ok(None);
        }

        let metadata = match self.store.get_identity_metadata(did_hash)? {
            Some(m) => m,
            None => return Ok(None),
        };

        // Full view for self, owner context, or elevated roles.
        if matches!(relation, SubjectRelation::Self_ | SubjectRelation::Owner)
            || matches!(
                principal.role,
                lib_access_control::Role::System
                    | lib_access_control::Role::Emergency
                    | lib_access_control::Role::Council
            )
        {
            return Ok(Some(IdentityMetadataView::from_metadata(&metadata)));
        }

        // InfraAdmin sees node graph but not wallet/attribute detail.
        if principal.role == lib_access_control::Role::InfraAdmin {
            return Ok(Some(IdentityMetadataView {
                did: metadata.did,
                display_name: metadata.display_name,
                public_key: None,
                controlled_nodes: Some(metadata.controlled_nodes),
                owned_wallets: None,
                attributes: Some(Vec::new()),
            }));
        }

        // Device owner sees limited scope.
        if principal.role == lib_access_control::Role::Device
            && matches!(relation, SubjectRelation::Owner)
        {
            return Ok(Some(IdentityMetadataView {
                did: metadata.did,
                display_name: metadata.display_name,
                public_key: None,
                controlled_nodes: Some(metadata.controlled_nodes),
                owned_wallets: Some(metadata.owned_wallets),
                attributes: Some(Vec::new()),
            }));
        }

        // Default: public view.
        Ok(Some(IdentityMetadataView::public(
            metadata.did,
            metadata.display_name,
        )))
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

    /// Read the token balance for an address without mutating state.
    pub fn get_token_balance(&self, token: &TokenId, addr: &Address) -> TxApplyResult<u64> {
        let balance = self
            .store
            .get_token_balance(token, addr)
            .map_err(|e| TxApplyError::Storage(e.to_string()))?;
        let balance_u64 = u64::try_from(balance)
            .map_err(|_| TxApplyError::Storage("token balance exceeds u64::MAX".to_string()))?;
        Ok(balance_u64)
    }

    /// Read the token balance as u128 for an address without mutating state.
    /// Used by bonding curve operations which work with u128 amounts.
    pub fn get_token_balance_u128(&self, token: &TokenId, addr: &Address) -> TxApplyResult<u128> {
        self.store
            .get_token_balance(token, addr)
            .map_err(|e| TxApplyError::Storage(e.to_string()))
    }

    /// Read token supply without mutating state.
    pub fn get_token_supply(&self, token: &TokenId) -> TxApplyResult<Option<u128>> {
        self.store
            .get_token_supply(token)
            .map_err(|e| TxApplyError::Storage(e.to_string()))
    }

    /// Persist token supply in canonical state storage.
    pub fn put_token_supply(&self, token: &TokenId, supply: u128) -> TxApplyResult<()> {
        self.store
            .put_token_supply(token, supply)
            .map_err(|e| TxApplyError::Storage(e.to_string()))
    }

    /// Persist a wallet projection entry in canonical storage.
    pub fn put_wallet_projection(
        &self,
        wallet_id: &[u8; 32],
        record: &WalletProjectionRecord,
    ) -> TxApplyResult<()> {
        self.store
            .put_wallet_projection(wallet_id, record)
            .map_err(|e| TxApplyError::Storage(e.to_string()))
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

        // Derive address from recipient public key's 32-byte key_id
        // (blake3 hash of the dilithium public key bytes).
        let owner_bytes: [u8; 32] = output.recipient.key_id;

        let utxo = Utxo {
            amount,
            owner: Address::new(owner_bytes),
            token: TokenId::NATIVE,
            created_at_height: block_height,
            script: None,
            merkle_leaf: if output.merkle_leaf == crate::types::Hash::default() {
                None
            } else {
                Some(output.merkle_leaf.as_array())
            },
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

/// Apply a token transfer transaction (balance model) with protocol fee routing.
///
/// Debits `amount` from `from`, credits `net_amount` (amount minus fee) to `to`,
/// and credits `fee_amount` to `fee_destination`.
///
/// `fee_bps` is the fee rate in basis points (100 = 1%). Pass 0 to skip fee.
/// If `fee_destination` is the zero address, the fee is not collected.
pub fn apply_token_transfer(
    mutator: &StateMutator<'_>,
    token: &TokenId,
    from: &Address,
    to: &Address,
    amount: u128,
    fee_bps: u16,
    fee_destination: &Address,
) -> TxApplyResult<u128> {
    let fee_amount = if fee_bps > 0 && *fee_destination != Address::ZERO {
        (amount * fee_bps as u128) / 10_000
    } else {
        0
    };
    let net_amount = amount.saturating_sub(fee_amount);

    mutator.debit_token(token, from, amount)?;
    mutator.credit_token(token, to, net_amount)?;
    if fee_amount > 0 {
        mutator.credit_token(token, fee_destination, fee_amount)?;
    }
    Ok(fee_amount)
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

    // First pass: validate structure and find fee sink output
    for (_index, output) in tx.outputs.iter().enumerate() {
        // Convert recipient public key to address via key_id (blake3 hash of dilithium key)
        let output_address = Address::new(output.recipient.key_id);

        if &output_address == fee_sink_address {
            fee_sink_output_found = true;
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

        // Derive address from recipient public key's 32-byte key_id
        // (blake3 hash of the dilithium public key bytes).
        let addr_bytes: [u8; 32] = output.recipient.key_id;
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
            merkle_leaf: if output.merkle_leaf == crate::types::Hash::default() {
                None
            } else {
                Some(output.merkle_leaf.as_array())
            },
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
// Oracle Attestation Application (ORACLE-R3: Canonical Path)
// =============================================================================

/// Outcome of applying an oracle attestation transaction.
#[derive(Debug, Clone)]
pub struct OracleAttestationOutcome {
    pub epoch_id: u64,
    pub validator_pubkey: [u8; 32],
    pub sov_usd_price: u128,
    pub finalized: bool,
}

/// Apply an oracle attestation transaction.
///
/// This is the CANONICAL execution path for oracle attestations (ORACLE-R3).
/// In strict-spec mode (V1), this is the ONLY allowed path for attestation processing.
///
/// # Arguments
/// * `mutator` - State mutator for consensus state writes
/// * `tx` - The attestation transaction
/// * `block_timestamp` - The block's timestamp for epoch derivation
/// * `oracle_state` - Mutable reference to oracle state (will be modified)
/// * `resolve_signing_pubkey` - Function to resolve validator signing keys
///
/// # Returns
/// The attestation outcome, including whether the epoch was finalized by this attestation.
pub fn apply_oracle_attestation<F>(
    _mutator: &StateMutator<'_>,
    tx: &Transaction,
    block_timestamp: u64,
    oracle_state: &mut crate::oracle::OracleState,
    resolve_signing_pubkey: F,
) -> TxApplyResult<OracleAttestationOutcome>
where
    F: Fn([u8; 32]) -> Option<Vec<u8>>,
{
    let data = tx.oracle_attestation_data().ok_or_else(|| {
        TxApplyError::InvalidType("OracleAttestation requires oracle_attestation_data".to_string())
    })?;

    // Derive current epoch from block timestamp
    let current_epoch = oracle_state.epoch_id(block_timestamp);

    // Build the attestation
    let attestation = crate::oracle::OraclePriceAttestation {
        epoch_id: data.epoch_id,
        sov_usd_price: data.sov_usd_price,
        cbe_usd_price: data.cbe_usd_price,
        timestamp: data.timestamp,
        validator_pubkey: data.validator_pubkey,
        signature: data.signature.clone(),
    };

    // Process the attestation through oracle state
    // This handles: validation, aggregation, threshold detection, finalization
    let result =
        oracle_state.process_attestation(&attestation, current_epoch, resolve_signing_pubkey);

    match result {
        Ok(admission) => {
            let finalized = matches!(
                admission,
                crate::oracle::OracleAttestationAdmission::Finalized(_)
            );

            Ok(OracleAttestationOutcome {
                epoch_id: data.epoch_id,
                validator_pubkey: data.validator_pubkey,
                sov_usd_price: data.sov_usd_price,
                finalized,
            })
        }
        Err(crate::oracle::OracleAttestationAdmissionError::ConflictingSigner { .. }) => {
            // Double-sign detected - this should trigger slashing
            Err(TxApplyError::InvalidType(
                "Conflicting attestation detected - validator double-signed".to_string(),
            ))
        }
        Err(e) => Err(TxApplyError::InvalidType(format!(
            "Attestation rejected: {:?}",
            e
        ))),
    }
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
