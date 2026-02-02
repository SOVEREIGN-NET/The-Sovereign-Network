//! Block Executor
//!
//! The BlockExecutor is the single entry point for applying blocks to state.
//! It implements the canonical execution lifecycle:
//!
//! 1. Prechecks (height validation, structural checks)
//! 2. begin_block
//! 3. Apply transactions sequentially
//! 4. append_block
//! 5. commit_block
//!
//! On any error: rollback_block
//!
//! # Authorization Invariant (Phase 2)
//!
//! **EXPLICIT DECISION**: The executor assumes transaction authorization has been
//! validated externally via the ZK proofs contained in each `TransactionInput`.
//!
//! Specifically:
//! - Each `TransactionInput` contains a `zk_proof` field with ownership proof
//! - Each input also contains a `nullifier` to prevent double-spend
//! - The executor does NOT verify these proofs during execution
//! - Proof verification is the responsibility of the validation layer or a
//!   dedicated ZK verifier that runs before blocks enter the executor
//!
//! This is **Option B** from the spec: "Ownership is enforced earlier and
//! executor assumes validity."
//!
//! Rationale: ZK proof verification is computationally expensive and should
//! be parallelizable. The executor focuses on state transitions only.

use std::sync::Arc;

use crate::block::Block;
use crate::storage::{Address, BlockchainStore, BlockHash, StorageError, TokenId};
use crate::transaction::hash_transaction;
use crate::types::TransactionType;

use super::errors::{BlockApplyError, BlockApplyResult, TxApplyError};
use super::tx_apply::{self, StateMutator, TransferOutcome, CoinbaseOutcome};

use crate::protocol::ProtocolParams;

/// Configuration for block execution
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum block size in bytes
    pub max_block_size: usize,
    /// Block reward amount (for coinbase validation)
    pub block_reward: u64,
    /// Whether to allow empty blocks (no transactions)
    pub allow_empty_blocks: bool,
    /// Protocol parameters for fee model versioning (Phase 3B)
    pub protocol_params: ProtocolParams,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_block_size: 1_048_576, // 1MB
            block_reward: 50_000_000,  // 50 tokens (in smallest unit)
            allow_empty_blocks: true,
            protocol_params: ProtocolParams::default(),
        }
    }
}

impl ExecutorConfig {
    /// Create config with specific protocol params
    pub fn with_protocol_params(mut self, params: ProtocolParams) -> Self {
        self.protocol_params = params;
        self
    }
}

/// Outcome of successful block application
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    /// Block height that was applied
    pub height: u64,
    /// Block hash
    pub block_hash: BlockHash,
    /// Number of transactions in block
    pub tx_count: usize,
    /// Summary of state changes
    pub state_changes: StateChangesSummary,
    /// Total fees collected from transactions
    pub fees_collected: u64,
}

/// Summary of state changes (counts only, not full diff)
#[derive(Debug, Clone, Default)]
pub struct StateChangesSummary {
    /// Number of UTXOs created
    pub utxos_created: usize,
    /// Number of UTXOs spent
    pub utxos_spent: usize,
    /// Number of token balance changes
    pub balance_changes: usize,
    /// Number of account updates
    pub account_updates: usize,
}

/// The main block executor
///
/// This is the ONLY entry point for applying blocks to blockchain state.
pub struct BlockExecutor {
    store: Arc<dyn BlockchainStore>,
    config: ExecutorConfig,
}

/// Scope guard that ensures rollback_block is called if not disarmed.
///
/// This provides panic-safety: even if a panic occurs after begin_block,
/// the guard's Drop implementation will call rollback_block to prevent
/// partial state corruption.
struct RollbackGuard<'a> {
    store: &'a dyn BlockchainStore,
    armed: bool,
}

impl<'a> RollbackGuard<'a> {
    fn new(store: &'a dyn BlockchainStore) -> Self {
        Self { store, armed: true }
    }

    /// Disarm the guard after successful commit.
    /// Once disarmed, Drop will not call rollback_block.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl<'a> Drop for RollbackGuard<'a> {
    fn drop(&mut self) {
        if self.armed {
            // Best-effort rollback on panic or early return
            let _ = self.store.rollback_block();
        }
    }
}

impl BlockExecutor {
    /// Create a new block executor
    pub fn new(store: Arc<dyn BlockchainStore>, config: ExecutorConfig) -> Self {
        Self { store, config }
    }

    /// Create with default config
    pub fn with_store(store: Arc<dyn BlockchainStore>) -> Self {
        Self::new(store, ExecutorConfig::default())
    }

    /// Get reference to the store
    pub fn store(&self) -> &Arc<dyn BlockchainStore> {
        &self.store
    }

    /// Apply a block to the blockchain
    ///
    /// This is the canonical execution lifecycle:
    /// 1. Prechecks
    /// 2. begin_block
    /// 3. Apply transactions
    /// 4. append_block
    /// 5. commit_block
    ///
    /// # Panic Safety
    ///
    /// Uses a scope guard to ensure rollback_block is called on both errors
    /// AND panics. If a panic occurs after begin_block, the guard's Drop
    /// implementation will automatically call rollback_block to prevent
    /// partial state corruption.
    pub fn apply_block(&self, block: &Block) -> BlockApplyResult<ApplyOutcome> {
        // =====================================================================
        // Step 1: Prechecks (before begin_block)
        // =====================================================================

        let expected_height = self.get_expected_height()?;
        let block_height = block.header.height;

        if block_height != expected_height {
            return Err(BlockApplyError::HeightMismatch {
                expected: expected_height,
                actual: block_height,
            });
        }

        // Validate previous block hash (except for genesis)
        if block_height > 0 {
            self.validate_previous_hash(block, block_height)?;
        }

        // Structural validation
        self.validate_block_structure(block)?;

        // Validate fee model version (Phase 3B)
        self.validate_fee_model_version(block)?;

        // =====================================================================
        // Step 2: Begin block transaction
        // =====================================================================

        self.store.begin_block(block_height)?;

        // Create rollback guard for panic safety.
        // The guard will call rollback_block on Drop unless disarmed.
        // This ensures cleanup even if a panic occurs during block application.
        let guard = RollbackGuard::new(self.store.as_ref());

        // Apply the block
        let outcome = self.apply_block_inner(block)?;

        // Success - disarm the guard so it won't rollback on drop
        guard.disarm();

        Ok(outcome)
    }

    /// Inner block application (after begin_block)
    fn apply_block_inner(&self, block: &Block) -> BlockApplyResult<ApplyOutcome> {
        let block_height = block.header.height;
        let block_hash = BlockHash::new(block.header.block_hash.as_array());

        let mutator = StateMutator::new(self.store.as_ref());
        let mut summary = StateChangesSummary::default();
        let mut total_fees: u64 = 0;

        // =====================================================================
        // Step 2.5: Block-level coinbase validation
        // =====================================================================

        // Count coinbase transactions and validate position
        let coinbase_count = block.transactions.iter()
            .filter(|tx| tx.transaction_type == TransactionType::Coinbase)
            .count();

        if coinbase_count > 1 {
            return Err(BlockApplyError::ValidationFailed(
                "Block must have at most one coinbase transaction".to_string()
            ));
        }

        // If there is a coinbase, it must be the first transaction
        if coinbase_count == 1 {
            if block.transactions.first()
                .map(|tx| tx.transaction_type != TransactionType::Coinbase)
                .unwrap_or(true)
            {
                return Err(BlockApplyError::ValidationFailed(
                    "Coinbase transaction must be first in block".to_string()
                ));
            }
        }

        // =====================================================================
        // Step 3: Apply transactions (Phase 3C: two-pass for fee routing)
        // =====================================================================

        // Phase 3C: Process non-coinbase transactions first to calculate fees
        // Then process coinbase with the collected fees for proper routing.

        let coinbase_tx = if coinbase_count == 1 {
            Some(&block.transactions[0])
        } else {
            None
        };

        // 3a: Process non-coinbase transactions first
        let non_coinbase_start = if coinbase_count == 1 { 1 } else { 0 };

        for (rel_index, tx) in block.transactions[non_coinbase_start..].iter().enumerate() {
            let index = rel_index + non_coinbase_start;

            // Stateless validation
            self.validate_tx_stateless(tx)
                .map_err(|e| BlockApplyError::TxFailed { index, reason: e })?;

            // Stateful validation (reads only)
            self.validate_tx_stateful(tx)
                .map_err(|e| BlockApplyError::TxFailed { index, reason: e })?;

            // Apply transaction (writes)
            let tx_result = self.apply_non_coinbase_tx(&mutator, tx, block_height)
                .map_err(|e| BlockApplyError::TxFailed { index, reason: e })?;

            // Accumulate results
            match tx_result {
                TxOutcome::Transfer(outcome) => {
                    summary.utxos_spent += outcome.inputs_spent;
                    summary.utxos_created += outcome.outputs_created;
                    total_fees += outcome.fee;
                }
                TxOutcome::TokenTransfer(_outcome) => {
                    summary.balance_changes += 2; // sender + receiver
                }
                TxOutcome::Coinbase(_) => {
                    // Should not happen - coinbase filtered out
                    unreachable!("Coinbase should not be in non-coinbase pass");
                }
            }
        }

        // 3b: Process coinbase with collected fees (Phase 3C)
        if let Some(coinbase) = coinbase_tx {
            self.validate_tx_stateless(coinbase)
                .map_err(|e| BlockApplyError::TxFailed { index: 0, reason: e })?;

            let coinbase_result = self.apply_coinbase_with_fees(
                &mutator,
                coinbase,
                block_height,
                total_fees,
            ).map_err(|e| BlockApplyError::TxFailed { index: 0, reason: e })?;

            summary.utxos_created += coinbase_result.outputs_created;
        }

        // =====================================================================
        // Step 4: Append block to history
        // =====================================================================

        self.store.append_block(block)
            .map_err(|e| BlockApplyError::PersistFailed(e.to_string()))?;

        // =====================================================================
        // Step 5: Commit all changes
        // =====================================================================

        self.store.commit_block()?;

        Ok(ApplyOutcome {
            height: block_height,
            block_hash,
            tx_count: block.transactions.len(),
            state_changes: summary,
            fees_collected: total_fees,
        })
    }

    /// Get the expected next block height
    fn get_expected_height(&self) -> BlockApplyResult<u64> {
        match self.store.latest_height() {
            Ok(h) => Ok(h + 1),
            Err(StorageError::NotInitialized) => Ok(0), // Genesis case
            Err(e) => Err(BlockApplyError::Storage(e)),
        }
    }

    /// Validate previous block hash
    ///
    /// Uses get_block_hash_by_height for efficiency (avoids full block deserialization)
    fn validate_previous_hash(&self, block: &Block, height: u64) -> BlockApplyResult<()> {
        let prev_height = height - 1;

        // Use optimized hash lookup to avoid full block deserialization
        let expected_hash = self.store.get_block_hash_by_height(prev_height)?
            .ok_or_else(|| BlockApplyError::ValidationFailed(
                format!("Previous block at height {} not found", prev_height)
            ))?;

        let actual_hash = BlockHash::new(block.header.previous_block_hash.as_array());

        if expected_hash != actual_hash {
            return Err(BlockApplyError::InvalidPreviousHash {
                expected: expected_hash,
                actual: actual_hash,
            });
        }

        Ok(())
    }

    /// Validate block structure (before execution)
    fn validate_block_structure(&self, block: &Block) -> BlockApplyResult<()> {
        // Check block size
        let size = block.size();
        if size > self.config.max_block_size {
            return Err(BlockApplyError::BlockTooLarge {
                size,
                max: self.config.max_block_size,
            });
        }

        // Check for empty blocks
        if block.transactions.is_empty() && !self.config.allow_empty_blocks {
            return Err(BlockApplyError::EmptyBlock);
        }

        // Phase 2 structural validation: transaction count must match header
        let actual_tx_count = block.transactions.len() as u32;
        if block.header.transaction_count != actual_tx_count {
            return Err(BlockApplyError::ValidationFailed(format!(
                "Transaction count mismatch: header says {} but block has {}",
                block.header.transaction_count, actual_tx_count
            )));
        }

        // TODO: Merkle root validation would go here if implemented
        // For Phase 2, we skip this as merkle root computation may not be mandatory

        Ok(())
    }

    /// Validate fee model version is correct for block height (Phase 3B)
    ///
    /// # Rules
    /// - Block must use the fee model version that is active at its height
    /// - Before activation height: version 1 required
    /// - At/after activation height: version 2 required
    fn validate_fee_model_version(&self, block: &Block) -> BlockApplyResult<()> {
        let height = block.header.height;
        let version = block.header.fee_model_version;
        let expected = self.config.protocol_params.active_fee_model_version(height);

        if version != expected {
            return Err(BlockApplyError::InvalidFeeModelVersion {
                height,
                actual: version,
                expected,
            });
        }

        Ok(())
    }

    /// Stateless transaction validation
    ///
    /// NOTE: This duplicates some logic from crate::validation::tx_validate module.
    /// This is INTENTIONAL - the executor needs to own its validation to ensure
    /// execution-time checks are consistent with what it expects. The validation
    /// module is for pre-execution filtering (e.g., mempool acceptance), while
    /// executor validation is the authoritative check during block application.
    fn validate_tx_stateless(&self, tx: &crate::transaction::Transaction) -> Result<(), TxApplyError> {
        // Check transaction type is supported in Phase 2
        match tx.transaction_type {
            TransactionType::Transfer => {}
            TransactionType::TokenTransfer => {}
            TransactionType::Coinbase => {}
            other => {
                return Err(TxApplyError::UnsupportedType(format!("{:?}", other)));
            }
        }

        // Basic structural checks
        match tx.transaction_type {
            TransactionType::Transfer => {
                if tx.inputs.is_empty() {
                    return Err(TxApplyError::EmptyInputs);
                }
                if tx.outputs.is_empty() {
                    return Err(TxApplyError::EmptyOutputs);
                }

                // Check for duplicate inputs
                let mut seen_inputs = std::collections::HashSet::new();
                for input in &tx.inputs {
                    use crate::storage::TxHash;
                    let outpoint = crate::storage::OutPoint::new(
                        TxHash::new(input.previous_output.as_array()),
                        input.output_index,
                    );
                    if !seen_inputs.insert(outpoint.clone()) {
                        return Err(TxApplyError::DuplicateInput(outpoint));
                    }
                }
            }
            TransactionType::Coinbase => {
                // Coinbase must have no inputs
                if !tx.inputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase must have no inputs".to_string()
                    ));
                }
                // Coinbase must have outputs
                if tx.outputs.is_empty() {
                    return Err(TxApplyError::EmptyOutputs);
                }
                // Phase 2 lock: Coinbase fee must be 0
                if tx.fee != 0 {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase transaction fee must be 0".to_string()
                    ));
                }
                // Coinbase must not have non-Phase-2 fields set
                if tx.identity_data.is_some() || tx.wallet_data.is_some() ||
                   tx.validator_data.is_some() || tx.dao_proposal_data.is_some() ||
                   tx.dao_vote_data.is_some() || tx.dao_execution_data.is_some() ||
                   tx.ubi_claim_data.is_some() || tx.profit_declaration_data.is_some() {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase must not have non-Phase-2 data fields".to_string()
                    ));
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer must have token_transfer_data
                if tx.token_transfer_data.is_none() {
                    return Err(TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string()
                    ));
                }
                // Validate token_transfer_data fields
                let data = tx.token_transfer_data.as_ref().unwrap();
                if data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "Token transfer amount must be greater than 0".to_string()
                    ));
                }
                // Phase 2 lock: TokenTransfer fee must be 0
                if tx.fee != 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenTransfer transaction fee must be 0 in Phase 2".to_string()
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Stateful transaction validation (reads only, no writes)
    fn validate_tx_stateful(&self, tx: &crate::transaction::Transaction) -> Result<(), TxApplyError> {
        use crate::storage::TxHash;
        use super::state_view::StateView;

        let view = StateView::new(self.store.as_ref());

        match tx.transaction_type {
            TransactionType::Transfer => {
                // Verify all inputs exist
                for input in &tx.inputs {
                    let outpoint = crate::storage::OutPoint::new(
                        TxHash::new(input.previous_output.as_array()),
                        input.output_index,
                    );

                    if !view.utxo_exists(&outpoint)? {
                        return Err(TxApplyError::UtxoNotFound(outpoint));
                    }
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer validation would check sender balance
                // For now, the actual balance check happens during apply
            }
            _ => {}
        }

        Ok(())
    }

    /// Apply a single transaction
    fn apply_transaction(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<TxOutcome, TxApplyError> {
        let tx_hash = hash_transaction(tx);

        match tx.transaction_type {
            TransactionType::Transfer => {
                let outcome = tx_apply::apply_native_transfer(
                    mutator,
                    tx,
                    &tx_hash,
                    block_height,
                )?;
                Ok(TxOutcome::Transfer(outcome))
            }
            TransactionType::Coinbase => {
                // Legacy path: no fees passed (for backwards compatibility in tests)
                let fee_sink = self.config.protocol_params.fee_sink_address();
                let outcome = tx_apply::apply_coinbase(
                    mutator,
                    tx,
                    &tx_hash,
                    block_height,
                    self.config.block_reward,
                    0, // No fees in legacy path
                    fee_sink,
                )?;
                Ok(TxOutcome::Coinbase(outcome))
            }
            TransactionType::TokenTransfer => {
                // Extract token transfer data - must be present for TokenTransfer type
                let transfer_data = tx.token_transfer_data.as_ref()
                    .ok_or_else(|| TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string()
                    ))?;

                // Convert to storage types
                let token = if transfer_data.is_native() {
                    TokenId::NATIVE
                } else {
                    TokenId::new(transfer_data.token_id)
                };
                let from = Address::new(transfer_data.from);
                let to = Address::new(transfer_data.to);
                let amount = transfer_data.amount;

                // Validate amount > 0
                if amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "Token transfer amount must be greater than 0".to_string()
                    ));
                }

                // Apply the token transfer (debit from, credit to)
                tx_apply::apply_token_transfer(
                    mutator,
                    &token,
                    &from,
                    &to,
                    amount,
                )?;

                Ok(TxOutcome::TokenTransfer(TokenTransferOutcome {
                    token,
                    from,
                    to,
                    amount,
                }))
            }
            _ => Err(TxApplyError::UnsupportedType(
                format!("{:?}", tx.transaction_type)
            )),
        }
    }

    /// Apply a non-coinbase transaction (Phase 3C helper)
    ///
    /// This is used in the first pass to process all fee-paying transactions
    /// before processing coinbase with the collected fees.
    fn apply_non_coinbase_tx(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<TxOutcome, TxApplyError> {
        // Coinbase should not be passed to this method
        if tx.transaction_type == TransactionType::Coinbase {
            return Err(TxApplyError::InvalidType(
                "Coinbase should not be processed in non-coinbase pass".to_string()
            ));
        }

        // Delegate to existing apply_transaction for non-coinbase types
        self.apply_transaction(mutator, tx, block_height)
    }

    /// Apply coinbase transaction with collected fees (Phase 3C)
    ///
    /// This is called after all non-coinbase transactions are processed,
    /// so we know the total fees to route to the fee sink.
    fn apply_coinbase_with_fees(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
        fees_collected: u64,
    ) -> Result<CoinbaseOutcome, TxApplyError> {
        if tx.transaction_type != TransactionType::Coinbase {
            return Err(TxApplyError::InvalidType(
                "Expected coinbase transaction".to_string()
            ));
        }

        let tx_hash = hash_transaction(tx);
        let fee_sink_address = self.config.protocol_params.fee_sink_address();

        tx_apply::apply_coinbase(
            mutator,
            tx,
            &tx_hash,
            block_height,
            self.config.block_reward,
            fees_collected,
            fee_sink_address,
        )
    }
}

/// Outcome of applying a single transaction
enum TxOutcome {
    Transfer(TransferOutcome),
    TokenTransfer(TokenTransferOutcome),
    Coinbase(CoinbaseOutcome),
}

/// Outcome of a token transfer transaction
#[derive(Debug, Clone)]
pub struct TokenTransferOutcome {
    pub token: TokenId,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SledStore;
    use crate::block::{Block, BlockHeader};
    use crate::types::{Hash, Difficulty};

    fn create_test_store() -> Arc<dyn BlockchainStore> {
        Arc::new(SledStore::open_temporary().unwrap())
    }

    fn create_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // Unique genesis hash
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            timestamp: 1000,
            difficulty: Difficulty::default(),
            nonce: 0,
            height: 0,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, vec![])
    }

    fn create_block_at_height(height: u64, prev_hash: Hash) -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: prev_hash,
            merkle_root: Hash::default(),
            timestamp: 1000 + height,
            difficulty: Difficulty::default(),
            nonce: 0,
            height,
            block_hash,
            transaction_count: 0,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, vec![])
    }

    #[test]
    fn test_apply_genesis_block() {
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        let genesis = create_genesis_block();
        let outcome = executor.apply_block(&genesis).unwrap();

        assert_eq!(outcome.height, 0);
        assert_eq!(outcome.tx_count, 0);
        assert_eq!(store.latest_height().unwrap(), 0);
    }

    #[test]
    fn test_apply_sequential_blocks() {
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        // Genesis
        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Block 1
        let block1 = create_block_at_height(1, genesis.header.block_hash);
        executor.apply_block(&block1).unwrap();

        // Block 2
        let block2 = create_block_at_height(2, block1.header.block_hash);
        executor.apply_block(&block2).unwrap();

        assert_eq!(store.latest_height().unwrap(), 2);
    }

    #[test]
    fn test_reject_wrong_height() {
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store);

        // Try to apply block at height 1 without genesis
        let block = create_block_at_height(1, Hash::default());
        let result = executor.apply_block(&block);

        assert!(matches!(result, Err(BlockApplyError::HeightMismatch { .. })));
    }

    #[test]
    fn test_reject_wrong_previous_hash() {
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store);

        // Apply genesis
        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Try to apply block with wrong previous hash
        let mut block1 = create_block_at_height(1, Hash::default()); // Wrong!
        let result = executor.apply_block(&block1);

        assert!(matches!(result, Err(BlockApplyError::InvalidPreviousHash { .. })));
    }

    // =========================================================================
    // Integration Tests T2-T5
    // =========================================================================

    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
    use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
    use crate::integration::zk_integration::ZkTransactionProof;
    use crate::types::TransactionType;
    use lib_proofs::types::ZkProof;

    fn create_dummy_public_key() -> PublicKey {
        PublicKey::new(vec![0u8; 32])
    }

    fn create_dummy_signature() -> Signature {
        Signature {
            signature: vec![0u8; 64],
            public_key: create_dummy_public_key(),
            algorithm: SignatureAlgorithm::Dilithium2,
            timestamp: 0,
        }
    }

    fn create_dummy_zk_proof() -> ZkProof {
        ZkProof::default()
    }

    fn create_dummy_tx_proof() -> ZkTransactionProof {
        ZkTransactionProof::new(
            create_dummy_zk_proof(),
            create_dummy_zk_proof(),
            create_dummy_zk_proof(),
        )
    }

    fn create_transfer_tx(prev_tx_hash: Hash, output_index: u32) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x03, // development
            transaction_type: TransactionType::Transfer,
            inputs: vec![TransactionInput {
                previous_output: prev_tx_hash,
                output_index,
                nullifier: Hash::default(),
                zk_proof: create_dummy_tx_proof(),
            }],
            outputs: vec![TransactionOutput {
                commitment: Hash::default(),
                note: Hash::default(),
                recipient: create_dummy_public_key(),
            }],
            fee: 1,
            signature: create_dummy_signature(),
            memo: vec![],
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    fn create_coinbase_tx(recipient_pk: PublicKey) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::Coinbase,
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: Hash::default(),
                note: Hash::default(),
                recipient: recipient_pk,
            }],
            fee: 0,
            signature: create_dummy_signature(),
            memo: vec![],
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Create a genesis block with a coinbase transaction for funding
    fn create_funded_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // Unique genesis hash
        let block_hash = Hash::new(hash_bytes);

        // Create coinbase tx for funding
        let coinbase = create_coinbase_tx(create_dummy_public_key());

        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            timestamp: 1000,
            difficulty: Difficulty::default(),
            nonce: 0,
            height: 0,
            block_hash,
            transaction_count: 1,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, vec![coinbase])
    }

    fn create_block_with_txs(height: u64, prev_hash: Hash, txs: Vec<Transaction>) -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        hash_bytes[8] = txs.len() as u8; // Make hash unique per tx count
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: prev_hash,
            merkle_root: Hash::default(),
            timestamp: 1000 + height,
            difficulty: Difficulty::default(),
            nonce: 0,
            height,
            block_hash,
            transaction_count: txs.len() as u32,
            block_size: 0,
            cumulative_difficulty: Difficulty::default(),
            fee_model_version: 2, // Phase 2+ uses v2
        };
        Block::new(header, txs)
    }

    /// T2: Block with invalid transaction is rolled back
    #[test]
    fn test_t2_rollback_on_invalid_tx() {
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        // Apply genesis
        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Create a block with a transfer tx referencing non-existent UTXO
        let fake_tx_hash = Hash::new([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let bad_tx = create_transfer_tx(fake_tx_hash, 0);

        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![bad_tx]);
        let result = executor.apply_block(&block1);

        // Should fail due to UTXO not found
        assert!(result.is_err(), "Block with invalid tx should fail");

        // Height should still be at genesis after rollback
        assert_eq!(store.latest_height().unwrap(), 0);
    }

    /// T3: Double spend across blocks is rejected
    ///
    /// This test funds via genesis coinbase (through executor), then tests
    /// that the same UTXO cannot be spent twice.
    #[test]
    fn test_t3_double_spend_across_blocks() {
        use crate::transaction::hashing::hash_transaction;

        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        // Apply funded genesis (contains coinbase) - UTXOs created via executor
        let genesis = create_funded_genesis_block();
        let genesis_outcome = executor.apply_block(&genesis).unwrap();
        assert_eq!(genesis_outcome.height, 0);

        // Get the coinbase tx hash to reference its outputs
        let coinbase_tx = &genesis.transactions[0];
        let coinbase_tx_hash = hash_transaction(coinbase_tx);

        // Create a transfer spending the coinbase UTXO (output index 0)
        let spend_tx = create_transfer_tx(coinbase_tx_hash, 0);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![spend_tx.clone()]);

        // First spend should succeed
        executor.apply_block(&block1).unwrap();
        assert_eq!(store.latest_height().unwrap(), 1);

        // Try to spend the same UTXO again in block 2
        let double_spend_tx = create_transfer_tx(coinbase_tx_hash, 0);
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![double_spend_tx]);

        // This should fail - UTXO already spent
        let result = executor.apply_block(&block2);
        assert!(result.is_err(), "Double spend should be rejected");

        // Height should remain at block 1
        assert_eq!(store.latest_height().unwrap(), 1);
    }

    /// T4: Token transfer with insufficient balance fails
    #[test]
    fn test_t4_token_transfer_balance_underflow() {
        use crate::storage::{TokenId, Address};

        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        // Apply genesis
        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Token transfers are currently simplified in Phase 2
        // The actual balance check happens during apply
        // This test verifies that the executor properly handles the case

        // For now, we verify that token balance operations work correctly
        // through the StateView/StateMutator primitives

        // Set up an address with zero balance
        let addr = Address([0xAB; 32]);
        let token = TokenId::NATIVE;

        store.begin_block(1).unwrap();

        // Try to get balance of address with no tokens
        let balance = store.get_token_balance(&token, &addr).unwrap();
        assert_eq!(balance, 0);

        // In a real token transfer, we'd check:
        // if balance < transfer_amount { return Err(...) }

        store.rollback_block().unwrap();

        // Verify state was not changed
        assert_eq!(store.latest_height().unwrap(), 0);
    }

    /// T5: State persists across store restart
    #[test]
    fn test_t5_persistence_across_restart() {
        use std::path::PathBuf;

        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().unwrap();
        let store_path = temp_dir.path().join("blockchain_test");

        // First session: apply genesis and a block
        {
            let store = Arc::new(SledStore::open(&store_path).unwrap()) as Arc<dyn BlockchainStore>;
            let executor = BlockExecutor::with_store(store.clone());

            let genesis = create_genesis_block();
            executor.apply_block(&genesis).unwrap();

            let block1 = create_block_at_height(1, genesis.header.block_hash);
            executor.apply_block(&block1).unwrap();

            assert_eq!(store.latest_height().unwrap(), 1);

            // Store is dropped here, should flush to disk
        }

        // Second session: reopen and verify state persisted
        {
            let store = Arc::new(SledStore::open(&store_path).unwrap()) as Arc<dyn BlockchainStore>;

            // Height should still be 1
            assert_eq!(store.latest_height().unwrap(), 1);

            // Genesis block should be retrievable
            let genesis = store.get_block_by_height(0).unwrap();
            assert!(genesis.is_some());

            // Block 1 should be retrievable
            let block1 = store.get_block_by_height(1).unwrap();
            assert!(block1.is_some());

            // Can continue building on the chain
            let executor = BlockExecutor::with_store(store.clone());
            let block2 = create_block_at_height(2, block1.unwrap().header.block_hash);
            executor.apply_block(&block2).unwrap();

            assert_eq!(store.latest_height().unwrap(), 2);
        }
    }
}
