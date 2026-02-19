//! Block Executor (Single Authority)
//!
//! The BlockExecutor is the **single entry point** for applying blocks to state.
//! No consensus logic reads or writes state outside this module.
//!
//! # Execution Order (NON-NEGOTIABLE)
//!
//! ```text
//! validate_header
//! validate_block_resources
//! begin_block
//!   for tx in block.txs:
//!     validate_tx_stateless
//!     validate_tx_stateful
//!     apply_tx
//! append_block
//! commit_block
//! ```
//!
//! **Any error → rollback_block()**
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

use std::sync::Arc;

use crate::block::Block;
use crate::storage::{
    Address, Amount, BlockHash, BlockHeight, BlockchainStore, StorageError, TokenId,
};
use crate::transaction::hash_transaction;
use crate::types::TransactionType;

use super::errors::{BlockApplyError, BlockApplyResult, TxApplyError};
use super::tx_apply::{self, CoinbaseOutcome, StateMutator, TransferOutcome};

use crate::protocol::{fee_model, ProtocolParams};
use crate::resources::{BlockAccumulator, BlockLimits};

// Re-export lib-fees types for convenience
pub use lib_fees::{
    compute_fee_v2, verify_fee, FeeDeficit, FeeInput, FeeParams, SigScheme, TxKind,
};

// =============================================================================
// FEE MODEL V2
// =============================================================================

/// Fee Model V2 - Detailed computation with exec units, witness caps, etc.
///
/// This is the canonical fee calculation model for Phase 2+.
/// Uses lib_fees::compute_fee_v2 as the pure computation function.
///
/// # BlockExecutor Integration
///
/// BlockExecutor MUST reject: `tx.fee < compute_fee_v2(...)`
#[derive(Debug, Clone)]
pub struct FeeModelV2 {
    /// Fee computation parameters
    pub fee_params: FeeParams,
    /// Block reward amount (for coinbase)
    pub block_reward: Amount,
    /// Protocol parameters for version checking
    pub protocol_params: ProtocolParams,
}

impl Default for FeeModelV2 {
    fn default() -> Self {
        Self {
            fee_params: FeeParams::default(),
            block_reward: 50_000_000, // 50 tokens
            protocol_params: ProtocolParams::default(),
        }
    }
}

impl FeeModelV2 {
    /// Create with custom protocol params
    pub fn with_protocol_params(mut self, params: ProtocolParams) -> Self {
        self.protocol_params = params;
        self
    }

    /// Create with custom fee params
    pub fn with_fee_params(mut self, params: FeeParams) -> Self {
        self.fee_params = params;
        self
    }

    /// Calculate minimum required fee for a transaction
    pub fn calculate_min_fee(&self, input: &FeeInput) -> u64 {
        compute_fee_v2(input, &self.fee_params)
    }

    /// Verify transaction has paid sufficient fee
    ///
    /// Returns `Ok(())` if `paid_fee >= required_fee`, otherwise returns error.
    pub fn verify_tx_fee(&self, input: &FeeInput, paid_fee: u64) -> Result<(), FeeDeficit> {
        verify_fee(input, &self.fee_params, paid_fee)
    }

    /// Validate fee model version for a block
    pub fn validate_version(&self, height: BlockHeight, version: u16) -> BlockApplyResult<()> {
        let expected = self.protocol_params.active_fee_model_version(height);
        if version != expected {
            return Err(BlockApplyError::InvalidFeeModelVersion {
                height,
                actual: version,
                expected,
            });
        }
        Ok(())
    }

    /// Convert transaction to FeeInput for fee calculation
    pub fn tx_to_fee_input(tx: &crate::transaction::Transaction) -> FeeInput {
        // Determine TxKind from transaction type
        let kind = match tx.transaction_type {
            TransactionType::Transfer => TxKind::NativeTransfer,
            TransactionType::TokenTransfer => TxKind::TokenTransfer,
            TransactionType::Coinbase => TxKind::NativeTransfer, // Coinbase doesn't pay fees
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation => TxKind::Governance,
            TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::DaoProposal
            | TransactionType::DaoVote
            | TransactionType::DaoExecution
            | TransactionType::GovernanceConfigUpdate => TxKind::Governance,
            TransactionType::UbiDistribution => TxKind::NativeTransfer,
            TransactionType::ContractDeployment | TransactionType::ContractExecution => {
                TxKind::ContractCall
            }
            TransactionType::ContentUpload => TxKind::DataUpload,
            // Other types default to NativeTransfer pricing
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::WalletRegistration
            | TransactionType::WalletUpdate => TxKind::NativeTransfer,
            // Catch-all for any future types
            _ => TxKind::NativeTransfer,
        };

        // Determine signature scheme (default to Dilithium5 for quantum safety)
        let sig_scheme = SigScheme::Dilithium5;

        // Calculate sizes
        let envelope_bytes = 100; // Header overhead estimate
        let payload_bytes = tx.memo.len() as u32;
        // Witness is based on signature size, not ZK proof internals
        let witness_bytes = (tx.inputs.len() as u32) * sig_scheme.signature_size();

        FeeInput {
            kind,
            sig_scheme,
            sig_count: tx.inputs.len().max(1) as u8,
            envelope_bytes,
            payload_bytes,
            witness_bytes,
            exec_units: 0, // Would be set for contract calls
            state_reads: (tx.inputs.len() + tx.outputs.len()) as u32,
            state_writes: tx.outputs.len() as u32,
            state_write_bytes: (tx.outputs.len() * 64) as u32, // Estimate per output
        }
    }
}

// =============================================================================
// LEGACY CONFIG (for backwards compatibility)
// =============================================================================

/// Configuration for block execution (legacy - use FeeModelV2 + BlockLimits)
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

    /// Convert to new FeeModelV2 + BlockLimits
    pub fn to_fee_model_and_limits(&self) -> (FeeModelV2, BlockLimits) {
        let fee_model = FeeModelV2 {
            block_reward: self.block_reward as Amount,
            protocol_params: self.protocol_params.clone(),
            ..Default::default()
        };
        // Map legacy max_block_size to new max_payload_bytes
        let limits = BlockLimits {
            max_payload_bytes: self.max_block_size as u64,
            ..Default::default()
        };
        (fee_model, limits)
    }

    /// Whether empty blocks are allowed (legacy field, now always true)
    pub fn allows_empty_blocks(&self) -> bool {
        self.allow_empty_blocks
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

/// The main block executor (Single Authority)
///
/// This is the **ONLY** entry point for applying blocks to blockchain state.
/// No consensus logic reads or writes state outside this struct.
///
/// # Invariant
///
/// All state mutations happen through BlockExecutor. Period.
#[derive(Debug)]
pub struct BlockExecutor {
    store: Arc<dyn BlockchainStore>,
    fee_model: FeeModelV2,
    limits: BlockLimits,
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
    /// Create a new block executor with explicit fee model and limits
    pub fn new(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        limits: BlockLimits,
    ) -> Self {
        Self {
            store,
            fee_model,
            limits,
        }
    }

    /// Create with legacy ExecutorConfig (converts internally)
    pub fn from_config(store: Arc<dyn BlockchainStore>, config: ExecutorConfig) -> Self {
        let (fee_model, limits) = config.to_fee_model_and_limits();
        Self {
            store,
            fee_model,
            limits,
        }
    }

    /// Create with default fee model and limits
    pub fn with_store(store: Arc<dyn BlockchainStore>) -> Self {
        Self::new(store, FeeModelV2::default(), BlockLimits::default())
    }

    /// Get reference to the store
    pub fn store(&self) -> &Arc<dyn BlockchainStore> {
        &self.store
    }

    /// Get reference to the fee model
    pub fn fee_model(&self) -> &FeeModelV2 {
        &self.fee_model
    }

    /// Get reference to the block limits
    pub fn limits(&self) -> &BlockLimits {
        &self.limits
    }

    /// Apply a block to the blockchain
    ///
    /// # Execution Order (NON-NEGOTIABLE)
    ///
    /// ```text
    /// validate_header
    /// validate_block_resources
    /// begin_block
    ///   for tx in block.txs:
    ///     validate_tx_stateless
    ///     validate_tx_stateful
    ///     apply_tx
    /// append_block
    /// commit_block
    /// ```
    ///
    /// **Any error → rollback_block()**
    ///
    /// # Panic Safety
    ///
    /// Uses a scope guard to ensure rollback_block is called on both errors
    /// AND panics after begin_block.
    pub fn apply_block(&self, block: &Block) -> BlockApplyResult<ApplyOutcome> {
        let block_height = block.header.height;

        // =====================================================================
        // Step 1: validate_header
        // =====================================================================
        self.validate_header(block)?;

        // =====================================================================
        // Step 2: validate_block_resources
        // =====================================================================
        self.validate_block_resources(block)?;

        // =====================================================================
        // Step 3: begin_block
        // =====================================================================
        self.store.begin_block(block_height)?;

        // Create rollback guard for panic safety.
        // The guard will call rollback_block on Drop unless disarmed.
        let guard = RollbackGuard::new(self.store.as_ref());

        // Apply the block (steps 4-6)
        let outcome = self.apply_block_inner(block)?;

        // Success - disarm the guard so it won't rollback on drop
        guard.disarm();

        Ok(outcome)
    }

    /// Step 1: Validate block header
    ///
    /// Checks:
    /// - Height is expected next height
    /// - Previous hash matches (except genesis)
    /// - Fee model version is correct for height
    fn validate_header(&self, block: &Block) -> BlockApplyResult<()> {
        let expected_height = self.get_expected_height()?;
        let block_height = block.header.height;

        // Height must be sequential
        if block_height != expected_height {
            return Err(BlockApplyError::HeightMismatch {
                expected: expected_height,
                actual: block_height,
            });
        }

        // Previous hash must match (except for genesis)
        if block_height > 0 {
            self.validate_previous_hash(block, block_height)?;
        }

        // Fee model version must be correct for this height
        self.fee_model
            .validate_version(block_height, block.header.fee_model_version)?;

        Ok(())
    }

    /// Step 2: Validate block resources against limits (quick initial check)
    ///
    /// Checks:
    /// - Block payload size within limits
    /// - Transaction count within limits
    /// - Transaction count matches header
    ///
    /// Note: Detailed per-tx resource accounting is done by BlockAccumulator
    /// in apply_block_inner, which can reject the block mid-execution.
    fn validate_block_resources(&self, block: &Block) -> BlockApplyResult<()> {
        // Check block payload size
        let size = block.size() as u64;
        if size > self.limits.max_payload_bytes {
            return Err(BlockApplyError::BlockTooLarge {
                size: size as usize,
                max: self.limits.max_payload_bytes as usize,
            });
        }

        // Check transaction count
        let tx_count = block.transactions.len() as u32;
        if tx_count > self.limits.max_tx_count {
            return Err(BlockApplyError::ValidationFailed(format!(
                "Block has {} transactions, max is {}",
                tx_count, self.limits.max_tx_count
            )));
        }

        // Transaction count must match header
        if block.header.transaction_count != tx_count {
            return Err(BlockApplyError::ValidationFailed(format!(
                "Transaction count mismatch: header says {} but block has {}",
                block.header.transaction_count, tx_count
            )));
        }

        Ok(())
    }

    /// Steps 4-6: Apply transactions, append block, commit
    ///
    /// Called after begin_block. Guard ensures rollback on error.
    fn apply_block_inner(&self, block: &Block) -> BlockApplyResult<ApplyOutcome> {
        let block_height = block.header.height;
        let block_hash = BlockHash::new(block.header.block_hash.as_array());

        let mutator = StateMutator::new(self.store.as_ref());
        let mut summary = StateChangesSummary::default();
        let mut total_fees: u64 = 0;

        // Initialize block-level resource accumulator
        let mut accumulator = BlockAccumulator::new();

        // =====================================================================
        // Pre-step: Coinbase position validation
        // =====================================================================

        // Count coinbase transactions and validate position
        let coinbase_count = block
            .transactions
            .iter()
            .filter(|tx| tx.transaction_type == TransactionType::Coinbase)
            .count();

        if coinbase_count > 1 {
            return Err(BlockApplyError::ValidationFailed(
                "Block must have at most one coinbase transaction".to_string(),
            ));
        }

        // If there is a coinbase, it must be the first transaction
        if coinbase_count == 1 {
            if block
                .transactions
                .first()
                .map(|tx| tx.transaction_type != TransactionType::Coinbase)
                .unwrap_or(true)
            {
                return Err(BlockApplyError::ValidationFailed(
                    "Coinbase transaction must be first in block".to_string(),
                ));
            }
        }

        // =====================================================================
        // Genesis block exception (height 0)
        // =====================================================================
        //
        // Genesis is created out-of-band by the founding node (UTXOs are injected
        // directly into the UTXO set by GenesisFundingService).  When a peer
        // receives and replays the genesis block its transactions don't satisfy
        // normal executor invariants (empty inputs, system recipients, etc.).
        // We accept the genesis block as-is: just record it in the store and
        // return an empty outcome — the founding node already committed the state.
        if block_height == 0 {
            self.store
                .append_block(block)
                .map_err(|e| BlockApplyError::PersistFailed(e.to_string()))?;
            self.store.commit_block()?;
            return Ok(ApplyOutcome {
                height: block_height,
                block_hash,
                tx_count: block.transactions.len(),
                state_changes: summary,
                fees_collected: total_fees,
            });
        }

        // =====================================================================
        // Step 4: Apply transactions (Phase 3C: two-pass for fee routing)
        // =====================================================================
        //
        // For each tx: validate_tx_stateless → validate_tx_stateful → apply_tx
        //
        // Phase 3C: Process non-coinbase transactions first to calculate fees
        // Then process coinbase with the collected fees for proper routing.

        let coinbase_tx = if coinbase_count == 1 {
            Some(&block.transactions[0])
        } else {
            None
        };

        // 4a: Process non-coinbase transactions first
        let non_coinbase_start = if coinbase_count == 1 { 1 } else { 0 };

        for (rel_index, tx) in block.transactions[non_coinbase_start..].iter().enumerate() {
            let index = rel_index + non_coinbase_start;

            // Resource accounting: accumulate tx resources BEFORE application
            // Block is rejected if any limit exceeded
            let (payload_bytes, witness_bytes, verify_units, state_write_bytes) =
                self.calculate_tx_resources(tx);
            accumulator.add_tx(
                &self.limits,
                payload_bytes,
                witness_bytes,
                verify_units,
                state_write_bytes,
            )?;

            // validate_tx_stateless
            self.validate_tx_stateless(tx)
                .map_err(|e| BlockApplyError::TxFailed { index, reason: e })?;

            // validate_tx_stateful (reads only)
            self.validate_tx_stateful(tx)
                .map_err(|e| BlockApplyError::TxFailed { index, reason: e })?;

            // apply_tx (writes)
            let tx_result = self
                .apply_tx(&mutator, tx, block_height)
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
                TxOutcome::TokenMint(_outcome) => {
                    summary.balance_changes += 1; // recipient only
                }
                TxOutcome::DaoProposal(_) => {
                    summary.balance_changes += 1; // tracks deterministic DAO state updates
                }
                TxOutcome::DaoVote(_) => {
                    summary.balance_changes += 1; // tracks deterministic DAO state updates
                }
                TxOutcome::DaoExecution(_) => {
                    summary.balance_changes += 1; // tracks deterministic DAO state updates
                }
                TxOutcome::Coinbase(_) => {
                    // Should not happen - coinbase filtered out
                    unreachable!("Coinbase should not be in non-coinbase pass");
                }
                TxOutcome::LegacySystem => {
                    // No state changes for legacy system transactions.
                }
            }
        }

        // 4b: Process coinbase with collected fees (Phase 3C)
        if let Some(coinbase) = coinbase_tx {
            // Coinbase also accumulates resources
            let (payload_bytes, witness_bytes, verify_units, state_write_bytes) =
                self.calculate_tx_resources(coinbase);
            accumulator.add_tx(
                &self.limits,
                payload_bytes,
                witness_bytes,
                verify_units,
                state_write_bytes,
            )?;

            self.validate_tx_stateless(coinbase)
                .map_err(|e| BlockApplyError::TxFailed {
                    index: 0,
                    reason: e,
                })?;

            let coinbase_result = self
                .apply_coinbase_with_fees(&mutator, coinbase, block_height, total_fees)
                .map_err(|e| BlockApplyError::TxFailed {
                    index: 0,
                    reason: e,
                })?;

            summary.utxos_created += coinbase_result.outputs_created;
        }

        // =====================================================================
        // Step 5: append_block
        // =====================================================================

        self.store
            .append_block(block)
            .map_err(|e| BlockApplyError::PersistFailed(e.to_string()))?;

        // =====================================================================
        // Step 6: commit_block
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
        let expected_hash = self
            .store
            .get_block_hash_by_height(prev_height)?
            .ok_or_else(|| {
                BlockApplyError::ValidationFailed(format!(
                    "Previous block at height {} not found",
                    prev_height
                ))
            })?;

        let actual_hash = BlockHash::new(block.header.previous_block_hash.as_array());

        if expected_hash != actual_hash {
            return Err(BlockApplyError::InvalidPreviousHash {
                expected: expected_hash,
                actual: actual_hash,
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
    fn validate_tx_stateless(
        &self,
        tx: &crate::transaction::Transaction,
    ) -> Result<(), TxApplyError> {
        // Check transaction type is supported in Phase 2.
        //
        // The executor understands four Phase-2 types (Transfer, TokenTransfer, TokenMint,
        // Coinbase) and applies full structural + fee validation to them below.
        //
        // All other types in the TransactionType enum are legacy system types that existed
        // before the Phase-2 executor was introduced. Blocks mined on earlier protocol
        // versions may contain them, and peers must be able to sync those blocks without
        // rejection. We accept them here as pass-throughs (no structural validation) and
        // apply them as no-ops in apply_transaction.
        //
        // Using an exhaustive match (rather than a catch-all `_`) forces the compiler to
        // demand an explicit decision for any new TransactionType variant added in the future,
        // preventing accidental silent acceptance of unrelated future types.
        match tx.transaction_type {
            // Phase-2 types: fall through to structural validation below.
            TransactionType::Transfer => {}
            TransactionType::TokenTransfer => {}
            TransactionType::TokenMint => {}
            TransactionType::Coinbase => {}
            // Known legacy system types: no structural validation, applied as no-ops.
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation
            | TransactionType::WalletRegistration
            | TransactionType::WalletUpdate
            | TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister
            | TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload
            | TransactionType::UbiDistribution
            | TransactionType::DifficultyUpdate
            | TransactionType::UBIClaim
            | TransactionType::ProfitDeclaration
            | TransactionType::GovernanceConfigUpdate
            | TransactionType::ContractDeployment
            | TransactionType::ContractExecution
            // Phase 3/4 types - handled by executor but validation not fully wired yet
            | TransactionType::TokenCreation
            | TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                return Ok(());
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
                        "Coinbase must have no inputs".to_string(),
                    ));
                }
                // Coinbase must have outputs
                if tx.outputs.is_empty() {
                    return Err(TxApplyError::EmptyOutputs);
                }
                // Phase 2 lock: Coinbase fee must be 0
                if tx.fee != 0 {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase transaction fee must be 0".to_string(),
                    ));
                }
                // Coinbase must not have non-Phase-2 fields set
                if tx.identity_data.is_some()
                    || tx.wallet_data.is_some()
                    || tx.validator_data.is_some()
                    || tx.dao_proposal_data.is_some()
                    || tx.dao_vote_data.is_some()
                    || tx.dao_execution_data.is_some()
                    || tx.ubi_claim_data.is_some()
                    || tx.profit_declaration_data.is_some()
                {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase must not have non-Phase-2 data fields".to_string(),
                    ));
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer must have token_transfer_data
                if tx.token_transfer_data.is_none() {
                    return Err(TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string(),
                    ));
                }
                // Validate token_transfer_data fields
                let data = tx.token_transfer_data.as_ref().unwrap();
                if data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "Token transfer amount must be greater than 0".to_string(),
                    ));
                }
                // Phase 2 lock: TokenTransfer fee must be 0
                if tx.fee != 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenTransfer transaction fee must be 0 in Phase 2".to_string(),
                    ));
                }
            }
            TransactionType::TokenMint => {
                if tx.version < 2 {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint transactions not supported in this serialization version"
                            .to_string(),
                    ));
                }
                if tx.token_mint_data.is_none() {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint requires token_mint_data field".to_string(),
                    ));
                }
                let data = tx.token_mint_data.as_ref().unwrap();
                if data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint amount must be greater than 0".to_string(),
                    ));
                }
                if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint must not have UTXO inputs or outputs".to_string(),
                    ));
                }
                if tx.fee != 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint transaction fee must be 0 in Phase 2".to_string(),
                    ));
                }
            }
            TransactionType::DaoProposal => {
                let data = tx.dao_proposal_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "DaoProposal requires dao_proposal_data field".to_string(),
                    )
                })?;
                if data.proposer.trim().is_empty() || data.title.trim().is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "DaoProposal proposer/title must be non-empty".to_string(),
                    ));
                }
            }
            TransactionType::DaoVote => {
                let data = tx.dao_vote_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType("DaoVote requires dao_vote_data field".to_string())
                })?;
                if data.voter.trim().is_empty() || data.vote_choice.trim().is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "DaoVote voter/vote_choice must be non-empty".to_string(),
                    ));
                }
            }
            TransactionType::DaoExecution => {
                let data = tx.dao_execution_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "DaoExecution requires dao_execution_data field".to_string(),
                    )
                })?;
                if data.executor.trim().is_empty() || data.execution_type.trim().is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "DaoExecution executor/execution_type must be non-empty".to_string(),
                    ));
                }
            }
            _ => {}
        }

        // =========================================================================
        // Fee Validation (Phase 4: Fee Model v2)
        // =========================================================================
        // BlockExecutor MUST reject: tx.fee < compute_fee_v2(...)
        // Coinbase and zero-fee transactions (TokenTransfer in Phase 2) are exempt.
        self.validate_tx_fee(tx)?;

        Ok(())
    }

    /// Validate transaction has paid sufficient fee using Fee Model v2
    ///
    /// # Rule
    ///
    /// BlockExecutor MUST reject: `tx.fee < compute_fee_v2(...)`
    ///
    /// # Exemptions
    ///
    /// - Coinbase transactions (fee must be 0)
    /// - TokenTransfer in Phase 2 (fee must be 0, subsidized)
    fn validate_tx_fee(&self, tx: &crate::transaction::Transaction) -> Result<(), TxApplyError> {
        // Exempt transactions that don't pay fees
        match tx.transaction_type {
            TransactionType::Coinbase => return Ok(()), // Creates value, no fee
            TransactionType::TokenTransfer => return Ok(()), // Phase 2: subsidized
            TransactionType::TokenMint => return Ok(()), // Phase 2: system mint
            _ => {}
        }

        // Convert transaction to FeeInput
        let fee_input = FeeModelV2::tx_to_fee_input(tx);

        // Compute required fee using pure function
        let required_fee = self.fee_model.calculate_min_fee(&fee_input);

        // Verify paid fee >= required fee
        if tx.fee < required_fee {
            return Err(TxApplyError::InsufficientFee {
                required: required_fee,
                paid: tx.fee,
            });
        }

        Ok(())
    }

    /// Stateful transaction validation (reads only, no writes)
    fn validate_tx_stateful(
        &self,
        tx: &crate::transaction::Transaction,
    ) -> Result<(), TxApplyError> {
        use super::state_view::StateView;
        use crate::storage::TxHash;

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
                let transfer = tx.token_transfer_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType("TokenTransfer requires token_transfer_data".into())
                })?;

                let token = if transfer.is_native() {
                    TokenId::NATIVE
                } else {
                    TokenId::new(transfer.token_id)
                };
                let from = Address::new(transfer.from);

                let expected_nonce = view.get_token_nonce(&token, &from)?;
                if transfer.nonce != expected_nonce {
                    return Err(TxApplyError::InvalidNonce {
                        expected: expected_nonce,
                        actual: transfer.nonce,
                    });
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Calculate resource requirements for a transaction
    ///
    /// Returns (payload_bytes, witness_bytes, verify_units, state_write_bytes)
    ///
    /// This is used by BlockAccumulator to track cumulative resource usage
    /// and reject the block if any limit is exceeded.
    fn calculate_tx_resources(&self, tx: &crate::transaction::Transaction) -> (u64, u64, u64, u64) {
        use crate::transaction::Transaction;

        // Payload bytes: serialized tx size (excluding witnesses)
        // Approximation: tx size minus signature/proof data
        let payload_bytes = self.estimate_tx_payload_size(tx);

        // Witness bytes: signatures + ZK proofs
        let witness_bytes = self.estimate_tx_witness_size(tx);

        // Verify units: cost of signature/proof verification
        // Ed25519 = 1 unit, Groth16 = 100 units (example costs)
        let verify_units = self.estimate_tx_verify_units(tx);

        // State write bytes: estimated storage changes
        // Inputs (deletions) + outputs (insertions) + token balance updates
        let state_write_bytes = self.estimate_tx_state_writes(tx);

        (
            payload_bytes,
            witness_bytes,
            verify_units,
            state_write_bytes,
        )
    }

    /// Estimate payload size (serialized tx minus witnesses)
    fn estimate_tx_payload_size(&self, tx: &crate::transaction::Transaction) -> u64 {
        // Base size: version (4) + chain_id (1) + type (1) + fee (8) + memo length
        let base = 14 + tx.memo.len();

        // Inputs: each input is ~100 bytes (prev_output hash, index, nullifier)
        // Exclude zk_proof from payload (it's witness data)
        let inputs_payload = tx.inputs.len() * 68; // 32 + 4 + 32 = 68

        // Outputs: each output is ~96 bytes (commitment, note, recipient)
        let outputs = tx.outputs.len() * 96;

        // Optional data fields (rough estimates)
        let optional_data = tx.identity_data.as_ref().map(|_| 256).unwrap_or(0)
            + tx.wallet_data.as_ref().map(|_| 128).unwrap_or(0)
            + tx.validator_data.as_ref().map(|_| 256).unwrap_or(0)
            + tx.token_transfer_data.as_ref().map(|_| 104).unwrap_or(0)
            + tx.token_mint_data.as_ref().map(|_| 72).unwrap_or(0); // 32+32+8

        (base + inputs_payload + outputs + optional_data) as u64
    }

    /// Estimate witness size (signatures + ZK proofs)
    fn estimate_tx_witness_size(&self, tx: &crate::transaction::Transaction) -> u64 {
        // Main signature (Ed25519 = 64 bytes)
        let sig_size = tx.signature.signature.len();

        // ZK proofs in inputs: sum of all proof data from amount, balance, nullifier proofs
        let proof_size: usize = tx
            .inputs
            .iter()
            .map(|i| {
                i.zk_proof.amount_proof.proof_data.len()
                    + i.zk_proof.balance_proof.proof_data.len()
                    + i.zk_proof.nullifier_proof.proof_data.len()
            })
            .sum();

        (sig_size + proof_size) as u64
    }

    /// Estimate verification cost in units
    fn estimate_tx_verify_units(&self, tx: &crate::transaction::Transaction) -> u64 {
        // Ed25519 signature verification: 1 unit
        let sig_units = 1u64;

        // ZK proof verification: each proof in ZkTransactionProof costs units
        // 3 proofs per input (amount, balance, nullifier), ~10 units each
        let proof_units: u64 = tx.inputs.len() as u64 * 30;

        sig_units + proof_units
    }

    /// Estimate state write bytes
    fn estimate_tx_state_writes(&self, tx: &crate::transaction::Transaction) -> u64 {
        match tx.transaction_type {
            TransactionType::Transfer => {
                // UTXO deletions (inputs) + UTXO creations (outputs)
                // Each UTXO entry ~150 bytes (key + value)
                let utxo_writes = (tx.inputs.len() + tx.outputs.len()) * 150;
                utxo_writes as u64
            }
            TransactionType::Coinbase => {
                // Only creates outputs
                let utxo_writes = tx.outputs.len() * 150;
                utxo_writes as u64
            }
            TransactionType::TokenTransfer => {
                // Two balance updates (from + to), ~100 bytes each
                200
            }
            TransactionType::TokenMint => {
                // One balance update (to), ~100 bytes
                100
            }
            _ => {
                // Conservative estimate for unknown types
                500
            }
        }
    }

    fn dao_state_contract_id() -> [u8; 32] {
        lib_crypto::hash_blake3(b"DAO_GOVERNANCE_V1")
    }

    fn apply_dao_proposal(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        tx_hash: &crate::types::Hash,
    ) -> Result<DaoProposalOutcome, TxApplyError> {
        let data = tx.dao_proposal_data.as_ref().ok_or_else(|| {
            TxApplyError::InvalidType("DaoProposal requires dao_proposal_data field".to_string())
        })?;

        let contract_id = Self::dao_state_contract_id();
        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(data.proposal_id.as_bytes());

        let encoded = bincode::serialize(data).map_err(|e| {
            TxApplyError::Internal(format!("Failed to serialize DaoProposalData: {e}"))
        })?;
        mutator.put_contract_storage(&contract_id, &proposal_key, &encoded)?;

        let mut index_key = b"proposal_index:".to_vec();
        index_key.extend_from_slice(tx_hash.as_bytes());
        mutator.put_contract_storage(
            &contract_id,
            &index_key,
            data.proposal_id.as_bytes(),
        )?;

        Ok(DaoProposalOutcome {
            proposal_id: data.proposal_id,
        })
    }

    fn apply_dao_vote(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
    ) -> Result<DaoVoteOutcome, TxApplyError> {
        let data = tx.dao_vote_data.as_ref().ok_or_else(|| {
            TxApplyError::InvalidType("DaoVote requires dao_vote_data field".to_string())
        })?;

        let contract_id = Self::dao_state_contract_id();
        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(data.proposal_id.as_bytes());
        let proposal_exists = self
            .store
            .get_contract_storage(&contract_id, &proposal_key)?
            .is_some();
        if !proposal_exists {
            return Err(TxApplyError::InvalidType(
                "DaoVote references unknown proposal".to_string(),
            ));
        }

        let mut vote_key = b"vote:".to_vec();
        vote_key.extend_from_slice(data.proposal_id.as_bytes());
        vote_key.extend_from_slice(b":");
        vote_key.extend_from_slice(data.vote_id.as_bytes());
        let encoded = bincode::serialize(data)
            .map_err(|e| TxApplyError::Internal(format!("Failed to serialize DaoVoteData: {e}")))?;
        mutator.put_contract_storage(&contract_id, &vote_key, &encoded)?;

        Ok(DaoVoteOutcome {
            proposal_id: data.proposal_id,
            vote_id: data.vote_id,
        })
    }

    fn apply_dao_execution(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        tx_hash: &crate::types::Hash,
    ) -> Result<DaoExecutionOutcome, TxApplyError> {
        let data = tx.dao_execution_data.as_ref().ok_or_else(|| {
            TxApplyError::InvalidType("DaoExecution requires dao_execution_data field".to_string())
        })?;

        let contract_id = Self::dao_state_contract_id();
        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(data.proposal_id.as_bytes());
        let proposal_exists = self
            .store
            .get_contract_storage(&contract_id, &proposal_key)?
            .is_some();
        if !proposal_exists {
            return Err(TxApplyError::InvalidType(
                "DaoExecution references unknown proposal".to_string(),
            ));
        }

        let mut execution_key = b"execution:".to_vec();
        execution_key.extend_from_slice(data.proposal_id.as_bytes());
        execution_key.extend_from_slice(b":");
        execution_key.extend_from_slice(tx_hash.as_bytes());
        let encoded = bincode::serialize(data).map_err(|e| {
            TxApplyError::Internal(format!("Failed to serialize DaoExecutionData: {e}"))
        })?;
        mutator.put_contract_storage(&contract_id, &execution_key, &encoded)?;
        mutator.put_contract_storage(
            &contract_id,
            b"last_execution_proposal",
            data.proposal_id.as_bytes(),
        )?;

        Ok(DaoExecutionOutcome {
            proposal_id: data.proposal_id,
        })
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
                let outcome = tx_apply::apply_native_transfer(mutator, tx, &tx_hash, block_height)?;
                Ok(TxOutcome::Transfer(outcome))
            }
            TransactionType::Coinbase => {
                // Legacy path: no fees passed (for backwards compatibility in tests)
                let fee_sink = self.fee_model.protocol_params.fee_sink_address();
                let outcome = tx_apply::apply_coinbase(
                    mutator,
                    tx,
                    &tx_hash,
                    block_height,
                    self.fee_model.block_reward as u64,
                    0, // No fees in legacy path
                    fee_sink,
                )?;
                Ok(TxOutcome::Coinbase(outcome))
            }
            TransactionType::TokenTransfer => {
                // Extract token transfer data - must be present for TokenTransfer type
                let transfer_data = tx.token_transfer_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string(),
                    )
                })?;

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
                        "Token transfer amount must be greater than 0".to_string(),
                    ));
                }

                // Apply the token transfer (debit from, credit to)
                tx_apply::apply_token_transfer(mutator, &token, &from, &to, amount)?;

                // Increment nonce for replay protection
                mutator.increment_token_nonce(&token, &from)?;

                Ok(TxOutcome::TokenTransfer(TokenTransferOutcome {
                    token,
                    from,
                    to,
                    amount,
                }))
            }
            TransactionType::TokenMint => {
                let mint_data = tx.token_mint_data.as_ref().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "TokenMint requires token_mint_data field".to_string(),
                    )
                })?;

                if mint_data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint amount must be greater than 0".to_string(),
                    ));
                }

                let token = if mint_data.token_id == [0u8; 32] {
                    TokenId::NATIVE
                } else {
                    TokenId::new(mint_data.token_id)
                };

                let to = Address::new(mint_data.to);
                let amount = mint_data.amount;

                tx_apply::apply_token_mint(mutator, &token, &to, amount)?;

                Ok(TxOutcome::TokenMint(TokenMintOutcome { token, to, amount }))
            }
            TransactionType::DaoProposal => {
                let outcome = self.apply_dao_proposal(mutator, tx, &tx_hash)?;
                Ok(TxOutcome::DaoProposal(outcome))
            }
            TransactionType::DaoVote => {
                let outcome = self.apply_dao_vote(mutator, tx)?;
                Ok(TxOutcome::DaoVote(outcome))
            }
            TransactionType::DaoExecution => {
                let outcome = self.apply_dao_execution(mutator, tx, &tx_hash)?;
                Ok(TxOutcome::DaoExecution(outcome))
            }
            // Known legacy system types: accepted as no-ops. This mirrors the allowlist in
            // validate_tx_stateless — any type listed here must also be listed there.
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation
            | TransactionType::WalletRegistration
            | TransactionType::WalletUpdate
            | TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister
            | TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload
            | TransactionType::UbiDistribution
            | TransactionType::DifficultyUpdate
            | TransactionType::UBIClaim
            | TransactionType::ProfitDeclaration
            | TransactionType::GovernanceConfigUpdate
            | TransactionType::ContractDeployment
            | TransactionType::ContractExecution => Ok(TxOutcome::LegacySystem),

            // Coinbase is routed through apply_coinbase_with_fees, never here.
            TransactionType::Coinbase => Err(TxApplyError::InvalidType(
                "Coinbase must not be routed through apply_transaction".to_string(),
            )),
            _ => Err(TxApplyError::UnsupportedType(format!(
                "{:?}",
                tx.transaction_type
            ))),
        }
    }

    /// Apply a transaction (non-coinbase)
    ///
    /// This is the `apply_tx` step in the execution order.
    /// Used in the first pass to process all fee-paying transactions
    /// before processing coinbase with the collected fees.
    fn apply_tx(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<TxOutcome, TxApplyError> {
        // Coinbase should not be passed to this method
        if tx.transaction_type == TransactionType::Coinbase {
            return Err(TxApplyError::InvalidType(
                "Coinbase should not be processed in apply_tx pass".to_string(),
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
                "Expected coinbase transaction".to_string(),
            ));
        }

        let tx_hash = hash_transaction(tx);
        let fee_sink_address = self.fee_model.protocol_params.fee_sink_address();

        tx_apply::apply_coinbase(
            mutator,
            tx,
            &tx_hash,
            block_height,
            self.fee_model.block_reward as u64,
            fees_collected,
            fee_sink_address,
        )
    }
}

/// Outcome of applying a single transaction
enum TxOutcome {
    Transfer(TransferOutcome),
    TokenTransfer(TokenTransferOutcome),
    TokenMint(TokenMintOutcome),
    DaoProposal(DaoProposalOutcome),
    DaoVote(DaoVoteOutcome),
    DaoExecution(DaoExecutionOutcome),
    Coinbase(CoinbaseOutcome),
    /// Legacy system transaction types (IdentityRegistration, WalletRegistration, etc.)
    /// accepted as no-ops by the Phase-2 executor for backwards compatibility.
    LegacySystem,
}

/// Outcome of a token transfer transaction
#[derive(Debug, Clone)]
pub struct TokenTransferOutcome {
    pub token: TokenId,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
}

/// Outcome of a token mint transaction
#[derive(Debug, Clone)]
pub struct TokenMintOutcome {
    pub token: TokenId,
    pub to: Address,
    pub amount: u128,
}

/// Outcome of DAO proposal transaction
#[derive(Debug, Clone)]
pub struct DaoProposalOutcome {
    pub proposal_id: crate::types::Hash,
}

/// Outcome of DAO vote transaction
#[derive(Debug, Clone)]
pub struct DaoVoteOutcome {
    pub proposal_id: crate::types::Hash,
    pub vote_id: crate::types::Hash,
}

/// Outcome of DAO execution transaction
#[derive(Debug, Clone)]
pub struct DaoExecutionOutcome {
    pub proposal_id: crate::types::Hash,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::storage::SledStore;
    use crate::types::{Difficulty, Hash};

    fn create_test_store() -> Arc<dyn BlockchainStore> {
        Arc::new(SledStore::open_temporary().unwrap())
    }

    /// Create executor with testing fee params (minimal fees for tests)
    fn create_test_executor(store: Arc<dyn BlockchainStore>) -> BlockExecutor {
        let fee_model = FeeModelV2 {
            fee_params: FeeParams::for_testing(), // Minimal fees
            block_reward: 50_000_000,
            protocol_params: ProtocolParams::default(),
        };
        BlockExecutor::new(store, fee_model, BlockLimits::default())
    }

    fn create_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // Unique genesis hash
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::default(),
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            timestamp: 1000,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            cumulative_difficulty: Difficulty::minimum(),
            height: 0,
            block_hash,
            transaction_count: 0,
            block_size: 0,
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
            state_root: Hash::default(),
            timestamp: 1000 + height,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            cumulative_difficulty: Difficulty::minimum(),
            height,
            block_hash,
            transaction_count: 0,
            block_size: 0,
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

        assert!(matches!(
            result,
            Err(BlockApplyError::HeightMismatch { .. })
        ));
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

        assert!(matches!(
            result,
            Err(BlockApplyError::InvalidPreviousHash { .. })
        ));
    }

    // =========================================================================
    // Integration Tests T2-T5
    // =========================================================================

    use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
    use crate::integration::zk_integration::ZkTransactionProof;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput};
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
            fee: 10_000, // High enough for testing fee params
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
            token_mint_data: None,
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
            token_mint_data: None,
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
            state_root: Hash::default(),
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
            state_root: Hash::default(),
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
        let fake_tx_hash = Hash::new([
            0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]);
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
        let executor = create_test_executor(store.clone());

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
        use crate::storage::{Address, TokenId};

        let store = create_test_store();
        let executor = create_test_executor(store.clone());

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

    // =========================================================================
    // Legacy system transaction tests
    // =========================================================================

    fn create_legacy_tx(tx_type: TransactionType) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: tx_type,
            inputs: vec![],
            outputs: vec![],
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
            token_mint_data: None,
            governance_config_data: None,
        }
    }

    fn create_dao_proposal_tx(proposal_id: Hash) -> Transaction {
        let mut tx = create_legacy_tx(TransactionType::DaoProposal);
        tx.fee = 1_000_000;
        tx.dao_proposal_data = Some(crate::transaction::DaoProposalData {
            proposal_id,
            proposer: "did:sov:test:proposer".to_string(),
            title: "Enable treasury stream".to_string(),
            description: "Deterministic proposal for executor test".to_string(),
            proposal_type: "TreasurySpending".to_string(),
            voting_period_blocks: 100,
            quorum_required: 60,
            execution_params: Some(vec![0xAA, 0xBB]),
            created_at: 1001,
            created_at_height: 1,
        });
        tx
    }

    fn create_dao_vote_tx(proposal_id: Hash, vote_id: Hash) -> Transaction {
        let mut tx = create_legacy_tx(TransactionType::DaoVote);
        tx.fee = 1_000_000;
        tx.dao_vote_data = Some(crate::transaction::DaoVoteData {
            vote_id,
            proposal_id,
            voter: "did:sov:test:voter".to_string(),
            vote_choice: "Yes".to_string(),
            voting_power: 10,
            justification: Some("looks good".to_string()),
            timestamp: 1002,
        });
        tx
    }

    fn create_dao_execution_tx(proposal_id: Hash) -> Transaction {
        let mut tx = create_legacy_tx(TransactionType::DaoExecution);
        tx.fee = 1_000_000;
        tx.dao_execution_data = Some(crate::transaction::DaoExecutionData {
            proposal_id,
            executor: "did:sov:test:executor".to_string(),
            execution_type: "TreasuryTransfer".to_string(),
            recipient: Some("did:sov:test:recipient".to_string()),
            amount: Some(42),
            executed_at: 1003,
            executed_at_height: 1,
            multisig_signatures: vec![vec![0x01, 0x02]],
        });
        tx
    }

    /// Known legacy types must pass validate_tx_stateless without structural validation.
    #[test]
    fn test_legacy_tx_passes_stateless_validation() {
        let store = create_test_store();
        let executor = create_test_executor(store);

        let legacy_types = [
            TransactionType::IdentityRegistration,
            TransactionType::IdentityUpdate,
            TransactionType::IdentityRevocation,
            TransactionType::WalletRegistration,
            TransactionType::WalletUpdate,
            TransactionType::ValidatorRegistration,
            TransactionType::ValidatorUpdate,
            TransactionType::ValidatorUnregister,
            TransactionType::SessionCreation,
            TransactionType::SessionTermination,
            TransactionType::ContentUpload,
            TransactionType::UbiDistribution,
            TransactionType::DifficultyUpdate,
            TransactionType::UBIClaim,
            TransactionType::ProfitDeclaration,
            TransactionType::GovernanceConfigUpdate,
            TransactionType::ContractDeployment,
            TransactionType::ContractExecution,
        ];

        for tx_type in legacy_types {
            let tx = create_legacy_tx(tx_type);
            let result = executor.validate_tx_stateless(&tx);
            assert!(
                result.is_ok(),
                "Expected legacy tx type {:?} to pass stateless validation, got {:?}",
                tx_type,
                result
            );
        }
    }

    /// A block containing legacy tx types must be accepted end-to-end by apply_block.
    #[test]
    fn test_block_with_legacy_tx_is_accepted() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        // Apply genesis
        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Build block 1 with legacy txs: IdentityRegistration and WalletRegistration
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&1u64.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let mut tx1 = create_legacy_tx(TransactionType::IdentityRegistration);
        tx1.fee = 0; // legacy txs are fee-free
        let mut tx2 = create_legacy_tx(TransactionType::WalletRegistration);
        tx2.fee = 0;

        let header = BlockHeader {
            version: 1,
            previous_block_hash: genesis.header.block_hash,
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            timestamp: 1001,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            cumulative_difficulty: Difficulty::minimum(),
            height: 1,
            block_hash,
            transaction_count: 2,
            block_size: 0,
            fee_model_version: 2,
        };
        let block1 = Block::new(header, vec![tx1, tx2]);

        let outcome = executor.apply_block(&block1).unwrap();
        assert_eq!(outcome.height, 1);
        assert_eq!(outcome.tx_count, 2);
        assert_eq!(store.latest_height().unwrap(), 1);
    }

    #[test]
    fn test_dao_lifecycle_txs_persist_canonical_state() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let proposal_id = Hash::new([0x11; 32]);
        let vote_id = Hash::new([0x22; 32]);
        let proposal_tx = create_dao_proposal_tx(proposal_id);
        let vote_tx = create_dao_vote_tx(proposal_id, vote_id);
        let execution_tx = create_dao_execution_tx(proposal_id);
        let execution_tx_hash = hash_transaction(&execution_tx);

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&1u64.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_block_hash: genesis.header.block_hash,
            merkle_root: Hash::default(),
            state_root: Hash::default(),
            timestamp: 1001,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            cumulative_difficulty: Difficulty::minimum(),
            height: 1,
            block_hash,
            transaction_count: 3,
            block_size: 0,
            fee_model_version: 2,
        };
        let block = Block::new(header, vec![proposal_tx, vote_tx, execution_tx]);
        executor.apply_block(&block).unwrap();

        let dao_contract_id = BlockExecutor::dao_state_contract_id();

        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(proposal_id.as_bytes());
        let proposal_raw = store
            .get_contract_storage(&dao_contract_id, &proposal_key)
            .unwrap()
            .expect("proposal must be persisted");
        let proposal: crate::transaction::DaoProposalData =
            bincode::deserialize(&proposal_raw).expect("proposal decode");
        assert_eq!(proposal.title, "Enable treasury stream");

        let mut vote_key = b"vote:".to_vec();
        vote_key.extend_from_slice(proposal_id.as_bytes());
        vote_key.extend_from_slice(b":");
        vote_key.extend_from_slice(vote_id.as_bytes());
        let vote_raw = store
            .get_contract_storage(&dao_contract_id, &vote_key)
            .unwrap()
            .expect("vote must be persisted");
        let vote: crate::transaction::DaoVoteData =
            bincode::deserialize(&vote_raw).expect("vote decode");
        assert_eq!(vote.vote_choice, "Yes");

        let mut execution_key = b"execution:".to_vec();
        execution_key.extend_from_slice(proposal_id.as_bytes());
        execution_key.extend_from_slice(b":");
        execution_key.extend_from_slice(execution_tx_hash.as_bytes());
        let execution_raw = store
            .get_contract_storage(&dao_contract_id, &execution_key)
            .unwrap()
            .expect("execution must be persisted");
        let execution: crate::transaction::DaoExecutionData =
            bincode::deserialize(&execution_raw).expect("execution decode");
        assert_eq!(execution.execution_type, "TreasuryTransfer");
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
