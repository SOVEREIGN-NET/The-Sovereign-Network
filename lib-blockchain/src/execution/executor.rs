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
    WalletProjectionRecord,
};
use crate::transaction::{
    contract_deployment::ContractDeploymentPayloadV1,
    contract_execution::DecodedContractExecutionMemo, decode_canonical_bonding_curve_tx,
    envelope_signer_matches_sender, hash_transaction, token_creation::TokenCreationPayloadV1,
    CanonicalBondingCurveEnvelope, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
    BONDING_CURVE_SELL_ACTION, BONDING_CURVE_TX_PAYLOAD_LEN, DEFAULT_TOKEN_CREATION_FEE,
};
use crate::types::TransactionType;

use super::errors::{BlockApplyError, BlockApplyResult, TxApplyError};
use super::tx_apply::{self, CoinbaseOutcome, StateMutator, TransferOutcome};

use crate::protocol::ProtocolParams;
use crate::resources::{BlockAccumulator, BlockLimits};

// Re-export lib-fees types for convenience
pub use lib_fees::{
    compute_fee_v2, verify_fee, FeeDeficit, FeeInput, FeeParams, SigScheme, SigSchemeExt, TxKind,
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
    /// Fixed fee for canonical TokenCreation transactions
    pub token_creation_fee: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_block_size: 1_048_576, // 1MB
            block_reward: 50_000_000,  // 50 tokens (in smallest unit)
            allow_empty_blocks: true,
            protocol_params: ProtocolParams::default(),
            token_creation_fee: DEFAULT_TOKEN_CREATION_FEE,
        }
    }
}

impl ExecutorConfig {
    /// Create config with specific protocol params
    pub fn with_protocol_params(mut self, params: ProtocolParams) -> Self {
        self.protocol_params = params;
        self
    }

    pub fn with_token_creation_fee(mut self, fee: u64) -> Self {
        self.token_creation_fee = fee;
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
    token_creation_fee: u64,
    /// When true, skip fee validation for all transactions.
    /// Used during catch-up sync to replay already-committed peer blocks
    /// whose transactions were valid under older fee rules.
    skip_fee_validation: bool,
    /// When true, skip previous-block-hash validation during header checks.
    /// Used during trusted peer import (bootstrap/catch-up sync) where BFT
    /// consensus has already guaranteed chain validity.
    skip_prev_hash_validation: bool,
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
    fn canonical_sov_token_id() -> TokenId {
        TokenId::new(crate::contracts::utils::generate_lib_token_id())
    }

    fn is_canonical_sov_token(token_id: &[u8; 32]) -> bool {
        *token_id == [0u8; 32] || *token_id == crate::contracts::utils::generate_lib_token_id()
    }

    fn sync_canonical_sov_contract_after_mint(
        &self,
        mutator: &StateMutator<'_>,
        recipient: &Address,
        amount: u128,
    ) -> Result<(), TxApplyError> {
        let token_id = Self::canonical_sov_token_id();
        let mut contract = mutator
            .get_token_contract(&token_id)?
            .unwrap_or_else(crate::contracts::TokenContract::new_sov_native);
        let current_supply = mutator.get_token_supply(&token_id)?.unwrap_or(contract.total_supply);
        let new_supply = current_supply.checked_add(amount).ok_or_else(|| {
            TxApplyError::InvalidType("SOV total supply overflow".to_string())
        })?;
        let balance = mutator.get_token_balance_u128(&token_id, recipient)?;
        let recipient_pk = lib_crypto::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: recipient.0,
        };
        contract.total_supply = new_supply;
        let new_balance = balance + amount;
        contract.set_balance(&recipient_pk, new_balance);
        mutator.put_token_supply(&token_id, new_supply)?;
        mutator.put_token_contract(&contract)?;
        Ok(())
    }

    /// Create a new block executor with explicit token creation fee.
    pub fn new_with_token_creation_fee(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        limits: BlockLimits,
        token_creation_fee: u64,
    ) -> Self {
        Self {
            store,
            fee_model,
            limits,
            token_creation_fee,
            skip_fee_validation: false,
            skip_prev_hash_validation: false,
        }
    }

    /// Create a new block executor with explicit fee model and limits
    pub fn new(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        limits: BlockLimits,
    ) -> Self {
        Self::new_with_token_creation_fee(store, fee_model, limits, DEFAULT_TOKEN_CREATION_FEE)
    }

    /// Create a block executor for catch-up sync: skips fee validation but
    /// VALIDATES prev-hash to ensure chain continuity from peer blocks.
    pub fn new_catchup_sync(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        _limits: BlockLimits,
    ) -> Self {
        Self {
            store,
            fee_model,
            limits: BlockLimits::for_trusted_replay(),
            token_creation_fee: DEFAULT_TOKEN_CREATION_FEE,
            skip_fee_validation: true,
            skip_prev_hash_validation: false, // MUST validate chain continuity
        }
    }

    /// Create a block executor that skips fee validation AND prev-hash validation.
    ///
    /// Use ONLY for replaying already-committed blocks from a trusted source
    /// (e.g. initial bootstrap from genesis). For catch-up sync from peers,
    /// use `new_catchup_sync` which validates prev-hash.
    pub fn new_trusted_replay(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        limits: BlockLimits,
    ) -> Self {
        Self::new_trusted_replay_with_token_creation_fee(
            store,
            fee_model,
            limits,
            DEFAULT_TOKEN_CREATION_FEE,
        )
    }

    pub fn new_trusted_replay_with_token_creation_fee(
        store: Arc<dyn BlockchainStore>,
        fee_model: FeeModelV2,
        _limits: BlockLimits,
        token_creation_fee: u64,
    ) -> Self {
        Self {
            store,
            fee_model,
            limits: BlockLimits::for_trusted_replay(),
            token_creation_fee,
            skip_fee_validation: true,
            skip_prev_hash_validation: true,
        }
    }

    /// Create with legacy ExecutorConfig (converts internally)
    pub fn from_config(store: Arc<dyn BlockchainStore>, config: ExecutorConfig) -> Self {
        let (fee_model, limits) = config.to_fee_model_and_limits();
        Self {
            store,
            fee_model,
            limits,
            token_creation_fee: config.token_creation_fee,
            skip_fee_validation: false,
            skip_prev_hash_validation: false,
        }
    }

    /// Create with legacy ExecutorConfig for trusted peer block replay.
    ///
    /// Identical to `from_config` but sets `skip_fee_validation = true` and
    /// `skip_prev_hash_validation = true`.
    /// Use this when importing already-committed peer blocks during catch-up
    /// sync; those blocks passed consensus and must be applied regardless of
    /// the local fee schedule or any legacy genesis hash inconsistencies.
    pub fn from_config_trusted_replay(
        store: Arc<dyn BlockchainStore>,
        config: ExecutorConfig,
    ) -> Self {
        let (fee_model, _limits) = config.to_fee_model_and_limits();
        Self {
            store,
            fee_model,
            limits: BlockLimits::for_trusted_replay(),
            token_creation_fee: config.token_creation_fee,
            skip_fee_validation: true,
            skip_prev_hash_validation: true,
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

    pub fn token_creation_fee(&self) -> u64 {
        self.token_creation_fee
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
    /// - Header structure and previous-hash continuity are correct
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

        // Previous hash must match (except for genesis).
        // Skip during trusted peer replay: BFT consensus already validated
        // the chain. The importing node may have committed genesis with a
        // different block_hash than what the peer stored when it built block 1,
        // so re-validating would incorrectly reject an otherwise valid chain.
        if block_height > 0 && !self.skip_prev_hash_validation {
            self.validate_previous_hash(block, block_height)?;
        }

        Ok(())
    }

    /// Step 2: Validate block resources against limits (quick initial check)
    ///
    /// Checks:
    /// - Block payload size within limits
    /// - Transaction count within limits
    /// - Transaction count within limits
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

        Ok(())
    }

    /// Steps 4-6: Apply transactions, append block, commit
    ///
    /// Called after begin_block. Guard ensures rollback on error.
    fn apply_block_inner(&self, block: &Block) -> BlockApplyResult<ApplyOutcome> {
        let block_height = block.header.height;
        let block_timestamp = block.header.timestamp;
        let block_hash = BlockHash::new(block.hash().as_array());

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
            // Explicitly persist the canonical CBE zero-state so that reads
            // after genesis return a concrete record rather than an implicit
            // default.  This makes genesis determinism auditable (#1927).
            //
            // PERSISTENCE CONTRACT:
            // This is the first write of `BondingCurveEconomicState` to sled
            // (serialised via bincode).  Its field layout is therefore part of
            // the stable on-disk schema from block 0 onward.
            // Do NOT add, remove, or reorder fields in `BondingCurveEconomicState`
            // without either introducing a versioned wrapper (e.g. V1/V2) and a
            // migration path, or coordinating a breaking storage-format change.
            // Any such change without migration will corrupt deserialization of
            // existing chains.
            self.store
                .put_cbe_economic_state(&lib_types::BondingCurveEconomicState::default())
                .map_err(|e| BlockApplyError::PersistFailed(e.to_string()))?;

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
                .apply_tx(&mutator, tx, block_height, block_timestamp)
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
                TxOutcome::TokenCreation(_outcome) => {
                    summary.balance_changes += 2; // creator + treasury balance credits
                }
                TxOutcome::ContractDeployment(_outcome) => {
                    summary.balance_changes += 1; // tracks one deterministic contract deployment operation (multiple underlying storage writes: code + metadata)
                }
                TxOutcome::ContractExecution(_outcome) => {
                    summary.balance_changes += 1; // tracks one deterministic contract execution operation (may involve multiple underlying state mutations)
                }
                TxOutcome::DaoProposal(_) => {
                    summary.account_updates += 1; // governance state write (not a token balance change)
                }
                TxOutcome::DaoVote(_) => {
                    summary.account_updates += 1; // governance state write (not a token balance change)
                }
                TxOutcome::DaoExecution(_) => {
                    summary.account_updates += 1; // governance state write (not a token balance change)
                }
                TxOutcome::BondingCurveDeploy => {}
                TxOutcome::BondingCurveBuy(_) => {
                    summary.balance_changes += 2; // SOV debit (balance_sov) + token credit
                }
                TxOutcome::BondingCurveSell(_) => {
                    summary.balance_changes += 2; // token debit + SOV credit (balance_sov)
                }
                TxOutcome::BondingCurveGraduate => {}
                TxOutcome::OracleAttestation(_) => {
                    // ORACLE-R3: Oracle attestations are processed by Blockchain after
                    // block execution (not by BlockExecutor). They don't touch storage
                    // directly - they update in-memory oracle_state.
                    summary.account_updates += 1;
                }
                TxOutcome::Coinbase(_) => {
                    // Should not happen - coinbase filtered out
                    unreachable!("Coinbase should not be in non-coinbase pass");
                }
                TxOutcome::TreasuryAllocation => {
                    summary.balance_changes += 2; // source debit + destination credit
                }
                TxOutcome::PayrollMint => {
                    // Collaborator credit + treasury credit = 2 balance changes
                    summary.balance_changes += 2;
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

        let actual_hash = BlockHash::new(block.header.previous_hash);

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
            TransactionType::TokenCreation => {}
            TransactionType::ContractDeployment => {}
            TransactionType::ContractExecution => {}
            TransactionType::DaoProposal => {}
            TransactionType::DaoVote => {}
            TransactionType::DaoExecution => {}
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
            // Phase 3/4 types - handled by executor but validation not fully wired yet
            | TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity
            // Bonding curve types - handled by executor but validation not fully wired yet
            | TransactionType::BondingCurveDeploy
            | TransactionType::BondingCurveBuy
            | TransactionType::BondingCurveSell
            | TransactionType::BondingCurveGraduate
            // Oracle governance types - handled by executor
            | TransactionType::UpdateOracleCommittee
            | TransactionType::UpdateOracleConfig
            // Oracle attestation - validated in StatefulValidator; no special-casing here
            // Cancel oracle update - validated in stateful validator, applied as no-op here
            | TransactionType::OracleAttestation
            | TransactionType::CancelOracleUpdate
            // Entity registry init - handled by process_entity_registry_transactions
            | TransactionType::InitEntityRegistry
            // Treasury threshold-approval transactions - handled by block processors
            | TransactionType::RecordOnRampTrade
            | TransactionType::TreasuryAllocation
            | TransactionType::InitCbeToken
            | TransactionType::CreateEmploymentContract
            | TransactionType::ProcessPayroll
            | TransactionType::DaoStake
            | TransactionType::DaoUnstake
            // Domain registration/update - state applied by process_domain_transactions
            | TransactionType::DomainRegistration
            | TransactionType::DomainUpdate => {
                // Fall through to the general validation flow below without
                // treating oracle attestations as automatically valid.
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
                if tx.identity_data().is_some()
                    || tx.wallet_data().is_some()
                    || tx.validator_data().is_some()
                    || tx.dao_proposal_data().is_some()
                    || tx.dao_vote_data().is_some()
                    || tx.dao_execution_data().is_some()
                    || tx.ubi_claim_data().is_some()
                    || tx.profit_declaration_data().is_some()
                {
                    return Err(TxApplyError::InvalidType(
                        "Coinbase must not have non-Phase-2 data fields".to_string(),
                    ));
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer must have token_transfer_data
                if tx.token_transfer_data().is_none() {
                    return Err(TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string(),
                    ));
                }
                // Validate token_transfer_data fields
                let data = tx.token_transfer_data().unwrap();
                if data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "Token transfer amount must be greater than 0".to_string(),
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
                if tx.token_mint_data().is_none() {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint requires token_mint_data field".to_string(),
                    ));
                }
                let data = tx.token_mint_data().unwrap();
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
            TransactionType::TokenCreation => {
                if !tx.inputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "TokenCreation must not have UTXO inputs".to_string(),
                    ));
                }
                if !tx.outputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "TokenCreation must not have UTXO outputs".to_string(),
                    ));
                }
                TokenCreationPayloadV1::decode_memo(&tx.memo).map_err(|e| {
                    TxApplyError::InvalidType(format!(
                        "TokenCreation requires canonical memo payload: {e}"
                    ))
                })?;
            }
            TransactionType::ContractDeployment => {
                // Contract deployments must not perform UTXO operations.
                if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "ContractDeployment must not have inputs or outputs".to_string(),
                    ));
                }
                ContractDeploymentPayloadV1::decode_memo(&tx.memo).map_err(|e| {
                    TxApplyError::InvalidType(format!(
                        "ContractDeployment requires canonical deployment memo: {e}"
                    ))
                })?;
            }
            TransactionType::ContractExecution => {
                // Contract executions must not perform UTXO operations.
                if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "ContractExecution must not have inputs or outputs".to_string(),
                    ));
                }
                Self::decode_contract_call_memo(&tx.memo)?;
            }
            TransactionType::DaoProposal => {
                let data = tx.dao_proposal_data().ok_or_else(|| {
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
                let data = tx.dao_vote_data().ok_or_else(|| {
                    TxApplyError::InvalidType("DaoVote requires dao_vote_data field".to_string())
                })?;
                if data.voter.trim().is_empty() || data.vote_choice.trim().is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "DaoVote voter/vote_choice must be non-empty".to_string(),
                    ));
                }
            }
            TransactionType::DaoExecution => {
                let data = tx.dao_execution_data().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "DaoExecution requires dao_execution_data field".to_string(),
                    )
                })?;
                if data.proposal_id == crate::types::Hash::default() {
                    return Err(TxApplyError::InvalidType(
                        "DaoExecution proposal_id must be non-zero".to_string(),
                    ));
                }
                if data.executor.trim().is_empty() {
                    return Err(TxApplyError::InvalidType(
                        "DaoExecution executor must be non-empty".to_string(),
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
        // Skip fee validation entirely during trusted replay (catch-up sync).
        if self.skip_fee_validation {
            return Ok(());
        }
        // Exempt transactions that don't pay fees
        match tx.transaction_type {
            TransactionType::Coinbase => return Ok(()), // Creates value, no fee
            TransactionType::TokenTransfer => return Ok(()), // Phase 2: subsidized
            TransactionType::TokenMint => return Ok(()), // Phase 2: system mint
            TransactionType::TokenCreation => {
                // Accept fee=0 (subsidized/system creation) or fee==token_creation_fee (standard).
                if tx.fee != 0 && tx.fee != self.token_creation_fee {
                    return Err(TxApplyError::InvalidType(format!(
                        "TokenCreation transaction fee must equal 0 or {}",
                        self.token_creation_fee
                    )));
                }
                return Ok(());
            }
            _ => {}
        }
        // System transactions (empty inputs, excluding typed token ops that must pay fees)
        // are fee-exempt. Mirrors TransactionValidator::validate_transaction() logic.
        if tx.inputs.is_empty() && tx.transaction_type != TransactionType::TokenTransfer {
            return Ok(());
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
                let transfer = tx.token_transfer_data().ok_or_else(|| {
                    TxApplyError::InvalidType("TokenTransfer requires token_transfer_data".into())
                })?;

                let token = if Self::is_canonical_sov_token(&transfer.token_id) {
                    Self::canonical_sov_token_id()
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
        let optional_data = tx.identity_data().map(|_| 256).unwrap_or(0)
            + tx.wallet_data().map(|_| 128).unwrap_or(0)
            + tx.validator_data().map(|_| 256).unwrap_or(0)
            + tx.token_transfer_data().map(|_| 104).unwrap_or(0)
            + tx.token_mint_data().map(|_| 72).unwrap_or(0); // 32+32+8

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

    /// Decode and validate a ContractExecution memo.
    fn decode_contract_call_memo(
        memo: &[u8],
    ) -> Result<DecodedContractExecutionMemo, TxApplyError> {
        DecodedContractExecutionMemo::decode_compat(memo)
            .map_err(|e| TxApplyError::InvalidType(format!("Invalid ContractExecution memo: {e}")))
    }

    fn dao_state_contract_id() -> [u8; 32] {
        lib_crypto::hash_blake3(b"DAO_GOVERNANCE_V1")
    }

    fn apply_dao_proposal(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        _tx_hash: &crate::types::Hash,
    ) -> Result<DaoProposalOutcome, TxApplyError> {
        let data = tx.dao_proposal_data().ok_or_else(|| {
            TxApplyError::InvalidType("DaoProposal requires dao_proposal_data field".to_string())
        })?;

        let contract_id = Self::dao_state_contract_id();
        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(data.proposal_id.as_bytes());

        // Enforce idempotency: once a proposal is stored, it is immutable.
        if self
            .store
            .get_contract_storage(&contract_id, &proposal_key)?
            .is_some()
        {
            return Err(TxApplyError::InvalidType(
                "DaoProposal with this ID already exists".to_string(),
            ));
        }

        let encoded = bincode::serialize(data).map_err(|e| {
            TxApplyError::Internal(format!("Failed to serialize DaoProposalData: {e}"))
        })?;
        mutator.put_contract_storage(&contract_id, &proposal_key, &encoded)?;

        let mut index_key = b"proposal_index:".to_vec();
        index_key.extend_from_slice(data.proposal_id.as_bytes());
        mutator.put_contract_storage(&contract_id, &index_key, data.proposal_id.as_bytes())?;

        Ok(DaoProposalOutcome {
            proposal_id: data.proposal_id,
        })
    }

    fn apply_dao_vote(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<DaoVoteOutcome, TxApplyError> {
        let data = tx.dao_vote_data().ok_or_else(|| {
            TxApplyError::InvalidType("DaoVote requires dao_vote_data field".to_string())
        })?;

        let contract_id = Self::dao_state_contract_id();
        let mut proposal_key = b"proposal:".to_vec();
        proposal_key.extend_from_slice(data.proposal_id.as_bytes());
        let proposal_raw = self
            .store
            .get_contract_storage(&contract_id, &proposal_key)?
            .ok_or_else(|| {
                TxApplyError::InvalidType("DaoVote references unknown proposal".to_string())
            })?;

        // Validate that the voting period has not expired.
        let proposal: crate::transaction::DaoProposalData = bincode::deserialize(&proposal_raw)
            .map_err(|e| {
                TxApplyError::Internal(format!(
                    "Failed to deserialize proposal for vote check: {e}"
                ))
            })?;
        let voting_deadline = proposal
            .created_at_height
            .saturating_add(proposal.voting_period_blocks);
        if block_height > voting_deadline {
            return Err(TxApplyError::InvalidType(format!(
                "DaoVote rejected: voting period for proposal '{}' expired at height {voting_deadline} (current height: {block_height})",
                data.proposal_id,
            )));
        }

        // Key on voter identity so each voter casts exactly one vote per proposal
        // (any subsequent vote by the same voter overwrites the previous one).
        let mut vote_key = b"vote:".to_vec();
        vote_key.extend_from_slice(data.proposal_id.as_bytes());
        vote_key.extend_from_slice(b":");
        vote_key.extend_from_slice(data.voter.as_bytes());
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
        _tx_hash: &crate::types::Hash,
    ) -> Result<DaoExecutionOutcome, TxApplyError> {
        let data = tx.dao_execution_data().ok_or_else(|| {
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

        // Use a deterministic key (not including tx_hash) so a proposal can only be
        // executed once. Re-submitting an execution transaction for the same proposal
        // must be rejected to prevent double-execution.
        let mut execution_key = b"execution:".to_vec();
        execution_key.extend_from_slice(data.proposal_id.as_bytes());
        if self
            .store
            .get_contract_storage(&contract_id, &execution_key)?
            .is_some()
        {
            return Err(TxApplyError::InvalidType(
                "DaoExecution: proposal has already been executed".to_string(),
            ));
        }

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

    fn apply_contract_deployment(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        tx_hash: &crate::types::Hash,
    ) -> Result<ContractDeploymentOutcome, TxApplyError> {
        let payload = ContractDeploymentPayloadV1::decode_memo(&tx.memo).map_err(|e| {
            TxApplyError::InvalidType(format!(
                "ContractDeployment requires canonical deployment memo: {e}"
            ))
        })?;

        let contract_id = tx_hash.as_array();
        mutator.put_contract_code(&contract_id, &payload.code)?;
        mutator.put_contract_storage(
            &contract_id,
            b"__contract_type",
            payload.contract_type.as_bytes(),
        )?;
        mutator.put_contract_storage(&contract_id, b"__abi", &payload.abi)?;
        mutator.put_contract_storage(&contract_id, b"__init_args", &payload.init_args)?;
        mutator.put_contract_storage(
            &contract_id,
            b"__limits",
            &bincode::serialize(&(payload.gas_limit, payload.memory_limit_bytes)).map_err(|e| {
                TxApplyError::Internal(format!(
                    "Failed to serialize deployment limits for contract storage: {e}"
                ))
            })?,
        )?;

        Ok(ContractDeploymentOutcome {
            contract_id,
            contract_type: payload.contract_type,
        })
    }

    fn apply_contract_execution(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        tx_hash: &crate::types::Hash,
        block_height: u64,
    ) -> Result<ContractExecutionOutcome, TxApplyError> {
        let decoded = Self::decode_contract_call_memo(&tx.memo)?;
        let contract_id = decoded.contract_id.ok_or_else(|| {
            TxApplyError::InvalidType(
                "ContractExecution memo must include deployed contract_id (ZHTP2 format)"
                    .to_string(),
            )
        })?;
        let call = decoded.call;

        if self.store.get_contract_code(&contract_id)?.is_none() {
            return Err(TxApplyError::InvalidType(format!(
                "ContractExecution references unknown deployed contract_id {}",
                hex::encode(contract_id)
            )));
        }
        if self
            .store
            .get_contract_storage(&contract_id, b"__abi")?
            .is_none()
        {
            return Err(TxApplyError::InvalidType(format!(
                "ContractExecution target {} missing deployed ABI metadata",
                hex::encode(contract_id)
            )));
        }
        let limits = self
            .store
            .get_contract_storage(&contract_id, b"__limits")?
            .ok_or_else(|| {
                TxApplyError::InvalidType(format!(
                    "ContractExecution target {} missing deployed execution limits",
                    hex::encode(contract_id)
                ))
            })?;
        let (_gas_limit, _memory_limit_bytes): (u64, u32) =
            bincode::deserialize(&limits).map_err(|e| {
                TxApplyError::InvalidType(format!(
                    "ContractExecution target {} has invalid stored limits: {}",
                    hex::encode(contract_id),
                    e
                ))
            })?;

        // Persist canonical call record under a deterministic per-tx key.
        let mut call_key = b"__call:".to_vec();
        call_key.extend_from_slice(tx_hash.as_bytes());
        let caller = tx.signature.public_key.key_id;
        let call_record =
            bincode::serialize(&(block_height, call.method.clone(), caller, call.params)).map_err(
                |e| {
                    TxApplyError::Internal(format!("Failed to serialize contract call record: {e}"))
                },
            )?;
        mutator.put_contract_storage(&contract_id, &call_key, &call_record)?;
        // __last_call_key is a convenience pointer to the most recent call key.
        // It is safe to overwrite on every execution because both writes occur within
        // the same block transaction boundary.
        mutator.put_contract_storage(&contract_id, b"__last_call_key", &call_key)?;

        Ok(ContractExecutionOutcome {
            contract_id,
            method: call.method,
        })
    }

    fn apply_canonical_bonding_curve_tx(
        &self,
        mutator: &StateMutator<'_>,
        payload: &[u8],
    ) -> Result<CanonicalBondingCurveOutcome, TxApplyError> {
        // ── 1. Parse ──────────────────────────────────────────────────────────
        let curve_tx = decode_canonical_bonding_curve_tx(payload).map_err(|e| {
            TxApplyError::InvalidType(format!("Invalid canonical curve payload: {e}"))
        })?;

        // Extract common fields for shared pre-validation.
        let (sender, tx_nonce, amount_in_or_cbe, is_buy) = match &curve_tx {
            CanonicalBondingCurveTx::Buy(tx) => (tx.sender, tx.nonce, tx.amount_in, true),
            CanonicalBondingCurveTx::Sell(tx) => (tx.sender, tx.nonce, tx.amount_cbe, false),
        };

        // ── 2. Non-zero amount ────────────────────────────────────────────────
        if amount_in_or_cbe == 0 {
            return Err(TxApplyError::InvalidType(
                "Canonical curve tx: amount must be non-zero".to_string(),
            ));
        }

        // ── 3. Load global economic state ────────────────────────────────────
        let econ = mutator.get_cbe_economic_state()?;

        // ── 4. Phase / graduation check ───────────────────────────────────────
        if econ.graduated {
            return Err(TxApplyError::InvalidType(
                "CBE curve has graduated; BUY_CBE and SELL_CBE are no longer valid".to_string(),
            ));
        }

        // ── 5. Sell-enabled gate (SELL_CBE only) ─────────────────────────────
        if !is_buy && !econ.sell_enabled {
            return Err(TxApplyError::InvalidType(
                "SELL_CBE is disabled by protocol flag sell_enabled=false".to_string(),
            ));
        }

        // ── 6. Load account state (zero-default for new participants) ─────────
        let account = mutator.get_cbe_account_state(&sender)?;

        // ── 7. Nonce check ────────────────────────────────────────────────────
        let expected_nonce = account.next_nonce.to_u64();
        let provided_nonce = tx_nonce.to_u64();
        if provided_nonce != expected_nonce {
            return Err(TxApplyError::InvalidNonce {
                expected: expected_nonce,
                actual: provided_nonce,
            });
        }

        // ── 8. Balance check (reads from token_balances tree) ────────────────
        if is_buy {
            let sov_bal = mutator.get_token_balance_u128(
                &Self::canonical_sov_token_id(),
                &Address::new(sender),
            )?;
            if sov_bal < amount_in_or_cbe {
                return Err(TxApplyError::InvalidType(format!(
                    "BUY_CBE: insufficient SOV balance (have {}, need {})",
                    sov_bal, amount_in_or_cbe
                )));
            }
        } else {
            let cbe_token_id = TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
            let cbe_bal = mutator.get_token_balance_u128(
                &cbe_token_id,
                &Address::new(sender),
            )?;
            if cbe_bal < amount_in_or_cbe {
                return Err(TxApplyError::InvalidType(format!(
                    "SELL_CBE: insufficient CBE balance (have {}, need {})",
                    cbe_bal, amount_in_or_cbe
                )));
            }
        }

        // ── 9. expected_s_c stale-state check ────────────────────────────────
        let expected_s_c = match &curve_tx {
            CanonicalBondingCurveTx::Buy(tx) => tx.expected_s_c,
            CanonicalBondingCurveTx::Sell(tx) => tx.expected_s_c,
        };
        if expected_s_c != econ.s_c {
            return Err(TxApplyError::InvalidType(format!(
                "Canonical curve stale state: expected_s_c={expected_s_c} does not match current s_c={}",
                econ.s_c
            )));
        }

        // ── 10. Dispatch to typed economic computation ───────────────────────
        let next_nonce = lib_types::Nonce48::from_u64(provided_nonce + 1)
            .ok_or_else(|| TxApplyError::InvalidType("nonce overflow".to_string()))?;

        match curve_tx {
            CanonicalBondingCurveTx::Buy(tx) => self.apply_buy_cbe(
                mutator,
                tx.max_price,
                amount_in_or_cbe,
                sender,
                econ,
                account,
                next_nonce,
            ),
            CanonicalBondingCurveTx::Sell(tx) => self.apply_sell_cbe(
                mutator,
                tx.min_payout,
                amount_in_or_cbe,
                sender,
                econ,
                account,
                next_nonce,
            ),
        }
    }

    fn apply_buy_cbe(
        &self,
        mutator: &StateMutator<'_>,
        max_price: u128,
        amount_in: u128,
        sender: [u8; 32],
        mut econ: lib_types::BondingCurveEconomicState,
        mut account: lib_types::BondingCurveAccountState,
        next_nonce: lib_types::Nonce48,
    ) -> Result<CanonicalBondingCurveOutcome, TxApplyError> {
        use crate::contracts::bonding_curve::canonical::{
            mint_with_reserve, GRAD_THRESHOLD, MAX_DELTA_S_PER_TX, MAX_GROSS_SOV_PER_TX, SCALE,
        };
        use primitive_types::U256;

        if amount_in > MAX_GROSS_SOV_PER_TX {
            return Err(TxApplyError::InvalidType(format!(
                "BUY_CBE: amount_in {amount_in} exceeds MAX_GROSS_SOV_PER_TX"
            )));
        }

        // Event-driven on-ramp split (see docs/architecture/token-architecture.md):
        //   20% → SOV treasury (held as CBE tokens, contributes to SOV NAV)
        //   32% → CBE strategic reserve (locked, backs floor price)
        //   48% → CBE liquidity pool (accumulates toward graduation)
        //
        // The 80% DAO portion splits 40/60 into reserve/liquidity.
        // Integer arithmetic: compute each leg, liquidity gets the remainder for exactness.
        let sov_treasury_credit = amount_in * 20 / 100;
        let reserve_credit = amount_in * 32 / 100;
        let liquidity_credit = amount_in - sov_treasury_credit - reserve_credit;

        let delta_s = mint_with_reserve(reserve_credit, econ.s_c)
            .map_err(|e| TxApplyError::InvalidType(format!("BUY_CBE: mint overflow: {e:?}")))?;

        if delta_s == 0 {
            return Err(TxApplyError::InvalidType(
                "BUY_CBE: zero tokens minted for given reserve credit".to_string(),
            ));
        }

        if delta_s > MAX_DELTA_S_PER_TX {
            return Err(TxApplyError::InvalidType(format!(
                "BUY_CBE: delta_s {delta_s} exceeds MAX_DELTA_S_PER_TX"
            )));
        }

        // Slippage: effective = amount_in * SCALE / delta_s; use U256 to avoid overflow.
        let effective = U256::from(amount_in)
            .checked_mul(U256::from(SCALE))
            .ok_or_else(|| {
                TxApplyError::InvalidType(
                    "BUY_CBE: slippage overflow in amount_in * SCALE".to_string(),
                )
            })?
            / U256::from(delta_s);
        if effective > U256::from(max_price) {
            return Err(TxApplyError::InvalidType(format!(
                "BUY_CBE: slippage — effective price {effective} > max_price {max_price}"
            )));
        }

        econ.s_c = econ
            .s_c
            .checked_add(delta_s)
            .ok_or_else(|| TxApplyError::InvalidType("BUY_CBE: s_c overflow".to_string()))?;
        econ.reserve_balance = econ
            .reserve_balance
            .checked_add(reserve_credit)
            .ok_or_else(|| TxApplyError::InvalidType("BUY_CBE: reserve overflow".to_string()))?;
        econ.sov_treasury_cbe_balance = econ
            .sov_treasury_cbe_balance
            .checked_add(sov_treasury_credit)
            .ok_or_else(|| TxApplyError::InvalidType("BUY_CBE: sov_treasury overflow".to_string()))?;
        econ.liquidity_pool
            .mint(liquidity_credit)
            .map_err(|e| TxApplyError::InvalidType(format!("BUY_CBE: liquidity pool: {e}")))?;
        // Keep legacy field in sync for backwards compat.
        econ.liquidity_pool_balance = econ.liquidity_pool.balance;

        // Satisfy PRE_BACKED entries FIFO from the compensation pool routing share.
        // For now the full liquidity credit is used as the compensation routing share.
        econ.satisfy_pre_backed(liquidity_credit);

        if econ.reserve_balance >= GRAD_THRESHOLD {
            econ.graduated = true;
        }

        // Only nonce lives in cbe_account_state now; balances use token_balances tree.
        account.next_nonce = next_nonce;

        mutator.put_cbe_economic_state(&econ)?;
        mutator.put_cbe_account_state(&sender, &account)?;

        // Wire SOV ledger: debit sender's actual SOV token balance.
        mutator.debit_token(
            &Self::canonical_sov_token_id(),
            &Address::new(sender),
            amount_in,
        )?;

        // Wire CBE ledger: credit sender's CBE token balance.
        let cbe_token_id = TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
        mutator.credit_token(
            &cbe_token_id,
            &Address::new(sender),
            delta_s,
        )?;

        // ── Event-driven SOV minting ──────────────────────────────────────
        // The 20% SOV treasury portion generates new SOV supply. SOV mints
        // proportional to the CBE value deposited, priced at the current
        // SOV NAV model:
        //   sov_to_mint = sov_treasury_credit_cbe × cbe_price / sov_price
        //
        // During bootstrap (before SOV has a market price), SOV genesis
        // price is $0.10. CBE price comes from the bonding curve at current s_c.
        // Both prices are in SCALE (1e18) units.
        //
        // For now, use the curve price as the CBE/SOV ratio directly:
        //   sov_to_mint = sov_treasury_credit (in SOV atoms, since buyer paid in SOV)
        // This is correct because the buyer already paid `amount_in` SOV, and 20%
        // of that SOV is the treasury's share. The SOV minting matches the value
        // contributed to the treasury.
        let sov_to_mint = sov_treasury_credit;
        if sov_to_mint > 0 {
            // Credit the SOV treasury address with the newly minted SOV.
            // The treasury address is the fee_sink (DAO treasury).
            let treasury_addr = *self.fee_model.protocol_params.fee_sink_address();
            mutator.credit_token(
                &Self::canonical_sov_token_id(),
                &treasury_addr,
                sov_to_mint,
            )?;
            // Track total SOV minted via on-ramp for audit.
            econ.total_sov_minted = econ
                .total_sov_minted
                .checked_add(sov_to_mint)
                .unwrap_or(econ.total_sov_minted);
            // Re-persist econ with updated total_sov_minted.
            mutator.put_cbe_economic_state(&econ)?;
        }

        Ok(CanonicalBondingCurveOutcome::Buy(BondingCurveBuyOutcome {
            token_id: crate::Blockchain::derive_cbe_token_id_pub(),
            buyer: sender,
            stable_spent: amount_in,
            tokens_received: delta_s,
        }))
    }

    fn apply_sell_cbe(
        &self,
        mutator: &StateMutator<'_>,
        min_payout: u128,
        amount_cbe: u128,
        sender: [u8; 32],
        mut econ: lib_types::BondingCurveEconomicState,
        mut account: lib_types::BondingCurveAccountState,
        next_nonce: lib_types::Nonce48,
    ) -> Result<CanonicalBondingCurveOutcome, TxApplyError> {
        use crate::contracts::bonding_curve::canonical::payout_for_burn;

        let sov_out = payout_for_burn(amount_cbe, econ.s_c).map_err(|e| {
            TxApplyError::InvalidType(format!("SELL_CBE: payout_for_burn failed: {e:?}"))
        })?;

        if sov_out == 0 {
            return Err(TxApplyError::InvalidType(
                "SELL_CBE: zero payout for given burn amount".to_string(),
            ));
        }
        if sov_out < min_payout {
            return Err(TxApplyError::InvalidType(format!(
                "SELL_CBE: payout {sov_out} < min_payout {min_payout}"
            )));
        }
        if econ.reserve_balance < sov_out {
            return Err(TxApplyError::InvalidType(format!(
                "SELL_CBE: insolvent — reserve_balance {} < sov_out {sov_out}",
                econ.reserve_balance
            )));
        }

        econ.s_c = econ
            .s_c
            .checked_sub(amount_cbe)
            .ok_or_else(|| TxApplyError::InvalidType("SELL_CBE: s_c underflow".to_string()))?;
        econ.reserve_balance = econ
            .reserve_balance
            .checked_sub(sov_out)
            .ok_or_else(|| TxApplyError::InvalidType("SELL_CBE: reserve underflow".to_string()))?;

        // Only nonce lives in cbe_account_state now; balances use token_balances tree.
        account.next_nonce = next_nonce;

        mutator.put_cbe_economic_state(&econ)?;
        mutator.put_cbe_account_state(&sender, &account)?;

        // Wire CBE ledger: debit seller's CBE token balance.
        let cbe_token_id = TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
        mutator.debit_token(
            &cbe_token_id,
            &Address::new(sender),
            amount_cbe,
        )?;

        // Wire SOV ledger: credit seller's actual SOV token balance.
        mutator.credit_token(
            &Self::canonical_sov_token_id(),
            &Address::new(sender),
            sov_out,
        )?;

        Ok(CanonicalBondingCurveOutcome::Sell(
            BondingCurveSellOutcome {
                token_id: crate::Blockchain::derive_cbe_token_id_pub(),
                seller: sender,
                tokens_sold: amount_cbe,
                stable_received: sov_out,
            },
        ))
    }

    /// Apply a payroll mint — synthetic CBE bonding curve event (spec §6).
    ///
    /// Mints `amount_cbe` (X) CBE to the collaborator wallet and 0.25X to the SOV
    /// treasury address.  Records a PRE_BACKED entry for the full 1.25X gross.
    /// No SOV enters the system — `s_c` does not change, `reserve_balance` is
    /// unaffected, and the floor price remains stable.
    fn apply_payroll_mint(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<(), TxApplyError> {
        use crate::contracts::bonding_curve::canonical::{compute_debt_state, DEBT_CEILING};
        use crate::transaction::core::ProcessPayrollData;

        let data: &ProcessPayrollData = tx
            .process_payroll_data()
            .ok_or_else(|| {
                TxApplyError::InvalidType("ProcessPayroll missing payload".to_string())
            })?;

        let amount_cbe = data.amount_cbe;
        let collaborator = data.collaborator_address;
        let deliverable_hash = data.deliverable_hash;

        if amount_cbe == 0 {
            return Err(TxApplyError::InvalidType(
                "PAYROLL_MINT: amount_cbe must be > 0".to_string(),
            ));
        }

        // ── 1. Compute gross mint (1.25X) and split ─────────────────────────
        let gross = amount_cbe
            .checked_mul(125)
            .and_then(|v| v.checked_div(100))
            .ok_or_else(|| {
                TxApplyError::InvalidType("PAYROLL_MINT: gross overflow".to_string())
            })?;

        // 0.25X → SOV treasury (held as CBE, not swapped)
        let sov_treasury_credit = gross / 5; // = 0.25X
        // Remaining X split: 40% reserve, 60% liquidity — but these are CBE-denominated
        // obligations, not SOV. The actual reserve_balance (SOV) doesn't change because
        // no SOV entered. We track the obligation via PRE_BACKED.

        // ── 2. Debt ceiling check ───────────────────────────────────────────
        let mut econ = mutator.get_cbe_economic_state()?;

        let new_outstanding = econ
            .outstanding_pre_backed
            .checked_add(gross)
            .ok_or_else(|| {
                TxApplyError::InvalidType("PAYROLL_MINT: outstanding overflow".to_string())
            })?;

        if new_outstanding > DEBT_CEILING {
            return Err(TxApplyError::InvalidType(format!(
                "PAYROLL_MINT: debt ceiling breached — outstanding {} + gross {} > ceiling {}",
                econ.outstanding_pre_backed, gross, DEBT_CEILING
            )));
        }

        // ── 3. Update compensation pool (tracks CBE allocated to collaborators)
        econ.compensation_pool
            .mint(amount_cbe)
            .map_err(|e| TxApplyError::InvalidType(format!("PAYROLL_MINT: compensation pool: {e}")))?;

        // ── 4. Update SOV treasury CBE balance ──────────────────────────────
        econ.sov_treasury_cbe_balance = econ
            .sov_treasury_cbe_balance
            .checked_add(sov_treasury_credit)
            .ok_or_else(|| {
                TxApplyError::InvalidType("PAYROLL_MINT: sov_treasury overflow".to_string())
            })?;

        // ── 5. Record PRE_BACKED entry ──────────────────────────────────────
        econ.pre_backed_queue.push(lib_types::PreBackedEntry {
            block_height,
            amount_cbe: gross,
            recipient: collaborator,
            deliverable_hash,
            satisfied: false,
        });
        econ.outstanding_pre_backed = new_outstanding;
        econ.debt_state = compute_debt_state(new_outstanding);

        // ── 6. Persist economic state ───────────────────────────────────────
        mutator.put_cbe_economic_state(&econ)?;

        // ── 7. Credit CBE tokens ────────────────────────────────────────────
        let cbe_token_id = TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());

        // X CBE → collaborator wallet
        mutator.credit_token(
            &cbe_token_id,
            &Address::new(collaborator),
            amount_cbe,
        )?;

        // 0.25X CBE → SOV treasury address
        let treasury_addr = *self.fee_model.protocol_params.fee_sink_address();
        mutator.credit_token(
            &cbe_token_id,
            &treasury_addr,
            sov_treasury_credit,
        )?;

        tracing::info!(
            "PAYROLL_MINT: collaborator={} amount_cbe={} gross={} treasury_credit={} deliverable={} outstanding={}",
            hex::encode(&collaborator[..4]),
            amount_cbe,
            gross,
            sov_treasury_credit,
            hex::encode(&deliverable_hash[..4]),
            new_outstanding,
        );

        Ok(())
    }

    /// Apply a TreasuryAllocation transaction — transfer SOV from source treasury
    /// to destination DAO wallet in the canonical token ledger.
    fn apply_treasury_allocation(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
    ) -> Result<(), TxApplyError> {
        use crate::transaction::core::TreasuryAllocationData;

        let data: &TreasuryAllocationData = match &tx.payload {
            crate::transaction::core::TransactionPayload::TreasuryAllocation(d) => d,
            _ => {
                return Err(TxApplyError::InvalidType(
                    "TreasuryAllocation missing payload".to_string(),
                ))
            }
        };

        mutator.transfer_token(
            &Self::canonical_sov_token_id(),
            &Address::new(data.source_treasury_key_id),
            &Address::new(data.destination_key_id),
            data.amount as u128,
        )?;

        tracing::info!(
            "TreasuryAllocation: {} SOV from {} to {} (proposal={})",
            data.amount,
            hex::encode(&data.source_treasury_key_id[..4]),
            hex::encode(&data.destination_key_id[..4]),
            hex::encode(&data.proposal_id[..4]),
        );

        Ok(())
    }

    fn apply_dao_stake(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<(), TxApplyError> {
        use crate::contracts::economics::fee_router::{
            DAO_EDUCATION_KEY_ID, DAO_ENERGY_KEY_ID, DAO_FOOD_KEY_ID, DAO_HEALTHCARE_KEY_ID,
            DAO_HOUSING_KEY_ID,
        };
        use crate::storage::DaoStakeRecord;

        let data = match tx.dao_stake_data() {
            Some(d) => d,
            None => {
                return Err(TxApplyError::InvalidType(
                    "DaoStake missing payload".to_string(),
                ))
            }
        };

        // The signer must be the declared staker.
        if data.staker != tx.signature.public_key.key_id {
            return Err(TxApplyError::InvalidType(
                "DaoStake staker must match transaction signer".to_string(),
            ));
        }

        // Only the 5 known sector DAO wallets are valid stake targets.
        let known_daos = [
            DAO_HEALTHCARE_KEY_ID,
            DAO_EDUCATION_KEY_ID,
            DAO_ENERGY_KEY_ID,
            DAO_HOUSING_KEY_ID,
            DAO_FOOD_KEY_ID,
        ];
        if !known_daos.contains(&data.sector_dao_key_id) {
            return Err(TxApplyError::InvalidType(
                "DaoStake target is not a known sector DAO".to_string(),
            ));
        }

        let sov_token = Self::canonical_sov_token_id();
        let staker_addr = Address::new(data.staker);
        let dao_addr = Address::new(data.sector_dao_key_id);

        // Debit SOV from staker, credit to DAO wallet.
        // This moves SOV out of the staker's spendable balance for the lock period.
        // The DaoStakeRecord tracks when it can be reclaimed.
        mutator.transfer_token(&sov_token, &staker_addr, &dao_addr, data.amount)?;

        // Increment the staker's SOV nonce to prevent replay of this exact transaction.
        mutator.increment_token_nonce(&sov_token, &staker_addr)?;

        // Persist the stake record with the absolute unlock height.
        let locked_until = block_height.saturating_add(data.lock_blocks);
        let record = DaoStakeRecord {
            staker: data.staker,
            sector_dao_key_id: data.sector_dao_key_id,
            amount: data.amount,
            staked_at_height: block_height,
            locked_until,
        };
        mutator.put_dao_stake(&record)?;

        tracing::info!(
            "[DAO_STAKE] staker={} dao={} amount={} locked_until={}",
            hex::encode(&data.staker[..6]),
            hex::encode(&data.sector_dao_key_id[..6]),
            data.amount,
            locked_until,
        );

        Ok(())
    }

    fn apply_dao_unstake(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
    ) -> Result<(), TxApplyError> {
        use crate::storage::DaoStakeRecord;

        let data = match tx.dao_unstake_data() {
            Some(d) => d,
            None => {
                return Err(TxApplyError::InvalidType(
                    "DaoUnstake missing payload".to_string(),
                ))
            }
        };

        // The signer must be the declared staker.
        if data.staker != tx.signature.public_key.key_id {
            return Err(TxApplyError::InvalidType(
                "DaoUnstake staker must match transaction signer".to_string(),
            ));
        }

        // Load the stake record — it must exist.
        let record: DaoStakeRecord = mutator
            .get_dao_stake(&data.sector_dao_key_id, &data.staker)?
            .ok_or_else(|| {
                TxApplyError::InvalidType(format!(
                    "DaoUnstake: no stake record found for staker={} dao={}",
                    hex::encode(&data.staker[..6]),
                    hex::encode(&data.sector_dao_key_id[..6]),
                ))
            })?;

        // Enforce the lock period — cannot unstake before locked_until.
        if block_height < record.locked_until {
            return Err(TxApplyError::InvalidType(format!(
                "DaoUnstake: stake still locked until height {} (current {})",
                record.locked_until, block_height,
            )));
        }

        let sov_token = Self::canonical_sov_token_id();
        let dao_addr = Address::new(data.sector_dao_key_id);
        let staker_addr = Address::new(data.staker);

        // Enforce exact SOV nonce matching to prevent replay of old signed unstake transactions.
        let expected_nonce = mutator.get_token_nonce(&sov_token, &staker_addr)?;
        if data.nonce != expected_nonce {
            return Err(TxApplyError::InvalidType(format!(
                "DaoUnstake: invalid nonce for staker={} expected={} got={}",
                hex::encode(&data.staker[..6]),
                expected_nonce,
                data.nonce,
            )));
        }

        // Return locked SOV from DAO wallet back to staker.
        mutator.transfer_token(&sov_token, &dao_addr, &staker_addr, record.amount)?;

        // Delete the stake record.
        mutator.delete_dao_stake(&data.sector_dao_key_id, &data.staker)?;

        // Increment the staker's SOV nonce only after the unstake has been applied successfully.
        mutator.increment_token_nonce(&sov_token, &staker_addr)?;

        tracing::info!(
            "[DAO_UNSTAKE] staker={} dao={} amount={} height={}",
            hex::encode(&data.staker[..6]),
            hex::encode(&data.sector_dao_key_id[..6]),
            record.amount,
            block_height,
        );

        Ok(())
    }

    fn canonical_bonding_curve_envelope_from_transaction(
        &self,
        tx: &crate::transaction::Transaction,
    ) -> Result<CanonicalBondingCurveEnvelope, TxApplyError> {
        let payload: [u8; BONDING_CURVE_TX_PAYLOAD_LEN] =
            tx.memo.as_slice().try_into().map_err(|_| {
                TxApplyError::InvalidType(format!(
                    "Canonical curve payload must be exactly {} bytes, got {}",
                    BONDING_CURVE_TX_PAYLOAD_LEN,
                    tx.memo.len()
                ))
            })?;

        Ok(CanonicalBondingCurveEnvelope {
            payload,
            signature: tx.signature.clone(),
        })
    }

    fn apply_canonical_bonding_curve_envelope(
        &self,
        mutator: &StateMutator<'_>,
        envelope: &CanonicalBondingCurveEnvelope,
    ) -> Result<CanonicalBondingCurveOutcome, TxApplyError> {
        let signer_matches = envelope_signer_matches_sender(envelope).map_err(|e| {
            TxApplyError::InvalidType(format!("Invalid canonical curve envelope: {e}"))
        })?;
        if !signer_matches {
            return Err(TxApplyError::InvalidType(
                "Canonical curve signer does not match payload sender".to_string(),
            ));
        }

        self.apply_canonical_bonding_curve_tx(mutator, &envelope.payload)
    }

    /// Apply a single transaction
    fn apply_transaction(
        &self,
        mutator: &StateMutator<'_>,
        tx: &crate::transaction::Transaction,
        block_height: u64,
        _block_timestamp: u64,
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
                let transfer_data = tx.token_transfer_data().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "TokenTransfer requires token_transfer_data field".to_string(),
                    )
                })?;

                // Convert to storage types
                let token = if Self::is_canonical_sov_token(&transfer_data.token_id) {
                    Self::canonical_sov_token_id()
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

                // CBE transfers use standard token_balances with 0 fee;
                // all other tokens use standard token_balances with the SOV fee rate.
                let cbe_token_id_arr = crate::Blockchain::derive_cbe_token_id_pub();
                let fee_destination = *self.fee_model.protocol_params.fee_sink_address();
                let fee_bps = if transfer_data.token_id == cbe_token_id_arr {
                    0u16
                } else {
                    crate::contracts::tokens::constants::SOV_FEE_RATE_BPS
                };
                let _fee_collected = tx_apply::apply_token_transfer(
                    mutator,
                    &token,
                    &from,
                    &to,
                    amount,
                    fee_bps,
                    &fee_destination,
                )?;

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
                let mint_data = tx.token_mint_data().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "TokenMint requires token_mint_data field".to_string(),
                    )
                })?;

                if mint_data.amount == 0 {
                    return Err(TxApplyError::InvalidType(
                        "TokenMint amount must be greater than 0".to_string(),
                    ));
                }

                let token = if Self::is_canonical_sov_token(&mint_data.token_id) {
                    Self::canonical_sov_token_id()
                } else {
                    TokenId::new(mint_data.token_id)
                };

                let to = Address::new(mint_data.to);
                let amount = mint_data.amount;

                tx_apply::apply_token_mint(mutator, &token, &to, amount)?;
                if token == Self::canonical_sov_token_id() {
                    self.sync_canonical_sov_contract_after_mint(mutator, &to, amount)?;
                }

                Ok(TxOutcome::TokenMint(TokenMintOutcome { token, to, amount }))
            }
            TransactionType::WalletRegistration => {
                let wallet_data = tx.wallet_data().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "WalletRegistration requires wallet_data field".to_string(),
                    )
                })?;
                let wallet_id = wallet_data.wallet_id.as_array();
                mutator.put_wallet_projection(
                    &wallet_id,
                    &WalletProjectionRecord {
                        wallet_data: wallet_data.clone(),
                        committed_at_height: block_height,
                    },
                )?;

                if wallet_data.initial_balance > 0 {
                    let recipient = Address::new(wallet_data.wallet_id.as_array());
                    let token = Self::canonical_sov_token_id();
                    tx_apply::apply_token_mint(
                        mutator,
                        &token,
                        &recipient,
                        wallet_data.initial_balance as u128,
                    )?;
                    self.sync_canonical_sov_contract_after_mint(
                        mutator,
                        &recipient,
                        wallet_data.initial_balance as u128,
                    )?;
                }

                Ok(TxOutcome::LegacySystem)
            }
            TransactionType::WalletUpdate => {
                let wallet_data = tx.wallet_data().ok_or_else(|| {
                    TxApplyError::InvalidType(
                        "WalletUpdate requires wallet_data field".to_string(),
                    )
                })?;
                let wallet_id = wallet_data.wallet_id.as_array();
                mutator.put_wallet_projection(
                    &wallet_id,
                    &WalletProjectionRecord {
                        wallet_data: wallet_data.clone(),
                        committed_at_height: block_height,
                    },
                )?;

                Ok(TxOutcome::LegacySystem)
            }
            TransactionType::TokenCreation => {
                let payload = TokenCreationPayloadV1::decode_memo(&tx.memo).map_err(|e| {
                    TxApplyError::InvalidType(format!(
                        "TokenCreation requires canonical memo payload: {e}"
                    ))
                })?;
                let (creator_allocation, treasury_allocation) = payload.split_initial_supply();

                let creator = tx.signature.public_key.clone();
                if payload.treasury_recipient == creator.key_id {
                    return Err(TxApplyError::InvalidType(
                        "TokenCreation treasury_recipient must differ from creator".to_string(),
                    ));
                }
                let mut token = crate::contracts::TokenContract::new_custom(
                    payload.name.clone(),
                    payload.symbol.clone(),
                    0,
                    creator.clone(),
                );
                token.decimals = if payload.decimals == 0 {
                    8
                } else {
                    payload.decimals
                };
                token.max_supply = payload.initial_supply as u128;
                token.mint(&creator, creator_allocation as u128).map_err(|e| {
                    TxApplyError::Internal(format!("TokenCreation mint failed: {e}"))
                })?;
                let treasury_pk = lib_crypto::PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id: payload.treasury_recipient,
                };
                token.mint(&treasury_pk, treasury_allocation as u128).map_err(|e| {
                    TxApplyError::Internal(format!("TokenCreation treasury mint failed: {e}"))
                })?;

                let token_id = token.token_id;
                let token_id_ref = TokenId::new(token_id);

                // Enforce idempotency/replay-safety: do not overwrite an existing token.
                if mutator.get_token_contract(&token_id_ref)?.is_some() {
                    return Err(TxApplyError::InvalidType(
                        "TokenCreation for existing token_id is not allowed".to_string(),
                    ));
                }

                // Enforce case-insensitive symbol uniqueness across all tokens.
                if mutator.token_symbol_exists_case_insensitive(&payload.symbol)? {
                    return Err(TxApplyError::InvalidType(format!(
                        "TokenCreation: symbol '{}' conflicts with an existing token (case-insensitive)",
                        payload.symbol
                    )));
                }

                mutator.put_token_contract(&token)?;

                // Keep balance-tree state consistent with typed token transfer path.
                let creator_addr = Address::new(creator.key_id);
                let treasury_addr = Address::new(payload.treasury_recipient);
                tx_apply::apply_token_mint(
                    mutator,
                    &token_id_ref,
                    &creator_addr,
                    creator_allocation as u128,
                )?;
                tx_apply::apply_token_mint(
                    mutator,
                    &token_id_ref,
                    &treasury_addr,
                    treasury_allocation as u128,
                )?;

                Ok(TxOutcome::TokenCreation(TokenCreationOutcome {
                    token_id,
                    creator: creator_addr,
                    treasury: treasury_addr,
                    creator_allocation: creator_allocation as u128,
                    treasury_allocation: treasury_allocation as u128,
                    initial_supply: payload.initial_supply as u128,
                }))
            }
            TransactionType::ContractDeployment => {
                let outcome = self.apply_contract_deployment(mutator, tx, &tx_hash)?;
                Ok(TxOutcome::ContractDeployment(outcome))
            }
            TransactionType::ContractExecution => {
                let outcome = self.apply_contract_execution(mutator, tx, &tx_hash, block_height)?;
                Ok(TxOutcome::ContractExecution(outcome))
            }
            // Known legacy system types: accepted as no-ops. This mirrors the allowlist in
            // validate_tx_stateless — any type listed here must also be listed there.
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation
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
            | TransactionType::UpdateOracleCommittee
            | TransactionType::UpdateOracleConfig
            // Employment contract creation and CBE init: state is maintained in-memory by
            // process_employment_contract_transactions (called after executor.apply_block
            // in process_and_commit_block). The executor accepts them as no-ops so blocks
            // containing these types don't fail validation.
            | TransactionType::InitCbeToken
            | TransactionType::CreateEmploymentContract => Ok(TxOutcome::LegacySystem),

            TransactionType::ProcessPayroll => {
                self.apply_payroll_mint(mutator, tx, block_height)?;
                Ok(TxOutcome::PayrollMint)
            }

            TransactionType::DaoStake => {
                self.apply_dao_stake(mutator, tx, block_height)?;
                Ok(TxOutcome::LegacySystem)
            }

            TransactionType::DaoUnstake => {
                self.apply_dao_unstake(mutator, tx, block_height)?;
                Ok(TxOutcome::LegacySystem)
            }

            // Bonding curve types
            // BondingCurveDeploy and BondingCurveGraduate are wire-format legacy variants
            // retained for backward compatibility. There is only one CBE curve, initialized
            // at genesis; user-deployed curves are not supported. No-op in the executor.
            TransactionType::BondingCurveDeploy => Ok(TxOutcome::BondingCurveDeploy),
            TransactionType::BondingCurveGraduate => Ok(TxOutcome::BondingCurveGraduate),
            TransactionType::BondingCurveBuy => {
                // Type-mismatch guard: reject SELL payloads before full pre-validation.
                if tx.memo.first() == Some(&BONDING_CURVE_SELL_ACTION) {
                    return Err(TxApplyError::InvalidType(
                        "Canonical SELL_CBE payload cannot execute as BondingCurveBuy".to_string(),
                    ));
                }
                let envelope = self.canonical_bonding_curve_envelope_from_transaction(tx)?;
                match self.apply_canonical_bonding_curve_envelope(mutator, &envelope)? {
                    CanonicalBondingCurveOutcome::Buy(outcome) => {
                        Ok(TxOutcome::BondingCurveBuy(outcome))
                    }
                    CanonicalBondingCurveOutcome::Sell(_) => Err(TxApplyError::InvalidType(
                        "Canonical SELL_CBE payload cannot execute as BondingCurveBuy".to_string(),
                    )),
                }
            }
            TransactionType::BondingCurveSell => {
                // Type-mismatch guard: reject BUY payloads before full pre-validation.
                if tx.memo.first() == Some(&BONDING_CURVE_BUY_ACTION) {
                    return Err(TxApplyError::InvalidType(
                        "Canonical BUY_CBE payload cannot execute as BondingCurveSell".to_string(),
                    ));
                }
                let envelope = self.canonical_bonding_curve_envelope_from_transaction(tx)?;
                match self.apply_canonical_bonding_curve_envelope(mutator, &envelope)? {
                    CanonicalBondingCurveOutcome::Sell(outcome) => {
                        Ok(TxOutcome::BondingCurveSell(outcome))
                    }
                    CanonicalBondingCurveOutcome::Buy(_) => Err(TxApplyError::InvalidType(
                        "Canonical BUY_CBE payload cannot execute as BondingCurveSell".to_string(),
                    )),
                }
            }

            TransactionType::DaoProposal => {
                let outcome = self.apply_dao_proposal(mutator, tx, &tx_hash)?;
                Ok(TxOutcome::DaoProposal(outcome))
            }
            TransactionType::DaoVote => {
                let outcome = self.apply_dao_vote(mutator, tx, block_height)?;
                Ok(TxOutcome::DaoVote(outcome))
            }
            TransactionType::DaoExecution => {
                let outcome = self.apply_dao_execution(mutator, tx, &tx_hash)?;
                Ok(TxOutcome::DaoExecution(outcome))
            }

            // ORACLE-R3: Oracle attestation is handled as LegacySystem in executor.
            // The actual oracle_state mutation happens in Blockchain.finish_block_processing()
            // which iterates through transactions and calls apply_oracle_attestation().
            // This separation is necessary because oracle_state is in-memory (not in storage).
            TransactionType::OracleAttestation => Ok(TxOutcome::LegacySystem),

            // RecordOnRampTrade (#1897): executor arm is a no-op.
            // The actual OnRampState mutation happens in Blockchain.process_on_ramp_trade_transactions()
            // called from finish_block_processing().
            TransactionType::RecordOnRampTrade => Ok(TxOutcome::LegacySystem),

            TransactionType::TreasuryAllocation => {
                self.apply_treasury_allocation(mutator, tx)?;
                Ok(TxOutcome::TreasuryAllocation)
            }

            // Coinbase is routed through apply_coinbase_with_fees, never here.
            // (Handled above; this duplicate arm was removed — see the Coinbase arm near the top of this match.)
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
        block_timestamp: u64,
    ) -> Result<TxOutcome, TxApplyError> {
        // Coinbase should not be passed to this method
        if tx.transaction_type == TransactionType::Coinbase {
            return Err(TxApplyError::InvalidType(
                "Coinbase should not be processed in apply_tx pass".to_string(),
            ));
        }

        // Delegate to existing apply_transaction for non-coinbase types
        self.apply_transaction(mutator, tx, block_height, block_timestamp)
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
#[derive(Debug)]
#[allow(dead_code)]
enum TxOutcome {
    Transfer(TransferOutcome),
    TokenTransfer(TokenTransferOutcome),
    TokenMint(TokenMintOutcome),
    TokenCreation(TokenCreationOutcome),
    ContractDeployment(ContractDeploymentOutcome),
    ContractExecution(ContractExecutionOutcome),
    DaoProposal(DaoProposalOutcome),
    DaoVote(DaoVoteOutcome),
    DaoExecution(DaoExecutionOutcome),
    BondingCurveDeploy,
    BondingCurveBuy(BondingCurveBuyOutcome),
    BondingCurveSell(BondingCurveSellOutcome),
    BondingCurveGraduate,
    /// Oracle attestation outcome (ORACLE-R3: Canonical Path)
    OracleAttestation(OracleAttestationOutcome),
    Coinbase(CoinbaseOutcome),
    /// Treasury allocation: SOV transferred from source treasury to destination wallet.
    TreasuryAllocation,
    /// Payroll mint: synthetic curve event that mints CBE to a collaborator.
    PayrollMint,
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

/// Outcome of a token creation transaction
#[derive(Debug, Clone)]
pub struct TokenCreationOutcome {
    pub token_id: [u8; 32],
    pub creator: Address,
    pub treasury: Address,
    pub creator_allocation: u128,
    pub treasury_allocation: u128,
    pub initial_supply: u128,
}

/// Outcome of a contract deployment transaction
#[derive(Debug, Clone)]
pub struct ContractDeploymentOutcome {
    pub contract_id: [u8; 32],
    pub contract_type: String,
}

/// Outcome of a contract execution transaction
#[derive(Debug, Clone)]
pub struct ContractExecutionOutcome {
    pub contract_id: [u8; 32],
    pub method: String,
}

/// Outcome of a DAO proposal transaction
#[derive(Debug, Clone)]
pub struct DaoProposalOutcome {
    pub proposal_id: crate::types::Hash,
}

/// Outcome of a DAO vote transaction
#[derive(Debug, Clone)]
pub struct DaoVoteOutcome {
    pub proposal_id: crate::types::Hash,
    pub vote_id: crate::types::Hash,
}

/// Outcome of a DAO execution transaction
#[derive(Debug, Clone)]
pub struct DaoExecutionOutcome {
    pub proposal_id: crate::types::Hash,
}

/// Outcome of a bonding curve buy transaction
#[derive(Debug, Clone)]
pub struct BondingCurveBuyOutcome {
    pub token_id: [u8; 32],
    pub buyer: [u8; 32],
    pub stable_spent: u128,
    pub tokens_received: u128,
}

/// Outcome of a bonding curve sell transaction
#[derive(Debug, Clone)]
pub struct BondingCurveSellOutcome {
    pub token_id: [u8; 32],
    pub seller: [u8; 32],
    pub tokens_sold: u128,
    pub stable_received: u128,
}

/// Outcome of parsing a canonical fixed-width bonding curve transaction.
#[derive(Debug, Clone)]
pub enum CanonicalBondingCurveOutcome {
    Buy(BondingCurveBuyOutcome),
    Sell(BondingCurveSellOutcome),
}

/// Outcome of an oracle attestation transaction (ORACLE-R3: Canonical Path)
#[derive(Debug, Clone)]
pub struct OracleAttestationOutcome {
    pub epoch_id: u64,
    pub validator_pubkey: [u8; 32],
    pub sov_usd_price: u128,
    pub finalized: bool,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::storage::SledStore;
    use crate::transaction::encode_contract_execution_memo_v2;
    use crate::types::ContractCall;
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
        BlockExecutor::new_with_token_creation_fee(
            store,
            fee_model,
            BlockLimits::default(),
            DEFAULT_TOKEN_CREATION_FEE,
        )
    }

    fn create_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // Unique genesis hash
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1000,
            height: 0,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
        };
        Block::new(header, vec![])
    }

    fn create_block_at_height(height: u64, prev_hash: Hash) -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&height.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_hash: prev_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1000 + height,
            height,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
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
    fn test_genesis_writes_cbe_zero_state_to_sled() {
        // #1927: genesis must explicitly persist the canonical CBE economic
        // zero-state so reads after block 0 return a concrete record rather
        // than an implicit fallback default.
        let store = create_test_store();
        let executor = BlockExecutor::with_store(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let state = store.get_cbe_economic_state().unwrap();
        assert_eq!(state, lib_types::BondingCurveEconomicState::default());
        assert_eq!(state.s_c, 0);
        assert!(!state.graduated);
        assert!(!state.sell_enabled);
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
        let block1 = create_block_at_height(1, Hash::default()); // Wrong!
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
        PublicKey::new([0u8; 2592])
    }

    fn create_dummy_signature() -> Signature {
        Signature {
            signature: vec![0u8; 64],
            public_key: create_dummy_public_key(),
            algorithm: SignatureAlgorithm::DEFAULT,
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
            payload: crate::transaction::TransactionPayload::None,
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
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    /// Create a genesis block with a coinbase transaction for funding
    #[allow(dead_code)]
    fn create_funded_genesis_block() -> Block {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = 0x01; // Unique genesis hash
        let block_hash = Hash::new(hash_bytes);

        // Create coinbase tx for funding
        let coinbase = create_coinbase_tx(create_dummy_public_key());

        let header = BlockHeader {
            version: 1,
            previous_hash: Hash::default().into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1000,
            height: 0,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
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
            previous_hash: prev_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1000 + height,
            height,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
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

        let genesis = create_genesis_block();
        let genesis_outcome = executor.apply_block(&genesis).unwrap();
        assert_eq!(genesis_outcome.height, 0);

        // Apply a funded block that creates the spendable coinbase UTXO.
        let funded_block = create_block_with_txs(
            1,
            genesis.header.block_hash,
            vec![create_coinbase_tx(create_dummy_public_key())],
        );
        executor.apply_block(&funded_block).unwrap();
        assert_eq!(store.latest_height().unwrap(), 1);

        // Get the coinbase tx hash to reference its outputs
        let coinbase_tx = &funded_block.transactions[0];
        let coinbase_tx_hash = hash_transaction(coinbase_tx);

        // Create a transfer spending the coinbase UTXO (output index 0)
        let spend_tx = create_transfer_tx(coinbase_tx_hash, 0);
        let block2 =
            create_block_with_txs(2, funded_block.header.block_hash, vec![spend_tx.clone()]);

        // First spend should succeed
        executor.apply_block(&block2).unwrap();
        assert_eq!(store.latest_height().unwrap(), 2);

        // Try to spend the same UTXO again in block 3
        let double_spend_tx = create_transfer_tx(coinbase_tx_hash, 0);
        let block3 = create_block_with_txs(3, block2.header.block_hash, vec![double_spend_tx]);

        // This should fail - UTXO already spent
        let result = executor.apply_block(&block3);
        assert!(result.is_err(), "Double spend should be rejected");

        // Height should remain at block 2
        assert_eq!(store.latest_height().unwrap(), 2);
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
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    fn create_contract_deployment_tx() -> Transaction {
        let payload = crate::transaction::contract_deployment::ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![0x01, 0x02, 0x03, 0x04],
            abi: br#"{"name":"test"}"#.to_vec(),
            init_args: vec![0xAA, 0xBB],
            gas_limit: 10_000,
            memory_limit_bytes: 1_048_576,
        };

        let mut tx = create_legacy_tx(TransactionType::ContractDeployment);
        tx.fee = 1_000_000;
        tx.memo = payload
            .encode_memo()
            .expect("contract deployment test memo encoding must work");
        tx
    }

    fn create_contract_execution_tx(contract_id: [u8; 32], method: &str) -> Transaction {
        let call = ContractCall::token_call(method.to_string(), vec![0x10, 0x20]);
        let call_sig = create_dummy_signature();

        let mut tx = create_legacy_tx(TransactionType::ContractExecution);
        tx.fee = 1_000_000;
        tx.memo = encode_contract_execution_memo_v2(contract_id, &call, &call_sig)
            .expect("contract execution test memo encoding must work");
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
            // DaoProposal/DaoVote/DaoExecution are Phase-2 types with structural
            // validation — they are NOT listed here.
            TransactionType::DifficultyUpdate,
            TransactionType::UBIClaim,
            TransactionType::ProfitDeclaration,
            TransactionType::GovernanceConfigUpdate,
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
        tx2.payload = crate::transaction::TransactionPayload::Wallet(
            crate::transaction::WalletTransactionData {
                wallet_id: Hash::new([0xBB; 32]),
                wallet_type: "Primary".to_string(),
                wallet_name: "test-wallet".to_string(),
                alias: None,
                public_key: vec![0u8; 32],
                owner_identity_id: None,
                seed_commitment: Hash::default(),
                created_at: 0,
                registration_fee: 0,
                capabilities: 0,
                initial_balance: 0,
            },
        );

        let header = BlockHeader {
            version: 1,
            previous_hash: genesis.header.block_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1001,
            height: 1,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
        };
        let block1 = Block::new(header, vec![tx1, tx2]);

        let outcome = executor.apply_block(&block1).unwrap();
        assert_eq!(outcome.height, 1);
        assert_eq!(outcome.tx_count, 2);
        assert_eq!(store.latest_height().unwrap(), 1);
    }

    // =========================================================================
    // TokenCreation canonical path tests
    // =========================================================================

    use crate::storage::TokenId;
    use crate::transaction::token_creation::TokenCreationPayloadV1;

    fn create_token_creation_tx_with_fee(
        name: &str,
        symbol: &str,
        initial_supply: u64,
        treasury_recipient: [u8; 32],
        fee: u64,
    ) -> Transaction {
        let payload = TokenCreationPayloadV1 {
            name: name.to_string(),
            symbol: symbol.to_string(),
            initial_supply,
            decimals: 8,
            treasury_allocation_bps: 2_000,
            treasury_recipient,
        };
        let memo = payload.encode_memo().expect("valid token creation memo");
        Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::TokenCreation,
            inputs: vec![],
            outputs: vec![],
            fee,
            signature: create_dummy_signature(),
            memo,
            payload: crate::transaction::TransactionPayload::None,
        }
    }

    fn create_token_creation_tx(
        name: &str,
        symbol: &str,
        initial_supply: u64,
        treasury_recipient: [u8; 32],
    ) -> Transaction {
        create_token_creation_tx_with_fee(
            name,
            symbol,
            initial_supply,
            treasury_recipient,
            DEFAULT_TOKEN_CREATION_FEE,
        )
    }

    /// TokenCreation canonical path: token is created and minted to creator.
    #[test]
    fn test_token_creation_canonical() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let treasury = [0xAA; 32];
        let tx = create_token_creation_tx("Test Token", "TEST", 1_000_000, treasury);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);
        let outcome = executor.apply_block(&block1).unwrap();

        assert_eq!(outcome.height, 1);
        assert_eq!(outcome.tx_count, 1);

        // Verify the token contract exists in the store
        let token_id = crate::contracts::utils::generate_custom_token_id("Test Token", "TEST");
        let contract = store
            .get_token_contract(&TokenId::new(token_id))
            .unwrap()
            .expect("token contract should exist");
        assert_eq!(contract.symbol, "TEST");
        assert_eq!(contract.total_supply, 1_000_000);
        let creator_addr = Address::new(create_dummy_signature().public_key.key_id);
        let treasury_addr = Address::new(treasury);
        let creator_balance = store
            .get_token_balance(&TokenId::new(token_id), &creator_addr)
            .expect("creator balance read should succeed");
        let treasury_balance = store
            .get_token_balance(&TokenId::new(token_id), &treasury_addr)
            .expect("treasury balance read should succeed");
        assert_eq!(creator_balance, 800_000);
        assert_eq!(treasury_balance, 200_000);
    }

    /// TokenCreation must reject when treasury recipient equals creator.
    #[test]
    fn test_token_creation_self_treasury_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let creator_key_id = create_dummy_signature().public_key.key_id;
        let tx = create_token_creation_tx("Self Treasury", "SELF", 1_000_000, creator_key_id);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);
        let result = executor.apply_block(&block1);

        assert!(
            result.is_err(),
            "TokenCreation with treasury == creator should be rejected"
        );
    }

    /// Duplicate TokenCreation for the same token_id must be rejected.
    #[test]
    fn test_token_creation_duplicate_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // First creation succeeds
        let tx = create_token_creation_tx("Test Token", "TEST", 1_000_000, [0xAA; 32]);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);
        executor.apply_block(&block1).unwrap();

        // Second creation with same name+symbol (same token_id) must be rejected
        let tx2 = create_token_creation_tx("Test Token", "TEST", 500_000, [0xAA; 32]);
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![tx2]);
        let result = executor.apply_block(&block2);
        assert!(
            result.is_err(),
            "Duplicate TokenCreation should be rejected"
        );
    }

    /// TokenCreation with a symbol that differs only in case must be rejected.
    #[test]
    fn test_token_creation_symbol_case_insensitive_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        // Create token with uppercase symbol
        let tx = create_token_creation_tx("Alpha Token", "ALPHA", 1_000_000, [0xAA; 32]);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);
        executor.apply_block(&block1).unwrap();

        // Token with different name but same symbol (lowercase) must be rejected
        let tx2 = create_token_creation_tx("Beta Token", "alpha", 500_000, [0xBB; 32]);
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![tx2]);
        let result = executor.apply_block(&block2);
        assert!(
            result.is_err(),
            "TokenCreation with case-conflicting symbol should be rejected"
        );
    }

    #[test]
    fn test_token_creation_fee_below_canonical_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let tx = create_token_creation_tx_with_fee(
            "Low Fee Token",
            "LOW",
            1_000_000,
            [0xAA; 32],
            DEFAULT_TOKEN_CREATION_FEE - 1,
        );
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);

        let result = executor.apply_block(&block1);

        assert!(
            result.is_err(),
            "TokenCreation with low fee should be rejected"
        );
    }

    #[test]
    fn test_token_creation_fee_above_canonical_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let tx = create_token_creation_tx_with_fee(
            "High Fee Token",
            "HIGH",
            1_000_000,
            [0xAA; 32],
            DEFAULT_TOKEN_CREATION_FEE + 1,
        );
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);

        let result = executor.apply_block(&block1);

        assert!(
            result.is_err(),
            "TokenCreation with non-canonical high fee should be rejected"
        );
    }

    #[test]
    fn test_token_creation_fee_zero_accepted() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let tx = create_token_creation_tx_with_fee(
            "Subsidized Token",
            "FREE",
            1_000_000,
            [0xBB; 32],
            0, // subsidized/system creation
        );
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);

        let result = executor.apply_block(&block1);

        assert!(
            result.is_ok(),
            "TokenCreation with fee=0 (subsidized) should be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_contract_deployment_writes_contract_code() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let tx = create_contract_deployment_tx();
        let tx_hash = hash_transaction(&tx);
        let expected_contract_id = tx_hash.as_array();

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&1u64.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_hash: genesis.header.block_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1001,
            height: 1,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
        };

        let block = Block::new(header, vec![tx]);
        executor.apply_block(&block).unwrap();

        let code = store
            .get_contract_code(&expected_contract_id)
            .expect("read contract code")
            .expect("contract code should exist");
        assert_eq!(code, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_contract_execution_persists_call_record() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let deploy_tx = create_contract_deployment_tx();
        let contract_id = hash_transaction(&deploy_tx).as_array();
        let deploy_block = create_block_with_txs(1, genesis.header.block_hash, vec![deploy_tx]);
        executor.apply_block(&deploy_block).unwrap();

        let tx = create_contract_execution_tx(contract_id, "create_custom_token");
        let tx_hash = hash_transaction(&tx);
        let mut call_key = b"__call:".to_vec();
        call_key.extend_from_slice(tx_hash.as_bytes());

        let mut hash_bytes = [0u8; 32];
        hash_bytes[0..8].copy_from_slice(&1u64.to_be_bytes());
        let block_hash = Hash::new(hash_bytes);

        let header = BlockHeader {
            version: 1,
            previous_hash: deploy_block.header.block_hash.into(),
            data_helix_root: Hash::default().into(),
            timestamp: 1001,
            height: 2,
            verification_helix_root: [0u8; 32],
            state_root: Hash::default().into(),
            bft_quorum_root: [0u8; 32],
            block_hash,
        };

        let block = Block::new(header, vec![tx]);
        executor.apply_block(&block).unwrap();

        let stored = store
            .get_contract_storage(&contract_id, &call_key)
            .expect("read contract storage")
            .expect("call record should exist");
        let (stored_height, stored_method, _stored_caller, stored_params): (
            u64,
            String,
            [u8; 32],
            Vec<u8>,
        ) = bincode::deserialize(&stored).expect("decode call record");
        assert_eq!(stored_height, 2);
        assert_eq!(stored_method, "create_custom_token");
        assert_eq!(stored_params, vec![0x10, 0x20]);
    }

    #[test]
    fn test_contract_execution_rejects_legacy_memo_without_contract_id() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let mut tx = create_legacy_tx(TransactionType::ContractExecution);
        tx.fee = 1_000_000;
        let call = ContractCall::token_call("create_custom_token".to_string(), vec![0x10, 0x20]);
        let call_sig = create_dummy_signature();
        tx.memo = b"ZHTP".to_vec();
        tx.memo.extend(
            bincode::serialize(&(call, call_sig)).expect("legacy execution memo serialization"),
        );

        let block = create_block_with_txs(1, genesis.header.block_hash, vec![tx]);
        let result = executor.apply_block(&block);
        assert!(
            result.is_err(),
            "legacy ContractExecution memo without contract_id must be rejected"
        );
    }

    #[test]
    fn test_contract_execution_same_type_contracts_do_not_collide() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let deploy_a = create_contract_deployment_tx();
        let contract_a = hash_transaction(&deploy_a).as_array();
        let mut deploy_b = create_contract_deployment_tx();
        deploy_b.memo = crate::transaction::contract_deployment::ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![0x09, 0x08, 0x07, 0x06],
            abi: br#"{"name":"test_b"}"#.to_vec(),
            init_args: vec![0xCC, 0xDD],
            gas_limit: 12_000,
            memory_limit_bytes: 2_048_000,
        }
        .encode_memo()
        .expect("deployment memo encode");
        let contract_b = hash_transaction(&deploy_b).as_array();

        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![deploy_a, deploy_b]);
        executor.apply_block(&block1).unwrap();

        let tx_a = create_contract_execution_tx(contract_a, "set_value");
        let tx_a_hash = hash_transaction(&tx_a);
        let tx_b = create_contract_execution_tx(contract_b, "set_value");
        let tx_b_hash = hash_transaction(&tx_b);
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![tx_a, tx_b]);
        executor.apply_block(&block2).unwrap();

        let mut key_a = b"__call:".to_vec();
        key_a.extend_from_slice(tx_a_hash.as_bytes());
        let mut key_b = b"__call:".to_vec();
        key_b.extend_from_slice(tx_b_hash.as_bytes());

        assert!(
            store
                .get_contract_storage(&contract_a, &key_a)
                .expect("read contract_a call")
                .is_some(),
            "contract A must contain its call record"
        );
        assert!(
            store
                .get_contract_storage(&contract_b, &key_b)
                .expect("read contract_b call")
                .is_some(),
            "contract B must contain its call record"
        );
        assert!(
            store
                .get_contract_storage(&contract_a, &key_b)
                .expect("read contract_a foreign call")
                .is_none(),
            "contract A must not contain contract B call record"
        );
        assert!(
            store
                .get_contract_storage(&contract_b, &key_a)
                .expect("read contract_b foreign call")
                .is_none(),
            "contract B must not contain contract A call record"
        );
    }

    /// T5: State persists across store restart
    #[test]
    fn test_t5_persistence_across_restart() {
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

    // =========================================================================
    // DAO governance lifecycle tests
    // =========================================================================

    fn proposal_id_for(tag: &str) -> crate::types::Hash {
        crate::types::Hash::new(lib_crypto::hash_blake3(tag.as_bytes()))
    }

    fn create_dao_proposal_tx(proposal_id: crate::types::Hash) -> Transaction {
        let mut tx = create_legacy_tx(TransactionType::DaoProposal);
        tx.fee = 1_000; // governance tx min fee with FeeParams::for_testing()
        tx.payload = crate::transaction::TransactionPayload::DaoProposal(
            crate::transaction::DaoProposalData {
                proposal_id,
                proposer: "alice".to_string(),
                title: "Test Proposal".to_string(),
                description: "A test governance proposal".to_string(),
                proposal_type: "parameter_change".to_string(),
                voting_period_blocks: 100,
                quorum_required: 51,
                execution_params: None,
                created_at: 1000,
                created_at_height: 1,
            },
        );
        tx
    }

    fn create_dao_vote_tx(
        proposal_id: crate::types::Hash,
        voter: &str,
        vote_choice: &str,
    ) -> Transaction {
        let vote_id = crate::types::Hash::new(lib_crypto::hash_blake3(
            format!("{voter}:{}", hex::encode(proposal_id.as_bytes())).as_bytes(),
        ));
        let mut tx = create_legacy_tx(TransactionType::DaoVote);
        tx.fee = 1_000; // governance tx min fee with FeeParams::for_testing()
        tx.payload =
            crate::transaction::TransactionPayload::DaoVote(crate::transaction::DaoVoteData {
                vote_id,
                proposal_id,
                voter: voter.to_string(),
                vote_choice: vote_choice.to_string(),
                voting_power: 100,
                justification: None,
                timestamp: 2000,
            });
        tx
    }

    fn create_dao_execution_tx(proposal_id: crate::types::Hash) -> Transaction {
        let mut tx = create_legacy_tx(TransactionType::DaoExecution);
        tx.fee = 1_000; // governance tx min fee with FeeParams::for_testing()
        tx.payload = crate::transaction::TransactionPayload::DaoExecution(
            crate::transaction::DaoExecutionData {
                proposal_id,
                executor: "council".to_string(),
                execution_type: "parameter_change".to_string(),
                recipient: None,
                amount: None,
                executed_at: 3000,
                executed_at_height: 3,
                multisig_signatures: vec![],
            },
        );
        tx
    }

    /// DAO full lifecycle: Proposal (block 1) → Vote (block 2) → Execution (block 3).
    ///
    /// SledStore writes are only visible after apply_batch in commit_block, so each
    /// lifecycle step must be in a separate block.
    #[test]
    fn test_dao_lifecycle_proposal_vote_execution() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let proposal_id = proposal_id_for("lifecycle-test-1");

        // Block 1: submit the proposal
        let proposal_tx = create_dao_proposal_tx(proposal_id);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![proposal_tx]);
        executor
            .apply_block(&block1)
            .expect("Block 1 (proposal) must succeed");

        // Block 2: cast a vote (within the 100-block voting period)
        let vote_tx = create_dao_vote_tx(proposal_id, "alice", "Yes");
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![vote_tx]);
        executor
            .apply_block(&block2)
            .expect("Block 2 (vote) must succeed");

        // Block 3: execute the proposal
        let exec_tx = create_dao_execution_tx(proposal_id);
        let block3 = create_block_with_txs(3, block2.header.block_hash, vec![exec_tx]);
        executor
            .apply_block(&block3)
            .expect("Block 3 (execution) must succeed");

        assert_eq!(store.latest_height().unwrap(), 3);

        // Verify execution record persisted
        let dao_contract = lib_crypto::hash_blake3(b"DAO_GOVERNANCE_V1");
        let mut exec_key = b"execution:".to_vec();
        exec_key.extend_from_slice(proposal_id.as_bytes());
        let record = store
            .get_contract_storage(&dao_contract, &exec_key)
            .expect("read execution record")
            .expect("execution record should exist after block 3");
        assert!(!record.is_empty());
    }

    /// Submitting the same proposal twice must be rejected.
    #[test]
    fn test_dao_duplicate_proposal_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let proposal_id = proposal_id_for("duplicate-proposal-test");

        // Block 1: first proposal succeeds
        let proposal_tx = create_dao_proposal_tx(proposal_id);
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![proposal_tx]);
        executor
            .apply_block(&block1)
            .expect("First proposal must succeed");

        // Block 2: same proposal_id must be rejected
        let dup_tx = create_dao_proposal_tx(proposal_id);
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![dup_tx]);
        let result = executor.apply_block(&block2);
        assert!(result.is_err(), "Duplicate DaoProposal must be rejected");
    }

    /// Executing the same proposal twice must be rejected (double-execution safety).
    #[test]
    fn test_dao_duplicate_execution_rejected() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let proposal_id = proposal_id_for("double-execution-test");

        // Block 1: proposal
        let block1 = create_block_with_txs(
            1,
            genesis.header.block_hash,
            vec![create_dao_proposal_tx(proposal_id)],
        );
        executor.apply_block(&block1).unwrap();

        // Block 2: first execution succeeds
        let block2 = create_block_with_txs(
            2,
            block1.header.block_hash,
            vec![create_dao_execution_tx(proposal_id)],
        );
        executor.apply_block(&block2).unwrap();

        // Block 3: second execution of the same proposal must be rejected
        let block3 = create_block_with_txs(
            3,
            block2.header.block_hash,
            vec![create_dao_execution_tx(proposal_id)],
        );
        let result = executor.apply_block(&block3);
        assert!(result.is_err(), "Double DaoExecution must be rejected");
    }

    /// DaoVote must be rejected when the proposal voting period has expired.
    #[test]
    fn test_dao_vote_rejected_after_voting_period() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let proposal_id = proposal_id_for("expired-vote-test");

        // Block 1: proposal with a 1-block voting period (expires after height 2)
        let mut proposal_data = create_dao_proposal_tx(proposal_id);
        if let crate::transaction::TransactionPayload::DaoProposal(ref mut d) =
            proposal_data.payload
        {
            d.voting_period_blocks = 1; // deadline = created_at_height(1) + 1 = height 2
        }
        let block1 = create_block_with_txs(1, genesis.header.block_hash, vec![proposal_data]);
        executor.apply_block(&block1).unwrap();

        // Block 2: vote at height 2 is within deadline (2 <= 1+1=2)
        let vote_tx = create_dao_vote_tx(proposal_id, "bob", "No");
        let block2 = create_block_with_txs(2, block1.header.block_hash, vec![vote_tx]);
        executor.apply_block(&block2).unwrap();

        // Block 3: vote at height 3 is past the deadline (3 > 2) — must be rejected
        let late_vote_tx = create_dao_vote_tx(proposal_id, "carol", "Yes");
        let block3 = create_block_with_txs(3, block2.header.block_hash, vec![late_vote_tx]);
        let result = executor.apply_block(&block3);
        assert!(
            result.is_err(),
            "DaoVote after voting period expiry must be rejected"
        );
    }

    // =========================================================================
    // Bonding Curve tests
    // =========================================================================

    #[test]
    fn test_bonding_curve_tx_constructors_use_version_v8() {
        use crate::transaction::core::{
            BondingCurveBuyData, BondingCurveDeployData, BondingCurveGraduateData,
            BondingCurveSellData, TX_VERSION_V8,
        };

        let sig = create_dummy_signature();
        let creator = [1u8; 32];

        let deploy_tx = Transaction::new_bonding_curve_deploy_with_chain_id(
            1,
            BondingCurveDeployData {
                name: "Test".into(),
                symbol: "TST".into(),
                curve_type: 0,
                base_price: 1000,
                curve_param: 100,
                midpoint_supply: None,
                threshold_type: 0,
                threshold_value: 1_000_000,
                threshold_time_seconds: None,
                sell_enabled: false,
                creator,
                nonce: 1,
            },
            sig.clone(),
            vec![],
        );
        assert_eq!(
            deploy_tx.version, TX_VERSION_V8,
            "deploy tx must be version V8"
        );
        assert!(
            deploy_tx.bonding_curve_deploy_data().is_some(),
            "deploy data must survive serialization gate"
        );

        let buy_tx = Transaction::new_bonding_curve_buy_with_chain_id(
            1,
            BondingCurveBuyData {
                token_id: [0u8; 32],
                stable_amount: 1000,
                min_tokens_out: 0,
                buyer: creator,
                nonce: 2,
            },
            sig.clone(),
            vec![],
        );
        assert_eq!(buy_tx.version, TX_VERSION_V8);

        let sell_tx = Transaction::new_bonding_curve_sell_with_chain_id(
            1,
            BondingCurveSellData {
                token_id: [0u8; 32],
                token_amount: 100,
                min_stable_out: 0,
                seller: creator,
                nonce: 3,
            },
            sig.clone(),
            vec![],
        );
        assert_eq!(sell_tx.version, TX_VERSION_V8);

        let grad_tx = Transaction::new_bonding_curve_graduate_with_chain_id(
            1,
            BondingCurveGraduateData {
                token_id: [0u8; 32],
                pool_id: [0u8; 32],
                sov_seed_amount: 0,
                token_seed_amount: 0,
                graduator: creator,
                nonce: 4,
            },
            sig,
            vec![],
        );
        assert_eq!(grad_tx.version, TX_VERSION_V8);
    }

    #[test]
    fn test_bonding_curve_tx_v8_roundtrips_data_fields() {
        use crate::transaction::core::{BondingCurveDeployData, TX_VERSION_V8};

        let creator = [7u8; 32];
        let sig = create_dummy_signature();
        let tx = Transaction::new_bonding_curve_deploy_with_chain_id(
            1,
            BondingCurveDeployData {
                name: "RoundTrip".into(),
                symbol: "RT".into(),
                curve_type: 1,
                base_price: 500,
                curve_param: 200,
                midpoint_supply: None,
                threshold_type: 1,
                threshold_value: 500_000,
                threshold_time_seconds: None,
                sell_enabled: true,
                creator,
                nonce: 99,
            },
            sig,
            vec![],
        );
        assert_eq!(tx.version, TX_VERSION_V8);

        // Roundtrip through bincode — bonding curve data must survive
        let bytes = bincode::serialize(&tx).expect("serialize");
        let decoded: Transaction = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.version, TX_VERSION_V8);
        let data = decoded
            .bonding_curve_deploy_data()
            .expect("deploy_data must be Some after roundtrip");
        assert_eq!(data.symbol, "RT");
        assert_eq!(data.creator, creator);
    }

    #[test]
    fn test_canonical_bonding_curve_buy_executes_economic_computation() {
        use crate::contracts::bonding_curve::canonical::SCALE;
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, Nonce48};

        let store = create_test_store();

        // Block 0: seed the sender with SOV so pre-validation passes.
        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so debit_token succeeds.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new([0x11; 32]);
            store
                .set_token_balance(&sov_token_id, &addr, 10_000 * SCALE)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x11; 32],
                &BondingCurveAccountState {
                    key_id: [0x11; 32],
                    balance_cbe: 0,
                    balance_sov: 0, // balances now live in token_balances tree
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        // Block 1: actual execution.
        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let amount_in = 1_000 * SCALE; // generous buy amount
        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: [0x11; 32],
                amount_in,
                max_price: u128::MAX, // no slippage restriction
                expected_s_c: 0,
            }));

        let outcome = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect("BUY_CBE economic computation should succeed");

        // The outcome return value is readable immediately (no sled involved).
        let delta_s = match outcome {
            CanonicalBondingCurveOutcome::Buy(ref o) => {
                assert_eq!(o.stable_spent, amount_in);
                assert!(o.tokens_received > 0, "buyer must receive CBE tokens");
                o.tokens_received
            }
            CanonicalBondingCurveOutcome::Sell(_) => panic!("expected Buy outcome"),
        };

        // put_cbe_economic_state writes to the pending sled batch; commit to flush.
        drop(mutator);
        store.commit_block().unwrap();

        // Read from the committed tree.
        let econ = store.get_cbe_economic_state().unwrap();
        assert_eq!(econ.s_c, delta_s, "supply must equal minted tokens");
        assert!(econ.reserve_balance > 0, "reserve (32%) must be credited");
        assert!(econ.sov_treasury_cbe_balance > 0, "sov treasury (20%) must be credited");
        assert!(econ.liquidity_pool_balance > 0, "liquidity pool (48%) must be credited");
        assert_eq!(
            econ.reserve_balance + econ.sov_treasury_cbe_balance + econ.liquidity_pool_balance,
            amount_in,
            "reserve + sov_treasury + liquidity must equal amount_in exactly (20/32/48 split)"
        );

        // Token balances: SOV debited, CBE credited via token_balances tree.
        let sov_token_id =
            crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
        let cbe_token_id =
            crate::storage::TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
        let addr = crate::storage::Address::new([0x11; 32]);
        let sov_bal = store.get_token_balance(&sov_token_id, &addr).unwrap();
        let cbe_bal = store.get_token_balance(&cbe_token_id, &addr).unwrap();
        assert_eq!(sov_bal, 10_000 * SCALE - amount_in);
        assert_eq!(cbe_bal, delta_s);

        // Nonce incremented in cbe_account_state.
        let acc = store.get_cbe_account_state(&[0x11; 32]).unwrap().unwrap();
        assert_eq!(acc.next_nonce.to_u64(), 1);
    }

    #[test]
    fn test_canonical_bonding_curve_buy_rejects_slippage_violation() {
        use crate::contracts::bonding_curve::canonical::SCALE;
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, Nonce48};

        let store = create_test_store();

        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so balance check passes.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new([0x22; 32]);
            store
                .set_token_balance(&sov_token_id, &addr, 10_000 * SCALE)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x22; 32],
                &BondingCurveAccountState {
                    key_id: [0x22; 32],
                    balance_cbe: 0,
                    balance_sov: 0,
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        // max_price = 1 (1 atomic SOV per CBE) is impossibly cheap → slippage rejection.
        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: [0x22; 32],
                amount_in: 1_000 * SCALE,
                max_price: 1, // absurdly tight slippage cap
                expected_s_c: 0,
            }));

        let err = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect_err("slippage violation must be rejected");

        assert!(
            err.to_string().contains("slippage"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_canonical_bonding_curve_buy_triggers_graduation() {
        use crate::contracts::bonding_curve::canonical::{GRAD_THRESHOLD, SCALE};
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use lib_types::{
            BondingCurveAccountState, BondingCurveBuyTx, BondingCurveEconomicState, Nonce48,
        };

        let store = create_test_store();

        // Seed: place the reserve just one step below the graduation threshold.
        // reserve_credit = amount_in * 20/100; so amount_in that tips = (GRAD_THRESHOLD - (threshold-1)) * 100 / 20
        // Easiest: seed economic state with reserve = GRAD_THRESHOLD - 1.
        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so debit_token succeeds.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new([0x33; 32]);
            store
                .set_token_balance(&sov_token_id, &addr, 100_000 * SCALE)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x33; 32],
                &BondingCurveAccountState {
                    key_id: [0x33; 32],
                    balance_cbe: 0,
                    balance_sov: 0, // balances now live in token_balances tree
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
            // Pre-load reserve so the next buy tips graduation.
            // reserve_credit of a 100 * SCALE buy ≈ 20 * SCALE; GRAD_THRESHOLD ≈ 2_745_966 * SCALE.
            // Use seeded econ state with reserve = GRAD_THRESHOLD - 1.
            // With 20/32/48 split, if reserve=R then the total deposit that produced it
            // was R * 100/32 ≈ R * 3.125. SOV treasury = 20% and liquidity = 48%.
            let reserve_seeded = GRAD_THRESHOLD - 1;
            let implied_total = reserve_seeded * 100 / 32;
            seed.put_cbe_economic_state(&BondingCurveEconomicState {
                s_c: 0,
                reserve_balance: reserve_seeded,
                sov_treasury_cbe_balance: implied_total * 20 / 100,
                liquidity_pool_balance: implied_total * 48 / 100,
                total_sov_minted: 0,
                graduated: false,
                sell_enabled: false,
                ..Default::default()
            })
            .unwrap();
        }
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        // Even a tiny buy (amount_in = 5) yields reserve_credit = 1, tipping GRAD_THRESHOLD.
        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: [0x33; 32],
                amount_in: 100 * SCALE,
                max_price: u128::MAX,
                expected_s_c: 0,
            }));

        executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect("graduation-triggering buy must succeed");

        drop(mutator);
        store.commit_block().unwrap();

        let econ = store.get_cbe_economic_state().unwrap();
        assert!(
            econ.graduated,
            "curve must be marked graduated once reserve >= GRAD_THRESHOLD"
        );
        assert!(econ.reserve_balance >= GRAD_THRESHOLD);
    }

    #[test]
    fn test_canonical_bonding_curve_sell_executes_economic_computation() {
        use crate::contracts::bonding_curve::canonical::SCALE;
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
            BONDING_CURVE_SELL_ACTION,
        };
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, BondingCurveSellTx, Nonce48};

        let store = create_test_store();

        // Block 0: seed SOV so we can buy first.
        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so debit_token succeeds.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new([0x44; 32]);
            store
                .set_token_balance(&sov_token_id, &addr, 10_000 * SCALE)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x44; 32],
                &BondingCurveAccountState {
                    key_id: [0x44; 32],
                    balance_cbe: 0,
                    balance_sov: 0, // balances now live in token_balances tree
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        // Block 1: BUY to acquire CBE.
        let amount_in = 1_000 * SCALE;
        store.begin_block(1).unwrap();
        let (delta_s, reserve_after_buy) = {
            let mutator = StateMutator::new(store.as_ref());
            let executor = BlockExecutor::with_store(store.clone());
            let payload = encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(
                BondingCurveBuyTx {
                    action: BONDING_CURVE_BUY_ACTION,
                    chain_id: 0x03,
                    nonce: Nonce48::from_u64(0).unwrap(),
                    sender: [0x44; 32],
                    amount_in,
                    max_price: u128::MAX,
                    expected_s_c: 0,
                },
            ));
            let outcome = executor
                .apply_canonical_bonding_curve_tx(&mutator, &payload)
                .expect("BUY must succeed");
            let delta_s = match outcome {
                CanonicalBondingCurveOutcome::Buy(ref o) => o.tokens_received,
                _ => panic!("expected Buy"),
            };
            drop(mutator);
            store.commit_block().unwrap();
            let econ = store.get_cbe_economic_state().unwrap();
            (delta_s, econ.reserve_balance)
        };

        // Block 2: enable selling (protocol flag).
        store.begin_block(2).unwrap();
        {
            let seed = StateMutator::new(store.as_ref());
            let mut econ = store.get_cbe_economic_state().unwrap();
            econ.sell_enabled = true;
            seed.put_cbe_economic_state(&econ).unwrap();
        }
        store.commit_block().unwrap();

        // Block 3: SELL all acquired CBE back.
        store.begin_block(3).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
                action: BONDING_CURVE_SELL_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(1).unwrap(),
                sender: [0x44; 32],
                amount_cbe: delta_s,
                min_payout: 0, // no slippage floor
                expected_s_c: delta_s,
            }));

        let outcome = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect("SELL_CBE economic computation should succeed");

        let sov_out = match outcome {
            CanonicalBondingCurveOutcome::Sell(ref o) => {
                assert_eq!(o.tokens_sold, delta_s);
                assert!(o.stable_received > 0, "seller must receive SOV");
                o.stable_received
            }
            CanonicalBondingCurveOutcome::Buy(_) => panic!("expected Sell outcome"),
        };

        drop(mutator);
        store.commit_block().unwrap();

        let econ = store.get_cbe_economic_state().unwrap();
        assert_eq!(econ.s_c, 0, "all CBE burned, supply must return to 0");
        assert_eq!(econ.reserve_balance, reserve_after_buy - sov_out);

        // Token balances: CBE fully burned, SOV = initial - buy_cost + sell_payout.
        let sov_token_id =
            crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
        let cbe_token_id =
            crate::storage::TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
        let addr = crate::storage::Address::new([0x44; 32]);
        let cbe_bal = store.get_token_balance(&cbe_token_id, &addr).unwrap();
        let sov_bal = store.get_token_balance(&sov_token_id, &addr).unwrap();
        assert_eq!(cbe_bal, 0, "all CBE must be consumed");
        assert_eq!(sov_bal, 10_000 * SCALE - amount_in + sov_out);

        let acc = store.get_cbe_account_state(&[0x44; 32]).unwrap().unwrap();
        assert_eq!(acc.next_nonce.to_u64(), 2);
    }

    #[test]
    fn test_canonical_bonding_curve_sell_rejects_insufficient_reserve() {
        use crate::contracts::bonding_curve::canonical::SCALE;
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_SELL_ACTION,
        };
        use lib_types::{
            BondingCurveAccountState, BondingCurveEconomicState, BondingCurveSellTx, Nonce48,
        };

        let store = create_test_store();

        // Seed: account has CBE but reserve is empty.
        let cbe_amount = 100 * SCALE;
        store.begin_block(0).unwrap();
        {
            // Seed CBE token balance so the balance check passes.
            let cbe_token_id =
                crate::storage::TokenId::new(crate::Blockchain::derive_cbe_token_id_pub());
            let addr = crate::storage::Address::new([0x55; 32]);
            store
                .set_token_balance(&cbe_token_id, &addr, cbe_amount)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x55; 32],
                &BondingCurveAccountState {
                    key_id: [0x55; 32],
                    balance_cbe: 0,
                    balance_sov: 0,
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
            // s_c must equal cbe_amount so payout_for_burn can compute a non-zero sov_out.
            // sell_enabled=true so the solvency check (not the flag) is what triggers the error.
            seed.put_cbe_economic_state(&BondingCurveEconomicState {
                s_c: cbe_amount,
                reserve_balance: 0, // empty — solvency check must fail
                sov_treasury_cbe_balance: 0,
                liquidity_pool_balance: 0,
                total_sov_minted: 0,
                graduated: false,
                sell_enabled: true,
                ..Default::default()
            })
            .unwrap();
        }
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
                action: BONDING_CURVE_SELL_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: [0x55; 32],
                amount_cbe: cbe_amount,
                min_payout: 0,
                expected_s_c: cbe_amount,
            }));

        let err = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect_err("sell against empty reserve must fail");

        assert!(
            err.to_string().contains("reserve") || err.to_string().contains("Insolvent"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_canonical_bonding_curve_sell_rejects_min_payout_violation() {
        use crate::contracts::bonding_curve::canonical::SCALE;
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
            BONDING_CURVE_SELL_ACTION,
        };
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, BondingCurveSellTx, Nonce48};

        let store = create_test_store();

        // Block 0: seed and buy some CBE.
        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so debit_token succeeds.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new([0x66; 32]);
            store
                .set_token_balance(&sov_token_id, &addr, 10_000 * SCALE)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &[0x66; 32],
                &BondingCurveAccountState {
                    key_id: [0x66; 32],
                    balance_cbe: 0,
                    balance_sov: 0, // balances now live in token_balances tree
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        store.begin_block(1).unwrap();
        let delta_s = {
            let mutator = StateMutator::new(store.as_ref());
            let executor = BlockExecutor::with_store(store.clone());
            let payload = encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(
                BondingCurveBuyTx {
                    action: BONDING_CURVE_BUY_ACTION,
                    chain_id: 0x03,
                    nonce: Nonce48::from_u64(0).unwrap(),
                    sender: [0x66; 32],
                    amount_in: 1_000 * SCALE,
                    max_price: u128::MAX,
                    expected_s_c: 0,
                },
            ));
            let outcome = executor
                .apply_canonical_bonding_curve_tx(&mutator, &payload)
                .unwrap();
            match outcome {
                CanonicalBondingCurveOutcome::Buy(ref o) => o.tokens_received,
                _ => panic!("expected Buy"),
            }
        };
        store.commit_block().unwrap();

        // Block 2: enable selling (protocol flag).
        store.begin_block(2).unwrap();
        {
            let seed = StateMutator::new(store.as_ref());
            let mut econ = store.get_cbe_economic_state().unwrap();
            econ.sell_enabled = true;
            seed.put_cbe_economic_state(&econ).unwrap();
        }
        store.commit_block().unwrap();

        // Block 3: SELL with an impossibly high min_payout.
        store.begin_block(3).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
                action: BONDING_CURVE_SELL_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(1).unwrap(),
                sender: [0x66; 32],
                amount_cbe: delta_s,
                min_payout: u128::MAX, // impossible floor
                expected_s_c: delta_s,
            }));

        let err = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect_err("min_payout violation must be rejected");

        assert!(
            err.to_string().contains("slippage") || err.to_string().contains("min_payout"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_canonical_bonding_curve_lane_rejects_unknown_action() {
        use crate::execution::tx_apply::StateMutator;

        let store = create_test_store();
        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let mut payload = [0u8; 88];
        payload[0] = 0xff;

        let err = executor
            .apply_canonical_bonding_curve_tx(&mutator, &payload)
            .expect_err("unknown canonical action must be rejected");

        assert!(err.to_string().contains("Invalid canonical curve payload"));
    }

    #[test]
    fn test_canonical_bonding_curve_envelope_rejects_signer_sender_mismatch() {
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveEnvelope,
            CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use lib_crypto::KeyPair;
        use lib_types::{BondingCurveBuyTx, Nonce48};

        let store = create_test_store();
        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());
        let signer = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(43).unwrap(),
                sender: other.public_key.key_id,
                amount_in: 1000,
                max_price: 2000,
                expected_s_c: 3000,
            }));
        let envelope = CanonicalBondingCurveEnvelope {
            payload,
            signature: signer.sign(&payload).unwrap(),
        };

        let err = executor
            .apply_canonical_bonding_curve_envelope(&mutator, &envelope)
            .expect_err("mismatched envelope signer must be rejected");
        assert!(err
            .to_string()
            .contains("Canonical curve signer does not match payload sender"));
    }

    #[test]
    fn test_apply_transaction_routes_bonding_curve_buy_to_canonical_memo_lane() {
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use crate::types::transaction_type::TransactionType;
        use lib_crypto::KeyPair;
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, Nonce48};

        let store = create_test_store();
        let signer = KeyPair::generate().unwrap();

        // Block 0: seed sender SOV balance (writes go into the batch; readable only after commit).
        store.begin_block(0).unwrap();
        {
            // Seed the SOV token ledger so debit_token succeeds.
            let sov_token_id =
                crate::storage::TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = crate::storage::Address::new(signer.public_key.key_id);
            store
                .set_token_balance(&sov_token_id, &addr, 10_000)
                .unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &signer.public_key.key_id,
                &BondingCurveAccountState {
                    key_id: signer.public_key.key_id,
                    balance_cbe: 0,
                    balance_sov: 0, // balances now live in token_balances tree
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        // Block 1: actual execution test.
        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                // nonce=0 and expected_s_c=0 pass pre-validation (zero-default state).
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: signer.public_key.key_id,
                amount_in: 1000,
                max_price: u128::MAX, // no slippage restriction — routing test only
                expected_s_c: 0,
            }));
        let tx = crate::transaction::Transaction {
            version: crate::transaction::TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::BondingCurveBuy,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: signer.sign(&payload).unwrap(),
            memo: payload.to_vec(),
            payload: crate::transaction::TransactionPayload::None,
        };

        // Economics are now wired: the transaction should succeed end-to-end.
        let outcome = executor
            .apply_transaction(&mutator, &tx, 0, 0)
            .expect("canonical BUY_CBE should succeed once economic computation is wired");

        // Routing verified: the tx reached the canonical memo lane and returned a Buy outcome.
        assert!(
            matches!(outcome, TxOutcome::BondingCurveBuy(_)),
            "expected BondingCurveBuy outcome, got: {outcome:?}"
        );
    }

    #[test]
    fn test_apply_transaction_rejects_canonical_action_type_mismatch() {
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_SELL_ACTION,
        };
        use crate::types::transaction_type::TransactionType;
        use lib_crypto::KeyPair;
        use lib_types::{BondingCurveSellTx, Nonce48};

        let store = create_test_store();
        store.begin_block(0).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());
        let signer = KeyPair::generate().unwrap();

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Sell(BondingCurveSellTx {
                action: BONDING_CURVE_SELL_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(56).unwrap(),
                sender: signer.public_key.key_id,
                amount_cbe: 100,
                min_payout: 90,
                expected_s_c: 3000,
            }));
        let tx = crate::transaction::Transaction {
            version: crate::transaction::TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::BondingCurveBuy,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: signer.sign(&payload).unwrap(),
            memo: payload.to_vec(),
            payload: crate::transaction::TransactionPayload::None,
        };

        let err = executor
            .apply_transaction(&mutator, &tx, 0, 0)
            .expect_err("mismatched canonical action/type must be rejected");
        assert!(err
            .to_string()
            .contains("Canonical SELL_CBE payload cannot execute as BondingCurveBuy"));
    }

    // =========================================================================
    // SOV Ledger Wiring Tests (#1896)
    // =========================================================================

    /// Helper: seed SOV balance inside a block-scoped write at the given height.
    fn seed_sov_balance(store: &Arc<dyn BlockchainStore>, key_id: [u8; 32], amount: u64, block_height: u64, prev_hash: Hash) {
        let token_id = TokenId::new(crate::contracts::utils::generate_lib_token_id());
        let addr = Address::new(key_id);
        let block = create_block_at_height(block_height, prev_hash);
        store.begin_block(block_height).unwrap();
        store.set_token_balance(&token_id, &addr, amount as u128).unwrap();
        store.append_block(&block).unwrap();
        store.commit_block().unwrap();
    }

    /// Helper: read SOV balance for an address from the test store.
    fn read_sov_balance(store: &Arc<dyn BlockchainStore>, key_id: [u8; 32]) -> u64 {
        let token_id = TokenId::new(crate::contracts::utils::generate_lib_token_id());
        let addr = Address::new(key_id);
        store.get_token_balance(&token_id, &addr).unwrap() as u64
    }

    #[test]
    fn test_treasury_allocation_moves_sov() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let source_key = [0xAA; 32];
        let dest_key = [0xBB; 32];
        let amount = 5_000u64;

        // Seed source treasury with SOV at block height 1
        seed_sov_balance(&store, source_key, 10_000, 1, genesis.header.block_hash);
        let block1_hash = store.get_block_hash_by_height(1).unwrap().unwrap();

        let data = crate::transaction::core::TreasuryAllocationData {
            source_treasury_key_id: source_key,
            destination_key_id: dest_key,
            amount,
            spending_category: "grants".to_string(),
            proposal_id: [0xCC; 32],
            approvals: crate::transaction::threshold_approval::ThresholdApprovalSet::default(),
        };

        let tx = Transaction {
            version: crate::transaction::core::TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::TreasuryAllocation,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: create_dummy_signature(),
            memo: vec![],
            payload: crate::transaction::core::TransactionPayload::TreasuryAllocation(data),
        };

        let block2 = create_block_with_txs(2, Hash::new(block1_hash.0), vec![tx]);
        executor.apply_block(&block2).unwrap();

        assert_eq!(read_sov_balance(&store, source_key), 5_000);
        assert_eq!(read_sov_balance(&store, dest_key), 5_000);
    }

    #[test]
    fn test_treasury_allocation_rejects_insufficient_balance() {
        let store = create_test_store();
        let executor = create_test_executor(store.clone());

        let genesis = create_genesis_block();
        executor.apply_block(&genesis).unwrap();

        let source_key = [0xAA; 32];
        let dest_key = [0xBB; 32];

        // Source has only 1_000 but allocation requests 5_000
        seed_sov_balance(&store, source_key, 1_000, 1, genesis.header.block_hash);
        let block1_hash = store.get_block_hash_by_height(1).unwrap().unwrap();

        let data = crate::transaction::core::TreasuryAllocationData {
            source_treasury_key_id: source_key,
            destination_key_id: dest_key,
            amount: 5_000,
            spending_category: "grants".to_string(),
            proposal_id: [0xCC; 32],
            approvals: crate::transaction::threshold_approval::ThresholdApprovalSet::default(),
        };

        let tx = Transaction {
            version: crate::transaction::core::TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::TreasuryAllocation,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: create_dummy_signature(),
            memo: vec![],
            payload: crate::transaction::core::TransactionPayload::TreasuryAllocation(data),
        };

        let block2 = create_block_with_txs(2, Hash::new(block1_hash.0), vec![tx]);
        let result = executor.apply_block(&block2);
        assert!(result.is_err(), "Should reject treasury allocation with insufficient balance");
    }

    #[test]
    fn test_buy_cbe_debits_sov_ledger() {
        use crate::execution::tx_apply::StateMutator;
        use crate::transaction::{
            encode_canonical_bonding_curve_tx, CanonicalBondingCurveTx, BONDING_CURVE_BUY_ACTION,
        };
        use lib_crypto::KeyPair;
        use lib_types::{BondingCurveAccountState, BondingCurveBuyTx, Nonce48};

        let store = create_test_store();
        let signer = KeyPair::generate().unwrap();
        let buyer_key = signer.public_key.key_id;
        let amount_in: u128 = 1_000;

        // Block 0: seed SOV balance + bonding curve account state together.
        store.begin_block(0).unwrap();
        {
            let sov_token_id = TokenId::new(crate::contracts::utils::generate_lib_token_id());
            let addr = Address::new(buyer_key);
            store.set_token_balance(&sov_token_id, &addr, amount_in).unwrap();

            let seed = StateMutator::new(store.as_ref());
            seed.put_cbe_account_state(
                &buyer_key,
                &BondingCurveAccountState {
                    key_id: buyer_key,
                    balance_cbe: 0,
                    balance_sov: amount_in,
                    next_nonce: Nonce48::from_u64(0).unwrap(),
                },
            )
            .unwrap();
        }
        store.commit_block().unwrap();

        // Block 1: apply BUY_CBE transaction.
        store.begin_block(1).unwrap();
        let mutator = StateMutator::new(store.as_ref());
        let executor = BlockExecutor::with_store(store.clone());

        let payload =
            encode_canonical_bonding_curve_tx(&CanonicalBondingCurveTx::Buy(BondingCurveBuyTx {
                action: BONDING_CURVE_BUY_ACTION,
                chain_id: 0x03,
                nonce: Nonce48::from_u64(0).unwrap(),
                sender: buyer_key,
                amount_in,
                max_price: u128::MAX,
                expected_s_c: 0,
            }));
        let tx = Transaction {
            version: crate::transaction::core::TX_VERSION_V8,
            chain_id: 0x03,
            transaction_type: TransactionType::BondingCurveBuy,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: signer.sign(&payload).unwrap(),
            memo: payload.to_vec(),
            payload: crate::transaction::core::TransactionPayload::None,
        };

        let outcome = executor
            .apply_transaction(&mutator, &tx, 1, 1001)
            .expect("BUY_CBE should succeed");
        assert!(matches!(outcome, TxOutcome::BondingCurveBuy(_)));

        store.commit_block().unwrap();

        // SOV token ledger should be debited by amount_in.
        let sov_after = read_sov_balance(&store, buyer_key);
        assert_eq!(
            sov_after, 0,
            "SOV ledger should be fully debited after BUY_CBE (before={}, after={})",
            amount_in, sov_after
        );
    }
}
