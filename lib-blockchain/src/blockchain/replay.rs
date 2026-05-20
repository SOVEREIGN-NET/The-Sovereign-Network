//! Block replay for state reconstruction.
//!
//! On startup, if sled has blocks but in-memory registries are empty,
//! replay all blocks to rebuild the full in-memory state. This is the
//! single source of truth — block history defines all derived state.
//!
//! No sled writes happen during replay (self.store is None).
//! No event publishing. No broadcast. Just state reconstruction.

use anyhow::Result;
use tracing::{debug, info, warn};

use crate::block::Block;
use crate::blockchain::Blockchain;

impl Blockchain {
    /// Replay a single block's transactions to rebuild in-memory state.
    ///
    /// Does NOT write to sled. Does NOT validate signatures or fees.
    /// Assumes blocks are fed in order (height 0 to tip).
    ///
    /// For height 0: also applies genesis-specific state (council, allocations)
    /// that was populated via direct inserts in build_block0(), not via transactions.
    pub fn replay_block_state(&mut self, block: &Block) -> Result<()> {
        let height = block.height();

        // Genesis-specific state: council, allocations, SOV token
        if height == 0 {
            if let Ok(cfg) = crate::genesis::GenesisConfig::from_embedded() {
                let _ = cfg.apply_genesis_state(self);
            }
            self.replay_ensure_sov_token();
        }

        // Process all transaction types (same order as finish_block_processing)
        self.process_identity_transactions(block)?;
        self.process_wallet_transactions(block)?;
        self.process_entity_registry_transactions(block)?;
        self.process_employment_contract_transactions(block)?;
        self.process_domain_transactions(block);
        self.process_credential_transactions(block);
        self.process_validator_registration_transactions(block);
        self.process_gateway_transactions(block);
        self.process_contract_transactions(block)?;
        self.process_token_transactions(block)?;
        self.process_nft_transactions(block);

        // DAO registry indexing
        for tx in &block.transactions {
            self.index_dao_registry_entry_from_tx(tx, height);
        }

        // On-ramp trades
        self.process_on_ramp_trade_transactions(block);

        // Oracle attestations
        self.process_oracle_attestation_transactions(block, block.header.timestamp);

        // Economic features
        if let Err(e) = self.process_ubi_claim_transactions(block) {
            debug!("Replay: UBI claim error at height {}: {} (non-fatal)", height, e);
        }
        if let Err(e) = self.process_profit_declarations(block) {
            debug!("Replay: profit declaration error at height {}: {} (non-fatal)", height, e);
        }

        // Oracle epoch advancement
        if self
            .oracle_state
            .should_process_epoch(block.header.timestamp, self.last_oracle_epoch_processed)
        {
            let block_epoch = self.oracle_state.epoch_id(block.header.timestamp);
            self.oracle_state.apply_pending_updates(block_epoch);
            self.apply_pending_committee_removals(block_epoch);
            self.last_oracle_epoch_processed = block.header.timestamp;
        }

        // Governance proposals
        if let Err(e) = self.process_approved_governance_proposals() {
            debug!("Replay: governance error at height {}: {} (non-fatal)", height, e);
        }

        // Update chain state
        self.height = height;

        Ok(())
    }

    /// Replay all blocks from a store to fully reconstruct in-memory state.
    ///
    /// Called on startup when sled has blocks. Creates a fully populated
    /// Blockchain with all registries, validators, domains, credentials, etc.
    pub fn replay_from_store(
        store: std::sync::Arc<dyn crate::storage::BlockchainStore>,
    ) -> Result<Option<Self>> {
        let latest_height = match store.latest_height() {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };

        // Check if store actually has block 0
        if store.get_block_by_height(0)?.is_none() {
            return Ok(None);
        }

        info!(
            "Replaying {} blocks from sled to rebuild in-memory state...",
            latest_height + 1
        );

        let start = std::time::Instant::now();
        let mut bc = Self::new_runtime_state();
        // store is None during replay — prevents sled writes from process_* functions
        bc.blocks.clear();

        for height in 0..=latest_height {
            let block = store
                .get_block_by_height(height)?
                .ok_or_else(|| anyhow::anyhow!("Missing block at height {} — sled corrupted", height))?;

            bc.replay_block_state(&block)?;
            bc.blocks.push(block);
        }

        let elapsed = start.elapsed();
        info!(
            "Replay complete: {} blocks in {:.2}s — {} identities, {} wallets, {} validators, {} domains, {} credentials",
            latest_height + 1,
            elapsed.as_secs_f64(),
            bc.identity_registry.len(),
            bc.wallet_registry.len(),
            bc.validator_registry.len(),
            bc.domain_registry.len(),
            bc.credential_registry.len(),
        );

        // Post-replay: attach store and executor
        bc.replay_ensure_treasury();

        // Now attach the store (enables sled writes for future blocks)
        let executor = std::sync::Arc::new(
            crate::execution::executor::BlockExecutor::new_catchup_sync(
                store.clone(),
                crate::execution::executor::FeeModelV2::default(),
                Default::default(),
            ),
        );
        bc.store = Some(store);
        bc.executor = Some(executor);

        // Rebuild the PoUW mint index from the replayed blocks so
        // /api/v1/pouw/rewards reports the full on-chain history. (The
        // per-block hook in process_token_transactions also populates it
        // during replay; this is an idempotent, authoritative re-scan.)
        bc.rebuild_pouw_mint_index();

        // Backfill genesis-only identities into the sled store. Genesis
        // populates bc.identity_registry directly without going through
        // transactions, so identities created at genesis are absent from
        // sled's identity tree. Any later IdentityUpdate against them halts
        // consensus with "Cannot update non-existent identity".
        bc.backfill_genesis_identities_to_store();

        Ok(Some(bc))
    }

    /// Ensure every in-memory genesis identity is also present in the sled
    /// identity store. Idempotent — overwrites existing entries with the
    /// genesis-derived consensus + metadata.
    fn backfill_genesis_identities_to_store(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        let mut written = 0usize;
        for (did, data) in &self.identity_registry {
            let did_hash = crate::storage::did_to_hash(did);
            // Skip if already present (avoids overwriting state that may have
            // diverged via on-chain updates).
            match store.get_identity(&did_hash) {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        "backfill: get_identity({}) failed: {} — attempting write anyway",
                        did,
                        e
                    );
                }
            }
            let (consensus, metadata) = crate::storage::convert_legacy_identity(data);
            if let Err(e) = store.put_identity_direct(&did_hash, &consensus) {
                tracing::warn!("backfill: put_identity_direct({}): {}", did, e);
                continue;
            }
            if let Err(e) = store.put_identity_metadata_direct(&did_hash, &metadata) {
                tracing::warn!("backfill: put_identity_metadata_direct({}): {}", did, e);
                continue;
            }
            written += 1;
        }
        if written > 0 {
            tracing::info!(
                "Backfilled {} genesis identities into sled identity store",
                written
            );
        }
    }

    /// Ensure SOV token contract exists during replay (idempotent).
    fn replay_ensure_sov_token(&mut self) {
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        self.token_contracts
            .entry(sov_id)
            .or_insert_with(crate::contracts::TokenContract::new_sov_native);
    }

    /// Ensure treasury wallet is set during replay (idempotent).
    fn replay_ensure_treasury(&mut self) {
        if self.dao_treasury_wallet_id.is_none() {
            if let Some(member) = self.council_members.first() {
                if !member.wallet_id.is_empty() {
                    self.dao_treasury_wallet_id = Some(member.wallet_id.clone());
                }
            }
        }
    }
}
