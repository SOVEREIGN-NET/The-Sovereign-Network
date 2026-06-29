//! Block replay for state reconstruction.
//!
//! Production startup uses [`Blockchain::load_from_store`] (sled-first hydration
//! with block-scan fallback). [`replay_from_store`] is retained as a thin
//! compatibility wrapper.

use anyhow::Result;
use tracing::{info, warn};

use crate::block::Block;
use crate::blockchain::Blockchain;

impl Blockchain {
    /// Advance replay metadata for a block (genesis registries, oracle epochs,
    /// governance). Does **not** replay transaction state — use
    /// [`load_from_store`] / executor apply for balance reconstruction.
    ///
    /// Kept as `replay_block_state` for call-site compatibility; prefer
    /// [`Self::advance_replay_metadata`] for new code.
    pub fn advance_replay_metadata(&mut self, block: &Block) -> Result<()> {
        let height = block.height();

        if height == 0 {
            if let Ok(cfg) = crate::genesis::GenesisConfig::from_embedded() {
                let _ = cfg.apply_genesis_state(self);
            }
            self.replay_ensure_sov_token();
        }

        // Oracle epoch advancement (in-memory oracle_state — not in sled apply path)
        if self
            .oracle_state
            .should_process_epoch(block.header.timestamp, self.last_oracle_epoch_processed)
        {
            let block_epoch = self.oracle_state.epoch_id(block.header.timestamp);
            self.oracle_state.apply_pending_updates(block_epoch);
            self.apply_pending_committee_removals(block_epoch);
            self.last_oracle_epoch_processed = block.header.timestamp;
        }

        if let Err(e) = self.process_approved_governance_proposals() {
            tracing::debug!(
                "Replay: governance error at height {}: {} (non-fatal)",
                height,
                e
            );
        }

        self.height = height;
        Ok(())
    }

    /// Deprecated alias for [`Self::advance_replay_metadata`].
    #[deprecated(note = "use advance_replay_metadata — this no longer replays tx state")]
    pub fn replay_block_state(&mut self, block: &Block) -> Result<()> {
        self.advance_replay_metadata(block)
    }

    /// Compatibility wrapper — delegates to [`load_from_store`].
    ///
    /// Previously replayed every block through legacy `process_*_transactions`
    /// writers. Phase 4 (#2641) makes sled the sole write path; startup state
    /// is rebuilt by projection hydration or the scan fallback inside
    /// `load_from_store`.
    pub fn replay_from_store(
        store: std::sync::Arc<dyn crate::storage::BlockchainStore>,
    ) -> Result<Option<Self>> {
        info!("replay_from_store: delegating to load_from_store (#2641)");
        Self::load_from_store(store)
    }

    /// Version-gated regeneration of the sled `identity_metadata` tree (#58).
    ///
    /// `identity_metadata` is non-consensus and fully derivable from blocks, so
    /// rather than reading old-shaped blobs out of sled (unsafe under bincode's
    /// positional, non-self-describing encoding — a missing trailing field is
    /// not defaulted, it corrupts the decode), we rebuild the whole tree from
    /// the already-replayed in-memory `identity_registry`, which carries the
    /// real `kyber_public_key` from each identity transaction.
    ///
    /// Idempotent: the persisted version gate makes repeat boots a no-op, and
    /// the rebuild itself is a clear + deterministic rewrite. A mid-way failure
    /// leaves the version behind so the next boot retries.
    pub(crate) fn migrate_identity_metadata_schema(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        let current = crate::storage::IDENTITY_METADATA_SCHEMA_VERSION;
        let persisted = match store.identity_metadata_schema_version() {
            Ok(v) => v,
            Err(e) => {
                warn!("identity_metadata schema migration: version read failed: {e} — skipping");
                return;
            }
        };
        if persisted >= current {
            return;
        }

        info!(
            "Migrating identity_metadata schema v{} -> v{}: regenerating {} records from blocks",
            persisted,
            current,
            self.identity_registry.len()
        );

        if let Err(e) = store.clear_identity_metadata() {
            warn!("identity_metadata schema migration: clear failed: {e} — aborting (version unchanged)");
            return;
        }

        let records: Vec<([u8; 32], crate::storage::IdentityMetadata)> = self
            .identity_registry
            .iter()
            .map(|(did, data)| {
                let did_hash = crate::storage::did_to_hash(did);
                let (_, metadata) = crate::storage::convert_legacy_identity(data);
                (did_hash, metadata)
            })
            .collect();
        let expected = records.len();

        let written = match store.put_identity_metadata_batch(&records) {
            Ok(n) => n,
            Err(e) => {
                warn!(
                    "identity_metadata schema migration: bulk write failed after clear: {e} \
                     — version NOT bumped, next boot will retry"
                );
                return;
            }
        };
        if written != expected {
            warn!(
                "identity_metadata schema migration: only {written}/{expected} records written \
                 — version NOT bumped, next boot will retry"
            );
            return;
        }

        if let Err(e) = store.set_identity_metadata_schema_version(current) {
            warn!("identity_metadata schema migration: version bump failed: {e} — will retry next boot");
            return;
        }

        info!("identity_metadata schema migration complete: {written} records at v{current}");
    }

    /// Version-gated regeneration of the sled `validators` tree (#56).
    pub(crate) fn migrate_validator_records_schema(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        let current = crate::storage::VALIDATOR_RECORD_SCHEMA_VERSION;
        let persisted = match store.validator_record_schema_version() {
            Ok(v) => v,
            Err(e) => {
                warn!("validator_records schema migration: version read failed: {e} — skipping");
                return;
            }
        };
        if persisted >= current {
            return;
        }

        info!(
            "Migrating validator_records schema v{} -> v{}: regenerating {} records from blocks",
            persisted,
            current,
            self.validator_registry.len()
        );

        if let Err(e) = store.clear_validator_records() {
            warn!(
                "validator_records schema migration: clear failed: {e} — aborting (version unchanged)"
            );
            return;
        }

        let records: Vec<([u8; 32], crate::storage::StoredValidatorRecord)> = self
            .validator_registry
            .iter()
            .map(|(did, info)| {
                let did_hash = crate::storage::did_to_hash(did);
                (did_hash, crate::storage::StoredValidatorRecord::from(info))
            })
            .collect();
        let expected = records.len();

        let written = match store.put_validator_record_batch(&records) {
            Ok(n) => n,
            Err(e) => {
                warn!(
                    "validator_records schema migration: bulk write failed after clear: {e} \
                     — version NOT bumped, next boot will retry"
                );
                return;
            }
        };
        if written != expected {
            warn!(
                "validator_records schema migration: only {written}/{expected} records written \
                 — version NOT bumped, next boot will retry"
            );
            return;
        }

        if let Err(e) = store.set_validator_record_schema_version(current) {
            warn!(
                "validator_records schema migration: version bump failed: {e} — will retry next boot"
            );
            return;
        }

        self.invalidate_active_validator_cache();
        info!("validator_records schema migration complete: {written} records at v{current}");
    }

    /// Ensure every in-memory genesis identity is also present in the sled
    /// identity store. Idempotent — overwrites existing entries with the
    /// genesis-derived consensus + metadata.
    pub(crate) fn backfill_genesis_identities_to_store(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        let mut written = 0usize;
        for (did, data) in &self.identity_registry {
            let did_hash = crate::storage::did_to_hash(did);
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

}

#[cfg(test)]
mod tests {
    use crate::blockchain::Blockchain;
    use crate::storage::{
        did_to_hash, BlockchainStore, IdentityMetadata, SledStore,
        IDENTITY_METADATA_SCHEMA_VERSION,
    };
    use crate::transaction::IdentityTransactionData;
    use std::sync::Arc;

    fn identity_data(did: &str, kyber: Vec<u8>) -> IdentityTransactionData {
        IdentityTransactionData {
            did: did.to_string(),
            display_name: "Migrated".to_string(),
            public_key: vec![0x11; 64],
            ownership_proof: vec![],
            identity_type: "human".to_string(),
            did_document_hash: Default::default(),
            created_at: 0,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: vec![],
            owned_wallets: vec![],
            kyber_public_key: kyber,
        }
    }

    /// #58: the schema migration backfills `kyber_public_key` into existing
    /// metadata records from the replayed in-memory registry, bumps the stored
    /// version, and is idempotent on a second run.
    ///
    /// This variant simulates the migration with a CURRENT-shape record that
    /// happens to have an empty `kyber_public_key` — exercising the
    /// clear-and-rewrite behaviour from the in-memory registry. For the
    /// "old-shaped blob is never decoded" safety property the PR claims, see
    /// `migrate_identity_metadata_schema_does_not_decode_legacy_blobs` below
    /// (CR PR #2679).
    #[test]
    fn migrate_identity_metadata_schema_backfills_kyber_and_bumps_version() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(SledStore::open(&temp.path().join("kyber_migrate")).unwrap());

        // Mark the store as pre-v2 explicitly — the version-key init in
        // SledStore::from_db now sets a brand-new empty store to current
        // (CR #2679), so an absent key alone no longer means "v1".
        let did = "did:zhtp:kyber-migrate";
        let did_hash = did_to_hash(did);
        let stale = IdentityMetadata {
            did: did.to_string(),
            display_name: "Migrated".to_string(),
            public_key: vec![0x11; 64],
            kyber_public_key: Vec::new(),
            ..Default::default()
        };
        store.put_identity_metadata_direct(&did_hash, &stale).unwrap();
        store.set_identity_metadata_schema_version(1).unwrap();
        assert_eq!(store.identity_metadata_schema_version().unwrap(), 1);

        // In-memory registry (as rebuilt by block replay) carries the real kyber.
        let mut bc = Blockchain::new().expect("construct blockchain");
        bc.identity_registry
            .insert(did.to_string(), identity_data(did, vec![0xAB; 1568]));
        bc.set_store(store.clone());

        bc.migrate_identity_metadata_schema();

        assert_eq!(
            store.identity_metadata_schema_version().unwrap(),
            IDENTITY_METADATA_SCHEMA_VERSION
        );
        let migrated = store.get_identity_metadata(&did_hash).unwrap().unwrap();
        assert_eq!(migrated.kyber_public_key, vec![0xAB; 1568]);
        assert_eq!(bc.identity_kyber_public_key(did), Some(vec![0xAB; 1568]));

        // Idempotent: the version gate makes a second run a no-op.
        bc.migrate_identity_metadata_schema();
        assert_eq!(
            store.identity_metadata_schema_version().unwrap(),
            IDENTITY_METADATA_SCHEMA_VERSION
        );
    }

    /// A store already at the current version is left untouched (no clear/rewrite).
    #[test]
    fn migrate_identity_metadata_schema_skips_when_current() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(SledStore::open(&temp.path().join("kyber_current")).unwrap());

        let did = "did:zhtp:kyber-current";
        let did_hash = did_to_hash(did);
        let meta = IdentityMetadata {
            did: did.to_string(),
            display_name: "Untouched".to_string(),
            public_key: vec![0x22; 64],
            kyber_public_key: vec![0xCD; 1568],
            ..Default::default()
        };
        store.put_identity_metadata_direct(&did_hash, &meta).unwrap();
        store
            .set_identity_metadata_schema_version(IDENTITY_METADATA_SCHEMA_VERSION)
            .unwrap();

        // Empty registry: if the migration ran it would clear the record.
        let mut bc = Blockchain::new().expect("construct blockchain");
        bc.set_store(store.clone());
        bc.migrate_identity_metadata_schema();

        // Record survives untouched because the gate short-circuited.
        let after = store.get_identity_metadata(&did_hash).unwrap().unwrap();
        assert_eq!(after.kyber_public_key, vec![0xCD; 1568]);
    }

    /// CR PR #2679: the PR description claims "No old-shaped blob is ever
    /// read" — the migration's safety property. This test plants raw bytes
    /// in `identity_metadata` that bincode-deserialise to nothing the current
    /// shape recognises (truncated junk), then runs the migration. The
    /// migration must:
    ///   1. NOT panic (would happen if any code path tried to decode the blob)
    ///   2. Replace the junk with a freshly-encoded current-shape record
    ///   3. Bump the version
    ///
    /// Implementation note: the migration calls `clear_identity_metadata`
    /// which uses `Tree::clear()` (a bulk delete without per-entry
    /// deserialisation), then writes new bytes. So even a maliciously-corrupt
    /// blob is thrown away without ever being decoded.
    #[test]
    fn migrate_identity_metadata_schema_does_not_decode_legacy_blobs() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            Arc::new(SledStore::open(&temp.path().join("kyber_junk_blob")).unwrap());

        let did = "did:zhtp:has-corrupt-blob";
        let did_hash = did_to_hash(did);

        // Plant a literally-undecodable blob in the identity_metadata tree.
        // No version of `IdentityMetadata` past or future bincode-deserialises
        // from b"NOT_A_VALID_METADATA_BLOB__" — if anyone tries to decode
        // this, they'll get an error or panic.
        store
            .put_identity_metadata_raw_bytes(&did_hash, b"NOT_A_VALID_METADATA_BLOB__")
            .unwrap();
        // Force version to 1 so the migration actually runs (the brand-new
        // store init in from_db otherwise marks it as current).
        store.set_identity_metadata_schema_version(1).unwrap();

        // In-memory registry carries the canonical record (as block replay
        // would have produced).
        let mut bc = Blockchain::new().expect("construct blockchain");
        bc.identity_registry.insert(
            did.to_string(),
            identity_data(did, vec![0xEE; 1568]),
        );
        bc.set_store(store.clone());

        // The migration must complete without ever trying to decode the
        // junk bytes that were sitting in the tree.
        bc.migrate_identity_metadata_schema();

        // Junk replaced by a clean current-shape record carrying the kyber
        // key from the in-memory registry.
        assert_eq!(
            store.identity_metadata_schema_version().unwrap(),
            IDENTITY_METADATA_SCHEMA_VERSION
        );
        let rebuilt = store.get_identity_metadata(&did_hash).unwrap().unwrap();
        assert_eq!(rebuilt.kyber_public_key, vec![0xEE; 1568]);
        assert_eq!(rebuilt.did, did);
    }
}