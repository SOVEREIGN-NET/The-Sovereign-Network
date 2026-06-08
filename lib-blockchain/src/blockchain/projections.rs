use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::block::Block;
use crate::blockchain::Blockchain;
// Reviewer (Sonar S2208): explicit imports instead of `use crate::projections::*`.
// All projection table + record types this module operates on are listed here so
// callers/code-search can see the exact dependency surface.
use crate::projections::{
    pouw_mint_key, ContractBlockProjectionRecord, ContractBlockProjectionTable,
    CredentialProjectionRecord, CredentialProjectionTable, DaoRegistryProjectionRecord,
    DaoRegistryProjectionTable, DidUsernameProjectionRecord, DidUsernameProjectionTable,
    DomainProjectionRecord, DomainProjectionTable, EmploymentProjectionRecord,
    EmploymentProjectionTable, GatewayProjectionRecord, GatewayProjectionTable,
    HotStateProjectionMeta, HotStateProjectionMetaTable, PouwMintProjectionRecord,
    PouwMintProjectionTable, ValidatorProjectionRecord, ValidatorProjectionTable,
    HOT_STATE_PROJECTION_VERSION,
};
use crate::storage::table::TableAccess;
use crate::storage::BlockchainStore;
use crate::transaction::Transaction;
use crate::types::transaction_type::TransactionType;

const META_KEY: &str = "hot_state";

impl Blockchain {
    /// Stage all projection updates derived from a freshly-applied block.
    ///
    /// Sonar S3776: previously this function reached cognitive complexity 46
    /// because every tx-type branch was inlined. It is now a thin loop that
    /// delegates to one helper per concern, keeping per-function complexity
    /// well under the 15-CC limit while preserving the original behaviour
    /// exactly.
    pub(crate) fn stage_hot_state_projection_updates(
        &self,
        store: &dyn BlockchainStore,
        block: &Block,
    ) -> Result<()> {
        let height = block.height();

        for tx in &block.transactions {
            self.stage_validator_for_tx(store, tx, height)?;
            self.stage_gateway_for_tx(store, tx, height)?;
            self.stage_tx_type_specific(store, tx, height)?;
            self.stage_dao_registry_for_tx(store, tx, height)?;
        }

        self.stage_contract_blocks(store)?;
        self.stage_hot_state_projection_meta(store, block)
    }

    fn stage_validator_for_tx(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        let Some(vd) = tx.validator_data() else {
            return Ok(());
        };
        let Some(info) = self.validator_registry.get(&vd.identity_id) else {
            return Ok(());
        };
        store.stage::<ValidatorProjectionTable>(
            vd.identity_id.as_str(),
            &ValidatorProjectionRecord {
                info: info.clone(),
                committed_at_height: height,
            },
        )?;
        Ok(())
    }

    fn stage_gateway_for_tx(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        let Some(gd) = tx.gateway_data() else {
            return Ok(());
        };
        let Some(info) = self.gateway_registry.get(&gd.identity_id) else {
            return Ok(());
        };
        store.stage::<GatewayProjectionTable>(
            gd.identity_id.as_str(),
            &GatewayProjectionRecord {
                info: info.clone(),
                committed_at_height: height,
            },
        )?;
        Ok(())
    }

    /// Dispatch on `transaction_type` for the per-type staging branches.
    /// Each branch is its own helper to keep complexity low; types not
    /// listed here have no projection effect.
    fn stage_tx_type_specific(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        match tx.transaction_type {
            TransactionType::DomainRegistration => {
                self.stage_domain_from_registration_memo(store, tx, height)
            }
            TransactionType::DomainUpdate => {
                self.stage_domain_from_update_memo(store, tx, height)
            }
            TransactionType::RegisterCredential => {
                if let crate::transaction::TransactionPayload::RegisterCredential(ref data) =
                    tx.payload
                {
                    self.stage_credential_projection(store, &data.username, height)?;
                }
                Ok(())
            }
            TransactionType::UpdateCredentialPassword => {
                if let crate::transaction::TransactionPayload::UpdateCredentialPassword(
                    ref data,
                ) = tx.payload
                {
                    self.stage_credential_projection(store, &data.username, height)?;
                }
                Ok(())
            }
            TransactionType::CreateEmploymentContract => {
                self.stage_employment_contracts(store)
            }
            TransactionType::TokenMint => self.stage_pouw_mint_for_tx(store, tx, height),
            _ => Ok(()),
        }
    }

    fn stage_domain_from_registration_memo(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        let Ok(payload) = crate::transaction::DomainRegistrationPayload::decode_memo(&tx.memo)
        else {
            return Ok(());
        };
        let Some(record) = self.domain_registry.get(&payload.domain) else {
            return Ok(());
        };
        store.stage::<DomainProjectionTable>(
            payload.domain.as_str(),
            &DomainProjectionRecord {
                record: record.clone(),
                committed_at_height: height,
            },
        )?;
        Ok(())
    }

    fn stage_domain_from_update_memo(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        let Ok(payload) = crate::transaction::DomainUpdatePayload::decode_memo(&tx.memo) else {
            return Ok(());
        };
        let Some(record) = self.domain_registry.get(&payload.domain) else {
            return Ok(());
        };
        store.stage::<DomainProjectionTable>(
            payload.domain.as_str(),
            &DomainProjectionRecord {
                record: record.clone(),
                committed_at_height: height,
            },
        )?;
        Ok(())
    }

    fn stage_employment_contracts(&self, store: &dyn BlockchainStore) -> Result<()> {
        for contract in &self.employment_registry.contracts {
            store.stage::<EmploymentProjectionTable>(
                &hex::encode(contract.contract_id),
                &EmploymentProjectionRecord {
                    contract: contract.clone(),
                    committed_at_height: contract.start_height,
                },
            )?;
        }
        Ok(())
    }

    fn stage_pouw_mint_for_tx(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        if !tx.memo.starts_with(b"pouw:mint:") {
            return Ok(());
        }
        let Some(mint) = tx.token_mint_data() else {
            return Ok(());
        };
        let tx_hash = tx.hash().as_array();
        let key = pouw_mint_key(&mint.to, &tx_hash);
        store.stage::<PouwMintProjectionTable>(
            &key,
            &PouwMintProjectionRecord {
                recipient: mint.to,
                mint: crate::blockchain::PouwMintRecord {
                    amount: mint.amount,
                    block_height: height,
                    tx_hash,
                },
            },
        )?;
        Ok(())
    }

    fn stage_dao_registry_for_tx(
        &self,
        store: &dyn BlockchainStore,
        tx: &Transaction,
        height: u64,
    ) -> Result<()> {
        let Some(entry) = Self::dao_registry_entry_from_tx(tx, height) else {
            return Ok(());
        };
        let dao_id = entry.dao_id;
        store.stage::<DaoRegistryProjectionTable>(
            &dao_id,
            &DaoRegistryProjectionRecord { entry },
        )?;
        Ok(())
    }

    fn stage_contract_blocks(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (contract_id, block_height) in &self.contract_blocks {
            store.stage::<ContractBlockProjectionTable>(
                contract_id,
                &ContractBlockProjectionRecord {
                    contract_id: *contract_id,
                    block_height: *block_height,
                },
            )?;
        }
        Ok(())
    }

    fn stage_credential_projection(
        &self,
        store: &dyn BlockchainStore,
        username: &str,
        height: u64,
    ) -> Result<()> {
        let Some(credential) = self.credential_registry.get(username) else {
            return Ok(());
        };
        store.stage::<CredentialProjectionTable>(
            username,
            &CredentialProjectionRecord {
                credential: credential.clone(),
                committed_at_height: height,
            },
        )?;
        store.stage::<DidUsernameProjectionTable>(
            credential.owner_did.as_str(),
            &DidUsernameProjectionRecord {
                username: username.to_owned(),
                committed_at_height: height,
            },
        )?;
        Ok(())
    }

    fn stage_hot_state_projection_meta(
        &self,
        store: &dyn BlockchainStore,
        block: &Block,
    ) -> Result<()> {
        let meta = HotStateProjectionMeta {
            version: HOT_STATE_PROJECTION_VERSION,
            height: block.height(),
            block_hash: block.hash().as_array(),
            completed_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            validators: self.validator_registry.len(),
            gateways: self.gateway_registry.len(),
            domains: self.domain_registry.len(),
            credentials: self.credential_registry.len(),
            employment_contracts: self.employment_registry.contracts.len(),
            dao_entries: self.dao_registry_index.len(),
            pouw_mints: self.pouw_mint_index.values().map(Vec::len).sum(),
            contract_blocks: self.contract_blocks.len(),
        };
        store.stage::<HotStateProjectionMetaTable>(META_KEY, &meta)?;
        Ok(())
    }

    pub(crate) fn hot_state_projection_is_current(
        store: &dyn BlockchainStore,
        latest_height: u64,
    ) -> Result<bool> {
        let Some(block_hash) = store.get_block_hash_by_height(latest_height)? else {
            return Ok(false);
        };
        let Some(meta) = store.get::<HotStateProjectionMetaTable>(META_KEY)? else {
            return Ok(false);
        };
        Ok(meta.is_current_for(latest_height, block_hash.0))
    }

    pub(crate) fn hydrate_hot_state_from_projections(
        &mut self,
        store: &dyn BlockchainStore,
        latest_height: u64,
    ) -> Result<bool> {
        if !Self::hot_state_projection_is_current(store, latest_height)? {
            return Ok(false);
        }

        self.validator_registry.clear();
        self.validator_blocks.clear();
        for (_, record) in store.iter::<ValidatorProjectionTable>()? {
            self.validator_blocks
                .insert(record.info.identity_id.clone(), record.committed_at_height);
            self.validator_registry
                .insert(record.info.identity_id.clone(), record.info);
        }

        self.gateway_registry.clear();
        self.gateway_blocks.clear();
        for (_, record) in store.iter::<GatewayProjectionTable>()? {
            self.gateway_blocks
                .insert(record.info.identity_id.clone(), record.committed_at_height);
            self.gateway_registry
                .insert(record.info.identity_id.clone(), record.info);
        }

        self.domain_registry.clear();
        for (_, record) in store.iter::<DomainProjectionTable>()? {
            self.domain_registry
                .insert(record.record.domain.clone(), record.record);
        }

        self.credential_registry.clear();
        for (_, record) in store.iter::<CredentialProjectionTable>()? {
            self.credential_registry
                .insert(record.credential.username.clone(), record.credential);
        }

        self.did_to_username.clear();
        for (raw_did, record) in store.iter::<DidUsernameProjectionTable>()? {
            if let Ok(did) = String::from_utf8(raw_did) {
                self.did_to_username.insert(did, record.username);
            }
        }

        self.employment_registry = crate::contracts::employment::EmploymentRegistry::new();
        for (_, record) in store.iter::<EmploymentProjectionTable>()? {
            let c = record.contract;
            self.employment_registry
                .contract_by_sid
                .entry(c.employee_sid.key_id)
                .or_default()
                .push(c.contract_id);
            self.employment_registry
                .contract_by_dao
                .entry(c.dao_id)
                .or_default()
                .push(c.contract_id);
            self.employment_registry.contracts.push(c);
        }

        self.dao_registry_index.clear();
        for (_, record) in store.iter::<DaoRegistryProjectionTable>()? {
            self.dao_registry_index
                .insert(record.entry.dao_id, record.entry);
        }

        self.pouw_mint_index.clear();
        for (_, record) in store.iter::<PouwMintProjectionTable>()? {
            self.pouw_mint_index
                .entry(record.recipient)
                .or_default()
                .push(record.mint);
        }

        self.contract_blocks.clear();
        for (_, record) in store.iter::<ContractBlockProjectionTable>()? {
            self.contract_blocks
                .insert(record.contract_id, record.block_height);
        }

        debug!(
            "hydrated hot blockchain state from projections at height {}",
            latest_height
        );
        Ok(true)
    }

    /// Rebuild projection tables from the in-memory hot state after a
    /// full replay.
    ///
    /// Sonar S3776: previously this function reached cognitive complexity
    /// 28. It is now a thin orchestrator: validate preconditions, then
    /// delegate each registry/table backfill to its own helper. The
    /// metadata-write begin/commit/rollback bracketing is preserved.
    pub(crate) fn backfill_hot_state_projections_from_replay(
        &self,
        store: &dyn BlockchainStore,
    ) -> Result<()> {
        let Some(tip) = self.backfill_resolve_tip(store)? else {
            return Ok(());
        };

        store.begin_metadata_write()?;
        let result = self.run_backfill_staging(store, &tip);
        match result {
            Ok(()) => store.commit_metadata_write().map_err(Into::into),
            Err(e) => {
                if let Err(rollback) = store.rollback_block() {
                    warn!(
                        "failed to roll back projection backfill metadata batch: {}",
                        rollback
                    );
                }
                Err(e)
            }
        }
    }

    /// Resolve the chain tip we'll backfill against, or `None` if the
    /// backfill should be skipped (no chain data, or projections already
    /// current). Centralising the preconditions keeps the caller flat.
    fn backfill_resolve_tip(
        &self,
        store: &dyn BlockchainStore,
    ) -> Result<Option<Block>> {
        let latest_height = match store.latest_height() {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };
        if latest_height == 0 && store.get_block_by_height(0)?.is_none() {
            return Ok(None);
        }
        if Self::hot_state_projection_is_current(store, latest_height).unwrap_or(false) {
            return Ok(None);
        }
        Ok(store.get_block_by_height(latest_height)?)
    }

    /// Single failure-domain wrapper around the per-table backfill calls.
    /// Returning `Result<()>` from one place lets the outer rollback path
    /// stay simple.
    fn run_backfill_staging(
        &self,
        store: &dyn BlockchainStore,
        tip: &Block,
    ) -> Result<()> {
        self.clear_projection_tables(store)?;
        self.backfill_validators(store)?;
        self.backfill_gateways(store)?;
        self.backfill_domains(store)?;
        self.backfill_credentials(store)?;
        self.backfill_did_to_username(store)?;
        self.backfill_employment(store)?;
        self.backfill_dao_registry(store)?;
        self.backfill_pouw_mints(store)?;
        self.stage_contract_blocks(store)?;
        self.stage_hot_state_projection_meta(store, tip)
    }

    fn backfill_validators(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (id, info) in &self.validator_registry {
            let committed_at_height = self.validator_blocks.get(id).copied().unwrap_or(0);
            store.stage::<ValidatorProjectionTable>(
                id.as_str(),
                &ValidatorProjectionRecord {
                    info: info.clone(),
                    committed_at_height,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_gateways(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (id, info) in &self.gateway_registry {
            let committed_at_height = self.gateway_blocks.get(id).copied().unwrap_or(0);
            store.stage::<GatewayProjectionTable>(
                id.as_str(),
                &GatewayProjectionRecord {
                    info: info.clone(),
                    committed_at_height,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_domains(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (domain, record) in &self.domain_registry {
            store.stage::<DomainProjectionTable>(
                domain.as_str(),
                &DomainProjectionRecord {
                    record: record.clone(),
                    committed_at_height: record.registered_at,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_credentials(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (username, credential) in &self.credential_registry {
            store.stage::<CredentialProjectionTable>(
                username.as_str(),
                &CredentialProjectionRecord {
                    credential: credential.clone(),
                    committed_at_height: credential.registered_at_height,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_did_to_username(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (did, username) in &self.did_to_username {
            let committed_at_height = self
                .credential_registry
                .get(username)
                .map(|c| c.registered_at_height)
                .unwrap_or(0);
            store.stage::<DidUsernameProjectionTable>(
                did.as_str(),
                &DidUsernameProjectionRecord {
                    username: username.clone(),
                    committed_at_height,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_employment(&self, store: &dyn BlockchainStore) -> Result<()> {
        for contract in &self.employment_registry.contracts {
            store.stage::<EmploymentProjectionTable>(
                &hex::encode(contract.contract_id),
                &EmploymentProjectionRecord {
                    contract: contract.clone(),
                    committed_at_height: contract.start_height,
                },
            )?;
        }
        Ok(())
    }

    fn backfill_dao_registry(&self, store: &dyn BlockchainStore) -> Result<()> {
        for entry in self.dao_registry_index.values() {
            store.stage::<DaoRegistryProjectionTable>(
                &entry.dao_id,
                &DaoRegistryProjectionRecord {
                    entry: entry.clone(),
                },
            )?;
        }
        Ok(())
    }

    fn backfill_pouw_mints(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (recipient, records) in &self.pouw_mint_index {
            for mint in records {
                let key = pouw_mint_key(recipient, &mint.tx_hash);
                store.stage::<PouwMintProjectionTable>(
                    &key,
                    &PouwMintProjectionRecord {
                        recipient: *recipient,
                        mint: mint.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn clear_projection_tables(&self, store: &dyn BlockchainStore) -> Result<()> {
        for (key, _) in store.iter::<ValidatorProjectionTable>()? {
            store.stage_delete::<ValidatorProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<GatewayProjectionTable>()? {
            store.stage_delete::<GatewayProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<DomainProjectionTable>()? {
            store.stage_delete::<DomainProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<CredentialProjectionTable>()? {
            store.stage_delete::<CredentialProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<DidUsernameProjectionTable>()? {
            store.stage_delete::<DidUsernameProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<EmploymentProjectionTable>()? {
            store.stage_delete::<EmploymentProjectionTable>(std::str::from_utf8(&key)?)?;
        }
        for (key, _) in store.iter::<DaoRegistryProjectionTable>()? {
            if key.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                store.stage_delete::<DaoRegistryProjectionTable>(&arr)?;
            }
        }
        for (key, _) in store.iter::<PouwMintProjectionTable>()? {
            if key.len() == 64 {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&key);
                store.stage_delete::<PouwMintProjectionTable>(&arr)?;
            }
        }
        for (key, _) in store.iter::<ContractBlockProjectionTable>()? {
            if key.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                store.stage_delete::<ContractBlockProjectionTable>(&arr)?;
            }
        }
        store.stage_delete::<HotStateProjectionMetaTable>(META_KEY)?;
        Ok(())
    }
}
