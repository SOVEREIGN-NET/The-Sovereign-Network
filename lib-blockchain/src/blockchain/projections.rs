use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::projections::*;
use crate::storage::table::TableAccess;
use crate::storage::BlockchainStore;
use crate::types::transaction_type::TransactionType;

const META_KEY: &str = "hot_state";

impl Blockchain {
    pub(crate) fn stage_hot_state_projection_updates(
        &self,
        store: &dyn BlockchainStore,
        block: &Block,
    ) -> Result<()> {
        let height = block.height();

        for tx in &block.transactions {
            if let Some(vd) = tx.validator_data() {
                if let Some(info) = self.validator_registry.get(&vd.identity_id) {
                    store.stage::<ValidatorProjectionTable>(
                        vd.identity_id.as_str(),
                        &ValidatorProjectionRecord {
                            info: info.clone(),
                            committed_at_height: height,
                        },
                    )?;
                }
            }

            if let Some(gd) = tx.gateway_data() {
                if let Some(info) = self.gateway_registry.get(&gd.identity_id) {
                    store.stage::<GatewayProjectionTable>(
                        gd.identity_id.as_str(),
                        &GatewayProjectionRecord {
                            info: info.clone(),
                            committed_at_height: height,
                        },
                    )?;
                }
            }

            match tx.transaction_type {
                TransactionType::DomainRegistration => {
                    if let Ok(payload) =
                        crate::transaction::DomainRegistrationPayload::decode_memo(&tx.memo)
                    {
                        if let Some(record) = self.domain_registry.get(&payload.domain) {
                            store.stage::<DomainProjectionTable>(
                                payload.domain.as_str(),
                                &DomainProjectionRecord {
                                    record: record.clone(),
                                    committed_at_height: height,
                                },
                            )?;
                        }
                    }
                }
                TransactionType::DomainUpdate => {
                    if let Ok(payload) =
                        crate::transaction::DomainUpdatePayload::decode_memo(&tx.memo)
                    {
                        if let Some(record) = self.domain_registry.get(&payload.domain) {
                            store.stage::<DomainProjectionTable>(
                                payload.domain.as_str(),
                                &DomainProjectionRecord {
                                    record: record.clone(),
                                    committed_at_height: height,
                                },
                            )?;
                        }
                    }
                }
                TransactionType::RegisterCredential => {
                    if let crate::transaction::TransactionPayload::RegisterCredential(ref data) =
                        tx.payload
                    {
                        self.stage_credential_projection(store, &data.username, height)?;
                    }
                }
                TransactionType::UpdateCredentialPassword => {
                    if let crate::transaction::TransactionPayload::UpdateCredentialPassword(
                        ref data,
                    ) = tx.payload
                    {
                        self.stage_credential_projection(store, &data.username, height)?;
                    }
                }
                TransactionType::CreateEmploymentContract => {
                    for contract in &self.employment_registry.contracts {
                        store.stage::<EmploymentProjectionTable>(
                            &hex::encode(contract.contract_id),
                            &EmploymentProjectionRecord {
                                contract: contract.clone(),
                                committed_at_height: contract.start_height,
                            },
                        )?;
                    }
                }
                TransactionType::TokenMint => {
                    if tx.memo.starts_with(b"pouw:mint:") {
                        if let Some(mint) = tx.token_mint_data() {
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
                        }
                    }
                }
                _ => {}
            }

            if let Some(entry) = Self::dao_registry_entry_from_tx(tx, height) {
                let dao_id = entry.dao_id;
                store.stage::<DaoRegistryProjectionTable>(
                    &dao_id,
                    &DaoRegistryProjectionRecord { entry },
                )?;
            }
        }

        for (contract_id, block_height) in &self.contract_blocks {
            store.stage::<ContractBlockProjectionTable>(
                contract_id,
                &ContractBlockProjectionRecord {
                    contract_id: *contract_id,
                    block_height: *block_height,
                },
            )?;
        }

        self.stage_hot_state_projection_meta(store, block)
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

    pub(crate) fn backfill_hot_state_projections_from_replay(
        &self,
        store: &dyn BlockchainStore,
    ) -> Result<()> {
        let latest_height = match store.latest_height() {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };
        if latest_height == 0 && store.get_block_by_height(0)?.is_none() {
            return Ok(());
        }
        if Self::hot_state_projection_is_current(store, latest_height).unwrap_or(false) {
            return Ok(());
        }
        let Some(tip) = store.get_block_by_height(latest_height)? else {
            return Ok(());
        };

        store.begin_metadata_write()?;
        let result = (|| -> Result<()> {
            self.clear_projection_tables(store)?;
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
            for (domain, record) in &self.domain_registry {
                store.stage::<DomainProjectionTable>(
                    domain.as_str(),
                    &DomainProjectionRecord {
                        record: record.clone(),
                        committed_at_height: record.registered_at,
                    },
                )?;
            }
            for (username, credential) in &self.credential_registry {
                store.stage::<CredentialProjectionTable>(
                    username.as_str(),
                    &CredentialProjectionRecord {
                        credential: credential.clone(),
                        committed_at_height: credential.registered_at_height,
                    },
                )?;
            }
            for (did, username) in &self.did_to_username {
                store.stage::<DidUsernameProjectionTable>(
                    did.as_str(),
                    &DidUsernameProjectionRecord {
                        username: username.clone(),
                        committed_at_height: self
                            .credential_registry
                            .get(username)
                            .map(|c| c.registered_at_height)
                            .unwrap_or(0),
                    },
                )?;
            }
            for contract in &self.employment_registry.contracts {
                store.stage::<EmploymentProjectionTable>(
                    &hex::encode(contract.contract_id),
                    &EmploymentProjectionRecord {
                        contract: contract.clone(),
                        committed_at_height: contract.start_height,
                    },
                )?;
            }
            for entry in self.dao_registry_index.values() {
                store.stage::<DaoRegistryProjectionTable>(
                    &entry.dao_id,
                    &DaoRegistryProjectionRecord {
                        entry: entry.clone(),
                    },
                )?;
            }
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
            for (contract_id, block_height) in &self.contract_blocks {
                store.stage::<ContractBlockProjectionTable>(
                    contract_id,
                    &ContractBlockProjectionRecord {
                        contract_id: *contract_id,
                        block_height: *block_height,
                    },
                )?;
            }
            self.stage_hot_state_projection_meta(store, &tip)
        })();

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
