use crate::contracts::utils::id_generation;
use crate::contracts::integration::ContractEvent;
use crate::contracts::dao_registry::types::*;
use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DAO Registry contract
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAORegistry {
    /// Map from dao_id -> DAOEntry
    pub registry: HashMap<[u8; 32], DAOEntry>,
    /// Index from token_addr -> dao_id for fast lookup
    pub token_index: HashMap<[u8; 32], [u8; 32]>,
}

impl DAORegistry {
    /// Create empty registry
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
            token_index: HashMap::new(),
        }
    }

    /// Register a new DAO
    /// Returns (dao_id, ContractEvent::DaoRegistered)
    pub fn register_dao(
        &mut self,
        token_addr: [u8; 32],
        class: String,
        metadata_hash: Option<[u8; 32]>,
        treasury: PublicKey,
        owner: PublicKey,
    ) -> Result<([u8; 32], ContractEvent), String> {
        if self.token_index.contains_key(&token_addr) {
            return Err("DAO for token already registered".to_string());
        }

        // Generate unique DAO id using token_addr + owner + timestamp
        let timestamp = crate::utils::time::current_timestamp();
        let dao_id = id_generation::generate_contract_id(&[
            &token_addr,
            &owner.as_bytes(),
            &timestamp.to_le_bytes(),
        ]);

        let entry = DAOEntry {
            dao_id,
            token_addr,
            class: class.clone(),
            metadata_hash,
            treasury: treasury.clone(),
            owner: owner.clone(),
            created_at: timestamp,
        };

        self.registry.insert(dao_id, entry);
        self.token_index.insert(token_addr, dao_id);

        let event = ContractEvent::DaoRegistered {
            dao_id,
            token_addr,
            owner: owner.clone(),
            treasury,
            class,
            metadata_hash,
        };

        Ok((dao_id, event))
    }

    /// Lookup a DAO by token address
    pub fn get_dao(&self, token_addr: [u8; 32]) -> Result<DAOMetadata, String> {
        match self.token_index.get(&token_addr) {
            Some(dao_id) => match self.registry.get(dao_id) {
                Some(entry) => Ok(DAOMetadata {
                    dao_id: entry.dao_id,
                    token_addr: entry.token_addr,
                    class: entry.class.clone(),
                    metadata_hash: entry.metadata_hash,
                    treasury: entry.treasury.clone(),
                    owner: entry.owner.clone(),
                    created_at: entry.created_at,
                }),
                None => Err("DAO entry not found for id".to_string()),
            },
            None => Err("DAO not found for token address".to_string()),
        }
    }

    /// List all DAOs sorted by creation date ascending
    /// Note: Pagination not implemented yet; consider adding (cursor, limit) later
    pub fn list_daos(&self) -> Vec<DAOEntry> {
        let mut all: Vec<DAOEntry> = self.registry.values().cloned().collect();
        all.sort_by_key(|e| e.created_at);
        all
    }

    /// Update metadata hash for a DAO. Only owner can update metadata.
    /// Returns ContractEvent::DaoUpdated on success
    pub fn update_metadata(
        &mut self,
        dao_id: [u8; 32],
        updater: PublicKey,
        metadata_hash: Option<[u8; 32]>,
    ) -> Result<ContractEvent, String> {
        let entry = self
            .registry
            .get_mut(&dao_id)
            .ok_or_else(|| "DAO not found".to_string())?;

        if entry.owner != updater {
            return Err("Only DAO owner can update metadata".to_string());
        }

        entry.metadata_hash = metadata_hash;

        let event = ContractEvent::DaoUpdated {
            dao_id,
            updater,
            metadata_hash,
        };

        Ok(event)
    }
}
