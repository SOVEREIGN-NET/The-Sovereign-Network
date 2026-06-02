use super::*;

impl Blockchain {
    pub fn register_identity(&mut self, identity_data: IdentityTransactionData) -> Result<Hash> {
        if self.identity_registry.contains_key(&identity_data.did) {
            return Err(anyhow::anyhow!(
                "Identity {} already exists on blockchain",
                identity_data.did
            ));
        }

        let registration_tx = Transaction::new_identity_registration(
            identity_data.clone(),
            vec![],
            Signature {
                signature: identity_data.ownership_proof.clone(),
                public_key: PublicKey::new(
                    identity_data.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
                ),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: identity_data.created_at,
            },
            format!("Identity registration for {}", identity_data.did).into_bytes(),
        );

        self.add_pending_transaction(registration_tx.clone())?;
        self.identity_registry
            .insert(identity_data.did.clone(), identity_data.clone());
        self.identity_blocks
            .insert(identity_data.did.clone(), self.height + 1);

        Ok(registration_tx.hash())
    }

    pub async fn register_identity_with_persistence(
        &mut self,
        identity_data: IdentityTransactionData,
    ) -> Result<Hash> {
        let tx_hash = self.register_identity(identity_data.clone())?;

        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager
                .store_identity_data(&identity_data.did, &identity_data)
                .await
            {
                eprintln!("Warning: Failed to persist identity data to storage: {}", e);
            }
        }

        Ok(tx_hash)
    }

    pub fn get_identity(&self, did: &str) -> Option<&IdentityTransactionData> {
        self.identity_registry.get(did)
    }

    /// Sled-first identity facade (state-unification #2635 / #2639).
    ///
    /// Reads the authoritative `IdentityConsensus` projection the executor's
    /// `StateMutator::register_identity` writes to sled (keyed by DID hash via
    /// `did_to_hash`). Returns `None` when no store is attached (store-less
    /// mode) or the DID is unknown to the store.
    ///
    /// This is the canonical sled read for the #2639 migration. It deliberately
    /// returns the sled `IdentityConsensus` type rather than the in-memory
    /// `IdentityTransactionData`: the two carry different fields, so callers
    /// migrate field-by-field. The legacy `get_identity` (in-memory) is left in
    /// place until #2639 retires each caller.
    pub fn identity_consensus_by_did(
        &self,
        did: &str,
    ) -> Option<crate::storage::IdentityConsensus> {
        let store = self.get_store()?;
        let did_hash = crate::storage::did_to_hash(did);
        store.get_identity(&did_hash).ok().flatten()
    }

    /// Union existence check across the in-memory shadow and durable sled (#2639).
    ///
    /// Checks the in-memory `identity_registry` FIRST, then sled. This ordering
    /// is deliberate and makes the method safe in every context:
    ///
    /// - The in-memory shadow includes identities registered earlier in the
    ///   current block or still pending in the mempool — state sled has not yet
    ///   committed (SledStore reads the committed tree, not the open tx_batch).
    ///   So intra-block / submission-time gates (credential & gateway
    ///   registration) keep accepting same-block registrations exactly as
    ///   before — no consensus regression.
    /// - Sled adds the identities the shadow DROPPED: on a store-backed node the
    ///   shadow can be empty or partial after a restart or window prune, where a
    ///   bare `contains_key` silently under-reports. Sled is durable there.
    ///
    /// The result is a strict superset of the old in-memory check: it returns
    /// `true` whenever `identity_registry.contains_key` did, and ALSO catches
    /// the sled-only (post-restart) case. A transient sled error is logged, not
    /// treated as "absent". Detecting a shadow-only phantom (present in-mem,
    /// absent in sled) is the divergence detector's job, not this gate's.
    pub fn identity_exists(&self, did: &str) -> bool {
        if self.identity_registry.contains_key(did) {
            return true;
        }
        if let Some(store) = self.get_store() {
            let did_hash = crate::storage::did_to_hash(did);
            match store.get_identity(&did_hash) {
                Ok(found) => return found.is_some(),
                Err(e) => {
                    tracing::warn!(
                        did = %did,
                        error = %e,
                        "identity_exists: sled read failed; treating as not-in-sled"
                    );
                }
            }
        }
        false
    }

    /// Authoritative identity count (#2639).
    ///
    /// Display/metrics helper: prefers the durable sled count, falling back to
    /// the in-memory shadow length only when store-less or on a (logged) sled
    /// error. Best-effort by design — this never feeds a consensus decision, so
    /// a transient miscount degrades a log line rather than the chain.
    pub fn identity_count(&self) -> usize {
        if let Some(store) = self.get_store() {
            match store.count_identities() {
                Ok(n) => return n,
                Err(e) => {
                    tracing::warn!(error = %e, "identity_count: sled count failed; using in-memory shadow");
                }
            }
        }
        self.identity_registry.len()
    }

    /// Iterate the authoritative identity set as consensus projections (#2639).
    ///
    /// Returns sled `IdentityConsensus` records on a store-backed node (the full
    /// durable set), or an empty vec on a (logged) sled error. In store-less
    /// mode there is no sled to read, so this returns empty — callers that must
    /// also work store-less should branch on [`get_store`]. Returns owned
    /// records (not borrows) so the caller need not hold the chain lock while
    /// iterating.
    pub fn iter_identities_consensus(&self) -> Vec<crate::storage::IdentityConsensus> {
        let Some(store) = self.get_store() else {
            return Vec::new();
        };
        match store.iter_identities() {
            Ok(it) => it.collect(),
            Err(e) => {
                tracing::warn!(error = %e, "iter_identities_consensus: sled scan failed");
                Vec::new()
            }
        }
    }

    /// Full Dilithium public key for a DID, sled-first and consensus-pinned (#2639).
    ///
    /// The full key bytes live only in the (non-consensus) `IdentityMetadata`
    /// tree — `IdentityConsensus` carries just `public_key_hash`. To use a
    /// metadata-sourced key safely for signature verification we PIN it to
    /// consensus: the returned key is accepted only if
    /// `blake3(public_key) == IdentityConsensus.public_key_hash`. This makes the
    /// auth path trust sled's durable state while catching any metadata↔consensus
    /// drift (exactly the divergence class #2645 exists to eliminate).
    ///
    /// Falls back to the in-memory shadow only in store-less mode.
    pub fn identity_public_key(&self, did: &str) -> Option<Vec<u8>> {
        if let Some(store) = self.get_store() {
            let did_hash = crate::storage::did_to_hash(did);
            let consensus = store.get_identity(&did_hash).ok().flatten()?;
            let metadata = store.get_identity_metadata(&did_hash).ok().flatten()?;
            // Pin the metadata key to the consensus-committed hash before trusting it.
            if crate::types::hash::blake3_hash(&metadata.public_key).as_array()
                != consensus.public_key_hash
            {
                tracing::warn!(
                    did = %did,
                    "identity_public_key: metadata key hash != consensus public_key_hash; refusing drifted key"
                );
                return None;
            }
            return Some(metadata.public_key);
        }
        self.identity_registry.get(did).map(|id| id.public_key.clone())
    }

    /// Display name for a DID, sled-first (#2639).
    ///
    /// `display_name` is metadata (not consensus), read from the durable
    /// `identity_metadata` tree on a store-backed node, with the in-memory
    /// shadow as the store-less fallback.
    pub fn identity_display_name(&self, did: &str) -> Option<String> {
        if let Some(store) = self.get_store() {
            let did_hash = crate::storage::did_to_hash(did);
            if let Some(meta) = store.get_identity_metadata(&did_hash).ok().flatten() {
                return Some(meta.display_name);
            }
            return None;
        }
        self.identity_registry.get(did).map(|id| id.display_name.clone())
    }

    pub fn update_identity(
        &mut self,
        did: &str,
        updated_data: IdentityTransactionData,
    ) -> Result<Hash> {
        let existing = self
            .identity_registry
            .get(did)
            .ok_or_else(|| anyhow::anyhow!("Identity {} not found on blockchain", did))?;

        if existing.did != updated_data.did {
            return Err(anyhow::anyhow!(
                "Immutable DID mismatch for identity update"
            ));
        }
        if existing.public_key != updated_data.public_key {
            return Err(anyhow::anyhow!(
                "Immutable public key mismatch for identity update"
            ));
        }
        if existing.identity_type != updated_data.identity_type {
            return Err(anyhow::anyhow!(
                "Immutable identity type mismatch for identity update"
            ));
        }

        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(
                &format!("identity_update_{}", did).as_bytes(),
            ),
            zk_proof: ZkTransactionProof::default(),
        };

        let update_tx = Transaction::new_identity_update(
            updated_data.clone(),
            vec![auth_input],
            vec![],
            100,
            Signature {
                signature: updated_data.ownership_proof.clone(),
                public_key: PublicKey::new(
                    updated_data.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
                ),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: updated_data.created_at,
            },
            format!("Identity update for {}", did).into_bytes(),
        );

        self.add_pending_transaction(update_tx.clone())?;
        self.identity_registry.insert(did.to_string(), updated_data);

        Ok(update_tx.hash())
    }

    pub async fn update_identity_with_persistence(
        &mut self,
        did: &str,
        updated_data: IdentityTransactionData,
    ) -> Result<Hash> {
        let tx_hash = self.update_identity(did, updated_data.clone())?;

        if let Some(storage_manager_arc) = &self.storage_manager {
            let mut storage_manager = storage_manager_arc.write().await;
            if let Err(e) = storage_manager.store_identity_data(did, &updated_data).await {
                eprintln!(
                    "Warning: Failed to persist updated identity data to storage: {}",
                    e
                );
            }
        }

        Ok(tx_hash)
    }

    pub fn revoke_identity(&mut self, did: &str, authorizing_signature: Vec<u8>) -> Result<Hash> {
        if !self.identity_registry.contains_key(did) {
            return Err(anyhow::anyhow!("Identity {} not found on blockchain", did));
        }

        let auth_input = TransactionInput {
            previous_output: Hash::default(),
            output_index: 0,
            nullifier: crate::types::hash::blake3_hash(
                &format!("identity_revoke_{}", did).as_bytes(),
            ),
            zk_proof: ZkTransactionProof::default(),
        };

        let revocation_tx = Transaction::new_identity_revocation(
            did.to_string(),
            vec![auth_input],
            50,
            Signature {
                signature: authorizing_signature,
                public_key: PublicKey::new([0u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: crate::utils::time::current_timestamp(),
            },
            format!("Identity revocation for {}", did).into_bytes(),
        );

        self.add_pending_transaction(revocation_tx.clone())?;

        if let Some(mut identity_data) = self.identity_registry.remove(did) {
            identity_data.identity_type = "revoked".to_string();
            self.identity_registry
                .insert(format!("{}_revoked", did), identity_data);
        }

        Ok(revocation_tx.hash())
    }

    pub fn list_all_identities(&self) -> Vec<&IdentityTransactionData> {
        self.identity_registry.values().collect()
    }

    pub fn get_all_identities(&self) -> &HashMap<String, IdentityTransactionData> {
        &self.identity_registry
    }

    pub fn get_identity_confirmations(&self, did: &str) -> Option<u64> {
        self.identity_blocks.get(did).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    pub fn process_identity_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if transaction.transaction_type.is_identity_transaction() {
                if let Some(identity_data) = transaction.identity_data() {
                    match transaction.transaction_type {
                        TransactionType::IdentityRegistration => {
                            let mut new_identity_data = identity_data.clone();
                            if let Some(existing_identity) =
                                self.identity_registry.get(&identity_data.did)
                            {
                                new_identity_data.controlled_nodes =
                                    existing_identity.controlled_nodes.clone();
                            }

                            self.identity_registry
                                .insert(identity_data.did.clone(), new_identity_data.clone());
                            self.identity_blocks
                                .insert(identity_data.did.clone(), block.height());

                            if let Some(ref store) = self.store {
                                self.persist_identity_registration(
                                    store.as_ref(),
                                    &new_identity_data,
                                    block.height(),
                                )?;
                            }

                            if identity_data.identity_type == "verified_citizen"
                                || identity_data.identity_type == "citizen"
                                || identity_data.identity_type == "external_citizen"
                            {
                                let ubi_wallet_id = new_identity_data
                                    .owned_wallets
                                    .iter()
                                    .find(|wallet_id| {
                                        self.wallet_registry
                                            .get(*wallet_id)
                                            .map(|w| w.wallet_type == "UBI")
                                            .unwrap_or(false)
                                    })
                                    .cloned();

                                if let Some(ubi_wallet) = ubi_wallet_id {
                                    if let Err(e) = self.register_for_ubi(
                                        identity_data.did.clone(),
                                        ubi_wallet,
                                        block.height(),
                                    ) {
                                        warn!(
                                            "Failed to register {} for UBI: {}",
                                            identity_data.did, e
                                        );
                                    }
                                } else {
                                    warn!("No UBI wallet found for citizen {}", identity_data.did);
                                }
                            }
                        }
                        TransactionType::IdentityUpdate => {
                            let mut updated_identity_data = identity_data.clone();
                            if let Some(existing_identity) =
                                self.identity_registry.get(&identity_data.did)
                            {
                                updated_identity_data.controlled_nodes =
                                    existing_identity.controlled_nodes.clone();
                            }

                            if let Some(existing_identity) =
                                self.identity_registry.get(&identity_data.did)
                            {
                                if existing_identity.public_key != updated_identity_data.public_key
                                {
                                    return Err(anyhow::anyhow!(
                                        "Immutable public key mismatch for identity update: {}",
                                        identity_data.did
                                    ));
                                }
                                if existing_identity.identity_type
                                    != updated_identity_data.identity_type
                                {
                                    return Err(anyhow::anyhow!(
                                        "Immutable identity type mismatch for identity update: {}",
                                        identity_data.did
                                    ));
                                }
                            } else {
                                return Err(anyhow::anyhow!(
                                    "Cannot update non-existent identity: {}",
                                    identity_data.did
                                ));
                            }

                            self.identity_registry
                                .insert(identity_data.did.clone(), updated_identity_data.clone());

                            if let Some(ref store) = self.store {
                                self.persist_identity_update(
                                    store.as_ref(),
                                    &updated_identity_data,
                                )?;
                            }
                        }
                        TransactionType::IdentityRevocation => {
                            let did_hash = did_to_hash(&identity_data.did);

                            let mut revoked_data = identity_data.clone();
                            revoked_data.identity_type = "revoked".to_string();
                            self.identity_registry
                                .insert(format!("{}_revoked", identity_data.did), revoked_data);
                            self.identity_registry.remove(&identity_data.did);

                            if let Some(ref store) = self.store {
                                if let Some(existing_identity) =
                                    store.get_identity(&did_hash).map_err(|e| {
                                        anyhow::anyhow!(
                                            "Failed to load identity for revocation: {}",
                                            e
                                        )
                                    })?
                                {
                                    store
                                        .delete_identity_owner_index(&existing_identity.owner)
                                        .map_err(|e| {
                                            anyhow::anyhow!(
                                                "Failed to delete identity owner index: {}",
                                                e
                                            )
                                        })?;
                                }
                                store.delete_identity(&did_hash).map_err(|e| {
                                    anyhow::anyhow!("Failed to delete identity from sled: {}", e)
                                })?;
                                store.delete_identity_metadata(&did_hash).map_err(|e| {
                                    anyhow::anyhow!(
                                        "Failed to delete identity metadata from sled: {}",
                                        e
                                    )
                                })?;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn persist_identity_registration(
        &self,
        store: &dyn BlockchainStore,
        identity_data: &IdentityTransactionData,
        block_height: u64,
    ) -> Result<()> {
        use crate::storage::derive_address_from_public_key;
        use crate::types::hash::blake3_hash;

        let did_hash = did_to_hash(&identity_data.did);
        let owner = derive_address_from_public_key(&identity_data.public_key);

        let consensus = IdentityConsensus {
            did_hash,
            owner,
            public_key_hash: blake3_hash(&identity_data.public_key).as_array(),
            did_document_hash: identity_data.did_document_hash.as_array(),
            seed_commitment: None,
            identity_type: IdentityType::from_str(&identity_data.identity_type),
            status: IdentityStatus::Active,
            version: 1,
            created_at: identity_data.created_at,
            registered_at_height: block_height,
            registration_fee: identity_data.registration_fee,
            dao_fee: identity_data.dao_fee,
            controlled_node_count: identity_data.controlled_nodes.len() as u32,
            owned_wallet_count: identity_data.owned_wallets.len() as u32,
            attribute_count: 0,
        };

        let metadata = IdentityMetadata {
            did: identity_data.did.clone(),
            display_name: identity_data.display_name.clone(),
            public_key: identity_data.public_key.clone(),
            ownership_proof: identity_data.ownership_proof.clone(),
            controlled_nodes: identity_data.controlled_nodes.clone(),
            owned_wallets: identity_data.owned_wallets.clone(),
            attributes: Vec::new(),
        };

        store
            .put_identity(&did_hash, &consensus)
            .map_err(|e| anyhow::anyhow!("Failed to store identity in sled: {}", e))?;
        store
            .put_identity_metadata(&did_hash, &metadata)
            .map_err(|e| anyhow::anyhow!("Failed to store identity metadata in sled: {}", e))?;
        store
            .put_identity_owner_index(&consensus.owner, &did_hash)
            .map_err(|e| anyhow::anyhow!("Failed to store identity owner index in sled: {}", e))?;

        debug!(
            "Persisted identity {} to sled storage (registration)",
            identity_data.did
        );
        Ok(())
    }

    pub(super) fn persist_identity_update(
        &self,
        store: &dyn BlockchainStore,
        identity_data: &IdentityTransactionData,
    ) -> Result<()> {
        use crate::storage::derive_address_from_public_key;
        use crate::types::hash::blake3_hash;

        let did_hash = did_to_hash(&identity_data.did);

        let existing = store
            .get_identity(&did_hash)
            .map_err(|e| anyhow::anyhow!("Failed to load identity for update: {}", e))?
            .ok_or_else(|| {
                anyhow::anyhow!("Cannot update non-existent identity: {}", identity_data.did)
            })?;

        let existing_metadata = store
            .get_identity_metadata(&did_hash)
            .map_err(|e| anyhow::anyhow!("Failed to load identity metadata for update: {}", e))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing identity metadata for update: {}",
                    identity_data.did
                )
            })?;

        let incoming_owner = derive_address_from_public_key(&identity_data.public_key);
        let incoming_public_key_hash = blake3_hash(&identity_data.public_key).as_array();
        let incoming_identity_type = IdentityType::from_str(&identity_data.identity_type);

        if existing.did_hash != did_hash {
            return Err(anyhow::anyhow!(
                "Immutable DID hash mismatch for identity update"
            ));
        }
        if existing.owner != incoming_owner {
            return Err(anyhow::anyhow!(
                "Immutable owner mismatch for identity update"
            ));
        }
        if existing.public_key_hash != incoming_public_key_hash {
            return Err(anyhow::anyhow!(
                "Immutable public key mismatch for identity update"
            ));
        }
        if existing.identity_type != incoming_identity_type {
            return Err(anyhow::anyhow!(
                "Immutable identity type mismatch for identity update"
            ));
        }
        if existing_metadata.did != identity_data.did {
            return Err(anyhow::anyhow!(
                "Immutable DID mismatch for identity update"
            ));
        }
        if existing_metadata.public_key != identity_data.public_key {
            return Err(anyhow::anyhow!(
                "Immutable public key mismatch for identity update"
            ));
        }

        let mut updated_consensus = existing.clone();
        updated_consensus.did_document_hash = identity_data.did_document_hash.as_array();
        updated_consensus.controlled_node_count = identity_data.controlled_nodes.len() as u32;
        updated_consensus.owned_wallet_count = identity_data.owned_wallets.len() as u32;

        let mut updated_metadata = existing_metadata.clone();
        updated_metadata.display_name = identity_data.display_name.clone();
        updated_metadata.ownership_proof = identity_data.ownership_proof.clone();
        updated_metadata.controlled_nodes = identity_data.controlled_nodes.clone();
        updated_metadata.owned_wallets = identity_data.owned_wallets.clone();

        store
            .put_identity(&did_hash, &updated_consensus)
            .map_err(|e| anyhow::anyhow!("Failed to update identity in sled: {}", e))?;
        store
            .put_identity_metadata(&did_hash, &updated_metadata)
            .map_err(|e| anyhow::anyhow!("Failed to update identity metadata in sled: {}", e))?;

        debug!(
            "Persisted identity {} to sled storage (update)",
            identity_data.did
        );
        Ok(())
    }

    pub fn is_public_key_registered(&self, public_key: &[u8]) -> bool {
        self.identity_registry
            .values()
            .any(|identity_data| {
                identity_data.public_key == public_key && identity_data.identity_type != "revoked"
            })
    }

    pub fn get_identity_by_public_key(
        &self,
        public_key: &[u8],
    ) -> Option<&IdentityTransactionData> {
        self.identity_registry.values().find(|identity_data| {
            identity_data.public_key == public_key && identity_data.identity_type != "revoked"
        })
    }

    pub fn auto_register_wallet_identity(
        &mut self,
        wallet_id: &str,
        public_key: Vec<u8>,
        did: Option<String>,
    ) -> Result<Hash> {
        if self.is_public_key_registered(&public_key) {
            tracing::info!(" Public key already registered on blockchain");
            return Ok(Hash::default());
        }

        let identity_did =
            did.unwrap_or_else(|| format!("did:zhtp:wallet-{}", hex::encode(&public_key[..16])));

        tracing::info!(" Auto-registering wallet identity: {}", identity_did);

        let identity_data = IdentityTransactionData {
            did: identity_did.clone(),
            display_name: format!("Wallet {}", &wallet_id[..8.min(wallet_id.len())]),
            public_key: public_key.clone(),
            ownership_proof: vec![],
            identity_type: "service".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(identity_did.as_bytes()),
            created_at: crate::utils::time::current_timestamp(),
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: vec![wallet_id.to_string()],
            kyber_public_key: Vec::new(),
        };

        let registration_tx = Transaction::new_identity_registration(
            identity_data.clone(),
            vec![],
            Signature {
                signature: vec![0xAA; 64],
                public_key: PublicKey::new(
                    public_key.as_slice().try_into().unwrap_or([0u8; 2592])
                ),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: identity_data.created_at,
            },
            b"Auto-registration for wallet identity".to_vec(),
        );

        self.add_system_transaction(registration_tx.clone(), "auto_identity_registration")?;
        self.identity_registry
            .insert(identity_did.clone(), identity_data.clone());
        self.identity_blocks.insert(identity_did, self.height + 1);

        tracing::info!(" Wallet identity auto-registered on blockchain");

        Ok(registration_tx.hash())
    }

    pub fn ensure_wallet_identity_registered(
        &mut self,
        wallet_id: &str,
        public_key: &[u8],
        did: Option<String>,
    ) -> Result<()> {
        if !self.is_public_key_registered(public_key) {
            self.auto_register_wallet_identity(wallet_id, public_key.to_vec(), did)?;
        }
        Ok(())
    }
}
