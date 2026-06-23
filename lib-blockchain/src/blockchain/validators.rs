use super::*;
use crate::block::Block;
use crate::storage::{did_to_hash, BlockchainStore, StoredValidatorRecord, ValidatorConsensusRecord, ValidatorMetadata};
use crate::transaction::ValidatorTransactionData;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as StdHash, Hasher};
use tracing::{debug, error, warn};

/// Cached active-validator snapshot for [`Blockchain::active_validator_infos`].
#[derive(Debug, Clone)]
struct ActiveValidatorCacheEntry {
    sled_gen: u64,
    registry_fp: (usize, u64),
    snapshot: Vec<ValidatorInfo>,
}

#[derive(Debug, Default)]
struct ActiveValidatorCacheState {
    sled_gen: u64,
    entry: Option<ActiveValidatorCacheEntry>,
}

/// Thread-safe cache handle; fresh on [`Blockchain`] clone (not shared).
#[derive(Debug, Default)]
pub(super) struct ActiveValidatorCacheHandle(
    std::sync::Arc<std::sync::Mutex<ActiveValidatorCacheState>>,
);

impl Clone for ActiveValidatorCacheHandle {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl ActiveValidatorCacheHandle {
    pub(super) fn read_hit(&self, registry_fp: (usize, u64)) -> Option<Vec<ValidatorInfo>> {
        let state = self.0.lock().ok()?;
        let entry = state.entry.as_ref()?;
        if entry.sled_gen == state.sled_gen && entry.registry_fp == registry_fp {
            Some(entry.snapshot.clone())
        } else {
            None
        }
    }

    pub(super) fn store(&self, registry_fp: (usize, u64), snapshot: Vec<ValidatorInfo>) {
        if let Ok(mut state) = self.0.lock() {
            state.entry = Some(ActiveValidatorCacheEntry {
                sled_gen: state.sled_gen,
                registry_fp,
                snapshot,
            });
        }
    }

    pub(super) fn invalidate_sled_snapshot(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.sled_gen = state.sled_gen.wrapping_add(1);
        }
    }
}

pub(super) fn default_active_validator_cache() -> ActiveValidatorCacheHandle {
    ActiveValidatorCacheHandle::default()
}

// =============================================================================
// Validator storage boundary (#56)
// =============================================================================
// The ONLY place the in-memory `ValidatorInfo` is converted to/from the durable
// `StoredValidatorRecord` (consensus+metadata split). Storage stays ignorant of
// `ValidatorInfo`; the blockchain layer owns the mapping. The split is lossless:
// every `ValidatorInfo` field maps to exactly one of consensus/metadata, so the
// round-trip `ValidatorInfo -> StoredValidatorRecord -> ValidatorInfo` is the
// identity (guarded by `validator_record_roundtrip_is_lossless`).

impl From<&ValidatorInfo> for StoredValidatorRecord {
    fn from(info: &ValidatorInfo) -> Self {
        StoredValidatorRecord {
            consensus: ValidatorConsensusRecord {
                identity_id: info.identity_id.clone(),
                consensus_key: info.consensus_key,
                stake: info.stake,
                storage_provided: info.storage_provided,
                status: info.status.clone(),
                oracle_key_id: info.oracle_key_id,
            },
            metadata: ValidatorMetadata {
                networking_key: info.networking_key.clone(),
                rewards_key: info.rewards_key.clone(),
                network_address: info.network_address.clone(),
                commission_rate: info.commission_rate,
                registered_at: info.registered_at,
                last_activity: info.last_activity,
                blocks_validated: info.blocks_validated,
                slash_count: info.slash_count,
                admission_source: info.admission_source.clone(),
                governance_proposal_id: info.governance_proposal_id.clone(),
            },
        }
    }
}

impl From<&StoredValidatorRecord> for ValidatorInfo {
    fn from(rec: &StoredValidatorRecord) -> Self {
        ValidatorInfo {
            identity_id: rec.consensus.identity_id.clone(),
            stake: rec.consensus.stake,
            storage_provided: rec.consensus.storage_provided,
            consensus_key: rec.consensus.consensus_key,
            networking_key: rec.metadata.networking_key.clone(),
            rewards_key: rec.metadata.rewards_key.clone(),
            network_address: rec.metadata.network_address.clone(),
            commission_rate: rec.metadata.commission_rate,
            status: rec.consensus.status.clone(),
            registered_at: rec.metadata.registered_at,
            last_activity: rec.metadata.last_activity,
            blocks_validated: rec.metadata.blocks_validated,
            slash_count: rec.metadata.slash_count,
            admission_source: rec.metadata.admission_source.clone(),
            governance_proposal_id: rec.metadata.governance_proposal_id.clone(),
            oracle_key_id: rec.consensus.oracle_key_id,
        }
    }
}

impl Blockchain {
    /// Sled-first validator record read (#56 / #2639).
    pub fn validator_record_by_did(&self, did: &str) -> Option<StoredValidatorRecord> {
        let store = self.get_store()?;
        let did_hash = did_to_hash(did);
        match store.get_validator_record(&did_hash) {
            Ok(found) => found,
            Err(e) => {
                warn!(
                    did = %did,
                    error = %e,
                    "validator_record_by_did: sled read failed; treating as absent"
                );
                None
            }
        }
    }

    /// Union existence: in-memory shadow first (same-block / mempool), then sled (#56).
    pub fn validator_exists(&self, did: &str) -> bool {
        if self.validator_registry.contains_key(did) {
            return true;
        }
        if let Some(store) = self.get_store() {
            let did_hash = did_to_hash(did);
            match store.get_validator_record(&did_hash) {
                Ok(found) => return found.is_some(),
                Err(e) => {
                    warn!(
                        did = %did,
                        error = %e,
                        "validator_exists: sled read failed; treating as not-in-sled"
                    );
                }
            }
        }
        false
    }

    /// Authoritative validator info: in-memory overlay first, then sled (#56).
    pub fn validator_info_by_did(&self, did: &str) -> Option<ValidatorInfo> {
        if let Some(info) = self.validator_registry.get(did) {
            return Some(info.clone());
        }
        self.validator_record_by_did(did)
            .map(|rec| ValidatorInfo::from(&rec))
    }

    /// Authoritative active validator set for vote/propose/consensus sync (#56).
    ///
    /// Sled-first with in-memory overlay for same-block registrations. All
    /// consensus-relevant active-set reads must use this (or a wrapper), not
    /// [`get_active_validators`] which reads the in-memory shadow only.
    pub fn active_validators_for_consensus(&self) -> Vec<ValidatorInfo> {
        self.active_validator_infos()
    }

    /// Active validators, sled-first with in-memory overlay (#56).
    ///
    /// The in-memory overlay is authoritative for same-block changes before sled
    /// persist: active entries replace sled, and non-active entries remove a sled
    /// active record (e.g. Unregister in the current block).
    ///
    /// Results are cached until sled writes bump [`active_validator_cache_gen`] or the
    /// in-memory overlay fingerprint changes (status/stake per registry entry).
    pub fn active_validator_infos(&self) -> Vec<ValidatorInfo> {
        let registry_fp = self.validator_registry_overlay_fingerprint();
        if let Some(snapshot) = self.active_validator_cache.read_hit(registry_fp) {
            return snapshot;
        }
        let snapshot = self.build_active_validator_infos_uncached();
        self.active_validator_cache
            .store(registry_fp, snapshot.clone());
        snapshot
    }

    /// Invalidate sled-portion of the active-validator cache after durable writes.
    pub(super) fn invalidate_active_validator_cache(&self) {
        self.active_validator_cache.invalidate_sled_snapshot();
    }

    fn validator_registry_overlay_fingerprint(&self) -> (usize, u64) {
        let mut hasher = DefaultHasher::new();
        for (did, info) in &self.validator_registry {
            did.hash(&mut hasher);
            info.status.hash(&mut hasher);
            info.stake.hash(&mut hasher);
        }
        (self.validator_registry.len(), hasher.finish())
    }

    fn build_active_validator_infos_uncached(&self) -> Vec<ValidatorInfo> {
        let mut by_id: HashMap<String, ValidatorInfo> = HashMap::new();
        if let Some(store) = self.get_store() {
            match store.iter_validator_records() {
                Ok(iter) => {
                    for rec in iter {
                        if rec.consensus.status == "active" {
                            by_id.insert(
                                rec.consensus.identity_id.clone(),
                                ValidatorInfo::from(&rec),
                            );
                        }
                    }
                }
                Err(e) => {
                    // Warn-and-continue: a single broken sled node can diverge from the
                    // fleet until quorum fails; operators should treat this as restart-worthy.
                    // Cryptographic validator-set divergence detection awaits #57 state_root.
                    error!(
                        error = %e,
                        "active_validator_infos: sled iter failed; falling back to in-memory \
                         shadow only — node may disagree with fleet on validator set until restart"
                    );
                }
            }
        }
        for (did, info) in &self.validator_registry {
            if info.status == "active" {
                by_id.insert(did.clone(), info.clone());
            } else {
                // Same-block deactivation before metadata-batch sled write.
                by_id.remove(did);
            }
        }
        by_id.into_values().collect()
    }

    /// Active validator oracle key IDs for committee gating (#56).
    pub fn active_validator_key_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        use crate::types::hash::blake3_hash;
        self.active_validator_infos()
            .into_iter()
            .map(|v| {
                v.oracle_key_id
                    .unwrap_or_else(|| blake3_hash(&v.consensus_key).as_array())
            })
            .collect()
    }

    /// Whether `signer_pk` matches an active validator's consensus key (#56).
    pub fn is_active_validator_consensus_signer(&self, signer_pk: &[u8]) -> bool {
        self.active_validator_infos().iter().any(|v| {
            v.status == "active" && v.consensus_key.as_slice() == signer_pk
        })
    }

    /// Resolve a validator by blake3(consensus_key) for oracle attestation checks (#56).
    pub fn validator_by_consensus_key_hash(
        &self,
        key_hash: [u8; 32],
    ) -> Option<ValidatorInfo> {
        use crate::types::hash::blake3_hash;
        self.active_validator_infos()
            .into_iter()
            .find(|v| blake3_hash(&v.consensus_key).as_array() == key_hash)
    }

    fn build_validator_info_from_tx(
        vd: &ValidatorTransactionData,
        height: u64,
        existing: Option<&ValidatorInfo>,
    ) -> Option<ValidatorInfo> {
        let consensus_key: [u8; 2592] = vd.consensus_key.as_slice().try_into().ok()?;
        let status = match vd.operation {
            crate::transaction::ValidatorOperation::Register => "active",
            crate::transaction::ValidatorOperation::Update => "active",
            crate::transaction::ValidatorOperation::Unregister => "inactive",
        };
        let (
            registered_at,
            blocks_validated,
            slash_count,
            oracle_key_id,
            governance_proposal_id,
            admission_source,
        ) = if let Some(ex) = existing {
            (
                ex.registered_at,
                ex.blocks_validated,
                ex.slash_count,
                ex.oracle_key_id,
                ex.governance_proposal_id.clone(),
                ex.admission_source.clone(),
            )
        } else {
            (
                height,
                0,
                0,
                None,
                None,
                ADMISSION_SOURCE_ONCHAIN_GOVERNANCE.to_string(),
            )
        };
        let registered_at = if vd.operation == crate::transaction::ValidatorOperation::Register {
            height
        } else {
            registered_at
        };
        Some(ValidatorInfo {
            identity_id: vd.identity_id.clone(),
            stake: vd.stake,
            storage_provided: vd.storage_provided,
            consensus_key,
            networking_key: vd.networking_key.clone(),
            rewards_key: vd.rewards_key.clone(),
            network_address: vd.network_address.clone(),
            commission_rate: vd.commission_rate,
            status: status.to_string(),
            registered_at,
            last_activity: height,
            blocks_validated,
            slash_count,
            admission_source,
            governance_proposal_id,
            oracle_key_id,
        })
    }

    pub(super) fn persist_validator_record(
        &self,
        store: &dyn BlockchainStore,
        info: &ValidatorInfo,
    ) -> Result<()> {
        let did_hash = did_to_hash(&info.identity_id);
        let record = StoredValidatorRecord::from(info);
        store
            .put_validator_record(&did_hash, &record)
            .map_err(|e| anyhow::anyhow!("Failed to store validator {} in sled: {}", info.identity_id, e))?;
        self.invalidate_active_validator_cache();
        debug!("Persisted validator {} to sled storage", info.identity_id);
        Ok(())
    }

    /// Write durable validator records for validator txs in `block` (requires open tx batch).
    pub(super) fn persist_validator_records_for_block(
        &self,
        store: &dyn BlockchainStore,
        block: &Block,
    ) -> Result<()> {
        for tx in &block.transactions {
            let Some(vd) = tx.validator_data() else {
                continue;
            };
            if let Some(info) = self.validator_registry.get(&vd.identity_id) {
                self.persist_validator_record(store, info)?;
            }
        }
        Ok(())
    }

    /// Durable write outside a block batch (oracle slash path).
    pub(super) fn persist_validator_record_direct(&self, info: &ValidatorInfo) -> Result<()> {
        let Some(ref store) = self.store else {
            return Ok(());
        };
        let did_hash = did_to_hash(&info.identity_id);
        let record = StoredValidatorRecord::from(info);
        store
            .put_validator_record_direct(&did_hash, &record)
            .map_err(|e| anyhow::anyhow!("Failed to direct-persist validator {}: {}", info.identity_id, e))?;
        self.invalidate_active_validator_cache();
        Ok(())
    }

    pub fn register_validator(&mut self, validator_info: ValidatorInfo) -> Result<Hash> {
        if self.validator_exists(&validator_info.identity_id) {
            return Err(anyhow::anyhow!(
                "Validator {} already exists on blockchain",
                validator_info.identity_id
            ));
        }

        if !self
            .identity_registry
            .contains_key(&validator_info.identity_id)
        {
            return Err(anyhow::anyhow!(
                "Identity {} must be registered before becoming a validator",
                validator_info.identity_id
            ));
        }

        if validator_info.consensus_key.is_empty() {
            return Err(anyhow::anyhow!("Validator consensus_key must not be empty"));
        }
        if validator_info.networking_key.is_empty() {
            return Err(anyhow::anyhow!(
                "Validator networking_key must not be empty"
            ));
        }
        if validator_info.rewards_key.is_empty() {
            return Err(anyhow::anyhow!("Validator rewards_key must not be empty"));
        }
        if validator_info.consensus_key.as_slice() == validator_info.networking_key.as_slice() {
            return Err(anyhow::anyhow!(
                "Validator key separation violation: consensus_key and networking_key must be different keys. Reusing the same key across roles collapses security domain boundaries."
            ));
        }
        if validator_info.consensus_key.as_slice() == validator_info.rewards_key.as_slice() {
            return Err(anyhow::anyhow!(
                "Validator key separation violation: consensus_key and rewards_key must be different keys. A compromised consensus key must not give an attacker control over staking rewards."
            ));
        }
        if validator_info.networking_key == validator_info.rewards_key {
            return Err(anyhow::anyhow!(
                "Validator key separation violation: networking_key and rewards_key must be different keys. A compromised network identity key must not give an attacker access to reward funds."
            ));
        }

        let min_stake = if self.height == 0 { 1_000 } else { 100_000 };
        if validator_info.stake < min_stake {
            return Err(anyhow::anyhow!(
                "Insufficient stake for validator: {} SOV (minimum: {} SOV required)",
                validator_info.stake,
                min_stake
            ));
        }

        if self.height > 0 && validator_info.storage_provided < 10_737_418_240 {
            return Err(anyhow::anyhow!(
                "Insufficient storage for validator: {} bytes (minimum: 10 GB required for blockchain storage)",
                validator_info.storage_provided
            ));
        }

        let validator_tx_data = IdentityTransactionData {
            did: validator_info.identity_id.clone(),
            display_name: format!("Validator: {}", validator_info.network_address),
            public_key: validator_info.consensus_key.to_vec(),
            ownership_proof: vec![],
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!(
                    "validator:{}:{}",
                    validator_info.identity_id, validator_info.registered_at
                )
                .as_bytes(),
            ),
            created_at: validator_info.registered_at,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
                    kyber_public_key: Vec::new(),
        };

        let registration_tx = Transaction::new_identity_registration(
            validator_tx_data,
            vec![],
            Signature {
                signature: validator_info.consensus_key.to_vec(),
                public_key: PublicKey::new(validator_info.consensus_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: validator_info.registered_at,
            },
            format!(
                "Validator registration for {} with stake {}",
                validator_info.identity_id, validator_info.stake
            )
            .into_bytes(),
        );

        self.add_pending_transaction(registration_tx.clone())?;
        self.validator_registry
            .insert(validator_info.identity_id.clone(), validator_info.clone());
        self.validator_blocks
            .insert(validator_info.identity_id.clone(), self.height + 1);

        info!(
            " Validator {} registered with {} SOV stake and {} bytes storage",
            validator_info.identity_id, validator_info.stake, validator_info.storage_provided
        );

        Ok(registration_tx.hash())
    }

    pub fn get_validator(&self, identity_id: &str) -> Option<&ValidatorInfo> {
        self.validator_registry.get(identity_id)
    }

    pub fn list_all_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values().collect()
    }

    /// In-memory shadow only — **not** for vote/propose. Use
    /// [`active_validators_for_consensus`] for consensus paths (#56).
    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry
            .values()
            .filter(|v| v.status == "active")
            .collect()
    }

    pub fn get_all_validators(&self) -> &HashMap<String, ValidatorInfo> {
        &self.validator_registry
    }

    pub fn update_validator(
        &mut self,
        identity_id: &str,
        updated_info: ValidatorInfo,
    ) -> Result<Hash> {
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!(
                "Validator {} not found on blockchain",
                identity_id
            ));
        }

        let validator_tx_data = IdentityTransactionData {
            did: updated_info.identity_id.clone(),
            display_name: format!("Validator Update: {}", updated_info.network_address),
            public_key: updated_info.consensus_key.to_vec(),
            ownership_proof: vec![],
            identity_type: "validator".to_string(),
            did_document_hash: crate::types::hash::blake3_hash(
                format!(
                    "validator_update:{}:{}",
                    updated_info.identity_id, updated_info.last_activity
                )
                .as_bytes(),
            ),
            created_at: updated_info.last_activity,
            registration_fee: 0,
            dao_fee: 0,
            controlled_nodes: Vec::new(),
            owned_wallets: Vec::new(),
                    kyber_public_key: Vec::new(),
        };

        let update_tx = Transaction::new_identity_update(
            validator_tx_data,
            vec![],
            vec![],
            100,
            Signature {
                signature: updated_info.consensus_key.to_vec(),
                public_key: PublicKey::new(updated_info.consensus_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: updated_info.last_activity,
            },
            format!("Validator update for {}", identity_id).into_bytes(),
        );

        self.add_pending_transaction(update_tx.clone())?;
        self.validator_registry
            .insert(identity_id.to_string(), updated_info);

        Ok(update_tx.hash())
    }

    pub fn unregister_validator(&mut self, identity_id: &str) -> Result<Hash> {
        if !self.validator_registry.contains_key(identity_id) {
            return Err(anyhow::anyhow!(
                "Validator {} not found on blockchain",
                identity_id
            ));
        }

        let mut validator_info = self.validator_registry.get(identity_id).unwrap().clone();
        validator_info.status = "inactive".to_string();

        let unregister_tx = Transaction::new_identity_revocation(
            identity_id.to_string(),
            vec![],
            100,
            Signature {
                signature: validator_info.consensus_key.to_vec(),
                public_key: PublicKey::new(validator_info.consensus_key),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: validator_info.last_activity,
            },
            format!("Validator unregistration for {}", identity_id).into_bytes(),
        );

        self.add_pending_transaction(unregister_tx.clone())?;
        self.validator_registry
            .insert(identity_id.to_string(), validator_info);

        info!("Validator {} unregistered", identity_id);

        Ok(unregister_tx.hash())
    }

    pub fn get_validator_confirmations(&self, identity_id: &str) -> Option<u64> {
        self.validator_blocks.get(identity_id).map(|block_height| {
            if self.height >= *block_height {
                self.height - block_height + 1
            } else {
                0
            }
        })
    }

    pub fn get_active_validator_set_for_consensus(&self) -> Vec<(String, u64)> {
        self.active_validators_for_consensus()
            .into_iter()
            .map(|v| (v.identity_id, v.stake))
            .collect()
    }

    pub fn get_total_validator_stake(&self) -> u64 {
        self.active_validators_for_consensus()
            .into_iter()
            .fold(0u64, |sum, v| sum.saturating_add(v.stake))
    }

    pub fn is_validator_active(&self, identity_id: &str) -> bool {
        self.validator_info_by_did(identity_id)
            .map(|validator| validator.status == "active" && validator.stake > 0)
            .unwrap_or(false)
    }

    pub fn sync_validator_set_to_consensus(&self) {
        let active_validators = self.active_validators_for_consensus();
        info!(
            "Validator set sync: {} active validators with {} total stake",
            active_validators.len(),
            self.get_total_validator_stake()
        );

        for validator in &active_validators {
            debug!(
                "Validator in sync: {} (stake: {}, joined at height: {})",
                validator.identity_id, validator.stake, validator.registered_at
            );
        }
    }

    pub fn process_validator_registration_transactions(&mut self, block: &Block) -> Result<()> {
        let height = block.height();
        for tx in &block.transactions {
            let Some(validator_data) = tx.validator_data() else {
                continue;
            };
            let existing = self.validator_registry.get(&validator_data.identity_id);
            let Some(validator_info) =
                Self::build_validator_info_from_tx(validator_data, height, existing)
            else {
                warn!(
                    "Skipping validator {}: consensus_key must be 2592 bytes (Dilithium5)",
                    validator_data.identity_id
                );
                continue;
            };
            self.validator_registry
                .insert(validator_data.identity_id.clone(), validator_info.clone());
            if validator_data.operation == crate::transaction::ValidatorOperation::Register {
                self.validator_blocks
                    .insert(validator_data.identity_id.clone(), height);
            }
            info!(
                "Validator {} {:?} at height {} ({} SOV stake)",
                validator_data.identity_id,
                validator_data.operation,
                height,
                validator_data.stake
            );
        }
        Ok(())
    }

    pub fn process_validator_transactions(&mut self, block: &Block) -> Result<()> {
        for transaction in &block.transactions {
            if let Some(identity_data) = transaction.identity_data() {
                if identity_data.identity_type == "validator" {
                    if let Some(validator_info) = self.validator_registry.get(&identity_data.did) {
                        let mut updated_info = validator_info.clone();
                        updated_info.last_activity = identity_data.created_at;
                        updated_info.blocks_validated += 1;

                        self.validator_registry
                            .insert(identity_data.did.clone(), updated_info);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod validator_boundary_tests {
    use super::*;

    fn sample_validator_info() -> ValidatorInfo {
        ValidatorInfo {
            identity_id: "did:zhtp:validator-1".to_string(),
            stake: 1_000_000,
            storage_provided: 42 * 1024 * 1024 * 1024,
            consensus_key: [7u8; 2592],
            networking_key: vec![1, 2, 3],
            rewards_key: vec![4, 5, 6],
            network_address: "1.2.3.4:9000".to_string(),
            commission_rate: 5,
            status: "active".to_string(),
            registered_at: 100,
            last_activity: 200,
            blocks_validated: 17,
            slash_count: 0,
            admission_source: "onchain_governance".to_string(),
            governance_proposal_id: Some("prop-7".to_string()),
            oracle_key_id: Some([9u8; 32]),
        }
    }

    /// The `ValidatorInfo -> StoredValidatorRecord -> ValidatorInfo` round-trip is
    /// the identity: every field maps to exactly one side of the consensus/metadata
    /// split, so the boundary conversion is lossless (#56). If a new `ValidatorInfo`
    /// field is added without being routed into one of the halves, this fails.
    #[test]
    fn validator_record_roundtrip_is_lossless() {
        let original = sample_validator_info();
        let stored: StoredValidatorRecord = (&original).into();
        let back: ValidatorInfo = (&stored).into();
        assert_eq!(original, back, "round-trip must preserve every field");
    }

    /// Consensus-affecting fields land in the consensus half; everything else in
    /// metadata. Locks the boundary so a field can't silently change sides (#56).
    #[test]
    fn validator_record_split_places_fields_correctly() {
        let info = sample_validator_info();
        let s: StoredValidatorRecord = (&info).into();
        // CONSENSUS half — only fields with a verified consensus read.
        assert_eq!(s.consensus.identity_id, info.identity_id);
        assert_eq!(s.consensus.consensus_key, info.consensus_key);
        assert_eq!(s.consensus.stake, info.stake);
        assert_eq!(s.consensus.storage_provided, info.storage_provided);
        assert_eq!(s.consensus.status, info.status);
        assert_eq!(s.consensus.oracle_key_id, info.oracle_key_id);
        // METADATA half — ops / routing / provenance, incl. the other two keys.
        assert_eq!(s.metadata.networking_key, info.networking_key);
        assert_eq!(s.metadata.rewards_key, info.rewards_key);
        assert_eq!(s.metadata.network_address, info.network_address);
        assert_eq!(s.metadata.commission_rate, info.commission_rate);
        assert_eq!(s.metadata.registered_at, info.registered_at);
        assert_eq!(s.metadata.last_activity, info.last_activity);
        assert_eq!(s.metadata.blocks_validated, info.blocks_validated);
        assert_eq!(s.metadata.slash_count, info.slash_count);
        assert_eq!(s.metadata.admission_source, info.admission_source);
        assert_eq!(
            s.metadata.governance_proposal_id,
            info.governance_proposal_id
        );
    }

    /// Update txs must not reset slash_count / provenance fields — slashing-evasion vector (#56).
    #[test]
    fn validator_update_tx_preserves_slash_count_and_provenance_fields() {
        use crate::block::{Block, BlockHeader};
        use crate::integration::crypto_integration::{
            PublicKey, Signature, SignatureAlgorithm,
        };
        use crate::transaction::{ValidatorOperation, ValidatorTransactionData};
        use crate::types::hash::Hash;

        let did = "did:zhtp:val-update".to_string();
        let mut bc = Blockchain::default();
        bc.validator_registry.insert(
            did.clone(),
            ValidatorInfo {
                identity_id: did.clone(),
                stake: 1_000_000,
                storage_provided: 1 << 40,
                consensus_key: [11u8; 2592],
                networking_key: vec![1],
                rewards_key: vec![2],
                network_address: "host:1".to_string(),
                commission_rate: 5,
                status: "active".to_string(),
                registered_at: 3,
                last_activity: 3,
                blocks_validated: 99,
                slash_count: 4,
                admission_source: "governance".to_string(),
                governance_proposal_id: Some("prop-keep".to_string()),
                oracle_key_id: Some([0xAB; 32]),
            },
        );

        let vd = ValidatorTransactionData {
            identity_id: did.clone(),
            stake: 2_000_000,
            storage_provided: 1 << 40,
            consensus_key: [11u8; 2592].to_vec(),
            networking_key: vec![1],
            rewards_key: vec![2],
            network_address: "host:2".to_string(),
            commission_rate: 7,
            operation: ValidatorOperation::Update,
            timestamp: 10,
        };
        let tx = Transaction::new_validator_update(
            vd,
            vec![],
            vec![],
            0,
            Signature {
                signature: vec![],
                public_key: PublicKey::new([11u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 10,
            },
            vec![],
        );
        let header = BlockHeader {
            version: 1,
            previous_hash: [0u8; 32],
            data_helix_root: [0u8; 32],
            timestamp: 10,
            height: 10,
            verification_helix_root: [0u8; 32],
            state_root: [0u8; 32],
            bft_quorum_root: [0u8; 32],
            block_hash: Hash::default(),
        };
        let block = Block::new(header, vec![tx]);
        bc.process_validator_registration_transactions(&block)
            .expect("apply update tx");

        let got = bc.validator_registry.get(&did).expect("validator present");
        assert_eq!(got.stake, 2_000_000, "tx stake applied");
        assert_eq!(got.slash_count, 4, "slash_count must not reset on update");
        assert_eq!(got.blocks_validated, 99, "blocks_validated preserved");
        assert_eq!(got.oracle_key_id, Some([0xAB; 32]), "oracle_key_id preserved");
        assert_eq!(
            got.governance_proposal_id.as_deref(),
            Some("prop-keep"),
            "governance_proposal_id preserved"
        );
        assert_eq!(got.registered_at, 3, "registered_at preserved on update");
    }
}
