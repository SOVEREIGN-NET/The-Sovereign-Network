use super::*;
use crate::storage::{StoredValidatorRecord, ValidatorConsensusRecord, ValidatorMetadata};

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
    pub fn register_validator(&mut self, validator_info: ValidatorInfo) -> Result<Hash> {
        if self
            .validator_registry
            .contains_key(&validator_info.identity_id)
        {
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

    pub fn validator_exists(&self, identity_id: &str) -> bool {
        self.validator_registry.contains_key(identity_id)
    }

    pub fn list_all_validators(&self) -> Vec<&ValidatorInfo> {
        self.validator_registry.values().collect()
    }

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
        self.get_active_validators()
            .iter()
            .map(|v| (v.identity_id.clone(), v.stake))
            .collect()
    }

    pub fn get_total_validator_stake(&self) -> u64 {
        self.get_active_validators()
            .iter()
            .fold(0u64, |sum, v| sum.saturating_add(v.stake))
    }

    pub fn is_validator_active(&self, identity_id: &str) -> bool {
        self.validator_registry
            .get(identity_id)
            .map(|validator| validator.status == "active" && validator.stake > 0)
            .unwrap_or(false)
    }

    pub fn sync_validator_set_to_consensus(&self) {
        let active_validators = self.get_active_validators();
        info!(
            "Validator set sync: {} active validators with {} total stake",
            active_validators.len(),
            self.get_total_validator_stake()
        );

        for validator in active_validators {
            debug!(
                "Validator in sync: {} (stake: {}, joined at height: {})",
                validator.identity_id, validator.stake, validator.registered_at
            );
        }
    }

    pub fn process_validator_registration_transactions(&mut self, block: &Block) {
        let height = block.height();
        for tx in &block.transactions {
            if let Some(validator_data) = tx.validator_data() {
                let status = match validator_data.operation {
                    crate::transaction::ValidatorOperation::Register => "active",
                    crate::transaction::ValidatorOperation::Update => "active",
                    crate::transaction::ValidatorOperation::Unregister => "inactive",
                };
                let validator_info = ValidatorInfo {
                    identity_id: validator_data.identity_id.clone(),
                    stake: validator_data.stake,
                    storage_provided: validator_data.storage_provided,
                    consensus_key: validator_data.consensus_key.as_slice().try_into().unwrap_or([0u8; 2592]),
                    networking_key: validator_data.networking_key.clone(),
                    rewards_key: validator_data.rewards_key.clone(),
                    network_address: validator_data.network_address.clone(),
                    commission_rate: validator_data.commission_rate,
                    status: status.to_string(),
                    registered_at: height,
                    last_activity: height,
                    blocks_validated: 0,
                    slash_count: 0,
                    admission_source: ADMISSION_SOURCE_ONCHAIN_GOVERNANCE.to_string(),
                    governance_proposal_id: None,
                    oracle_key_id: None,
                };
                self.validator_registry
                    .insert(validator_data.identity_id.clone(), validator_info);
                self.validator_blocks
                    .insert(validator_data.identity_id.clone(), height);
                info!(
                    "Registered new validator {} with {} SOV stake",
                    &validator_data.identity_id[..validator_data.identity_id.len().min(40)],
                    validator_data.stake
                );
            }
        }
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
}
