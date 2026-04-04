use super::*;

impl Blockchain {
    pub(super) fn current_oracle_epoch(&self) -> u64 {
        let reference_timestamp = self.latest_block().map(|b| b.header.timestamp).unwrap_or(0);
        self.oracle_state.epoch_id(reference_timestamp)
    }

    pub(super) fn is_oracle_committee_proposal_type(proposal_type: &str) -> bool {
        matches!(
            proposal_type,
            "update_oracle_committee" | "oracle_committee_update" | "UpdateOracleCommittee"
        )
    }

    pub(super) fn is_oracle_config_proposal_type(proposal_type: &str) -> bool {
        matches!(
            proposal_type,
            "update_oracle_config" | "oracle_config_update" | "UpdateOracleConfig"
        )
    }

    pub(super) fn is_oracle_protocol_upgrade_proposal_type(proposal_type: &str) -> bool {
        matches!(
            proposal_type,
            "oracle_protocol_upgrade" | "upgrade_oracle_protocol" | "OracleProtocolUpgrade"
        )
    }

    pub fn apply_oracle_protocol_upgrade(&mut self, proposal_id: Hash) -> Result<()> {
        if self.executed_dao_proposals.contains(&proposal_id) {
            debug!(
                "Oracle protocol upgrade proposal {:?} already executed, skipping",
                proposal_id
            );
            return Ok(());
        }

        let proposal = self.get_dao_proposal(&proposal_id).ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle protocol upgrade proposal {:?} not found",
                proposal_id
            )
        })?;

        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has not passed voting",
                proposal_id
            ));
        }

        let execution_params = proposal.execution_params.ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle protocol upgrade proposal {:?} has no execution parameters",
                proposal_id
            )
        })?;

        let upgrade_data: crate::transaction::OracleProtocolUpgradeData =
            bincode::deserialize(&execution_params).map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to decode oracle protocol upgrade params: {}",
                    e
                )
            })?;

        upgrade_data.validate(self.height).map_err(|e| {
            anyhow::anyhow!(
                "ParameterValidationError: Invalid oracle protocol upgrade: {}",
                e
            )
        })?;

        let target_version =
            crate::oracle::OracleProtocolVersion::from_u16(upgrade_data.target_version)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "ParameterValidationError: Invalid target protocol version {}",
                        upgrade_data.target_version
                    )
                })?;

        self.oracle_state
            .schedule_protocol_upgrade(
                target_version,
                upgrade_data.activate_at_height,
                self.height,
                Some(proposal_id.as_array()),
            )
            .map_err(|e| {
                anyhow::anyhow!("ScheduleError: Failed to schedule protocol upgrade: {}", e)
            })?;

        self.executed_dao_proposals.insert(proposal_id);
        info!(
            "🔮 Oracle protocol upgrade scheduled: v{} at height {} (proposal {:?})",
            upgrade_data.target_version, upgrade_data.activate_at_height, proposal_id
        );
        Ok(())
    }

    pub fn apply_oracle_committee_update(&mut self, proposal_id: Hash) -> Result<()> {
        if self.executed_dao_proposals.contains(&proposal_id) {
            debug!(
                "Oracle committee proposal {:?} already executed, skipping",
                proposal_id
            );
            return Ok(());
        }

        let proposal = self.get_dao_proposal(&proposal_id).ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle committee proposal {:?} not found",
                proposal_id
            )
        })?;

        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has not passed voting",
                proposal_id
            ));
        }

        let execution_params = proposal.execution_params.ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle committee proposal {:?} has no execution parameters",
                proposal_id
            )
        })?;

        let update_data: crate::transaction::OracleCommitteeUpdateData =
            bincode::deserialize(&execution_params).map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to decode oracle committee update params: {}",
                    e
                )
            })?;

        let current_epoch = self.current_oracle_epoch();
        update_data.validate(current_epoch).map_err(|e| {
            anyhow::anyhow!(
                "ParameterValidationError: Invalid oracle committee update: {}",
                e
            )
        })?;

        let active_validator_key_ids: HashSet<[u8; 32]> = self
            .validator_registry
            .values()
            .filter(|v| v.status == "active")
            .map(|v| {
                v.oracle_key_id
                    .unwrap_or_else(|| crate::types::hash::blake3_hash(&v.consensus_key).as_array())
            })
            .collect();

        for member in &update_data.new_members {
            if !active_validator_key_ids.contains(member) {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: committee member {} is not an active validator key_id",
                    hex::encode(member)
                ));
            }
        }

        self.oracle_state
            .schedule_committee_update(
                update_data.new_members.clone(),
                update_data.activate_at_epoch,
                current_epoch,
                Some(proposal_id.as_array()),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to schedule committee update: {}",
                    e
                )
            })?;

        self.executed_dao_proposals.insert(proposal_id);
        Ok(())
    }

    pub fn bootstrap_oracle_committee(
        &mut self,
        members_with_pubkeys: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<()> {
        if !self.oracle_state.committee.members().is_empty() {
            return Err(anyhow::anyhow!(
                "Oracle committee already initialized; use DAO governance proposals to modify it"
            ));
        }
        if members_with_pubkeys.is_empty() {
            return Err(anyhow::anyhow!("Oracle committee members cannot be empty"));
        }
        let member_ids: Vec<[u8; 32]> = members_with_pubkeys.iter().map(|(id, _)| *id).collect();
        let unique: std::collections::BTreeSet<[u8; 32]> = member_ids.iter().copied().collect();
        if unique.len() != member_ids.len() {
            return Err(anyhow::anyhow!(
                "Oracle committee members must not contain duplicates"
            ));
        }
        for (key_id, pk) in &members_with_pubkeys {
            if !pk.is_empty() {
                self.oracle_state
                    .oracle_signing_pubkeys
                    .insert(*key_id, pk.clone());
            }
        }
        self.oracle_state
            .committee
            .set_members_genesis_only(member_ids);
        info!(
            "🔮 Oracle committee bootstrapped with {} members",
            self.oracle_state.committee.members().len()
        );

        if let Some(store) = &self.store {
            if let Err(e) = store.save_oracle_state(&self.oracle_state) {
                warn!("⚠️ Failed to persist oracle_state to SledStore: {}", e);
            } else {
                info!("🔮 Oracle state persisted to SledStore");
            }
        }

        Ok(())
    }

    pub fn apply_oracle_config_update(&mut self, proposal_id: Hash) -> Result<()> {
        if self.executed_dao_proposals.contains(&proposal_id) {
            debug!(
                "Oracle config proposal {:?} already executed, skipping",
                proposal_id
            );
            return Ok(());
        }

        let proposal = self.get_dao_proposal(&proposal_id).ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle config proposal {:?} not found",
                proposal_id
            )
        })?;

        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has not passed voting",
                proposal_id
            ));
        }

        let execution_params = proposal.execution_params.ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Oracle config proposal {:?} has no execution parameters",
                proposal_id
            )
        })?;

        let update_data: crate::transaction::OracleConfigUpdateData =
            bincode::deserialize(&execution_params).map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to decode oracle config update params: {}",
                    e
                )
            })?;

        let current_epoch = self.current_oracle_epoch();
        update_data.validate(current_epoch).map_err(|e| {
            anyhow::anyhow!(
                "ParameterValidationError: Invalid oracle config update: {}",
                e
            )
        })?;

        let mut next_config = crate::oracle::OracleConfig::default();
        next_config.epoch_duration_secs = update_data.epoch_duration_secs;
        next_config.max_source_age_secs = update_data.max_source_age_secs;
        next_config.max_deviation_bps = update_data.max_deviation_bps;
        next_config.max_price_staleness_epochs = update_data.max_price_staleness_epochs;

        self.oracle_state
            .schedule_config_update(
                next_config,
                update_data.activate_at_epoch,
                current_epoch,
                Some(proposal_id.as_array()),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to schedule config update: {}",
                    e
                )
            })?;

        self.executed_dao_proposals.insert(proposal_id);
        Ok(())
    }

    pub(super) fn apply_cancel_oracle_update(&mut self, proposal_id: Hash) -> Result<()> {
        let proposal = self
            .get_dao_proposals()
            .iter()
            .find(|p| p.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;

        let cancel_data: crate::transaction::CancelOracleUpdateData =
            match &proposal.execution_params {
                Some(params) => bincode::deserialize(params)
                    .map_err(|e| anyhow::anyhow!("Failed to deserialize cancel data: {}", e))?,
                None => return Err(anyhow::anyhow!("Missing execution_params in cancel proposal")),
            };

        cancel_data
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid cancel data: {}", e))?;

        let cancelled = self.oracle_state.cancel_pending_updates(
            cancel_data.cancel_committee_update,
            cancel_data.cancel_config_update,
        );

        if cancelled {
            self.executed_dao_proposals.insert(proposal_id);
            info!(
                "🔮 Cancelled oracle updates by proposal {:?}: committee={}, config={}",
                proposal_id, cancel_data.cancel_committee_update, cancel_data.cancel_config_update
            );
        } else {
            info!(
                "🔮 No pending oracle updates to cancel for proposal {:?}",
                proposal_id
            );
            self.executed_dao_proposals.insert(proposal_id);
        }

        Ok(())
    }
}

impl Blockchain {
    pub fn validate_cbe_graduation_oracle_gate(
        &self,
        token_id: [u8; 32],
        block_timestamp: u64,
    ) -> Result<()> {
        use crate::contracts::tokens::CBE_SYMBOL;
        use crate::oracle::ORACLE_PRICE_SCALE;

        const CBE_GRADUATION_THRESHOLD_USD: u128 = 269_000;
        const MICRO_USD_PER_USD: u128 = 1_000_000;

        let token = if let Some(store) = &self.store {
            store
                .get_bonding_curve_token(&crate::storage::TokenId(token_id))
                .map_err(|e| anyhow::anyhow!("failed to read bonding curve token: {}", e))?
                .or_else(|| self.bonding_curve_registry.get(&token_id).cloned())
        } else {
            self.bonding_curve_registry.get(&token_id).cloned()
        }
        .ok_or_else(|| anyhow::anyhow!("bonding curve token not found"))?;

        if token.symbol != CBE_SYMBOL || token.phase.is_graduated() {
            return Ok(());
        }

        let current_epoch = self.oracle_state.epoch_id(block_timestamp);
        let fresh_price = self.oracle_state.latest_fresh_price(current_epoch).ok_or_else(|| {
            anyhow::anyhow!(
                "CBE graduation blocked: no fresh finalized oracle price available (current_epoch={})",
                current_epoch
            )
        })?;

        let reserve_sov = token.reserve_balance as u128;
        let sov_usd_price = fresh_price.sov_usd_price;
        let usd_value_scaled = reserve_sov.checked_mul(sov_usd_price).ok_or_else(|| {
            anyhow::anyhow!("CBE graduation blocked: arithmetic overflow in USD value calculation")
        })?;
        let usd_value_micro = usd_value_scaled.checked_div(ORACLE_PRICE_SCALE).ok_or_else(|| {
            anyhow::anyhow!("CBE graduation blocked: division by zero in USD value calculation")
        })?;
        let threshold_micro_usd = CBE_GRADUATION_THRESHOLD_USD * MICRO_USD_PER_USD;

        if usd_value_micro < threshold_micro_usd {
            return Err(anyhow::anyhow!(
                "CBE graduation blocked: reserve USD value below threshold (reserve_sov={}, sov_usd_price={}, usd_value_micro={}, threshold_micro={})",
                reserve_sov,
                sov_usd_price,
                usd_value_micro,
                threshold_micro_usd
            ));
        }

        Ok(())
    }

    pub(super) fn validate_block_cbe_graduation_gating(&self, block: &Block) -> Result<()> {
        for tx in &block.transactions {
            if tx.transaction_type
                != crate::types::transaction_type::TransactionType::BondingCurveGraduate
            {
                continue;
            }
            let data = tx
                .bonding_curve_graduate_data()
                .ok_or_else(|| anyhow::anyhow!("BondingCurveGraduate missing data"))?;
            self.validate_cbe_graduation_oracle_gate(data.token_id, block.header.timestamp)?;
        }
        Ok(())
    }

    pub fn slash_oracle_validator(
        &mut self,
        key_id: [u8; 32],
        reason: crate::oracle::OracleSlashReason,
        epoch_id: u64,
    ) -> u64 {
        self.slash_oracle_validator_with_options(key_id, reason, epoch_id, false)
    }

    pub fn slash_oracle_validator_with_options(
        &mut self,
        key_id: [u8; 32],
        reason: crate::oracle::OracleSlashReason,
        epoch_id: u64,
        aligned_removal: bool,
    ) -> u64 {
        use crate::types::hash::blake3_hash;

        let validator = self.validator_registry.values_mut().find(|v| {
            let kid = blake3_hash(&v.consensus_key).as_array();
            kid == key_id
        });

        let slash_amount = if let Some(v) = validator {
            let config = &self.oracle_slashing_config;
            let amount = config.calculate_slash(v.stake);
            v.stake = v.stake.saturating_sub(amount);
            amount
        } else {
            0
        };

        self.oracle_banned_validators.insert(key_id);

        let committee_removal_at_epoch = if aligned_removal {
            let removal_epoch = epoch_id.saturating_add(1);
            self.oracle_state
                .committee_removal_queue
                .push(crate::oracle::CommitteeRemovalEntry {
                    validator_key_id: key_id,
                    remove_at_epoch: removal_epoch,
                    reason,
                });
            info!(
                "⚔️ Oracle validator {} queued for committee removal at epoch {} (aligned semantics)",
                hex::encode(&key_id[..8]),
                removal_epoch
            );
            Some(removal_epoch)
        } else {
            self.oracle_state.committee.remove_member(key_id);
            None
        };

        self.oracle_slash_events
            .push(crate::oracle::OracleSlashEvent {
                validator_key_id: key_id,
                reason,
                epoch_id,
                slash_amount,
                slashed_at_height: self.height,
                committee_removal_at_epoch,
            });

        if slash_amount > 0 {
            warn!(
                "⚔️ Oracle validator {} slashed {} SOV for {} at epoch {}",
                hex::encode(&key_id[..8]),
                slash_amount,
                reason,
                epoch_id
            );
        } else {
            info!(
                "⚔️ Oracle validator {} banned for {} at epoch {} (no stake to slash)",
                hex::encode(&key_id[..8]),
                reason,
                epoch_id
            );
        }

        slash_amount
    }

    pub fn apply_pending_committee_removals(&mut self, current_epoch: u64) {
        let queue = &mut self.oracle_state.committee_removal_queue;
        let mut remaining = Vec::with_capacity(queue.len());

        for entry in queue.drain(..) {
            if entry.remove_at_epoch <= current_epoch {
                self.oracle_state
                    .committee
                    .remove_member(entry.validator_key_id);
                info!(
                    "🚫 Oracle validator {} removed from committee at epoch {} (scheduled for {})",
                    hex::encode(&entry.validator_key_id[..8]),
                    current_epoch,
                    entry.remove_at_epoch
                );
            } else {
                remaining.push(entry);
            }
        }

        *queue = remaining;
    }

    pub fn init_oracle_committee(&mut self, members: Vec<[u8; 32]>) -> Result<()> {
        if !self.oracle_state.committee.members().is_empty() {
            return Err(anyhow::anyhow!("Oracle committee already initialized"));
        }

        self.oracle_state
            .committee
            .set_members_genesis_only(members);
        Ok(())
    }

    pub(super) fn process_oracle_attestation_transactions(
        &mut self,
        block: &Block,
        block_timestamp: u64,
    ) {
        for tx in &block.transactions {
            if tx.transaction_type == TransactionType::OracleAttestation {
                if let Some(data) = tx.oracle_attestation_data() {
                    let attestation = crate::oracle::OraclePriceAttestation {
                        epoch_id: data.epoch_id,
                        sov_usd_price: data.sov_usd_price,
                        cbe_usd_price: data.cbe_usd_price,
                        timestamp: data.timestamp,
                        validator_pubkey: data.validator_pubkey,
                        signature: data.signature.clone(),
                    };

                    match self.apply_oracle_attestation(&attestation, block_timestamp) {
                        Ok(outcome) => {
                            if outcome.finalized {
                                info!(
                                    "🔮 Oracle epoch {} finalized at price {} via transaction",
                                    outcome.epoch_id, outcome.sov_usd_price
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "🔮 Oracle attestation transaction failed: {} (tx hash: {})",
                                e,
                                hex::encode(tx.hash().as_bytes())
                            );
                        }
                    }
                }
            }
        }
    }

    pub fn apply_oracle_attestation(
        &mut self,
        attestation: &crate::oracle::OraclePriceAttestation,
        block_timestamp: u64,
    ) -> Result<crate::execution::tx_apply::OracleAttestationOutcome, String> {
        let current_epoch = self.oracle_state.epoch_id(block_timestamp);

        let oracle_pubkeys = self.oracle_state.oracle_signing_pubkeys.clone();
        let key_map: Vec<([u8; 32], Vec<u8>)> = self
            .validator_registry
            .values()
            .filter(|v| !v.consensus_key.is_empty())
            .map(|v| {
                let kid = crate::types::hash::blake3_hash(&v.consensus_key).as_array();
                (kid, v.consensus_key.clone())
            })
            .collect();

        let result = self.oracle_state.process_attestation(attestation, current_epoch, |key_id| {
            if let Some(pk) = oracle_pubkeys.get(&key_id) {
                if !pk.is_empty() {
                    return Some(pk.clone());
                }
            }
            key_map
                .iter()
                .find(|(kid, _)| *kid == key_id)
                .map(|(_, pk)| pk.clone())
        });

        match result {
            Ok(admission) => {
                let finalized = matches!(
                    admission,
                    crate::oracle::OracleAttestationAdmission::Finalized(_)
                );

                if let crate::oracle::OracleAttestationAdmission::Finalized(ref price) = admission {
                    if let Some(cbe_price) = price.cbe_usd_price {
                        self.token_pricing_state.update_cbe_usd_price(
                            cbe_price,
                            price.epoch_id,
                            block_timestamp,
                        );
                        info!(
                            "💰 Token pricing state updated with CBE/USD price {} from oracle epoch {}",
                            cbe_price, price.epoch_id
                        );
                    }
                }

                Ok(crate::execution::tx_apply::OracleAttestationOutcome {
                    epoch_id: attestation.epoch_id,
                    validator_pubkey: attestation.validator_pubkey,
                    sov_usd_price: attestation.sov_usd_price,
                    finalized,
                })
            }
            Err(crate::oracle::OracleAttestationAdmissionError::ConflictingSigner { .. }) => {
                self.slash_oracle_validator(
                    attestation.validator_pubkey,
                    crate::oracle::OracleSlashReason::ConflictingAttestation,
                    attestation.epoch_id,
                );
                Err("Conflicting attestation detected - validator double-signed".to_string())
            }
            Err(e) => Err(format!("Attestation rejected: {:?}", e)),
        }
    }
}
