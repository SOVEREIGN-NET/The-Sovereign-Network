use super::*;

impl Blockchain {
    /// Idempotently populate the Bootstrap Council from config.
    pub fn ensure_council_bootstrap(&mut self, config: &crate::dao::CouncilBootstrapConfig) {
        if !self.council_members.is_empty() || config.members.is_empty() {
            return;
        }

        self.council_threshold = if config.threshold == 0 {
            4
        } else {
            config.threshold
        };

        for entry in &config.members {
            self.council_members.push(crate::dao::CouncilMember {
                identity_id: entry.identity_id.clone(),
                wallet_id: entry.wallet_id.clone(),
                stake_amount: entry.stake_amount,
                joined_at_height: self.height,
            });
        }

        info!(
            "🏛️ Bootstrap Council initialized: {} members, threshold {}",
            self.council_members.len(),
            self.council_threshold
        );
    }

    pub fn is_council_member(&self, did: &str) -> bool {
        self.council_members.iter().any(|m| m.identity_id == did)
    }

    pub fn get_council_members(&self) -> &[crate::dao::CouncilMember] {
        &self.council_members
    }

    pub fn activate_emergency_state(
        &mut self,
        council_signatures: &[String],
        activated_by: String,
    ) -> Result<()> {
        let threshold = self.council_threshold as usize;
        let valid = council_signatures
            .iter()
            .filter(|did| self.is_council_member(did.as_str()))
            .count();
        if valid < threshold {
            return Err(anyhow::anyhow!(
                "Emergency activation requires {} council signatures, got {}",
                threshold,
                valid
            ));
        }
        let expiry = self.height + self.treasury_epoch_length_blocks.max(1);
        self.emergency_state = true;
        self.emergency_activated_at = Some(self.height);
        self.emergency_activated_by = Some(activated_by);
        self.emergency_expires_at = Some(expiry);
        info!(
            "🚨 Emergency state activated at height {}, expires at {}",
            self.height, expiry
        );
        Ok(())
    }

    pub fn validate_treasury_spending_category(
        &self,
        params: &crate::dao::TreasuryExecutionParams,
    ) -> Result<()> {
        if params.category == crate::dao::TreasurySpendingCategory::Emergency
            && !self.emergency_state
        {
            return Err(anyhow::anyhow!(
                "Treasury spending category 'Emergency' requires emergency_state to be active"
            ));
        }
        Ok(())
    }

    pub fn compute_decentralization_snapshot(&self) -> crate::dao::DecentralizationSnapshot {
        let citizen_count = self.identity_registry.len() as u64;

        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let max_wallet_pct_bps: u16 = if let Some(token) = self.token_contracts.get(&sov_id) {
            let total = token.total_supply;
            if total == 0 {
                0
            } else {
                let max_bal = token.max_balance();
                ((max_bal as u128 * 10_000) / total as u128).min(u16::MAX as u128) as u16
            }
        } else {
            0
        };

        crate::dao::DecentralizationSnapshot {
            verified_citizen_count: citizen_count,
            max_wallet_pct_bps,
            snapshot_height: self.height,
        }
    }

    pub fn check_phase0_to_phase1(&self) -> bool {
        let cfg = &self.phase_transition_config;
        let snap = self.compute_decentralization_snapshot();
        let cond_a = snap.verified_citizen_count >= cfg.min_citizens_for_phase1;
        let cond_b = snap.max_wallet_pct_bps <= cfg.max_wallet_pct_bps_for_phase1;
        let cond_c = cfg
            .phase0_max_duration_blocks
            .map(|n| self.height >= n)
            .unwrap_or(false);

        cond_a || cond_b || cond_c
    }

    pub fn check_phase1_to_phase2(&self) -> bool {
        let cfg = &self.phase_transition_config;
        let snap = self.compute_decentralization_snapshot();

        let enough_citizens = snap.verified_citizen_count >= cfg.min_citizens_for_phase2;
        let low_concentration = snap.max_wallet_pct_bps <= cfg.max_wallet_pct_bps_for_phase2;
        let quorum_cycles =
            self.governance_cycles_with_quorum >= cfg.phase2_quorum_consecutive_cycles;

        enough_citizens && low_concentration && quorum_cycles
    }

    pub fn try_advance_governance_phase(&mut self) {
        match self.governance_phase {
            crate::dao::GovernancePhase::Bootstrap => {
                if self.check_phase0_to_phase1() {
                    let snap = self.compute_decentralization_snapshot();
                    self.last_decentralization_snapshot = Some(snap);
                    self.governance_phase = crate::dao::GovernancePhase::Hybrid;
                    info!(
                        "🗳 Governance advanced to Hybrid phase at height {}",
                        self.height
                    );
                }
            }
            crate::dao::GovernancePhase::Hybrid => {
                if self.check_phase1_to_phase2() {
                    let snap = self.compute_decentralization_snapshot();
                    self.last_decentralization_snapshot = Some(snap);
                    self.governance_phase = crate::dao::GovernancePhase::FullDao;
                    self.council_members.clear();
                    self.council_threshold = 0;
                    info!(
                        "🏛 Governance advanced to Full DAO phase at height {}",
                        self.height
                    );
                }
            }
            crate::dao::GovernancePhase::FullDao => {}
        }
    }

    pub async fn create_dao_proposal(
        &self,
        proposer_keypair: &lib_crypto::KeyPair,
        title: String,
        description: String,
        proposal_type: lib_consensus::DaoProposalType,
    ) -> Result<crate::types::Hash> {
        let proposal_tx =
            crate::integration::consensus_integration::create_dao_proposal_transaction(
                proposer_keypair,
                title,
                description,
                proposal_type,
            )?;

        Ok(proposal_tx.hash())
    }

    pub async fn cast_dao_vote(
        &self,
        voter_keypair: &lib_crypto::KeyPair,
        proposal_id: lib_crypto::Hash,
        vote_choice: lib_consensus::DaoVoteChoice,
    ) -> Result<crate::types::Hash> {
        let vote_tx = crate::integration::consensus_integration::create_dao_vote_transaction(
            voter_keypair,
            proposal_id,
            vote_choice,
        )?;

        Ok(vote_tx.hash())
    }

    pub fn get_dao_proposals(&self) -> Vec<crate::transaction::DaoProposalData> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter_map(|tx| tx.dao_proposal_data())
            .cloned()
            .collect()
    }

    pub fn get_dao_proposal(
        &self,
        proposal_id: &Hash,
    ) -> Option<crate::transaction::DaoProposalData> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoProposal)
            .filter_map(|tx| tx.dao_proposal_data())
            .find(|proposal| &proposal.proposal_id == proposal_id)
            .cloned()
    }

    pub fn get_dao_votes_for_proposal(
        &self,
        proposal_id: &Hash,
    ) -> Vec<crate::transaction::DaoVoteData> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter_map(|tx| tx.dao_vote_data())
            .filter(|vote| &vote.proposal_id == proposal_id)
            .cloned()
            .collect()
    }

    pub fn get_all_dao_votes(&self) -> Vec<crate::transaction::DaoVoteData> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoVote)
            .filter_map(|tx| tx.dao_vote_data())
            .cloned()
            .collect()
    }

    pub fn get_dao_executions(&self) -> Vec<crate::transaction::DaoExecutionData> {
        self.blocks
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.transaction_type == TransactionType::DaoExecution)
            .filter_map(|tx| tx.dao_execution_data())
            .cloned()
            .collect()
    }

    fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        let decoded = hex::decode(trimmed).ok()?;
        if decoded.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Some(out)
    }

    fn parse_dao_class(value: &str) -> Option<crate::types::dao::DAOType> {
        crate::types::dao::DAOType::from_str(value)
    }

    pub(crate) const DAO_REGISTRY_REGISTER_EXEC: &'static str = "dao_registry_register_v1";
    pub(crate) const DAO_FACTORY_CREATE_EXEC: &'static str = "dao_factory_create_v1";

    fn dao_registry_entry_from_tx(
        tx: &Transaction,
        block_height: u64,
    ) -> Option<DaoRegistryIndexEntry> {
        if tx.transaction_type != TransactionType::DaoExecution {
            return None;
        }
        let exec = tx.dao_execution_data()?;
        if exec.execution_type != Self::DAO_REGISTRY_REGISTER_EXEC
            && exec.execution_type != Self::DAO_FACTORY_CREATE_EXEC
        {
            return None;
        }
        let event_bytes = exec.multisig_signatures.first()?;
        let event = serde_json::from_slice::<serde_json::Value>(event_bytes).ok()?;
        let token_key_id = event
            .get("token_id")
            .and_then(|v| v.as_str())
            .and_then(Self::parse_hex_32)?;
        let class_str = event
            .get("class")
            .and_then(|v| v.as_str())
            .map(|v| v.to_ascii_lowercase())?;
        let metadata_hash = event
            .get("metadata_hash")
            .and_then(|v| v.as_str())
            .and_then(Self::parse_hex_32)?;
        let treasury_key_id = event
            .get("treasury_key_id")
            .and_then(|v| v.as_str())
            .and_then(Self::parse_hex_32)?;
        let class = Self::parse_dao_class(&class_str)?;
        let token_addr = crate::integration::crypto_integration::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: token_key_id,
        };
        let treasury = crate::integration::crypto_integration::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: treasury_key_id,
        };
        let dao_id = crate::contracts::dao_registry::derive_dao_id(&token_addr, class, &treasury);
        Some(DaoRegistryIndexEntry {
            dao_id,
            token_key_id,
            class: class_str,
            metadata_hash,
            treasury_key_id,
            owner_key_id: tx.signature.public_key.key_id,
            created_at: block_height,
        })
    }

    pub(super) fn index_dao_registry_entry_from_tx(&mut self, tx: &Transaction, block_height: u64) {
        if let Some(entry) = Self::dao_registry_entry_from_tx(tx, block_height) {
            self.dao_registry_index.entry(entry.dao_id).or_insert(entry);
        }
    }

    pub fn rebuild_dao_registry_index(&mut self) {
        let mut rebuilt: HashMap<[u8; 32], DaoRegistryIndexEntry> = HashMap::new();
        for block in &self.blocks {
            for tx in &block.transactions {
                if let Some(entry) = Self::dao_registry_entry_from_tx(tx, block.header.height) {
                    rebuilt.entry(entry.dao_id).or_insert(entry);
                }
            }
        }
        self.dao_registry_index = rebuilt;
    }

    pub fn get_dao_registry_entry(&self, dao_id: &[u8; 32]) -> Option<&DaoRegistryIndexEntry> {
        self.dao_registry_index.get(dao_id)
    }

    pub fn list_dao_registry_entries(&self) -> Vec<&DaoRegistryIndexEntry> {
        let mut entries: Vec<&DaoRegistryIndexEntry> = self.dao_registry_index.values().collect();
        entries.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.dao_id.cmp(&b.dao_id))
        });
        entries
    }

    pub fn tally_dao_votes(&self, proposal_id: &Hash) -> (u64, u64, u64, u64) {
        let votes = self.get_dao_votes_for_proposal(proposal_id);

        let mut yes_votes = 0u64;
        let mut no_votes = 0u64;
        let mut abstain_votes = 0u64;
        let mut total_voting_power = 0u64;

        for vote in votes {
            total_voting_power += vote.voting_power;
            match vote.vote_choice.as_str() {
                "Yes" => yes_votes += vote.voting_power,
                "No" => no_votes += vote.voting_power,
                "Abstain" => abstain_votes += vote.voting_power,
                _ => {}
            }
        }

        (yes_votes, no_votes, abstain_votes, total_voting_power)
    }

    pub fn has_proposal_passed(
        &self,
        proposal_id: &Hash,
        required_approval_percent: u32,
    ) -> Result<bool> {
        let (yes_votes, _no_votes, _abstain_votes, total_voting_power) =
            self.tally_dao_votes(proposal_id);

        if total_voting_power == 0 {
            return Ok(false);
        }

        let approval_percent = (yes_votes * 100) / total_voting_power;
        Ok(approval_percent >= required_approval_percent as u64)
    }

    pub fn get_circulating_sov_supply(&self) -> u128 {
        let sov_id = crate::contracts::utils::generate_lib_token_id();
        self.token_contracts
            .get(&sov_id)
            .map(|t| t.total_supply)
            .unwrap_or(0)
    }

    pub fn has_proposal_passed_with_quorum(
        &self,
        proposal_id: &Hash,
        quorum_pct: u32,
        approval_pct: u32,
    ) -> Result<bool> {
        let (yes_votes, _no, _ab, total_cast) = self.tally_dao_votes(proposal_id);
        if total_cast == 0 {
            return Ok(false);
        }
        let circulating = self.get_circulating_sov_supply().max(1);
        let participation_pct = (total_cast as u128 * 100) / circulating;
        if participation_pct < quorum_pct as u128 {
            return Ok(false);
        }
        let yes_pct = (yes_votes * 100) / total_cast;
        Ok(yes_pct >= approval_pct as u64)
    }

    pub fn set_dao_treasury_wallet(&mut self, wallet_id: String) -> Result<()> {
        if !self.wallet_registry.contains_key(&wallet_id) {
            return Err(anyhow::anyhow!(
                "Treasury wallet {} not found in registry",
                wallet_id
            ));
        }

        info!("🏦 Setting DAO treasury wallet: {}", wallet_id);
        self.dao_treasury_wallet_id = Some(wallet_id);
        Ok(())
    }

    pub fn get_dao_treasury_wallet_id(&self) -> Option<&String> {
        self.dao_treasury_wallet_id.as_ref()
    }

    pub fn get_dao_treasury_wallet(&self) -> Result<&crate::transaction::WalletTransactionData> {
        let wallet_id = self
            .dao_treasury_wallet_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DAO treasury wallet not set"))?;

        self.wallet_registry
            .get(wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Treasury wallet not found in registry"))
    }

    pub fn get_dao_treasury_balance(&self) -> Result<u128> {
        let treasury_wallet_id = self
            .dao_treasury_wallet_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DAO treasury wallet not set"))?;

        let treasury_key = match hex::decode(treasury_wallet_id) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Self::wallet_key_for_sov(&id)
            }
            _ => {
                let treasury_wallet = self.get_dao_treasury_wallet()?;
                let pk_bytes: [u8; 2592] = treasury_wallet.public_key.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("Treasury wallet public key must be 2592 bytes (Dilithium5)"))?;
                crate::integration::crypto_integration::PublicKey::new(pk_bytes)
            }
        };

        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        if let Some(token) = self.token_contracts.get(&sov_token_id) {
            Ok(token.balance_of(&treasury_key))
        } else {
            tracing::debug!(
                "SOV token contract not found, treasury balance query returning 0 during bootstrap"
            );
            Ok(0)
        }
    }

    pub fn get_dao_treasury_utxos(&self) -> Result<Vec<(Hash, TransactionOutput)>> {
        let treasury_wallet = self.get_dao_treasury_wallet()?;
        let pk_bytes: [u8; 2592] = treasury_wallet.public_key.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("Treasury wallet public key must be 2592 bytes (Dilithium5)"))?;
        let treasury_pubkey = crate::integration::crypto_integration::PublicKey::new(pk_bytes);

        let mut utxos = Vec::new();
        for (utxo_id, output) in &self.utxo_set {
            if output.recipient.as_bytes() == treasury_pubkey.as_bytes() {
                utxos.push((*utxo_id, output.clone()));
            }
        }

        Ok(utxos)
    }

    pub fn create_treasury_fee_transaction(
        &self,
        block_height: u64,
        total_fees: u64,
    ) -> Result<Transaction> {
        let treasury_wallet = self.get_dao_treasury_wallet()?;
        let treasury_output = TransactionOutput {
            commitment: crate::types::hash::blake3_hash(&total_fees.to_le_bytes()),
            note: Hash::default(),
            recipient: crate::integration::crypto_integration::PublicKey::new(
                treasury_wallet.public_key.as_slice().try_into().unwrap_or([0u8; 2592]),
            ),
        };

        Ok(Transaction::new(
            vec![],
            vec![treasury_output],
            0,
            crate::integration::crypto_integration::Signature {
                signature: vec![],
                public_key: crate::integration::crypto_integration::PublicKey::new([0u8; 2592]),
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::DEFAULT,
                timestamp: crate::utils::time::current_timestamp(),
            },
            format!(
                "Block {} fee collection: {} SOV to DAO treasury",
                block_height, total_fees
            )
            .into_bytes(),
        ))
    }

    pub fn execute_dao_proposal(
        &mut self,
        proposal_id: Hash,
        executor_identity: String,
        recipient_wallet_id: String,
        amount: u64,
    ) -> Result<Hash> {
        if self.treasury_frozen {
            return Err(anyhow::anyhow!("Treasury is frozen"));
        }
        if amount == 0 {
            return Err(anyhow::anyhow!(
                "Execution amount must be greater than zero"
            ));
        }

        let proposal = self
            .get_dao_proposal(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found"))?;

        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!("Proposal has not passed"));
        }

        if self.executed_dao_proposals.contains(&proposal_id) {
            return Err(anyhow::anyhow!("Proposal already executed"));
        }
        let executions = self.get_dao_executions();
        if executions.iter().any(|exec| exec.proposal_id == proposal_id) {
            return Err(anyhow::anyhow!("Proposal already executed"));
        }
        if self.pending_transactions.iter().any(|tx| {
            tx.transaction_type == TransactionType::DaoExecution
                && tx.dao_execution_data().map(|d| d.proposal_id) == Some(proposal_id)
        }) {
            return Err(anyhow::anyhow!(
                "Proposal execution already pending in mempool"
            ));
        }

        if self.governance_phase == crate::dao::GovernancePhase::Bootstrap {
            let votes = self.get_dao_votes_for_proposal(&proposal_id);
            let council_yes = votes
                .iter()
                .filter(|v| v.vote_choice == "Yes" && self.is_council_member(&v.voter))
                .count() as u8;
            if council_yes < self.council_threshold {
                return Err(anyhow::anyhow!(
                    "Phase 0 requires {} council yes-votes, got {}",
                    self.council_threshold,
                    council_yes
                ));
            }
        }

        let treasury_wallet_id_hex = self
            .dao_treasury_wallet_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DAO treasury wallet not set"))?;
        let treasury_id_bytes: [u8; 32] = hex::decode(&treasury_wallet_id_hex)
            .map_err(|e| anyhow::anyhow!("Invalid treasury wallet hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Treasury wallet ID must be 32 bytes"))?;
        let treasury_pk = Self::wallet_key_for_sov(&treasury_id_bytes);

        let recip_id_bytes: [u8; 32] = hex::decode(&recipient_wallet_id)
            .map_err(|e| anyhow::anyhow!("Invalid recipient wallet hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Recipient wallet ID must be 32 bytes"))?;
        let recipient_pk = Self::wallet_key_for_sov(&recip_id_bytes);

        let treasury_balance = self.get_dao_treasury_balance()?;
        if treasury_balance < amount as u128 {
            return Err(anyhow::anyhow!(
                "Insufficient treasury balance: need {}, available {}",
                amount,
                treasury_balance
            ));
        }
        let epoch = self.height / self.treasury_epoch_length_blocks.max(1);
        let spent_this_epoch = self.treasury_epoch_spend.get(&epoch).copied().unwrap_or(0);
        let epoch_start_balance =
            if let Some(&stored) = self.treasury_epoch_start_balance.get(&epoch) {
                stored
            } else {
                let treasury_balance_u64 = u64::try_from(treasury_balance).unwrap_or(u64::MAX);
                let start = treasury_balance_u64.saturating_add(spent_this_epoch);
                self.treasury_epoch_start_balance.insert(epoch, start);
                start
            };
        let epoch_cap = epoch_start_balance.saturating_mul(5) / 100;
        if spent_this_epoch.saturating_add(amount) > epoch_cap {
            return Err(anyhow::anyhow!(
                "Treasury epoch spend cap: {} + {} > cap {} (epoch-start balance: {})",
                spent_this_epoch,
                amount,
                epoch_cap,
                epoch_start_balance
            ));
        }

        let treasury_exec_params = {
            let bytes = proposal
                .execution_params
                .as_ref()
                .filter(|b| !b.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "spending_category required in execution_params; proposal is missing a valid TreasuryExecutionParams"
                    )
                })?;
            serde_json::from_slice::<crate::dao::TreasuryExecutionParams>(bytes).map_err(|e| {
                anyhow::anyhow!(
                    "execution_params could not be deserialized as TreasuryExecutionParams: {}",
                    e
                )
            })?
        };
        self.validate_treasury_spending_category(&treasury_exec_params)?;

        let sov_id = crate::contracts::utils::generate_lib_token_id();
        let sov_token = self
            .token_contracts
            .get_mut(&sov_id)
            .ok_or_else(|| anyhow::anyhow!("SOV token contract not found"))?;
        sov_token
            .debit_balance(&treasury_pk, amount as u128)
            .map_err(|e| anyhow::anyhow!("Treasury debit failed: {}", e))?;
        sov_token
            .credit_balance(&recipient_pk, amount as u128)
            .map_err(|e| anyhow::anyhow!("Recipient credit failed: {}", e))?;

        *self.treasury_epoch_spend.entry(epoch).or_insert(0) += amount;

        let votes = self.get_dao_votes_for_proposal(&proposal_id);
        let multisig_signatures: Vec<Vec<u8>> = votes
            .iter()
            .filter(|v| v.vote_choice == "Yes")
            .map(|v| v.voter.as_bytes().to_vec())
            .collect();

        let now = crate::utils::time::current_timestamp();
        let execution_data = crate::transaction::DaoExecutionData {
            proposal_id,
            executor: executor_identity.clone(),
            execution_type: "TreasurySpending".to_string(),
            recipient: Some(recipient_wallet_id.clone()),
            amount: Some(amount),
            executed_at: now,
            executed_at_height: self.height,
            multisig_signatures,
        };

        let proposal_id_bytes = proposal_id.as_bytes();
        let memo_text = format!(
            "DAO Proposal {} Execution",
            hex::encode(&proposal_id_bytes[..8])
        );
        let executor_pubkey = self
            .identity_registry
            .get(&executor_identity)
            .map(|id| crate::integration::crypto_integration::PublicKey::new(
                id.public_key.as_slice().try_into().unwrap_or([0u8; 2592])
            ))
            .unwrap_or_else(|| crate::integration::crypto_integration::PublicKey::new([0u8; 2592]));
        let sig_bytes = crate::types::hash::blake3_hash(
            &[
                proposal_id.as_bytes(),
                executor_identity.as_bytes(),
                &now.to_le_bytes(),
            ]
            .concat(),
        )
        .as_bytes()
        .to_vec();
        let execution_tx = Transaction::new_dao_execution(
            execution_data,
            Vec::new(),
            Vec::new(),
            0,
            crate::integration::crypto_integration::Signature {
                signature: sig_bytes,
                public_key: executor_pubkey,
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::DEFAULT,
                timestamp: now,
            },
            memo_text.into_bytes(),
        );

        let tx_hash = execution_tx.hash();
        self.add_pending_transaction(execution_tx)?;
        self.executed_dao_proposals.insert(proposal_id);

        info!(
            "✅ DAO proposal {:?} executed (balance model), tx: {:?}",
            proposal_id, tx_hash
        );
        Ok(tx_hash)
    }

    pub fn apply_difficulty_parameter_update(&mut self, proposal_id: Hash) -> Result<()> {
        if self.executed_dao_proposals.contains(&proposal_id) {
            debug!(
                "Difficulty proposal {:?} already executed, skipping",
                proposal_id
            );
            return Ok(());
        }

        let proposal = self.get_dao_proposal(&proposal_id).ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Difficulty parameter update proposal {:?} not found",
                proposal_id
            )
        })?;

        if !self.has_proposal_passed(&proposal_id, proposal.quorum_required as u32)? {
            return Err(anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has not passed voting",
                proposal_id
            ));
        }

        let execution_params_bytes = proposal.execution_params.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "InvalidProposal: Proposal {:?} has no execution parameters",
                proposal_id
            )
        })?;

        let execution_params: lib_consensus::dao::dao_types::DaoExecutionParams =
            bincode::deserialize(&execution_params_bytes).map_err(|e| {
                anyhow::anyhow!(
                    "ParameterValidationError: Failed to decode execution params: {}",
                    e
                )
            })?;

        let update = match execution_params.action {
            lib_consensus::dao::dao_types::DaoExecutionAction::GovernanceParameterUpdate(
                update,
            ) => update,
            _ => {
                return Err(anyhow::anyhow!(
                    "InvalidProposal: Proposal {:?} is not a governance parameter update",
                    proposal_id
                ))
            }
        };

        let mut new_target_timespan: Option<u64> = None;
        let mut new_adjustment_interval: Option<u64> = None;
        let mut new_base_fee: Option<u64> = None;
        let mut new_bytes_per_sov: Option<u64> = None;
        let mut new_witness_cap: Option<u32> = None;
        let mut new_token_creation_fee: Option<u64> = None;

        for param in &update.updates {
            match param {
                lib_consensus::dao::dao_types::GovernanceParameterValue::BlockchainTargetTimespan(v) => {
                    new_target_timespan = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::BlockchainAdjustmentInterval(v) => {
                    new_adjustment_interval = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::TxFeeBase(v) => {
                    new_base_fee = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::TxFeeBytesPerSov(v) => {
                    new_bytes_per_sov = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::TxFeeWitnessCap(v) => {
                    new_witness_cap = Some(*v);
                }
                lib_consensus::dao::dao_types::GovernanceParameterValue::TokenCreationFee(v) => {
                    new_token_creation_fee = Some(*v);
                }
                _ => {}
            }
        }

        if new_target_timespan.is_none()
            && new_adjustment_interval.is_none()
            && new_base_fee.is_none()
            && new_bytes_per_sov.is_none()
            && new_witness_cap.is_none()
            && new_token_creation_fee.is_none()
        {
            return Err(anyhow::anyhow!(
                "ParameterValidationError: No applicable parameters found in governance update"
            ));
        }

        if let Some(ts) = new_target_timespan {
            if ts == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: target_timespan cannot be zero"
                ));
            }
        }
        if let Some(ai) = new_adjustment_interval {
            if ai == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: adjustment_interval cannot be zero"
                ));
            }
        }
        if let Some(base_fee) = new_base_fee {
            if base_fee == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: base_fee cannot be zero"
                ));
            }
        }
        if let Some(bytes_per_sov) = new_bytes_per_sov {
            if bytes_per_sov == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: bytes_per_sov cannot be zero"
                ));
            }
        }
        if let Some(witness_cap) = new_witness_cap {
            if witness_cap == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: witness_cap cannot be zero"
                ));
            }
        }
        if let Some(token_creation_fee) = new_token_creation_fee {
            if token_creation_fee == 0 {
                return Err(anyhow::anyhow!(
                    "ParameterValidationError: token_creation_fee cannot be zero"
                ));
            }
        }

        info!(
            "📊 Applying difficulty parameter update from proposal {:?}",
            proposal_id
        );
        if let Some(ts) = new_target_timespan {
            info!(
                "   target_timespan: {} → {}",
                self.difficulty_config.target_timespan, ts
            );
        }
        if let Some(ai) = new_adjustment_interval {
            info!(
                "   adjustment_interval: {} → {}",
                self.difficulty_config.adjustment_interval, ai
            );
        }
        if let Some(base_fee) = new_base_fee {
            info!(
                "   tx_base_fee: {} → {}",
                self.tx_fee_config.base_fee, base_fee
            );
        }
        if let Some(bytes_per_sov) = new_bytes_per_sov {
            info!(
                "   tx_bytes_per_sov: {} → {}",
                self.tx_fee_config.bytes_per_sov, bytes_per_sov
            );
        }
        if let Some(witness_cap) = new_witness_cap {
            info!(
                "   tx_witness_cap: {} → {}",
                self.tx_fee_config.witness_cap, witness_cap
            );
        }
        if let Some(token_creation_fee) = new_token_creation_fee {
            info!(
                "   token_creation_fee: {} → {}",
                self.tx_fee_config.token_creation_fee, token_creation_fee
            );
        }

        if let Some(ts) = new_target_timespan {
            self.difficulty_config.target_timespan = ts;
        }
        if let Some(ai) = new_adjustment_interval {
            self.difficulty_config.adjustment_interval = ai;
        }
        if let Some(base_fee) = new_base_fee {
            self.tx_fee_config.base_fee = base_fee;
            self.tx_fee_config_updated_at_height = self.height;
        }
        if let Some(bytes_per_sov) = new_bytes_per_sov {
            self.tx_fee_config.bytes_per_sov = bytes_per_sov;
            self.tx_fee_config_updated_at_height = self.height;
        }
        if let Some(witness_cap) = new_witness_cap {
            self.tx_fee_config.witness_cap = witness_cap;
            self.tx_fee_config_updated_at_height = self.height;
        }
        if let Some(token_creation_fee) = new_token_creation_fee {
            self.tx_fee_config.token_creation_fee = token_creation_fee;
            self.tx_fee_config_updated_at_height = self.height;
        }
        self.refresh_executor_token_creation_fee_if_needed();
        self.difficulty_config.last_updated_at_height = self.height;

        if let Some(ref coordinator) = self.consensus_coordinator {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let coord = coordinator.write().await;
                    coord
                        .apply_difficulty_governance_update(
                            None,
                            new_adjustment_interval,
                            new_target_timespan,
                        )
                        .await
                })
            })?;
        }

        self.executed_dao_proposals.insert(proposal_id);
        Ok(())
    }

    pub fn process_approved_governance_proposals(&mut self) -> Result<()> {
        if self.emergency_state
            && self
                .emergency_expires_at
                .is_some_and(|expiry| self.height >= expiry)
        {
            self.emergency_state = false;
            self.emergency_activated_at = None;
            self.emergency_activated_by = None;
            self.emergency_expires_at = None;
            info!("🔓 Emergency state expired at block height {}", self.height);
        }

        if self.treasury_frozen
            && self
                .treasury_freeze_expiry
                .is_some_and(|expiry| self.height >= expiry)
        {
            self.treasury_frozen = false;
            self.treasury_frozen_at = None;
            self.treasury_freeze_expiry = None;
            self.treasury_freeze_signatures.clear();
            info!("🔓 Treasury freeze expired at block height {}", self.height);
        }

        if self.height > 0 && self.height % 1_000 == 0 {
            self.try_advance_governance_phase();
        }

        let dao_proposals = self.get_dao_proposals();
        let mut difficulty_proposals: Vec<(Hash, u8)> = Vec::new();
        let mut fee_proposals: Vec<(Hash, u8)> = Vec::new();
        let mut oracle_committee_proposals: Vec<(Hash, u8)> = Vec::new();
        let mut oracle_config_proposals: Vec<(Hash, u8)> = Vec::new();
        let mut oracle_protocol_upgrade_proposals: Vec<(Hash, u8)> = Vec::new();
        let mut cancel_oracle_proposals: Vec<(Hash, u8)> = Vec::new();

        for proposal in &dao_proposals {
            let proposal_ref = (proposal.proposal_id, proposal.quorum_required);
            if proposal.proposal_type == "difficulty_parameter_update" {
                difficulty_proposals.push(proposal_ref);
            } else if proposal.proposal_type == "fee_structure"
                || proposal.proposal_type == "FeeStructure"
            {
                fee_proposals.push(proposal_ref);
            } else if Self::is_oracle_committee_proposal_type(&proposal.proposal_type) {
                oracle_committee_proposals.push(proposal_ref);
            } else if Self::is_oracle_config_proposal_type(&proposal.proposal_type) {
                oracle_config_proposals.push(proposal_ref);
            } else if Self::is_oracle_protocol_upgrade_proposal_type(&proposal.proposal_type) {
                oracle_protocol_upgrade_proposals.push(proposal_ref);
            } else if proposal.proposal_type == "cancel_oracle_update" {
                cancel_oracle_proposals.push(proposal_ref);
            }
        }

        for (proposal_id, quorum_required) in difficulty_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_difficulty_parameter_update(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed difficulty parameter update proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute difficulty parameter update proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!(
                        "Difficulty proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    debug!("Error checking status of proposal {:?}: {}", proposal_id, e);
                }
            }
        }

        for (proposal_id, quorum_required) in fee_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_difficulty_parameter_update(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed fee parameter update proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute fee parameter update proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!("Fee proposal {:?} has not passed voting yet", proposal_id);
                }
                Err(e) => {
                    warn!("Failed to check fee proposal {:?}: {}", proposal_id, e);
                }
            }
        }

        for (proposal_id, quorum_required) in oracle_committee_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_oracle_committee_update(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed oracle committee update proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute oracle committee update proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!(
                        "Oracle committee proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to check oracle committee proposal {:?}: {}",
                        proposal_id, e
                    );
                }
            }
        }

        for (proposal_id, quorum_required) in oracle_config_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_oracle_config_update(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed oracle config update proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute oracle config update proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!(
                        "Oracle config proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to check oracle config proposal {:?}: {}",
                        proposal_id, e
                    );
                }
            }
        }

        for (proposal_id, quorum_required) in oracle_protocol_upgrade_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_oracle_protocol_upgrade(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed oracle protocol upgrade proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute oracle protocol upgrade proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!(
                        "Oracle protocol upgrade proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to check oracle protocol upgrade proposal {:?}: {}",
                        proposal_id, e
                    );
                }
            }
        }

        for (proposal_id, quorum_required) in cancel_oracle_proposals {
            if self.executed_dao_proposals.contains(&proposal_id) {
                continue;
            }

            match self.has_proposal_passed(&proposal_id, quorum_required as u32) {
                Ok(true) => match self.apply_cancel_oracle_update(proposal_id) {
                    Ok(()) => info!(
                        "✅ Successfully executed cancel oracle update proposal {:?}",
                        proposal_id
                    ),
                    Err(e) => warn!(
                        "Failed to execute cancel oracle update proposal {:?}: {}",
                        proposal_id, e
                    ),
                },
                Ok(false) => {
                    debug!(
                        "Cancel oracle update proposal {:?} has not passed voting yet",
                        proposal_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to check cancel oracle update proposal {:?}: {}",
                        proposal_id, e
                    );
                }
            }
        }

        Ok(())
    }

    pub fn activate_treasury_freeze(
        &mut self,
        validator_dids: Vec<String>,
        _reason: String,
    ) -> Result<()> {
        let validator_count = self.validator_registry.len();
        if validator_count == 0 {
            return Err(anyhow::anyhow!(
                "Insufficient validator signatures: got 0, need at least 1 validator"
            ));
        }

        let unique_validator_dids: HashSet<String> = validator_dids.into_iter().collect();
        let threshold = (validator_count * 8 + 9) / 10;

        if unique_validator_dids.len() < threshold {
            return Err(anyhow::anyhow!(
                "Insufficient validator signatures: got {} valid, need {} (80% of {})",
                unique_validator_dids.len(),
                threshold,
                validator_count
            ));
        }

        for did in &unique_validator_dids {
            match self.validator_registry.get(did) {
                Some(v) if v.status == "active" => continue,
                _ => return Err(anyhow::anyhow!("Invalid or inactive validator: {}", did)),
            }
        }

        self.treasury_frozen = true;
        self.treasury_frozen_at = Some(self.height);
        self.treasury_freeze_expiry = Some(self.height + 10_080);
        self.treasury_freeze_signatures = unique_validator_dids
            .into_iter()
            .map(|d| (d, Vec::new()))
            .collect();

        Ok(())
    }

    pub fn council_veto_proposal(
        &mut self,
        proposal_id: &Hash,
        signer_did: String,
        reason: String,
    ) -> Result<()> {
        if !self
            .council_members
            .iter()
            .any(|m| m.identity_id == signer_did)
        {
            return Err(anyhow::anyhow!("Signer is not a council member"));
        }

        let vetoes = self.pending_vetoes.entry(proposal_id.as_array()).or_default();

        if vetoes.iter().any(|(did, _)| did == &signer_did) {
            return Ok(());
        }

        vetoes.push((signer_did, reason));
        Ok(())
    }

    pub fn council_cosign_proposal(
        &mut self,
        proposal_id: &Hash,
        signer_did: String,
        signature: Vec<u8>,
    ) -> Result<()> {
        if !self
            .council_members
            .iter()
            .any(|m| m.identity_id == signer_did)
        {
            return Err(anyhow::anyhow!("Signer is not a council member"));
        }

        let cosigns = self.pending_cosigns.entry(proposal_id.as_array()).or_default();

        if cosigns.iter().any(|(did, _)| did == &signer_did) {
            return Ok(());
        }

        cosigns.push((signer_did, signature));
        Ok(())
    }
}
