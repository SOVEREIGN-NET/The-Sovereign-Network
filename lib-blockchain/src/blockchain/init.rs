use super::*;

impl Blockchain {
    pub(super) fn new_runtime_state() -> Self {
        let genesis_block = crate::block::create_genesis_block();

        Blockchain {
            blocks: vec![genesis_block],
            height: 0,
            difficulty: Difficulty::from_bits(crate::INITIAL_DIFFICULTY),
            difficulty_config: DifficultyConfig::default(),
            tx_fee_config: crate::transaction::TxFeeConfig::default(),
            tx_fee_config_updated_at_height: 0,
            total_work: 0,
            utxo_set: HashMap::new(),
            nullifier_set: HashSet::new(),
            pending_transactions: Vec::new(),
            identity_registry: HashMap::new(),
            identity_blocks: HashMap::new(),
            wallet_registry: HashMap::new(),
            wallet_blocks: HashMap::new(),
            economics_transactions: Vec::new(),
            token_contracts: HashMap::new(),
            web4_contracts: HashMap::new(),
            contract_blocks: HashMap::new(),
            dao_registry_index: HashMap::new(),
            validator_registry: HashMap::new(),
            validator_blocks: HashMap::new(),
            gateway_registry: HashMap::new(),
            gateway_blocks: HashMap::new(),
            dao_treasury_wallet_id: None,
            welfare_services: HashMap::new(),
            welfare_service_blocks: HashMap::new(),
            welfare_audit_trail: HashMap::new(),
            service_performance: HashMap::new(),
            outcome_reports: HashMap::new(),
            economic_processor: Some(EconomicTransactionProcessor::new()),
            consensus_coordinator: None,
            storage_manager: None,
            store: None,
            proof_aggregator: None,
            auto_persist_enabled: true,
            blocks_since_last_persist: 0,
            broadcast_sender: None,
            executed_dao_proposals: HashSet::new(),
            receipts: HashMap::new(),
            finality_depth: 12,
            finalized_blocks: HashSet::new(),
            contract_states: HashMap::new(),
            contract_state_history: std::collections::BTreeMap::new(),
            utxo_snapshots: std::collections::BTreeMap::new(),
            fork_points: HashMap::new(),
            reorg_count: 0,
            fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig::default(),
            event_publisher: crate::events::BlockchainEventPublisher::new(),
            ubi_registry: HashMap::new(),
            ubi_blocks: HashMap::new(),
            token_nonces: HashMap::new(),
            executor: None,
            treasury_kernel: None,
            bonding_curve_registry: crate::contracts::bonding_curve::BondingCurveRegistry::new(),
            amm_pools: HashMap::new(),
            governance_phase: crate::dao::GovernancePhase::default(),
            council_members: Vec::new(),
            council_threshold: default_council_threshold(),
            entity_registry: None,
            employment_registry: crate::contracts::employment::EmploymentRegistry::new(),
            treasury_epoch_spend: HashMap::new(),
            treasury_epoch_length_blocks: default_treasury_epoch_length(),
            emergency_state: false,
            emergency_activated_at: None,
            emergency_activated_by: None,
            emergency_expires_at: None,
            treasury_epoch_start_balance: HashMap::new(),
            treasury_frozen: false,
            treasury_frozen_at: None,
            treasury_freeze_expiry: None,
            treasury_freeze_signatures: Vec::new(),
            voting_power_mode: crate::dao::VotingPowerMode::default(),
            vote_delegations: HashMap::new(),
            pending_cosigns: HashMap::new(),
            pending_vetoes: HashMap::new(),
            veto_window_blocks: default_veto_window(),
            treasury_epoch_execution_count: HashMap::new(),
            max_executions_per_epoch: default_max_executions(),
            oracle_state: crate::oracle::OracleState::default(),
            token_pricing_state: crate::pricing::TokenPricingState::new(),
            exchange_state: crate::exchange::ExchangeState::new(),
            onramp_state: crate::onramp::OnRampState::new(),
            oracle_slash_events: Vec::new(),
            oracle_slashing_config: crate::oracle::OracleSlashingConfig::default(),
            oracle_banned_validators: std::collections::HashSet::new(),
            last_oracle_epoch_processed: 0,
            last_decentralization_snapshot: None,
            phase_transition_config: crate::dao::PhaseTransitionConfig::default(),
            governance_cycles_with_quorum: 0,
            last_governance_cycle_height: 0,
            fee_router: crate::contracts::economics::fee_router::FeeRouter::new_with_dao_wallets(
                crate::contracts::economics::fee_router::DAO_HEALTHCARE_KEY_ID,
            ),
            domain_registry: HashMap::new(),
            nft_collections: HashMap::new(),
        }
    }

    pub fn new() -> Result<Self> {
        let cfg = crate::genesis::GenesisConfig::from_embedded()?;
        let bc = cfg.build_block0()?;
        cfg.verify_hash(&bc.blocks[0].header.block_hash.as_array())?;
        Ok(bc)
    }

    pub(crate) fn new_empty_for_genesis(genesis_block: crate::block::Block) -> Result<Self> {
        let mut bc = Self::new_runtime_state();
        bc.blocks[0] = genesis_block.clone();
        bc.update_utxo_set(&genesis_block)?;
        bc.save_utxo_snapshot(0)?;
        bc.ensure_treasury_wallet();
        Ok(bc)
    }

    pub fn derive_cbe_token_id_pub() -> [u8; 32] {
        Self::derive_cbe_token_id()
    }

    #[deprecated(
        since = "0.2.0",
        note = "cbe_token field removed from Blockchain (EPIC-001 Phase 1)"
    )]
    #[allow(dead_code)]
    pub(super) fn initialize_cbe_genesis(&mut self) {
        use crate::contracts::bonding_curve::{
            BondingCurveToken, CurveType, PiecewiseLinearCurve, Threshold,
        };
        use crate::contracts::tokens::{CBE_NAME, CBE_SYMBOL};

        let token_id = Self::derive_cbe_token_id();
        if self.bonding_curve_registry.contains(&token_id) {
            return; // Already registered — idempotent
        }

        let genesis_creator = crate::integration::crypto_integration::PublicKey {
            dilithium_pk: [0u8; 2592],
            kyber_pk: [0u8; 1568],
            key_id: [0u8; 32],
        };
        let curve = CurveType::PiecewiseLinear(PiecewiseLinearCurve::cbe_default());
        let threshold = Threshold::ReserveAmount(2_745_966_000);

        match BondingCurveToken::deploy(
            token_id,
            CBE_NAME.to_string(),
            CBE_SYMBOL.to_string(),
            curve,
            threshold,
            true,
            genesis_creator,
            "did:zhtp:genesis".to_string(),
            0,
            self.get_genesis_timestamp(),
        ) {
            Ok(token) => {
                if let Err(e) = self.bonding_curve_registry.register(token) {
                    tracing::warn!("Failed to register CBE bonding curve: {}", e);
                } else {
                    tracing::info!(
                        "CBE genesis bonding curve initialized: {}",
                        hex::encode(&token_id[..8])
                    );
                }
            }
            Err(e) => tracing::warn!("Failed to deploy CBE bonding curve: {}", e),
        }
    }

    #[deprecated(
        since = "0.2.0",
        note = "cbe_token field removed from Blockchain (EPIC-001 Phase 1)"
    )]
    #[allow(dead_code)]
    pub(super) fn initialize_cbe_token_genesis(&mut self) {
        // No-op: cbe_token field removed from Blockchain struct.
    }

    pub(super) fn get_genesis_timestamp(&self) -> u64 {
        self.blocks
            .first()
            .map(|b| b.header.timestamp)
            .unwrap_or(1_700_000_000)
    }

    fn derive_cbe_token_id() -> [u8; 32] {
        use crate::contracts::tokens::{CBE_NAME, CBE_SYMBOL};
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        CBE_NAME.hash(&mut hasher);
        CBE_SYMBOL.hash(&mut hasher);
        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        for i in 8..32 {
            id[i] = ((hash >> (i % 8)) & 0xFF) as u8;
        }
        id
    }

    pub fn update_cbe_usd_oracle_price(&mut self, price_8dec: u128, epoch: u64, timestamp: u64) {
        self.token_pricing_state
            .update_cbe_usd_price(price_8dec, epoch, timestamp);

        if self.token_pricing_state.dynamic_pricing_active {
            info!(
                "Unified pricing: Dynamic mode activated - SOV price atomic = {}",
                self.token_pricing_state.get_sov_price_8dec()
            );
        }
    }

    pub fn update_cbe_sov_ratio_from_curve(&mut self, timestamp: u64) {
        let cbe_token_id = Self::derive_cbe_token_id();

        if let Some(cbe_token) = self.bonding_curve_registry.get(&cbe_token_id) {
            let cbe_sov_ratio_8dec = cbe_token.current_price() as u128;

            if cbe_sov_ratio_8dec > 0 {
                self.token_pricing_state
                    .update_cbe_sov_ratio(cbe_sov_ratio_8dec, timestamp);
            }
        }
    }

    pub fn get_cbe_curve_price_atomic(&self) -> Option<u128> {
        let cbe_token_id = Self::derive_cbe_token_id();
        self.bonding_curve_registry
            .get(&cbe_token_id)
            .map(|t| t.current_price())
    }

    pub fn get_sov_price_info(&self) -> crate::pricing::TokenPrice {
        let price_8dec = self.token_pricing_state.get_sov_price_8dec();
        let price_cents = crate::pricing::PricingCalculator::to_cents(price_8dec);
        let components = self.token_pricing_state.get_sov_components();

        crate::pricing::TokenPrice {
            token_id: "sov".to_string(),
            symbol: "SOV".to_string(),
            price_usd_cents: price_cents,
            pricing_phase: crate::pricing::PricingPhase::Curve,
            price_mode: self.token_pricing_state.get_sov_pricing_mode(),
            price_source: self.token_pricing_state.get_sov_price_source(),
            components,
            last_updated: self.token_pricing_state.last_updated,
        }
    }

    pub fn get_cbe_price_info(&self) -> Option<crate::pricing::CbePriceInfo> {
        let cbe_token_id = Self::derive_cbe_token_id();
        let cbe_token = self.bonding_curve_registry.get(&cbe_token_id)?;
        let sov_price_8dec = self.token_pricing_state.get_sov_price_8dec();

        let (price_cents, components) = self
            .token_pricing_state
            .calculate_cbe_price(sov_price_8dec, cbe_token.current_price());

        let (price_mode, price_source, oracle_confidence_bps) =
            if self.token_pricing_state.cbe_usd_price.is_some() {
                (
                    crate::pricing::PricingMode::PostGraduation,
                    crate::pricing::PriceSource::Oracle,
                    Some(9_500),
                )
            } else {
                (
                    crate::pricing::PricingMode::PreGraduation,
                    crate::pricing::PriceSource::BondingCurve,
                    None,
                )
            };

        Some(crate::pricing::CbePriceInfo {
            price_usd_cents: price_cents,
            price_mode,
            price_source,
            phase: cbe_token.phase.to_string(),
            reserve_usd: cbe_token.reserve_balance,
            supply: cbe_token.total_supply,
            components,
            oracle_confidence_bps,
            last_updated: self.token_pricing_state.last_updated,
        })
    }

    pub async fn new_with_storage(storage_config: BlockchainStorageConfig) -> Result<Self> {
        let mut blockchain = Self::new()?;
        blockchain
            .initialize_storage_manager(storage_config)
            .await?;
        Ok(blockchain)
    }

    pub fn new_with_store(store: std::sync::Arc<dyn BlockchainStore>) -> Result<Self> {
        let mut blockchain = Self::new()?;
        let executor = std::sync::Arc::new(crate::execution::executor::BlockExecutor::with_store(
            store.clone(),
        ));
        blockchain.executor = Some(executor);
        blockchain.store = Some(store);
        blockchain.auto_persist_enabled = false;
        info!("Blockchain initialized with incremental store + canonical BlockExecutor path");
        Ok(blockchain)
    }

    pub fn new_with_executor(store: std::sync::Arc<dyn BlockchainStore>) -> Result<Self> {
        let mut blockchain = Self::new()?;
        let executor = std::sync::Arc::new(crate::execution::executor::BlockExecutor::with_store(
            store.clone(),
        ));

        blockchain.executor = Some(executor);
        blockchain.store = Some(store);
        blockchain.auto_persist_enabled = false;

        info!("Blockchain initialized with BlockExecutor as single source of truth");
        Ok(blockchain)
    }

    pub fn load_from_store(store: std::sync::Arc<dyn BlockchainStore>) -> Result<Option<Self>> {
        info!("📂 Loading blockchain from SledStore...");

        let latest_height = match store.latest_height() {
            Ok(h) => h,
            Err(e) => {
                info!("📂 SledStore appears empty or uninitialized: {}", e);
                return Ok(None);
            }
        };

        if latest_height == 0 && store.get_block_by_height(0).ok().flatten().is_none() {
            info!("📂 SledStore has no blocks - returning None");
            return Ok(None);
        }

        info!(
            "📂 Found blockchain data up to height {} in SledStore",
            latest_height
        );

        let mut blockchain = Self::new_runtime_state();
        let executor = std::sync::Arc::new(crate::execution::executor::BlockExecutor::with_store(
            store.clone(),
        ));
        blockchain.executor = Some(executor);
        blockchain.store = Some(store.clone());
        blockchain.auto_persist_enabled = false;
        blockchain.blocks.clear();
        blockchain.height = 0;

        for height in 0..=latest_height {
            match store.get_block_by_height(height)? {
                Some(block) => {
                    for tx in &block.transactions {
                        for input in &tx.inputs {
                            blockchain.nullifier_set.insert(input.nullifier);
                            blockchain.utxo_set.remove(&input.previous_output);
                        }

                        for output in &tx.outputs {
                            let tx_hash = tx.hash();
                            blockchain.utxo_set.insert(tx_hash, output.clone());
                        }

                        if let Some(identity_data) = tx.identity_data() {
                            blockchain
                                .identity_registry
                                .insert(identity_data.did.clone(), identity_data.clone());
                            blockchain
                                .identity_blocks
                                .insert(identity_data.did.clone(), height);
                        }

                        if let Some(wallet_data) = tx.wallet_data() {
                            let wallet_id = hex::encode(wallet_data.wallet_id.as_bytes());
                            blockchain
                                .wallet_registry
                                .insert(wallet_id.clone(), wallet_data.clone());
                            blockchain.wallet_blocks.insert(wallet_id, height);

                            // Replay SOV minting for WalletRegistration transactions.
                            // process_token_transactions (called below with the sled store
                            // temporarily removed) reads balances from the in-memory
                            // token_contracts HashMap.  Without replaying the minting here,
                            // any subsequent TokenTransfer from this wallet will fail with
                            // "insufficient balance: have 0" even though the balance was
                            // correctly committed to sled during the original block execution.
                            if tx.transaction_type == TransactionType::WalletRegistration
                                && wallet_data.initial_balance > 0
                            {
                                blockchain.ensure_sov_token_contract();
                                let sov_token_id =
                                    crate::contracts::utils::generate_lib_token_id();
                                let mut wallet_id_bytes = [0u8; 32];
                                wallet_id_bytes
                                    .copy_from_slice(wallet_data.wallet_id.as_bytes());
                                let recipient_pk =
                                    Self::wallet_key_for_sov(&wallet_id_bytes);
                                let current = blockchain
                                    .token_contracts
                                    .get(&sov_token_id)
                                    .map(|t| t.balance_of(&recipient_pk))
                                    .unwrap_or(0);
                                let target = wallet_data.initial_balance as u128;
                                let deficit = target.saturating_sub(current);
                                if deficit > 0 {
                                    if let Some(token) =
                                        blockchain.token_contracts.get_mut(&sov_token_id)
                                    {
                                        let _ = token.mint(&recipient_pk, deficit);
                                    }
                                }
                            }
                        }

                        if tx.transaction_type == TransactionType::ContractExecution {
                            debug!(
                                "📦 Replaying ContractExecution tx at height {}, memo_len={}",
                                height,
                                tx.memo.len()
                            );
                            if let Err(e) = blockchain.process_contract_execution(tx, height) {
                                warn!(
                                    "⚠️ Failed to replay ContractExecution at height {}: {}",
                                    height, e
                                );
                            }
                        }

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
                            blockchain
                                .validator_registry
                                .insert(validator_data.identity_id.clone(), validator_info);
                            blockchain
                                .validator_blocks
                                .insert(validator_data.identity_id.clone(), height);
                        }
                    }

                    // Replay CBE pool initialization from on-chain InitCbeToken transactions.
                    // Replay domain registration/update transactions.
                    blockchain.process_domain_transactions(&block);

                    // Replay gateway registration/update transactions.
                    blockchain.process_gateway_transactions(&block);

                    // Replay employment contract creation so employment_registry is populated.
                    if let Err(e) = blockchain.process_employment_contract_transactions(&block) {
                        warn!(
                            "⚠️ Failed to replay CreateEmploymentContract at height {}: {}",
                            height, e
                        );
                    }

                    // During sled-store replay we skip SOV token transaction processing
                    // entirely.  The correct final SOV balances are loaded from the
                    // token_balances sled tree after this loop.
                    //
                    // We intentionally leave blockchain.token_nonces EMPTY here.
                    // In BlockExecutor mode (the only production mode), nonces are
                    // tracked exclusively in sled via increment_token_nonce() and
                    // get_token_nonce() falls through to sled when the in-memory map
                    // has no entry.  Populating the in-memory map from the block
                    // history would make it a stale cache: after restart the executor
                    // continues to update only sled, so the in-memory entry never
                    // advances past the replay count and the nonce API returns stale
                    // values — causing clients to submit wrong nonces that the executor
                    // then rejects with "expected N+1, got N".

                    blockchain.blocks.push(block);
                    blockchain.height = height;
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing block at height {} - store is corrupted",
                        height
                    ));
                }
            }
        }

        let sov_token_id = crate::contracts::utils::generate_lib_token_id();
        if let Some(sov_contract) = blockchain.token_contracts.get(&sov_token_id) {
            let entries: Vec<([u8; 32], u128)> = sov_contract
                .balances_iter()
                .map(|(pk, &bal)| (pk.key_id, bal))
                .collect();
            let token_id = crate::storage::TokenId(sov_token_id);
            match store.backfill_token_balances_from_contract(&token_id, &entries) {
                Ok(0) => debug!("SOV token_balances tree already up-to-date (no backfill needed)"),
                Ok(n) => info!(
                    "💰 Backfilled {} SOV balances into token_balances tree (legacy migration)",
                    n
                ),
                Err(e) => warn!("⚠️ Failed to backfill SOV token_balances: {}", e),
            }
        }

        let mut backfilled_blocks = 0;
        for contract_id in blockchain.token_contracts.keys() {
            if !blockchain.contract_blocks.contains_key(contract_id) {
                blockchain.contract_blocks.insert(*contract_id, 0);
                backfilled_blocks += 1;
            }
        }
        for contract_id in blockchain.web4_contracts.keys() {
            if !blockchain.contract_blocks.contains_key(contract_id) {
                blockchain.contract_blocks.insert(*contract_id, 0);
                backfilled_blocks += 1;
            }
        }
        if backfilled_blocks > 0 {
            info!(
                "📦 Backfilled {} contract deployment heights to genesis (block 0)",
                backfilled_blocks
            );
        }
        blockchain.rebuild_dao_registry_index();

        let mut migrated_count = 0usize;
        for wallet in blockchain.wallet_registry.values_mut() {
            if wallet.initial_balance > 0 && wallet.initial_balance < lib_types::sov::SCALE {
                let old = wallet.initial_balance;
                wallet.initial_balance = old.saturating_mul(lib_types::sov::SCALE);
                migrated_count += 1;
                info!(
                    "Migrated wallet initial_balance: {} -> {} atomic units",
                    old, wallet.initial_balance
                );
            }
        }
        if migrated_count > 0 {
            info!(
                "Migrated {} wallet initial_balance values from human SOV to atomic units",
                migrated_count
            );
        }

        blockchain.ensure_sov_token_contract();
        blockchain.ensure_treasury_wallet();
        blockchain.migrate_sov_key_balances_to_wallets();
        blockchain.repair_backfill_inflation();

        {
            let sov_token_id = crate::contracts::utils::generate_lib_token_id();
            let storage_sov_id = crate::storage::TokenId(sov_token_id);
            let wallet_ids: Vec<String> = blockchain.wallet_registry.keys().cloned().collect();
            let mut synced = 0usize;
            for wallet_id_hex in &wallet_ids {
                if let Some(wallet_bytes) = Self::wallet_id_bytes(wallet_id_hex) {
                    let addr = crate::storage::Address::new(wallet_bytes);
                    if let Ok(balance) = store.get_token_balance(&storage_sov_id, &addr) {
                        if balance > 0 {
                            if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
                                let pk = Self::wallet_key_for_sov(&wallet_bytes);
                                token.set_balance(&pk, balance as u128);
                                synced += 1;
                            }
                        }
                    }
                }
            }
            if synced > 0 {
                info!(
                    "💰 Synced {} SOV balances from token_balances tree into in-memory contracts",
                    synced
                );
            }
            
            // Also sync total supply from sled
            if let Ok(Some(supply)) = store.get_token_supply(&storage_sov_id) {
                if let Some(token) = blockchain.token_contracts.get_mut(&sov_token_id) {
                    token.total_supply = supply as u128;
                }
            }
        }

        // One-time correction: zero out SOV that was incorrectly minted to UBI
        // and Savings wallets by a bug in the recovery migration path.
        let corrected = blockchain.correct_ubi_savings_misbalances();
        if corrected > 0 {
            info!(
                "Startup correction: removed erroneous 5 000 SOV welcome bonus from {} UBI/Savings wallet(s)",
                corrected
            );
        }

        let backfill_entries = blockchain.collect_sov_backfill_entries();
        if !backfill_entries.is_empty() {
            info!(
                "SOV backfill needed for {} wallets (will be minted via TokenMint after startup)",
                backfill_entries.len()
            );
        }

        if let Err(e) = blockchain.process_approved_governance_proposals() {
            warn!(
                "Failed to apply governance parameter updates during load_from_store: {}",
                e
            );
        }

        match store.get_oracle_state() {
            Ok(Some(oracle_state)) => {
                let member_count = oracle_state.committee.members().len();
                blockchain.oracle_state = oracle_state;
                info!(
                    "🔮 Restored oracle_state from SledStore: {} committee members",
                    member_count
                );
            }
            Ok(None) => {
                info!("🔮 No persisted oracle_state in SledStore (oracle committee not yet bootstrapped)");
            }
            Err(e) => {
                warn!("⚠️ Failed to load oracle_state from SledStore: {}", e);
            }
        }

        // Initialize FeeRouter with the known sector DAO wallet addresses.
        // The fee_sink is used for UBI/emergency/dev pools until dedicated wallets are created.
        // FeeRouter::new_with_dao_wallets() is idempotent: if already initialized via
        // deserialization it's already set; this only fires on first load or after sled wipe.
        if !blockchain.fee_router.is_initialized() {
            let fee_sink = crate::contracts::economics::fee_router::DAO_HEALTHCARE_KEY_ID;
            blockchain.fee_router =
                crate::contracts::economics::fee_router::FeeRouter::new_with_dao_wallets(fee_sink);
            info!("💰 FeeRouter initialized with sector DAO wallet addresses");
        }

        // Ensure CBE bonding curve is registered (idempotent — skips if already present).
        // This is needed when loading from sled after a binary upgrade that added the
        // bonding curve, or when the original genesis didn't include it.
        blockchain.initialize_cbe_genesis();

        info!(
            "📂 Loaded blockchain from SledStore: height={}, identities={}, wallets={}, tokens={}",
            blockchain.height,
            blockchain.identity_registry.len(),
            blockchain.wallet_registry.len(),
            blockchain.token_contracts.len()
        );

        Ok(Some(blockchain))
    }

    pub fn set_store(&mut self, store: std::sync::Arc<dyn BlockchainStore>) {
        self.store = Some(store);
        self.auto_persist_enabled = false;
        info!("Phase 2 incremental store attached to blockchain");
    }

    pub fn get_store(&self) -> Option<&std::sync::Arc<dyn BlockchainStore>> {
        self.store.as_ref()
    }

    pub fn set_executor(
        &mut self,
        executor: std::sync::Arc<crate::execution::executor::BlockExecutor>,
    ) {
        self.executor = Some(executor);
        self.refresh_executor_token_creation_fee_if_needed();
        info!("BlockExecutor set as single source of truth for state mutations");
    }

    pub(super) fn refresh_executor_token_creation_fee_if_needed(&mut self) {
        let Some(executor) = self.executor.as_ref() else {
            return;
        };

        if executor.token_creation_fee() == self.tx_fee_config.token_creation_fee {
            return;
        }

        let rebuilt = std::sync::Arc::new(
            crate::execution::executor::BlockExecutor::new_with_token_creation_fee(
                std::sync::Arc::clone(executor.store()),
                executor.fee_model().clone(),
                executor.limits().clone(),
                self.tx_fee_config.token_creation_fee,
            ),
        );
        self.executor = Some(rebuilt);
        info!(
            "Refreshed BlockExecutor token_creation_fee to {}",
            self.tx_fee_config.token_creation_fee
        );
    }

    pub fn has_executor(&self) -> bool {
        self.executor.is_some()
    }

    pub async fn initialize_storage_manager(
        &mut self,
        config: BlockchainStorageConfig,
    ) -> Result<()> {
        info!("🗃️ Initializing blockchain storage manager");

        let storage_manager = BlockchainStorageManager::new(config).await?;
        self.storage_manager = Some(std::sync::Arc::new(tokio::sync::RwLock::new(
            storage_manager,
        )));
        self.auto_persist_enabled = true;

        info!("Storage manager initialized successfully");
        Ok(())
    }

    pub fn initialize_proof_aggregator(&mut self) -> Result<()> {
        info!("Initializing recursive proof aggregator");

        let aggregator = lib_proofs::RecursiveProofAggregator::new()?;
        self.proof_aggregator = Some(std::sync::Arc::new(tokio::sync::RwLock::new(aggregator)));

        info!("Recursive proof aggregator initialized successfully");
        Ok(())
    }

    pub fn set_broadcast_channel(
        &mut self,
        sender: tokio::sync::mpsc::UnboundedSender<BlockchainBroadcastMessage>,
    ) {
        debug!("Blockchain broadcast channel configured");
        self.broadcast_sender = Some(sender);
    }

    pub fn fund_genesis_block(
        &mut self,
        genesis_outputs: Vec<crate::TransactionOutput>,
        genesis_signature: crate::integration::crypto_integration::Signature,
        chain_id: u64,
        wallet_registrations: Vec<crate::transaction::WalletTransactionData>,
        identity_registrations: Vec<crate::transaction::core::IdentityTransactionData>,
        validator_registrations: Vec<ValidatorInfo>,
    ) -> Result<()> {
        info!(
            "Funding genesis block with {} outputs",
            genesis_outputs.len()
        );

        if self.blocks.is_empty() {
            return Err(anyhow::anyhow!("No genesis block found in blockchain"));
        }

        let genesis_block = &mut self.blocks[0];
        let genesis_tx = crate::Transaction {
            version: crate::transaction::TX_VERSION_V8,
            chain_id: chain_id as u8,
            transaction_type: crate::types::TransactionType::Transfer,
            inputs: vec![],
            outputs: genesis_outputs.clone(),
            fee: 0,
            signature: genesis_signature,
            memo: b"Genesis funding transaction".to_vec(),
            payload: crate::transaction::TransactionPayload::None,
        };

        genesis_block.transactions.push(genesis_tx.clone());

        let updated_merkle_root = crate::transaction::hashing::calculate_transaction_merkle_root(
            &genesis_block.transactions,
        );
        genesis_block.header.data_helix_root = updated_merkle_root.as_array();
        genesis_block.header.block_hash = genesis_block.header.calculate_hash();

        let genesis_tx_id = crate::types::hash::blake3_hash(b"genesis_funding_transaction");
        for (index, output) in genesis_outputs.iter().enumerate() {
            let utxo_hash = crate::types::hash::blake3_hash(
                &format!("genesis_funding:{}:{}", hex::encode(genesis_tx_id), index).as_bytes(),
            );
            self.utxo_set.insert(utxo_hash, output.clone());
        }

        for wallet_data in wallet_registrations {
            let wallet_id_hex = hex::encode(wallet_data.wallet_id.as_bytes());
            self.wallet_registry
                .insert(wallet_id_hex.clone(), wallet_data);
            info!("Registered genesis wallet: {}", &wallet_id_hex[..16]);
        }

        for identity_data in identity_registrations {
            match self.register_identity(identity_data.clone()) {
                Ok(_) => info!("Registered genesis identity: {}", identity_data.did),
                Err(e) => warn!(
                    "Failed to register genesis identity {}: {}",
                    identity_data.did, e
                ),
            }
        }

        for validator_data in validator_registrations {
            match self.register_validator(validator_data.clone()) {
                Ok(_) => info!("Registered genesis validator: {}", validator_data.identity_id),
                Err(e) => warn!(
                    "Failed to register genesis validator {}: {}",
                    validator_data.identity_id, e
                ),
            }
        }

        info!(
            "Genesis funding complete: {} UTXOs, {} wallets, {} identities, {} validators",
            genesis_outputs.len(),
            self.wallet_registry.len(),
            self.identity_registry.len(),
            self.validator_registry.len()
        );

        Ok(())
    }
}
