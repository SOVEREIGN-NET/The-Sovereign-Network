use super::*;

/// Statistics about blockchain persistence state
#[derive(Debug, Clone)]
pub struct PersistenceStats {
    pub height: u64,
    pub blocks_count: usize,
    pub utxo_count: usize,
    pub identity_count: usize,
    pub wallet_count: usize,
    pub pending_tx_count: usize,
    pub blocks_since_last_persist: u64,
}

// =============================================================================
// V1 Migration Types (Dec 2025 format - before UBI/Profit transaction types)
// =============================================================================

/// Transaction V1 format - without ubi_claim_data and profit_declaration_data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TransactionV1 {
    pub version: u32,
    pub chain_id: u8,
    pub transaction_type: TransactionType,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub signature: Signature,
    pub memo: Vec<u8>,
    pub identity_data: Option<IdentityTransactionData>,
    pub wallet_data: Option<crate::transaction::WalletTransactionData>,
    pub validator_data: Option<crate::transaction::ValidatorTransactionData>,
    pub dao_proposal_data: Option<crate::transaction::DaoProposalData>,
    pub dao_vote_data: Option<crate::transaction::DaoVoteData>,
    pub dao_execution_data: Option<crate::transaction::DaoExecutionData>,
}

impl TransactionV1 {
    #[allow(dead_code)]
    fn migrate_to_current(self) -> Transaction {
        Transaction {
            version: self.version,
            chain_id: self.chain_id,
            transaction_type: self.transaction_type,
            inputs: self.inputs,
            outputs: self.outputs,
            fee: self.fee,
            signature: self.signature,
            memo: self.memo,
            payload: if let Some(d) = self.identity_data {
                crate::transaction::TransactionPayload::Identity(d)
            } else if let Some(d) = self.wallet_data {
                crate::transaction::TransactionPayload::Wallet(d)
            } else if let Some(d) = self.validator_data {
                crate::transaction::TransactionPayload::Validator(d)
            } else if let Some(d) = self.dao_proposal_data {
                crate::transaction::TransactionPayload::DaoProposal(d)
            } else if let Some(d) = self.dao_vote_data {
                crate::transaction::TransactionPayload::DaoVote(d)
            } else if let Some(d) = self.dao_execution_data {
                crate::transaction::TransactionPayload::DaoExecution(d)
            } else {
                crate::transaction::TransactionPayload::None
            },
        }
    }
}

/// Block V1 format - uses TransactionV1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockV1 {
    pub header: crate::block::BlockHeader,
    pub transactions: Vec<TransactionV1>,
}

impl BlockV1 {
    fn migrate_to_current(self) -> Block {
        Block {
            header: self.header,
            transactions: self
                .transactions
                .into_iter()
                .map(|tx| tx.migrate_to_current())
                .collect(),
        }
    }
}

/// Blockchain V1 format (Dec 2025) - for backward compatibility migration
/// This struct matches the format used by production nodes before the Phase 2 updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainV1 {
    pub blocks: Vec<BlockV1>,
    pub height: u64,
    pub difficulty: Difficulty,
    pub total_work: u128,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub nullifier_set: HashSet<Hash>,
    pub pending_transactions: Vec<TransactionV1>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub identity_blocks: HashMap<String, u64>,
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    pub wallet_blocks: HashMap<String, u64>,
    pub economics_transactions: Vec<EconomicsTransaction>,
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    pub contract_blocks: HashMap<[u8; 32], u64>,
    pub validator_registry: HashMap<String, ValidatorInfo>,
    pub validator_blocks: HashMap<String, u64>,
    pub dao_treasury_wallet_id: Option<String>,
    pub welfare_services: HashMap<String, lib_consensus::WelfareService>,
    pub welfare_service_blocks: HashMap<String, u64>,
    pub welfare_audit_trail: HashMap<lib_crypto::Hash, lib_consensus::WelfareAuditEntry>,
    pub service_performance: HashMap<String, lib_consensus::ServicePerformanceMetrics>,
    pub outcome_reports: HashMap<lib_crypto::Hash, lib_consensus::OutcomeReport>,
    pub auto_persist_enabled: bool,
    pub blocks_since_last_persist: u64,
}

impl BlockchainV1 {
    fn migrate_to_current(self) -> Blockchain {
        info!("🔄 Migrating blockchain from V1 format to current format");
        info!(
            "   V1 data: height={}, identities={}, wallets={}, utxos={}",
            self.height,
            self.identity_registry.len(),
            self.wallet_registry.len(),
            self.utxo_set.len()
        );

        let blocks: Vec<Block> = self
            .blocks
            .into_iter()
            .map(|b| b.migrate_to_current())
            .collect();
        let pending_transactions: Vec<Transaction> = self
            .pending_transactions
            .into_iter()
            .map(|tx| tx.migrate_to_current())
            .collect();

        info!(
            "   Migrated {} blocks, {} pending transactions",
            blocks.len(),
            pending_transactions.len()
        );

        Blockchain {
            blocks,
            height: self.height,
            difficulty: self.difficulty,
            difficulty_config: DifficultyConfig::default(),
            tx_fee_config: crate::transaction::TxFeeConfig::default(),
            tx_fee_config_updated_at_height: 0,
            total_work: self.total_work,
            utxo_set: self.utxo_set,
            nullifier_set: self.nullifier_set,
            pending_transactions,
            identity_registry: self.identity_registry,
            identity_blocks: self.identity_blocks,
            wallet_registry: self.wallet_registry,
            wallet_blocks: self.wallet_blocks,
            economics_transactions: self.economics_transactions,
            token_contracts: self.token_contracts,
            web4_contracts: self.web4_contracts,
            contract_blocks: self.contract_blocks,
            dao_registry_index: HashMap::new(),
            validator_registry: self.validator_registry,
            validator_blocks: self.validator_blocks,
            dao_treasury_wallet_id: self.dao_treasury_wallet_id,
            welfare_services: self.welfare_services,
            welfare_service_blocks: self.welfare_service_blocks,
            welfare_audit_trail: self.welfare_audit_trail,
            service_performance: self.service_performance,
            outcome_reports: self.outcome_reports,
            economic_processor: Some(EconomicTransactionProcessor::new()),
            consensus_coordinator: None,
            storage_manager: None,
            store: None,
            proof_aggregator: None,
            auto_persist_enabled: self.auto_persist_enabled,
            blocks_since_last_persist: self.blocks_since_last_persist,
            broadcast_sender: None,
            executed_dao_proposals: HashSet::new(),
            receipts: HashMap::new(),
            finality_depth: default_finality_depth(),
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV3 {
    pub blocks: Vec<Block>,
    pub height: u64,
    pub difficulty: Difficulty,
    #[serde(default)]
    pub difficulty_config: DifficultyConfig,
    #[serde(default)]
    pub tx_fee_config: crate::transaction::TxFeeConfig,
    #[serde(default)]
    pub tx_fee_config_updated_at_height: u64,
    pub total_work: u128,
    pub utxo_set: HashMap<Hash, TransactionOutput>,
    pub nullifier_set: HashSet<Hash>,
    pub pending_transactions: Vec<Transaction>,
    pub identity_registry: HashMap<String, IdentityTransactionData>,
    pub identity_blocks: HashMap<String, u64>,
    pub wallet_registry: HashMap<String, crate::transaction::WalletTransactionData>,
    pub wallet_blocks: HashMap<String, u64>,
    #[serde(default)]
    pub economics_transactions: Vec<EconomicsTransaction>,
    #[serde(default)]
    pub token_contracts: HashMap<[u8; 32], crate::contracts::TokenContract>,
    #[serde(default)]
    pub web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    #[serde(default)]
    pub contract_blocks: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub dao_registry_index: HashMap<[u8; 32], DaoRegistryIndexEntry>,
    #[serde(default)]
    pub validator_registry: HashMap<String, ValidatorInfo>,
    #[serde(default)]
    pub validator_blocks: HashMap<String, u64>,
    #[serde(default)]
    pub dao_treasury_wallet_id: Option<String>,
    #[serde(default)]
    pub welfare_services: HashMap<String, lib_consensus::WelfareService>,
    #[serde(default)]
    pub welfare_service_blocks: HashMap<String, u64>,
    #[serde(default)]
    pub welfare_audit_trail: HashMap<lib_crypto::Hash, lib_consensus::WelfareAuditEntry>,
    #[serde(default)]
    pub service_performance: HashMap<String, lib_consensus::ServicePerformanceMetrics>,
    #[serde(default)]
    pub outcome_reports: HashMap<lib_crypto::Hash, lib_consensus::OutcomeReport>,
    #[serde(default)]
    pub auto_persist_enabled: bool,
    #[serde(default)]
    pub blocks_since_last_persist: u64,
    #[serde(default)]
    pub executed_dao_proposals: HashSet<Hash>,
    #[serde(default)]
    pub receipts: HashMap<Hash, crate::receipts::TransactionReceipt>,
    #[serde(default = "default_finality_depth")]
    pub finality_depth: u64,
    #[serde(default)]
    pub finalized_blocks: HashSet<u64>,
    #[serde(default)]
    pub contract_states: HashMap<[u8; 32], Vec<u8>>,
    #[serde(default)]
    pub contract_state_history: std::collections::BTreeMap<u64, HashMap<[u8; 32], Vec<u8>>>,
    #[serde(default)]
    pub utxo_snapshots: std::collections::BTreeMap<u64, HashMap<Hash, TransactionOutput>>,
    #[serde(default)]
    pub fork_points: HashMap<u64, crate::fork_recovery::ForkPoint>,
    #[serde(default)]
    pub reorg_count: u64,
    #[serde(default)]
    pub fork_recovery_config: crate::fork_recovery::ForkRecoveryConfig,
    #[serde(default)]
    pub ubi_registry: HashMap<String, UbiRegistryEntry>,
    #[serde(default)]
    pub ubi_blocks: HashMap<String, u64>,
    #[serde(default)]
    pub token_nonces: HashMap<([u8; 32], [u8; 32]), u64>,
    #[serde(default)]
    pub amm_pools: HashMap<[u8; 32], crate::contracts::bonding_curve::AmmPool>,
    #[serde(default)]
    pub governance_phase: crate::dao::GovernancePhase,
    #[serde(default)]
    pub council_members: Vec<crate::dao::CouncilMember>,
    #[serde(default = "default_council_threshold")]
    pub council_threshold: u8,
    #[serde(default)]
    pub treasury_epoch_spend: HashMap<u64, u64>,
    #[serde(default = "default_treasury_epoch_length")]
    pub treasury_epoch_length_blocks: u64,
    #[serde(default)]
    pub emergency_state: bool,
    #[serde(default)]
    pub emergency_activated_at: Option<u64>,
    #[serde(default)]
    pub emergency_activated_by: Option<String>,
    #[serde(default)]
    pub emergency_expires_at: Option<u64>,
    #[serde(default)]
    pub treasury_epoch_start_balance: HashMap<u64, u64>,
    #[serde(default)]
    pub treasury_frozen: bool,
    #[serde(default)]
    pub treasury_frozen_at: Option<u64>,
    #[serde(default)]
    pub treasury_freeze_expiry: Option<u64>,
    #[serde(default)]
    pub treasury_freeze_signatures: Vec<(String, Vec<u8>)>,
    #[serde(default)]
    pub voting_power_mode: crate::dao::VotingPowerMode,
    #[serde(default)]
    pub vote_delegations: HashMap<String, String>,
    #[serde(default)]
    pub pending_cosigns: HashMap<[u8; 32], Vec<(String, Vec<u8>)>>,
    #[serde(default)]
    pub pending_vetoes: HashMap<[u8; 32], Vec<(String, String)>>,
    #[serde(default = "default_veto_window")]
    pub veto_window_blocks: u64,
    #[serde(default)]
    pub treasury_epoch_execution_count: HashMap<u64, u32>,
    #[serde(default = "default_max_executions")]
    pub max_executions_per_epoch: u32,
    #[serde(default)]
    pub last_decentralization_snapshot: Option<crate::dao::DecentralizationSnapshot>,
    #[serde(default)]
    pub phase_transition_config: crate::dao::PhaseTransitionConfig,
    #[serde(default)]
    pub governance_cycles_with_quorum: u32,
    #[serde(default)]
    pub last_governance_cycle_height: u64,
}

impl BlockchainStorageV3 {
    pub(super) fn from_blockchain(bc: &Blockchain) -> Self {
        BlockchainStorageV3 {
            blocks: bc.blocks.clone(),
            height: bc.height,
            difficulty: bc.difficulty.clone(),
            difficulty_config: bc.difficulty_config.clone(),
            tx_fee_config: bc.tx_fee_config.clone(),
            tx_fee_config_updated_at_height: bc.tx_fee_config_updated_at_height,
            total_work: bc.total_work,
            utxo_set: bc.utxo_set.clone(),
            nullifier_set: bc.nullifier_set.clone(),
            pending_transactions: bc.pending_transactions.clone(),
            identity_registry: bc.identity_registry.clone(),
            identity_blocks: bc.identity_blocks.clone(),
            wallet_registry: bc.wallet_registry.clone(),
            wallet_blocks: bc.wallet_blocks.clone(),
            economics_transactions: bc.economics_transactions.clone(),
            token_contracts: bc.token_contracts.clone(),
            web4_contracts: bc.web4_contracts.clone(),
            contract_blocks: bc.contract_blocks.clone(),
            dao_registry_index: bc.dao_registry_index.clone(),
            validator_registry: bc.validator_registry.clone(),
            validator_blocks: bc.validator_blocks.clone(),
            dao_treasury_wallet_id: bc.dao_treasury_wallet_id.clone(),
            welfare_services: bc.welfare_services.clone(),
            welfare_service_blocks: bc.welfare_service_blocks.clone(),
            welfare_audit_trail: bc.welfare_audit_trail.clone(),
            service_performance: bc.service_performance.clone(),
            outcome_reports: bc.outcome_reports.clone(),
            auto_persist_enabled: bc.auto_persist_enabled,
            blocks_since_last_persist: bc.blocks_since_last_persist,
            executed_dao_proposals: bc.executed_dao_proposals.clone(),
            receipts: bc.receipts.clone(),
            finality_depth: bc.finality_depth,
            finalized_blocks: bc.finalized_blocks.clone(),
            contract_states: bc.contract_states.clone(),
            contract_state_history: bc.contract_state_history.clone(),
            utxo_snapshots: bc.utxo_snapshots.clone(),
            fork_points: bc.fork_points.clone(),
            reorg_count: bc.reorg_count,
            fork_recovery_config: bc.fork_recovery_config.clone(),
            ubi_registry: bc.ubi_registry.clone(),
            ubi_blocks: bc.ubi_blocks.clone(),
            token_nonces: bc.token_nonces.clone(),
            amm_pools: HashMap::new(),
            governance_phase: bc.governance_phase.clone(),
            council_members: bc.council_members.clone(),
            council_threshold: bc.council_threshold,
            treasury_epoch_spend: bc.treasury_epoch_spend.clone(),
            treasury_epoch_length_blocks: bc.treasury_epoch_length_blocks,
            emergency_state: bc.emergency_state,
            emergency_activated_at: bc.emergency_activated_at,
            emergency_activated_by: bc.emergency_activated_by.clone(),
            emergency_expires_at: bc.emergency_expires_at,
            treasury_epoch_start_balance: bc.treasury_epoch_start_balance.clone(),
            treasury_frozen: bc.treasury_frozen,
            treasury_frozen_at: bc.treasury_frozen_at,
            treasury_freeze_expiry: bc.treasury_freeze_expiry,
            treasury_freeze_signatures: bc.treasury_freeze_signatures.clone(),
            voting_power_mode: bc.voting_power_mode.clone(),
            vote_delegations: bc.vote_delegations.clone(),
            pending_cosigns: bc.pending_cosigns.clone(),
            pending_vetoes: bc.pending_vetoes.clone(),
            veto_window_blocks: bc.veto_window_blocks,
            treasury_epoch_execution_count: bc.treasury_epoch_execution_count.clone(),
            max_executions_per_epoch: bc.max_executions_per_epoch,
            last_decentralization_snapshot: bc.last_decentralization_snapshot.clone(),
            phase_transition_config: bc.phase_transition_config.clone(),
            governance_cycles_with_quorum: bc.governance_cycles_with_quorum,
            last_governance_cycle_height: bc.last_governance_cycle_height,
        }
    }

    pub(super) fn to_blockchain(self) -> Blockchain {
        Blockchain {
            blocks: self.blocks,
            height: self.height,
            difficulty: self.difficulty,
            difficulty_config: self.difficulty_config,
            tx_fee_config: self.tx_fee_config,
            tx_fee_config_updated_at_height: self.tx_fee_config_updated_at_height,
            total_work: self.total_work,
            utxo_set: self.utxo_set,
            nullifier_set: self.nullifier_set,
            pending_transactions: self.pending_transactions,
            identity_registry: self.identity_registry,
            identity_blocks: self.identity_blocks,
            wallet_registry: self.wallet_registry,
            wallet_blocks: self.wallet_blocks,
            economics_transactions: self.economics_transactions,
            token_contracts: self.token_contracts,
            web4_contracts: self.web4_contracts,
            contract_blocks: self.contract_blocks,
            dao_registry_index: self.dao_registry_index,
            validator_registry: self.validator_registry,
            validator_blocks: self.validator_blocks,
            dao_treasury_wallet_id: self.dao_treasury_wallet_id,
            welfare_services: self.welfare_services,
            welfare_service_blocks: self.welfare_service_blocks,
            welfare_audit_trail: self.welfare_audit_trail,
            service_performance: self.service_performance,
            outcome_reports: self.outcome_reports,
            economic_processor: None,
            consensus_coordinator: None,
            storage_manager: None,
            store: None,
            proof_aggregator: None,
            broadcast_sender: None,
            event_publisher: crate::events::BlockchainEventPublisher::new(),
            auto_persist_enabled: self.auto_persist_enabled,
            blocks_since_last_persist: self.blocks_since_last_persist,
            executed_dao_proposals: self.executed_dao_proposals,
            receipts: self.receipts,
            finality_depth: self.finality_depth,
            finalized_blocks: self.finalized_blocks,
            contract_states: self.contract_states,
            contract_state_history: self.contract_state_history,
            utxo_snapshots: self.utxo_snapshots,
            fork_points: self.fork_points,
            reorg_count: self.reorg_count,
            fork_recovery_config: self.fork_recovery_config,
            ubi_registry: self.ubi_registry,
            ubi_blocks: self.ubi_blocks,
            token_nonces: self.token_nonces,
            executor: None,
            treasury_kernel: None,
            bonding_curve_registry: crate::contracts::bonding_curve::BondingCurveRegistry::new(),
            amm_pools: HashMap::new(),
            governance_phase: self.governance_phase,
            council_members: self.council_members,
            council_threshold: self.council_threshold,
            entity_registry: None,
            employment_registry: crate::contracts::employment::EmploymentRegistry::new(),
            treasury_epoch_spend: self.treasury_epoch_spend,
            treasury_epoch_length_blocks: self.treasury_epoch_length_blocks,
            emergency_state: self.emergency_state,
            emergency_activated_at: self.emergency_activated_at,
            emergency_activated_by: self.emergency_activated_by,
            emergency_expires_at: self.emergency_expires_at,
            treasury_epoch_start_balance: self.treasury_epoch_start_balance,
            treasury_frozen: self.treasury_frozen,
            treasury_frozen_at: self.treasury_frozen_at,
            treasury_freeze_expiry: self.treasury_freeze_expiry,
            treasury_freeze_signatures: self.treasury_freeze_signatures,
            voting_power_mode: self.voting_power_mode,
            vote_delegations: self.vote_delegations,
            pending_cosigns: self.pending_cosigns,
            pending_vetoes: self.pending_vetoes,
            veto_window_blocks: self.veto_window_blocks,
            treasury_epoch_execution_count: self.treasury_epoch_execution_count,
            max_executions_per_epoch: self.max_executions_per_epoch,
            oracle_state: crate::oracle::OracleState::default(),
            token_pricing_state: crate::pricing::TokenPricingState::new(),
            exchange_state: crate::exchange::ExchangeState::new(),
            onramp_state: crate::onramp::OnRampState::new(),
            oracle_slash_events: Vec::new(),
            oracle_slashing_config: crate::oracle::OracleSlashingConfig::default(),
            oracle_banned_validators: std::collections::HashSet::new(),
            last_oracle_epoch_processed: 0,
            last_decentralization_snapshot: self.last_decentralization_snapshot,
            phase_transition_config: self.phase_transition_config,
            governance_cycles_with_quorum: self.governance_cycles_with_quorum,
            last_governance_cycle_height: self.last_governance_cycle_height,
            fee_router: crate::contracts::economics::fee_router::FeeRouter::new_with_dao_wallets(
                crate::contracts::economics::fee_router::DAO_HEALTHCARE_KEY_ID,
            ),
            domain_registry: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV4 {
    pub v3: BlockchainStorageV3,
    #[serde(default)]
    pub oracle_state: crate::oracle::OracleState,
    #[serde(default)]
    pub exchange_state: crate::exchange::ExchangeState,
    #[serde(default)]
    pub oracle_slash_events: Vec<crate::oracle::OracleSlashEvent>,
    #[serde(default)]
    pub oracle_slashing_config: crate::oracle::OracleSlashingConfig,
    #[serde(default)]
    pub oracle_banned_validators: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub last_oracle_epoch_processed: u64,
}

impl BlockchainStorageV4 {
    pub(super) fn to_blockchain(self) -> Blockchain {
        let mut blockchain = self.v3.to_blockchain();
        blockchain.oracle_state = self.oracle_state;
        blockchain.exchange_state = self.exchange_state;
        blockchain.oracle_slash_events = self.oracle_slash_events;
        blockchain.oracle_slashing_config = self.oracle_slashing_config;
        blockchain.oracle_banned_validators = self.oracle_banned_validators;
        blockchain.last_oracle_epoch_processed = self.last_oracle_epoch_processed;
        blockchain
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct LegacyBlockchainStorageV5 {
    pub v4: BlockchainStorageV4,
    #[serde(default)]
    pub onramp_state: crate::onramp::OnRampState,
}

impl LegacyBlockchainStorageV5 {
    pub(super) fn to_blockchain(self) -> Blockchain {
        let mut blockchain = self.v4.to_blockchain();
        blockchain.onramp_state = self.onramp_state;
        blockchain
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV6 {
    pub v3: BlockchainStorageV3,
    #[serde(default)]
    pub oracle_state: crate::oracle::OracleState,
    #[serde(default)]
    pub exchange_state: crate::exchange::ExchangeState,
    #[serde(default)]
    pub onramp_state: crate::onramp::OnRampState,
    #[serde(default)]
    pub oracle_slash_events: Vec<crate::oracle::OracleSlashEvent>,
    #[serde(default)]
    pub oracle_slashing_config: crate::oracle::OracleSlashingConfig,
    #[serde(default)]
    pub oracle_banned_validators: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub last_oracle_epoch_processed: u64,
    #[serde(default)]
    pub entity_registry: Option<crate::contracts::governance::EntityRegistry>,
}

impl BlockchainStorageV6 {
    pub(super) fn to_blockchain(self) -> Blockchain {
        let mut blockchain = self.v3.to_blockchain();
        blockchain.oracle_state = self.oracle_state;
        blockchain.exchange_state = self.exchange_state;
        blockchain.onramp_state = self.onramp_state;
        blockchain.oracle_slash_events = self.oracle_slash_events;
        blockchain.oracle_slashing_config = self.oracle_slashing_config;
        blockchain.oracle_banned_validators = self.oracle_banned_validators;
        blockchain.last_oracle_epoch_processed = self.last_oracle_epoch_processed;
        blockchain.entity_registry = self.entity_registry;
        blockchain
    }
}

/// Stub type that matches the bincode serialization layout of the old CbeToken
/// struct. Needed so that V7 `.dat` files can still be deserialized after the
/// real CbeToken module was deleted (EPIC-001 Phase 1F). The value is never
/// used — `to_blockchain()` ignores it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct LegacyCbeTokenStub {
    token_id: [u8; 32],
    balances: HashMap<[u8; 32], u64>,
    vesting_schedules: HashMap<[u8; 32], Vec<LegacyVestingScheduleStub>>,
    allowances: HashMap<[u8; 32], HashMap<[u8; 32], u64>>,
    total_supply: u64,
    distribution: LegacyDistributionStub,
    pool_addresses: LegacyPoolAddressesStub,
    initialized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyVestingScheduleStub {
    total_amount: u64,
    vested_amount: u64,
    start_block: u64,
    vesting_duration_blocks: u64,
    cliff_blocks: u64,
    pool: LegacyVestingPoolStub,
}

/// Mirrors the old VestingPool enum layout for bincode compat (u32 variant index).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum LegacyVestingPoolStub {
    Compensation,
    Operational,
    Performance,
    Strategic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyDistributionStub {
    compensation: u64,
    operational: u64,
    performance: u64,
    strategic: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LegacyPoolAddressesStub {
    compensation: Option<[u8; 32]>,
    operational: Option<[u8; 32]>,
    performance: Option<[u8; 32]>,
    strategic: Option<[u8; 32]>,
}

impl Default for LegacyCbeTokenStub {
    fn default() -> Self {
        Self {
            token_id: [0u8; 32],
            balances: HashMap::new(),
            vesting_schedules: HashMap::new(),
            allowances: HashMap::new(),
            total_supply: 0,
            distribution: LegacyDistributionStub {
                compensation: 0,
                operational: 0,
                performance: 0,
                strategic: 0,
            },
            pool_addresses: LegacyPoolAddressesStub::default(),
            initialized: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV7 {
    pub v6: BlockchainStorageV6,
    #[serde(default)]
    pub cbe_token: LegacyCbeTokenStub,
}

impl BlockchainStorageV7 {
    pub(super) fn from_blockchain(bc: &Blockchain) -> Self {
        Self {
            v6: BlockchainStorageV6 {
                v3: BlockchainStorageV3::from_blockchain(bc),
                oracle_state: bc.oracle_state.clone(),
                exchange_state: bc.exchange_state.clone(),
                onramp_state: bc.onramp_state.clone(),
                oracle_slash_events: bc.oracle_slash_events.clone(),
                oracle_slashing_config: bc.oracle_slashing_config.clone(),
                oracle_banned_validators: bc.oracle_banned_validators.clone(),
                last_oracle_epoch_processed: bc.last_oracle_epoch_processed,
                entity_registry: bc.entity_registry.clone(),
            },
            cbe_token: LegacyCbeTokenStub::default(),
        }
    }

    pub(super) fn to_blockchain(self) -> Blockchain {
        // cbe_token field removed from Blockchain — ignore V7's persisted value
        self.v6.to_blockchain()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV8 {
    pub v7: BlockchainStorageV7,
    #[serde(default)]
    pub employment_registry: crate::contracts::employment::EmploymentRegistry,
    #[serde(default)]
    pub cbe_dao_id: Option<[u8; 32]>,
}

impl BlockchainStorageV8 {
    fn from_blockchain(bc: &Blockchain) -> Self {
        Self {
            v7: BlockchainStorageV7::from_blockchain(bc),
            employment_registry: bc.employment_registry.clone(),
            cbe_dao_id: None,
        }
    }

    fn to_blockchain(self) -> Blockchain {
        let mut blockchain = self.v7.to_blockchain();
        blockchain.employment_registry = self.employment_registry;
        // cbe_dao_id field removed from Blockchain — discard V8's persisted value
        if self.cbe_dao_id.is_some() {
            tracing::info!(
                "V8 persistence: discarding non-None cbe_dao_id (field removed in Phase 1)"
            );
        }
        blockchain
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BlockchainStorageV9 {
    pub v8: BlockchainStorageV8,
    #[serde(default)]
    pub domain_registry:
        HashMap<String, crate::transaction::OnChainDomainRecord>,
}

impl BlockchainStorageV9 {
    fn from_blockchain(bc: &Blockchain) -> Self {
        Self {
            v8: BlockchainStorageV8::from_blockchain(bc),
            domain_registry: bc.domain_registry.clone(),
        }
    }

    fn to_blockchain(self) -> Blockchain {
        let mut blockchain = self.v8.to_blockchain();
        blockchain.domain_registry = self.domain_registry;
        blockchain
    }
}

impl Blockchain {
    pub(crate) const FILE_MAGIC: [u8; 4] = [0x5A, 0x48, 0x54, 0x50];
    const FILE_VERSION: u16 = 9;

    #[deprecated(
        since = "0.2.0",
        note = "Use Phase 2 incremental storage with SledStore instead"
    )]
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;

        info!(
            "💾 Saving blockchain to {} (height: {}, identities: {}, wallets: {}, tokens: {})",
            path.display(),
            self.height,
            self.identity_registry.len(),
            self.wallet_registry.len(),
            self.token_contracts.len()
        );

        let start = std::time::Instant::now();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let storage = BlockchainStorageV9::from_blockchain(self);
        let serialized = bincode::serialize(&storage)
            .map_err(|e| anyhow::anyhow!("Failed to serialize blockchain: {}", e))?;

        let mut file_data = Vec::with_capacity(6 + serialized.len());
        file_data.extend_from_slice(&Self::FILE_MAGIC);
        file_data.extend_from_slice(&Self::FILE_VERSION.to_le_bytes());
        file_data.extend_from_slice(&serialized);

        let temp_path = path.with_extension("dat.tmp");
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(&file_data)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;

        let elapsed = start.elapsed();
        info!(
            "💾 Blockchain saved successfully (v{}, {} bytes, {:?})",
            Self::FILE_VERSION,
            file_data.len(),
            elapsed
        );

        Ok(())
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use Phase 2 incremental storage with SledStore instead"
    )]
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        info!("📂 Loading blockchain from {}", path.display());

        let start = std::time::Instant::now();
        let file_data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read blockchain file: {}", e))?;

        if file_data.len() < 6 {
            return Err(anyhow::anyhow!("Blockchain file too small"));
        }

        let mut blockchain: Blockchain = if file_data[0..4] == Self::FILE_MAGIC {
            let version = u16::from_le_bytes([file_data[4], file_data[5]]);
            let data = &file_data[6..];

            info!("📂 Detected versioned format v{}", version);

            match version {
                9 => deserialize_or_err::<BlockchainStorageV9, _, _>(
                    data,
                    "v9 blockchain",
                    |storage| {
                    info!("📂 Loaded blockchain storage v9 (on-chain domain registry)");
                    storage.to_blockchain()
                },
                )?,
                8 => deserialize_or_err::<BlockchainStorageV8, _, _>(
                    data,
                    "v8 blockchain",
                    |storage| {
                    info!("📂 Loaded blockchain storage v8 (employment registry + CBE DAO format)");
                    storage.to_blockchain()
                },
                )?,
                7 => deserialize_or_err::<BlockchainStorageV7, _, _>(
                    data,
                    "v7 blockchain",
                    |storage| {
                    info!("📂 Loaded blockchain storage v7 (cbe-token persistence format)");
                    storage.to_blockchain()
                },
                )?,
                6 => deserialize_or_err::<BlockchainStorageV6, _, _>(
                    data,
                    "v6 blockchain",
                    |storage| {
                    info!("📂 Loaded legacy blockchain storage v6 (migrating to v7)");
                    storage.to_blockchain()
                },
                )?,
                5 => deserialize_or_err::<LegacyBlockchainStorageV5, _, _>(
                    data,
                    "legacy v5 blockchain",
                    |storage| {
                        info!("📂 Loaded legacy blockchain storage v5 (migrating to v6)");
                        storage.to_blockchain()
                    },
                )?,
                4 => match bincode::deserialize::<BlockchainStorageV4>(data) {
                    Ok(storage) => {
                        info!("📂 Loaded blockchain storage v4 (migrating to v5)");
                        let mut blockchain = storage.to_blockchain();
                        blockchain.onramp_state = crate::onramp::OnRampState::default();
                        blockchain
                    }
                    Err(storage_err) => match bincode::deserialize::<Blockchain>(data) {
                        Ok(bc) => {
                            info!("📂 Loaded v4 with direct Blockchain format");
                            bc
                        }
                        Err(direct_err) => {
                            error!("❌ Failed to deserialize v4 blockchain:");
                            error!("   BlockchainStorageV4 error: {}", storage_err);
                            error!("   Direct format error: {}", direct_err);
                            return Err(anyhow::anyhow!(
                                "Failed to deserialize v4 blockchain: {}",
                                storage_err
                            ));
                        }
                    },
                },
                3 => match bincode::deserialize::<BlockchainStorageV3>(data) {
                    Ok(storage) => {
                        info!("📂 Loaded blockchain storage v3 (new format)");
                        storage.to_blockchain()
                    }
                    Err(storage_err) => {
                        info!(
                            "📂 BlockchainStorageV3 failed, trying direct format: {}",
                            storage_err
                        );
                        match bincode::deserialize::<Blockchain>(data) {
                            Ok(bc) => {
                                info!("📂 Loaded v3 with direct Blockchain format (legacy v3)");
                                bc
                            }
                            Err(direct_err) => {
                                error!("❌ Failed to deserialize v3 blockchain:");
                                error!("   BlockchainStorageV3 error: {}", storage_err);
                                error!("   Direct format error: {}", direct_err);
                                return Err(anyhow::anyhow!(
                                    "Failed to deserialize v3 blockchain: {}",
                                    storage_err
                                ));
                            }
                        }
                    }
                },
                2 => {
                    return Err(anyhow::anyhow!(
                        "V2 format not supported - please use newer binary"
                    ));
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unsupported blockchain file version: {}. This binary supports v{}",
                        version,
                        Self::FILE_VERSION
                    ));
                }
            }
        } else {
            info!("📂 No version header found, trying legacy formats...");
            match bincode::deserialize::<Blockchain>(&file_data) {
                Ok(bc) => {
                    info!("📂 Loaded as legacy direct format");
                    bc
                }
                Err(current_err) => {
                    info!("📂 Direct format failed, trying V1 migration format...");
                    match bincode::deserialize::<BlockchainV1>(&file_data) {
                        Ok(v1_blockchain) => {
                            info!("📂 Blockchain loaded as V1 format, migrating...");
                            v1_blockchain.migrate_to_current()
                        }
                        Err(v1_err) => {
                            error!("❌ Failed to deserialize blockchain as any format:");
                            error!("   Direct format error: {}", current_err);
                            error!("   V1 format error: {}", v1_err);
                            return Err(anyhow::anyhow!(
                                "Failed to deserialize blockchain. File may be corrupted or from incompatible version. Error: {}",
                                current_err
                            ));
                        }
                    }
                }
            }
        };

        blockchain.economic_processor = Some(EconomicTransactionProcessor::new());
        blockchain.event_publisher = crate::events::BlockchainEventPublisher::new();

        if let Err(e) = blockchain.reprocess_contract_executions() {
            warn!("Failed to reprocess contract executions: {}", e);
        }
        blockchain.rebuild_dao_registry_index();

        let elapsed = start.elapsed();

        const SOV_ATOMIC_UNITS: u64 = 100_000_000;
        let mut migrated_count = 0usize;
        for wallet in blockchain.wallet_registry.values_mut() {
            if wallet.initial_balance > 0 && wallet.initial_balance < SOV_ATOMIC_UNITS {
                let old = wallet.initial_balance;
                wallet.initial_balance = old.saturating_mul(SOV_ATOMIC_UNITS);
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

        let backfill_entries = blockchain.collect_sov_backfill_entries();
        if !backfill_entries.is_empty() {
            warn!(
                "Legacy blockchain.dat load found {} wallets missing SOV balances; load_from_file \
                 no longer mints or repairs supply during startup",
                backfill_entries.len()
            );
        }

        // One-time correction: zero out SOV that was incorrectly minted to UBI and
        // Savings wallets by a bug in the recovery migration path.
        let corrected = blockchain.correct_ubi_savings_misbalances();
        if corrected > 0 {
            info!(
                "Startup correction: removed erroneous 5 000 SOV welcome bonus from {} UBI/Savings wallet(s)",
                corrected
            );
        }

        if let Err(e) = blockchain.process_approved_governance_proposals() {
            warn!(
                "Failed to apply governance parameter updates during load_from_file: {}",
                e
            );
        }

        if blockchain
            .oracle_state
            .needs_epoch_tracking_migration(blockchain.last_oracle_epoch_processed)
        {
            blockchain.last_oracle_epoch_processed = blockchain
                .oracle_state
                .migrate_epoch_tracking(blockchain.last_oracle_epoch_processed);
        }

        if blockchain.oracle_state.should_process_epoch(
            blockchain.last_committed_timestamp(),
            blockchain.last_oracle_epoch_processed,
        ) {
            let current_epoch = blockchain
                .oracle_state
                .epoch_id(blockchain.last_committed_timestamp());
            blockchain.oracle_state.apply_pending_updates(current_epoch);
            blockchain.apply_pending_committee_removals(current_epoch);
            blockchain.last_oracle_epoch_processed = blockchain.last_committed_timestamp();
            info!("🔮 Oracle caught up to epoch {} during load", current_epoch);
        }

        blockchain.evict_phase2_invalid_transactions("load_from_file");

        info!(
            "📂 Blockchain loaded successfully (height: {}, identities: {}, wallets: {}, tokens: {}, UTXOs: {}, {:?})",
            blockchain.height,
            blockchain.identity_registry.len(),
            blockchain.wallet_registry.len(),
            blockchain.token_contracts.len(),
            blockchain.utxo_set.len(),
            elapsed
        );

        Ok(blockchain)
    }

    #[allow(deprecated)]
    pub fn load_or_create(path: &std::path::Path) -> Result<(Self, bool)> {
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(blockchain) => {
                    info!("✅ Loaded existing blockchain from disk");
                    return Ok((blockchain, true));
                }
                Err(e) => {
                    error!(
                        "⚠️ Failed to load blockchain from {}: {}. Creating new blockchain.",
                        path.display(),
                        e
                    );
                    let backup_path = path.with_extension("dat.corrupt");
                    if let Err(rename_err) = std::fs::rename(path, &backup_path) {
                        warn!("Failed to backup corrupt blockchain file: {}", rename_err);
                    } else {
                        warn!("Corrupt blockchain backed up to {}", backup_path.display());
                    }
                }
            }
        } else {
            info!(
                "📂 No existing blockchain found at {}, creating new blockchain",
                path.display()
            );
        }

        let blockchain = Self::new()?;
        Ok((blockchain, false))
    }

    pub fn persistence_file_exists(path: &std::path::Path) -> bool {
        path.exists()
    }

    pub fn get_persistence_stats(&self) -> PersistenceStats {
        PersistenceStats {
            height: self.height,
            blocks_count: self.blocks.len(),
            utxo_count: self.utxo_set.len(),
            identity_count: self.identity_registry.len(),
            wallet_count: self.wallet_registry.len(),
            pending_tx_count: self.pending_transactions.len(),
            blocks_since_last_persist: self.blocks_since_last_persist,
        }
    }

    pub fn mark_persisted(&mut self) {
        self.blocks_since_last_persist = 0;
    }

    pub fn increment_persist_counter(&mut self) {
        self.blocks_since_last_persist += 1;
    }

    pub fn should_auto_persist(&self, interval: u64) -> bool {
        self.auto_persist_enabled && self.blocks_since_last_persist >= interval
    }
}

fn deserialize_or_err<T, U, F>(data: &[u8], label: &str, on_success: F) -> Result<U>
where
    T: serde::de::DeserializeOwned,
    F: FnOnce(T) -> U,
{
    match bincode::deserialize::<T>(data) {
        Ok(storage) => Ok(on_success(storage)),
        Err(storage_err) => {
            error!("❌ Failed to deserialize {}: {}", label, storage_err);
            Err(anyhow::anyhow!(
                "Failed to deserialize {}: {}",
                label,
                storage_err
            ))
        }
    }
}
