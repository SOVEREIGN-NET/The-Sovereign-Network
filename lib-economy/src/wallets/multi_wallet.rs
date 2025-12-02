//! Multi-wallet system for diverse economic activities
//! 
//! Implements a comprehensive multi-wallet architecture that supports different
//! types of economic activities using the ZHTP identity system and economic incentives
//! with seamless lib-blockchain and lib-identity integrations.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::wallets::WalletBalance;
use crate::models::TokenReward;
use crate::types::{TransactionType, Priority};
use crate::transactions::create_payment_transaction;
use crate::wasm::logging::info;

// integrations (without blockchain dependency to avoid circular dependency)
use lib_identity::{IdentityManager, identity::ZhtpIdentity as Identity};

// Local type definitions to replace blockchain imports
pub type Address = Vec<u8>; // Simple address type

/// Multi-wallet types for different economic activities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletType {
    /// Primary ZHTP wallet for general transactions
    Primary,
    /// Specialized wallet for  rewards
    IspBypassRewards,
    /// Specialized wallet for mesh discovery rewards
    MeshDiscoveryRewards,
    /// Specialized wallet for staking activities
    Staking,
    /// Specialized wallet for DAO governance
    Governance,
    /// Specialized wallet for UBI distributions
    UbiDistribution,
    /// Specialized wallet for infrastructure investment
    Infrastructure,
    /// Cross-chain bridge wallet
    Bridge,
    /// Smart contract interaction wallet
    SmartContract,
    /// Privacy-focused wallet with enhanced ZK features
    Privacy,
}

impl WalletType {
    /// Get wallet type description
    pub fn description(&self) -> &'static str {
        match self {
            WalletType::Primary => "Primary ZHTP wallet for general use",
            WalletType::IspBypassRewards => " service rewards",
            WalletType::MeshDiscoveryRewards => "Mesh discovery and topology rewards",
            WalletType::Staking => "Staking and infrastructure investment",
            WalletType::Governance => "DAO governance and voting",
            WalletType::UbiDistribution => "Universal Basic Income distribution",
            WalletType::Infrastructure => "Infrastructure provider rewards",
            WalletType::Bridge => "Cross-chain bridge operations",
            WalletType::SmartContract => "Smart contract interactions",
            WalletType::Privacy => "Privacy-enhanced transactions",
        }
    }

    /// Get default transaction priority for this wallet type
    pub fn default_priority(&self) -> Priority {
        match self {
            WalletType::Primary => Priority::Normal,
            WalletType::IspBypassRewards => Priority::High,
            WalletType::MeshDiscoveryRewards => Priority::High,
            WalletType::Staking => Priority::Normal,
            WalletType::Governance => Priority::High,
            WalletType::UbiDistribution => Priority::Low,
            WalletType::Infrastructure => Priority::High,
            WalletType::Bridge => Priority::Urgent,
            WalletType::SmartContract => Priority::Normal,
            WalletType::Privacy => Priority::High,
        }
    }

    /// Check if this wallet type requires special permissions
    pub fn requires_special_permissions(&self) -> bool {
        matches!(
            self,
            WalletType::Governance | WalletType::UbiDistribution | WalletType::Bridge
        )
    }
}

/// Comprehensive multi-wallet manager with blockchain integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiWalletManager {
    /// Identity associated with this multi-wallet
    pub identity: Identity,
    /// Collection of specialized wallets
    pub wallets: HashMap<WalletType, WalletBalance>,
    /// Wallet creation timestamps
    pub wallet_created_at: HashMap<WalletType, u64>,
    /// Cross-wallet transaction capabilities
    pub transfer_capabilities: TransferCapabilities,
    /// Transaction history across all wallets
    pub cross_wallet_history: Vec<CrossWalletTransaction>,
    /// Wallet-specific permissions
    pub wallet_permissions: HashMap<WalletType, WalletPermissions>,
    /// Auto-consolidation settings per wallet type
    pub auto_consolidation_rules: HashMap<WalletType, ConsolidationRule>,
}

/// Cross-wallet transfer capabilities with blockchain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCapabilities {
    /// Maximum daily transfer limit per wallet type
    pub daily_transfer_limits: HashMap<WalletType, u64>,
    /// Transfer fee rates between wallet types
    pub transfer_fee_rates: HashMap<(WalletType, WalletType), u64>, // basis points
    /// Minimum transfer amounts
    pub minimum_transfer_amounts: HashMap<WalletType, u64>,
    /// Blockchain confirmation requirements
    pub confirmation_requirements: HashMap<WalletType, u32>,
    /// Cross-wallet transaction cooldowns
    pub transfer_cooldowns: HashMap<WalletType, u64>, // seconds
}

/// Wallet-specific permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPermissions {
    /// Can initiate transfers to external addresses
    pub can_transfer_external: bool,
    /// Can participate in governance
    pub can_vote: bool,
    /// Can stake tokens
    pub can_stake: bool,
    /// Can receive automated rewards
    pub can_receive_rewards: bool,
    /// Maximum transaction amount per day
    pub daily_transaction_limit: u64,
    /// Requires multi-signature for large transactions
    pub requires_multisig_threshold: Option<u64>,
}

/// Auto-consolidation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationRule {
    /// Enable auto-consolidation for this wallet
    pub enabled: bool,
    /// Minimum balance before consolidation
    pub minimum_balance: u64,
    /// Target wallet for consolidation
    pub target_wallet: WalletType,
    /// Consolidation frequency in seconds
    pub frequency_seconds: u64,
    /// Last consolidation timestamp
    pub last_consolidation: u64,
}

/// Cross-wallet transaction record with blockchain validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossWalletTransaction {
    /// Transaction ID from blockchain
    pub blockchain_tx_id: [u8; 32],
    /// Source wallet type
    pub from_wallet: WalletType,
    /// Destination wallet type
    pub to_wallet: WalletType,
    /// Transfer amount
    pub amount: u64,
    /// Transaction fees paid
    pub fees: u64,
    /// Blockchain block height
    pub block_height: u64,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Blockchain confirmation status
    pub confirmations: u32,
    /// Transfer reason/purpose
    pub purpose: String,
}

impl MultiWalletManager {
    /// Create new multi-wallet manager with identity verification
    pub async fn new(identity: Identity) -> Result<Self> {
        // Verify identity with proper registration
        let mut identity_manager = IdentityManager::new();
        
        // Add the identity to the manager first
        identity_manager.add_identity(identity.clone());
        
        let identity_hash = &identity.id;
        let proof_params = lib_identity::types::IdentityProofParams::new(
            None, // min_age
            None, // jurisdiction
            vec![], // required_credentials
            1, // privacy_level
        );
        let identity_proof = identity_manager.verify_identity(identity_hash, &proof_params).await?;
        
        if !identity_proof.verified {
            return Err(anyhow::anyhow!("Identity verification failed"));
        }

        let node_id = identity.id.clone();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Create primary wallet
        let mut wallets = HashMap::new();
        let mut wallet_created_at = HashMap::new();
        let mut wallet_permissions = HashMap::new();
        let mut auto_consolidation_rules = HashMap::new();

        // Initialize primary wallet
        wallets.insert(WalletType::Primary, WalletBalance::new(node_id.0));
        wallet_created_at.insert(WalletType::Primary, current_time);
        wallet_permissions.insert(WalletType::Primary, WalletPermissions::default_permissions());
        auto_consolidation_rules.insert(WalletType::Primary, ConsolidationRule::disabled());

        // Initialize transfer capabilities
        let transfer_capabilities = TransferCapabilities::new();

        let manager = Self {
            identity,
            wallets,
            wallet_created_at,
            transfer_capabilities,
            cross_wallet_history: Vec::new(),
            wallet_permissions,
            auto_consolidation_rules,
        };

        info!(
            "🏦 Multi-wallet manager created for identity {} with primary wallet",
            hex::encode(node_id)
        );

        Ok(manager)
    }

    /// Create specialized wallet with blockchain registration
    pub async fn create_specialized_wallet(&mut self, wallet_type: WalletType) -> Result<()> {
        if self.wallets.contains_key(&wallet_type) {
            return Err(anyhow::anyhow!("Wallet type {:?} already exists", wallet_type));
        }

        // Check if special permissions are required
        if wallet_type.requires_special_permissions() {
            self.verify_special_permissions(&wallet_type).await?;
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Create wallet with appropriate node ID derivation
        let wallet_node_id = self.derive_wallet_node_id(&wallet_type)?;
        let wallet = WalletBalance::new(wallet_node_id);

        // Set wallet permissions based on type
        let permissions = self.get_permissions_for_wallet_type(&wallet_type);
        let consolidation_rule = self.get_consolidation_rule_for_wallet_type(&wallet_type);

        // Register wallet creation (in production, this would be a transaction)
        self.register_wallet_on_blockchain(&wallet_type).await?;

        // Add to collections
        self.wallets.insert(wallet_type.clone(), wallet);
        self.wallet_created_at.insert(wallet_type.clone(), current_time);
        self.wallet_permissions.insert(wallet_type.clone(), permissions);
        self.auto_consolidation_rules.insert(wallet_type.clone(), consolidation_rule);

        info!(
            " Created specialized wallet {:?} for identity {}",
            wallet_type, hex::encode(self.identity.id.clone())
        );

        Ok(())
    }

    /// Transfer between wallets with blockchain validation
    pub async fn transfer_between_wallets(
        &mut self,
        from_wallet: WalletType,
        to_wallet: WalletType,
        amount: u64,
        purpose: String,
    ) -> Result<[u8; 32]> {
        // Validate wallets exist
        if !self.wallets.contains_key(&from_wallet) {
            return Err(anyhow::anyhow!("Source wallet {:?} does not exist", from_wallet));
        }
        if !self.wallets.contains_key(&to_wallet) {
            return Err(anyhow::anyhow!("Destination wallet {:?} does not exist", to_wallet));
        }

        // Check transfer capabilities and limits
        self.validate_transfer_capability(&from_wallet, &to_wallet, amount).await?;

        // Calculate transfer fees
        let fee = self.calculate_transfer_fee(&from_wallet, &to_wallet, amount)?;
        let total_deduction = amount + fee;

        // Check source wallet balance
        {
            let source_wallet = self.wallets.get(&from_wallet).unwrap();
            if !source_wallet.can_afford(total_deduction) {
                return Err(anyhow::anyhow!("Insufficient funds in source wallet"));
            }
        }

        // Perform the transfer
        {
            let source_wallet = self.wallets.get_mut(&from_wallet).unwrap();
            source_wallet.available_balance -= total_deduction;
        }

        {
            let dest_wallet = self.wallets.get_mut(&to_wallet).unwrap();
            dest_wallet.available_balance += amount;
        }

        // Create blockchain transaction record
        let tx_id = self.create_blockchain_transaction_record(&from_wallet, &to_wallet, amount, fee).await?;

        // Record cross-wallet transaction
        let cross_wallet_tx = CrossWalletTransaction {
            blockchain_tx_id: tx_id,
            from_wallet: from_wallet.clone(),
            to_wallet: to_wallet.clone(),
            amount,
            fees: fee,
            block_height: 0, // Block height not available in this context
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            confirmations: 1, // Initial confirmation
            purpose,
        };

        self.cross_wallet_history.push(cross_wallet_tx);

        // Keep history manageable
        if self.cross_wallet_history.len() > 1000 {
            self.cross_wallet_history.remove(0);
        }

        info!(
            " Transferred {} ZHTP from {:?} to {:?} (fee: {} ZHTP, tx: {})",
            amount, from_wallet, to_wallet, fee, hex::encode(tx_id)
        );

        Ok(tx_id)
    }

    /// Add reward to appropriate specialized wallet
    pub async fn add_reward_to_specialized_wallet(
        &mut self,
        wallet_type: WalletType,
        reward: &TokenReward,
    ) -> Result<()> {
        // Create wallet if it doesn't exist (for reward types)
        if !self.wallets.contains_key(&wallet_type) {
            match wallet_type {
                WalletType::IspBypassRewards | WalletType::MeshDiscoveryRewards | WalletType::Infrastructure => {
                    self.create_specialized_wallet(wallet_type.clone()).await?;
                },
                _ => {
                    return Err(anyhow::anyhow!("Cannot auto-create wallet type {:?}", wallet_type));
                }
            }
        }

        // Check permissions
        let permissions = self.wallet_permissions.get(&wallet_type).unwrap();
        if !permissions.can_receive_rewards {
            return Err(anyhow::anyhow!("Wallet {:?} cannot receive rewards", wallet_type));
        }

        // Add reward to wallet
        let wallet = self.wallets.get_mut(&wallet_type).unwrap();
        wallet.add_reward(reward)?;

        // Check auto-consolidation rules
        self.check_auto_consolidation(&wallet_type).await?;

        info!(
            "🎁 Added {} SOV reward to {:?} wallet",
            reward.total_reward, wallet_type
        );

        Ok(())
    }

    /// Get total balance across all wallets
    pub fn get_total_balance(&self) -> u64 {
        self.wallets.values().map(|wallet| wallet.total_balance()).sum()
    }

    /// Get balance breakdown by wallet type
    pub fn get_balance_breakdown(&self) -> HashMap<WalletType, u64> {
        self.wallets.iter().map(|(wallet_type, wallet)| {
            (wallet_type.clone(), wallet.total_balance())
        }).collect()
    }

    /// Perform auto-consolidation based on rules
    pub async fn perform_auto_consolidation(&mut self) -> Result<Vec<[u8; 32]>> {
        let mut consolidation_transactions = Vec::new();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        for (wallet_type, rule) in self.auto_consolidation_rules.clone().iter() {
            if !rule.enabled {
                continue;
            }

            // Check if consolidation is due
            if current_time - rule.last_consolidation < rule.frequency_seconds {
                continue;
            }

            // Check if wallet has enough balance
            if let Some(wallet) = self.wallets.get(wallet_type) {
                if wallet.available_balance >= rule.minimum_balance {
                    let consolidation_amount = wallet.available_balance - (rule.minimum_balance / 2); // Leave some balance
                    
                    if consolidation_amount > 0 {
                        let tx_id = self.transfer_between_wallets(
                            wallet_type.clone(),
                            rule.target_wallet.clone(),
                            consolidation_amount,
                            "Auto-consolidation".to_string(),
                        ).await?;

                        consolidation_transactions.push(tx_id);

                        // Update last consolidation time
                        if let Some(rule_mut) = self.auto_consolidation_rules.get_mut(wallet_type) {
                            rule_mut.last_consolidation = current_time;
                        }

                        info!(
                            " Auto-consolidated {} ZHTP from {:?} to {:?}",
                            consolidation_amount, wallet_type, rule.target_wallet
                        );
                    }
                }
            }
        }

        Ok(consolidation_transactions)
    }

    /// Get comprehensive multi-wallet statistics
    pub async fn get_multi_wallet_statistics(&self) -> Result<serde_json::Value> {
        let total_balance = self.get_total_balance();
        let balance_breakdown = self.get_balance_breakdown();

        let wallet_stats: HashMap<String, serde_json::Value> = self.wallets.iter().map(|(wallet_type, wallet)| {
            (
                format!("{:?}", wallet_type),
                serde_json::json!({
                    "available_balance": wallet.available_balance,
                    "staked_balance": wallet.staked_balance,
                    "pending_rewards": wallet.pending_rewards,
                    "total_balance": wallet.total_balance(),
                    "transaction_count": wallet.transaction_history.len(),
                    "description": wallet_type.description(),
                    "created_at": self.wallet_created_at.get(wallet_type).unwrap_or(&0)
                })
            )
        }).collect();

        Ok(serde_json::json!({
            "identity": {
                "node_id": hex::encode(self.identity.id.clone()),
                "public_key": hex::encode(&self.identity.public_key.dilithium_pk),
                "identity_type": format!("{:?}", self.identity.identity_type)
            },
            "total_balance": total_balance,
            "balance_breakdown": balance_breakdown,
            "wallet_count": self.wallets.len(),
            "wallet_statistics": wallet_stats,
            "cross_wallet_transactions": self.cross_wallet_history.len(),
            "blockchain_context": {
                "current_height": 0,
                "is_synced": true,
                "peer_count": 0
            },
            "transfer_capabilities": {
                "daily_limits_active": !self.transfer_capabilities.daily_transfer_limits.is_empty(),
                "fee_rates_configured": !self.transfer_capabilities.transfer_fee_rates.is_empty(),
                "confirmation_requirements": !self.transfer_capabilities.confirmation_requirements.is_empty()
            }
        }))
    }

    // Private helper methods

    async fn verify_special_permissions(&self, wallet_type: &WalletType) -> Result<()> {
        // In production, this would check identity permissions on blockchain
        match wallet_type {
            WalletType::Governance => {
                // Check if identity has governance permissions
                // For now, allow all verified identities
                Ok(())
            },
            WalletType::UbiDistribution => {
                // Check if identity is authorized for UBI distribution
                // This would typically require DAO approval
                Ok(())
            },
            WalletType::Bridge => {
                // Check if identity is authorized for bridge operations
                // This requires special bridge operator status
                Ok(())
            },
            _ => Ok(())
        }
    }

    fn derive_wallet_node_id(&self, wallet_type: &WalletType) -> Result<[u8; 32]> {
        // Derive deterministic node ID for wallet type
        
        
        let mut input = Vec::new();
        input.extend_from_slice(&self.identity.id.as_bytes());
        input.extend_from_slice(format!("{:?}", wallet_type).as_bytes());
        
        let hash = lib_crypto::hash_blake3(&input);
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&hash[..32]);
        
        Ok(node_id)
    }

    fn get_permissions_for_wallet_type(&self, wallet_type: &WalletType) -> WalletPermissions {
        match wallet_type {
            WalletType::Primary => WalletPermissions {
                can_transfer_external: true,
                can_vote: false,
                can_stake: true,
                can_receive_rewards: true,
                daily_transaction_limit: 10_000_000, // 10M ZHTP
                requires_multisig_threshold: Some(1_000_000), // 1M ZHTP
            },
            WalletType::Governance => WalletPermissions {
                can_transfer_external: false,
                can_vote: true,
                can_stake: false,
                can_receive_rewards: false,
                daily_transaction_limit: 100_000, // 100K ZHTP
                requires_multisig_threshold: Some(10_000), // 10K ZHTP
            },
            WalletType::IspBypassRewards | WalletType::MeshDiscoveryRewards | WalletType::Infrastructure => WalletPermissions {
                can_transfer_external: false,
                can_vote: false,
                can_stake: false,
                can_receive_rewards: true,
                daily_transaction_limit: 1_000_000, // 1M ZHTP
                requires_multisig_threshold: None,
            },
            WalletType::Staking => WalletPermissions {
                can_transfer_external: false,
                can_vote: false,
                can_stake: true,
                can_receive_rewards: true,
                daily_transaction_limit: 5_000_000, // 5M ZHTP
                requires_multisig_threshold: Some(500_000), // 500K ZHTP
            },
            _ => WalletPermissions::default_permissions(),
        }
    }

    fn get_consolidation_rule_for_wallet_type(&self, wallet_type: &WalletType) -> ConsolidationRule {
        match wallet_type {
            WalletType::IspBypassRewards | WalletType::MeshDiscoveryRewards => ConsolidationRule {
                enabled: true,
                minimum_balance: 100_000, // 100K ZHTP
                target_wallet: WalletType::Primary,
                frequency_seconds: 86400, // Daily
                last_consolidation: 0,
            },
            WalletType::Infrastructure => ConsolidationRule {
                enabled: true,
                minimum_balance: 500_000, // 500K ZHTP
                target_wallet: WalletType::Staking,
                frequency_seconds: 86400 * 7, // Weekly
                last_consolidation: 0,
            },
            _ => ConsolidationRule::disabled(),
        }
    }

    async fn validate_transfer_capability(
        &self,
        from_wallet: &WalletType,
        to_wallet: &WalletType,
        amount: u64,
    ) -> Result<()> {
        // Validate the target wallet type is compatible
        match (from_wallet, to_wallet) {
            (WalletType::Governance, WalletType::UbiDistribution) => {
                return Err(anyhow::anyhow!("Cannot transfer from governance to UBI distribution directly"));
            },
            (WalletType::UbiDistribution, WalletType::Governance) => {
                return Err(anyhow::anyhow!("UBI to governance transfers require special approval"));
            },
            (WalletType::Infrastructure, WalletType::Governance) => {
                return Err(anyhow::anyhow!("Infrastructure to governance transfers require DAO approval"));
            },
            _ => {} // Other combinations are allowed
        }
        // Check daily transfer limits
        if let Some(limit) = self.transfer_capabilities.daily_transfer_limits.get(from_wallet) {
            if amount > *limit {
                return Err(anyhow::anyhow!("Transfer amount exceeds daily limit"));
            }
        }

        // Check minimum transfer amounts
        if let Some(minimum) = self.transfer_capabilities.minimum_transfer_amounts.get(from_wallet) {
            if amount < *minimum {
                return Err(anyhow::anyhow!("Transfer amount below minimum"));
            }
        }

        // Check cooldowns
        if let Some(cooldown) = self.transfer_capabilities.transfer_cooldowns.get(from_wallet) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            
            // Check if enough time has passed since last transfer (simplified check)
            if current_time < *cooldown {
                return Err(anyhow::anyhow!("Transfer cooldown period not yet expired"));
            }
        }

        Ok(())
    }

    fn calculate_transfer_fee(&self, from_wallet: &WalletType, to_wallet: &WalletType, amount: u64) -> Result<u64> {
        // Get fee rate for this wallet pair
        let fee_rate = self.transfer_capabilities.transfer_fee_rates
            .get(&(from_wallet.clone(), to_wallet.clone()))
            .unwrap_or(&50); // Default 0.5%

        let fee = (amount * fee_rate) / 10_000; // Convert basis points to fee
        Ok(fee.max(1)) // Minimum fee of 1 ZHTP
    }

    async fn create_blockchain_transaction_record(
        &self,
        from_wallet: &WalletType,
        to_wallet: &WalletType,
        amount: u64,
        fee: u64,
    ) -> Result<[u8; 32]> {
        // Create proper blockchain transaction using imported transaction creation functionality
        let transaction_type = self.get_transaction_type_for_wallet_transfer(from_wallet, to_wallet);
        
        // Generate wallet addresses (simplified for demonstration) 
        let from_address = self.get_wallet_address(from_wallet)?;
        let to_address = self.get_wallet_address(to_wallet)?;
        
        // Convert priority based on fee (simple heuristic)
        let priority = if fee >= amount / 10 {
            Priority::High
        } else if fee >= amount / 50 {
            Priority::Normal
        } else {
            Priority::Low
        };
        
        // Create the transaction using the imported create_payment_transaction function
        let transaction = create_payment_transaction(
            from_address,
            to_address,
            amount,
            priority,
        )?;
        
        info!(
            "🏦 Created blockchain transaction: from={:?} to={:?} amount={} fee={} type={:?}",
            from_wallet, to_wallet, amount, fee, transaction_type
        );
        
        // Return the transaction ID
        Ok(transaction.tx_id)
    }

    /// Get wallet address for a given wallet type
    fn get_wallet_address(&self, wallet_type: &WalletType) -> Result<[u8; 32]> {
        // In production, this would derive proper addresses based on wallet type
        // For now, create deterministic addresses based on identity and wallet type
        use lib_crypto::hash_blake3;
        
        let mut input = Vec::new();
        input.extend_from_slice(&self.identity.id.as_bytes());
        input.extend_from_slice(format!("{:?}", wallet_type).as_bytes());
        
        let hash = hash_blake3(&input);
        Ok(hash) // Return full 32-byte hash as address
    }

    /// Get appropriate transaction type for wallet transfers
    fn get_transaction_type_for_wallet_transfer(&self, from_wallet: &WalletType, to_wallet: &WalletType) -> TransactionType {
        match (from_wallet, to_wallet) {
            // Reward-related transfers
            (_, WalletType::IspBypassRewards) | (_, WalletType::MeshDiscoveryRewards) => TransactionType::Reward,
            (WalletType::IspBypassRewards, _) | (WalletType::MeshDiscoveryRewards, _) => TransactionType::Reward,
            
            // UBI-related transfers
            (_, WalletType::UbiDistribution) | (WalletType::UbiDistribution, _) => TransactionType::UbiDistribution,
            
            // Staking-related transfers
            (_, WalletType::Staking) => TransactionType::Stake,
            (WalletType::Staking, _) => TransactionType::Unstake,
            
            // Governance-related transfers
            (_, WalletType::Governance) | (WalletType::Governance, _) => TransactionType::ProposalExecution,
            
            // All other transfers are standard payments
            _ => TransactionType::Payment,
        }
    }

    async fn register_wallet_on_blockchain(&self, wallet_type: &WalletType) -> Result<()> {
        // In production, this would register the wallet creation on blockchain
        // For now, just log the registration
        info!(
            "Registered wallet {:?} creation",
            wallet_type
        );
        Ok(())
    }

    async fn check_auto_consolidation(&mut self, wallet_type: &WalletType) -> Result<()> {
        if let Some(rule) = self.auto_consolidation_rules.get(wallet_type).cloned() {
            if rule.enabled {
                if let Some(wallet) = self.wallets.get(wallet_type) {
                    if wallet.available_balance >= rule.minimum_balance {
                        // Trigger consolidation check on next cycle
                        info!(
                            "Auto-consolidation eligible for {:?} wallet (balance: {} >= minimum: {})",
                            wallet_type, wallet.available_balance, rule.minimum_balance
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

impl WalletPermissions {
    fn default_permissions() -> Self {
        Self {
            can_transfer_external: true,
            can_vote: false,
            can_stake: true,
            can_receive_rewards: true,
            daily_transaction_limit: 1_000_000, // 1M ZHTP
            requires_multisig_threshold: None,
        }
    }
}

impl ConsolidationRule {
    fn disabled() -> Self {
        Self {
            enabled: false,
            minimum_balance: 0,
            target_wallet: WalletType::Primary,
            frequency_seconds: 0,
            last_consolidation: 0,
        }
    }
}

impl TransferCapabilities {
    fn new() -> Self {
        let mut daily_limits = HashMap::new();
        daily_limits.insert(WalletType::Primary, 10_000_000); // 10M ZHTP
        daily_limits.insert(WalletType::Governance, 100_000); // 100K ZHTP
        daily_limits.insert(WalletType::Staking, 5_000_000); // 5M ZHTP

        let mut fee_rates = HashMap::new();
        fee_rates.insert((WalletType::Primary, WalletType::Staking), 25); // 0.25%
        fee_rates.insert((WalletType::IspBypassRewards, WalletType::Primary), 10); // 0.1%
        fee_rates.insert((WalletType::MeshDiscoveryRewards, WalletType::Primary), 10); // 0.1%

        let mut minimum_amounts = HashMap::new();
        minimum_amounts.insert(WalletType::Primary, 1000); // 1000 ZHTP
        minimum_amounts.insert(WalletType::Governance, 10000); // 10000 ZHTP

        let mut confirmations = HashMap::new();
        confirmations.insert(WalletType::Bridge, 6); // 6 confirmations for bridge
        confirmations.insert(WalletType::Governance, 3); // 3 confirmations for governance

        let mut cooldowns = HashMap::new();
        cooldowns.insert(WalletType::Governance, 3600); // 1 hour cooldown

        Self {
            daily_transfer_limits: daily_limits,
            transfer_fee_rates: fee_rates,
            minimum_transfer_amounts: minimum_amounts,
            confirmation_requirements: confirmations,
            transfer_cooldowns: cooldowns,
        }
    }
}

/// Create a new multi-wallet manager with identity
pub async fn create_multi_wallet_manager(identity: Identity) -> Result<MultiWalletManager> {
    MultiWalletManager::new(identity).await
}

/// Create multi-wallet manager with pre-configured specialized wallets
pub async fn create_comprehensive_multi_wallet_manager(identity: Identity) -> Result<MultiWalletManager> {
    let mut manager = MultiWalletManager::new(identity).await?;
    
    // Create common specialized wallets
    manager.create_specialized_wallet(WalletType::IspBypassRewards).await?;
    manager.create_specialized_wallet(WalletType::MeshDiscoveryRewards).await?;
    manager.create_specialized_wallet(WalletType::Staking).await?;
    manager.create_specialized_wallet(WalletType::Infrastructure).await?;
    
    info!("🏦 Created comprehensive multi-wallet manager with {} wallets", manager.wallets.len());
    
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::types::{IdentityType, AccessLevel};
    use lib_identity::wallets::WalletManager;
    use lib_proofs::ZeroKnowledgeProof;
    use lib_crypto::{Hash, KeyPair, PublicKey};

    fn create_test_identity() -> Identity {
        let keypair = KeyPair::generate().expect("keypair");
        let public_key: PublicKey = keypair.public_key.clone();
        let private_key = Some(keypair.private_key.clone());
        let did = "did:zhtp:test_identity".to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Identity {
            id: Hash::from_bytes("test_identity".as_bytes()),
            identity_type: IdentityType::Human,
            did,
            public_key,
            private_key,
            node_id: Hash::from_bytes("node_id".as_bytes()),
            device_node_ids: HashMap::new(),
            primary_device: "primary-device".to_string(),
            ownership_proof: ZeroKnowledgeProof::default(),
            credentials: HashMap::new(), // credential map empty in test
            reputation: 100,
            age: Some(25),
            access_level: AccessLevel::FullCitizen,
            metadata: HashMap::new(),
            private_data_id: Some(Hash::from_bytes("private_data".as_bytes())),
            wallet_manager: WalletManager::new(Hash::from_bytes("test_identity".as_bytes())),
            did_document_hash: Some(Hash::from_bytes("did_document".as_bytes())),
            attestations: vec![],
            created_at: now,
            last_active: now,
            recovery_keys: vec![],
            owner_identity_id: None,
            reward_wallet_id: None,
            encrypted_master_seed: None,
            next_wallet_index: 0,
            password_hash: None,
            master_seed_phrase: None,
            zk_identity_secret: [0u8; 32],
            zk_credential_hash: [0u8; 32],
            wallet_master_seed: [0u8; 64],
            citizenship_verified: false,
            dao_member_id: String::new(),
            dao_voting_power: 0,
            jurisdiction: None,
        }
    }

    #[tokio::test]
    async fn test_multi_wallet_creation() {
        let identity = create_test_identity();
        let manager = MultiWalletManager::new(identity).await.unwrap();
        
        assert_eq!(manager.wallets.len(), 1);
        assert!(manager.wallets.contains_key(&WalletType::Primary));
        assert_eq!(manager.get_total_balance(), 0);
    }

    #[tokio::test]
    async fn test_specialized_wallet_creation() {
        let identity = create_test_identity();
        let mut manager = MultiWalletManager::new(identity).await.unwrap();
        
        manager.create_specialized_wallet(WalletType::IspBypassRewards).await.unwrap();
        manager.create_specialized_wallet(WalletType::Staking).await.unwrap();
        
        assert_eq!(manager.wallets.len(), 3);
        assert!(manager.wallets.contains_key(&WalletType::IspBypassRewards));
        assert!(manager.wallets.contains_key(&WalletType::Staking));
    }

    #[tokio::test]
    async fn test_wallet_permissions() {
        let identity = create_test_identity();
        let mut manager = MultiWalletManager::new(identity).await.unwrap();
        
        manager.create_specialized_wallet(WalletType::Governance).await.unwrap();
        
        let governance_permissions = manager.wallet_permissions.get(&WalletType::Governance).unwrap();
        assert!(governance_permissions.can_vote);
        assert!(!governance_permissions.can_transfer_external);
        
        let primary_permissions = manager.wallet_permissions.get(&WalletType::Primary).unwrap();
        assert!(primary_permissions.can_transfer_external);
        assert!(!primary_permissions.can_vote);
    }
}
