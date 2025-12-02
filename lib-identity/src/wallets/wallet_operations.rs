//! Wallet operations from the original identity.rs

use anyhow::Result;
use lib_crypto::Hash;
use crate::wallets::{WalletManager, WalletId, WalletType};

impl WalletManager {
    /// Create a basic wallet for testing purposes (bypasses seed phrase requirement)
    #[cfg(test)]
    pub fn create_wallet_for_testing(
        &mut self,
        wallet_type: WalletType,
        name: String,
        alias: Option<String>,
    ) -> Result<WalletId> {
        // Generate quantum-resistant public key
        let mut public_key = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut public_key);
        
        // Create the wallet without seed phrase for testing
        let wallet = crate::wallets::QuantumWallet::new(
            wallet_type,
            name,
            alias.clone(),
            self.owner_id.clone(),
            public_key,
        );
        
        let wallet_id = wallet.id.clone();
        
        // Store wallet
        self.wallets.insert(wallet_id.clone(), wallet);
        
        // Store alias mapping if provided
        if let Some(alias) = alias {
            self.alias_map.insert(alias, wallet_id.clone());
        }
        
        Ok(wallet_id)
    }

    /// Add funds to a wallet
    pub fn add_funds_to_wallet(&mut self, wallet_id: &WalletId, amount: u64) -> Result<()> {
        let new_balance = if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.add_funds(amount);
            wallet.balance
        } else {
            return Err(anyhow::anyhow!("Wallet not found"));
        };
        
        self.calculate_total_balance();
        
        tracing::info!(
            "Added {} ZHTP to wallet {}. New balance: {}",
            amount,
            hex::encode(&wallet_id.0[..8]),
            new_balance
        );
        
        Ok(())
    }
    
    /// Remove funds from a wallet
    pub fn remove_funds_from_wallet(&mut self, wallet_id: &WalletId, amount: u64) -> Result<()> {
        let new_balance = if let Some(wallet) = self.wallets.get_mut(wallet_id) {
            wallet.remove_funds(amount).map_err(|e| anyhow::anyhow!(e))?;
            wallet.balance
        } else {
            return Err(anyhow::anyhow!("Wallet not found"));
        };
        
        self.calculate_total_balance();
        
        tracing::info!(
            "Removed {} ZHTP from wallet {}. New balance: {}",
            amount,
            hex::encode(&wallet_id.0[..8]),
            new_balance
        );
        
        Ok(())
    }
    
    /// Get wallet balance
    pub fn get_wallet_balance(&self, wallet_id: &WalletId) -> Option<u64> {
        self.wallets.get(wallet_id).map(|wallet| wallet.balance)
    }
    
    /// Check if wallet has sufficient funds
    pub fn has_sufficient_funds(&self, wallet_id: &WalletId, amount: u64) -> bool {
        self.get_wallet_balance(wallet_id)
            .map_or(false, |balance| balance >= amount)
    }
    
    /// Bulk transfer to multiple wallets
    pub fn bulk_transfer_to_wallets(
        &mut self,
        from_wallet: &WalletId,
        transfers: Vec<(WalletId, u64)>,
        purpose: String,
    ) -> Result<Vec<Hash>> {
        // Calculate total amount needed
        let total_amount: u64 = transfers.iter().map(|(_, amount)| amount).sum();
        
        // Check if source wallet has sufficient funds
        if !self.has_sufficient_funds(from_wallet, total_amount) {
            return Err(anyhow::anyhow!("Insufficient funds for bulk transfer"));
        }
        
        let mut transaction_hashes = Vec::new();
        
        // Execute all transfers
        for (to_wallet, amount) in transfers {
            let tx_hash = self.transfer_between_wallets(
                from_wallet,
                &to_wallet,
                amount,
                format!("{} (bulk)", purpose),
            )?;
            transaction_hashes.push(tx_hash);
        }
        
        tracing::info!(
            "Completed bulk transfer of {} ZHTP from wallet {} to {} recipients",
            total_amount,
            hex::encode(&from_wallet.0[..8]),
            transaction_hashes.len()
        );
        
        Ok(transaction_hashes)
    }
    
    /// Get recent transactions across all wallets
    pub fn get_all_recent_transactions(&self) -> Vec<TransactionSummary> {
        let mut all_transactions = Vec::new();
        
        for wallet in self.wallets.values() {
            for tx_hash in &wallet.recent_transactions {
                all_transactions.push(TransactionSummary {
                    transaction_hash: tx_hash.clone(),
                    wallet_id: wallet.id.clone(),
                    wallet_name: wallet.name.clone(),
                    wallet_type: wallet.wallet_type.clone(),
                    timestamp: wallet.last_transaction.unwrap_or(wallet.created_at),
                });
            }
        }
        
        // Sort by timestamp (most recent first)
        all_transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        all_transactions
    }
    
    /// Auto-distribute UBI to UBI wallets
    pub fn auto_distribute_ubi(&mut self, amount_per_wallet: u64) -> Result<Vec<Hash>> {
        let ubi_wallets: Vec<WalletId> = self.wallets.values()
            .filter(|wallet| wallet.wallet_type == crate::wallets::WalletType::UBI)
            .map(|wallet| wallet.id.clone())
            .collect();
        
        let mut distribution_hashes = Vec::new();
        
        for wallet_id in ubi_wallets {
            if let Some(wallet) = self.wallets.get_mut(&wallet_id) {
                wallet.add_funds(amount_per_wallet);
                
                // Generate UBI distribution hash
                let ubi_data = [
                    wallet_id.as_bytes(),
                    &amount_per_wallet.to_le_bytes(),
                    b"ubi_distribution",
                    &std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_le_bytes(),
                ].concat();
                let ubi_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&ubi_data));
                
                wallet.add_transaction(ubi_hash.clone());
                distribution_hashes.push(ubi_hash);
            }
        }
        
        self.calculate_total_balance();
        
        tracing::info!(
            "Auto-distributed {} ZHTP to {} UBI wallets",
            amount_per_wallet,
            distribution_hashes.len()
        );
        
        Ok(distribution_hashes)
    }

    /// Process UBI distribution to all eligible wallets
    pub fn process_ubi_distribution(&mut self, total_ubi_pool: u64) -> Result<UbiDistributionResult> {
        let ubi_wallets: Vec<WalletId> = self.wallets.values()
            .filter(|wallet| wallet.wallet_type == crate::wallets::WalletType::UBI)
            .map(|wallet| wallet.id.clone())
            .collect();
        
        if ubi_wallets.is_empty() {
            return Ok(UbiDistributionResult {
                total_distributed: 0,
                recipients: 0,
                individual_amount: 0,
                distribution_hashes: Vec::new(),
                distribution_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
        }
        
        let individual_amount = total_ubi_pool / ubi_wallets.len() as u64;
        let mut distribution_hashes = Vec::new();
        let mut total_distributed = 0;
        
        for wallet_id in &ubi_wallets {
            if let Some(wallet) = self.wallets.get_mut(wallet_id) {
                wallet.add_funds(individual_amount);
                total_distributed += individual_amount;
                
                // Generate distribution hash
                let distribution_data = [
                    wallet_id.as_bytes(),
                    &individual_amount.to_le_bytes(),
                    b"ubi_distribution",
                    &std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_le_bytes(),
                ].concat();
                
                let distribution_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&distribution_data));
                distribution_hashes.push(distribution_hash);
            }
        }
        
        Ok(UbiDistributionResult {
            total_distributed,
            recipients: ubi_wallets.len(),
            individual_amount,
            distribution_hashes,
            distribution_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Generate staking rewards for eligible wallets
    pub fn generate_staking_rewards(&mut self, reward_rate: f64) -> Result<StakingRewardsResult> {
        let mut total_rewards = 0u64;
        let mut reward_recipients = 0;
        let mut reward_details = Vec::new();
        
        for (wallet_id, wallet) in self.wallets.iter_mut() {
            if wallet.staked_balance > 0 {
                let reward_amount = (wallet.staked_balance as f64 * reward_rate) as u64;
                wallet.add_rewards(reward_amount);
                
                total_rewards += reward_amount;
                reward_recipients += 1;
                
                reward_details.push(WalletRewardDetail {
                    wallet_id: wallet_id.clone(),
                    staked_amount: wallet.staked_balance,
                    reward_amount,
                    new_total_rewards: wallet.pending_rewards,
                });
            }
        }
        
        Ok(StakingRewardsResult {
            total_rewards,
            reward_recipients,
            reward_rate,
            reward_details,
            generation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Process cross-wallet transaction
    pub fn process_cross_wallet_transaction(
        &mut self,
        transaction: CrossWalletTransactionRequest,
    ) -> Result<CrossWalletTransactionResult> {
        // Validate wallets exist and belong to this manager
        let from_wallet = self.wallets.get(&transaction.from_wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Source wallet not found"))?;
        
        let _to_wallet = self.wallets.get(&transaction.to_wallet_id)
            .ok_or_else(|| anyhow::anyhow!("Destination wallet not found"))?;
        
        // Check sufficient balance
        if from_wallet.balance < transaction.amount {
            return Err(anyhow::anyhow!("Insufficient balance"));
        }
        
        // Execute transaction
        let from_wallet_mut = self.wallets.get_mut(&transaction.from_wallet_id).unwrap();
        from_wallet_mut.deduct_funds(transaction.amount)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        
        let to_wallet_mut = self.wallets.get_mut(&transaction.to_wallet_id).unwrap();
        to_wallet_mut.add_funds(transaction.amount);
        
        // Generate transaction hash
        let tx_data = [
            transaction.from_wallet_id.as_bytes(),
            transaction.to_wallet_id.as_bytes(),
            &transaction.amount.to_le_bytes(),
            transaction.purpose.as_bytes(),
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_le_bytes(),
        ].concat();
        
        let transaction_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&tx_data));
        
        // Get the new balances before constructing the result
        let new_from_balance = self.wallets.get(&transaction.from_wallet_id).unwrap().balance;
        let new_to_balance = self.wallets.get(&transaction.to_wallet_id).unwrap().balance;
        
        Ok(CrossWalletTransactionResult {
            transaction_hash,
            from_wallet_id: transaction.from_wallet_id,
            to_wallet_id: transaction.to_wallet_id,
            amount: transaction.amount,
            new_from_balance,
            new_to_balance,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Calculate total balance across all wallets
    pub fn calculate_total_balance(&mut self) -> u64 {
        self.total_balance = self.wallets.values()
            .map(|wallet| wallet.balance)
            .sum();
        self.total_balance
    }
    
    /// Get wallet count
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }
    
    /// Get active wallet count
    pub fn active_wallet_count(&self) -> usize {
        self.wallets.values()
            .filter(|wallet| wallet.is_active)
            .count()
    }
    
    /// Get wallets by type
    pub fn get_wallets_by_type(&self, wallet_type: &crate::wallets::WalletType) -> Vec<&crate::wallets::QuantumWallet> {
        self.wallets.values()
            .filter(|wallet| &wallet.wallet_type == wallet_type)
            .collect()
    }

    /// Perform wallet health check
    pub fn perform_health_check(&self) -> WalletHealthReport {
        let mut healthy_wallets = 0;
        let mut unhealthy_wallets = 0;
        let mut total_balance = 0;
        let mut issues = Vec::new();
        
        for (wallet_id, wallet) in &self.wallets {
            total_balance += wallet.balance;
            
            if wallet.is_healthy() {
                healthy_wallets += 1;
            } else {
                unhealthy_wallets += 1;
                issues.push(format!("Wallet {} is unhealthy", hex::encode(&wallet_id.0[..8])));
            }
        }
        
        WalletHealthReport {
            total_wallets: self.wallets.len(),
            healthy_wallets,
            unhealthy_wallets,
            total_balance,
            issues,
            check_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Transaction summary for listing operations
#[derive(Debug, Clone)]
pub struct TransactionSummary {
    pub transaction_hash: Hash,
    pub wallet_id: WalletId,
    pub wallet_name: String,
    pub wallet_type: crate::wallets::WalletType,
    pub timestamp: u64,
}

/// Result of UBI distribution process
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UbiDistributionResult {
    pub total_distributed: u64,
    pub recipients: usize,
    pub individual_amount: u64,
    pub distribution_hashes: Vec<Hash>,
    pub distribution_timestamp: u64,
}

/// Result of staking rewards generation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StakingRewardsResult {
    pub total_rewards: u64,
    pub reward_recipients: usize,
    pub reward_rate: f64,
    pub reward_details: Vec<WalletRewardDetail>,
    pub generation_timestamp: u64,
}

/// Individual wallet reward details
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletRewardDetail {
    pub wallet_id: WalletId,
    pub staked_amount: u64,
    pub reward_amount: u64,
    pub new_total_rewards: u64,
}

/// Cross-wallet transaction request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossWalletTransactionRequest {
    pub from_wallet_id: WalletId,
    pub to_wallet_id: WalletId,
    pub amount: u64,
    pub purpose: String,
}

/// Result of cross-wallet transaction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossWalletTransactionResult {
    pub transaction_hash: Hash,
    pub from_wallet_id: WalletId,
    pub to_wallet_id: WalletId,
    pub amount: u64,
    pub new_from_balance: u64,
    pub new_to_balance: u64,
    pub timestamp: u64,
}

/// Wallet health report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletHealthReport {
    pub total_wallets: usize,
    pub healthy_wallets: usize,
    pub unhealthy_wallets: usize,
    pub total_balance: u64,
    pub issues: Vec<String>,
    pub check_timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_ubi_distribution() {
        let owner_id = Hash([1u8; 32]);
        let mut manager = WalletManager::new(owner_id);
        
        // Create UBI wallets
        let ubi_wallet1 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::UBI,
            "UBI Wallet 1".to_string(),
            Some("ubi1".to_string()),
        ).unwrap();
        
        let ubi_wallet2 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::UBI,
            "UBI Wallet 2".to_string(),
            Some("ubi2".to_string()),
        ).unwrap();
        
        // Distribute UBI
        let result = manager.process_ubi_distribution(1000).unwrap();
        
        assert_eq!(result.total_distributed, 1000);
        assert_eq!(result.recipients, 2);
        assert_eq!(result.individual_amount, 500);
        assert_eq!(result.distribution_hashes.len(), 2);
        
        // Verify wallets received funds
        assert_eq!(manager.get_wallet(&ubi_wallet1).unwrap().balance, 500);
        assert_eq!(manager.get_wallet(&ubi_wallet2).unwrap().balance, 500);
    }

    #[test]
    fn test_cross_wallet_transaction() {
        let owner_id = Hash([1u8; 32]);
        let mut manager = WalletManager::new(owner_id);
        
        let wallet1 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Primary,
            "Wallet 1".to_string(),
            None,
        ).unwrap();
        
        let wallet2 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Savings,
            "Wallet 2".to_string(),
            None,
        ).unwrap();
        
        // Add funds to first wallet
        manager.wallets.get_mut(&wallet1).unwrap().add_funds(1000);
        
        // Create transaction request
        let tx_request = CrossWalletTransactionRequest {
            from_wallet_id: wallet1.clone(),
            to_wallet_id: wallet2.clone(),
            amount: 300,
            purpose: "Transfer to savings".to_string(),
        };
        
        let result = manager.process_cross_wallet_transaction(tx_request).unwrap();
        
        assert_eq!(result.amount, 300);
        assert_eq!(result.new_from_balance, 700);
        assert_eq!(result.new_to_balance, 300);
        assert!(!result.transaction_hash.0.is_empty());
    }

    #[test]
    fn test_wallet_health_check() {
        let owner_id = Hash([1u8; 32]);
        let mut manager = WalletManager::new(owner_id);
        
        // Create some wallets
        let _wallet1 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Primary,
            "Healthy Wallet".to_string(),
            None,
        ).unwrap();
        
        let _wallet2 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::UBI,
            "Another Healthy Wallet".to_string(),
            None,
        ).unwrap();
        
        let health_report = manager.perform_health_check();
        
        assert_eq!(health_report.total_wallets, 2);
        assert_eq!(health_report.healthy_wallets, 2);
        assert_eq!(health_report.unhealthy_wallets, 0);
        assert!(health_report.issues.is_empty());
        assert!(health_report.check_timestamp > 0);
    }

    #[test]
    fn test_staking_rewards_generation() {
        let owner_id = Hash([1u8; 32]);
        let mut manager = WalletManager::new(owner_id);
        
        let wallet1 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Primary,
            "Staking Wallet 1".to_string(),
            None,
        ).unwrap();
        
        let wallet2 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Savings,
            "Staking Wallet 2".to_string(),
            None,
        ).unwrap();
        
        // Add staked amounts
        manager.wallets.get_mut(&wallet1).unwrap().staked_balance = 1000;
        manager.wallets.get_mut(&wallet2).unwrap().staked_balance = 2000;
        
        // Generate rewards at 5% rate
        let reward_result = manager.generate_staking_rewards(0.05).unwrap();
        
        assert_eq!(reward_result.reward_recipients, 2);
        assert_eq!(reward_result.total_rewards, 150); // 5% of 3000
        assert_eq!(reward_result.reward_details.len(), 2);
        
        // Check individual rewards
        let wallet1_reward = reward_result.reward_details.iter()
            .find(|r| r.wallet_id == wallet1).unwrap();
        assert_eq!(wallet1_reward.reward_amount, 50); // 5% of 1000
        
        let wallet2_reward = reward_result.reward_details.iter()
            .find(|r| r.wallet_id == wallet2).unwrap();
        assert_eq!(wallet2_reward.reward_amount, 100); // 5% of 2000
    }

    #[test]
    fn test_bulk_transfer() {
        let owner_id = Hash([1u8; 32]);
        let mut manager = WalletManager::new(owner_id);
        
        let source_wallet = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Primary,
            "Source Wallet".to_string(),
            None,
        ).unwrap();
        
        let dest1 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Savings,
            "Dest 1".to_string(),
            None,
        ).unwrap();
        
        let dest2 = manager.create_wallet_for_testing(
            crate::wallets::WalletType::Business,
            "Dest 2".to_string(),
            None,
        ).unwrap();
        
        // Add funds to source
        manager.add_funds_to_wallet(&source_wallet, 1000).unwrap();
        
        // Bulk transfer
        let transfers = vec![
            (dest1.clone(), 300),
            (dest2.clone(), 200),
        ];
        
        let tx_hashes = manager.bulk_transfer_to_wallets(
            &source_wallet,
            transfers,
            "Test bulk transfer".to_string(),
        ).unwrap();
        
        assert_eq!(tx_hashes.len(), 2);
        assert_eq!(manager.get_wallet_balance(&source_wallet).unwrap(), 500);
        assert_eq!(manager.get_wallet_balance(&dest1).unwrap(), 300);
        assert_eq!(manager.get_wallet_balance(&dest2).unwrap(), 200);
    }
}
